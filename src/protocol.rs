use std::{
    any::{Any, TypeId},
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::Arc,
};

use futures::future::BoxFuture;

use crate::{
    codec::{BoxPeekableBiStream, BoxPeekableUniStream},
    connection::StreamError,
    quic::{self, ConnectionError},
};

pub struct Protocols<C: ?Sized> {
    layers: HashMap<TypeId, Arc<dyn Protocol<C>>>,
}

impl<C: ?Sized> Default for Protocols<C> {
    fn default() -> Self {
        Self {
            layers: Default::default(),
        }
    }
}

impl<C: ?Sized> Debug for Protocols<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_list();
        for layer in self.layers.values() {
            f.entry(layer.as_ref());
        }
        f.finish()
    }
}

impl<C: ?Sized> Protocols<C> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<L: Any>(&self) -> Option<&L> {
        self.layers.get(&TypeId::of::<L>()).map(|layer| {
            (layer.as_ref() as &dyn Any)
                .downcast_ref()
                .expect("TypeId collision for protocol layers, this is a bug")
        })
    }
}

impl<C: quic::Connection + ?Sized> Protocols<C> {
    pub fn insert<L: Protocol<C>>(&mut self, layer: L) {
        self.layers.insert(TypeId::of::<L>(), Arc::new(layer));
    }

    pub(crate) async fn accept_uni<'a>(
        &'a self,
        conn: &'a Arc<C>,
        mut stream: BoxPeekableUniStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>
    where
        C: quic::Connection,
    {
        for layer in self.layers.values() {
            match layer.accept_uni(conn, stream).await? {
                StreamVerdict::Accepted => return Ok(StreamVerdict::Accepted),
                StreamVerdict::Passed(mut passed) => {
                    Pin::new(&mut passed).reset();
                    stream = passed
                }
            }
        }
        Ok(StreamVerdict::Passed(stream))
    }

    pub(crate) async fn accept_bi<'a>(
        &'a self,
        conn: &'a Arc<C>,
        mut stream: BoxPeekableBiStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>
    where
        C: quic::Connection,
    {
        for layer in self.layers.values() {
            match layer.accept_bi(conn, stream).await? {
                StreamVerdict::Accepted => return Ok(StreamVerdict::Accepted),
                StreamVerdict::Passed(mut passed) => {
                    Pin::new(&mut passed.0).reset();
                    stream = passed
                }
            }
        }
        Ok(StreamVerdict::Passed(stream))
    }
}

pub trait ProductProtocol<C: quic::Connection + ?Sized>:
    Any + Send + Sync + Hash + Eq + Ord
{
    type Protocol: Protocol<C>;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a Protocols<C>,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>>;
}

pub(crate) trait InitProtocols<C: quic::Connection + ?Sized>: Send + Sync {
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a mut Protocols<C>,
    ) -> BoxFuture<'a, Result<(), ConnectionError>>;

    /// Hash using TypeId + self value for type-erased identity.
    fn identity_hash(&self, state: &mut dyn Hasher);

    /// Equality via downcasting. Returns false for different types.
    fn identity_eq(&self, other: &dyn Any) -> bool;

    /// Ordering: by TypeId first, then by value within the same type.
    #[allow(dead_code)]
    fn identity_cmp(&self, other: &dyn Any) -> Ordering;

    /// Returns the concrete TypeId.
    fn identity_type_id(&self) -> TypeId;

    /// Returns self as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
}

impl<C: quic::Connection + ?Sized, P: ProductProtocol<C>> InitProtocols<C> for P {
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a mut Protocols<C>,
    ) -> BoxFuture<'a, Result<(), ConnectionError>> {
        Box::pin(async move {
            if layers
                .get::<<Self as ProductProtocol<C>>::Protocol>()
                .is_some()
            {
                return Ok(());
            }
            let layer = ProductProtocol::init(self, conn, layers).await?;
            layers.insert(layer);
            Ok(())
        })
    }

    fn identity_hash(&self, state: &mut dyn Hasher) {
        TypeId::of::<P>().hash(&mut DynHasher(state));
        self.hash(&mut DynHasher(state));
    }

    fn identity_eq(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<P>().is_some_and(|o| self == o)
    }

    fn identity_cmp(&self, other: &dyn Any) -> Ordering {
        let self_tid = type_id_as_u128(TypeId::of::<P>());
        let other_tid = type_id_as_u128(identity_type_id_of(other));
        match self_tid.cmp(&other_tid) {
            Ordering::Equal => other
                .downcast_ref::<P>()
                .map_or(Ordering::Equal, |o| self.cmp(o)),
            ord => ord,
        }
    }

    fn identity_type_id(&self) -> TypeId {
        TypeId::of::<P>()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Extracts the TypeId from a `dyn Any` value.
#[allow(dead_code)]
fn identity_type_id_of(val: &dyn Any) -> TypeId {
    val.type_id()
}

/// Transmutes a TypeId to u128 for cross-type ordering.
pub(crate) fn type_id_as_u128(tid: TypeId) -> u128 {
    // SAFETY: TypeId is currently a u128 on all platforms.
    // This is used only for deterministic ordering, not for safety-critical logic.
    unsafe { std::mem::transmute(tid) }
}

/// Adapter to use `&mut dyn Hasher` with `Hash::hash`.
struct DynHasher<'a>(&'a mut dyn Hasher);

impl Hasher for DynHasher<'_> {
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }

    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

/// Protocol layer trait for handling QUIC streams in a layered architecture.
/// Layers can inspect, accept, or pass through streams to underlying layers.
pub trait Protocol<C: quic::Connection + ?Sized>: Any + Send + Sync + Debug {
    /// Handles an incoming unidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_uni<'a>(
        &'a self,
        connection: &'a Arc<C>,
        stream: BoxPeekableUniStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>>;

    /// Handles an incoming bidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_bi<'a>(
        &'a self,
        connection: &'a Arc<C>,
        stream: BoxPeekableBiStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>>;
}

/// Verdict for stream handling in protocol layers.
#[derive(Debug)]
pub enum StreamVerdict<S> {
    /// The stream was accepted and handled by this layer.
    Accepted,
    /// The stream was not handled and should be passed to the next layer.
    Passed(S),
}

#[cfg(test)]
mod tests {
    use std::{
        any::Any, cmp::Ordering, collections::hash_map::DefaultHasher, hash::Hasher, sync::Arc,
    };

    use futures::future::BoxFuture;

    use super::*;
    use crate::quic::{self, ConnectionError};

    // Minimal mock protocol (runtime layer).
    #[derive(Debug)]
    struct MockProtocol;

    impl<C: quic::Connection + ?Sized> Protocol<C> for MockProtocol {
        fn accept_uni<'a>(
            &'a self,
            _: &'a Arc<C>,
            stream: BoxPeekableUniStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }

        fn accept_bi<'a>(
            &'a self,
            _: &'a Arc<C>,
            stream: BoxPeekableBiStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }
    }

    /// Test-only mock protocol factory.
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct MockFactory(u64);

    impl<C: quic::Connection + ?Sized> ProductProtocol<C> for MockFactory {
        type Protocol = MockProtocol;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols<C>,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in identity tests")
        }
    }

    /// Second mock for cross-type tests.
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct MockFactory2(u64);

    // Use a different protocol type to avoid TypeId collision on Protocol.
    #[derive(Debug)]
    struct MockProtocol2;

    impl<C: quic::Connection + ?Sized> Protocol<C> for MockProtocol2 {
        fn accept_uni<'a>(
            &'a self,
            _: &'a Arc<C>,
            stream: BoxPeekableUniStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }

        fn accept_bi<'a>(
            &'a self,
            _: &'a Arc<C>,
            stream: BoxPeekableBiStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }
    }

    impl<C: quic::Connection + ?Sized> ProductProtocol<C> for MockFactory2 {
        type Protocol = MockProtocol2;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols<C>,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in identity tests")
        }
    }

    // Use `dyn InitProtocols<C>` with C = some concrete quic::Connection.
    // We parameterize over C generically so this compiles without gm-quic.
    fn hash_via_identity<C: quic::Connection + ?Sized>(p: &dyn InitProtocols<C>) -> u64 {
        let mut hasher = DefaultHasher::new();
        p.identity_hash(&mut hasher);
        hasher.finish()
    }

    fn eq_via_identity<C: quic::Connection + ?Sized>(
        a: &dyn InitProtocols<C>,
        b: &dyn Any,
    ) -> bool {
        a.identity_eq(b)
    }

    fn cmp_via_identity<C: quic::Connection + ?Sized>(
        a: &dyn InitProtocols<C>,
        b: &dyn Any,
    ) -> Ordering {
        a.identity_cmp(b)
    }

    #[cfg(feature = "gm-quic")]
    type C = gm_quic::prelude::Connection;

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_hash_same_value_same_hash() {
        let a = MockFactory(42);
        let b = MockFactory(42);
        assert_eq!(hash_via_identity::<C>(&a), hash_via_identity::<C>(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_hash_different_value_different_hash() {
        let a = MockFactory(1);
        let b = MockFactory(2);
        assert_ne!(hash_via_identity::<C>(&a), hash_via_identity::<C>(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_hash_different_type_different_hash() {
        let a = MockFactory(1);
        let b = MockFactory2(1);
        assert_ne!(hash_via_identity::<C>(&a), hash_via_identity::<C>(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_eq_same_value() {
        let a = MockFactory(10);
        let b = MockFactory(10);
        assert!(eq_via_identity::<C>(&a, &b as &dyn Any));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_eq_different_value() {
        let a = MockFactory(10);
        let b = MockFactory(20);
        assert!(!eq_via_identity::<C>(&a, &b as &dyn Any));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_eq_different_type() {
        let a = MockFactory(10);
        let b = MockFactory2(10);
        assert!(!eq_via_identity::<C>(&a, &b as &dyn Any));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_cmp_same_type_ordering() {
        let a = MockFactory(1);
        let b = MockFactory(2);
        let c = MockFactory(1);
        assert_eq!(cmp_via_identity::<C>(&a, &b as &dyn Any), Ordering::Less);
        assert_eq!(cmp_via_identity::<C>(&b, &a as &dyn Any), Ordering::Greater,);
        assert_eq!(cmp_via_identity::<C>(&a, &c as &dyn Any), Ordering::Equal);
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_cmp_cross_type_consistent() {
        let a = MockFactory(1);
        let b = MockFactory2(1);
        let ab = cmp_via_identity::<C>(&a, &b as &dyn Any);
        let ba = cmp_via_identity::<C>(&b, &a as &dyn Any);
        // Cross-type ordering must be antisymmetric
        assert_ne!(ab, Ordering::Equal);
        assert_eq!(ab, ba.reverse());
    }

    // Cross-type ordering test using real factories (DHttpProtocolFactory vs QPackProtocolFactory)
    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_cmp_cross_type_real_factories() {
        use crate::dhttp::settings::Settings;

        let settings = Settings::default();
        let d = crate::dhttp::protocol::DHttpProtocolFactory::new(Arc::new(settings));
        let q = crate::qpack::protocol::QPackProtocolFactory::new();

        let dq = cmp_via_identity::<C>(&d, &q as &dyn Any);
        let qd = cmp_via_identity::<C>(&q, &d as &dyn Any);

        // They must not be equal and ordering must be antisymmetric
        assert_ne!(dq, Ordering::Equal);
        assert_eq!(dq, qd.reverse());
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_type_id_returns_concrete_type() {
        let a = MockFactory(0);
        let b = MockFactory2(0);
        assert_eq!(
            InitProtocols::<C>::identity_type_id(&a),
            std::any::TypeId::of::<MockFactory>(),
        );
        assert_eq!(
            InitProtocols::<C>::identity_type_id(&b),
            std::any::TypeId::of::<MockFactory2>(),
        );
    }
}
