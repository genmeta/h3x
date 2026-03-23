//! Protocol layer registry and stream dispatch.
//!
//! This module defines the [`Protocols`] registry and the [`Protocol`] trait that
//! together form h3x's layered protocol architecture. Each QUIC connection creates
//! exactly one [`Protocols`] instance during connection setup; this instance is
//! **connection-scoped** and shared (via `Arc<Protocols>`) across every request on
//! that connection.
//!
//! # Architecture
//!
//! ```text
//! Connection setup (typed, generic over C)
//!   └─ ProductProtocol<C>::init(conn)          // factory, runs once per protocol
//!        └─ produces non-generic Protocol impl  // e.g. DHttpProtocol, QPackProtocol
//!             └─ inserted into Protocols        // keyed by TypeId
//! ```
//!
//! After initialization, the generic transport type `C` is erased. Runtime protocol
//! objects store any connection capabilities they need internally (typically as
//! `Arc<dyn ErasedConnection>` or equivalent trait objects).
//!
//! # Handler access pattern
//!
//! Handlers receive protocol access through [`crate::server::Request::protocols()`]
//! and [`crate::server::Response::protocols()`], which return `&Arc<Protocols>`.
//! Combined with [`crate::stream_id::StreamId`], a handler can derive
//! per-request/session handles from the connection-scoped protocol state:
//!
//! ```ignore
//! // Native h3x handler:
//! let dhttp = request.protocols().get::<DHttpProtocol>().unwrap();
//! let stream_id = request.stream_id();
//!
//! // Hypothetical extension protocol:
//! let proto = request.protocols().get::<MyProtocol>().expect("MyProtocol required");
//! let session = proto.create_session(request.stream_id());
//! ```
//!
//! In hyper handlers, the same data is available via request extensions:
//!
//! ```ignore
//! let stream_id = request.extensions().get::<StreamId>().unwrap();
//! let protocols = request.extensions().get::<Arc<Protocols>>().unwrap();
//! let proto = protocols.get::<MyProtocol>().unwrap();
//! ```
//!
//! # Convention for new protocols
//!
//! When adding a new protocol layer:
//!
//! 1. The runtime struct (e.g. `MyProtocol`) must be **non-generic** and implement
//!    [`Protocol`] + [`Any`].
//! 2. The factory struct (e.g. `MyProtocolFactory`) implements [`ProductProtocol<C>`]
//!    to perform typed initialization against `Arc<C>`, then returns the non-generic
//!    runtime protocol.
//! 3. The runtime protocol is **connection-scoped**: created once, shared across all
//!    streams. Per-request or per-session state should be produced by handler-facing
//!    methods (e.g. `create_session(stream_id)`) rather than stored in [`Protocols`].
//! 4. Erase transport-specific types at the boundary: use [`crate::codec::BoxReadStream`],
//!    [`crate::codec::BoxWriteStream`], or [`crate::runtime::ErasedConnection`] to hold
//!    connection capabilities without leaking generic `C`.

use std::{
    any::{Any, TypeId},
    collections::{HashMap, hash_map::DefaultHasher},
    fmt::Debug,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::Arc,
};

use futures::future::BoxFuture;

use crate::{
    codec::{ErasedPeekableBiStream, ErasedPeekableUniStream},
    connection::StreamError,
    quic::{self, ConnectionError},
};

/// Connection-scoped protocol registry.
///
/// Stores non-generic runtime protocol objects keyed by [`TypeId`]. A single instance
/// is created during connection setup and shared (via `Arc<Protocols>`) with every
/// request handler on that connection.
///
/// Protocol runtimes are **connection-scoped**: they live as long as the connection and
/// are shared across all concurrent request streams. Handlers that need per-request or
/// per-session state should derive it from the connection-scoped protocol using a method
/// like `proto.create_session(stream_id)`, rather than inserting per-request objects here.
///
/// # Example
///
/// ```ignore
/// // In a handler, access connection-scoped protocol state:
/// let dhttp = request.protocols().get::<DHttpProtocol>().unwrap();
///
/// // For hypothetical extension protocols, derive per-stream handles:
/// let proto = request.protocols().get::<MyProtocol>().expect("MyProtocol required");
/// let session = proto.create_session(request.stream_id());
/// ```
#[derive(Default)]
pub struct Protocols {
    layers: HashMap<TypeId, Arc<dyn Protocol>>,
}

impl Debug for Protocols {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_list();
        for layer in self.layers.values() {
            f.entry(layer.as_ref());
        }
        f.finish()
    }
}

impl Protocols {
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up a concrete protocol runtime by type.
    ///
    /// Returns a reference to the protocol if it was registered during connection
    /// setup. This is the primary handler-facing API for protocol access.
    ///
    /// The lookup is based on [`TypeId`], so callers specify the exact concrete type
    /// (e.g. `DHttpProtocol`, `QPackProtocol`). The returned reference borrows from
    /// the connection-scoped `Arc<dyn Protocol>` and is valid for the lifetime of the
    /// `Protocols` borrow.
    ///
    /// # Usage in native handlers
    ///
    /// ```ignore
    /// let dhttp = request.protocols().get::<DHttpProtocol>().unwrap();
    /// ```
    ///
    /// # Usage in hyper handlers
    ///
    /// ```ignore
    /// let protocols = request.extensions().get::<Arc<Protocols>>().unwrap();
    /// let dhttp = protocols.get::<DHttpProtocol>().unwrap();
    /// ```
    ///
    /// # Panics
    ///
    /// Never panics. Returns `None` if the protocol type was not registered.
    /// The internal `expect` guards against `TypeId` hash collisions (a theoretical
    /// impossibility) and is not reachable under normal operation.
    pub fn get<L: Any>(&self) -> Option<&L> {
        self.layers.get(&TypeId::of::<L>()).map(|layer| {
            (layer.as_ref() as &dyn Any)
                .downcast_ref()
                .expect("TypeId collision for protocol layers, this is a bug")
        })
    }

    pub fn insert<L: Protocol>(&mut self, layer: L) {
        self.layers.insert(TypeId::of::<L>(), Arc::new(layer));
    }

    pub(crate) async fn accept_uni(
        &self,
        mut stream: ErasedPeekableUniStream,
    ) -> Result<StreamVerdict<ErasedPeekableUniStream>, StreamError> {
        for layer in self.layers.values() {
            match layer.accept_uni(stream).await? {
                StreamVerdict::Accepted => return Ok(StreamVerdict::Accepted),
                StreamVerdict::Passed(mut passed) => {
                    Pin::new(&mut passed).reset();
                    stream = passed
                }
            }
        }
        Ok(StreamVerdict::Passed(stream))
    }

    pub(crate) async fn accept_bi(
        &self,
        mut stream: ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        for layer in self.layers.values() {
            match layer.accept_bi(stream).await? {
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

pub trait ProductProtocol<C: quic::Connection + ?Sized>: Any + Send + Sync + Hash + Eq {
    type Protocol: Protocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>>;
}

pub(crate) trait InitProtocols<C: quic::Connection + ?Sized>: Send + Sync {
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a mut Protocols,
    ) -> BoxFuture<'a, Result<(), ConnectionError>>;
}

impl<C: quic::Connection + ?Sized, P: ProductProtocol<C>> InitProtocols<C> for P {
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a mut Protocols,
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
}

/// Computes a deterministic identity hash for a `ProductProtocol` factory,
/// combining its `TypeId` and value hash.
pub(crate) fn compute_factory_identity<C: quic::Connection + ?Sized, F: ProductProtocol<C>>(
    factory: &F,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    TypeId::of::<F>().hash(&mut hasher);
    factory.hash(&mut hasher);
    hasher.finish()
}

/// Protocol layer trait for handling QUIC streams in a layered architecture.
/// Layers can inspect, accept, or pass through streams to underlying layers.
pub trait Protocol: Any + Send + Sync + Debug {
    /// Handles an incoming unidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>>;

    /// Handles an incoming bidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>>;
}

/// Verdict for stream handling in protocol layers.
#[derive(Debug)]
pub enum StreamVerdict<S> {
    /// The stream was accepted and handled by this layer.
    Accepted,
    /// The stream was not handled and should be passed to the next layer.
    Passed(S),
}

#[cfg(all(test, feature = "gm-quic"))]
mod tests {
    use std::{collections::hash_map::DefaultHasher, hash::Hasher, sync::Arc};

    use futures::future::BoxFuture;

    use super::*;
    use crate::quic::{self, ConnectionError};

    // Minimal mock protocol (runtime layer).
    #[derive(Debug)]
    struct MockProtocol;

    impl Protocol for MockProtocol {
        fn accept_uni<'a>(
            &'a self,
            stream: ErasedPeekableUniStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }

        fn accept_bi<'a>(
            &'a self,
            stream: ErasedPeekableBiStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }
    }

    /// Test-only mock protocol factory.
    #[derive(Debug, Clone, Hash, PartialEq, Eq)]
    struct MockFactory(u64);

    impl<C: quic::Connection + ?Sized> ProductProtocol<C> for MockFactory {
        type Protocol = MockProtocol;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in identity tests")
        }
    }

    /// Second mock for cross-type tests.
    #[derive(Debug, Clone, Hash, PartialEq, Eq)]
    struct MockFactory2(u64);

    // Use a different protocol type to avoid TypeId collision on Protocol.
    #[derive(Debug)]
    struct MockProtocol2;

    impl Protocol for MockProtocol2 {
        fn accept_uni<'a>(
            &'a self,
            stream: ErasedPeekableUniStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }

        fn accept_bi<'a>(
            &'a self,
            stream: ErasedPeekableBiStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }
    }

    impl<C: quic::Connection + ?Sized> ProductProtocol<C> for MockFactory2 {
        type Protocol = MockProtocol2;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in identity tests")
        }
    }

    fn compute_identity<C: quic::Connection + ?Sized, F: ProductProtocol<C>>(f: &F) -> u64 {
        compute_factory_identity::<C, F>(f)
    }

    #[cfg(feature = "gm-quic")]
    type C = gm_quic::prelude::Connection;

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_hash_same_value_same_hash() {
        let a = MockFactory(42);
        let b = MockFactory(42);
        assert_eq!(compute_identity::<C, _>(&a), compute_identity::<C, _>(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_hash_different_value_different_hash() {
        let a = MockFactory(1);
        let b = MockFactory(2);
        assert_ne!(compute_identity::<C, _>(&a), compute_identity::<C, _>(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn identity_hash_different_type_different_hash() {
        let a = MockFactory(1);
        let b = MockFactory2(1);
        assert_ne!(compute_identity::<C, _>(&a), compute_identity::<C, _>(&b));
    }
}
