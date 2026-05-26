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
//! `Arc<dyn quic::DynConnection>` or equivalent trait objects).
//!
//! # Handler access pattern
//!
//! Raw handlers receive protocol access through
//! [`crate::endpoint::server::UnresolvedRequest::connection`], which exposes
//! connection-scoped protocol state. Combined with [`crate::stream_id::StreamId`],
//! a handler can derive per-request/session handles from that state:
//!
//! ```ignore
//! // Raw h3x handler:
//! let dhttp = request.connection.protocols().get::<DHttpProtocol>().unwrap();
//! let stream_id = request.stream_id;
//!
//! // Hypothetical extension protocol:
//! let proto = request.protocols().get::<MyProtocol>().expect("MyProtocol required");
//! let session = proto.create_session(request.stream_id);
//! ```
//!
//! In hyper handlers, the same data is available via request extensions:
//!
//! ```ignore
//! let stream_id = request.extensions().get::<StreamId>().unwrap();
//! let connection = request
//!     .extensions()
//!     .get::<Arc<ConnectionState<dyn DynConnection>>>()
//!     .unwrap();
//! let proto = connection.protocols().get::<MyProtocol>().unwrap();
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
//!    [`crate::codec::BoxWriteStream`], or [`crate::quic::DynConnection`] to hold
//!    connection capabilities without leaking generic `C`.

use std::{
    any::{Any, TypeId},
    collections::{HashMap, hash_map::DefaultHasher},
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    ops,
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
    /// let connection = request
    ///     .extensions()
    ///     .get::<Arc<ConnectionState<dyn DynConnection>>>()
    ///     .unwrap();
    /// let dhttp = connection.protocols().get::<DHttpProtocol>().unwrap();
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

pub trait ProductProtocol<C: quic::Connection>:
    Any + Send + Sync + Hash + Eq + fmt::Display + fmt::Debug
{
    type Protocol: Protocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>>;
}

pub(crate) trait InitProtocols<C: quic::Connection>:
    Send + Sync + fmt::Display + fmt::Debug
{
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a mut Protocols,
    ) -> BoxFuture<'a, Result<(), ConnectionError>>;
}

impl<C: quic::Connection, P: ProductProtocol<C>> InitProtocols<C> for P {
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

pub(crate) struct IdentifiedProtocolInitializer<C> {
    identity: u64,
    init: Box<dyn InitProtocols<C>>,
}

impl<C: quic::Connection> IdentifiedProtocolInitializer<C> {
    pub fn new<F: ProductProtocol<C>>(factory: F) -> Self {
        let identity = {
            let mut hasher = DefaultHasher::new();
            TypeId::of::<F>().hash(&mut hasher);
            factory.hash(&mut hasher);
            hasher.finish()
        };
        Self {
            identity,
            init: Box::new(factory),
        }
    }
}

impl<C> ops::Deref for IdentifiedProtocolInitializer<C> {
    type Target = dyn InitProtocols<C>;

    fn deref(&self) -> &Self::Target {
        &*self.init
    }
}

impl<C> Hash for IdentifiedProtocolInitializer<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}

impl<C> PartialEq for IdentifiedProtocolInitializer<C> {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl<C> Eq for IdentifiedProtocolInitializer<C> {}

impl<C> fmt::Debug for IdentifiedProtocolInitializer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.init, f)
    }
}

impl<C> fmt::Display for IdentifiedProtocolInitializer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.init, f)
    }
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

#[cfg(all(test, feature = "dquic"))]
mod tests {
    use std::{
        borrow::Cow,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use dhttp_identity::identity as agent;
    use futures::{
        Sink, Stream,
        future::{BoxFuture, pending},
    };

    use super::*;
    use crate::{
        codec::{BoxReadStream, BoxWriteStream, PeekableStreamReader, SinkWriter, StreamReader},
        error::Code,
        quic::{self, CancelStream, ConnectionError, GetStreamId, StopStream},
        varint::VarInt,
    };

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

    #[derive(Debug)]
    enum TestVerdict {
        Accepted,
        Passed,
        Error,
    }

    #[derive(Debug)]
    struct VerdictProtocol {
        uni: TestVerdict,
        bi: TestVerdict,
    }

    fn verdict_error() -> StreamError {
        StreamError::Reset {
            code: VarInt::from_u32(0x0102),
        }
    }

    impl Protocol for VerdictProtocol {
        fn accept_uni<'a>(
            &'a self,
            stream: ErasedPeekableUniStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
            Box::pin(async move {
                match self.uni {
                    TestVerdict::Accepted => Ok(StreamVerdict::Accepted),
                    TestVerdict::Passed => Ok(StreamVerdict::Passed(stream)),
                    TestVerdict::Error => Err(verdict_error()),
                }
            })
        }

        fn accept_bi<'a>(
            &'a self,
            stream: ErasedPeekableBiStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
            Box::pin(async move {
                match self.bi {
                    TestVerdict::Accepted => Ok(StreamVerdict::Accepted),
                    TestVerdict::Passed => Ok(StreamVerdict::Passed(stream)),
                    TestVerdict::Error => Err(verdict_error()),
                }
            })
        }
    }

    fn peekable_uni_stream() -> ErasedPeekableUniStream {
        let (reader, _writer) = quic::test::mock_stream_pair(VarInt::from_u32(0));
        PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxReadStream))
    }

    fn peekable_bi_stream() -> ErasedPeekableBiStream {
        let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(4));
        (
            PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxReadStream)),
            SinkWriter::new(Box::pin(writer) as BoxWriteStream),
        )
    }

    #[derive(Debug)]
    struct TestLocalAgent;

    impl agent::LocalAgent for TestLocalAgent {
        fn name(&self) -> &str {
            "test-local"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }

        fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ED25519
        }

        fn sign(
            &self,
            _scheme: rustls::SignatureScheme,
            _data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, agent::SignError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Debug)]
    struct TestRemoteAgent;

    impl agent::RemoteAgent for TestRemoteAgent {
        fn name(&self) -> &str {
            "test-remote"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Debug)]
    struct TestReadStream;

    impl GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct TestWriteStream;

    impl GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl CancelStream for TestWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct TestConnection;

    impl quic::ManageStream for TestConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
            pending().await
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, ConnectionError> {
            pending().await
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAgent for TestConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAgent for TestConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for TestConnection {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> ConnectionError {
            pending().await
        }
    }

    #[derive(Debug, Clone)]
    struct CountingFactory {
        id: u64,
        calls: Arc<AtomicUsize>,
    }

    impl PartialEq for CountingFactory {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for CountingFactory {}

    impl Hash for CountingFactory {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    impl fmt::Display for CountingFactory {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "CountingFactory({})", self.id)
        }
    }

    impl ProductProtocol<TestConnection> for CountingFactory {
        type Protocol = MockProtocol;

        fn init<'a>(
            &'a self,
            _: &'a Arc<TestConnection>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(MockProtocol)
            })
        }
    }

    /// Test-only mock protocol factory.
    #[derive(Debug, Clone, Hash, PartialEq, Eq)]
    struct MockFactoryFoo(u64);

    impl fmt::Display for MockFactoryFoo {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockFactory")
        }
    }

    impl<C: quic::Connection> ProductProtocol<C> for MockFactoryFoo {
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
    struct MockFactoryBar(u64);

    impl fmt::Display for MockFactoryBar {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockFactory2")
        }
    }

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

    impl<C: quic::Connection> ProductProtocol<C> for MockFactoryBar {
        type Protocol = MockProtocol2;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in identity tests")
        }
    }

    fn identity<C: quic::Connection, F: ProductProtocol<C>>(
        f: F,
    ) -> IdentifiedProtocolInitializer<C> {
        IdentifiedProtocolInitializer::new(f)
    }

    #[cfg(feature = "dquic")]
    type C = dquic::prelude::Connection;

    #[cfg(feature = "dquic")]
    #[test]
    fn identity_hash_same_value_same_hash() {
        let a = MockFactoryFoo(42);
        let b = MockFactoryFoo(42);
        assert_eq!(identity::<C, _>(a), identity::<C, _>(b));
    }

    #[cfg(feature = "dquic")]
    #[test]
    fn identity_hash_different_value_different_hash() {
        let a = MockFactoryFoo(1);
        let b = MockFactoryFoo(2);
        assert_ne!(identity::<C, _>(a), identity::<C, _>(b));
    }

    #[cfg(feature = "dquic")]
    #[test]
    fn identity_hash_different_type_different_hash() {
        let a = MockFactoryFoo(1);
        let b = MockFactoryBar(1);
        assert_ne!(identity::<C, _>(a), identity::<C, _>(b));
    }

    #[test]
    fn protocol_registry_get_insert_and_debug() {
        let mut protocols = Protocols::new();
        assert!(protocols.get::<MockProtocol>().is_none());

        protocols.insert(MockProtocol);
        assert!(protocols.get::<MockProtocol>().is_some());
        assert!(format!("{protocols:?}").contains("MockProtocol"));
    }

    #[tokio::test]
    async fn protocol_registry_accept_uni_covers_accept_pass_and_error() {
        let mut accepted = Protocols::new();
        accepted.insert(VerdictProtocol {
            uni: TestVerdict::Accepted,
            bi: TestVerdict::Passed,
        });
        assert!(matches!(
            accepted
                .accept_uni(peekable_uni_stream())
                .await
                .expect("accepted uni verdict"),
            StreamVerdict::Accepted
        ));

        let mut passed = Protocols::new();
        passed.insert(VerdictProtocol {
            uni: TestVerdict::Passed,
            bi: TestVerdict::Passed,
        });
        assert!(matches!(
            passed
                .accept_uni(peekable_uni_stream())
                .await
                .expect("passed uni verdict"),
            StreamVerdict::Passed(_)
        ));

        let mut errored = Protocols::new();
        errored.insert(VerdictProtocol {
            uni: TestVerdict::Error,
            bi: TestVerdict::Passed,
        });
        let error = match errored.accept_uni(peekable_uni_stream()).await {
            Ok(_) => panic!("errored protocol must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, StreamError::Reset { code } if code == VarInt::from_u32(0x0102)));
    }

    #[tokio::test]
    async fn protocol_registry_accept_bi_covers_accept_pass_and_error() {
        let mut accepted = Protocols::new();
        accepted.insert(VerdictProtocol {
            uni: TestVerdict::Passed,
            bi: TestVerdict::Accepted,
        });
        assert!(matches!(
            accepted
                .accept_bi(peekable_bi_stream())
                .await
                .expect("accepted bidi verdict"),
            StreamVerdict::Accepted
        ));

        let mut passed = Protocols::new();
        passed.insert(VerdictProtocol {
            uni: TestVerdict::Passed,
            bi: TestVerdict::Passed,
        });
        assert!(matches!(
            passed
                .accept_bi(peekable_bi_stream())
                .await
                .expect("passed bidi verdict"),
            StreamVerdict::Passed(_)
        ));

        let mut errored = Protocols::new();
        errored.insert(VerdictProtocol {
            uni: TestVerdict::Passed,
            bi: TestVerdict::Error,
        });
        let error = match errored.accept_bi(peekable_bi_stream()).await {
            Ok(_) => panic!("errored protocol must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, StreamError::Reset { code } if code == VarInt::from_u32(0x0102)));
    }

    #[tokio::test]
    async fn identified_initializer_delegates_formatting_and_initializes_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let initializer = IdentifiedProtocolInitializer::new(CountingFactory {
            id: 7,
            calls: calls.clone(),
        });
        let conn = Arc::new(TestConnection);
        let mut protocols = Protocols::new();

        assert_eq!(initializer.to_string(), "CountingFactory(7)");
        assert!(format!("{initializer:?}").contains("CountingFactory"));

        initializer
            .init_protocols(&conn, &mut protocols)
            .await
            .expect("protocol initializes");
        initializer
            .init_protocols(&conn, &mut protocols)
            .await
            .expect("duplicate init is skipped");

        assert!(protocols.get::<MockProtocol>().is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
