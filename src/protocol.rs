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
        collections::HashSet,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use dhttp_identity::identity::{self as authority, LocalAuthority as _, RemoteAuthority as _};
    use futures::{
        FutureExt, Sink, SinkExt, Stream,
        future::{BoxFuture, pending},
        task::noop_waker_ref,
    };
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::{
        codec::{BoxReadStream, BoxWriteStream, PeekableStreamReader, SinkWriter, StreamReader},
        error::Code,
        quic::{
            self, ConnectionError, GetStreamId, Lifecycle, ManageStream, ResetStream, StopStream,
            WithLocalAuthority, WithRemoteAuthority,
        },
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

    async fn peekable_uni_stream_with_bytes(bytes: &[u8]) -> ErasedPeekableUniStream {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(0));
        writer
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test uni bytes");
        writer.close().await.expect("close test uni stream");
        PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxReadStream))
    }

    async fn peekable_bi_stream_with_bytes(bytes: &[u8]) -> ErasedPeekableBiStream {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(4));
        writer
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test bidi bytes");
        writer.close().await.expect("close test bidi stream");
        (
            PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxReadStream)),
            SinkWriter::new(Box::pin(writer) as BoxWriteStream),
        )
    }

    #[derive(Debug, Default)]
    struct RoutingObservation {
        calls: AtomicUsize,
        reads: Mutex<Vec<Vec<u8>>>,
    }

    #[derive(Debug)]
    struct RoutedProtocol<const ID: u8> {
        observation: Arc<RoutingObservation>,
    }

    impl<const ID: u8> Protocol for RoutedProtocol<ID> {
        fn accept_uni<'a>(
            &'a self,
            stream: ErasedPeekableUniStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
            Box::pin(async move {
                let mut stream = stream;
                let call = self.observation.calls.fetch_add(1, Ordering::SeqCst);
                let read_len = if call == 0 { 1 } else { 2 };
                let mut buf = vec![0; read_len];
                stream
                    .read_exact(&mut buf)
                    .await
                    .expect("read routed uni bytes");
                self.observation
                    .reads
                    .lock()
                    .expect("lock routed uni observation")
                    .push(buf);
                if call == 0 {
                    Ok(StreamVerdict::Passed(stream))
                } else {
                    Ok(StreamVerdict::Accepted)
                }
            })
        }

        fn accept_bi<'a>(
            &'a self,
            stream: ErasedPeekableBiStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
            Box::pin(async move {
                let mut stream = stream;
                let call = self.observation.calls.fetch_add(1, Ordering::SeqCst);
                let read_len = if call == 0 { 1 } else { 2 };
                let mut buf = vec![0; read_len];
                stream
                    .0
                    .read_exact(&mut buf)
                    .await
                    .expect("read routed bidi bytes");
                self.observation
                    .reads
                    .lock()
                    .expect("lock routed bidi observation")
                    .push(buf);
                if call == 0 {
                    Ok(StreamVerdict::Passed(stream))
                } else {
                    Ok(StreamVerdict::Accepted)
                }
            })
        }
    }

    #[derive(Debug)]
    struct TestLocalAuthority;

    impl authority::LocalAuthority for TestLocalAuthority {
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
        ) -> BoxFuture<'_, Result<Vec<u8>, authority::SignError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Debug)]
    struct TestRemoteAuthority;

    impl authority::RemoteAuthority for TestRemoteAuthority {
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

    impl ResetStream for TestWriteStream {
        fn poll_reset(
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

    impl quic::WithLocalAuthority for TestConnection {
        type LocalAuthority = TestLocalAuthority;

        async fn local_authority(&self) -> Result<Option<Self::LocalAuthority>, ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAuthority for TestConnection {
        type RemoteAuthority = TestRemoteAuthority;

        async fn remote_authority(&self) -> Result<Option<Self::RemoteAuthority>, ConnectionError> {
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
            Box::pin(async { Ok(MockProtocol) })
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
            Box::pin(async { Ok(MockProtocol2) })
        }
    }

    #[derive(Debug, Clone, Hash, PartialEq, Eq)]
    struct FailingFactory(&'static str);

    impl fmt::Display for FailingFactory {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "FailingFactory({})", self.0)
        }
    }

    impl ProductProtocol<TestConnection> for FailingFactory {
        type Protocol = MockProtocol2;

        fn init<'a>(
            &'a self,
            _: &'a Arc<TestConnection>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            Box::pin(async move {
                Err(ConnectionError::Application {
                    source: quic::ApplicationError {
                        code: Code::H3_INTERNAL_ERROR,
                        reason: Cow::Borrowed("failing factory"),
                    },
                })
            })
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

    #[tokio::test]
    async fn mock_protocol_passes_uni_and_bi_streams() {
        let protocol = MockProtocol;

        let uni = protocol
            .accept_uni(peekable_uni_stream_with_bytes(b"mp").await)
            .await
            .expect("mock protocol passes uni stream");
        let StreamVerdict::Passed(mut uni) = uni else {
            panic!("mock protocol must pass uni stream");
        };
        let mut uni_buf = [0; 2];
        uni.read_exact(&mut uni_buf)
            .await
            .expect("read mock-passed uni bytes");
        assert_eq!(&uni_buf, b"mp");

        let bi = protocol
            .accept_bi(peekable_bi_stream_with_bytes(b"mb").await)
            .await
            .expect("mock protocol passes bidi stream");
        let StreamVerdict::Passed((mut reader, _writer)) = bi else {
            panic!("mock protocol must pass bidi stream");
        };
        let mut bi_buf = [0; 2];
        reader
            .read_exact(&mut bi_buf)
            .await
            .expect("read mock-passed bidi bytes");
        assert_eq!(&bi_buf, b"mb");
    }

    #[tokio::test]
    async fn test_connection_support_traits_return_expected_values() {
        let conn = TestConnection;

        let local = conn
            .local_authority()
            .await
            .expect("local authority lookup succeeds");
        assert!(local.is_none());
        let remote = conn
            .remote_authority()
            .await
            .expect("remote authority lookup succeeds");
        assert!(remote.is_none());
        conn.check().expect("test connection health check succeeds");
        conn.close(Code::H3_NO_ERROR, Cow::Borrowed("test close"));

        assert!(conn.open_bi().now_or_never().is_none());
        assert!(conn.open_uni().now_or_never().is_none());
        assert!(conn.accept_bi().now_or_never().is_none());
        assert!(conn.accept_uni().now_or_never().is_none());
        assert!(conn.closed().now_or_never().is_none());
    }

    #[tokio::test]
    async fn test_agents_and_streams_expose_minimal_trait_behavior() {
        let local = TestLocalAuthority;
        assert_eq!(local.name(), "test-local");
        assert!(local.cert_chain().is_empty());
        assert_eq!(local.sign_algorithm(), rustls::SignatureAlgorithm::ED25519);
        assert_eq!(
            local
                .sign(rustls::SignatureScheme::ED25519, b"payload")
                .await
                .expect("test local authority signs"),
            Vec::<u8>::new()
        );

        let remote = TestRemoteAuthority;
        assert_eq!(remote.name(), "test-remote");
        assert!(remote.cert_chain().is_empty());

        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        let mut reader = TestReadStream;
        assert!(matches!(
            Pin::new(&mut reader).poll_stream_id(&mut cx),
            Poll::Ready(Ok(id)) if id == VarInt::from_u32(0)
        ));
        assert!(matches!(
            Pin::new(&mut reader).poll_stop(&mut cx, VarInt::from_u32(7)),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut reader).poll_next(&mut cx),
            Poll::Ready(None)
        ));

        let mut writer = TestWriteStream;
        assert!(matches!(
            Pin::new(&mut writer).poll_stream_id(&mut cx),
            Poll::Ready(Ok(id)) if id == VarInt::from_u32(0)
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_reset(&mut cx, VarInt::from_u32(8)),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"ignored"))
            .expect("writer send succeeds");
        assert!(matches!(
            Pin::new(&mut writer).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_close(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn protocol_registry_get_insert_and_debug() {
        let mut protocols = Protocols::new();
        assert_eq!(format!("{protocols:?}"), "[]");
        assert!(protocols.get::<MockProtocol>().is_none());

        protocols.insert(MockProtocol);
        protocols.insert(MockProtocol2);
        assert!(protocols.get::<MockProtocol>().is_some());
        assert!(protocols.get::<MockProtocol2>().is_some());
        let debug = format!("{protocols:?}");
        assert!(debug.contains("MockProtocol"));
        assert!(debug.contains("MockProtocol2"));
    }

    #[tokio::test]
    async fn protocol_registry_accept_uni_passes_through_empty_registry() {
        let protocols = Protocols::default();
        let verdict = protocols
            .accept_uni(peekable_uni_stream_with_bytes(b"ok").await)
            .await
            .expect("empty registry must pass uni stream");
        let StreamVerdict::Passed(mut stream) = verdict else {
            panic!("empty registry must not accept uni stream");
        };

        let mut buf = [0; 2];
        stream
            .read_exact(&mut buf)
            .await
            .expect("read passed uni bytes");
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test]
    async fn protocol_registry_accept_bi_passes_through_empty_registry() {
        let protocols = Protocols::default();
        let verdict = protocols
            .accept_bi(peekable_bi_stream_with_bytes(b"bi").await)
            .await
            .expect("empty registry must pass bidi stream");
        let StreamVerdict::Passed((mut reader, _writer)) = verdict else {
            panic!("empty registry must not accept bidi stream");
        };

        let mut buf = [0; 2];
        reader
            .read_exact(&mut buf)
            .await
            .expect("read passed bidi bytes");
        assert_eq!(&buf, b"bi");
    }

    #[tokio::test]
    async fn protocol_registry_accept_uni_resets_stream_before_next_layer() {
        let observation = Arc::new(RoutingObservation::default());
        let mut protocols = Protocols::new();
        protocols.insert(RoutedProtocol::<1> {
            observation: observation.clone(),
        });
        protocols.insert(RoutedProtocol::<2> {
            observation: observation.clone(),
        });

        let verdict = protocols
            .accept_uni(peekable_uni_stream_with_bytes(b"ab").await)
            .await
            .expect("layered uni routing succeeds");
        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(observation.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *observation
                .reads
                .lock()
                .expect("lock layered uni observation"),
            vec![b"a".to_vec(), b"ab".to_vec()]
        );
    }

    #[tokio::test]
    async fn protocol_registry_accept_bi_resets_stream_before_next_layer() {
        let observation = Arc::new(RoutingObservation::default());
        let mut protocols = Protocols::new();
        protocols.insert(RoutedProtocol::<1> {
            observation: observation.clone(),
        });
        protocols.insert(RoutedProtocol::<2> {
            observation: observation.clone(),
        });

        let verdict = protocols
            .accept_bi(peekable_bi_stream_with_bytes(b"cd").await)
            .await
            .expect("layered bidi routing succeeds");
        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(observation.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *observation
                .reads
                .lock()
                .expect("lock layered bidi observation"),
            vec![b"c".to_vec(), b"cd".to_vec()]
        );
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

    #[test]
    fn identified_initializer_hashes_and_compares_by_factory_identity() {
        let initializers = HashSet::from([
            identity::<C, _>(MockFactoryFoo(1)),
            identity::<C, _>(MockFactoryFoo(1)),
            identity::<C, _>(MockFactoryFoo(2)),
            identity::<C, _>(MockFactoryBar(1)),
        ]);

        assert_eq!(initializers.len(), 3);
    }

    #[test]
    fn mock_factories_format_and_compare_by_configured_identity() {
        let calls = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            CountingFactory {
                id: 9,
                calls: calls.clone(),
            },
            CountingFactory { id: 9, calls }
        );
        assert_ne!(
            CountingFactory {
                id: 9,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            CountingFactory {
                id: 10,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        );

        assert_eq!(MockFactoryFoo(1).to_string(), "MockFactory");
        assert_eq!(MockFactoryBar(1).to_string(), "MockFactory2");
        assert_eq!(
            FailingFactory("format").to_string(),
            "FailingFactory(format)"
        );
    }

    #[tokio::test]
    async fn mock_factory_initializers_insert_their_protocols() {
        let conn = Arc::new(TestConnection);
        let mut protocols = Protocols::new();

        MockFactoryFoo(11)
            .init_protocols(&conn, &mut protocols)
            .await
            .expect("foo factory initializes mock protocol");
        MockFactoryBar(12)
            .init_protocols(&conn, &mut protocols)
            .await
            .expect("bar factory initializes second mock protocol");

        assert!(protocols.get::<MockProtocol>().is_some());
        assert!(protocols.get::<MockProtocol2>().is_some());
    }

    #[tokio::test]
    async fn second_mock_protocol_passes_uni_and_bi_streams() {
        let protocol = MockProtocol2;

        let uni = protocol
            .accept_uni(peekable_uni_stream_with_bytes(b"u2").await)
            .await
            .expect("second mock protocol passes uni stream");
        let StreamVerdict::Passed(mut uni) = uni else {
            panic!("second mock protocol must pass uni stream");
        };
        let mut uni_buf = [0; 2];
        uni.read_exact(&mut uni_buf)
            .await
            .expect("read second mock-passed uni bytes");
        assert_eq!(&uni_buf, b"u2");

        let bi = protocol
            .accept_bi(peekable_bi_stream_with_bytes(b"b2").await)
            .await
            .expect("second mock protocol passes bidi stream");
        let StreamVerdict::Passed((mut reader, _writer)) = bi else {
            panic!("second mock protocol must pass bidi stream");
        };
        let mut bi_buf = [0; 2];
        reader
            .read_exact(&mut bi_buf)
            .await
            .expect("read second mock-passed bidi bytes");
        assert_eq!(&bi_buf, b"b2");
    }

    #[tokio::test]
    async fn identified_initializer_propagates_init_errors_without_inserting_protocol() {
        let initializer = IdentifiedProtocolInitializer::new(FailingFactory("boom"));
        let conn = Arc::new(TestConnection);
        let mut protocols = Protocols::new();
        let init: &dyn InitProtocols<TestConnection> = ops::Deref::deref(&initializer);

        let error = init
            .init_protocols(&conn, &mut protocols)
            .await
            .expect_err("failing initializer must propagate connection error");

        assert!(matches!(
            error,
            ConnectionError::Application { source }
                if source.code == Code::H3_INTERNAL_ERROR
                    && source.reason == Cow::Borrowed("failing factory")
        ));
        assert!(protocols.get::<MockProtocol2>().is_none());
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
