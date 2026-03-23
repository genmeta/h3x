use std::{
    any::Any,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    io,
    marker::PhantomData,
    ops,
    sync::Arc,
};

use futures::{FutureExt, future::BoxFuture};
use snafu::Snafu;
use tracing::Instrument;

use crate::{
    codec::{self, PeekableStreamReader, SinkWriter, StreamReader},
    dhttp::{protocol::DHttpProtocolFactory, settings::Settings},
    error::{Code, ErrorScope, H3Error},
    protocol::{InitProtocols, ProductProtocol, Protocols, StreamVerdict, compute_factory_identity},
    qpack::protocol::QPackProtocolFactory,
    quic::{self, CancelStreamExt, StopStreamExt, agent},
    util::watch::Watch,
    varint::VarInt,
};

#[derive(Debug, Snafu, Clone)]
pub enum StreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Code {
        source: Arc<dyn H3Error + Send + Sync>,
    },
}

impl From<quic::ConnectionError> for StreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl StreamError {
    pub fn map_stream_reset(self, map: impl FnOnce(VarInt) -> Self) -> Self {
        match self {
            StreamError::Quic {
                source: quic::StreamError::Reset { code },
            } => map(code),
            error => error,
        }
    }
}

impl<E: H3Error + Send + Sync + 'static> From<E> for StreamError {
    fn from(value: E) -> Self {
        StreamError::Code {
            source: Arc::new(value),
        }
    }
}

/// Error converting between `StreamError` and `io::Error`.
///
/// This conversion bridges h3x stream errors through tokio's io::Error boundary.
/// The `io::Error` is constructed with `io::Error::other()`, preserving the original
/// `StreamError` as the inner error for later recovery via downcast.
impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        io::Error::other(value)
    }
}

/// Reverse conversion: recovers a `StreamError` from an `io::Error`.
///
/// This is used at codec/stream boundaries where errors pass through
/// `io::Error`-based interfaces (e.g., `AsyncRead`/`AsyncWrite`).
/// Recovery attempts: StreamError → quic::StreamError → H3Error (dyn).
/// If none match, this is a logic error (unreachable).
impl From<io::Error> for StreamError {
    fn from(source: io::Error) -> Self {
        let error = match source.downcast::<StreamError>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        let error = match quic::StreamError::try_from(error) {
            Ok(error) => return error.into(),
            Err(error) => error,
        };
        match error.downcast::<Arc<dyn H3Error + Send + Sync + 'static>>() {
            Ok(error) => error.into(),
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to connection::StreamError, this is a bug"
            ),
        }
    }
}

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionGoaway {
    #[snafu(display("local goaway"))]
    Local,
    #[snafu(display("peer goaway"))]
    Peer,
}

/// Extension trait providing error-handling helpers on any `Lifecycle` type.
pub trait LifecycleExt: quic::Lifecycle + Sync {
    /// Map h3-level StreamError to quic::StreamError, closing connection for connection-scope errors.
    fn handle_stream_error(&self, error: StreamError) -> BoxFuture<'_, quic::StreamError> {
        Box::pin(async move {
            match error {
                StreamError::Quic { source } => match source {
                    quic::StreamError::Connection { source } => {
                        self.handle_connection_error(source).await.into()
                    }
                    quic::StreamError::Reset { .. } => source,
                },
                StreamError::Code { source } => match source.scope() {
                    ErrorScope::Stream => quic::StreamError::Reset {
                        code: source.code().into_inner(),
                    },
                    ErrorScope::Connection => {
                        self.close(source.code(), source.to_string().into());
                        self.closed().await.into()
                    }
                },
            }
        })
    }

    /// Handle a connection-scope error. The connection is already dead.
    fn handle_connection_error(
        &self,
        error: quic::ConnectionError,
    ) -> BoxFuture<'_, quic::ConnectionError> {
        Box::pin(async move { error })
    }
}

impl<T: quic::Lifecycle + Sync + ?Sized> LifecycleExt for T {}

pub struct ConnectionBuilder<C: Any + ?Sized> {
    protocols_initializers: Vec<(u64, Box<dyn InitProtocols<C>>)>,
    _connection: PhantomData<C>,
}

impl<C: Any + ?Sized> fmt::Debug for ConnectionBuilder<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionBuilder")
            .field("protocols_count", &self.protocols_initializers.len())
            .finish()
    }
}

impl<C: quic::Connection> ConnectionBuilder<C> {
    pub fn new(settings: Arc<Settings>) -> Self {
        let builder = Self {
            protocols_initializers: Vec::new(),
            _connection: PhantomData,
        };
        builder
            .protocol(DHttpProtocolFactory::new(settings))
            .protocol(QPackProtocolFactory::new())
    }

    pub fn protocol<F: ProductProtocol<C>>(mut self, factory: F) -> Self {
        let identity = compute_factory_identity::<C, F>(&factory);
        self.protocols_initializers.push((identity, Box::new(factory)));
        self
    }

    pub async fn build(&self, quic: C) -> Result<Connection<C>, quic::ConnectionError>
    where
        C: Sized,
    {
        let quic = Arc::new(quic);
        let mut protocols = Protocols::new();

        for (_identity, initializer) in &self.protocols_initializers {
            initializer.init_protocols(&quic, &mut protocols).await?;
        }

        let protocols = Arc::new(protocols);
        let state = ConnectionState {
            quic,
            protocols,
            terminal_error: Watch::new(),
        };
        tokio::spawn(ConnectionState::observe_close_task(state.clone()).in_current_span());
        tokio::spawn(ConnectionState::accept_uni_stream_task(state.clone()).in_current_span());
        tokio::spawn(ConnectionState::accept_bi_stream_task(state.clone()).in_current_span());

        Ok(Connection(state))
    }
}

impl<C: quic::Connection + ?Sized> Hash for ConnectionBuilder<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Sort by identity hash for order-independent hashing
        let mut identities: Vec<u64> = self
            .protocols_initializers
            .iter()
            .map(|(id, _)| *id)
            .collect();
        identities.sort();
        for id in &identities {
            id.hash(state);
        }
    }
}

impl<C: quic::Connection + ?Sized> PartialEq for ConnectionBuilder<C> {
    fn eq(&self, other: &Self) -> bool {
        if self.protocols_initializers.len() != other.protocols_initializers.len() {
            return false;
        }
        let mut self_ids: Vec<u64> = self
            .protocols_initializers
            .iter()
            .map(|(id, _)| *id)
            .collect();
        let mut other_ids: Vec<u64> = other
            .protocols_initializers
            .iter()
            .map(|(id, _)| *id)
            .collect();
        self_ids.sort();
        other_ids.sort();
        self_ids == other_ids
    }
}

impl<C: quic::Connection + ?Sized> Eq for ConnectionBuilder<C> {}

#[derive(Debug)]
pub struct ConnectionState<C: ?Sized> {
    quic: Arc<C>,
    protocols: Arc<Protocols>,
    terminal_error: Watch<quic::ConnectionError>,
}

impl<C: ?Sized> ConnectionState<C> {
    pub fn quic(&self) -> &Arc<C> {
        &self.quic
    }

    pub fn protocol<P: Any>(&self) -> Option<&P> {
        self.protocols.get::<P>()
    }

    pub fn protocols(&self) -> &Arc<Protocols> {
        &self.protocols
    }

    fn record_terminal_error(&self, error: quic::ConnectionError) {
        self.terminal_error.set(error);
    }
}

impl<C: quic::Lifecycle + ?Sized> ConnectionState<C> {
    /// Returns locally observed connection health.
    ///
    /// This is a synchronous, deterministic view of whether this process has
    /// already observed the connection to fail. Terminal errors are latched the
    /// first time they are seen, so later `check()` calls do not rely on async RPC.
    pub fn check(&self) -> Result<(), quic::ConnectionError> {
        if let Some(error) = self.terminal_error.peek() {
            return Err(error);
        }

        match self.quic.check() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.record_terminal_error(error.clone());
                Err(error)
            }
        }
    }

    pub fn closed(&self) -> BoxFuture<'_, quic::ConnectionError> {
        let terminal_error = self.terminal_error.clone();
        if let Some(error) = terminal_error.peek() {
            return futures::future::ready(error).boxed();
        }

        self.quic
            .closed()
            .map(move |error| {
                terminal_error.set(error.clone());
                error
            })
            .boxed()
    }

    pub fn close(&self, code: Code, reason: impl Into<std::borrow::Cow<'static, str>>) {
        self.quic.close(code, reason.into());
    }

    async fn observe_close_task(state: Self) {
        let error = state.quic.closed().await;
        state.record_terminal_error(error);
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(quic: Arc<C>, protocols: Arc<Protocols>) -> Self {
        Self {
            quic,
            protocols,
            terminal_error: Watch::new(),
        }
    }
}

impl<C: quic::ManageStream + quic::Lifecycle + Sync + ?Sized> ConnectionState<C> {
    pub async fn open_bi(
        &self,
    ) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        match { self.quic.open_bi() }.await {
            Ok(streams) => Ok(streams),
            Err(error) => {
                let error = self.quic.handle_connection_error(error).await;
                self.record_terminal_error(error.clone());
                Err(error)
            }
        }
    }

    pub async fn open_uni(&self) -> Result<C::StreamWriter, quic::ConnectionError> {
        match { self.quic.open_uni() }.await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                let error = self.quic.handle_connection_error(error).await;
                self.record_terminal_error(error.clone());
                Err(error)
            }
        }
    }
}

impl<C: quic::WithLocalAgent + ?Sized> ConnectionState<C> {
    pub async fn local_agent(
        &self,
    ) -> Result<Option<Arc<dyn agent::LocalAgent>>, quic::ConnectionError> {
        match self.quic.local_agent().await {
            Ok(option) => Ok(option.map(|a| Arc::new(a) as Arc<dyn agent::LocalAgent>)),
            Err(error) => {
                self.record_terminal_error(error.clone());
                Err(error)
            }
        }
    }
}

impl<C: quic::WithRemoteAgent + ?Sized> ConnectionState<C> {
    pub async fn remote_agent(
        &self,
    ) -> Result<Option<Arc<dyn agent::RemoteAgent>>, quic::ConnectionError> {
        match self.quic.remote_agent().await {
            Ok(option) => Ok(option.map(|a| Arc::new(a) as Arc<dyn agent::RemoteAgent>)),
            Err(error) => {
                self.record_terminal_error(error.clone());
                Err(error)
            }
        }
    }
}

impl<C: quic::Connection + ?Sized> ConnectionState<C> {
    async fn accept_bi_stream_task(state: Self) {
        let task = async {
            loop {
                let (stream_reader, stream_writer) = match state.quic.accept_bi().await {
                    Ok(bi_stream) => bi_stream,
                    Err(error) => {
                        let error = state.quic.handle_connection_error(error).await;
                        state.record_terminal_error(error);
                        return;
                    }
                };
                // Erase the concrete stream types before protocol dispatch.
                let erased_reader = Box::pin(stream_reader) as codec::BoxReadStream;
                let erased_writer = Box::pin(stream_writer) as codec::BoxWriteStream;
                let stream_reader = StreamReader::new(erased_reader);
                let stream_writer = SinkWriter::new(erased_writer);
                let peekable_bi_stream = (PeekableStreamReader::new(stream_reader), stream_writer);

                match state.protocols.accept_bi(peekable_bi_stream).await {
                    Ok(StreamVerdict::Accepted) => continue,
                    // If the stream header indicates a stream type that is not supported by
                    // the recipient, the remainder of the stream cannot be consumed as the
                    // semantics are unknown. Recipients of unknown stream types MUST
                    // either abort reading of the stream or discard incoming data without
                    // further processing. If reading is aborted, the recipient SHOULD use
                    // the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    // (Section 8.1). The recipient MUST NOT consider unknown stream types
                    // to be a connection error of any kind.
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9114#section-9-4
                    Ok(StreamVerdict::Passed((mut stream_reader, mut stream_writer))) => {
                        let code = Code::H3_STREAM_CREATION_ERROR.into_inner();
                        _ = tokio::join!(stream_reader.stop(code), stream_writer.cancel(code))
                    }
                    Err(stream_error) => {
                        state.quic.handle_stream_error(stream_error).await;
                        continue;
                    }
                };
            }
        };
        tokio::select! {
            _ = task => {},
            _ = state.quic.closed() => {},
        }
    }

    async fn accept_uni_stream_task(state: Self) {
        let task = async {
            loop {
                let stream_reader = match state.quic.accept_uni().await {
                    Ok(uni_stream) => uni_stream,
                    Err(error) => {
                        let error = state.quic.handle_connection_error(error).await;
                        state.record_terminal_error(error);
                        return;
                    }
                };
                // Erase the concrete stream type before protocol dispatch.
                let erased_reader = Box::pin(stream_reader) as codec::BoxReadStream;
                let stream_reader = StreamReader::new(erased_reader);
                let peekable_uni_stream = PeekableStreamReader::new(stream_reader);

                match state.protocols.accept_uni(peekable_uni_stream).await {
                    Ok(StreamVerdict::Accepted) => continue,
                    // If the stream header indicates a stream type that is not supported by
                    // the recipient, the remainder of the stream cannot be consumed as the
                    // semantics are unknown. Recipients of unknown stream types MUST
                    // either abort reading of the stream or discard incoming data without
                    // further processing. If reading is aborted, the recipient SHOULD use
                    // the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    // (Section 8.1). The recipient MUST NOT consider unknown stream types
                    // to be a connection error of any kind.
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9114#section-9-4
                    Ok(StreamVerdict::Passed(mut stream_reader)) => {
                        let code = Code::H3_STREAM_CREATION_ERROR.into_inner();
                        let _ = stream_reader.stop(code).await;
                    }
                    Err(stream_error) => {
                        state.quic.handle_stream_error(stream_error).await;
                        continue;
                    }
                };
            }
        };
        tokio::select! {
            _ = task => {},
            _ = state.quic.closed() => {},
        }
    }
}

impl<C: ?Sized> Clone for ConnectionState<C> {
    fn clone(&self) -> Self {
        Self {
            quic: self.quic.clone(),
            protocols: self.protocols.clone(),
            terminal_error: self.terminal_error.clone(),
        }
    }
}

#[derive(Debug)]
pub struct Connection<C: quic::Connection + ?Sized>(ConnectionState<C>);

impl<C: quic::Connection + ?Sized> ops::Deref for Connection<C> {
    type Target = ConnectionState<C>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: quic::Connection + ?Sized> Connection<C> {
    pub async fn new(settings: Arc<Settings>, quic: C) -> Result<Self, quic::ConnectionError>
    where
        C: Sized,
    {
        ConnectionBuilder::new(settings).build(quic).await
    }

    #[cfg(test)]
    pub(crate) fn from_state_for_test(state: ConnectionState<C>) -> Self {
        Self(state)
    }
}

impl<C: quic::Connection + ?Sized> Drop for Connection<C> {
    fn drop(&mut self) {
        self.close(Code::H3_NO_ERROR, "no error");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(feature = "gm-quic")]
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };
    use std::{
        future::pending,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use bytes::Bytes;
    use futures::{Sink, future::BoxFuture, stream::Stream};

    #[cfg(feature = "gm-quic")]
    use super::ConnectionBuilder;
    use super::ConnectionState;
    #[cfg(feature = "gm-quic")]
    use crate::{
        codec::{ErasedPeekableBiStream, ErasedPeekableUniStream},
        connection::StreamError,
        dhttp::settings::{Setting, Settings},
        protocol::{ProductProtocol, Protocol, StreamVerdict},
    };
    use crate::{
        protocol::Protocols,
        quic::{self, ConnectionError, agent},
        varint::VarInt,
    };

    #[derive(Debug)]
    pub(crate) struct TestLocalAgent;

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
    pub(crate) struct TestRemoteAgent;

    impl agent::RemoteAgent for TestRemoteAgent {
        fn name(&self) -> &str {
            "test-remote"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Debug)]
    pub(crate) struct TestReadStream;

    impl quic::GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context,
        ) -> std::task::Poll<Result<VarInt, quic::StreamError>> {
            let _ = self;
            std::task::Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl quic::StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context,
            _code: VarInt,
        ) -> std::task::Poll<Result<(), quic::StreamError>> {
            let _ = self;
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let _ = self;
            std::task::Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    pub(crate) struct TestWriteStream;

    impl quic::GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context,
        ) -> std::task::Poll<Result<VarInt, quic::StreamError>> {
            let _ = self;
            std::task::Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl quic::CancelStream for TestWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context,
            _code: VarInt,
        ) -> std::task::Poll<Result<(), quic::StreamError>> {
            let _ = self;
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            let _ = self;
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            let _ = self;
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            let _ = self;
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            let _ = self;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    pub(crate) struct MockConnectionState {
        check_result: Mutex<Result<(), quic::ConnectionError>>,
        closed_error: Mutex<Option<quic::ConnectionError>>,
    }

    impl Default for MockConnectionState {
        fn default() -> Self {
            Self {
                check_result: Mutex::new(Ok(())),
                closed_error: Mutex::new(None),
            }
        }
    }

    #[derive(Debug, Clone, Default)]
    pub(crate) struct MockConnection {
        state: Arc<MockConnectionState>,
    }

    impl MockConnection {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn set_check_result(&self, result: Result<(), quic::ConnectionError>) {
            *self.state.check_result.lock().unwrap() = result;
        }

        pub(crate) fn set_closed_error(&self, error: quic::ConnectionError) {
            *self.state.closed_error.lock().unwrap() = Some(error);
        }
    }

    impl quic::ManageStream for MockConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        fn open_bi(
            &self,
        ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>
        {
            Box::pin(async { Err(test_connection_error("open_bi unavailable")) })
        }

        fn open_uni(&self) -> BoxFuture<'_, Result<Self::StreamWriter, ConnectionError>> {
            Box::pin(async { Err(test_connection_error("open_uni unavailable")) })
        }

        fn accept_bi(
            &self,
        ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>
        {
            Box::pin(async { Err(test_connection_error("accept_bi unavailable")) })
        }

        fn accept_uni(&self) -> BoxFuture<'_, Result<Self::StreamReader, ConnectionError>> {
            Box::pin(async { Err(test_connection_error("accept_uni unavailable")) })
        }
    }

    impl quic::WithLocalAgent for MockConnection {
        type LocalAgent = TestLocalAgent;

        fn local_agent(&self) -> BoxFuture<'_, Result<Option<Self::LocalAgent>, ConnectionError>> {
            Box::pin(async { Ok(None) })
        }
    }

    impl quic::WithRemoteAgent for MockConnection {
        type RemoteAgent = TestRemoteAgent;

        fn remote_agent(
            &self,
        ) -> BoxFuture<'_, Result<Option<Self::RemoteAgent>, ConnectionError>> {
            Box::pin(async { Ok(None) })
        }
    }

    impl quic::Lifecycle for MockConnection {
        fn close(&self, _code: crate::error::Code, _reason: std::borrow::Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            self.state.check_result.lock().unwrap().clone()
        }

        fn closed(&self) -> BoxFuture<'_, ConnectionError> {
            let closed_error = self.state.closed_error.lock().unwrap().clone();
            Box::pin(async move {
                match closed_error {
                    Some(error) => error,
                    None => pending().await,
                }
            })
        }
    }

    fn test_connection_error(reason: &str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.to_owned().into(),
            },
        }
    }

    fn assert_transport_reason(error: &quic::ConnectionError, expected_reason: &str) {
        match error {
            quic::ConnectionError::Transport { source } => {
                assert_eq!(source.reason.as_ref(), expected_reason);
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    #[cfg(feature = "gm-quic")]
    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    /// Local mock protocol for builder tests.
    #[cfg(feature = "gm-quic")]
    #[derive(Debug)]
    struct MockProtocol;

    #[cfg(feature = "gm-quic")]
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

    /// Local mock factory for builder tests.
    #[cfg(feature = "gm-quic")]
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct MockFactory(u64);

    #[cfg(feature = "gm-quic")]
    impl<C: quic::Connection + ?Sized> ProductProtocol<C> for MockFactory {
        type Protocol = MockProtocol;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in builder identity tests")
        }
    }

    #[cfg(feature = "gm-quic")]
    type C = gm_quic::prelude::Connection;

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_same_settings_equal_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_different_settings_different_hash() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(Setting::max_field_section_size(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);
        let a = ConnectionBuilder::<C>::new(s1);
        let b = ConnectionBuilder::<C>::new(s2);
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_extra_protocol_different_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(42));
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_order_independent_hash() {
        let s = Arc::new(Settings::default());
        // a: DHttpProtocolFactory, QPackProtocolFactory, MockFactory (from new + protocol)
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(7));
        // b: MockFactory first, then DHttpProtocolFactory, QPackProtocolFactory
        let b = {
            let builder = ConnectionBuilder::<C> {
                protocols_initializers: Vec::new(),
                _connection: std::marker::PhantomData,
            };
            builder
                .protocol(MockFactory(7))
                .protocol(crate::dhttp::protocol::DHttpProtocolFactory::new(s))
                .protocol(crate::qpack::protocol::QPackProtocolFactory::new())
        };
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_same_settings_eq() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s);
        assert_eq!(a, b);
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_different_settings_not_eq() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(Setting::max_field_section_size(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);
        let a = ConnectionBuilder::<C>::new(s1);
        let b = ConnectionBuilder::<C>::new(s2);
        assert_ne!(a, b);
    }

    /// Simulates pool key distinction: two builders with different protocol stacks
    /// produce different hashes, so the pool stores them under separate keys.
    #[cfg(feature = "gm-quic")]
    #[test]
    fn pool_key_different_builders_different_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(1));
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(2));
        // Pool computes hash via DefaultHasher the same way hash_of does.
        // Different protocol stacks must yield different keys.
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    /// Simulates pool key reuse: two identical builders produce the same hash,
    /// so the pool correctly groups them under one key for connection reuse.
    #[cfg(feature = "gm-quic")]
    #[test]
    fn pool_key_same_builders_same_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(42));
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(42));
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    /// Verifies hash determinism: hashing the same builder twice yields the same
    /// value, and an identically-constructed builder also matches.
    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_hash_determinism() {
        let s = Arc::new(Settings::default());
        let builder = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(99));
        let h1 = hash_of(&builder);
        let h2 = hash_of(&builder);
        assert_eq!(
            h1, h2,
            "hashing the same builder twice must be deterministic"
        );

        // A second, identically-constructed builder must produce the same hash.
        let builder2 = ConnectionBuilder::<C>::new(s).protocol(MockFactory(99));
        assert_eq!(
            h1,
            hash_of(&builder2),
            "identical builders must hash equally"
        );
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_clone_like_rebuild_hash_determinism() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(100));
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(100));
        assert_eq!(
            hash_of(&a),
            hash_of(&b),
            "builders built via same steps must hash identically"
        );
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_mock_factory_included_in_hash() {
        let s = Arc::new(Settings::default());
        let base = ConnectionBuilder::<C>::new(s.clone());
        let with_mock = ConnectionBuilder::<C>::new(s).protocol(MockFactory(42));
        assert_ne!(
            hash_of(&base),
            hash_of(&with_mock),
            "adding MockFactory must change the hash"
        );
    }

    #[test]
    fn check_latches_terminal_error_after_closed_is_observed() {
        let quic = MockConnection::new();
        let protocols = Arc::new(Protocols::new());
        let state = ConnectionState::new_for_test(Arc::new(quic.clone()), protocols);
        let expected = test_connection_error("closed");

        quic.set_check_result(Ok(()));
        quic.set_closed_error(expected.clone());

        let observed = futures::executor::block_on(state.closed());
        assert_transport_reason(&observed, "closed");

        quic.set_check_result(Ok(()));
        let check_error = state.check().expect_err("closed error should be latched");
        assert_transport_reason(&check_error, "closed");
    }
}
