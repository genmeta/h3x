use std::{
    any::Any,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    io,
    marker::PhantomData,
    ops,
    sync::Arc,
};

use dhttp_identity::identity as agent;
use futures::future::BoxFuture;
use snafu::Snafu;
use tokio::task::JoinHandle;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    codec::{PeekableStreamReader, SinkWriter, StreamReader},
    dhttp::{protocol::DHttpProtocolFactory, settings::Settings},
    error::{Code, H3ConnectionError, H3StreamError},
    protocol::{IdentifiedProtocolInitializer, ProductProtocol, Protocols, StreamVerdict},
    qpack::protocol::QPackProtocolFactory,
    quic::{self, CancelStreamExt, StopStreamExt},
    varint::VarInt,
};

/// H3 connection-level error: a QUIC transport/application error, or an
/// H3-defined connection-scope protocol violation.
#[derive(Debug, Snafu, Clone)]
pub enum ConnectionError {
    #[snafu(transparent)]
    Quic { source: quic::ConnectionError },
    #[snafu(display("h3 connection-scope protocol error"))]
    #[snafu(context(false))]
    H3 {
        source: Arc<dyn H3ConnectionError + 'static>,
    },
}

impl<E: H3ConnectionError + 'static> From<E> for ConnectionError {
    fn from(value: E) -> Self {
        ConnectionError::H3 {
            source: Arc::new(value),
        }
    }
}

impl From<ConnectionError> for io::Error {
    fn from(value: ConnectionError) -> Self {
        io::Error::new(io::ErrorKind::BrokenPipe, value)
    }
}

/// Recovers a `ConnectionError` from `io::Error`.
///
/// Recovery chain: `ConnectionError` (downcast) → `quic::ConnectionError` →
/// `Arc<dyn H3ConnectionError>`.
impl From<io::Error> for ConnectionError {
    fn from(source: io::Error) -> Self {
        let error = match source.downcast::<ConnectionError>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        let error = match error.downcast::<quic::ConnectionError>() {
            Ok(error) => return Self::Quic { source: error },
            Err(error) => error,
        };
        match error.downcast::<Arc<dyn H3ConnectionError + 'static>>() {
            Ok(error) => Self::H3 { source: error },
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to connection::ConnectionError, \
                 this is a bug"
            ),
        }
    }
}

/// Error observed on an H3 stream.
///
/// Three variants mirror the semantics of [`quic::StreamError`] but extended
/// with H3-level protocol errors:
///
/// - `Connection` — the underlying connection failed (QUIC transport/application
///   error, or H3 connection-scope protocol violation). This is the "connection
///   error projected onto a stream-returning API" case.
/// - `Reset` — the peer sent `RESET_STREAM` (or locally the stream was reset
///   with a raw VarInt code).
/// - `H3` — an H3 stream-scope protocol violation (e.g. malformed message).
///
/// # On the missing "pure stream error" type
///
/// Algebraically, `{Reset, H3}` forms a pure-stream subset distinct from
/// `ConnectionError`. We deliberately did **not** introduce a dedicated type
/// for that subset because:
///
/// 1. No current call site needs a type contract that excludes the
///    `Connection` variant — every `match` on `StreamError` must handle it.
/// 2. The quic layer below is itself flat (`Connection | Reset`); keeping the
///    H3 layer flat preserves structural correspondence.
/// 3. No natural domain term exists for the subset. Candidates considered and
///    rejected for lack of fit: `PureStreamError`, `LocalStreamError`,
///    `StreamFault`, `InStreamError`, `StreamScopeError`.
///
/// If a future consumer needs the contract ("this cannot be a connection
/// error"), a 2-variant `{Reset, H3}` type can be added non-breakingly with
/// `From<_> for StreamError` and `TryFrom<StreamError>` conversions.
#[derive(Debug, Snafu, Clone)]
pub enum StreamError {
    #[snafu(transparent)]
    Connection { source: ConnectionError },
    #[snafu(display("stream reset with code {code}"))]
    Reset { code: VarInt },
    #[snafu(display("h3 stream-scope protocol error"))]
    #[snafu(context(false))]
    H3 {
        source: Arc<dyn H3StreamError + 'static>,
    },
}

impl StreamError {
    pub fn map_stream_reset(self, map: impl FnOnce(VarInt) -> Self) -> Self {
        match self {
            StreamError::Reset { code } => map(code),
            error => error,
        }
    }
}

impl From<quic::StreamError> for StreamError {
    fn from(value: quic::StreamError) -> Self {
        match value {
            quic::StreamError::Connection { source } => Self::Connection {
                source: source.into(),
            },
            quic::StreamError::Reset { code } => Self::Reset { code },
        }
    }
}

impl From<quic::ConnectionError> for StreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Connection {
            source: value.into(),
        }
    }
}

impl<E: H3StreamError + 'static> From<E> for StreamError {
    fn from(value: E) -> Self {
        StreamError::H3 {
            source: Arc::new(value),
        }
    }
}

/// Registry of [`H3ConnectionError`] types that are allowed to flow into
/// stream-returning APIs. Each entry generates
/// `impl From<$ty> for StreamError` that wraps the value into
/// [`StreamError::Connection`] via [`ConnectionError::from`].
///
/// # Why a registry?
///
/// Rust coherence forbids two blanket impls
/// `impl<E: H3StreamError> From<E> for StreamError` and
/// `impl<E: H3ConnectionError> From<E> for StreamError` from coexisting
/// because the compiler cannot prove the bounds are mutually exclusive.
///
/// Since stream-scope and connection-scope errors are both legitimately
/// produced by stream-returning operations (a stream can fail with a
/// connection-level protocol violation), we register each connection-scope
/// H3 error type here explicitly. The registry acts as a documented opt-in:
/// adding a new connection-scope H3 type to the registry is the type-level
/// signal that it may be surfaced through a stream-returning API.
///
/// Alternative considered and rejected: requiring every call site to write
/// `ConnectionError::from(e).into()`. Too noisy at `?` sites.
macro_rules! h3_connection_error_into_stream_error {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl From<$ty> for StreamError {
                fn from(value: $ty) -> Self {
                    Self::Connection {
                        source: ConnectionError::from(value),
                    }
                }
            }
        )+
    };
}

h3_connection_error_into_stream_error!(
    crate::error::H3NoError,
    crate::error::H3StreamCreationError,
    crate::error::H3CriticalStreamClosed,
    crate::error::H3FrameUnexpected,
    crate::error::H3MissingSettings,
    crate::error::H3GeneralProtocolError,
    crate::error::H3InternalError,
    crate::error::H3FrameDecodeError,
    crate::error::QpackDecompressionFailed,
    crate::error::H3IdError,
    crate::dhttp::settings::InvalidSettingValue,
    crate::qpack::encoder::QPackDecoderStreamError,
    crate::qpack::decoder::QPackEncoderStreamError,
    crate::qpack::decoder::InvalidDynamicTableReference,
);

/// Error converting between `StreamError` and `io::Error`.
///
/// The `StreamError` is preserved as the inner error for later recovery via
/// downcast. `Reset` maps to `BrokenPipe` to mirror `quic::StreamError`.
impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        match value {
            error @ StreamError::Reset { .. } => io::Error::new(io::ErrorKind::BrokenPipe, error),
            StreamError::Connection { source } => io::Error::from(source),
            error @ StreamError::H3 { .. } => io::Error::other(error),
        }
    }
}

/// Reverse conversion: recovers a `StreamError` from an `io::Error`.
///
/// Recovery chain: `StreamError` (downcast) → `quic::StreamError` →
/// `ConnectionError` → `Arc<dyn H3StreamError>`.
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
        let error = match error.downcast::<ConnectionError>() {
            Ok(error) => {
                return Self::Connection { source: error };
            }
            Err(error) => error,
        };
        match error.downcast::<Arc<dyn H3StreamError + 'static>>() {
            Ok(error) => Self::H3 { source: error },
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to connection::StreamError, this is a bug"
            ),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionGoaway {
    #[snafu(display("local goaway"))]
    Local,
    #[snafu(display("peer goaway"))]
    Peer,
}

/// Extension trait providing error-handling helpers on any `Lifecycle` type.
pub trait LifecycleExt: quic::DynLifecycle + Sync {
    /// Handle an H3 connection-scope error.
    ///
    /// - `ConnectionError::Quic` — the connection has already failed; just
    ///   return the reported error unchanged.
    /// - `ConnectionError::H3` — a freshly detected connection-scope H3
    ///   protocol violation. Close the QUIC connection with the H3 error
    ///   code (unless the connection is already closed) and await the
    ///   definitive close reason.
    ///
    /// Callers never need to drive `self.close(...)` themselves for H3
    /// errors; this helper is the single place where the side effect
    /// happens.
    fn handle_connection_error(
        &self,
        error: ConnectionError,
    ) -> impl Future<Output = quic::ConnectionError> + Send + '_ {
        async move {
            match error {
                ConnectionError::Quic { source } => source,
                ConnectionError::H3 { source } => {
                    // Avoid a redundant `to_string()` allocation if the
                    // connection has already closed.
                    if let Err(error) = self.check() {
                        return error;
                    }
                    self.close(source.code(), source.to_string().into());
                    self.closed().await
                }
            }
        }
    }
}

impl<T: quic::DynLifecycle + Sync + ?Sized> LifecycleExt for T {}

/// RAII guard that closes the wrapped QUIC connection on drop.
///
/// Used during [`ConnectionBuilder::build`] so that a partially-constructed
/// connection (init failed, or the future was cancelled) does not leak. On
/// successful build the guard is [defused](Self::defuse) and ownership of the
/// `Arc<C>` is transferred into the live `Connection<C>`.
struct CloseOnDrop<C: ?Sized + quic::DynLifecycle>(Option<Arc<C>>);

impl<C: ?Sized + quic::DynLifecycle> CloseOnDrop<C> {
    fn new(quic: Arc<C>) -> Self {
        Self(Some(quic))
    }

    fn defuse(mut self) -> Arc<C> {
        self.0.take().expect("CloseOnDrop already defused")
    }
}

impl<C: ?Sized + quic::DynLifecycle> ops::Deref for CloseOnDrop<C> {
    type Target = Arc<C>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("CloseOnDrop already defused")
    }
}

impl<C: ?Sized + quic::DynLifecycle> Drop for CloseOnDrop<C> {
    fn drop(&mut self) {
        if let Some(quic) = self.0.take() {
            quic.close(Code::H3_NO_ERROR, "h3 build aborted".into());
        }
    }
}

pub struct ConnectionBuilder<C: Any> {
    initializers: Vec<IdentifiedProtocolInitializer<C>>,
    _connection: PhantomData<C>,
}

impl<C: Any> fmt::Debug for ConnectionBuilder<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionBuilder")
            .field("protocols", &self.initializers)
            .finish()
    }
}

impl<C: Any> fmt::Display for ConnectionBuilder<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionBuilder[")?;
        for (i, entry) in self.initializers.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        write!(f, "]")
    }
}

impl<C: quic::Connection> Default for ConnectionBuilder<C> {
    fn default() -> Self {
        Self::new(Arc::new(Settings::default()))
    }
}

impl<C: quic::Connection> ConnectionBuilder<C> {
    pub fn new(settings: Arc<Settings>) -> Self {
        let builder = Self {
            initializers: Vec::new(),
            _connection: PhantomData,
        };
        builder
            .protocol(DHttpProtocolFactory::new(settings))
            .protocol(QPackProtocolFactory::new())
    }

    pub fn protocol<F: ProductProtocol<C>>(mut self, factory: F) -> Self {
        self.initializers
            .push(IdentifiedProtocolInitializer::new(factory));
        self
    }

    pub async fn build(&self, quic: Arc<C>) -> Result<Connection<C>, quic::ConnectionError>
    where
        C: Sized,
    {
        // If any initializer fails (or this future is dropped before completion),
        // close the underlying QUIC connection so it does not leak. Defused on
        // success so the live `Connection<C>` keeps ownership.
        let quic = CloseOnDrop::new(quic);
        let mut protocols = Protocols::new();

        for initializer in &self.initializers {
            initializer.init_protocols(&quic, &mut protocols).await?;
        }

        let quic = quic.defuse();
        let protocols = Arc::new(protocols);
        let state = ConnectionState { quic, protocols };
        // Terminates when the QUIC connection closes and stream acceptance returns an error.
        // Wrapped in `AbortOnDropHandle` so dropping the owning `Connection<C>` aborts the
        // tasks immediately, breaking the strong-reference cycle that would otherwise keep
        // the underlying QUIC connection alive.
        let accept_uni: JoinHandle<()> =
            tokio::spawn(ConnectionState::accept_uni_stream_task(state.clone()).in_current_span());
        let accept_bi: JoinHandle<()> =
            tokio::spawn(ConnectionState::accept_bi_stream_task(state.clone()).in_current_span());

        Ok(Connection {
            state,
            _accept_tasks: [
                AbortOnDropHandle::new(accept_uni),
                AbortOnDropHandle::new(accept_bi),
            ],
        })
    }
}

impl<C: Any> Hash for ConnectionBuilder<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for initializer in &self.initializers {
            initializer.hash(state);
        }
    }
}

impl<C: Any> PartialEq for ConnectionBuilder<C> {
    fn eq(&self, other: &Self) -> bool {
        self.initializers == other.initializers
    }
}

impl<C: Any> Eq for ConnectionBuilder<C> {}

pub struct ConnectionState<C: ?Sized> {
    quic: Arc<C>,
    protocols: Arc<Protocols>,
}

// Manual `Debug` so that `ConnectionState<dyn DynConnection>` (which does not
// implement `Debug`) is still formattable. `quic` is intentionally omitted
// because most `dyn` connections do not implement `Debug`.
impl<C: ?Sized> fmt::Debug for ConnectionState<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionState")
            .field("protocols", &self.protocols)
            .finish_non_exhaustive()
    }
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
}

impl<C: quic::Connection> ConnectionState<C> {
    /// Erase the concrete QUIC connection type, yielding a state that is
    /// usable as `ConnectionState<dyn quic::DynConnection>`.
    ///
    /// Used on the server path so that [`UnresolvedRequest`](crate::endpoint::server::UnresolvedRequest)
    /// can carry a single type-erased connection handle regardless of the
    /// underlying QUIC implementation.
    #[must_use]
    pub fn erase(&self) -> ConnectionState<dyn quic::DynConnection> {
        // `Arc<C>` coerces to `Arc<dyn DynConnection>` because `C: Connection`
        // implies `C: DynConnection + Sized + 'static` via the blanket impl in
        // [`crate::quic`].
        let quic: Arc<dyn quic::DynConnection> = self.quic.clone();
        ConnectionState {
            quic,
            protocols: self.protocols.clone(),
        }
    }
}

impl<C: ?Sized + quic::DynLifecycle> ConnectionState<C> {
    pub fn check(&self) -> Result<(), quic::ConnectionError> {
        self.quic.check()
    }

    pub fn closed(&self) -> BoxFuture<'_, quic::ConnectionError> {
        self.quic.closed()
    }

    pub fn close(&self, code: Code, reason: impl Into<std::borrow::Cow<'static, str>>) {
        self.quic.close(code, reason.into());
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(quic: Arc<C>, protocols: Arc<Protocols>) -> Self {
        Self { quic, protocols }
    }
}

impl<C: quic::ManageStream + quic::Lifecycle + Sync> ConnectionState<C> {
    pub async fn open_bi(
        &self,
    ) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        match { self.quic.open_bi() }.await {
            Ok(streams) => Ok(streams),
            Err(error) => Err(self.quic.handle_connection_error(error.into()).await),
        }
    }

    pub async fn open_uni(&self) -> Result<C::StreamWriter, quic::ConnectionError> {
        match { self.quic.open_uni() }.await {
            Ok(stream) => Ok(stream),
            Err(error) => Err(self.quic.handle_connection_error(error.into()).await),
        }
    }
}

impl<C: ?Sized + quic::DynWithLocalAgent> ConnectionState<C> {
    pub async fn local_agent(
        &self,
    ) -> Result<Option<Arc<dyn agent::LocalAgent>>, quic::ConnectionError> {
        // Goes through the object-safe trait so that this impl applies
        // uniformly to both sized `C: WithLocalAgent` (via the blanket impl)
        // and `dyn DynConnection`.
        quic::DynWithLocalAgent::local_agent(&*self.quic).await
    }
}

impl<C: ?Sized + quic::DynWithRemoteAgent> ConnectionState<C> {
    pub async fn remote_agent(
        &self,
    ) -> Result<Option<Arc<dyn agent::RemoteAgent>>, quic::ConnectionError> {
        quic::DynWithRemoteAgent::remote_agent(&*self.quic).await
    }
}

impl<C: quic::Connection> ConnectionState<C> {
    async fn accept_bi_stream_task(state: Self) {
        let task = async {
            loop {
                let (reader, writer) = match quic::ManageStream::accept_bi(&*state.quic).await {
                    Ok(bi_stream) => bi_stream,
                    Err(error) => {
                        state.quic.handle_connection_error(error.into()).await;
                        return;
                    }
                };
                let stream_reader =
                    StreamReader::new(Box::pin(reader) as crate::codec::BoxReadStream);
                let stream_writer =
                    SinkWriter::new(Box::pin(writer) as crate::codec::BoxWriteStream);
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
                        // The stream has been consumed by protocol matching
                        // and is no longer reachable here; we can only drive
                        // connection close for connection-scope errors. For
                        // stream-scope errors the stream itself is already
                        // being torn down inside the protocol code.
                        if let StreamError::Connection { source } = stream_error {
                            state.quic.handle_connection_error(source).await;
                        }
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
                let stream_reader = match quic::ManageStream::accept_uni(&*state.quic).await {
                    Ok(uni_stream) => uni_stream,
                    Err(error) => {
                        state.quic.handle_connection_error(error.into()).await;
                        return;
                    }
                };
                let stream_reader =
                    StreamReader::new(Box::pin(stream_reader) as crate::codec::BoxReadStream);
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
                        // Same rationale as `accept_bi_stream_task`.
                        if let StreamError::Connection { source } = stream_error {
                            state.quic.handle_connection_error(source).await;
                        }
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
        }
    }
}

#[derive(Debug)]
pub struct Connection<C: quic::Connection> {
    state: ConnectionState<C>,
    /// Background stream-acceptance tasks, aborted when the `Connection<C>` is dropped.
    /// The tasks each hold a clone of `ConnectionState<C>` (which contains `Arc<C>`),
    /// so without abort-on-drop the strong reference cycle would keep the QUIC
    /// connection alive long after the owner has released its handle.
    _accept_tasks: [AbortOnDropHandle<()>; 2],
}

impl<C: quic::Connection> ops::Deref for Connection<C> {
    type Target = ConnectionState<C>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<C: quic::Connection> Connection<C> {
    pub async fn new(settings: Arc<Settings>, quic: Arc<C>) -> Result<Self, quic::ConnectionError> {
        ConnectionBuilder::new(settings).build(quic).await
    }
}

impl<C: quic::Connection> Connection<C> {
    #[cfg(test)]
    pub(crate) fn from_state_for_test(state: ConnectionState<C>) -> Self {
        let noop = || AbortOnDropHandle::new(tokio::spawn(async {}));
        Self {
            state,
            _accept_tasks: [noop(), noop()],
        }
    }
}

impl<C: quic::Connection> Drop for Connection<C> {
    fn drop(&mut self) {
        // Send a graceful close before aborting the accept tasks. The accept tasks
        // hold cloned `Arc<C>` references; aborting them via `AbortOnDropHandle`
        // releases those references so the underlying QUIC connection can be
        // dropped (and its own RAII close logic, if any, runs).
        self.close(Code::H3_NO_ERROR, "no error");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(feature = "dquic")]
    use std::{
        collections::hash_map::DefaultHasher,
        fmt,
        hash::{Hash, Hasher},
        marker::PhantomData,
    };
    use std::{
        error::Error as _,
        future::pending,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use bytes::Bytes;
    use dhttp_identity::identity as agent;
    use futures::{Sink, SinkExt, future::BoxFuture, stream::Stream};
    use tracing::Instrument;

    #[cfg(feature = "dquic")]
    use super::ConnectionBuilder;
    use super::{Connection, ConnectionState, LifecycleExt, StreamError};
    #[cfg(feature = "dquic")]
    use crate::{
        codec::{ErasedPeekableBiStream, ErasedPeekableUniStream},
        dhttp::settings::{MaxFieldSectionSize, Settings},
        protocol::{ProductProtocol, Protocol, StreamVerdict},
    };
    use crate::{
        error::{Code, H3MessageError, H3MissingSettings},
        protocol::Protocols,
        quic::{self, CancelStreamExt, ConnectionError, StopStreamExt},
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

    #[derive(Debug, Default)]
    pub(crate) struct MockConnectionState {
        terminal_error: crate::util::set_once::SetOnce<quic::ConnectionError>,
        close_calls: Mutex<Vec<(Code, String)>>,
        stream_calls: Mutex<Vec<&'static str>>,
        stream_ops_available: std::sync::atomic::AtomicBool,
    }

    #[derive(Debug, Clone, Default)]
    pub(crate) struct MockConnection {
        state: Arc<MockConnectionState>,
    }

    impl MockConnection {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn set_terminal_error(&self, error: quic::ConnectionError) {
            let _ = self.state.terminal_error.set(error);
        }

        pub(crate) fn enable_stream_ops(&self) {
            self.state
                .stream_ops_available
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        pub(crate) fn disable_stream_ops(&self) {
            self.state
                .stream_ops_available
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }

        pub(crate) fn close_calls(&self) -> Vec<(Code, String)> {
            self.state
                .close_calls
                .lock()
                .expect("close call log poisoned")
                .clone()
        }

        pub(crate) fn stream_calls(&self) -> Vec<&'static str> {
            self.state
                .stream_calls
                .lock()
                .expect("stream call log poisoned")
                .clone()
        }

        fn record_stream_call(&self, call: &'static str) {
            self.state
                .stream_calls
                .lock()
                .expect("stream call log poisoned")
                .push(call);
        }

        fn stream_ops_available(&self) -> bool {
            self.state
                .stream_ops_available
                .load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl quic::ManageStream for MockConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
            self.record_stream_call("open_bi");
            if self.stream_ops_available() {
                Ok((TestReadStream, TestWriteStream))
            } else {
                Err(test_connection_error("open_bi unavailable"))
            }
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, ConnectionError> {
            self.record_stream_call("open_uni");
            if self.stream_ops_available() {
                Ok(TestWriteStream)
            } else {
                Err(test_connection_error("open_uni unavailable"))
            }
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
            self.record_stream_call("accept_bi");
            if self.stream_ops_available() {
                Ok((TestReadStream, TestWriteStream))
            } else {
                Err(test_connection_error("accept_bi unavailable"))
            }
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, ConnectionError> {
            self.record_stream_call("accept_uni");
            if self.stream_ops_available() {
                Ok(TestReadStream)
            } else {
                Err(test_connection_error("accept_uni unavailable"))
            }
        }
    }

    impl quic::WithLocalAgent for MockConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, ConnectionError> {
            Ok(Some(TestLocalAgent))
        }
    }

    impl quic::WithRemoteAgent for MockConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, ConnectionError> {
            Ok(Some(TestRemoteAgent))
        }
    }

    impl quic::Lifecycle for MockConnection {
        fn close(&self, code: crate::error::Code, reason: std::borrow::Cow<'static, str>) {
            self.state
                .close_calls
                .lock()
                .expect("close call log poisoned")
                .push((code, reason.into_owned()));
        }

        fn check(&self) -> Result<(), ConnectionError> {
            match self.state.terminal_error.peek() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn closed(&self) -> ConnectionError {
            match self.state.terminal_error.get().await {
                Some(error) => error,
                None => pending().await,
            }
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

    fn assert_connection_h3_code(error: super::ConnectionError, expected_code: Code) {
        match error {
            super::ConnectionError::H3 { source } => assert_eq!(source.code(), expected_code),
            other => panic!("expected h3 connection error, got {other:?}"),
        }
    }

    fn assert_stream_reset(error: StreamError, expected_code: VarInt) {
        match error {
            StreamError::Reset { code } => assert_eq!(code, expected_code),
            other => panic!("expected stream reset, got {other:?}"),
        }
    }

    fn assert_stream_h3_code(error: StreamError, expected_code: Code) {
        match error {
            StreamError::H3 { source } => assert_eq!(source.code(), expected_code),
            other => panic!("expected h3 stream error, got {other:?}"),
        }
    }

    #[cfg(feature = "dquic")]
    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    /// Local mock protocol for builder tests.
    #[cfg(feature = "dquic")]
    #[derive(Debug)]
    struct MockProtocol;

    #[cfg(feature = "dquic")]
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
    #[cfg(feature = "dquic")]
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct MockFactory(u64);

    #[cfg(feature = "dquic")]
    impl fmt::Display for MockFactory {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockFactory")
        }
    }

    #[cfg(feature = "dquic")]
    impl<C: quic::Connection> ProductProtocol<C> for MockFactory {
        type Protocol = MockProtocol;

        fn init<'a>(
            &'a self,
            _: &'a Arc<C>,
            _: &'a Protocols,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            Box::pin(async { Ok(MockProtocol) })
        }
    }

    #[cfg(feature = "dquic")]
    #[derive(Debug)]
    struct PassThenDisableProtocol {
        quic: MockConnection,
    }

    #[cfg(feature = "dquic")]
    impl Protocol for PassThenDisableProtocol {
        fn accept_uni<'a>(
            &'a self,
            stream: ErasedPeekableUniStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
            self.quic.disable_stream_ops();
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }

        fn accept_bi<'a>(
            &'a self,
            stream: ErasedPeekableBiStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
            self.quic.disable_stream_ops();
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }
    }

    #[cfg(feature = "dquic")]
    #[derive(Debug, Clone, Copy)]
    enum ErrKind {
        Connection,
        Reset,
    }

    #[cfg(feature = "dquic")]
    #[derive(Debug)]
    struct ErrThenDisableProtocol {
        quic: MockConnection,
        kind: ErrKind,
    }

    #[cfg(feature = "dquic")]
    impl ErrThenDisableProtocol {
        fn make_error(&self) -> StreamError {
            match self.kind {
                ErrKind::Connection => StreamError::from(H3MissingSettings),
                ErrKind::Reset => StreamError::Reset {
                    code: VarInt::from_u32(7),
                },
            }
        }
    }

    #[cfg(feature = "dquic")]
    impl Protocol for ErrThenDisableProtocol {
        fn accept_uni<'a>(
            &'a self,
            _stream: ErasedPeekableUniStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
            self.quic.disable_stream_ops();
            let err = self.make_error();
            Box::pin(async move { Err(err) })
        }

        fn accept_bi<'a>(
            &'a self,
            _stream: ErasedPeekableBiStream,
        ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
            self.quic.disable_stream_ops();
            let err = self.make_error();
            Box::pin(async move { Err(err) })
        }
    }

    #[cfg(feature = "dquic")]
    type C = dquic::prelude::Connection;

    /// Hash equality and determinism: identical inputs must produce equal hashes.
    #[cfg(feature = "dquic")]
    #[test]
    fn hash_equality_and_determinism() {
        let s = || Arc::new(Settings::default());

        // Build a reference builder for the "same builder twice" determinism check.
        let det_builder = ConnectionBuilder::<C>::new(s()).protocol(MockFactory(99));
        let h_det = hash_of(&det_builder);

        // All cases where hash must be equal (rebuild from identical inputs).
        let cases: [(&str, ConnectionBuilder<C>, ConnectionBuilder<C>); 3] = [
            (
                "same settings",
                ConnectionBuilder::<C>::new(s()),
                ConnectionBuilder::<C>::new(s()),
            ),
            (
                "same protocol",
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(42)),
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(42)),
            ),
            (
                "clone-like rebuild",
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(100)),
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(100)),
            ),
        ];

        for (name, a, b) in &cases {
            assert_eq!(hash_of(a), hash_of(b), "hash equality: {name}");
        }

        // Same builder hashed twice must be deterministic.
        assert_eq!(
            hash_of(&det_builder),
            h_det,
            "hashing the same builder twice must be deterministic"
        );

        // An identically-constructed builder must produce the same hash.
        let builder2 = ConnectionBuilder::<C>::new(s()).protocol(MockFactory(99));
        assert_eq!(
            h_det,
            hash_of(&builder2),
            "identical builders must hash equally"
        );
    }

    #[cfg(feature = "dquic")]
    #[test]
    fn display_lists_each_initializer_separated_by_commas() {
        let s = || Arc::new(Settings::default());

        let empty = ConnectionBuilder::<C> {
            initializers: Vec::new(),
            _connection: PhantomData,
        };
        assert_eq!(format!("{}", empty), "ConnectionBuilder[]");

        let one = ConnectionBuilder::<C> {
            initializers: Vec::new(),
            _connection: PhantomData,
        }
        .protocol(MockFactory(1));
        assert_eq!(format!("{}", one), "ConnectionBuilder[MockFactory]");

        let two = ConnectionBuilder::<C> {
            initializers: Vec::new(),
            _connection: PhantomData,
        }
        .protocol(MockFactory(1))
        .protocol(MockFactory(2));
        assert_eq!(
            format!("{}", two),
            "ConnectionBuilder[MockFactory, MockFactory]"
        );

        let default_with_extra = ConnectionBuilder::<C>::new(s()).protocol(MockFactory(99));
        let rendered = format!("{}", default_with_extra);
        assert!(rendered.starts_with("ConnectionBuilder["));
        assert!(rendered.ends_with(']'));
        assert!(rendered.contains("MockFactory"));
        assert_eq!(rendered.matches(", ").count(), 2);
    }

    /// Different settings produce different hashes.
    #[cfg(feature = "dquic")]
    #[test]
    fn hash_ne_different_settings() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(MaxFieldSectionSize::setting(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);
        let a = ConnectionBuilder::<C>::new(s1);
        let b = ConnectionBuilder::<C>::new(s2);
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    /// Different protocol stacks produce different hashes.
    #[cfg(feature = "dquic")]
    #[test]
    fn hash_ne_different_protocols() {
        let s = || Arc::new(Settings::default());

        let cases: [(&str, ConnectionBuilder<C>, ConnectionBuilder<C>); 3] = [
            (
                "extra protocol",
                ConnectionBuilder::<C>::new(s()),
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(42)),
            ),
            (
                "different protocol value",
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(1)),
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(2)),
            ),
            (
                "mock factory included in hash",
                ConnectionBuilder::<C>::new(s()),
                ConnectionBuilder::<C>::new(s()).protocol(MockFactory(42)),
            ),
        ];

        for (name, a, b) in &cases {
            assert_ne!(hash_of(a), hash_of(b), "hash inequality: {name}");
        }
    }

    /// Different protocol ordering produces different hashes.
    #[cfg(feature = "dquic")]
    #[test]
    fn hash_ne_different_order() {
        let s = Arc::new(Settings::default());
        // a: DHttpProtocolFactory, QPackProtocolFactory, MockFactory (from new + protocol)
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(7));
        // b: MockFactory first, then DHttpProtocolFactory, QPackProtocolFactory
        let b = {
            let builder = ConnectionBuilder::<C> {
                initializers: Vec::new(),
                _connection: std::marker::PhantomData,
            };
            builder
                .protocol(MockFactory(7))
                .protocol(crate::dhttp::protocol::DHttpProtocolFactory::new(s))
                .protocol(crate::qpack::protocol::QPackProtocolFactory::new())
        };
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "dquic")]
    #[test]
    fn builder_same_settings_eq() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s);
        assert_eq!(a, b);
    }

    #[cfg(feature = "dquic")]
    #[test]
    fn builder_different_settings_not_eq() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(MaxFieldSectionSize::setting(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);
        let a = ConnectionBuilder::<C>::new(s1);
        let b = ConnectionBuilder::<C>::new(s2);
        assert_ne!(a, b);
    }

    #[cfg(feature = "dquic")]
    #[test]
    fn builder_display_and_debug_list_protocol_initializers() {
        let builder =
            ConnectionBuilder::<C>::new(Arc::new(Settings::default())).protocol(MockFactory(7));

        assert_eq!(
            builder.to_string(),
            "ConnectionBuilder[DHTTP/3, QPACK, MockFactory]"
        );
        let debug = format!("{builder:?}");
        assert!(debug.contains("ConnectionBuilder"));
        assert!(debug.contains("DHttpProtocolFactory"));
        assert!(debug.contains("QPackProtocolFactory"));
        assert!(debug.contains("MockFactory"));
    }

    #[tokio::test]
    async fn builder_closes_quic_when_initial_protocol_init_fails() {
        let quic = Arc::new(MockConnection::new());
        let result = ConnectionBuilder::new(Arc::new(Settings::default()))
            .build(quic.clone())
            .await;

        let error = result.expect_err("open_uni failure should abort connection build");
        assert_transport_reason(&error, "open_uni unavailable");
        assert_eq!(
            quic.close_calls(),
            vec![(Code::H3_NO_ERROR, "h3 build aborted".to_owned())]
        );
    }

    #[tokio::test]
    async fn builder_success_initializes_dhttp_and_qpack_protocols() {
        let quic = Arc::new(MockConnection::new());
        quic.enable_stream_ops();
        let settings = Arc::new(Settings::default());

        let connection = ConnectionBuilder::new(settings.clone())
            .build(quic.clone())
            .await
            .expect("builder should initialize built-in protocols");

        assert!(
            connection
                .protocol::<crate::dhttp::protocol::DHttpProtocol>()
                .is_some()
        );
        assert!(connection.qpack().is_ok());
        assert!(Arc::ptr_eq(&connection.settings(), &settings));
        assert_eq!(quic.stream_calls()[0], "open_uni");

        drop(connection);
        assert!(
            quic.close_calls()
                .iter()
                .any(|(code, reason)| *code == Code::H3_NO_ERROR && reason == "no error")
        );
    }

    #[cfg(feature = "dquic")]
    #[tokio::test]
    async fn builder_initializes_custom_protocol_factory() {
        let quic = Arc::new(MockConnection::new());
        quic.enable_stream_ops();

        let connection = ConnectionBuilder::new(Arc::new(Settings::default()))
            .protocol(MockFactory(7))
            .build(quic)
            .await
            .expect("custom protocol factory should initialize");

        assert!(connection.protocol::<MockProtocol>().is_some());
    }

    #[test]
    fn state_accessors_return_underlying_quic_and_protocol_registry() {
        let quic = Arc::new(MockConnection::new());
        let protocols = Arc::new(Protocols::new());
        let state = ConnectionState::new_for_test(quic.clone(), protocols.clone());

        assert!(Arc::ptr_eq(state.quic(), &quic));
        assert!(Arc::ptr_eq(state.protocols(), &protocols));
        assert!(state.protocol::<MockProtocol>().is_none());
        assert!(format!("{state:?}").contains("ConnectionState"));
    }

    #[tokio::test]
    async fn state_open_stream_helpers_delegate_success_and_error_paths() {
        let quic = MockConnection::new();
        let state =
            ConnectionState::new_for_test(Arc::new(quic.clone()), Arc::new(Protocols::new()));

        let bi_error = state
            .open_bi()
            .await
            .expect_err("open_bi should fail before enabled");
        assert_transport_reason(&bi_error, "open_bi unavailable");
        let uni_error = state
            .open_uni()
            .await
            .expect_err("open_uni should fail before enabled");
        assert_transport_reason(&uni_error, "open_uni unavailable");

        quic.enable_stream_ops();
        state
            .open_bi()
            .await
            .expect("open_bi should delegate success");
        state
            .open_uni()
            .await
            .expect("open_uni should delegate success");

        assert_eq!(
            quic.stream_calls(),
            vec!["open_bi", "open_uni", "open_bi", "open_uni"]
        );
    }

    #[tokio::test]
    async fn local_and_remote_agent_accessors_delegate_on_concrete_state() {
        let quic = MockConnection::new();
        let state = ConnectionState::new_for_test(Arc::new(quic), Arc::new(Protocols::new()));

        let local = state
            .local_agent()
            .await
            .expect("local agent lookup should succeed")
            .expect("local agent should be present");
        assert_eq!(local.name(), "test-local");

        let remote = state
            .remote_agent()
            .await
            .expect("remote agent lookup should succeed")
            .expect("remote agent should be present");
        assert_eq!(remote.name(), "test-remote");
    }

    #[tokio::test]
    async fn accept_tasks_handle_accept_errors_without_closing_again() {
        let bi_quic = MockConnection::new();
        let bi_state =
            ConnectionState::new_for_test(Arc::new(bi_quic.clone()), Arc::new(Protocols::new()));
        ConnectionState::accept_bi_stream_task(bi_state).await;
        assert_eq!(bi_quic.stream_calls(), vec!["accept_bi"]);
        assert!(bi_quic.close_calls().is_empty());

        let uni_quic = MockConnection::new();
        let uni_state =
            ConnectionState::new_for_test(Arc::new(uni_quic.clone()), Arc::new(Protocols::new()));
        ConnectionState::accept_uni_stream_task(uni_state).await;
        assert_eq!(uni_quic.stream_calls(), vec!["accept_uni"]);
        assert!(uni_quic.close_calls().is_empty());
    }

    #[cfg(feature = "dquic")]
    #[tokio::test]
    async fn accept_tasks_pass_unknown_streams_to_stop_and_cancel_paths() {
        let bi_quic = MockConnection::new();
        bi_quic.enable_stream_ops();
        let bi_protocols = {
            let mut protocols = Protocols::new();
            protocols.insert(PassThenDisableProtocol {
                quic: bi_quic.clone(),
            });
            Arc::new(protocols)
        };
        let bi_state = ConnectionState::new_for_test(Arc::new(bi_quic.clone()), bi_protocols);
        ConnectionState::accept_bi_stream_task(bi_state).await;
        assert_eq!(bi_quic.stream_calls(), vec!["accept_bi", "accept_bi"]);

        let uni_quic = MockConnection::new();
        uni_quic.enable_stream_ops();
        let uni_protocols = {
            let mut protocols = Protocols::new();
            protocols.insert(PassThenDisableProtocol {
                quic: uni_quic.clone(),
            });
            Arc::new(protocols)
        };
        let uni_state = ConnectionState::new_for_test(Arc::new(uni_quic.clone()), uni_protocols);
        ConnectionState::accept_uni_stream_task(uni_state).await;
        assert_eq!(uni_quic.stream_calls(), vec!["accept_uni", "accept_uni"]);
    }

    #[cfg(feature = "dquic")]
    #[tokio::test]
    async fn accept_bi_task_calls_handle_connection_error_for_connection_scope_errors() {
        let bi_quic = MockConnection::new();
        bi_quic.enable_stream_ops();

        let protocols = {
            let mut protocols = Protocols::new();
            protocols.insert(ErrThenDisableProtocol {
                quic: bi_quic.clone(),
                kind: ErrKind::Connection,
            });
            Arc::new(protocols)
        };
        let state = ConnectionState::new_for_test(Arc::new(bi_quic.clone()), protocols);
        let task = tokio::spawn(ConnectionState::accept_bi_stream_task(state).in_current_span());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !bi_quic.close_calls().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection-scope error should trigger close");

        bi_quic.set_terminal_error(test_connection_error("bi terminal"));
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("accept_bi task should terminate")
            .expect("task should not panic");

        assert!(bi_quic.stream_calls().contains(&"accept_bi"));
        assert_eq!(bi_quic.close_calls().len(), 1);
        assert_eq!(bi_quic.close_calls()[0].0, Code::H3_MISSING_SETTINGS);
    }

    #[cfg(feature = "dquic")]
    #[tokio::test]
    async fn accept_uni_task_calls_handle_connection_error_for_connection_scope_errors() {
        let uni_quic = MockConnection::new();
        uni_quic.enable_stream_ops();

        let protocols = {
            let mut protocols = Protocols::new();
            protocols.insert(ErrThenDisableProtocol {
                quic: uni_quic.clone(),
                kind: ErrKind::Connection,
            });
            Arc::new(protocols)
        };
        let state = ConnectionState::new_for_test(Arc::new(uni_quic.clone()), protocols);
        let task = tokio::spawn(ConnectionState::accept_uni_stream_task(state).in_current_span());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !uni_quic.close_calls().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection-scope error should trigger close");

        uni_quic.set_terminal_error(test_connection_error("uni terminal"));
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("accept_uni task should terminate")
            .expect("task should not panic");

        assert!(uni_quic.stream_calls().contains(&"accept_uni"));
        assert_eq!(uni_quic.close_calls().len(), 1);
        assert_eq!(uni_quic.close_calls()[0].0, Code::H3_MISSING_SETTINGS);
    }

    #[cfg(feature = "dquic")]
    #[tokio::test]
    async fn accept_bi_task_skips_close_for_stream_scope_errors() {
        let bi_quic = MockConnection::new();
        bi_quic.enable_stream_ops();

        let protocols = {
            let mut protocols = Protocols::new();
            protocols.insert(ErrThenDisableProtocol {
                quic: bi_quic.clone(),
                kind: ErrKind::Reset,
            });
            Arc::new(protocols)
        };
        let state = ConnectionState::new_for_test(Arc::new(bi_quic.clone()), protocols);
        let task = tokio::spawn(ConnectionState::accept_bi_stream_task(state).in_current_span());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if bi_quic.stream_calls().contains(&"accept_bi") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("task should call accept_bi");

        // give the stream-scope error path a chance to execute
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        bi_quic.set_terminal_error(test_connection_error("bi reset terminal"));
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("accept_bi task should terminate")
            .expect("task should not panic");

        assert!(
            bi_quic.close_calls().is_empty(),
            "stream-scope errors must not trigger connection close"
        );
    }

    #[cfg(feature = "dquic")]
    #[tokio::test]
    async fn accept_uni_task_skips_close_for_stream_scope_errors() {
        let uni_quic = MockConnection::new();
        uni_quic.enable_stream_ops();

        let protocols = {
            let mut protocols = Protocols::new();
            protocols.insert(ErrThenDisableProtocol {
                quic: uni_quic.clone(),
                kind: ErrKind::Reset,
            });
            Arc::new(protocols)
        };
        let state = ConnectionState::new_for_test(Arc::new(uni_quic.clone()), protocols);
        let task = tokio::spawn(ConnectionState::accept_uni_stream_task(state).in_current_span());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if uni_quic.stream_calls().contains(&"accept_uni") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("task should call accept_uni");

        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        uni_quic.set_terminal_error(test_connection_error("uni reset terminal"));
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("accept_uni task should terminate")
            .expect("task should not panic");

        assert!(uni_quic.close_calls().is_empty());
    }

    #[tokio::test]
    async fn lifecycle_ext_h3_error_closes_then_returns_terminal_error() {
        let quic = MockConnection::new();
        let quic_for_task = quic.clone();
        let task = tokio::spawn(
            async move {
                quic_for_task
                    .handle_connection_error(super::ConnectionError::from(H3MissingSettings))
                    .await
            }
            .in_current_span(),
        );

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !quic.close_calls().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("h3 error should close promptly");

        assert_eq!(
            quic.close_calls(),
            vec![(
                Code::H3_MISSING_SETTINGS,
                "no SETTINGS frame at beginning of control stream".to_owned()
            )]
        );

        quic.set_terminal_error(test_connection_error("after h3 close"));
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("closed should resolve")
            .expect("task should not panic");
        assert_transport_reason(&error, "after h3 close");
    }

    #[tokio::test]
    async fn lifecycle_ext_h3_error_returns_existing_terminal_error_without_closing() {
        let quic = MockConnection::new();
        quic.set_terminal_error(test_connection_error("already closed"));

        let error = quic
            .handle_connection_error(super::ConnectionError::from(H3MissingSettings))
            .await;

        assert_transport_reason(&error, "already closed");
        assert!(quic.close_calls().is_empty());
    }

    #[test]
    fn stream_error_from_connection_scope_h3_registry_variant() {
        let error = StreamError::from(H3MissingSettings);

        match error {
            StreamError::Connection { source } => {
                assert_connection_h3_code(source, Code::H3_MISSING_SETTINGS);
            }
            other => panic!("expected connection-scope stream error, got {other:?}"),
        }
    }

    #[test]
    fn h3_error_display_and_sources_are_layered() {
        let connection_error = super::ConnectionError::from(H3MissingSettings);
        assert_eq!(
            connection_error.to_string(),
            "h3 connection-scope protocol error"
        );
        assert_eq!(
            connection_error
                .source()
                .expect("h3 connection source")
                .to_string(),
            "no SETTINGS frame at beginning of control stream"
        );

        let stream_error = StreamError::from(H3MessageError::MissingHeaderSection);
        assert_eq!(stream_error.to_string(), "h3 stream-scope protocol error");
        assert_eq!(
            stream_error.source().expect("h3 stream source").to_string(),
            "missing header section in HTTP message"
        );
    }

    #[test]
    fn stream_error_h3_io_roundtrip_preserves_source() {
        let io_error = io::Error::from(StreamError::from(H3MessageError::MissingHeaderSection));
        assert_eq!(io_error.kind(), io::ErrorKind::Other);

        let recovered = StreamError::from(io_error);
        assert_stream_h3_code(recovered, Code::H3_MESSAGE_ERROR);
    }

    #[test]
    fn connection_error_recovery_rejects_untyped_io_error() {
        let result = std::panic::catch_unwind(|| {
            let _ = super::ConnectionError::from(io::Error::other("opaque"));
        });

        assert!(result.is_err());
    }

    #[test]
    fn stream_error_recovery_rejects_untyped_io_error() {
        let result = std::panic::catch_unwind(|| {
            let _ = StreamError::from(io::Error::other("opaque"));
        });

        assert!(result.is_err());
    }

    #[test]
    fn stream_error_map_stream_reset_maps_only_reset_code() {
        let reset_code = VarInt::from_u32(0x123);
        let mapped = StreamError::Reset { code: reset_code }.map_stream_reset(|code| {
            assert_eq!(code, reset_code);
            StreamError::from(H3MessageError::MissingHeaderSection)
        });

        assert_stream_h3_code(mapped, Code::H3_MESSAGE_ERROR);
    }

    #[test]
    fn connection_error_recovers_from_io_error_layers() {
        let connection_error = super::ConnectionError::from(test_connection_error("wrapped"));
        let recovered = super::ConnectionError::from(io::Error::from(connection_error));
        match recovered {
            super::ConnectionError::Quic { source } => assert_transport_reason(&source, "wrapped"),
            other => panic!("expected quic connection error, got {other:?}"),
        }

        let quic_error = test_connection_error("quic");
        let recovered = super::ConnectionError::from(io::Error::from(quic_error));
        match recovered {
            super::ConnectionError::Quic { source } => assert_transport_reason(&source, "quic"),
            other => panic!("expected quic connection error, got {other:?}"),
        }

        let h3_error = super::ConnectionError::from(H3MissingSettings);
        let super::ConnectionError::H3 { source } = h3_error else {
            panic!("expected h3 connection error");
        };
        let h3_source: Arc<dyn crate::error::H3ConnectionError> = source;
        let recovered = super::ConnectionError::from(io::Error::other(h3_source));
        assert_connection_h3_code(recovered, Code::H3_MISSING_SETTINGS);
    }

    #[test]
    fn stream_error_recovers_from_io_error_layers() {
        let reset_code = VarInt::from_u32(0x41);
        let reset = StreamError::Reset { code: reset_code };
        assert_stream_reset(StreamError::from(io::Error::from(reset)), reset_code);

        let quic_reset_code = VarInt::from_u32(0x42);
        let quic_reset = quic::StreamError::Reset {
            code: quic_reset_code,
        };
        assert_stream_reset(
            StreamError::from(io::Error::from(quic_reset)),
            quic_reset_code,
        );

        let connection_error = super::ConnectionError::from(test_connection_error("stream"));
        let recovered = StreamError::from(io::Error::from(connection_error));
        match recovered {
            StreamError::Connection {
                source: super::ConnectionError::Quic { source },
            } => assert_transport_reason(&source, "stream"),
            other => panic!("expected stream connection error, got {other:?}"),
        }

        let h3 = StreamError::from(H3MessageError::MissingHeaderSection);
        let StreamError::H3 { source } = h3 else {
            panic!("expected h3 stream error");
        };
        let h3_source: Arc<dyn crate::error::H3StreamError> = source;
        let recovered = StreamError::from(io::Error::other(h3_source));
        assert_stream_h3_code(recovered, Code::H3_MESSAGE_ERROR);
    }

    #[test]
    fn map_stream_reset_leaves_non_reset_errors_unchanged() {
        let mut mapper_called = false;
        let error = StreamError::from(H3MessageError::UnexpectedHeadersInBody);
        let mapped = error.map_stream_reset(|code| {
            mapper_called = true;
            StreamError::Reset { code }
        });

        assert!(!mapper_called);
        assert_stream_h3_code(mapped, Code::H3_MESSAGE_ERROR);
    }

    #[tokio::test]
    async fn test_stream_helpers_cover_stop_cancel_and_close() {
        let mut reader = TestReadStream;
        reader
            .stop(VarInt::from_u32(0x103))
            .await
            .expect("test reader stop should succeed");

        let mut writer = TestWriteStream;
        writer
            .cancel(VarInt::from_u32(0x103))
            .await
            .expect("test writer cancel should succeed");
        writer
            .close()
            .await
            .expect("test writer close should succeed");
    }

    #[tokio::test]
    async fn erased_connection_state_delegates_dyn_connection_operations() {
        let quic = MockConnection::new();
        quic.enable_stream_ops();
        let state =
            ConnectionState::new_for_test(Arc::new(quic.clone()), Arc::new(Protocols::new()));
        let erased = state.erase();

        assert!(Arc::ptr_eq(state.protocols(), erased.protocols()));
        assert_eq!(
            erased
                .local_agent()
                .await
                .expect("local agent delegated")
                .expect("local agent present")
                .name(),
            "test-local"
        );
        assert_eq!(
            erased
                .remote_agent()
                .await
                .expect("remote agent delegated")
                .expect("remote agent present")
                .name(),
            "test-remote"
        );
        assert!(erased.check().is_ok());

        let _ = quic::DynManageStream::open_bi(&**erased.quic())
            .await
            .expect("open_bi delegated");
        let _ = quic::DynManageStream::open_uni(&**erased.quic())
            .await
            .expect("open_uni delegated");
        let _ = quic::DynManageStream::accept_bi(&**erased.quic())
            .await
            .expect("accept_bi delegated");
        let _ = quic::DynManageStream::accept_uni(&**erased.quic())
            .await
            .expect("accept_uni delegated");

        assert_eq!(
            quic.stream_calls(),
            vec!["open_bi", "open_uni", "accept_bi", "accept_uni"]
        );

        erased.close(Code::H3_NO_ERROR, "dyn close");
        assert_eq!(
            quic.close_calls(),
            vec![(Code::H3_NO_ERROR, "dyn close".to_owned())]
        );

        quic.set_terminal_error(test_connection_error("dyn closed"));
        let closed = erased.closed().await;
        assert_transport_reason(&closed, "dyn closed");
    }

    #[tokio::test]
    async fn connection_from_state_for_test_closes_on_drop() {
        let quic = MockConnection::new();
        let state =
            ConnectionState::new_for_test(Arc::new(quic.clone()), Arc::new(Protocols::new()));
        let connection = Connection::from_state_for_test(state);

        assert!(quic.close_calls().is_empty());
        drop(connection);

        assert_eq!(
            quic.close_calls(),
            vec![(Code::H3_NO_ERROR, "no error".to_owned())]
        );
    }

    #[test]
    fn check_latches_terminal_error_after_closed_is_observed() {
        let quic = MockConnection::new();
        let protocols = Arc::new(Protocols::new());
        let state = ConnectionState::new_for_test(Arc::new(quic.clone()), protocols);
        let expected = test_connection_error("closed");

        // Initially healthy.
        assert!(state.check().is_ok());

        // Simulate connection death at the QUIC layer.
        quic.set_terminal_error(expected.clone());

        // check() sees the latched error.
        let check_error = state.check().expect_err("should be dead");
        assert_transport_reason(&check_error, "closed");

        // closed() returns the same error immediately.
        let observed = futures::executor::block_on(state.closed());
        assert_transport_reason(&observed, "closed");

        // Subsequent check() still returns the same error.
        let check_again = state.check().expect_err("still dead");
        assert_transport_reason(&check_again, "closed");
    }
}
