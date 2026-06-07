//! IPC forwarding of WebTransport sessions via RPC + per-stream socketpairs.
//!
//! Parallel to [`super::quic`] which bridges QUIC connections over IPC, this
//! module bridges WebTransport sessions. Each WebTransport stream is forwarded
//! through a dedicated Unix socketpair while control-plane RPCs (open, accept)
//! travel over the remoc channel with receiver-chosen FD transfer IDs.
//!
//! # Public API
//!
//! ## RTC trait
//!
//! - [`IpcWebTransportSession`] — session-level stream management
//!
//! ## Server-side adapter
//!
//! - [`WebTransportSessionAdapter`] — wraps [`WebTransportSession`](crate::webtransport::WebTransportSession),
//!   implements [`IpcWebTransportSession`]
//!
//! ## Client-side wrapper
//!
//! - [`IpcWebTransportSessionHandle`] — wraps [`IpcWebTransportSessionClient`], provides async
//!   stream management
//!
//! ## Bootstrap
//!
//! - [`WebTransportSessionBootstrap`] — one-shot value sent when a WebTransport session
//!   is established over IPC
//!
//! # FD semantics
//!
//! - **`open_bi` / `accept_bi`**: 2 FDs are delivered (read frame IO + write frame IO).
//! - **`open_uni`**: 1 FD (write frame IO, server side applies worker commands
//!   to the real WebTransport uni stream).
//! - **`accept_uni`**: 1 FD (read frame IO, server side executes worker pulls
//!   against the real WebTransport uni stream).

use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use snafu::Snafu;
use tokio::net::UnixStream;
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, debug};

/// WebTransport-flavoured lifecycle helpers for IPC-backed session handles.
///
/// IPC uses the same remoc control-plane and connection-error latch discipline
/// as RPC WebTransport handles, so this module reuses the RPC helper trait
/// directly while preserving the `ipc::webtransport::LifecycleExt` path.
pub use crate::rpc::webtransport::LifecycleExt;
use crate::{
    error::Code,
    ipc::{
        quic::{
            connection::{IPC_ERROR_KIND, IPC_FRAME_TYPE, bridge_reader, bridge_writer},
            stream::{reader as ipc_reader, writer as ipc_writer},
        },
        transport::{FdDelivery, FdTransfer, ReceivedFds},
    },
    quic::{
        self, BoxQuicStreamReader, BoxQuicStreamWriter, ConnectionError, DynLifecycle,
        GetStreamIdExt, ResetStreamExt, StopStreamExt,
    },
    rpc::lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt as _},
    varint::VarInt,
    webtransport::{
        self, AcceptStreamError, CloseReason, CloseSession, CloseSessionError, DrainSessionError,
        OpenStreamError, SessionClosed, SessionDrain, WebTransportSessionId,
    },
};

// ---------------------------------------------------------------------------
// IPC error types
// ---------------------------------------------------------------------------

/// Concrete error type for IPC plumbing failures.
///
/// Captures the specific category of failure: RPC call errors preserve
/// [`remoc::rtc::CallError`], QUIC stream errors preserve
/// [`StreamError`](quic::StreamError), and OS-level I/O errors (socketpair,
/// FD conversion, delivery) are serialized as strings.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module(ipc_plumbing_error), visibility(pub))]
pub enum IpcPlumbingError {
    /// RPC call failed.
    #[snafu(transparent)]
    Rpc { source: remoc::rtc::CallError },

    /// QUIC stream error (e.g. stream_id retrieval failed).
    #[snafu(transparent)]
    Stream { source: quic::StreamError },

    /// OS-level or infrastructure I/O failure.
    #[snafu(display("{message}"))]
    Io { message: String },
}

/// Errors from IPC `open_bi` / `open_uni` operations.
///
/// Extends [`OpenStreamError`] with an IPC transport variant for FD-passing
/// and socketpair failures.  Conversion to [`ConnectionError`] is deferred
/// to the latch site via [`ConnectionErrorLatch::latch_with`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module(ipc_webtransport_open_error), visibility(pub))]
pub enum IpcWebTransportOpenError {
    /// The underlying stream operation failed.
    #[snafu(transparent)]
    Stream { source: OpenStreamError },

    /// IPC plumbing failure (RPC, stream, or I/O).
    #[snafu(transparent)]
    Transport { source: IpcPlumbingError },
}

/// Errors from IPC `accept_bi` / `accept_uni` operations.
///
/// Extends [`SessionClosed`] with an IPC transport variant for FD-passing and
/// socketpair failures. Conversion to [`ConnectionError`] is deferred to the
/// latch site via [`ConnectionErrorLatch::latch_with`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module(ipc_webtransport_accept_error), visibility(pub))]
pub enum IpcWebTransportAcceptError {
    /// The session has been closed.
    #[snafu(display("webtransport session closed"))]
    Closed,

    /// The underlying WebTransport connection failed.
    #[snafu(transparent)]
    Connection { source: ConnectionError },

    /// IPC plumbing failure (RPC, stream, or I/O).
    #[snafu(transparent)]
    Transport { source: IpcPlumbingError },
}

impl From<remoc::rtc::CallError> for IpcWebTransportOpenError {
    fn from(error: remoc::rtc::CallError) -> Self {
        IpcPlumbingError::Rpc { source: error }.into()
    }
}

impl From<remoc::rtc::CallError> for IpcWebTransportAcceptError {
    fn from(error: remoc::rtc::CallError) -> Self {
        IpcPlumbingError::Rpc { source: error }.into()
    }
}

impl From<SessionClosed> for IpcWebTransportAcceptError {
    fn from(_source: SessionClosed) -> Self {
        IpcWebTransportAcceptError::Closed
    }
}

impl From<AcceptStreamError> for IpcWebTransportAcceptError {
    fn from(error: AcceptStreamError) -> Self {
        match error {
            AcceptStreamError::Closed { source } => source.into(),
            AcceptStreamError::Connection { source } => Self::Connection { source },
            AcceptStreamError::StreamId { source } => Self::Transport {
                source: IpcPlumbingError::Stream { source },
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IPC RTC trait
// ---------------------------------------------------------------------------

/// Remoc RPC counterpart of [`WebTransportSession`] for IPC.
///
/// All stream-opening methods receive a receiver-chosen FD transfer ID and
/// return the underlying QUIC stream ID after the FD delivery has been
/// queued to the local mux writer FIFO.
///
/// The `session_id` is not included — it is passed via [`WebTransportSessionBootstrap`].
#[remoc::rtc::remote]
pub trait IpcWebTransportSession: Send + Sync {
    async fn drain(&self) -> Result<(), DrainSessionError>;

    async fn close(&self, close: CloseSession) -> Result<(), CloseSessionError>;

    async fn drained(&self) -> Result<SessionDrain, CloseReason>;

    async fn closed(&self) -> Result<CloseReason, CloseReason>;

    /// Open a bidirectional stream. Returns the stream ID.
    /// The caller retrieves **2 FDs** from the registry.
    async fn open_bi(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError>;

    /// Open a unidirectional (send-only) stream. Returns the stream ID.
    /// The caller retrieves **1 FD**.
    async fn open_uni(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError>;

    /// Accept an incoming bidirectional stream. Returns the stream ID.
    /// The caller retrieves **2 FDs**.
    async fn accept_bi(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError>;

    /// Accept an incoming unidirectional (receive-only) stream.
    /// Returns the stream ID. The caller retrieves **1 FD**.
    async fn accept_uni(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError>;
}

// ---------------------------------------------------------------------------
// Error helpers (server side)
// ---------------------------------------------------------------------------

fn ipc_open_io(err: impl std::error::Error, context: &str) -> IpcWebTransportOpenError {
    debug!(error = %snafu::Report::from_error(&err), context, "ipc webtransport session i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
    .into()
}

fn ipc_accept_io(err: impl std::error::Error, context: &str) -> IpcWebTransportAcceptError {
    debug!(error = %snafu::Report::from_error(&err), context, "ipc webtransport session i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
    .into()
}

// ---------------------------------------------------------------------------
// Error helpers (client side) — latch errors into connection lifecycle
// ---------------------------------------------------------------------------

/// Convert an [`IpcPlumbingError`] into a [`ConnectionError`] representing an IPC
/// transport failure.
fn ipc_connection_error(error: &IpcPlumbingError) -> ConnectionError {
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: error.to_string().into(),
        },
    }
}

fn ipc_accept_error_connection(error: IpcWebTransportAcceptError) -> Option<ConnectionError> {
    match error {
        IpcWebTransportAcceptError::Closed => None,
        IpcWebTransportAcceptError::Connection { source } => Some(source),
        IpcWebTransportAcceptError::Transport { source } => Some(ipc_connection_error(&source)),
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// One-shot bootstrap payload for a WebTransport session over IPC.
///
/// Sent over the remoc channel when a WebTransport session is established
/// across the process boundary.
#[derive(Serialize, Deserialize)]
pub struct WebTransportSessionBootstrap {
    /// The session ID (immutable, no RPC needed).
    pub session_id: WebTransportSessionId,
    /// RPC client for WebTransport session stream operations.
    pub session: IpcWebTransportSessionClient,
}

// ---------------------------------------------------------------------------
// Server side: WebTransportSessionAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter that wraps a real [`WebTransportSession`] and
/// implements [`IpcWebTransportSession`].
///
/// Each stream-opening call:
/// 1. Delegates to the inner session to get real boxed streams.
/// 2. Creates Unix socketpairs.
/// 3. Spawns bridge tasks executing typed stream-frame IPC against real streams.
/// 4. Delivers client-side FDs through [`FdTransfer`].
/// 5. Returns the stream ID over RPC after FD delivery is queued.
pub struct WebTransportSessionAdapter {
    session: Arc<webtransport::WebTransportSession>,
    fd_transfer: FdTransfer,
    _lifecycle: Arc<dyn DynLifecycle>,
    tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
}

impl WebTransportSessionAdapter {
    pub fn new(
        session: Arc<webtransport::WebTransportSession>,
        fd_transfer: FdTransfer,
        lifecycle: Arc<dyn DynLifecycle>,
    ) -> Self {
        Self {
            session,
            fd_transfer,
            _lifecycle: lifecycle,
            tasks: Mutex::new(Vec::new()),
        }
    }

    fn spawn_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let handle = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));
        let mut tasks = self
            .tasks
            .lock()
            .expect("webtransport adapter task registry should not be poisoned");
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }
}

impl IpcWebTransportSession for WebTransportSessionAdapter {
    async fn drain(&self) -> Result<(), DrainSessionError> {
        self.session.drain().await
    }

    async fn close(&self, close: CloseSession) -> Result<(), CloseSessionError> {
        self.session.close(close).await
    }

    async fn drained(&self) -> Result<SessionDrain, CloseReason> {
        Ok(self.session.drained().await)
    }

    async fn closed(&self) -> Result<CloseReason, CloseReason> {
        Ok(self.session.closed().await)
    }

    async fn open_bi(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = self.session.open_bi().await?;

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        self.bridge_bi(
            delivery,
            Box::pin(reader) as BoxQuicStreamReader,
            Box::pin(writer) as BoxQuicStreamWriter,
            stream_id,
        )
        .await
    }

    async fn accept_bi(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = match self.session.accept_bi().await {
            Ok(streams) => streams,
            Err(error) => return Err(error.into()),
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        self.bridge_bi_accept(
            delivery,
            Box::pin(reader) as BoxQuicStreamReader,
            Box::pin(writer) as BoxQuicStreamWriter,
            stream_id,
        )
        .await
    }

    async fn open_uni(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let mut writer = self.session.open_uni().await?;

        let stream_id = GetStreamIdExt::stream_id(&mut writer)
            .await
            .map_err(IpcPlumbingError::from)?;

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;
        if let Err(error) = delivery.deliver(smallvec![cli_std.into()]).await {
            let _ = writer.reset(Code::H3_REQUEST_CANCELLED.into_inner()).await;
            return Err(ipc_open_io(error, "deliver fds"));
        }

        // Write frame IO on srv ↔ real WebTransport write stream.
        self.spawn_task(bridge_writer(srv, writer));

        Ok(stream_id)
    }

    async fn accept_uni(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let mut reader = match self.session.accept_uni().await {
            Ok(stream) => stream,
            Err(error) => return Err(error.into()),
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;
        if let Err(error) = delivery.deliver(smallvec![cli_std.into()]).await {
            let _ = reader.stop(Code::H3_REQUEST_CANCELLED.into_inner()).await;
            return Err(ipc_accept_io(error, "deliver fds"));
        }

        // Real WebTransport read stream ↔ read frame IO on srv.
        self.spawn_task(bridge_reader(reader, srv));

        Ok(stream_id)
    }
}

impl WebTransportSessionAdapter {
    /// Shared logic for open_bi: create 2 socketpairs and bridge.
    async fn bridge_bi(
        &self,
        delivery: FdDelivery,
        mut reader: BoxQuicStreamReader,
        mut writer: BoxQuicStreamWriter,
        stream_id: VarInt,
    ) -> Result<VarInt, IpcWebTransportOpenError> {
        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;

        if let Err(error) = delivery
            .deliver(smallvec![cli_a_std.into(), cli_b_std.into()])
            .await
        {
            let code = Code::H3_REQUEST_CANCELLED.into_inner();
            let _ = reader.stop(code).await;
            let _ = writer.reset(code).await;
            return Err(ipc_open_io(error, "deliver fds"));
        }

        // Bridge reader direction: real WebTransport reader ↔ read frame IO on srv_a.
        self.spawn_task(bridge_reader(reader, srv_a));

        // Bridge writer direction: write frame IO on srv_b ↔ real WebTransport writer.
        self.spawn_task(bridge_writer(srv_b, writer));

        Ok(stream_id)
    }

    /// Shared logic for accept_bi: create 2 socketpairs and bridge.
    async fn bridge_bi_accept(
        &self,
        delivery: FdDelivery,
        mut reader: BoxQuicStreamReader,
        mut writer: BoxQuicStreamWriter,
        stream_id: VarInt,
    ) -> Result<VarInt, IpcWebTransportAcceptError> {
        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;

        if let Err(error) = delivery
            .deliver(smallvec![cli_a_std.into(), cli_b_std.into()])
            .await
        {
            let code = Code::H3_REQUEST_CANCELLED.into_inner();
            let _ = reader.stop(code).await;
            let _ = writer.reset(code).await;
            return Err(ipc_accept_io(error, "deliver fds"));
        }

        self.spawn_task(bridge_reader(reader, srv_a));

        self.spawn_task(bridge_writer(srv_b, writer));

        Ok(stream_id)
    }
}

// ---------------------------------------------------------------------------
// IpcWebTransportLifecycle: session-level lifecycle for IPC WebTransport streams
// ---------------------------------------------------------------------------

/// Internal lifecycle state for [`IpcWebTransportSessionHandle`].
///
/// Delegates to the parent connection's lifecycle while maintaining a local
/// [`ConnectionErrorLatch`].  Implements [`quic::Lifecycle`] so it can be
/// shared with direct IPC stream-frame bridge handles.
struct IpcWebTransportLifecycle {
    parent: Arc<dyn DynLifecycle>,
    latch: ConnectionErrorLatch,
}

impl HasLatch for IpcWebTransportLifecycle {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for IpcWebTransportLifecycle {
    fn close(&self, code: crate::error::Code, reason: std::borrow::Cow<'static, str>) {
        DynLifecycle::close(self.parent.as_ref(), code, reason);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        self.check_with_probe(|| DynLifecycle::check(self.parent.as_ref()).err())
    }

    async fn closed(&self) -> ConnectionError {
        self.resolve_closed(async { DynLifecycle::closed(self.parent.as_ref()).await })
            .await
    }
}

// ---------------------------------------------------------------------------
// Client side: IpcWebTransportSessionHandle
// ---------------------------------------------------------------------------

/// Client-side WebTransport session handle that wraps an
/// [`IpcWebTransportSessionClient`] and provides async stream management via FD passing.
///
/// Created by the client after receiving a [`WebTransportSessionBootstrap`] over the
/// remoc channel.
pub struct IpcWebTransportSessionHandle {
    session_id: WebTransportSessionId,
    rpc: IpcWebTransportSessionClient,
    fd_transfer: FdTransfer,
    lifecycle: Arc<IpcWebTransportLifecycle>,
}

impl IpcWebTransportSessionHandle {
    /// Create a new handle from bootstrap data, FD registry, and the parent
    /// connection's lifecycle.
    pub fn new(
        session_id: WebTransportSessionId,
        rpc: IpcWebTransportSessionClient,
        fd_transfer: FdTransfer,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> Self {
        let lifecycle = Arc::new(IpcWebTransportLifecycle {
            parent: conn_lifecycle,
            latch: ConnectionErrorLatch::new(),
        });
        Self {
            session_id,
            rpc,
            fd_transfer,
            lifecycle,
        }
    }

    /// Guard an IPC open operation: check lifecycle, execute, lazily latch
    /// any resulting error.
    async fn guard_ipc_open<T>(
        &self,
        fut: impl Future<Output = Result<T, IpcWebTransportOpenError>>,
    ) -> Result<T, OpenStreamError> {
        self.lifecycle
            .guard_open_with(fut, |e| match e {
                IpcWebTransportOpenError::Stream { source } => source,
                IpcWebTransportOpenError::Transport { source } => OpenStreamError::Open {
                    source: ipc_connection_error(&source),
                },
            })
            .await
    }

    /// Guard an IPC accept operation: check lifecycle, execute, lazily latch
    /// any resulting transport error.
    async fn guard_ipc_accept<T>(
        &self,
        fut: impl Future<Output = Result<T, IpcWebTransportAcceptError>>,
    ) -> Result<T, AcceptStreamError> {
        self.lifecycle
            .guard_accept_err(fut, ipc_accept_error_connection)
            .await
    }

    /// Log and lazily latch an IPC plumbing error for open operations.
    fn latch_open_transport(&self, err: impl std::error::Error, context: &str) -> OpenStreamError {
        debug!(error = %snafu::Report::from_error(&err), context, "ipc webtransport session error");
        let message = format!("ipc webtransport: {context}: {err}");
        let source = self.lifecycle.latch().latch_with(|| {
            let plumbing = IpcPlumbingError::Io { message };
            ipc_connection_error(&plumbing)
        });
        OpenStreamError::Open { source }
    }

    /// Log and lazily latch an IPC plumbing error for accept operations.
    fn latch_accept_transport(
        &self,
        err: impl std::error::Error,
        context: &str,
    ) -> AcceptStreamError {
        debug!(error = %snafu::Report::from_error(&err), context, "ipc webtransport session error");
        let message = format!("ipc webtransport: {context}: {err}");
        let source = self.lifecycle.latch().latch_with(|| {
            let plumbing = IpcPlumbingError::Io { message };
            ipc_connection_error(&plumbing)
        });
        AcceptStreamError::Connection { source }
    }

    fn fd_to_open_unix_stream(
        &self,
        fd: std::os::fd::OwnedFd,
    ) -> Result<UnixStream, OpenStreamError> {
        let std_stream = std::os::unix::net::UnixStream::from(fd);
        std_stream
            .set_nonblocking(true)
            .map_err(|e| self.latch_open_transport(e, "set_nonblocking"))?;
        UnixStream::from_std(std_stream)
            .map_err(|e| self.latch_open_transport(e, "unix stream from_std"))
    }

    fn fd_to_accept_unix_stream(
        &self,
        fd: std::os::fd::OwnedFd,
    ) -> Result<UnixStream, AcceptStreamError> {
        let std_stream = std::os::unix::net::UnixStream::from(fd);
        std_stream
            .set_nonblocking(true)
            .map_err(|e| self.latch_accept_transport(e, "set_nonblocking"))?;
        UnixStream::from_std(std_stream)
            .map_err(|e| self.latch_accept_transport(e, "unix stream from_std"))
    }

    async fn resolve_open_with_fds(
        &self,
        receiver: crate::ipc::transport::FdReceiver,
        rpc: impl Future<Output = Result<VarInt, IpcWebTransportOpenError>>,
    ) -> Result<(VarInt, ReceivedFds), IpcWebTransportOpenError> {
        let receive = receiver.into_future();
        tokio::pin!(receive);
        tokio::pin!(rpc);

        tokio::select! {
            biased;
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_open_io(e, "receive fds"))?;
                let stream_id = rpc.await?;
                Ok((stream_id, received))
            }
            rpc_result = &mut rpc => {
                let stream_id = rpc_result?;
                let received = receive.await.map_err(|e| ipc_open_io(e, "receive fds"))?;
                Ok((stream_id, received))
            }
        }
    }

    async fn resolve_accept_with_fds(
        &self,
        receiver: crate::ipc::transport::FdReceiver,
        rpc: impl Future<Output = Result<VarInt, IpcWebTransportAcceptError>>,
    ) -> Result<(VarInt, ReceivedFds), IpcWebTransportAcceptError> {
        let receive = receiver.into_future();
        tokio::pin!(receive);
        tokio::pin!(rpc);

        tokio::select! {
            biased;
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_accept_io(e, "receive fds"))?;
                let stream_id = rpc.await?;
                Ok((stream_id, received))
            }
            rpc_result = &mut rpc => {
                let stream_id = rpc_result?;
                let received = receive.await.map_err(|e| ipc_accept_io(e, "receive fds"))?;
                Ok((stream_id, received))
            }
        }
    }
}

impl webtransport::Session for IpcWebTransportSessionHandle {
    type StreamReader = BoxQuicStreamReader;
    type StreamWriter = BoxQuicStreamWriter;

    fn id(&self) -> WebTransportSessionId {
        self.session_id
    }

    async fn drain(&self) -> Result<(), DrainSessionError> {
        IpcWebTransportSession::drain(&self.rpc).await
    }

    async fn close(&self, close: CloseSession) -> Result<(), CloseSessionError> {
        IpcWebTransportSession::close(&self.rpc, close).await
    }

    async fn drained(&self) -> SessionDrain {
        match IpcWebTransportSession::drained(&self.rpc).await {
            Ok(drain) => drain,
            Err(reason) => SessionDrain::Closed(reason),
        }
    }

    async fn closed(&self) -> CloseReason {
        match IpcWebTransportSession::closed(&self.rpc).await {
            Ok(reason) | Err(reason) => reason,
        }
    }

    async fn open_bi(&self) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), OpenStreamError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        let (stream_id, received) =
            self.guard_ipc_open(self.resolve_open_with_fds(
                receiver,
                IpcWebTransportSession::open_bi(&self.rpc, fd_id),
            ))
            .await?;
        self.fds_to_bi(stream_id, received).await
    }

    async fn accept_bi(
        &self,
    ) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), AcceptStreamError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        let (stream_id, received) = self
            .guard_ipc_accept(self.resolve_accept_with_fds(
                receiver,
                IpcWebTransportSession::accept_bi(&self.rpc, fd_id),
            ))
            .await?;
        self.fds_to_bi_accept(stream_id, received).await
    }

    async fn open_uni(&self) -> Result<BoxQuicStreamWriter, OpenStreamError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        let (stream_id, received) = self
            .guard_ipc_open(self.resolve_open_with_fds(
                receiver,
                IpcWebTransportSession::open_uni(&self.rpc, fd_id),
            ))
            .await?;
        self.fds_to_uni_writer(stream_id, received).await
    }

    async fn accept_uni(&self) -> Result<BoxQuicStreamReader, AcceptStreamError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        let (stream_id, received) = self
            .guard_ipc_accept(self.resolve_accept_with_fds(
                receiver,
                IpcWebTransportSession::accept_uni(&self.rpc, fd_id),
            ))
            .await?;
        self.fds_to_uni_reader(stream_id, received).await
    }
}

impl IpcWebTransportSessionHandle {
    /// Retrieve 2 FDs and construct boxed IPC stream-frame bridge handles.
    async fn fds_to_bi(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), OpenStreamError> {
        let (fd_a, fd_b) = received
            .into_pair()
            .map_err(|e| self.latch_open_transport(e, "fd count"))?;

        let lifecycle = self.lifecycle.clone();

        let sock_a = self.fd_to_open_unix_stream(fd_a)?;
        let reader = Box::pin(ipc_reader::reader(stream_id, sock_a, lifecycle.clone()))
            as BoxQuicStreamReader;

        let sock_b = self.fd_to_open_unix_stream(fd_b)?;
        let writer =
            Box::pin(ipc_writer::writer(stream_id, sock_b, lifecycle)) as BoxQuicStreamWriter;

        Ok((reader, writer))
    }

    /// Retrieve 2 FDs for accept_bi.
    async fn fds_to_bi_accept(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), AcceptStreamError> {
        let (fd_a, fd_b) = received
            .into_pair()
            .map_err(|e| self.latch_accept_transport(e, "fd count"))?;

        let lifecycle = self.lifecycle.clone();

        let sock_a = self.fd_to_accept_unix_stream(fd_a)?;
        let reader = Box::pin(ipc_reader::reader(stream_id, sock_a, lifecycle.clone()))
            as BoxQuicStreamReader;

        let sock_b = self.fd_to_accept_unix_stream(fd_b)?;
        let writer =
            Box::pin(ipc_writer::writer(stream_id, sock_b, lifecycle)) as BoxQuicStreamWriter;

        Ok((reader, writer))
    }

    /// Retrieve 1 FD and construct a boxed IPC write bridge (for open_uni).
    async fn fds_to_uni_writer(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<BoxQuicStreamWriter, OpenStreamError> {
        let fd = received
            .into_one()
            .map_err(|e| self.latch_open_transport(e, "fd count"))?;
        let lifecycle = self.lifecycle.clone();
        let sock = self.fd_to_open_unix_stream(fd)?;
        Ok(Box::pin(ipc_writer::writer(stream_id, sock, lifecycle)) as BoxQuicStreamWriter)
    }

    /// Retrieve 1 FD and construct a boxed IPC read bridge (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<BoxQuicStreamReader, AcceptStreamError> {
        let fd = received
            .into_one()
            .map_err(|e| self.latch_accept_transport(e, "fd count"))?;
        let lifecycle = self.lifecycle.clone();
        let sock = self.fd_to_accept_unix_stream(fd)?;
        Ok(Box::pin(ipc_reader::reader(stream_id, sock, lifecycle)) as BoxQuicStreamReader)
    }
}

impl IpcWebTransportSessionClient {
    /// Convert into an [`IpcWebTransportSessionHandle`].
    pub fn into_handle(
        self,
        session_id: WebTransportSessionId,
        fd_transfer: FdTransfer,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> IpcWebTransportSessionHandle {
        IpcWebTransportSessionHandle::new(session_id, self, fd_transfer, conn_lifecycle)
    }
}

#[cfg(test)]
mod tests {
    use std::future;

    use remoc::prelude::ServerShared;

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        dhttp::{
            message::{MessageWriter, test::read_stream_for_test},
            protocol::DHttpProtocol,
            settings::Settings,
            webtransport::settings::{
                EnableWebTransport, InitialMaxData, InitialMaxStreamsBidi, InitialMaxStreamsUni,
            },
        },
        extended_connect::{EstablishedConnect, PendingWriteStreamError},
        protocol::Protocols,
        qpack::field::Protocol,
        stream_id::StreamId,
        webtransport::{
            CloseReason, CloseSession, DrainReason, SessionCloseReason, SessionDrain,
            SessionDrainReason, WEBTRANSPORT_H3, WebTransportProtocol,
        },
    };

    fn connection_error(reason: &'static str) -> ConnectionError {
        ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn assert_transport_reason(error: &ConnectionError, expected: &str) {
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    fn connection_with_webtransport(
        mock: Arc<MockConnection>,
    ) -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let erased: Arc<dyn quic::DynConnection> = mock.clone();
        let mut protocols = Protocols::new();
        let dhttp = DHttpProtocol::new_for_test(erased.clone());
        dhttp
            .state
            .peer_settings
            .set(Arc::new(enabled_webtransport_settings()))
            .expect("peer settings should be set once");
        protocols.insert(dhttp);
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        Arc::new(ConnectionState::new_for_test(mock, Arc::new(protocols)).erase())
    }

    fn enabled_webtransport_settings() -> Settings {
        let mut settings = Settings::default();
        settings.set(EnableWebTransport::setting(true));
        settings.set(InitialMaxStreamsBidi::setting(VarInt::from_u32(16)));
        settings.set(InitialMaxStreamsUni::setting(VarInt::from_u32(16)));
        settings.set(InitialMaxData::setting(VarInt::MAX));
        settings
    }

    fn webtransport_session_for_test(
        mock: Arc<MockConnection>,
        stream_id: StreamId,
    ) -> Arc<webtransport::WebTransportSession> {
        let connection = connection_with_webtransport(mock);
        let session = webtransport::WebTransportSession::try_from(EstablishedConnect::pending(
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection.clone(),
            read_stream_for_test(stream_id.0),
            future::pending::<Result<MessageWriter, PendingWriteStreamError>>(),
        ))
        .expect("webtransport session should be registered");
        Arc::new(session)
    }

    fn spawn_ipc_session<S>(
        session: Arc<S>,
    ) -> (AbortOnDropHandle<()>, IpcWebTransportSessionClient)
    where
        S: IpcWebTransportSession + 'static,
    {
        let (server, client) = IpcWebTransportSessionServerShared::new(session, 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    struct TestIpcSession {
        drained: Mutex<bool>,
        closed: Mutex<Option<CloseSession>>,
    }

    impl TestIpcSession {
        fn new() -> Self {
            Self {
                drained: Mutex::new(false),
                closed: Mutex::new(None),
            }
        }
    }

    impl IpcWebTransportSession for TestIpcSession {
        async fn drain(&self) -> Result<(), DrainSessionError> {
            *self
                .drained
                .lock()
                .expect("drained mutex should not poison") = true;
            Ok(())
        }

        async fn close(&self, close: CloseSession) -> Result<(), CloseSessionError> {
            *self.closed.lock().expect("closed mutex should not poison") = Some(close);
            Ok(())
        }

        async fn drained(&self) -> Result<SessionDrain, CloseReason> {
            if *self
                .drained
                .lock()
                .expect("drained mutex should not poison")
            {
                Ok(SessionDrain::Requested(DrainReason::Session(
                    SessionDrainReason::Local,
                )))
            } else {
                Ok(SessionDrain::Closed(CloseReason::Session(
                    SessionCloseReason::ControlStreamError,
                )))
            }
        }

        async fn closed(&self) -> Result<CloseReason, CloseReason> {
            match self
                .closed
                .lock()
                .expect("closed mutex should not poison")
                .clone()
            {
                Some(close) => Ok(CloseReason::Session(SessionCloseReason::Local(close))),
                None => Ok(CloseReason::Session(SessionCloseReason::ControlStreamError)),
            }
        }

        async fn open_bi(&self, _fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError> {
            Err(IpcPlumbingError::Io {
                message: "test ipc session does not open bidi streams".into(),
            }
            .into())
        }

        async fn open_uni(&self, _fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError> {
            Err(IpcPlumbingError::Io {
                message: "test ipc session does not open uni streams".into(),
            }
            .into())
        }

        async fn accept_bi(&self, _fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError> {
            Err(IpcWebTransportAcceptError::Closed)
        }

        async fn accept_uni(&self, _fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError> {
            Err(IpcWebTransportAcceptError::Closed)
        }
    }

    fn fd_transfer_for_test() -> crate::ipc::transport::FdTransfer {
        let (mux, _peer) =
            crate::ipc::transport::MuxChannel::pair_for_test().expect("mux channel pair");
        let (sink, stream) = mux.split().expect("split mux channel");
        stream.fd_transfer(sink.fd_sender())
    }

    fn webtransport_adapter(reason: &'static str) -> WebTransportSessionAdapter {
        let mock = Arc::new(MockConnection::new());
        let session =
            webtransport_session_for_test(mock.clone(), StreamId::from(VarInt::from_u32(4)));
        mock.set_terminal_error(connection_error(reason));
        let lifecycle: Arc<dyn DynLifecycle> = mock;
        WebTransportSessionAdapter::new(session, fd_transfer_for_test(), lifecycle)
    }

    #[test]
    fn ipc_accept_error_preserves_connection_source() {
        let error = IpcWebTransportAcceptError::from(AcceptStreamError::Connection {
            source: connection_error("accept connection closed"),
        });

        let IpcWebTransportAcceptError::Connection { source } = error else {
            panic!("expected IPC accept connection error");
        };
        assert_transport_reason(&source, "accept connection closed");
    }

    #[test]
    fn ipc_accept_error_connection_mapping_preserves_connection_source() {
        let source = ipc_accept_error_connection(IpcWebTransportAcceptError::Connection {
            source: connection_error("mapped accept connection closed"),
        })
        .expect("connection IPC accept error should latch a connection error");

        assert_transport_reason(&source, "mapped accept connection closed");
        assert!(ipc_accept_error_connection(IpcWebTransportAcceptError::Closed).is_none());
    }

    #[tokio::test]
    async fn webtransport_adapter_preserves_connection_closed_accepts() {
        let adapter = webtransport_adapter("accept_bi connection closed");
        let error = IpcWebTransportSession::accept_bi(&adapter, VarInt::from_u32(1))
            .await
            .expect_err("accept_bi should preserve connection failure");
        let IpcWebTransportAcceptError::Connection { source } = error else {
            panic!("expected accept_bi connection error");
        };
        assert_transport_reason(&source, "accept_bi connection closed");

        let adapter = webtransport_adapter("accept_uni connection closed");
        let error = IpcWebTransportSession::accept_uni(&adapter, VarInt::from_u32(2))
            .await
            .expect_err("accept_uni should preserve connection failure");
        let IpcWebTransportAcceptError::Connection { source } = error else {
            panic!("expected accept_uni connection error");
        };
        assert_transport_reason(&source, "accept_uni connection closed");
    }

    #[tokio::test]
    async fn ipc_webtransport_session_delegates_control_methods() {
        let lifecycle = Arc::new(MockConnection::new());
        let session_id = WebTransportSessionId::try_from(StreamId::from(VarInt::from_u32(4)))
            .expect("test session id should be valid");
        let session = Arc::new(TestIpcSession::new());
        let (_server_task, client) = spawn_ipc_session(session);
        let handle_lifecycle: Arc<dyn DynLifecycle> = lifecycle;
        let handle = IpcWebTransportSessionHandle::new(
            session_id,
            client,
            fd_transfer_for_test(),
            handle_lifecycle,
        );
        let close = CloseSession::try_from((5_u32, "bye")).expect("valid close");

        webtransport::Session::drain(&handle)
            .await
            .expect("ipc drain should succeed");
        assert_eq!(
            webtransport::Session::drained(&handle).await,
            SessionDrain::Requested(DrainReason::Session(SessionDrainReason::Local))
        );

        webtransport::Session::close(&handle, close.clone())
            .await
            .expect("ipc close should succeed");
        assert_eq!(
            webtransport::Session::closed(&handle).await,
            CloseReason::Session(SessionCloseReason::Local(close))
        );
    }
}
