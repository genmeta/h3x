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
//! - **`open_bi` / `accept_bi`**: 2 FDs are delivered (reader pipe + writer pipe).
//! - **`open_uni`**: 1 FD (writer pipe, server side reads from pipe and sends
//!   to the real WebTransport uni stream).
//! - **`accept_uni`**: 1 FD (reader pipe, server side reads from the real
//!   WebTransport uni stream and writes to pipe).

use std::{future::Future, sync::Arc};

use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use snafu::Snafu;
use tokio::net::UnixStream;
use tracing::{Instrument, debug};

/// WebTransport-flavoured lifecycle helpers for IPC-backed session handles.
///
/// IPC uses the same remoc control-plane and connection-error latch discipline
/// as RPC WebTransport handles, so this module reuses the RPC helper trait
/// directly while preserving the `ipc::webtransport::LifecycleExt` path.
pub use crate::rpc::webtransport::LifecycleExt;
use crate::{
    codec::{BoxReadStream, BoxWriteStream},
    ipc::{
        quic::{
            IpcReadStream, IpcWriteStream,
            connection::{IPC_ERROR_KIND, IPC_FRAME_TYPE, bridge_reader, bridge_writer},
        },
        transport::{FdDelivery, FdTransfer, ReceivedFds},
    },
    quic::{self, ConnectionError, DynLifecycle, GetStreamIdExt},
    rpc::lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt as _},
    stream_id::StreamId,
    varint::VarInt,
    webtransport::{self, AcceptStreamError, OpenStreamError, SessionClosed},
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

// ---------------------------------------------------------------------------
// IPC RTC trait
// ---------------------------------------------------------------------------

/// Remoc RPC counterpart of [`WebTransportSession`] for IPC.
///
/// All stream-opening methods receive a receiver-chosen FD transfer ID and
/// return the underlying QUIC stream ID after the FD delivery has been
/// acknowledged.
///
/// The `session_id` is not included — it is passed via [`WebTransportSessionBootstrap`].
#[remoc::rtc::remote]
pub trait IpcWebTransportSession: Send + Sync {
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

fn ipc_open_io(err: impl std::fmt::Display, context: &str) -> IpcWebTransportOpenError {
    debug!(error = %err, context, "ipc webtransport session i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
    .into()
}

fn ipc_accept_io(err: impl std::fmt::Display, context: &str) -> IpcWebTransportAcceptError {
    debug!(error = %err, context, "ipc webtransport session i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
    .into()
}

fn ipc_open_cancelled(context: &str) -> IpcWebTransportOpenError {
    debug!(context, "ipc webtransport fd transfer cancelled");
    IpcPlumbingError::Io {
        message: format!("{context}: fd transfer cancelled"),
    }
    .into()
}

fn ipc_accept_cancelled(context: &str) -> IpcWebTransportAcceptError {
    debug!(context, "ipc webtransport fd transfer cancelled");
    IpcPlumbingError::Io {
        message: format!("{context}: fd transfer cancelled"),
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
    pub session_id: VarInt,
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
/// 3. Spawns bridge tasks forwarding data between real streams and pipes.
/// 4. Delivers client-side FDs through [`FdTransfer`].
/// 5. Returns the stream ID over RPC after FD delivery is acknowledged.
pub struct WebTransportSessionAdapter {
    session: Arc<webtransport::WebTransportSession>,
    fd_transfer: FdTransfer,
    lifecycle: Arc<dyn DynLifecycle>,
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
            lifecycle,
        }
    }
}

impl IpcWebTransportSession for WebTransportSessionAdapter {
    async fn open_bi(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError> {
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_open_cancelled("open_bi")),
            result = self.session.open_bi() => result?,
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        self.bridge_bi(delivery, reader, writer, stream_id).await
    }

    async fn accept_bi(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError> {
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_accept_cancelled("accept_bi")),
            result = self.session.accept_bi() => {
                match result {
                    Ok(streams) => streams,
                    Err(AcceptStreamError::Closed { source }) => return Err(source.into()),
                    Err(AcceptStreamError::Connection { source: _ }) => {
                        return Err(IpcWebTransportAcceptError::Closed);
                    }
                }
            }
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        self.bridge_bi_accept(delivery, reader, writer, stream_id)
            .await
    }

    async fn open_uni(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportOpenError> {
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let mut writer = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_open_cancelled("open_uni")),
            result = self.session.open_uni() => result?,
        };

        let stream_id = GetStreamIdExt::stream_id(&mut writer)
            .await
            .map_err(IpcPlumbingError::from)?;

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;
        delivery
            .deliver(smallvec![cli_std.into()])
            .await
            .map_err(|e| ipc_open_io(e, "deliver fds"))?;

        // IpcReadStream on srv → real WebTransport write stream
        let pipe_r = IpcReadStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok(stream_id)
    }

    async fn accept_uni(&self, fd_id: VarInt) -> Result<VarInt, IpcWebTransportAcceptError> {
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let mut reader = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_accept_cancelled("accept_uni")),
            result = self.session.accept_uni() => {
                match result {
                    Ok(stream) => stream,
                    Err(AcceptStreamError::Closed { source }) => return Err(source.into()),
                    Err(AcceptStreamError::Connection { source: _ }) => {
                        return Err(IpcWebTransportAcceptError::Closed);
                    }
                }
            }
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;
        delivery
            .deliver(smallvec![cli_std.into()])
            .await
            .map_err(|e| ipc_accept_io(e, "deliver fds"))?;

        // Real WebTransport read stream → IpcWriteStream on srv
        let pipe_w = IpcWriteStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        Ok(stream_id)
    }
}

impl WebTransportSessionAdapter {
    /// Shared logic for open_bi: create 2 socketpairs and bridge.
    async fn bridge_bi(
        &self,
        delivery: FdDelivery,
        reader: BoxReadStream,
        writer: BoxWriteStream,
        stream_id: VarInt,
    ) -> Result<VarInt, IpcWebTransportOpenError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;

        delivery
            .deliver(smallvec![cli_a_std.into(), cli_b_std.into()])
            .await
            .map_err(|e| ipc_open_io(e, "deliver fds"))?;

        // Bridge reader direction: real WebTransport reader → IpcWriteStream on srv_a
        let pipe_w = IpcWriteStream::new(stream_id, srv_a, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        // Bridge writer direction: IpcReadStream on srv_b → real WebTransport writer
        let pipe_r = IpcReadStream::new(stream_id, srv_b, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok(stream_id)
    }

    /// Shared logic for accept_bi: create 2 socketpairs and bridge.
    async fn bridge_bi_accept(
        &self,
        delivery: FdDelivery,
        reader: BoxReadStream,
        writer: BoxWriteStream,
        stream_id: VarInt,
    ) -> Result<VarInt, IpcWebTransportAcceptError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;

        delivery
            .deliver(smallvec![cli_a_std.into(), cli_b_std.into()])
            .await
            .map_err(|e| ipc_accept_io(e, "deliver fds"))?;

        let pipe_w = IpcWriteStream::new(stream_id, srv_a, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        let pipe_r = IpcReadStream::new(stream_id, srv_b, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

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
/// shared with [`IpcReadStream`] / [`IpcWriteStream`] as
/// `Arc<dyn DynLifecycle>`.
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
    session_id: VarInt,
    rpc: IpcWebTransportSessionClient,
    fd_transfer: FdTransfer,
    lifecycle: Arc<IpcWebTransportLifecycle>,
}

impl IpcWebTransportSessionHandle {
    /// Create a new handle from bootstrap data, FD registry, and the parent
    /// connection's lifecycle.
    pub fn new(
        session_id: VarInt,
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
            .guard_accept_err(fut, |e| match e {
                IpcWebTransportAcceptError::Closed => None,
                IpcWebTransportAcceptError::Transport { source } => {
                    Some(ipc_connection_error(&source))
                }
            })
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
            rpc_result = &mut rpc => {
                let stream_id = rpc_result?;
                let received = receive.await.map_err(|e| ipc_open_io(e, "receive fds"))?;
                Ok((stream_id, received))
            }
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_open_io(e, "receive fds"))?;
                let stream_id = rpc.await?;
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
            rpc_result = &mut rpc => {
                let stream_id = rpc_result?;
                let received = receive.await.map_err(|e| ipc_accept_io(e, "receive fds"))?;
                Ok((stream_id, received))
            }
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_accept_io(e, "receive fds"))?;
                let stream_id = rpc.await?;
                Ok((stream_id, received))
            }
        }
    }
}

impl webtransport::Session for IpcWebTransportSessionHandle {
    type StreamReader = IpcReadStream;
    type StreamWriter = IpcWriteStream;

    fn id(&self) -> StreamId {
        self.session_id.into()
    }

    async fn open_bi(&self) -> Result<(IpcReadStream, IpcWriteStream), OpenStreamError> {
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

    async fn accept_bi(&self) -> Result<(IpcReadStream, IpcWriteStream), AcceptStreamError> {
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

    async fn open_uni(&self) -> Result<IpcWriteStream, OpenStreamError> {
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

    async fn accept_uni(&self) -> Result<IpcReadStream, AcceptStreamError> {
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
    /// Retrieve 2 FDs and construct a (IpcReadStream, IpcWriteStream) pair.
    async fn fds_to_bi(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<(IpcReadStream, IpcWriteStream), OpenStreamError> {
        let (fd_a, fd_b) = received
            .into_pair()
            .map_err(|e| self.latch_open_transport(e, "fd count"))?;

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let sock_a = self.fd_to_open_unix_stream(fd_a)?;
        let reader = IpcReadStream::new(stream_id, sock_a, lifecycle.clone());

        let sock_b = self.fd_to_open_unix_stream(fd_b)?;
        let writer = IpcWriteStream::new(stream_id, sock_b, lifecycle);

        Ok((reader, writer))
    }

    /// Retrieve 2 FDs for accept_bi.
    async fn fds_to_bi_accept(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<(IpcReadStream, IpcWriteStream), AcceptStreamError> {
        let (fd_a, fd_b) = received
            .into_pair()
            .map_err(|e| self.latch_accept_transport(e, "fd count"))?;

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let sock_a = self.fd_to_accept_unix_stream(fd_a)?;
        let reader = IpcReadStream::new(stream_id, sock_a, lifecycle.clone());

        let sock_b = self.fd_to_accept_unix_stream(fd_b)?;
        let writer = IpcWriteStream::new(stream_id, sock_b, lifecycle);

        Ok((reader, writer))
    }

    /// Retrieve 1 FD and construct a IpcWriteStream (for open_uni).
    async fn fds_to_uni_writer(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<IpcWriteStream, OpenStreamError> {
        let fd = received
            .into_one()
            .map_err(|e| self.latch_open_transport(e, "fd count"))?;
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
        let sock = self.fd_to_open_unix_stream(fd)?;
        Ok(IpcWriteStream::new(stream_id, sock, lifecycle))
    }

    /// Retrieve 1 FD and construct a IpcReadStream (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        stream_id: VarInt,
        received: ReceivedFds,
    ) -> Result<IpcReadStream, AcceptStreamError> {
        let fd = received
            .into_one()
            .map_err(|e| self.latch_accept_transport(e, "fd count"))?;
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
        let sock = self.fd_to_accept_unix_stream(fd)?;
        Ok(IpcReadStream::new(stream_id, sock, lifecycle))
    }
}

impl IpcWebTransportSessionClient {
    /// Convert into an [`IpcWebTransportSessionHandle`].
    pub fn into_handle(
        self,
        session_id: VarInt,
        fd_transfer: FdTransfer,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> IpcWebTransportSessionHandle {
        IpcWebTransportSessionHandle::new(session_id, self, fd_transfer, conn_lifecycle)
    }
}
