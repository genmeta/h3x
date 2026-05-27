//! IPC forwarding of WebTransport sessions via RPC + per-stream socketpairs.
//!
//! Parallel to [`super::quic`] which bridges QUIC connections over IPC, this
//! module bridges WebTransport sessions. Each WebTransport stream is forwarded
//! through a dedicated Unix socketpair while control-plane RPCs (open, accept)
//! travel over the remoc channel.
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
//! - **`open_bi` / `accept_bi`**: 2 FDs are queued (reader pipe + writer pipe).
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
        transport::{FdRegistry, FdSender},
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
/// FD conversion, queue) are serialized as strings.
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
/// All stream-opening methods return `(VarInt, VarInt)` pairs:
/// - First element: FD-registry ID for [`FdRegistry::wait_fds`].
/// - Second element: underlying QUIC stream ID.
///
/// The `session_id` is not included — it is passed via [`WebTransportSessionBootstrap`].
#[remoc::rtc::remote]
pub trait IpcWebTransportSession: Send + Sync {
    /// Open a bidirectional stream. Returns `(fd_id, stream_id)`.
    /// The caller retrieves **2 FDs** from the registry.
    async fn open_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError>;

    /// Open a unidirectional (send-only) stream. Returns `(fd_id, stream_id)`.
    /// The caller retrieves **1 FD**.
    async fn open_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError>;

    /// Accept an incoming bidirectional stream. Returns `(fd_id, stream_id)`.
    /// The caller retrieves **2 FDs**.
    async fn accept_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError>;

    /// Accept an incoming unidirectional (receive-only) stream.
    /// Returns `(fd_id, stream_id)`. The caller retrieves **1 FD**.
    async fn accept_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError>;
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
/// 4. Queues client-side FDs through [`FdSender`].
/// 5. Returns `(fd_registry_id, stream_id)` over RPC.
pub struct WebTransportSessionAdapter {
    session: Arc<webtransport::WebTransportSession>,
    fd_sender: FdSender,
    lifecycle: Arc<dyn DynLifecycle>,
}

impl WebTransportSessionAdapter {
    pub fn new(
        session: Arc<webtransport::WebTransportSession>,
        fd_sender: FdSender,
        lifecycle: Arc<dyn DynLifecycle>,
    ) -> Self {
        Self {
            session,
            fd_sender,
            lifecycle,
        }
    }
}

impl IpcWebTransportSession for WebTransportSessionAdapter {
    async fn open_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
        let (mut reader, writer) = self.session.open_bi().await?;

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        self.bridge_bi(reader, writer, stream_id)
    }

    async fn accept_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
        let (mut reader, writer) = match self.session.accept_bi().await {
            Ok(streams) => streams,
            Err(AcceptStreamError::Closed { source }) => return Err(source.into()),
            Err(AcceptStreamError::Connection { source: _ }) => {
                return Err(IpcWebTransportAcceptError::Closed);
            }
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        self.bridge_bi_accept(reader, writer, stream_id)
    }

    async fn open_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
        let mut writer = self.session.open_uni().await?;

        let stream_id = GetStreamIdExt::stream_id(&mut writer)
            .await
            .map_err(IpcPlumbingError::from)?;

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;
        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_std.into()])
            .map_err(|e| ipc_open_io(e, "queue_fds"))?;

        // IpcReadStream on srv → real WebTransport write stream
        let pipe_r = IpcReadStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok((fd_id, stream_id))
    }

    async fn accept_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
        let mut reader = match self.session.accept_uni().await {
            Ok(stream) => stream,
            Err(AcceptStreamError::Closed { source }) => return Err(source.into()),
            Err(AcceptStreamError::Connection { source: _ }) => {
                return Err(IpcWebTransportAcceptError::Closed);
            }
        };

        let stream_id = GetStreamIdExt::stream_id(&mut reader)
            .await
            .map_err(IpcPlumbingError::from)?;

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;
        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_std.into()])
            .map_err(|e| ipc_accept_io(e, "queue_fds"))?;

        // Real WebTransport read stream → IpcWriteStream on srv
        let pipe_w = IpcWriteStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        Ok((fd_id, stream_id))
    }
}

impl WebTransportSessionAdapter {
    /// Shared logic for open_bi: create 2 socketpairs and bridge.
    fn bridge_bi(
        &self,
        reader: BoxReadStream,
        writer: BoxWriteStream,
        stream_id: VarInt,
    ) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_open_io(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_open_io(e, "into_std"))?;

        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_a_std.into(), cli_b_std.into()])
            .map_err(|e| ipc_open_io(e, "queue_fds"))?;

        // Bridge reader direction: real WebTransport reader → IpcWriteStream on srv_a
        let pipe_w = IpcWriteStream::new(stream_id, srv_a, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        // Bridge writer direction: IpcReadStream on srv_b → real WebTransport writer
        let pipe_r = IpcReadStream::new(stream_id, srv_b, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok((fd_id, stream_id))
    }

    /// Shared logic for accept_bi: create 2 socketpairs and bridge.
    fn bridge_bi_accept(
        &self,
        reader: BoxReadStream,
        writer: BoxWriteStream,
        stream_id: VarInt,
    ) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_accept_io(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_accept_io(e, "into_std"))?;

        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_a_std.into(), cli_b_std.into()])
            .map_err(|e| ipc_accept_io(e, "queue_fds"))?;

        let pipe_w = IpcWriteStream::new(stream_id, srv_a, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        let pipe_r = IpcReadStream::new(stream_id, srv_b, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok((fd_id, stream_id))
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
    fd_registry: FdRegistry,
    lifecycle: Arc<IpcWebTransportLifecycle>,
}

impl IpcWebTransportSessionHandle {
    /// Create a new handle from bootstrap data, FD registry, and the parent
    /// connection's lifecycle.
    pub fn new(
        session_id: VarInt,
        rpc: IpcWebTransportSessionClient,
        fd_registry: FdRegistry,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> Self {
        let lifecycle = Arc::new(IpcWebTransportLifecycle {
            parent: conn_lifecycle,
            latch: ConnectionErrorLatch::new(),
        });
        Self {
            session_id,
            rpc,
            fd_registry,
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
}

impl webtransport::Session for IpcWebTransportSessionHandle {
    type StreamReader = IpcReadStream;
    type StreamWriter = IpcWriteStream;

    fn id(&self) -> StreamId {
        self.session_id.into()
    }

    async fn open_bi(&self) -> Result<(IpcReadStream, IpcWriteStream), OpenStreamError> {
        let (fd_id, stream_id) = self
            .guard_ipc_open(IpcWebTransportSession::open_bi(&self.rpc))
            .await?;
        self.fds_to_bi(fd_id, stream_id).await
    }

    async fn accept_bi(&self) -> Result<(IpcReadStream, IpcWriteStream), AcceptStreamError> {
        let (fd_id, stream_id) = self
            .guard_ipc_accept(IpcWebTransportSession::accept_bi(&self.rpc))
            .await?;
        self.fds_to_bi_accept(fd_id, stream_id).await
    }

    async fn open_uni(&self) -> Result<IpcWriteStream, OpenStreamError> {
        let (fd_id, stream_id) = self
            .guard_ipc_open(IpcWebTransportSession::open_uni(&self.rpc))
            .await?;
        self.fds_to_uni_writer(fd_id, stream_id).await
    }

    async fn accept_uni(&self) -> Result<IpcReadStream, AcceptStreamError> {
        let (fd_id, stream_id) = self
            .guard_ipc_accept(IpcWebTransportSession::accept_uni(&self.rpc))
            .await?;
        self.fds_to_uni_reader(fd_id, stream_id).await
    }
}

impl IpcWebTransportSessionHandle {
    /// Retrieve 2 FDs and construct a (IpcReadStream, IpcWriteStream) pair.
    async fn fds_to_bi(
        &self,
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<(IpcReadStream, IpcWriteStream), OpenStreamError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_open_transport(e, "wait_fds"))?;
        if fds.len() != 2 {
            return Err(self.latch_open_transport(
                FdCountError {
                    expected: 2,
                    got: fds.len(),
                },
                "fd count",
            ));
        }
        let mut fds = fds.into_iter();
        let fd_a = fds.next().unwrap();
        let fd_b = fds.next().unwrap();

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
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<(IpcReadStream, IpcWriteStream), AcceptStreamError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_accept_transport(e, "wait_fds"))?;
        if fds.len() != 2 {
            return Err(self.latch_accept_transport(
                FdCountError {
                    expected: 2,
                    got: fds.len(),
                },
                "fd count",
            ));
        }
        let mut fds = fds.into_iter();
        let fd_a = fds.next().unwrap();
        let fd_b = fds.next().unwrap();

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
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<IpcWriteStream, OpenStreamError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_open_transport(e, "wait_fds"))?;
        if fds.len() != 1 {
            return Err(self.latch_open_transport(
                FdCountError {
                    expected: 1,
                    got: fds.len(),
                },
                "fd count",
            ));
        }
        let fd = fds.into_iter().next().unwrap();
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
        let sock = self.fd_to_open_unix_stream(fd)?;
        Ok(IpcWriteStream::new(stream_id, sock, lifecycle))
    }

    /// Retrieve 1 FD and construct a IpcReadStream (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<IpcReadStream, AcceptStreamError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_accept_transport(e, "wait_fds"))?;
        if fds.len() != 1 {
            return Err(self.latch_accept_transport(
                FdCountError {
                    expected: 1,
                    got: fds.len(),
                },
                "fd count",
            ));
        }
        let fd = fds.into_iter().next().unwrap();
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
        let sock = self.fd_to_accept_unix_stream(fd)?;
        Ok(IpcReadStream::new(stream_id, sock, lifecycle))
    }
}

/// Helper error type for FD count mismatches.
#[derive(Debug)]
struct FdCountError {
    expected: usize,
    got: usize,
}

impl std::fmt::Display for FdCountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "expected {} fds, got {}", self.expected, self.got)
    }
}

impl std::error::Error for FdCountError {}

impl IpcWebTransportSessionClient {
    /// Convert into an [`IpcWebTransportSessionHandle`].
    pub fn into_handle(
        self,
        session_id: VarInt,
        fd_registry: FdRegistry,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> IpcWebTransportSessionHandle {
        IpcWebTransportSessionHandle::new(session_id, self, fd_registry, conn_lifecycle)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        os::unix::net::UnixStream as StdUnixStream,
        sync::{Arc, Mutex},
    };

    use bytes::Bytes;
    use futures::{SinkExt, StreamExt, future, future::pending};
    use remoc::prelude::ServerShared;
    use smallvec::SmallVec;
    use tokio::time::{Duration, timeout};
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::{
        super::transport::{MuxChannel, MuxSink, MuxStream},
        *,
    };
    use crate::{
        codec::{BoxReadStream, BoxWriteStream, PeekableStreamReader, SinkWriter, StreamReader},
        connection::{ConnectionState, tests::MockConnection},
        error::Code,
        extended_connect::{EstablishedConnect, PendingWriteStreamError},
        message::{
            stream::WriteStream,
            test::{read_stream_for_test, write_stream_for_test},
        },
        protocol::{Protocol as ProtocolLayer, Protocols, StreamVerdict},
        qpack::field::Protocol,
        quic::GetStreamIdExt,
        webtransport::{WEBTRANSPORT_H3, WebTransportProtocol},
    };

    #[derive(Debug, Default)]
    struct TestLifecycle {
        closes: Mutex<Vec<(Code, Cow<'static, str>)>>,
        terminal: Mutex<Option<ConnectionError>>,
    }

    impl TestLifecycle {
        fn set_terminal(&self, error: ConnectionError) {
            *self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned") = Some(error);
        }

        fn closes(&self) -> Vec<(Code, Cow<'static, str>)> {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .clone()
        }
    }

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, code: Code, reason: Cow<'static, str>) {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .push((code, reason));
        }

        fn check(&self) -> Result<(), ConnectionError> {
            self.terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone()
                .map_or(Ok(()), Err)
        }

        async fn closed(&self) -> ConnectionError {
            let terminal = self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone();
            match terminal {
                Some(error) => error,
                None => pending().await,
            }
        }
    }

    #[derive(Debug)]
    struct TestIpcSession;

    impl IpcWebTransportSession for TestIpcSession {
        async fn open_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(1)))
        }

        async fn open_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(2)))
        }

        async fn accept_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(3)))
        }

        async fn accept_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(4)))
        }
    }

    #[derive(Debug)]
    struct ClosedAcceptIpcSession;

    impl IpcWebTransportSession for ClosedAcceptIpcSession {
        async fn open_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(1)))
        }

        async fn open_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(2)))
        }

        async fn accept_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
            Err(SessionClosed.into())
        }

        async fn accept_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
            Err(SessionClosed.into())
        }
    }

    #[derive(Debug)]
    struct ClosedOpenIpcSession;

    impl IpcWebTransportSession for ClosedOpenIpcSession {
        async fn open_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
            Err(OpenStreamError::Closed {
                source: SessionClosed,
            }
            .into())
        }

        async fn open_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportOpenError> {
            Err(OpenStreamError::Closed {
                source: SessionClosed,
            }
            .into())
        }

        async fn accept_bi(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(3)))
        }

        async fn accept_uni(&self) -> Result<(VarInt, VarInt), IpcWebTransportAcceptError> {
            Ok((VarInt::from_u32(0), VarInt::from_u32(4)))
        }
    }

    fn connection_error(reason: &'static str) -> ConnectionError {
        ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn assert_reason(error: &ConnectionError, expected: &str) {
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    fn assert_reason_contains(error: &ConnectionError, expected: &str) {
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert!(
            source.reason.contains(expected),
            "reason {:?} should contain {expected:?}",
            source.reason
        );
    }

    fn assert_ipc_transport_metadata(error: &ConnectionError, expected: &str) {
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.kind, IPC_ERROR_KIND);
        assert_eq!(source.frame_type, IPC_FRAME_TYPE);
        assert!(
            source.reason.contains(expected),
            "reason {:?} should contain {expected:?}",
            source.reason
        );
    }

    fn spawn_ipc_session_with<T>(
        session: Arc<T>,
    ) -> (AbortOnDropHandle<()>, IpcWebTransportSessionClient)
    where
        T: IpcWebTransportSession + 'static,
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

    fn spawn_ipc_session() -> (AbortOnDropHandle<()>, IpcWebTransportSessionClient) {
        spawn_ipc_session_with(Arc::new(TestIpcSession))
    }

    fn handle_with_registry(
        fd_registry: FdRegistry,
    ) -> (
        AbortOnDropHandle<()>,
        IpcWebTransportSessionHandle,
        Arc<TestLifecycle>,
    ) {
        let (task, client) = spawn_ipc_session();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent.clone();
        let handle =
            IpcWebTransportSessionHandle::new(VarInt::from_u32(42), client, fd_registry, lifecycle);
        (task, handle, parent)
    }

    struct RegisteredFds {
        id: VarInt,
        registry: FdRegistry,
        _sink: MuxSink,
        _stream: MuxStream,
    }

    async fn registered_fds_with_nonblocking(count: usize, nonblocking: bool) -> RegisteredFds {
        let (channel_a, channel_b) = MuxChannel::pair_for_test().expect("mux channel pair");
        let (mut sink_a, _stream_a) = channel_a.split().expect("split channel a");
        let (_sink_b, mut stream_b) = channel_b.split().expect("split channel b");
        let registry = stream_b.fd_registry();

        let mut fds = SmallVec::new();
        for _ in 0..count {
            let (fd, _peer) = StdUnixStream::pair().expect("fd pair");
            fd.set_nonblocking(nonblocking)
                .expect("set client fd nonblocking mode");
            fds.push(fd.into());
        }

        let id = sink_a.fd_sender().queue_fds(fds).expect("queue fds");
        sink_a
            .send(Bytes::new())
            .await
            .expect("drive queued fd frame");
        let _ = stream_b
            .next()
            .await
            .expect("stream should yield")
            .expect("empty bytes frame should decode");

        RegisteredFds {
            id,
            registry,
            _sink: sink_a,
            _stream: stream_b,
        }
    }

    async fn registered_fds(count: usize) -> RegisteredFds {
        registered_fds_with_nonblocking(count, true).await
    }

    fn fd_transport() -> (MuxSink, MuxStream, FdRegistry) {
        let (channel_a, channel_b) = MuxChannel::pair_for_test().expect("mux channel pair");
        let (sink_a, _stream_a) = channel_a.split().expect("split channel a");
        let (_sink_b, stream_b) = channel_b.split().expect("split channel b");
        let registry = stream_b.fd_registry();
        (sink_a, stream_b, registry)
    }

    async fn receive_queued_fds(
        sink: &mut MuxSink,
        stream: &mut MuxStream,
        registry: &FdRegistry,
        fd_id: VarInt,
    ) -> Vec<std::os::fd::OwnedFd> {
        sink.send(Bytes::new())
            .await
            .expect("drive queued fd frame");
        let _ = stream
            .next()
            .await
            .expect("stream should yield")
            .expect("empty bytes frame should decode");
        timeout(Duration::from_secs(1), registry.wait_fds(fd_id))
            .await
            .expect("queued fds should arrive")
            .expect("queued fds should decode")
            .into_vec()
    }

    fn connection_with_enabled_webtransport_pair() -> (
        Arc<MockConnection>,
        Arc<ConnectionState<dyn quic::DynConnection>>,
    ) {
        let quic = Arc::new(MockConnection::new());
        quic.enable_stream_ops();
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        let connection =
            Arc::new(ConnectionState::new_for_test(quic.clone(), Arc::new(protocols)).erase());
        (quic, connection)
    }

    fn connection_with_disabled_webtransport_pair() -> (
        Arc<MockConnection>,
        Arc<ConnectionState<dyn quic::DynConnection>>,
    ) {
        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        let connection =
            Arc::new(ConnectionState::new_for_test(quic.clone(), Arc::new(protocols)).erase());
        (quic, connection)
    }

    fn webtransport_connect_on(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        session_id: StreamId,
    ) -> EstablishedConnect {
        EstablishedConnect::pending(
            session_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection,
            read_stream_for_test(session_id.0),
            future::pending::<Result<WriteStream, PendingWriteStreamError>>(),
        )
    }

    fn closing_webtransport_connect_on(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        session_id: StreamId,
    ) -> EstablishedConnect {
        EstablishedConnect::ready(
            session_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection,
            read_stream_for_test(session_id.0),
            write_stream_for_test(session_id.0),
        )
    }

    fn webtransport_session_on(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        session_id: StreamId,
    ) -> Arc<webtransport::WebTransportSession> {
        Arc::new(
            webtransport::WebTransportSession::try_from(webtransport_connect_on(
                connection, session_id,
            ))
            .expect("connect should create webtransport session"),
        )
    }

    async fn closed_webtransport_session_on(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        session_id: StreamId,
    ) -> Arc<webtransport::WebTransportSession> {
        let session = Arc::new(
            webtransport::WebTransportSession::try_from(closing_webtransport_connect_on(
                connection, session_id,
            ))
            .expect("connect should create webtransport session"),
        );
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        session
    }

    async fn peekable_uni_stream_from_bytes(bytes: &[u8]) -> crate::codec::ErasedPeekableUniStream {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(4));
        writer
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test uni bytes");
        writer.close().await.expect("close test uni stream");
        PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxReadStream))
    }

    async fn peekable_bi_stream_from_bytes(bytes: &[u8]) -> crate::codec::ErasedPeekableBiStream {
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

    #[test]
    fn ipc_error_helpers_preserve_context() {
        let open = ipc_open_io("boom", "open context");
        let IpcWebTransportOpenError::Transport { source } = open else {
            panic!("expected open transport error");
        };
        assert_eq!(source.to_string(), "open context: boom");
        assert_reason_contains(&ipc_connection_error(&source), "open context: boom");

        let accept = ipc_accept_io("closed", "accept context");
        let IpcWebTransportAcceptError::Transport { source } = accept else {
            panic!("expected accept transport error");
        };
        assert_eq!(source.to_string(), "accept context: closed");
        assert_reason_contains(&ipc_connection_error(&source), "accept context: closed");

        let closed = IpcWebTransportAcceptError::from(SessionClosed);
        assert!(matches!(closed, IpcWebTransportAcceptError::Closed));

        let fd_count = FdCountError {
            expected: 2,
            got: 1,
        };
        assert_eq!(fd_count.to_string(), "expected 2 fds, got 1");
    }

    #[tokio::test]
    async fn session_adapter_open_methods_queue_expected_fds_and_stream_ids() {
        let (_quic, connection) = connection_with_enabled_webtransport_pair();
        let session = webtransport_session_on(connection, StreamId::from(VarInt::from_u32(42)));
        let (mut sink, mut stream, registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let (fd_id, stream_id) = IpcWebTransportSession::open_bi(&adapter)
            .await
            .expect("adapter open_bi should queue bidi fds");
        assert_eq!(stream_id, VarInt::from_u32(0));
        let fds = receive_queued_fds(&mut sink, &mut stream, &registry, fd_id).await;
        assert_eq!(fds.len(), 2);

        let (fd_id, stream_id) = IpcWebTransportSession::open_uni(&adapter)
            .await
            .expect("adapter open_uni should queue uni fd");
        assert_eq!(stream_id, VarInt::from_u32(0));
        let fds = receive_queued_fds(&mut sink, &mut stream, &registry, fd_id).await;
        assert_eq!(fds.len(), 1);
    }

    #[tokio::test]
    async fn session_adapter_open_methods_map_connection_open_errors() {
        let (quic, connection) = connection_with_disabled_webtransport_pair();
        let session = webtransport_session_on(connection, StreamId::from(VarInt::from_u32(42)));
        let (sink, _stream, _registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let error = IpcWebTransportSession::open_bi(&adapter)
            .await
            .expect_err("adapter open_bi should preserve connection open errors");
        let IpcWebTransportOpenError::Stream {
            source: OpenStreamError::Open { source },
        } = error
        else {
            panic!("expected open_bi stream open error");
        };
        assert_reason(&source, "open_bi unavailable");

        let error = IpcWebTransportSession::open_uni(&adapter)
            .await
            .expect_err("adapter open_uni should preserve connection open errors");
        let IpcWebTransportOpenError::Stream {
            source: OpenStreamError::Open { source },
        } = error
        else {
            panic!("expected open_uni stream open error");
        };
        assert_reason(&source, "open_uni unavailable");
        assert_eq!(quic.stream_calls(), vec!["open_bi", "open_uni"]);
    }

    #[tokio::test]
    async fn session_adapter_accept_methods_route_streams_and_queue_expected_fds() {
        let (_quic, connection) = connection_with_enabled_webtransport_pair();
        let session_id = StreamId::from(VarInt::from_u32(42));
        let session = webtransport_session_on(connection.clone(), session_id);
        let protocol = connection
            .protocol::<WebTransportProtocol>()
            .expect("connection should include webtransport protocol");
        let (mut sink, mut stream, registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let routed_bi = peekable_bi_stream_from_bytes(&[0x40, 0x41, 0x2a, 0xde]).await;
        let verdict = ProtocolLayer::accept_bi(protocol, routed_bi)
            .await
            .expect("bidi routing should not fail");
        assert!(matches!(verdict, StreamVerdict::Accepted));
        let (fd_id, stream_id) = IpcWebTransportSession::accept_bi(&adapter)
            .await
            .expect("adapter accept_bi should queue bidi fds");
        assert_eq!(stream_id, VarInt::from_u32(4));
        let fds = receive_queued_fds(&mut sink, &mut stream, &registry, fd_id).await;
        assert_eq!(fds.len(), 2);

        let routed_uni = peekable_uni_stream_from_bytes(&[0x40, 0x54, 0x2a, 0xbe]).await;
        let verdict = ProtocolLayer::accept_uni(protocol, routed_uni)
            .await
            .expect("uni routing should not fail");
        assert!(matches!(verdict, StreamVerdict::Accepted));
        let (fd_id, stream_id) = IpcWebTransportSession::accept_uni(&adapter)
            .await
            .expect("adapter accept_uni should queue uni fd");
        assert_eq!(stream_id, VarInt::from_u32(4));
        let fds = receive_queued_fds(&mut sink, &mut stream, &registry, fd_id).await;
        assert_eq!(fds.len(), 1);
    }

    #[tokio::test]
    async fn session_adapter_accept_methods_map_connection_closure_to_closed() {
        let (quic, connection) = connection_with_enabled_webtransport_pair();
        let session = webtransport_session_on(connection, StreamId::from(VarInt::from_u32(42)));
        quic.set_terminal_error(connection_error("adapter accept connection closed"));
        let (sink, _stream, _registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let error = IpcWebTransportSession::accept_bi(&adapter)
            .await
            .expect_err("connection closure should close bidi accept");
        assert!(matches!(error, IpcWebTransportAcceptError::Closed));

        let error = IpcWebTransportSession::accept_uni(&adapter)
            .await
            .expect_err("connection closure should close uni accept");
        assert!(matches!(error, IpcWebTransportAcceptError::Closed));
    }

    #[tokio::test]
    async fn session_adapter_accept_uni_maps_connection_closure_to_closed() {
        let (quic, connection) = connection_with_enabled_webtransport_pair();
        let session = webtransport_session_on(connection, StreamId::from(VarInt::from_u32(42)));
        quic.set_terminal_error(connection_error("adapter accept uni connection closed"));
        let (sink, _stream, _registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let error = IpcWebTransportSession::accept_uni(&adapter)
            .await
            .expect_err("connection closure should close uni accept");
        assert!(matches!(error, IpcWebTransportAcceptError::Closed));
    }

    #[tokio::test]
    async fn session_adapter_accept_methods_map_session_closed_to_closed() {
        let (_quic, connection) = connection_with_enabled_webtransport_pair();
        let session = closed_webtransport_session_on(
            connection.clone(),
            StreamId::from(VarInt::from_u32(42)),
        )
        .await;
        let (sink, _stream, _registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let error = timeout(
            Duration::from_secs(1),
            IpcWebTransportSession::accept_bi(&adapter),
        )
        .await
        .expect("closed bidi accept should not remain pending")
        .expect_err("closed session should close bidi accept");
        assert!(matches!(error, IpcWebTransportAcceptError::Closed));

        let (_quic, connection) = connection_with_enabled_webtransport_pair();
        let session =
            closed_webtransport_session_on(connection, StreamId::from(VarInt::from_u32(43))).await;
        let (sink, _stream, _registry) = fd_transport();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let adapter = WebTransportSessionAdapter::new(session, sink.fd_sender(), lifecycle);

        let error = timeout(
            Duration::from_secs(1),
            IpcWebTransportSession::accept_uni(&adapter),
        )
        .await
        .expect("closed uni accept should not remain pending")
        .expect_err("closed session should close uni accept");
        assert!(matches!(error, IpcWebTransportAcceptError::Closed));
    }

    #[test]
    fn transparent_error_wrappers_preserve_display_and_transport_metadata() {
        let stream = IpcPlumbingError::from(quic::StreamError::Reset {
            code: VarInt::from_u32(0x45),
        });
        let IpcPlumbingError::Stream { source } = &stream else {
            panic!("expected stream plumbing error");
        };
        assert_eq!(stream.to_string(), source.to_string());
        assert_ipc_transport_metadata(&ipc_connection_error(&stream), "stream reset with code");

        let open = IpcWebTransportOpenError::from(OpenStreamError::Closed {
            source: SessionClosed,
        });
        assert!(matches!(open, IpcWebTransportOpenError::Stream { .. }));
        assert_eq!(open.to_string(), "webtransport session closed");

        let open = IpcWebTransportOpenError::from(IpcPlumbingError::Io {
            message: "queued fd failed".into(),
        });
        assert!(matches!(open, IpcWebTransportOpenError::Transport { .. }));
        assert_eq!(open.to_string(), "queued fd failed");

        let accept = IpcWebTransportAcceptError::from(IpcPlumbingError::Io {
            message: "waited fd failed".into(),
        });
        assert!(matches!(
            accept,
            IpcWebTransportAcceptError::Transport { .. }
        ));
        assert_eq!(accept.to_string(), "waited fd failed");

        assert_eq!(
            IpcWebTransportAcceptError::Closed.to_string(),
            "webtransport session closed"
        );
    }

    #[test]
    fn call_errors_convert_to_transport_errors() {
        let open = IpcWebTransportOpenError::from(remoc::rtc::CallError::Dropped);
        let IpcWebTransportOpenError::Transport {
            source: IpcPlumbingError::Rpc { source },
        } = open
        else {
            panic!("expected open RPC transport error");
        };
        assert_eq!(source.to_string(), "processing request failed");

        let accept = IpcWebTransportAcceptError::from(remoc::rtc::CallError::RemoteForward);
        let IpcWebTransportAcceptError::Transport {
            source: IpcPlumbingError::Rpc { source },
        } = accept
        else {
            panic!("expected accept RPC transport error");
        };
        assert_eq!(source.to_string(), "forwarding error");
    }

    #[tokio::test]
    async fn ipc_webtransport_lifecycle_delegates_and_latches_parent_errors() {
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle = IpcWebTransportLifecycle {
            parent: parent.clone(),
            latch: ConnectionErrorLatch::new(),
        };

        quic::Lifecycle::close(&lifecycle, Code::H3_NO_ERROR, "done".into());
        assert_eq!(parent.closes(), vec![(Code::H3_NO_ERROR, "done".into())]);

        parent.set_terminal(connection_error("parent closed"));
        let error = quic::Lifecycle::check(&lifecycle).expect_err("parent error should latch");
        assert_reason(&error, "parent closed");

        parent.set_terminal(connection_error("later parent error"));
        let error = quic::Lifecycle::closed(&lifecycle).await;
        assert_reason(&error, "parent closed");
    }

    #[tokio::test]
    async fn ipc_webtransport_lifecycle_closed_latches_parent_without_prior_check() {
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle = IpcWebTransportLifecycle {
            parent: parent.clone(),
            latch: ConnectionErrorLatch::new(),
        };

        parent.set_terminal(connection_error("direct parent close"));
        let error = quic::Lifecycle::closed(&lifecycle).await;
        assert_reason(&error, "direct parent close");

        parent.set_terminal(connection_error("ignored later close"));
        let latched = quic::Lifecycle::check(&lifecycle).expect_err("closed should latch");
        assert_reason(&latched, "direct parent close");
    }

    #[tokio::test]
    async fn test_lifecycle_closed_remains_pending_without_terminal_error() {
        let lifecycle = TestLifecycle::default();

        let result = timeout(
            Duration::from_millis(10),
            quic::Lifecycle::closed(&lifecycle),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn closed_session_test_helpers_keep_unrelated_methods_available() {
        let closed_accept = ClosedAcceptIpcSession;
        assert_eq!(
            IpcWebTransportSession::open_bi(&closed_accept)
                .await
                .expect("closed accept helper should still open bidi"),
            (VarInt::from_u32(0), VarInt::from_u32(1))
        );
        assert_eq!(
            IpcWebTransportSession::open_uni(&closed_accept)
                .await
                .expect("closed accept helper should still open uni"),
            (VarInt::from_u32(0), VarInt::from_u32(2))
        );

        let closed_open = ClosedOpenIpcSession;
        assert_eq!(
            IpcWebTransportSession::accept_bi(&closed_open)
                .await
                .expect("closed open helper should still accept bidi"),
            (VarInt::from_u32(0), VarInt::from_u32(3))
        );
        assert_eq!(
            IpcWebTransportSession::accept_uni(&closed_open)
                .await
                .expect("closed open helper should still accept uni"),
            (VarInt::from_u32(0), VarInt::from_u32(4))
        );
    }

    #[tokio::test]
    async fn guard_ipc_operations_map_and_latch_errors() {
        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let closed = handle
            .guard_ipc_open(async {
                Err::<(), _>(IpcWebTransportOpenError::Stream {
                    source: OpenStreamError::Closed {
                        source: SessionClosed,
                    },
                })
            })
            .await
            .expect_err("closed open error should surface");
        assert!(matches!(closed, OpenStreamError::Closed { .. }));

        let open = handle
            .guard_ipc_open(async {
                Err::<(), _>(IpcWebTransportOpenError::Transport {
                    source: IpcPlumbingError::Io {
                        message: "open transport".into(),
                    },
                })
            })
            .await
            .expect_err("transport open error should surface");
        let OpenStreamError::Open { source } = open else {
            panic!("expected open connection error");
        };
        assert_reason(&source, "open transport");

        let latched = quic::Lifecycle::check(handle.lifecycle.as_ref())
            .expect_err("transport error should latch");
        assert_reason(&latched, "open transport");

        let closed = timeout(
            Duration::from_secs(1),
            quic::Lifecycle::closed(handle.lifecycle.as_ref()),
        )
        .await
        .expect("latched open transport error should resolve closed immediately");
        assert_reason(&closed, "open transport");

        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let closed = handle
            .guard_ipc_accept(async {
                Err::<(), _>(IpcWebTransportAcceptError::from(SessionClosed))
            })
            .await
            .expect_err("closed accept error should surface");
        assert!(matches!(closed, AcceptStreamError::Closed { .. }));
    }

    #[tokio::test]
    async fn guard_ipc_accept_transport_error_latches_connection_error() {
        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let error = handle
            .guard_ipc_accept(async {
                Err::<(), _>(IpcWebTransportAcceptError::Transport {
                    source: IpcPlumbingError::Io {
                        message: "accept transport".into(),
                    },
                })
            })
            .await
            .expect_err("transport accept error should surface");

        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason(&source, "accept transport");

        let latched = quic::Lifecycle::check(handle.lifecycle.as_ref())
            .expect_err("accept transport error should latch");
        assert_reason(&latched, "accept transport");

        let closed = timeout(
            Duration::from_secs(1),
            quic::Lifecycle::closed(handle.lifecycle.as_ref()),
        )
        .await
        .expect("latched accept transport error should resolve closed immediately");
        assert_reason(&closed, "accept transport");
    }

    #[tokio::test]
    async fn guard_ipc_operations_return_success_without_latching_errors() {
        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let open = handle
            .guard_ipc_open(async {
                Ok::<_, IpcWebTransportOpenError>((VarInt::from_u32(11), VarInt::from_u32(12)))
            })
            .await
            .expect("successful open guard should pass through value");
        assert_eq!(open, (VarInt::from_u32(11), VarInt::from_u32(12)));
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());

        let accept = handle
            .guard_ipc_accept(async {
                Ok::<_, IpcWebTransportAcceptError>((VarInt::from_u32(13), VarInt::from_u32(14)))
            })
            .await
            .expect("successful accept guard should pass through value");
        assert_eq!(accept, (VarInt::from_u32(13), VarInt::from_u32(14)));
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());
    }

    #[tokio::test]
    async fn fd_to_unix_stream_helpers_normalize_blocking_fds_without_latching_errors() {
        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let (open_fd, _open_peer) = StdUnixStream::pair().expect("open fd pair");
        open_fd
            .set_nonblocking(false)
            .expect("open fd should allow blocking mode");
        let _open_stream = handle
            .fd_to_open_unix_stream(open_fd.into())
            .expect("open fd conversion should normalize blocking sockets");
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());

        let (accept_fd, _accept_peer) = StdUnixStream::pair().expect("accept fd pair");
        accept_fd
            .set_nonblocking(false)
            .expect("accept fd should allow blocking mode");
        let _accept_stream = handle
            .fd_to_accept_unix_stream(accept_fd.into())
            .expect("accept fd conversion should normalize blocking sockets");
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());
    }

    #[tokio::test]
    async fn lifecycle_guard_helpers_prefer_errors_latched_while_future_is_pending() {
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle = IpcWebTransportLifecycle {
            parent,
            latch: ConnectionErrorLatch::new(),
        };

        let error = lifecycle
            .guard_open_with(
                async {
                    lifecycle
                        .latch()
                        .latch_with(|| connection_error("raced open"));
                    Err::<(), _>("ignored open error")
                },
                |_| OpenStreamError::Open {
                    source: connection_error("converted open"),
                },
            )
            .await
            .expect_err("latched open error should win");
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason(&source, "raced open");

        let parent = Arc::new(TestLifecycle::default());
        let lifecycle = IpcWebTransportLifecycle {
            parent,
            latch: ConnectionErrorLatch::new(),
        };

        let error = lifecycle
            .guard_accept_err(
                async {
                    lifecycle
                        .latch()
                        .latch_with(|| connection_error("raced accept"));
                    Err::<(), _>("ignored accept error")
                },
                |_| Some(connection_error("converted accept")),
            )
            .await
            .expect_err("latched accept error should win");
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason(&source, "raced accept");
    }

    #[tokio::test]
    async fn fds_to_streams_build_ipc_streams_with_expected_ids() {
        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let stream_id = VarInt::from_u32(7);

        let (mut reader, mut writer) = handle
            .fds_to_bi(registered.id, stream_id)
            .await
            .expect("bidi streams");

        assert_eq!(reader.stream_id().await.expect("reader id"), stream_id);
        assert_eq!(writer.stream_id().await.expect("writer id"), stream_id);

        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let mut writer = handle
            .fds_to_uni_writer(registered.id, stream_id)
            .await
            .expect("uni writer");
        assert_eq!(writer.stream_id().await.expect("writer id"), stream_id);

        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let mut reader = handle
            .fds_to_uni_reader(registered.id, stream_id)
            .await
            .expect("uni reader");
        assert_eq!(reader.stream_id().await.expect("reader id"), stream_id);

        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let (mut reader, mut writer) = handle
            .fds_to_bi_accept(registered.id, stream_id)
            .await
            .expect("accepted bidi streams");
        assert_eq!(reader.stream_id().await.expect("reader id"), stream_id);
        assert_eq!(writer.stream_id().await.expect("writer id"), stream_id);
    }

    #[tokio::test]
    async fn session_trait_methods_open_and_accept_registered_fds() {
        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let (mut reader, mut writer) = webtransport::Session::open_bi(&handle)
            .await
            .expect("open bidi streams");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(1)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(1)
        );

        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let mut writer = webtransport::Session::open_uni(&handle)
            .await
            .expect("open uni writer");
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(2)
        );

        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let (mut reader, mut writer) = webtransport::Session::accept_bi(&handle)
            .await
            .expect("accept bidi streams");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(3)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(3)
        );

        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let mut reader = webtransport::Session::accept_uni(&handle)
            .await
            .expect("accept uni reader");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(4)
        );
    }

    #[tokio::test]
    async fn session_trait_methods_map_rpc_drop_to_ipc_transport_errors() {
        let registered = registered_fds(2).await;
        let (task, handle, _parent) = handle_with_registry(registered.registry.clone());
        drop(task);

        let Err(error) = webtransport::Session::open_bi(&handle).await else {
            panic!("dropped RPC server should fail open_bi");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_ipc_transport_metadata(&source, "processing request failed");

        let Err(error) = webtransport::Session::open_uni(&handle).await else {
            panic!("latched RPC failure should fail open_uni");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_ipc_transport_metadata(&source, "processing request failed");

        let registered = registered_fds(2).await;
        let (task, handle, _parent) = handle_with_registry(registered.registry.clone());
        drop(task);

        let Err(error) = webtransport::Session::accept_bi(&handle).await else {
            panic!("dropped RPC server should fail accept_bi");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_ipc_transport_metadata(&source, "processing request failed");

        let Err(error) = webtransport::Session::accept_uni(&handle).await else {
            panic!("latched RPC failure should fail accept_uni");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_ipc_transport_metadata(&source, "processing request failed");
    }

    #[tokio::test]
    async fn session_trait_methods_map_closed_opens_without_latching_transport_errors() {
        let registered = registered_fds(1).await;
        let (task, client) = spawn_ipc_session_with(Arc::new(ClosedOpenIpcSession));
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent.clone();
        let handle = IpcWebTransportSessionHandle::new(
            VarInt::from_u32(42),
            client,
            registered.registry,
            lifecycle,
        );

        let Err(error) = webtransport::Session::open_bi(&handle).await else {
            panic!("open_bi should surface session closed");
        };
        assert!(matches!(error, OpenStreamError::Closed { .. }));
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());

        let Err(error) = webtransport::Session::open_uni(&handle).await else {
            panic!("open_uni should surface session closed");
        };
        assert!(matches!(error, OpenStreamError::Closed { .. }));
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());

        drop(task);
    }

    #[tokio::test]
    async fn session_trait_methods_map_closed_accepts_without_latching_transport_errors() {
        let registered = registered_fds(1).await;
        let (task, client) = spawn_ipc_session_with(Arc::new(ClosedAcceptIpcSession));
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent.clone();
        let handle = IpcWebTransportSessionHandle::new(
            VarInt::from_u32(42),
            client,
            registered.registry,
            lifecycle,
        );

        let Err(error) = webtransport::Session::accept_bi(&handle).await else {
            panic!("accept_bi should surface session closed");
        };
        assert!(matches!(error, AcceptStreamError::Closed { .. }));
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());

        let Err(error) = webtransport::Session::accept_uni(&handle).await else {
            panic!("accept_uni should surface session closed");
        };
        assert!(matches!(error, AcceptStreamError::Closed { .. }));
        assert!(quic::Lifecycle::check(handle.lifecycle.as_ref()).is_ok());

        drop(task);
    }

    #[tokio::test]
    async fn fd_count_mismatch_is_latched_as_transport_error() {
        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let Err(error) = handle.fds_to_bi(registered.id, VarInt::from_u32(9)).await else {
            panic!("bidi requires two fds");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason_contains(&source, "expected 2 fds, got 1");

        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let Err(error) = handle
            .fds_to_uni_reader(registered.id, VarInt::from_u32(9))
            .await
        else {
            panic!("uni reader requires one fd");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason_contains(&source, "expected 1 fds, got 2");

        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let Err(error) = handle
            .fds_to_bi_accept(registered.id, VarInt::from_u32(9))
            .await
        else {
            panic!("accepted bidi requires two fds");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason_contains(&source, "expected 2 fds, got 1");

        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let Err(error) = handle
            .fds_to_uni_writer(registered.id, VarInt::from_u32(9))
            .await
        else {
            panic!("uni writer requires one fd");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason_contains(&source, "expected 1 fds, got 2");
    }

    #[tokio::test]
    async fn closed_fd_registry_errors_are_latched_as_transport_errors() {
        let registered = registered_fds(1).await;
        let registry = registered.registry.clone();
        drop(registered);
        let (_task, handle, _parent) = handle_with_registry(registry);

        let Err(error) = handle
            .fds_to_uni_writer(VarInt::from_u32(99), VarInt::from_u32(9))
            .await
        else {
            panic!("closed registry should fail open conversion");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason_contains(&source, "wait_fds: fd registry is closed");

        let registered = registered_fds(1).await;
        let registry = registered.registry.clone();
        drop(registered);
        let (_task, handle, _parent) = handle_with_registry(registry);

        let Err(error) = handle
            .fds_to_uni_reader(VarInt::from_u32(99), VarInt::from_u32(9))
            .await
        else {
            panic!("closed registry should fail accept conversion");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason_contains(&source, "wait_fds: fd registry is closed");
    }

    #[tokio::test]
    async fn blocking_socket_fds_are_normalized_during_unix_stream_conversion_for_all_stream_kinds()
    {
        let registered = registered_fds_with_nonblocking(2, false).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let (mut reader, mut writer) = webtransport::Session::open_bi(&handle)
            .await
            .expect("blocking bidi fds should be normalized for open_bi");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(1)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(1)
        );

        let registered = registered_fds_with_nonblocking(1, false).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let mut writer = webtransport::Session::open_uni(&handle)
            .await
            .expect("blocking uni fd should be normalized for open_uni");
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(2)
        );

        let registered = registered_fds_with_nonblocking(2, false).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let (mut reader, mut writer) = webtransport::Session::accept_bi(&handle)
            .await
            .expect("blocking bidi fds should be normalized for accept_bi");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(3)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(3)
        );

        let registered = registered_fds_with_nonblocking(1, false).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());
        let mut reader = webtransport::Session::accept_uni(&handle)
            .await
            .expect("blocking uni fd should be normalized for accept_uni");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(4)
        );
    }

    #[tokio::test]
    async fn latched_transport_errors_short_circuit_later_session_methods() {
        let registered = registered_fds(1).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let Err(error) = webtransport::Session::open_bi(&handle).await else {
            panic!("fd count mismatch should fail open_bi");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason_contains(&source, "expected 2 fds, got 1");

        let Err(error) = webtransport::Session::open_uni(&handle).await else {
            panic!("latched open error should short-circuit open_uni");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason_contains(&source, "expected 2 fds, got 1");

        let registered = registered_fds(2).await;
        let (_task, handle, _parent) = handle_with_registry(registered.registry.clone());

        let Err(error) = webtransport::Session::accept_uni(&handle).await else {
            panic!("fd count mismatch should fail accept_uni");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason_contains(&source, "expected 1 fds, got 2");

        let Err(error) = webtransport::Session::accept_bi(&handle).await else {
            panic!("latched accept error should short-circuit accept_bi");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason_contains(&source, "expected 1 fds, got 2");
    }

    #[tokio::test]
    async fn parent_lifecycle_errors_block_session_methods_before_rpc_and_fd_work() {
        let registered = registered_fds(2).await;
        let (_task, handle, parent) = handle_with_registry(registered.registry.clone());
        parent.set_terminal(connection_error("parent lifecycle closed"));

        let Err(error) = webtransport::Session::open_bi(&handle).await else {
            panic!("parent lifecycle should block open_bi");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open connection error");
        };
        assert_reason(&source, "parent lifecycle closed");

        let Err(error) = webtransport::Session::accept_bi(&handle).await else {
            panic!("parent lifecycle should block accept_bi");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason(&source, "parent lifecycle closed");
    }

    #[tokio::test]
    async fn session_handle_exposes_id_and_converts_client() {
        let registered = registered_fds(1).await;
        let (_task, client) = spawn_ipc_session();
        let parent = Arc::new(TestLifecycle::default());
        let lifecycle: Arc<dyn DynLifecycle> = parent;
        let handle =
            client.into_handle(VarInt::from_u32(77), registered.registry.clone(), lifecycle);

        assert_eq!(
            webtransport::Session::id(&handle),
            StreamId::from(VarInt::from_u32(77))
        );
    }
}
