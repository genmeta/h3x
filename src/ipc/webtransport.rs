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
    rpc::lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
    stream_id::StreamId,
    varint::VarInt,
    webtransport::{
        self, AcceptStreamError, OpenStreamError, SessionClosed, WebTransportLifecycleExt,
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
/// Extends [`SessionClosed`] with an IPC transport variant.
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
    fn from(_: SessionClosed) -> Self {
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
            // IPC compatibility surface exposes only session closure here; the connection
            // error has already been latched by h3x's connection lifecycle.
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
            // IPC compatibility surface exposes only session closure here; the connection
            // error has already been latched by h3x's connection lifecycle.
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

        let sock_a = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_a))
            .map_err(|e| self.latch_open_transport(e, "UnixStream::from_std"))?;
        let reader = IpcReadStream::new(stream_id, sock_a, lifecycle.clone());

        let sock_b = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_b))
            .map_err(|e| self.latch_open_transport(e, "UnixStream::from_std"))?;
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

        let sock_a = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_a))
            .map_err(|e| self.latch_accept_transport(e, "UnixStream::from_std"))?;
        let reader = IpcReadStream::new(stream_id, sock_a, lifecycle.clone());

        let sock_b = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_b))
            .map_err(|e| self.latch_accept_transport(e, "UnixStream::from_std"))?;
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
        let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
            .map_err(|e| self.latch_open_transport(e, "UnixStream::from_std"))?;
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
        let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
            .map_err(|e| self.latch_accept_transport(e, "UnixStream::from_std"))?;
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
