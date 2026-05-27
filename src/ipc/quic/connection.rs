//! Connection-level IPC adapters and RTC trait.
//!
//! # RTC trait
//!
//! [`IpcConnection`] defines the RPC interface for connection-level stream
//! management over IPC.  Each stream-opening method returns a `(VarInt, VarInt)`
//! pair: `(fd_registry_id, stream_id)`.  The client retrieves the corresponding
//! socketpair FD(s) via [`FdRegistry::wait_fds`] and wraps them as
//! [`IpcReadStream`] / [`IpcWriteStream`].
//!
//! # Server side
//!
//! [`ConnectionAdapter`] wraps a `quic::Connection` and implements
//! [`IpcConnection`].  Each `open_bi` / `accept_bi` call:
//! 1. Opens a real QUIC stream pair via the inner connection.
//! 2. Creates 2 Unix socketpairs (one per direction).
//! 3. Queues the client-side FDs through the [`FdSender`].
//! 4. Spawns bridge tasks that forward data between the real QUIC
//!    streams and local [`IpcWriteStream`] / [`IpcReadStream`] endpoints.
//! 5. Returns `(fd_registry_id, stream_id)` over RPC.
//!
//! # Client side
//!
//! [`IpcConnectionHandle`] wraps an [`IpcConnectionClient`] and implements
//! [`quic::Connection`].  Each `open_bi` call:
//! 1. Calls the RPC method to get `(fd_registry_id, stream_id)`.
//! 2. Retrieves the socketpair FDs from the [`FdRegistry`].
//! 3. Wraps them as [`IpcReadStream`] / [`IpcWriteStream`].
//!
//! # Bootstrap
//!
//! [`ConnectionBootstrap`] is the one-shot value sent over the remoc base
//! channel when a new connection is established.  It carries the
//! [`IpcConnectionClient`] for stream management and agent access.

use std::{borrow::Cow, io, sync::Arc};

use futures::{SinkExt, StreamExt};
use remoc::prelude::ServerShared;
use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use tokio::net::UnixStream;
use tracing::{Instrument, debug};

use crate::{
    error::Code,
    ipc::{
        error::{IpcAcceptError, IpcOpenError, IpcPlumbingError},
        quic::stream::{IpcBiHandle, IpcReadStream, IpcUniHandle, IpcWriteStream},
        transport::{FdRegistry, FdSender},
    },
    quic::{
        self, ConnectionError, DynLifecycle, GetStreamIdExt, ManageStream, ReadStream, StreamError,
        WriteStream,
    },
    rpc::{
        lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
        quic::{
            CachedLocalAgent, CachedRemoteAgent, LocalAgentClient, LocalAgentServerShared,
            RemoteAgentClient, RemoteAgentServerShared,
        },
    },
    util::deferred::Resolved,
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// IPC RTC trait for connection-level stream management
// ---------------------------------------------------------------------------

/// Remote trait for IPC connection-level stream management.
///
/// Each stream-opening method returns a `(VarInt, VarInt)` pair:
/// - The first element is the FD-registry ID for
///   [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds).
/// - The second element is the underlying QUIC stream ID.
///
/// Agent and lifecycle methods mirror [`crate::rpc::quic::Connection`] and
/// are forwarded over the same remoc channel — only bulk stream data travels
/// through dedicated socketpairs.
///
/// # FD semantics
///
/// - **`open_bi` / `accept_bi`**: 2 FDs are queued (2 independent socketpairs).
///   The first FD carries the reader-side pipe (server's IpcWriteStream ↔
///   client's IpcReadStream), the second carries the writer-side pipe
///   (server's IpcReadStream ↔ client's IpcWriteStream).
///
/// - **`open_uni` / `accept_uni`**: 1 FD is queued (a single socketpair).
#[remoc::rtc::remote]
pub trait IpcConnection: Send + Sync {
    /// Open a bidirectional stream.
    ///
    /// Returns `Resolved<IpcBiHandle, StreamError>` on success — the handle
    /// may carry a stream error (e.g. stream_id retrieval failed) wrapped in
    /// [`Resolved::Error`].  Infrastructure failures yield [`IpcOpenError`].
    async fn open_bi(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError>;

    /// Accept an incoming bidirectional stream.
    ///
    /// Returns `Resolved<IpcBiHandle, StreamError>` on success.
    async fn accept_bi(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError>;

    /// Open a unidirectional (send-only) stream.
    ///
    /// Returns `Resolved<IpcUniHandle, StreamError>` on success.
    async fn open_uni(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError>;

    /// Accept an incoming unidirectional (receive-only) stream.
    ///
    /// Returns `Resolved<IpcUniHandle, StreamError>` on success.
    async fn accept_uni(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError>;

    /// Obtain the local agent (signing / identity) handle, if available.
    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, ConnectionError>;

    /// Obtain the remote agent (verification) handle, if available.
    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, ConnectionError>;

    /// Close the connection with an application error code and reason.
    async fn close(&self, code: Code, reason: Cow<'static, str>) -> Result<(), ConnectionError>;

    /// Wait until the connection is closed, returning the terminal error.
    async fn closed(&self) -> Result<ConnectionError, ConnectionError>;
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// One-shot bootstrap payload sent over the remoc base channel when a new
/// IPC connection is established.
///
/// Carries the [`IpcConnectionClient`] which provides both stream management
/// RPC and agent access — agent methods are part of the [`IpcConnection`]
/// trait alongside stream operations.
#[derive(Serialize, Deserialize)]
pub struct ConnectionBootstrap {
    /// RPC client for stream operations, agent access, and lifecycle.
    pub connection: IpcConnectionClient,
}

// ---------------------------------------------------------------------------
// Bridge helpers: forward data between real QUIC streams and pipe socketpairs
// ---------------------------------------------------------------------------

/// Forward data from a QUIC [`ReadStream`] to a [`IpcWriteStream`] (server side).
///
/// Reads chunks from the QUIC stream and sinks them into the pipe.
/// Terminates when either side closes or errors.
pub async fn bridge_reader(
    mut quic_reader: impl ReadStream + Unpin,
    mut pipe_writer: IpcWriteStream,
) {
    while let Some(Ok(chunk)) = quic_reader.next().await {
        if pipe_writer.send(chunk).await.is_err() {
            break;
        }
    }
    let _ = pipe_writer.close().await;
}

/// Forward data from a [`IpcReadStream`] to a QUIC [`WriteStream`] (server side).
///
/// Reads chunks from the pipe and sinks them into the QUIC stream.
/// Terminates when either side closes or errors.
pub async fn bridge_writer(
    mut pipe_reader: IpcReadStream,
    mut quic_writer: impl WriteStream + Unpin,
) {
    while let Some(Ok(chunk)) = pipe_reader.next().await {
        if quic_writer.send(chunk).await.is_err() {
            break;
        }
    }
    let _ = quic_writer.close().await;
}

// ---------------------------------------------------------------------------
// Server side: ConnectionAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter that wraps a real `quic::Connection` and implements
/// [`IpcConnection`].
///
/// The inner connection is shared via `Arc` so that:
/// - Bridge tasks can reference it as `Arc<dyn DynLifecycle>`.
/// - The [`FdSender`] queues client-side FDs for each new stream.
pub struct ConnectionAdapter<M> {
    inner: Arc<M>,
    fd_sender: FdSender,
}

impl<M> ConnectionAdapter<M> {
    pub fn new(inner: Arc<M>, fd_sender: FdSender) -> Self {
        Self { inner, fd_sender }
    }
}

impl<M> IpcConnection for ConnectionAdapter<M>
where
    M: ManageStream
        + quic::Lifecycle
        + quic::WithLocalAgent
        + quic::WithRemoteAgent
        + Send
        + Sync
        + 'static,
    M::StreamReader: Unpin + 'static,
    M::StreamWriter: Unpin + 'static,
    M::LocalAgent: Send + Sync,
    M::RemoteAgent: Send + Sync,
{
    async fn open_bi(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError> {
        self.open_bi_impl().await
    }

    async fn accept_bi(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError> {
        self.accept_bi_impl().await
    }

    async fn open_uni(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError> {
        self.open_uni_impl().await
    }

    async fn accept_uni(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError> {
        self.accept_uni_impl().await
    }

    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, ConnectionError> {
        match quic::WithLocalAgent::local_agent(self.inner.as_ref()).await? {
            Some(agent) => {
                let (server, client) = LocalAgentServerShared::new(Arc::new(agent), 1);
                tokio::spawn(
                    (async move {
                        let _ = server.serve(true).await;
                    })
                    .in_current_span(),
                );
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, ConnectionError> {
        match quic::WithRemoteAgent::remote_agent(self.inner.as_ref()).await? {
            Some(agent) => {
                let (server, client) = RemoteAgentServerShared::new(Arc::new(agent), 1);
                tokio::spawn(
                    (async move {
                        let _ = server.serve(true).await;
                    })
                    .in_current_span(),
                );
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn close(&self, code: Code, reason: Cow<'static, str>) -> Result<(), ConnectionError> {
        quic::Lifecycle::close(self.inner.as_ref(), code, reason);
        Ok(())
    }

    async fn closed(&self) -> Result<ConnectionError, ConnectionError> {
        Ok(quic::Lifecycle::closed(self.inner.as_ref()).await)
    }
}

impl<M> ConnectionAdapter<M>
where
    M: ManageStream
        + quic::Lifecycle
        + quic::WithLocalAgent
        + quic::WithRemoteAgent
        + Send
        + Sync
        + 'static,
    M::StreamReader: Unpin + 'static,
    M::StreamWriter: Unpin + 'static,
    M::LocalAgent: Send + Sync,
    M::RemoteAgent: Send + Sync,
{
    async fn open_bi_impl(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError> {
        let (mut reader, writer) = ManageStream::open_bi(self.inner.as_ref())
            .await
            .map_err(|e| IpcOpenError::Connection { source: e })?;
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        self.bridge_bi(reader, writer, stream_id)
            .map(Resolved::ok)
            .map_err(IpcOpenError::from)
    }

    async fn accept_bi_impl(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError> {
        let (mut reader, writer) = ManageStream::accept_bi(self.inner.as_ref())
            .await
            .map_err(|e| IpcAcceptError::Connection { source: e })?;
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        self.bridge_bi(reader, writer, stream_id)
            .map(Resolved::ok)
            .map_err(IpcAcceptError::from)
    }

    /// Shared logic for open_bi / accept_bi after obtaining the real streams.
    fn bridge_bi(
        &self,
        reader: M::StreamReader,
        writer: M::StreamWriter,
        stream_id: VarInt,
    ) -> Result<IpcBiHandle, IpcPlumbingError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        // Socketpair for the reader direction: server IpcWriteStream ↔ client IpcReadStream
        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        // Socketpair for the writer direction: server IpcReadStream ↔ client IpcWriteStream
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;

        let cli_a_std = cli_a
            .into_std()
            .map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        let cli_b_std = cli_b
            .into_std()
            .map_err(|e| ipc_io_plumbing(e, "into_std"))?;

        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_a_std.into(), cli_b_std.into()])
            .map_err(|e| ipc_io_plumbing(e, "queue_fds"))?;

        // Bridge reader direction: real QUIC reader → IpcWriteStream on srv_a
        let pipe_w = IpcWriteStream::new(stream_id, srv_a, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        // Bridge writer direction: IpcReadStream on srv_b → real QUIC writer
        let pipe_r = IpcReadStream::new(stream_id, srv_b, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok(IpcBiHandle { fd_id, stream_id })
    }

    async fn open_uni_impl(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError> {
        let mut writer = ManageStream::open_uni(self.inner.as_ref())
            .await
            .map_err(|e| IpcOpenError::Connection { source: e })?;
        let stream_id = match writer.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_std.into()])
            .map_err(|e| ipc_io_plumbing(e, "queue_fds"))?;

        // IpcReadStream on srv → real QUIC writer
        let pipe_r = IpcReadStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok(Resolved::ok(IpcUniHandle { fd_id, stream_id }))
    }

    async fn accept_uni_impl(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError> {
        let mut reader = ManageStream::accept_uni(self.inner.as_ref())
            .await
            .map_err(|e| IpcAcceptError::Connection { source: e })?;
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![cli_std.into()])
            .map_err(|e| ipc_io_plumbing(e, "queue_fds"))?;

        // Real QUIC reader → IpcWriteStream on srv
        let pipe_w = IpcWriteStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        Ok(Resolved::ok(IpcUniHandle { fd_id, stream_id }))
    }
}

// ---------------------------------------------------------------------------
// Client side: IpcConnectionHandle
// ---------------------------------------------------------------------------

/// Client-side connection handle that wraps an [`IpcConnectionClient`] and
/// implements [`quic::Connection`].
///
/// Created by the client after receiving a [`ConnectionBootstrap`] over the
/// remoc base channel of a connection-level [`MuxChannel`].
pub struct IpcConnectionHandle {
    rpc: IpcConnectionClient,
    fd_registry: FdRegistry,
    /// Retained for potential future use (e.g. client-initiated accept_bi
    /// where the client creates socketpairs and sends FDs back to the server).
    _conn_fd_sender: FdSender,
    lifecycle: Arc<IpcLifecycle>,
}

/// Internal lifecycle state for [`IpcConnectionHandle`].
///
/// Owns the latch that enforces first-wins error semantics across every
/// operation on the connection and its descendant streams.  Implements
/// [`quic::Lifecycle`] so the shared `Arc<IpcLifecycle>` can be handed to
/// [`IpcReadStream`] / [`IpcWriteStream`] as `Arc<dyn DynLifecycle>`.
struct IpcLifecycle {
    connection: IpcConnectionClient,
    latch: ConnectionErrorLatch,
}

impl HasLatch for IpcLifecycle {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for IpcLifecycle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let rpc = self.connection.clone();
        tokio::spawn(
            async move {
                let _ = IpcConnection::close(&rpc, code, reason).await;
            }
            .in_current_span(),
        );
    }

    fn check(&self) -> Result<(), ConnectionError> {
        self.check_with_probe(|| {
            remoc::rtc::Client::is_closed(&self.connection)
                .then(IpcConnectionHandle::ipc_channel_error)
        })
    }

    async fn closed(&self) -> ConnectionError {
        self.resolve_closed(async {
            IpcConnection::closed(&self.connection)
                .await
                .unwrap_or_else(|_| IpcConnectionHandle::ipc_channel_error())
        })
        .await
    }
}

impl IpcConnectionHandle {
    /// Create a new handle from bootstrap data and FD registry.
    pub fn new(
        rpc: IpcConnectionClient,
        fd_registry: FdRegistry,
        conn_fd_sender: FdSender,
    ) -> Self {
        let lifecycle = Arc::new(IpcLifecycle {
            connection: rpc.clone(),
            latch: ConnectionErrorLatch::new(),
        });
        Self {
            rpc,
            fd_registry,
            _conn_fd_sender: conn_fd_sender,
            lifecycle,
        }
    }

    /// Synthesize a transport error for IPC channel failures.
    fn ipc_channel_error() -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: IPC_CHANNEL_ERROR_KIND,
                frame_type: IPC_FRAME_TYPE,
                reason: "ipc connection channel closed".into(),
            },
        }
    }
}

impl quic::ManageStream for IpcConnectionHandle {
    type StreamReader = Resolved<IpcReadStream, StreamError>;
    type StreamWriter = Resolved<IpcWriteStream, StreamError>;

    async fn open_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
        let resolved = self
            .lifecycle
            .guard_with(IpcConnection::open_bi(&self.rpc), map_open_err)
            .await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let (r, w) = self.fds_to_bi(handle).await?;
                Ok((Resolved::ok(r), Resolved::ok(w)))
            }
            Resolved::Error { error } => Ok((Resolved::err(error.clone()), Resolved::err(error))),
        }
    }

    async fn accept_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
        let resolved = self
            .lifecycle
            .guard_with(IpcConnection::accept_bi(&self.rpc), map_accept_err)
            .await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let (r, w) = self.fds_to_bi(handle).await?;
                Ok((Resolved::ok(r), Resolved::ok(w)))
            }
            Resolved::Error { error } => Ok((Resolved::err(error.clone()), Resolved::err(error))),
        }
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, ConnectionError> {
        let resolved = self
            .lifecycle
            .guard_with(IpcConnection::open_uni(&self.rpc), map_open_err)
            .await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let w = self.fds_to_uni_writer(handle).await?;
                Ok(Resolved::ok(w))
            }
            Resolved::Error { error } => Ok(Resolved::err(error)),
        }
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, ConnectionError> {
        let resolved = self
            .lifecycle
            .guard_with(IpcConnection::accept_uni(&self.rpc), map_accept_err)
            .await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let r = self.fds_to_uni_reader(handle).await?;
                Ok(Resolved::ok(r))
            }
            Resolved::Error { error } => Ok(Resolved::err(error)),
        }
    }
}

impl IpcConnectionHandle {
    /// Retrieve 2 FDs and construct a (IpcReadStream, IpcWriteStream) pair.
    async fn fds_to_bi(
        &self,
        handle: IpcBiHandle,
    ) -> Result<(IpcReadStream, IpcWriteStream), ConnectionError> {
        let IpcBiHandle { fd_id, stream_id } = handle;
        let fds = self
            .lifecycle
            .guard_with(self.fd_registry.wait_fds(fd_id), |e| {
                ipc_transport_error(e, "wait_fds")
            })
            .await?;
        self.lifecycle.guard_sync(|| {
            if fds.len() != 2 {
                return Err(ConnectionError::Transport {
                    source: quic::TransportError {
                        kind: IPC_ERROR_KIND,
                        frame_type: IPC_FRAME_TYPE,
                        reason: format!("expected 2 fds for bidi stream, got {}", fds.len()).into(),
                    },
                });
            }
            let mut fds = fds.into_iter();
            let fd_a = fds.next().unwrap();
            let fd_b = fds.next().unwrap();

            let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

            // fd_a → reader pipe (matches server's IpcWriteStream on srv_a)
            let sock_a = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_a))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            let reader = IpcReadStream::new(stream_id, sock_a, lifecycle.clone());

            // fd_b → writer pipe (matches server's IpcReadStream on srv_b)
            let sock_b = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_b))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            let writer = IpcWriteStream::new(stream_id, sock_b, lifecycle);

            Ok((reader, writer))
        })
    }

    /// Retrieve 1 FD and construct a IpcWriteStream (for open_uni).
    async fn fds_to_uni_writer(
        &self,
        handle: IpcUniHandle,
    ) -> Result<IpcWriteStream, ConnectionError> {
        let IpcUniHandle { fd_id, stream_id } = handle;
        let fds = self
            .lifecycle
            .guard_with(self.fd_registry.wait_fds(fd_id), |e| {
                ipc_transport_error(e, "wait_fds")
            })
            .await?;
        self.lifecycle.guard_sync(|| {
            if fds.len() != 1 {
                return Err(ConnectionError::Transport {
                    source: quic::TransportError {
                        kind: IPC_ERROR_KIND,
                        frame_type: IPC_FRAME_TYPE,
                        reason: format!("expected 1 fd for uni stream, got {}", fds.len()).into(),
                    },
                });
            }
            let fd = fds.into_iter().next().unwrap();
            let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
            let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            Ok(IpcWriteStream::new(stream_id, sock, lifecycle))
        })
    }

    /// Retrieve 1 FD and construct a IpcReadStream (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        handle: IpcUniHandle,
    ) -> Result<IpcReadStream, ConnectionError> {
        let IpcUniHandle { fd_id, stream_id } = handle;
        let fds = self
            .lifecycle
            .guard_with(self.fd_registry.wait_fds(fd_id), |e| {
                ipc_transport_error(e, "wait_fds")
            })
            .await?;
        self.lifecycle.guard_sync(|| {
            if fds.len() != 1 {
                return Err(ConnectionError::Transport {
                    source: quic::TransportError {
                        kind: IPC_ERROR_KIND,
                        frame_type: IPC_FRAME_TYPE,
                        reason: format!("expected 1 fd for uni stream, got {}", fds.len()).into(),
                    },
                });
            }
            let fd = fds.into_iter().next().unwrap();
            let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
            let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            Ok(IpcReadStream::new(stream_id, sock, lifecycle))
        })
    }
}

impl quic::WithLocalAgent for IpcConnectionHandle {
    type LocalAgent = CachedLocalAgent;

    async fn local_agent(&self) -> Result<Option<CachedLocalAgent>, ConnectionError> {
        match self
            .lifecycle
            .guard(IpcConnection::local_agent(&self.rpc))
            .await?
        {
            Some(client) => Ok(Some(
                self.lifecycle
                    .guard(CachedLocalAgent::from_client(client))
                    .await?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::WithRemoteAgent for IpcConnectionHandle {
    type RemoteAgent = CachedRemoteAgent;

    async fn remote_agent(&self) -> Result<Option<CachedRemoteAgent>, ConnectionError> {
        match self
            .lifecycle
            .guard(IpcConnection::remote_agent(&self.rpc))
            .await?
        {
            Some(client) => Ok(Some(
                self.lifecycle
                    .guard(CachedRemoteAgent::from_client(client))
                    .await?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::Lifecycle for IpcConnectionHandle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        quic::Lifecycle::close(self.lifecycle.as_ref(), code, reason);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        quic::Lifecycle::check(self.lifecycle.as_ref())
    }

    async fn closed(&self) -> ConnectionError {
        quic::Lifecycle::closed(self.lifecycle.as_ref()).await
    }
}

// ---------------------------------------------------------------------------
// Error constants & helpers
// ---------------------------------------------------------------------------

/// Error kind for general IPC transport failures.
pub(crate) const IPC_ERROR_KIND: VarInt = VarInt::from_u32(0x0a);

/// Error kind for IPC channel closure.
const IPC_CHANNEL_ERROR_KIND: VarInt = VarInt::from_u32(0x01);

/// Frame type placeholder for IPC-synthesized transport errors.
pub(crate) const IPC_FRAME_TYPE: VarInt = VarInt::from_u32(0x00);

fn ipc_io_error(err: io::Error, context: &str) -> ConnectionError {
    debug!(error = %snafu::Report::from_error(err), context, "ipc i/o error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc: {context}").into(),
        },
    }
}

fn ipc_transport_error(err: impl std::error::Error, context: &str) -> ConnectionError {
    debug!(error = %snafu::Report::from_error(&err), context, "ipc transport error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc: {context}").into(),
        },
    }
}

/// Convert an I/O error into an [`IpcPlumbingError`] (server side).
fn ipc_io_plumbing(err: impl std::fmt::Display, context: &str) -> IpcPlumbingError {
    debug!(error = %err, context, "ipc plumbing i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
}

/// Convert an [`IpcPlumbingError`] into a [`ConnectionError`] (client side).
fn plumbing_to_conn(err: &IpcPlumbingError) -> ConnectionError {
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: err.to_string().into(),
        },
    }
}

/// Map an [`IpcOpenError`] into a [`ConnectionError`] for `guard_with` closures.
fn map_open_err(error: IpcOpenError) -> ConnectionError {
    match error {
        IpcOpenError::Connection { source } => source,
        IpcOpenError::Plumbing { source } => plumbing_to_conn(&source),
    }
}

/// Map an [`IpcAcceptError`] into a [`ConnectionError`] for `guard_with` closures.
fn map_accept_err(error: IpcAcceptError) -> ConnectionError {
    match error {
        IpcAcceptError::Connection { source } => source,
        IpcAcceptError::Plumbing { source } => plumbing_to_conn(&source),
    }
}

// ---------------------------------------------------------------------------
// IpcConnectionClient convenience
// ---------------------------------------------------------------------------

impl IpcConnectionClient {
    /// Convert into an [`IpcConnectionHandle`].
    pub fn into_handle(
        self,
        fd_registry: FdRegistry,
        conn_fd_sender: FdSender,
    ) -> IpcConnectionHandle {
        IpcConnectionHandle::new(self, fd_registry, conn_fd_sender)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        collections::VecDeque,
        future::pending,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use dhttp_identity::identity;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use remoc::prelude::ServerShared;
    use smallvec::smallvec;
    use tokio::{net::UnixStream, sync::mpsc, time};
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::*;
    use crate::{
        ipc::transport::{FdRegistry, FdSender, MuxChannel},
        quic::{CancelStream, GetStreamId, GetStreamIdExt, StopStream},
    };

    fn test_connection_error(reason: &str) -> ConnectionError {
        ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x31),
                frame_type: VarInt::from_u32(0x32),
                reason: reason.to_owned().into(),
            },
        }
    }

    fn test_stream_error(reason: &str) -> StreamError {
        StreamError::Connection {
            source: test_connection_error(reason),
        }
    }

    #[derive(Default)]
    struct TestLifecycle {
        terminal: Mutex<Option<ConnectionError>>,
    }

    impl TestLifecycle {
        fn set_terminal(&self, error: ConnectionError) {
            *self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned") = Some(error);
        }
    }

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            match self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone()
            {
                Some(error) => Err(error),
                None => Ok(()),
            }
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

    #[derive(Clone, Debug)]
    struct TestLocalAgent(&'static str);

    impl identity::LocalAgent for TestLocalAgent {
        fn name(&self) -> &str {
            self.0
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
        ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, identity::SignError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Clone, Debug)]
    struct TestRemoteAgent(&'static str);

    impl identity::RemoteAgent for TestRemoteAgent {
        fn name(&self) -> &str {
            self.0
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    struct TestReader {
        stream_id: Result<VarInt, StreamError>,
        rx: mpsc::Receiver<Bytes>,
    }

    impl GetStreamId for TestReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(self.stream_id.clone())
        }
    }

    impl StopStream for TestReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            self.get_mut().rx.close();
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for TestReader {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.get_mut().rx.poll_recv(cx).map(|item| item.map(Ok))
        }
    }

    struct TestWriter {
        stream_id: Result<VarInt, StreamError>,
        tx: Option<mpsc::Sender<Bytes>>,
    }

    impl GetStreamId for TestWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(self.stream_id.clone())
        }
    }

    impl CancelStream for TestWriter {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            self.get_mut().tx = None;
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for TestWriter {
        type Error = StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if self.tx.is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(test_stream_error("writer closed")))
            }
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            let this = self.get_mut();
            let Some(tx) = &this.tx else {
                return Err(test_stream_error("writer closed"));
            };
            tx.try_send(item)
                .map_err(|_| test_stream_error("writer send failed"))
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
            self.get_mut().tx = None;
            Poll::Ready(Ok(()))
        }
    }

    struct BidiHandles {
        tx_to_reader: mpsc::Sender<Bytes>,
        rx_from_writer: mpsc::Receiver<Bytes>,
    }

    struct UniWriterHandles {
        rx_from_writer: mpsc::Receiver<Bytes>,
    }

    struct UniReaderHandles {
        tx_to_reader: mpsc::Sender<Bytes>,
    }

    struct TestConnection {
        lifecycle: Arc<TestLifecycle>,
        closes: Mutex<Vec<(Code, Cow<'static, str>)>>,
        open_bi: Mutex<VecDeque<Result<(TestReader, TestWriter), ConnectionError>>>,
        accept_bi: Mutex<VecDeque<Result<(TestReader, TestWriter), ConnectionError>>>,
        open_uni: Mutex<VecDeque<Result<TestWriter, ConnectionError>>>,
        accept_uni: Mutex<VecDeque<Result<TestReader, ConnectionError>>>,
        local_agent: Mutex<Result<Option<TestLocalAgent>, ConnectionError>>,
        remote_agent: Mutex<Result<Option<TestRemoteAgent>, ConnectionError>>,
    }

    impl TestConnection {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                lifecycle: Arc::new(TestLifecycle::default()),
                closes: Mutex::new(Vec::new()),
                open_bi: Mutex::new(VecDeque::new()),
                accept_bi: Mutex::new(VecDeque::new()),
                open_uni: Mutex::new(VecDeque::new()),
                accept_uni: Mutex::new(VecDeque::new()),
                local_agent: Mutex::new(Ok(None)),
                remote_agent: Mutex::new(Ok(None)),
            })
        }

        fn set_local_agent(&self, agent: Option<TestLocalAgent>) {
            *self
                .local_agent
                .lock()
                .expect("local agent mutex should not be poisoned") = Ok(agent);
        }

        fn set_remote_agent(&self, agent: Option<TestRemoteAgent>) {
            *self
                .remote_agent
                .lock()
                .expect("remote agent mutex should not be poisoned") = Ok(agent);
        }

        fn close_calls(&self) -> Vec<(Code, Cow<'static, str>)> {
            self.closes
                .lock()
                .expect("close mutex should not be poisoned")
                .clone()
        }

        fn push_open_bi_success(&self, stream_id: VarInt) -> BidiHandles {
            let (reader_tx, reader_rx) = mpsc::channel(8);
            let (writer_tx, writer_rx) = mpsc::channel(8);
            self.open_bi
                .lock()
                .expect("open_bi mutex should not be poisoned")
                .push_back(Ok((
                    TestReader {
                        stream_id: Ok(stream_id),
                        rx: reader_rx,
                    },
                    TestWriter {
                        stream_id: Ok(stream_id),
                        tx: Some(writer_tx),
                    },
                )));
            BidiHandles {
                tx_to_reader: reader_tx,
                rx_from_writer: writer_rx,
            }
        }

        fn push_accept_bi_success(&self, stream_id: VarInt) -> BidiHandles {
            let (reader_tx, reader_rx) = mpsc::channel(8);
            let (writer_tx, writer_rx) = mpsc::channel(8);
            self.accept_bi
                .lock()
                .expect("accept_bi mutex should not be poisoned")
                .push_back(Ok((
                    TestReader {
                        stream_id: Ok(stream_id),
                        rx: reader_rx,
                    },
                    TestWriter {
                        stream_id: Ok(stream_id),
                        tx: Some(writer_tx),
                    },
                )));
            BidiHandles {
                tx_to_reader: reader_tx,
                rx_from_writer: writer_rx,
            }
        }

        fn push_open_uni_success(&self, stream_id: VarInt) -> UniWriterHandles {
            let (writer_tx, writer_rx) = mpsc::channel(8);
            self.open_uni
                .lock()
                .expect("open_uni mutex should not be poisoned")
                .push_back(Ok(TestWriter {
                    stream_id: Ok(stream_id),
                    tx: Some(writer_tx),
                }));
            UniWriterHandles {
                rx_from_writer: writer_rx,
            }
        }

        fn push_accept_uni_success(&self, stream_id: VarInt) -> UniReaderHandles {
            let (reader_tx, reader_rx) = mpsc::channel(8);
            self.accept_uni
                .lock()
                .expect("accept_uni mutex should not be poisoned")
                .push_back(Ok(TestReader {
                    stream_id: Ok(stream_id),
                    rx: reader_rx,
                }));
            UniReaderHandles {
                tx_to_reader: reader_tx,
            }
        }

        fn push_open_bi_stream_id_error(&self, error: StreamError) {
            let (_reader_tx, reader_rx) = mpsc::channel(1);
            let (writer_tx, _writer_rx) = mpsc::channel(1);
            self.open_bi
                .lock()
                .expect("open_bi mutex should not be poisoned")
                .push_back(Ok((
                    TestReader {
                        stream_id: Err(error.clone()),
                        rx: reader_rx,
                    },
                    TestWriter {
                        stream_id: Ok(VarInt::from_u32(1)),
                        tx: Some(writer_tx),
                    },
                )));
        }

        fn push_accept_bi_stream_id_error(&self, error: StreamError) {
            let (_reader_tx, reader_rx) = mpsc::channel(1);
            let (writer_tx, _writer_rx) = mpsc::channel(1);
            self.accept_bi
                .lock()
                .expect("accept_bi mutex should not be poisoned")
                .push_back(Ok((
                    TestReader {
                        stream_id: Err(error.clone()),
                        rx: reader_rx,
                    },
                    TestWriter {
                        stream_id: Ok(VarInt::from_u32(1)),
                        tx: Some(writer_tx),
                    },
                )));
        }

        fn push_open_uni_stream_id_error(&self, error: StreamError) {
            let (writer_tx, _writer_rx) = mpsc::channel(1);
            self.open_uni
                .lock()
                .expect("open_uni mutex should not be poisoned")
                .push_back(Ok(TestWriter {
                    stream_id: Err(error),
                    tx: Some(writer_tx),
                }));
        }

        fn push_accept_uni_stream_id_error(&self, error: StreamError) {
            let (_reader_tx, reader_rx) = mpsc::channel(1);
            self.accept_uni
                .lock()
                .expect("accept_uni mutex should not be poisoned")
                .push_back(Ok(TestReader {
                    stream_id: Err(error),
                    rx: reader_rx,
                }));
        }

        fn push_open_bi_error(&self, error: ConnectionError) {
            self.open_bi
                .lock()
                .expect("open_bi mutex should not be poisoned")
                .push_back(Err(error));
        }

        fn push_accept_bi_error(&self, error: ConnectionError) {
            self.accept_bi
                .lock()
                .expect("accept_bi mutex should not be poisoned")
                .push_back(Err(error));
        }

        fn push_open_uni_error(&self, error: ConnectionError) {
            self.open_uni
                .lock()
                .expect("open_uni mutex should not be poisoned")
                .push_back(Err(error));
        }

        fn push_accept_uni_error(&self, error: ConnectionError) {
            self.accept_uni
                .lock()
                .expect("accept_uni mutex should not be poisoned")
                .push_back(Err(error));
        }
    }

    impl ManageStream for TestConnection {
        type StreamReader = TestReader;
        type StreamWriter = TestWriter;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
            self.open_bi
                .lock()
                .expect("open_bi mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(test_connection_error("missing open_bi result")))
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
            self.accept_bi
                .lock()
                .expect("accept_bi mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(test_connection_error("missing accept_bi result")))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, ConnectionError> {
            self.open_uni
                .lock()
                .expect("open_uni mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(test_connection_error("missing open_uni result")))
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, ConnectionError> {
            self.accept_uni
                .lock()
                .expect("accept_uni mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(test_connection_error("missing accept_uni result")))
        }
    }

    impl quic::Lifecycle for TestConnection {
        fn close(&self, code: Code, reason: Cow<'static, str>) {
            self.closes
                .lock()
                .expect("close mutex should not be poisoned")
                .push((code, reason));
        }

        fn check(&self) -> Result<(), ConnectionError> {
            quic::Lifecycle::check(self.lifecycle.as_ref())
        }

        async fn closed(&self) -> ConnectionError {
            quic::Lifecycle::closed(self.lifecycle.as_ref()).await
        }
    }

    impl quic::WithLocalAgent for TestConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, ConnectionError> {
            self.local_agent
                .lock()
                .expect("local agent mutex should not be poisoned")
                .clone()
        }
    }

    impl quic::WithRemoteAgent for TestConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, ConnectionError> {
            self.remote_agent
                .lock()
                .expect("remote agent mutex should not be poisoned")
                .clone()
        }
    }

    struct FdHarness {
        server_sender: FdSender,
        client_registry: FdRegistry,
        client_sender: FdSender,
        sink: crate::ipc::transport::MuxSink,
        stream: crate::ipc::transport::MuxStream,
    }

    impl FdHarness {
        fn new() -> Self {
            let (server_mux, client_mux) = MuxChannel::pair_for_test().expect("create mux pair");
            let (server_sink, _server_stream) = server_mux.split().expect("split server mux");
            let (client_sink, client_stream) = client_mux.split().expect("split client mux");
            let client_registry = client_stream.fd_registry();
            let client_sender = client_sink.fd_sender();
            let server_sender = server_sink.fd_sender();
            Self {
                server_sender,
                client_registry,
                client_sender,
                sink: server_sink,
                stream: client_stream,
            }
        }

        async fn flush(&mut self) {
            self.sink.send(Bytes::new()).await.expect("flush fd frame");
            let _ = self
                .stream
                .next()
                .await
                .expect("mux stream item")
                .expect("bytes frame");
        }
    }

    fn spawn_connection_server<C>(
        connection: Arc<C>,
    ) -> (AbortOnDropHandle<()>, IpcConnectionClient)
    where
        C: IpcConnection + 'static,
    {
        let (server, client) = IpcConnectionServerShared::new(connection, 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    struct ScriptedIpcConnection {
        open_bi: Mutex<VecDeque<Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError>>>,
        accept_bi: Mutex<VecDeque<Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError>>>,
        open_uni: Mutex<VecDeque<Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError>>>,
        accept_uni: Mutex<VecDeque<Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError>>>,
        local_agent: Mutex<Result<Option<LocalAgentClient>, ConnectionError>>,
        remote_agent: Mutex<Result<Option<RemoteAgentClient>, ConnectionError>>,
        close_calls: Mutex<Vec<(Code, Cow<'static, str>)>>,
        closed_result: Mutex<Result<ConnectionError, ConnectionError>>,
    }

    impl ScriptedIpcConnection {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                open_bi: Mutex::new(VecDeque::new()),
                accept_bi: Mutex::new(VecDeque::new()),
                open_uni: Mutex::new(VecDeque::new()),
                accept_uni: Mutex::new(VecDeque::new()),
                local_agent: Mutex::new(Ok(None)),
                remote_agent: Mutex::new(Ok(None)),
                close_calls: Mutex::new(Vec::new()),
                closed_result: Mutex::new(Ok(test_connection_error("scripted closed"))),
            })
        }
    }

    impl IpcConnection for ScriptedIpcConnection {
        async fn open_bi(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError> {
            self.open_bi
                .lock()
                .expect("open_bi mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(IpcOpenError::Connection {
                        source: test_connection_error("missing scripted open_bi"),
                    })
                })
        }

        async fn accept_bi(&self) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError> {
            self.accept_bi
                .lock()
                .expect("accept_bi mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(IpcAcceptError::Connection {
                        source: test_connection_error("missing scripted accept_bi"),
                    })
                })
        }

        async fn open_uni(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError> {
            self.open_uni
                .lock()
                .expect("open_uni mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(IpcOpenError::Connection {
                        source: test_connection_error("missing scripted open_uni"),
                    })
                })
        }

        async fn accept_uni(&self) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError> {
            self.accept_uni
                .lock()
                .expect("accept_uni mutex should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(IpcAcceptError::Connection {
                        source: test_connection_error("missing scripted accept_uni"),
                    })
                })
        }

        async fn local_agent(&self) -> Result<Option<LocalAgentClient>, ConnectionError> {
            self.local_agent
                .lock()
                .expect("local agent mutex should not be poisoned")
                .clone()
        }

        async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, ConnectionError> {
            self.remote_agent
                .lock()
                .expect("remote agent mutex should not be poisoned")
                .clone()
        }

        async fn close(
            &self,
            code: Code,
            reason: Cow<'static, str>,
        ) -> Result<(), ConnectionError> {
            self.close_calls
                .lock()
                .expect("close mutex should not be poisoned")
                .push((code, reason));
            Ok(())
        }

        async fn closed(&self) -> Result<ConnectionError, ConnectionError> {
            self.closed_result
                .lock()
                .expect("closed mutex should not be poisoned")
                .clone()
        }
    }

    fn spawn_local_agent(agent: TestLocalAgent) -> (AbortOnDropHandle<()>, LocalAgentClient) {
        let (server, client) = LocalAgentServerShared::new(Arc::new(agent), 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    fn spawn_remote_agent(agent: TestRemoteAgent) -> (AbortOnDropHandle<()>, RemoteAgentClient) {
        let (server, client) = RemoteAgentServerShared::new(Arc::new(agent), 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    fn assert_transport_reason(error: &ConnectionError, expected_fragment: &str) {
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert!(
            source.reason.contains(expected_fragment),
            "transport reason {:?} should contain {expected_fragment:?}",
            source.reason,
        );
    }

    fn owned_fd() -> std::os::fd::OwnedFd {
        let (stream, _peer) = UnixStream::pair().expect("create unix pair");
        stream.into_std().expect("convert tokio stream").into()
    }

    #[tokio::test]
    async fn bridge_helpers_stop_when_destination_fails() {
        let lifecycle_state = Arc::new(TestLifecycle::default());
        lifecycle_state.set_terminal(test_connection_error("bridge reader terminal"));
        let lifecycle: Arc<dyn DynLifecycle> = lifecycle_state;

        let (reader_tx, reader_rx) = mpsc::channel(1);
        let (pipe_writer_sock, pipe_reader_sock) = UnixStream::pair().expect("create unix pair");
        let reader = TestReader {
            stream_id: Ok(VarInt::from_u32(101)),
            rx: reader_rx,
        };
        let pipe_writer =
            IpcWriteStream::new(VarInt::from_u32(101), pipe_writer_sock, lifecycle.clone());
        drop(pipe_reader_sock);
        reader_tx
            .send(Bytes::from_static(b"cannot-deliver"))
            .await
            .expect("stage reader payload");
        drop(reader_tx);

        time::timeout(
            std::time::Duration::from_secs(1),
            bridge_reader(reader, pipe_writer),
        )
        .await
        .expect("bridge reader should stop after pipe send failure");

        let lifecycle: Arc<dyn DynLifecycle> = Arc::new(TestLifecycle::default());
        let (pipe_read_sock, pipe_write_sock) = UnixStream::pair().expect("create unix pair");
        let closed_writer = TestWriter {
            stream_id: Ok(VarInt::from_u32(103)),
            tx: None,
        };
        let pipe_reader =
            IpcReadStream::new(VarInt::from_u32(103), pipe_read_sock, lifecycle.clone());
        let task = tokio::spawn(
            async move {
                bridge_writer(pipe_reader, closed_writer).await;
            }
            .in_current_span(),
        );
        tokio::task::yield_now().await;
        let mut pipe_writer =
            IpcWriteStream::new(VarInt::from_u32(103), pipe_write_sock, lifecycle);
        pipe_writer
            .send(Bytes::from_static(b"cannot-write"))
            .await
            .expect("stage pipe payload");
        drop(pipe_writer);

        time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("bridge writer should stop after quic send failure")
            .expect("bridge writer task should not panic");
    }

    #[tokio::test]
    async fn adapter_open_and_accept_streams_bridge_data() {
        let mut fd_harness = FdHarness::new();
        let connection = TestConnection::new();
        let adapter = ConnectionAdapter::new(connection.clone(), fd_harness.server_sender.clone());
        let (_rpc_task, rpc) = spawn_connection_server(Arc::new(adapter));
        let handle = rpc.into_handle(
            fd_harness.client_registry.clone(),
            fd_harness.client_sender.clone(),
        );

        let mut open_bi_handles = connection.push_open_bi_success(VarInt::from_u32(11));
        let Resolved::Value { value: open_bi } = IpcConnection::open_bi(&handle.rpc)
            .await
            .expect("open_bi rpc")
        else {
            panic!("open_bi should return handle");
        };
        fd_harness.flush().await;
        let (mut bi_reader, mut bi_writer) = handle.fds_to_bi(open_bi).await.expect("bidi fds");
        bi_writer
            .send(Bytes::from_static(b"client-to-server"))
            .await
            .expect("write bidi payload");
        let received = open_bi_handles
            .rx_from_writer
            .recv()
            .await
            .expect("server should receive bidi payload");
        assert_eq!(received, Bytes::from_static(b"client-to-server"));
        open_bi_handles
            .tx_to_reader
            .send(Bytes::from_static(b"server-to-client"))
            .await
            .expect("inject bidi payload");
        let received = bi_reader
            .next()
            .await
            .expect("bidi reader item")
            .expect("bidi reader payload");
        assert_eq!(received, Bytes::from_static(b"server-to-client"));

        let mut accept_bi_handles = connection.push_accept_bi_success(VarInt::from_u32(13));
        let Resolved::Value { value: accept_bi } = IpcConnection::accept_bi(&handle.rpc)
            .await
            .expect("accept_bi rpc")
        else {
            panic!("accept_bi should return handle");
        };
        fd_harness.flush().await;
        let (mut accepted_reader, mut accepted_writer) = handle
            .fds_to_bi(accept_bi)
            .await
            .expect("accepted bidi fds");
        accepted_writer
            .send(Bytes::from_static(b"accepted-client-write"))
            .await
            .expect("accepted writer");
        let received = accept_bi_handles
            .rx_from_writer
            .recv()
            .await
            .expect("server should receive accepted bidi payload");
        assert_eq!(received, Bytes::from_static(b"accepted-client-write"));
        accept_bi_handles
            .tx_to_reader
            .send(Bytes::from_static(b"accepted-server-write"))
            .await
            .expect("inject accepted payload");
        let received = accepted_reader
            .next()
            .await
            .expect("accepted reader item")
            .expect("accepted reader payload");
        assert_eq!(received, Bytes::from_static(b"accepted-server-write"));

        let mut open_uni_handles = connection.push_open_uni_success(VarInt::from_u32(17));
        let Resolved::Value { value: open_uni } = IpcConnection::open_uni(&handle.rpc)
            .await
            .expect("open_uni rpc")
        else {
            panic!("open_uni should return handle");
        };
        fd_harness.flush().await;
        let mut uni_writer = handle
            .fds_to_uni_writer(open_uni)
            .await
            .expect("uni writer fds");
        uni_writer
            .send(Bytes::from_static(b"uni-client-write"))
            .await
            .expect("uni write");
        let received = open_uni_handles
            .rx_from_writer
            .recv()
            .await
            .expect("server should receive uni payload");
        assert_eq!(received, Bytes::from_static(b"uni-client-write"));

        let accept_uni_handles = connection.push_accept_uni_success(VarInt::from_u32(19));
        let Resolved::Value { value: accept_uni } = IpcConnection::accept_uni(&handle.rpc)
            .await
            .expect("accept_uni rpc")
        else {
            panic!("accept_uni should return handle");
        };
        fd_harness.flush().await;
        let mut uni_reader = handle
            .fds_to_uni_reader(accept_uni)
            .await
            .expect("uni reader fds");
        accept_uni_handles
            .tx_to_reader
            .send(Bytes::from_static(b"uni-server-write"))
            .await
            .expect("inject uni payload");
        let received = uni_reader
            .next()
            .await
            .expect("uni reader item")
            .expect("uni reader payload");
        assert_eq!(received, Bytes::from_static(b"uni-server-write"));
    }

    #[tokio::test]
    async fn adapter_returns_resolved_stream_errors_and_connection_errors() {
        let fd_harness = FdHarness::new();
        let connection = TestConnection::new();
        let adapter = ConnectionAdapter::new(connection.clone(), fd_harness.server_sender);

        let stream_error = StreamError::Reset {
            code: VarInt::from_u32(77),
        };
        connection.push_open_bi_stream_id_error(stream_error.clone());
        let resolved = adapter.open_bi_impl().await.expect("open_bi impl");
        match resolved {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(77)),
            Resolved::Error { error } => panic!("expected reset error, got {error:?}"),
            Resolved::Value { .. } => panic!("expected stream_id error"),
        }

        connection.push_accept_bi_stream_id_error(stream_error.clone());
        let resolved = adapter.accept_bi_impl().await.expect("accept_bi impl");
        match resolved {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(77)),
            Resolved::Error { error } => panic!("expected reset error, got {error:?}"),
            Resolved::Value { .. } => panic!("expected stream_id error"),
        }

        connection.push_open_uni_stream_id_error(stream_error.clone());
        let resolved = adapter.open_uni_impl().await.expect("open_uni impl");
        match resolved {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(77)),
            Resolved::Error { error } => panic!("expected reset error, got {error:?}"),
            Resolved::Value { .. } => panic!("expected stream_id error"),
        }

        connection.push_accept_uni_stream_id_error(stream_error.clone());
        let resolved = adapter.accept_uni_impl().await.expect("accept_uni impl");
        match resolved {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(77)),
            Resolved::Error { error } => panic!("expected reset error, got {error:?}"),
            Resolved::Value { .. } => panic!("expected stream_id error"),
        }

        let open_error = test_connection_error("open_bi failed");
        connection.push_open_bi_error(open_error.clone());
        let error = match adapter.open_bi_impl().await {
            Ok(_) => panic!("open_bi should fail"),
            Err(error) => error,
        };
        let IpcOpenError::Connection { source } = error else {
            panic!("expected open_bi connection error");
        };
        assert_transport_reason(&source, "open_bi failed");

        let accept_error = test_connection_error("accept_bi failed");
        connection.push_accept_bi_error(accept_error.clone());
        let error = match adapter.accept_bi_impl().await {
            Ok(_) => panic!("accept_bi should fail"),
            Err(error) => error,
        };
        let IpcAcceptError::Connection { source } = error else {
            panic!("expected accept_bi connection error");
        };
        assert_transport_reason(&source, "accept_bi failed");

        let open_uni_error = test_connection_error("open_uni failed");
        connection.push_open_uni_error(open_uni_error.clone());
        let error = match adapter.open_uni_impl().await {
            Ok(_) => panic!("open_uni should fail"),
            Err(error) => error,
        };
        let IpcOpenError::Connection { source } = error else {
            panic!("expected open_uni connection error");
        };
        assert_transport_reason(&source, "open_uni failed");

        let accept_uni_error = test_connection_error("accept_uni failed");
        connection.push_accept_uni_error(accept_uni_error.clone());
        let error = match adapter.accept_uni_impl().await {
            Ok(_) => panic!("accept_uni should fail"),
            Err(error) => error,
        };
        let IpcAcceptError::Connection { source } = error else {
            panic!("expected accept_uni connection error");
        };
        assert_transport_reason(&source, "accept_uni failed");
    }

    #[tokio::test]
    async fn adapter_surfaces_agents_and_lifecycle() {
        let fd_harness = FdHarness::new();
        let connection = TestConnection::new();
        connection.set_local_agent(Some(TestLocalAgent("local-test")));
        connection.set_remote_agent(Some(TestRemoteAgent("remote-test")));

        let adapter = ConnectionAdapter::new(connection.clone(), fd_harness.server_sender);

        let local = IpcConnection::local_agent(&adapter)
            .await
            .expect("local agent rpc")
            .expect("local agent");
        let local = CachedLocalAgent::from_client(local)
            .await
            .expect("cache local agent");
        assert_eq!(identity::LocalAgent::name(&local), "local-test");

        let remote = IpcConnection::remote_agent(&adapter)
            .await
            .expect("remote agent rpc")
            .expect("remote agent");
        let remote = CachedRemoteAgent::from_client(remote)
            .await
            .expect("cache remote agent");
        assert_eq!(identity::RemoteAgent::name(&remote), "remote-test");

        IpcConnection::close(&adapter, Code::H3_NO_ERROR, "adapter close".into())
            .await
            .expect("adapter close");
        assert_eq!(
            connection.close_calls(),
            vec![(Code::H3_NO_ERROR, Cow::Borrowed("adapter close"))]
        );

        let terminal = test_connection_error("adapter terminal");
        connection.lifecycle.set_terminal(terminal.clone());
        let observed = IpcConnection::closed(&adapter)
            .await
            .expect("adapter closed");
        assert_transport_reason(&observed, "adapter terminal");
    }

    #[tokio::test]
    async fn adapter_returns_none_agents() {
        let fd_harness = FdHarness::new();
        let connection = TestConnection::new();
        let adapter = ConnectionAdapter::new(connection, fd_harness.server_sender);

        assert!(
            IpcConnection::local_agent(&adapter)
                .await
                .expect("local agent rpc")
                .is_none()
        );
        assert!(
            IpcConnection::remote_agent(&adapter)
                .await
                .expect("remote agent rpc")
                .is_none()
        );
    }

    #[tokio::test]
    async fn handle_manage_stream_maps_success_errors_and_fd_mismatches() {
        let mut fd_harness = FdHarness::new();
        let service = ScriptedIpcConnection::new();
        let (_task, client) = spawn_connection_server(service.clone());
        let handle = client.into_handle(
            fd_harness.client_registry.clone(),
            fd_harness.client_sender.clone(),
        );

        let bidi_id = fd_harness
            .server_sender
            .queue_fds(smallvec![owned_fd(), owned_fd()])
            .expect("queue bidi fds");
        fd_harness.flush().await;
        service
            .open_bi
            .lock()
            .expect("open_bi mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcBiHandle {
                fd_id: bidi_id,
                stream_id: VarInt::from_u32(41),
            })));
        let (reader, writer) = handle.open_bi().await.expect("handle open_bi");
        let mut reader = match reader.into_result() {
            Ok(reader) => reader,
            Err(error) => panic!("expected reader value, got {error:?}"),
        };
        let mut writer = match writer.into_result() {
            Ok(writer) => writer,
            Err(error) => panic!("expected writer value, got {error:?}"),
        };
        assert_eq!(
            reader.stream_id().await.expect("reader stream id"),
            VarInt::from_u32(41)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer stream id"),
            VarInt::from_u32(41)
        );

        let stream_error = StreamError::Reset {
            code: VarInt::from_u32(91),
        };
        service
            .open_bi
            .lock()
            .expect("open_bi mutex should not be poisoned")
            .push_back(Ok(Resolved::err(stream_error.clone())));
        let (reader, writer) = handle.open_bi().await.expect("handle open_bi error");
        match reader {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(91)),
            _ => panic!("expected open_bi reader reset"),
        }
        match writer {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(91)),
            _ => panic!("expected open_bi writer reset"),
        }

        service
            .accept_bi
            .lock()
            .expect("accept_bi mutex should not be poisoned")
            .push_back(Ok(Resolved::err(stream_error.clone())));
        let (reader, writer) = handle.accept_bi().await.expect("handle accept_bi");
        match reader {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(91)),
            _ => panic!("expected accept_bi reader reset"),
        }
        match writer {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(91)),
            _ => panic!("expected accept_bi writer reset"),
        }

        let accept_bi_id = fd_harness
            .server_sender
            .queue_fds(smallvec![owned_fd(), owned_fd()])
            .expect("queue accepted bidi fds");
        fd_harness.flush().await;
        service
            .accept_bi
            .lock()
            .expect("accept_bi mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcBiHandle {
                fd_id: accept_bi_id,
                stream_id: VarInt::from_u32(47),
            })));
        let (reader, writer) = handle.accept_bi().await.expect("handle accept_bi success");
        let mut reader = reader.into_result().expect("accepted reader value");
        let mut writer = writer.into_result().expect("accepted writer value");
        assert_eq!(
            reader.stream_id().await.expect("accepted reader stream id"),
            VarInt::from_u32(47)
        );
        assert_eq!(
            writer.stream_id().await.expect("accepted writer stream id"),
            VarInt::from_u32(47)
        );

        let uni_id = fd_harness
            .server_sender
            .queue_fds(smallvec![owned_fd()])
            .expect("queue uni fd");
        fd_harness.flush().await;
        service
            .open_uni
            .lock()
            .expect("open_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcUniHandle {
                fd_id: uni_id,
                stream_id: VarInt::from_u32(51),
            })));
        let writer = handle.open_uni().await.expect("handle open_uni");
        let mut writer = match writer.into_result() {
            Ok(writer) => writer,
            Err(error) => panic!("expected uni writer value, got {error:?}"),
        };
        assert_eq!(
            writer.stream_id().await.expect("uni writer stream id"),
            VarInt::from_u32(51)
        );

        service
            .accept_uni
            .lock()
            .expect("accept_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::err(stream_error.clone())));
        let reader = handle.accept_uni().await.expect("handle accept_uni");
        match reader {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(91)),
            _ => panic!("expected accept_uni reset"),
        }

        service
            .open_uni
            .lock()
            .expect("open_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::err(stream_error.clone())));
        let writer = handle.open_uni().await.expect("handle open_uni error");
        match writer {
            Resolved::Error {
                error: StreamError::Reset { code },
            } => assert_eq!(code, VarInt::from_u32(91)),
            _ => panic!("expected open_uni reset"),
        }

        let accept_uni_id = fd_harness
            .server_sender
            .queue_fds(smallvec![owned_fd()])
            .expect("queue accepted uni fd");
        fd_harness.flush().await;
        service
            .accept_uni
            .lock()
            .expect("accept_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcUniHandle {
                fd_id: accept_uni_id,
                stream_id: VarInt::from_u32(53),
            })));
        let reader = handle
            .accept_uni()
            .await
            .expect("handle accept_uni success");
        let mut reader = reader.into_result().expect("accepted uni reader value");
        assert_eq!(
            reader.stream_id().await.expect("accepted uni stream id"),
            VarInt::from_u32(53)
        );

        let mut mismatch_harness = FdHarness::new();
        let mismatch_service = ScriptedIpcConnection::new();
        let (_mismatch_task, mismatch_client) = spawn_connection_server(mismatch_service.clone());
        let mismatch_handle = mismatch_client.into_handle(
            mismatch_harness.client_registry.clone(),
            mismatch_harness.client_sender.clone(),
        );

        let wrong_bidi_id = mismatch_harness
            .server_sender
            .queue_fds(smallvec![owned_fd()])
            .expect("queue single fd");
        mismatch_harness.flush().await;
        mismatch_service
            .open_bi
            .lock()
            .expect("open_bi mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcBiHandle {
                fd_id: wrong_bidi_id,
                stream_id: VarInt::from_u32(61),
            })));
        let error = match mismatch_handle.open_bi().await {
            Ok(_) => panic!("wrong bidi fd count should fail"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "expected 2 fds for bidi stream, got 1");

        let mut uni_mismatch_harness = FdHarness::new();
        let uni_mismatch_service = ScriptedIpcConnection::new();
        let (_uni_mismatch_task, uni_mismatch_client) =
            spawn_connection_server(uni_mismatch_service.clone());
        let uni_mismatch_handle = uni_mismatch_client.into_handle(
            uni_mismatch_harness.client_registry.clone(),
            uni_mismatch_harness.client_sender.clone(),
        );

        let wrong_uni_id = uni_mismatch_harness
            .server_sender
            .queue_fds(smallvec![owned_fd(), owned_fd()])
            .expect("queue two fds");
        uni_mismatch_harness.flush().await;
        uni_mismatch_service
            .open_uni
            .lock()
            .expect("open_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcUniHandle {
                fd_id: wrong_uni_id,
                stream_id: VarInt::from_u32(71),
            })));
        let error = match uni_mismatch_handle.open_uni().await {
            Ok(_) => panic!("wrong uni fd count should fail"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "expected 1 fd for uni stream, got 2");

        let mut accept_uni_mismatch_harness = FdHarness::new();
        let accept_uni_mismatch_service = ScriptedIpcConnection::new();
        let (_accept_uni_mismatch_task, accept_uni_mismatch_client) =
            spawn_connection_server(accept_uni_mismatch_service.clone());
        let accept_uni_mismatch_handle = accept_uni_mismatch_client.into_handle(
            accept_uni_mismatch_harness.client_registry.clone(),
            accept_uni_mismatch_harness.client_sender.clone(),
        );

        let wrong_accept_uni_id = accept_uni_mismatch_harness
            .server_sender
            .queue_fds(smallvec![owned_fd(), owned_fd()])
            .expect("queue two accept uni fds");
        accept_uni_mismatch_harness.flush().await;
        accept_uni_mismatch_service
            .accept_uni
            .lock()
            .expect("accept_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcUniHandle {
                fd_id: wrong_accept_uni_id,
                stream_id: VarInt::from_u32(73),
            })));
        let error = match accept_uni_mismatch_handle.accept_uni().await {
            Ok(_) => panic!("wrong accepted uni fd count should fail"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "expected 1 fd for uni stream, got 2");

        let open_error_service = ScriptedIpcConnection::new();
        let (_open_error_task, open_error_client) =
            spawn_connection_server(open_error_service.clone());
        let open_error_handle = open_error_client.into_handle(
            fd_harness.client_registry.clone(),
            fd_harness.client_sender.clone(),
        );

        let wrong_open_error = test_connection_error("scripted open error");
        open_error_service
            .open_bi
            .lock()
            .expect("open_bi mutex should not be poisoned")
            .push_back(Err(IpcOpenError::Connection {
                source: wrong_open_error,
            }));
        let error = match open_error_handle.open_bi().await {
            Ok(_) => panic!("open_bi should fail"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "scripted open error");

        let accept_error_harness = FdHarness::new();
        let accept_error_service = ScriptedIpcConnection::new();
        let (_accept_error_task, accept_error_client) =
            spawn_connection_server(accept_error_service.clone());
        let accept_error_handle = accept_error_client.into_handle(
            accept_error_harness.client_registry,
            accept_error_harness.client_sender,
        );

        let wrong_accept_error = test_connection_error("scripted accept error");
        accept_error_service
            .accept_uni
            .lock()
            .expect("accept_uni mutex should not be poisoned")
            .push_back(Err(IpcAcceptError::Connection {
                source: wrong_accept_error,
            }));
        let error = match accept_error_handle.accept_uni().await {
            Ok(_) => panic!("accept_uni should fail"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "scripted accept error");
    }

    #[tokio::test]
    async fn handle_stream_open_reports_closed_fd_registry() {
        let service = ScriptedIpcConnection::new();
        let (_task, client) = spawn_connection_server(service.clone());
        let fd_harness = FdHarness::new();
        let handle = client.into_handle(
            fd_harness.client_registry.clone(),
            fd_harness.client_sender.clone(),
        );
        drop(fd_harness);
        service
            .open_bi
            .lock()
            .expect("open_bi mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcBiHandle {
                fd_id: VarInt::from_u32(501),
                stream_id: VarInt::from_u32(503),
            })));
        let error = match handle.open_bi().await {
            Ok(_) => panic!("closed fd registry should fail open_bi"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "ipc: wait_fds");

        let service = ScriptedIpcConnection::new();
        let (_task, client) = spawn_connection_server(service.clone());
        let fd_harness = FdHarness::new();
        let handle = client.into_handle(
            fd_harness.client_registry.clone(),
            fd_harness.client_sender.clone(),
        );
        drop(fd_harness);
        service
            .open_uni
            .lock()
            .expect("open_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcUniHandle {
                fd_id: VarInt::from_u32(505),
                stream_id: VarInt::from_u32(507),
            })));
        let error = match handle.open_uni().await {
            Ok(_) => panic!("closed fd registry should fail open_uni"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "ipc: wait_fds");

        let service = ScriptedIpcConnection::new();
        let (_task, client) = spawn_connection_server(service.clone());
        let fd_harness = FdHarness::new();
        let handle = client.into_handle(
            fd_harness.client_registry.clone(),
            fd_harness.client_sender.clone(),
        );
        drop(fd_harness);
        service
            .accept_uni
            .lock()
            .expect("accept_uni mutex should not be poisoned")
            .push_back(Ok(Resolved::ok(IpcUniHandle {
                fd_id: VarInt::from_u32(509),
                stream_id: VarInt::from_u32(511),
            })));
        let error = match handle.accept_uni().await {
            Ok(_) => panic!("closed fd registry should fail accept_uni"),
            Err(error) => error,
        };
        assert_transport_reason(&error, "ipc: wait_fds");
    }

    #[tokio::test]
    async fn handle_agents_and_lifecycle_paths_are_mapped() {
        let fd_harness = FdHarness::new();
        let service = ScriptedIpcConnection::new();
        let (local_agent_task, local_client) = spawn_local_agent(TestLocalAgent("scripted-local"));
        let (remote_agent_task, remote_client) =
            spawn_remote_agent(TestRemoteAgent("scripted-remote"));
        *service
            .local_agent
            .lock()
            .expect("local agent mutex should not be poisoned") = Ok(Some(local_client));
        *service
            .remote_agent
            .lock()
            .expect("remote agent mutex should not be poisoned") = Ok(Some(remote_client));
        *service
            .closed_result
            .lock()
            .expect("closed mutex should not be poisoned") =
            Err(test_connection_error("closed rpc failed"));

        let (_task, client) = spawn_connection_server(service.clone());
        let handle = client.into_handle(fd_harness.client_registry, fd_harness.client_sender);

        quic::Lifecycle::check(&handle).expect("handle should be live");

        let local = quic::WithLocalAgent::local_agent(&handle)
            .await
            .expect("local agent handle")
            .expect("local cached agent");
        assert_eq!(identity::LocalAgent::name(&local), "scripted-local");

        let remote = quic::WithRemoteAgent::remote_agent(&handle)
            .await
            .expect("remote agent handle")
            .expect("remote cached agent");
        assert_eq!(identity::RemoteAgent::name(&remote), "scripted-remote");

        quic::Lifecycle::close(&handle, Code::H3_NO_ERROR, "handle close".into());
        tokio::task::yield_now().await;
        assert_eq!(
            service
                .close_calls
                .lock()
                .expect("close mutex should not be poisoned")
                .clone(),
            vec![(Code::H3_NO_ERROR, Cow::Borrowed("handle close"))]
        );

        let closed = quic::Lifecycle::closed(&handle).await;
        assert_transport_reason(&closed, "ipc connection channel closed");
        let checked = quic::Lifecycle::check(&handle).expect_err("latched error should fail check");
        assert_transport_reason(&checked, "ipc connection channel closed");

        drop(local_agent_task);
        drop(remote_agent_task);
    }

    #[tokio::test]
    async fn handle_returns_none_agents() {
        let fd_harness = FdHarness::new();
        let service = ScriptedIpcConnection::new();
        let (_task, client) = spawn_connection_server(service);
        let handle = client.into_handle(fd_harness.client_registry, fd_harness.client_sender);

        assert!(
            quic::WithLocalAgent::local_agent(&handle)
                .await
                .expect("local agent handle")
                .is_none()
        );
        assert!(
            quic::WithRemoteAgent::remote_agent(&handle)
                .await
                .expect("remote agent handle")
                .is_none()
        );
    }

    #[test]
    fn helper_mappings_preserve_expected_reasons() {
        let plumbing = ipc_io_plumbing(io::Error::other("boom"), "socketpair");
        let conn = plumbing_to_conn(&plumbing);
        assert_transport_reason(&conn, "socketpair: boom");

        let open = map_open_err(IpcOpenError::Plumbing {
            source: plumbing.clone(),
        });
        assert_transport_reason(&open, "socketpair: boom");

        let accept = map_accept_err(IpcAcceptError::Plumbing { source: plumbing });
        assert_transport_reason(&accept, "socketpair: boom");

        let io_error = ipc_io_error(io::Error::other("io failure"), "from_std");
        assert_transport_reason(&io_error, "ipc: from_std");

        let transport = ipc_transport_error(io::Error::other("registry failed"), "wait_fds");
        assert_transport_reason(&transport, "ipc: wait_fds");

        let channel = IpcConnectionHandle::ipc_channel_error();
        assert_transport_reason(&channel, "ipc connection channel closed");
    }
}
