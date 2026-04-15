//! Connection-level capability adapters for IPC.
//!
//! # Server side
//!
//! [`ConnectionAdapter`] wraps a `quic::Connection` and implements
//! [`IpcConnection`].  Each `open_bi` / `accept_bi` call:
//! 1. Opens a real QUIC stream pair via the inner connection.
//! 2. Creates 2 Unix socketpairs (one per direction).
//! 3. Queues the client-side FDs through the [`FdSender`].
//! 4. Spawns bridge tasks that forward data between the real QUIC
//!    streams and local [`PipeWriter`] / [`PipeReader`] endpoints.
//! 5. Returns `(fd_registry_id, stream_id)` over RPC.
//!
//! # Client side
//!
//! [`IpcConnectionHandle`] wraps an [`IpcConnectionClient`] and implements
//! [`quic::Connection`].  Each `open_bi` call:
//! 1. Calls the RPC method to get `(fd_registry_id, stream_id)`.
//! 2. Retrieves the socketpair FDs from the [`FdRegistry`].
//! 3. Wraps them as [`PipeReader`] / [`PipeWriter`].
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
use tokio::net::UnixStream;
use tracing::{Instrument, warn};

use crate::{
    error::Code,
    ipc::{
        pipe::{PipeReader, PipeWriter},
        rpc::connection::{IpcConnection, IpcConnectionClient},
        transport::{FdRegistry, FdSender},
    },
    quic::{
        self, ConnectionError, DynLifecycle, GetStreamIdExt, ManageStream, ReadStream, StreamError,
        WriteStream,
    },
    rpc::quic::{
        CachedLocalAgent, CachedRemoteAgent, LocalAgentClient, LocalAgentServerShared,
        RemoteAgentClient, RemoteAgentServerShared,
    },
    util::set_once::SetOnce,
    varint::VarInt,
};

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

/// Forward data from a QUIC [`ReadStream`] to a [`PipeWriter`] (server side).
///
/// Reads chunks from the QUIC stream and sinks them into the pipe.
/// Terminates when either side closes or errors.
pub async fn bridge_reader(mut quic_reader: impl ReadStream + Unpin, mut pipe_writer: PipeWriter) {
    loop {
        match quic_reader.next().await {
            Some(Ok(chunk)) => {
                if pipe_writer.send(chunk).await.is_err() {
                    break;
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    let _ = pipe_writer.close().await;
}

/// Forward data from a [`PipeReader`] to a QUIC [`WriteStream`] (server side).
///
/// Reads chunks from the pipe and sinks them into the QUIC stream.
/// Terminates when either side closes or errors.
pub async fn bridge_writer(mut pipe_reader: PipeReader, mut quic_writer: impl WriteStream + Unpin) {
    loop {
        match pipe_reader.next().await {
            Some(Ok(chunk)) => {
                if quic_writer.send(chunk).await.is_err() {
                    break;
                }
            }
            Some(Err(_)) | None => break,
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
    async fn open_bi(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        self.open_bi_impl().await
    }

    async fn accept_bi(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        self.accept_bi_impl().await
    }

    async fn open_uni(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        self.open_uni_impl().await
    }

    async fn accept_uni(&self) -> Result<(VarInt, VarInt), ConnectionError> {
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
    async fn open_bi_impl(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        let (mut reader, writer) = ManageStream::open_bi(self.inner.as_ref()).await?;
        let stream_id = reader.stream_id().await.map_err(stream_error_to_conn)?;
        self.bridge_bi(reader, writer, stream_id)
    }

    async fn accept_bi_impl(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        let (mut reader, writer) = ManageStream::accept_bi(self.inner.as_ref()).await?;
        let stream_id = reader.stream_id().await.map_err(stream_error_to_conn)?;
        self.bridge_bi(reader, writer, stream_id)
    }

    /// Shared logic for open_bi / accept_bi after obtaining the real streams.
    fn bridge_bi(
        &self,
        reader: M::StreamReader,
        writer: M::StreamWriter,
        stream_id: VarInt,
    ) -> Result<(VarInt, VarInt), ConnectionError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        // Socketpair for the reader direction: server PipeWriter ↔ client PipeReader
        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_io_error(e, "socketpair"))?;
        // Socketpair for the writer direction: server PipeReader ↔ client PipeWriter
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_io_error(e, "socketpair"))?;

        let cli_a_std = cli_a.into_std().map_err(|e| ipc_io_error(e, "into_std"))?;
        let cli_b_std = cli_b.into_std().map_err(|e| ipc_io_error(e, "into_std"))?;

        let fd_id = self
            .fd_sender
            .queue_fds(vec![cli_a_std.into(), cli_b_std.into()])
            .map_err(|e| ipc_transport_error(e, "queue_fds"))?;

        // Bridge reader direction: real QUIC reader → PipeWriter on srv_a
        let (srv_a_read, srv_a_write) = srv_a.into_split();
        let pipe_w = PipeWriter::new(stream_id, srv_a_read, srv_a_write, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        // Bridge writer direction: PipeReader on srv_b → real QUIC writer
        let (srv_b_read, srv_b_write) = srv_b.into_split();
        let pipe_r = PipeReader::new(stream_id, srv_b_read, srv_b_write, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok((fd_id, stream_id))
    }

    async fn open_uni_impl(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        let mut writer = ManageStream::open_uni(self.inner.as_ref()).await?;
        let stream_id = writer.stream_id().await.map_err(stream_error_to_conn)?;
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_error(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_error(e, "into_std"))?;
        let fd_id = self
            .fd_sender
            .queue_fds(vec![cli_std.into()])
            .map_err(|e| ipc_transport_error(e, "queue_fds"))?;

        // PipeReader on srv → real QUIC writer
        let (srv_read, srv_write) = srv.into_split();
        let pipe_r = PipeReader::new(stream_id, srv_read, srv_write, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok((fd_id, stream_id))
    }

    async fn accept_uni_impl(&self) -> Result<(VarInt, VarInt), ConnectionError> {
        let mut reader = ManageStream::accept_uni(self.inner.as_ref()).await?;
        let stream_id = reader.stream_id().await.map_err(stream_error_to_conn)?;
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_error(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_error(e, "into_std"))?;
        let fd_id = self
            .fd_sender
            .queue_fds(vec![cli_std.into()])
            .map_err(|e| ipc_transport_error(e, "queue_fds"))?;

        // Real QUIC reader → PipeWriter on srv
        let (srv_read, srv_write) = srv.into_split();
        let pipe_w = PipeWriter::new(stream_id, srv_read, srv_write, lifecycle);
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        Ok((fd_id, stream_id))
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
/// Caches the first observed terminal error and delegates close/closed to
/// the IPC RPC.
struct IpcLifecycle {
    rpc: IpcConnectionClient,
    terminal_error: SetOnce<ConnectionError>,
}

impl IpcConnectionHandle {
    /// Create a new handle from bootstrap data and FD registry.
    pub fn new(
        rpc: IpcConnectionClient,
        fd_registry: FdRegistry,
        conn_fd_sender: FdSender,
    ) -> Self {
        let lifecycle = Arc::new(IpcLifecycle {
            rpc: rpc.clone(),
            terminal_error: SetOnce::new(),
        });
        Self {
            rpc,
            fd_registry,
            _conn_fd_sender: conn_fd_sender,
            lifecycle,
        }
    }

    /// Record a connection error and return it.
    fn latch_error(&self, error: ConnectionError) -> ConnectionError {
        let _ = self.lifecycle.terminal_error.set(error.clone());
        error
    }

    /// Synthesize a transport error for IPC channel failures.
    fn ipc_channel_error() -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: IPC_CHANNEL_ERROR_KIND,
                frame_type: IPC_FRAME_TYPE,
                reason: "IPC connection channel closed".into(),
            },
        }
    }
}

impl quic::ManageStream for IpcConnectionHandle {
    type StreamReader = PipeReader;
    type StreamWriter = PipeWriter;

    async fn open_bi(&self) -> Result<(PipeReader, PipeWriter), ConnectionError> {
        let (fd_id, stream_id) = IpcConnection::open_bi(&self.rpc)
            .await
            .map_err(|e| self.latch_error(e))?;
        self.fds_to_bi(fd_id, stream_id).await
    }

    async fn accept_bi(&self) -> Result<(PipeReader, PipeWriter), ConnectionError> {
        let (fd_id, stream_id) = IpcConnection::accept_bi(&self.rpc)
            .await
            .map_err(|e| self.latch_error(e))?;
        self.fds_to_bi(fd_id, stream_id).await
    }

    async fn open_uni(&self) -> Result<PipeWriter, ConnectionError> {
        let (fd_id, stream_id) = IpcConnection::open_uni(&self.rpc)
            .await
            .map_err(|e| self.latch_error(e))?;
        self.fds_to_uni_writer(fd_id, stream_id).await
    }

    async fn accept_uni(&self) -> Result<PipeReader, ConnectionError> {
        let (fd_id, stream_id) = IpcConnection::accept_uni(&self.rpc)
            .await
            .map_err(|e| self.latch_error(e))?;
        self.fds_to_uni_reader(fd_id, stream_id).await
    }
}

impl IpcConnectionHandle {
    /// Retrieve 2 FDs and construct a (PipeReader, PipeWriter) pair.
    async fn fds_to_bi(
        &self,
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<(PipeReader, PipeWriter), ConnectionError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_error(ipc_transport_error(e, "wait_fds")))?;
        if fds.len() != 2 {
            return Err(self.latch_error(ipc_transport_error(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected 2 FDs for bidi stream, got {}", fds.len()),
                ),
                "fd count",
            )));
        }
        let mut fds = fds.into_iter();
        let fd_a = fds.next().unwrap();
        let fd_b = fds.next().unwrap();

        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

        // fd_a → reader pipe (matches server's PipeWriter on srv_a)
        let sock_a = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_a))
            .map_err(|e| self.latch_error(ipc_io_error(e, "UnixStream::from_std")))?;
        let (a_read, a_write) = sock_a.into_split();
        let reader = PipeReader::new(stream_id, a_read, a_write, lifecycle.clone());

        // fd_b → writer pipe (matches server's PipeReader on srv_b)
        let sock_b = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_b))
            .map_err(|e| self.latch_error(ipc_io_error(e, "UnixStream::from_std")))?;
        let (b_read, b_write) = sock_b.into_split();
        let writer = PipeWriter::new(stream_id, b_read, b_write, lifecycle);

        Ok((reader, writer))
    }

    /// Retrieve 1 FD and construct a PipeWriter (for open_uni).
    async fn fds_to_uni_writer(
        &self,
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<PipeWriter, ConnectionError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_error(ipc_transport_error(e, "wait_fds")))?;
        if fds.len() != 1 {
            return Err(self.latch_error(ipc_transport_error(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected 1 FD for uni stream, got {}", fds.len()),
                ),
                "fd count",
            )));
        }
        let fd = fds.into_iter().next().unwrap();
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
        let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
            .map_err(|e| self.latch_error(ipc_io_error(e, "UnixStream::from_std")))?;
        let (read, write) = sock.into_split();
        Ok(PipeWriter::new(stream_id, read, write, lifecycle))
    }

    /// Retrieve 1 FD and construct a PipeReader (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        fd_id: VarInt,
        stream_id: VarInt,
    ) -> Result<PipeReader, ConnectionError> {
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .map_err(|e| self.latch_error(ipc_transport_error(e, "wait_fds")))?;
        if fds.len() != 1 {
            return Err(self.latch_error(ipc_transport_error(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected 1 FD for uni stream, got {}", fds.len()),
                ),
                "fd count",
            )));
        }
        let fd = fds.into_iter().next().unwrap();
        let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
        let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
            .map_err(|e| self.latch_error(ipc_io_error(e, "UnixStream::from_std")))?;
        let (read, write) = sock.into_split();
        Ok(PipeReader::new(stream_id, read, write, lifecycle))
    }
}

impl quic::WithLocalAgent for IpcConnectionHandle {
    type LocalAgent = CachedLocalAgent;

    async fn local_agent(&self) -> Result<Option<CachedLocalAgent>, ConnectionError> {
        match IpcConnection::local_agent(&self.rpc)
            .await
            .map_err(|e| self.latch_error(e))?
        {
            Some(client) => Ok(Some(
                CachedLocalAgent::from_client(client)
                    .await
                    .map_err(|e| self.latch_error(e))?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::WithRemoteAgent for IpcConnectionHandle {
    type RemoteAgent = CachedRemoteAgent;

    async fn remote_agent(&self) -> Result<Option<CachedRemoteAgent>, ConnectionError> {
        match IpcConnection::remote_agent(&self.rpc)
            .await
            .map_err(|e| self.latch_error(e))?
        {
            Some(client) => Ok(Some(
                CachedRemoteAgent::from_client(client)
                    .await
                    .map_err(|e| self.latch_error(e))?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::Lifecycle for IpcConnectionHandle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let rpc = self.rpc.clone();
        tokio::spawn(
            async move {
                let _ = IpcConnection::close(&rpc, code, reason).await;
            }
            .in_current_span(),
        );
    }

    fn check(&self) -> Result<(), ConnectionError> {
        if let Some(error) = self.lifecycle.terminal_error.peek() {
            return Err(error);
        }
        Ok(())
    }

    async fn closed(&self) -> ConnectionError {
        if let Some(error) = self.lifecycle.terminal_error.peek() {
            return error;
        }

        let error = match IpcConnection::closed(&self.rpc).await {
            Ok(error) => error,
            Err(_) => Self::ipc_channel_error(),
        };
        let _ = self.lifecycle.terminal_error.set(error.clone());
        error
    }
}

// Also implement Lifecycle for the shared inner, so it can be used as
// Arc<dyn DynLifecycle> by PipeReader/PipeWriter on the client side.
impl quic::Lifecycle for IpcLifecycle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let rpc = self.rpc.clone();
        tokio::spawn(
            async move {
                let _ = IpcConnection::close(&rpc, code, reason).await;
            }
            .in_current_span(),
        );
    }

    fn check(&self) -> Result<(), ConnectionError> {
        if let Some(error) = self.terminal_error.peek() {
            return Err(error);
        }
        Ok(())
    }

    async fn closed(&self) -> ConnectionError {
        if let Some(error) = self.terminal_error.peek() {
            return error;
        }
        let error = match IpcConnection::closed(&self.rpc).await {
            Ok(error) => error,
            Err(_) => IpcConnectionHandle::ipc_channel_error(),
        };
        let _ = self.terminal_error.set(error.clone());
        error
    }
}

// ---------------------------------------------------------------------------
// Error constants & helpers
// ---------------------------------------------------------------------------

/// Error kind for general IPC transport failures.
pub(super) const IPC_ERROR_KIND: VarInt = VarInt::from_u32(0x0a);

/// Error kind for IPC channel closure.
const IPC_CHANNEL_ERROR_KIND: VarInt = VarInt::from_u32(0x01);

/// Frame type placeholder for IPC-synthesized transport errors.
pub(super) const IPC_FRAME_TYPE: VarInt = VarInt::from_u32(0x00);

fn ipc_io_error(err: io::Error, context: &str) -> ConnectionError {
    warn!(%err, context, "IPC I/O error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("IPC {context}: {err}").into(),
        },
    }
}

fn ipc_transport_error(err: impl std::fmt::Display, context: &str) -> ConnectionError {
    warn!(%err, context, "IPC transport error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("IPC {context}: {err}").into(),
        },
    }
}

/// Convert a [`StreamError`] to a [`ConnectionError`].
///
/// If the stream error wraps a connection error, extract it directly;
/// otherwise synthesize a transport error.
fn stream_error_to_conn(err: StreamError) -> ConnectionError {
    match err {
        StreamError::Connection { source } => source,
        StreamError::Reset { code } => ConnectionError::Transport {
            source: quic::TransportError {
                kind: IPC_ERROR_KIND,
                frame_type: IPC_FRAME_TYPE,
                reason: format!("stream reset during IPC setup: {code}").into(),
            },
        },
    }
}
