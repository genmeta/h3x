//! Listener-level IPC adapters and RTC trait.
//!
//! # RTC trait
//!
//! [`IpcListen`] defines the RPC interface for accepting incoming connections.
//! The server side calls [`quic::Listen::accept`], creates a new
//! [`MuxChannel`] pair, queues the remote end's FD, and returns the
//! [`VarInt`] registry ID.
//!
//! # Server side
//!
//! [`ListenAdapter`] wraps a real `quic::Listen` and implements
//! [`IpcListen`].  Each `accept()` call:
//! 1. Accepts a new connection from the inner listener.
//! 2. Creates a [`MuxChannel`] pair (one for the server, one FD for the client).
//! 3. Queues the client FD through the parent [`FdSender`].
//! 4. Splits the server-side MuxChannel, establishes a remoc connection.
//! 5. Creates a [`ConnectionAdapter`] and RTC server for the new connection.
//! 6. Sends a [`ConnectionBootstrap`] over the remoc base channel.
//! 7. Returns the FD-registry ID.
//!
//! # Client side
//!
//! [`IpcListener`] wraps an [`IpcListenClient`] and the parent-level
//! [`FdRegistry`], implementing [`quic::Listen`].  Each `accept()` call:
//! 1. Calls the RPC `accept()` to get a FD-registry ID.
//! 2. Retrieves the client FD from the parent [`FdRegistry`].
//! 3. Reconstructs a [`MuxChannel`], establishes a remoc connection.
//! 4. Receives the [`ConnectionBootstrap`] from the base channel.
//! 5. Returns an [`IpcConnectionHandle`].

use std::sync::Arc;

use remoc::prelude::ServerShared;
use smallvec::smallvec;
use snafu::{ResultExt, Snafu};
use tracing::{Instrument, warn};

use super::connection::{
    ConnectionAdapter, ConnectionBootstrap, IPC_ERROR_KIND, IPC_FRAME_TYPE, IpcConnectionHandle,
    IpcConnectionServerShared,
};
use crate::{
    ipc::transport::{FdRegistry, FdSender, MuxChannel},
    quic::{self, ConnectionError},
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// IPC RTC trait for listener capability
// ---------------------------------------------------------------------------

/// Remote trait for IPC listener capability.
///
/// Each successful [`accept`](IpcListen::accept) returns a [`VarInt`] ID that
/// the caller can pass to
/// [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds) to
/// obtain the [`MuxChannel`](crate::ipc::transport::MuxChannel) FD for the
/// new connection.
#[remoc::rtc::remote]
pub trait IpcListen: Send + Sync {
    /// Accept an incoming connection.
    ///
    /// Returns the FD-registry ID for the new connection's MuxChannel.
    async fn accept(&mut self) -> Result<VarInt, ConnectionError>;

    /// Gracefully shut down the listener.
    async fn shutdown(&self) -> Result<(), ConnectionError>;
}

/// Construct a [`ConnectionError::Transport`] with a formatted reason.
fn ipc_listen_error(err: impl std::error::Error, context: &str) -> ConnectionError {
    warn!(error = %snafu::Report::from_error(&err), context, "ipc listener error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc listen: {context}").into(),
        },
    }
}

// ---------------------------------------------------------------------------
// Server side: ListenAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter wrapping a real `quic::Listen` and implementing
/// [`IpcListen`].
///
/// The `Codec` type parameter determines the remoc serialization codec used
/// for the per-connection remoc channel.  h3x deliberately does not choose a
/// codec; the downstream crate (e.g., gateway) picks one.
pub struct ListenAdapter<L, Codec> {
    inner: L,
    fd_sender: FdSender,
    _codec: std::marker::PhantomData<Codec>,
}

impl<L, Codec> ListenAdapter<L, Codec> {
    pub fn new(inner: L, fd_sender: FdSender) -> Self {
        Self {
            inner,
            fd_sender,
            _codec: std::marker::PhantomData,
        }
    }
}

impl<L, Codec> IpcListen for ListenAdapter<L, Codec>
where
    L: quic::Listen + 'static,
    Codec: remoc::codec::Codec,
{
    async fn accept(&mut self) -> Result<VarInt, ConnectionError> {
        let connection = quic::Listen::accept(&mut self.inner)
            .await
            .map_err(|e| ipc_listen_error(e, "accept"))?;
        let connection = Arc::new(connection);

        // Create a MuxChannel pair for this connection
        let (server_mux, client_fd) =
            MuxChannel::create_pair().map_err(|e| ipc_listen_error(e, "create mux pair"))?;

        // Queue the client FD through the parent-level FdSender
        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![client_fd])
            .map_err(|e| ipc_listen_error(e, "queue fd"))?;

        // Split the server MuxChannel — the remoc handshake + bootstrap are
        // spawned as a background task so we can return fd_id immediately.
        // The client needs fd_id to retrieve the FD and start its handshake;
        // blocking here would deadlock.
        let (sink, stream) = server_mux
            .split()
            .map_err(|e| ipc_listen_error(e, "split mux"))?;

        // Inherent termination: exits when remoc handshake completes or fails.
        tokio::spawn(Self::setup_connection(connection, sink, stream).in_current_span());

        Ok(fd_id)
    }

    async fn shutdown(&self) -> Result<(), ConnectionError> {
        quic::Listen::shutdown(&self.inner)
            .await
            .map_err(|e| ipc_listen_error(e, "shutdown"))
    }
}

impl<L, Codec> ListenAdapter<L, Codec>
where
    L: quic::Listen + 'static,
    Codec: remoc::codec::Codec,
{
    /// Perform the per-connection remoc handshake and bootstrap in the
    /// background.
    ///
    /// This runs as a spawned task so that [`IpcListen::accept`] can return
    /// the FD-registry ID immediately — the client needs the ID to retrieve
    /// its end of the [`MuxChannel`] and start the handshake.  If we awaited
    /// the handshake inline, the RPC response would never be sent and the
    /// client could never connect, causing a deadlock.
    async fn setup_connection(
        connection: Arc<L::Connection>,
        sink: crate::ipc::transport::MuxSink,
        stream: crate::ipc::transport::MuxStream,
    ) {
        let conn_fd_sender = sink.fd_sender();

        let (remoc_conn, mut tx, _rx) = match remoc::Connect::framed::<
            _,
            _,
            ConnectionBootstrap,
            (),
            Codec,
        >(remoc::Cfg::default(), sink, stream)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %snafu::Report::from_error(e), "per-connection remoc handshake failed");
                return;
            }
        };
        // Inherent termination: exits when remoc ChMux closes.
        tokio::spawn(remoc_conn.in_current_span());

        // Create the ConnectionAdapter for this connection's stream management
        let adapter = ConnectionAdapter::new(connection, conn_fd_sender);
        let (server, rpc_client) = IpcConnectionServerShared::new(Arc::new(adapter), 64);
        // Inherent termination: exits when remoc ChMux closes.
        tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        );

        // Send the bootstrap data over the remoc base channel
        let bootstrap = ConnectionBootstrap {
            connection: rpc_client,
        };
        if tx.send(bootstrap).await.is_err() {
            warn!("failed to send connection bootstrap: base channel closed");
        }
    }
}

// ---------------------------------------------------------------------------
// Client side: IpcListener
// ---------------------------------------------------------------------------

/// Client-side listener handle that wraps an [`IpcListenClient`] and
/// implements [`quic::Listen`].
///
/// Created by the process that receives listener capability over IPC.
/// The `Codec` parameter must match the server-side [`ListenAdapter`]'s codec.
pub struct IpcListener<Codec> {
    rpc: IpcListenClient,
    fd_registry: FdRegistry,
    _codec: std::marker::PhantomData<Codec>,
}

/// Error from [`IpcListener`] operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum IpcListenError {
    #[snafu(display("ipc accept rpc failed"))]
    Rpc { source: ConnectionError },
    #[snafu(display("failed to retrieve connection fd"))]
    WaitFd {
        source: crate::ipc::transport::WaitFdsError,
    },
    #[snafu(display("no fd received from registry"))]
    EmptyFd,
    #[snafu(display("failed to reconstruct mux channel"))]
    FromFd { source: std::io::Error },
    #[snafu(display("failed to split client mux channel"))]
    ClientSplit {
        source: crate::ipc::transport::SplitError,
    },
    #[snafu(display("failed to establish client remoc connection: {message}"))]
    ClientRemocConnect { message: String },
    #[snafu(display("failed to receive bootstrap: {message}"))]
    ReceiveBootstrap { message: String },
}

impl From<IpcListenError> for ConnectionError {
    fn from(err: IpcListenError) -> Self {
        ConnectionError::Transport {
            source: quic::TransportError {
                kind: IPC_ERROR_KIND,
                frame_type: IPC_FRAME_TYPE,
                reason: snafu::Report::from_error(err).to_string().into(),
            },
        }
    }
}

impl<Codec> IpcListener<Codec> {
    pub fn new(rpc: IpcListenClient, fd_registry: FdRegistry) -> Self {
        Self {
            rpc,
            fd_registry,
            _codec: std::marker::PhantomData,
        }
    }
}

impl<Codec> quic::Listen for IpcListener<Codec>
where
    Codec: remoc::codec::Codec,
{
    type Connection = IpcConnectionHandle;
    type Error = IpcListenError;

    async fn accept(&mut self) -> Result<IpcConnectionHandle, IpcListenError> {
        // 1. RPC: ask server to accept a new connection
        let fd_id = IpcListen::accept(&mut self.rpc).await.context(RpcSnafu)?;

        // 2. Retrieve the MuxChannel FD from the parent-level FdRegistry
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .context(WaitFdSnafu)?;
        let fd = fds.into_iter().next().ok_or(IpcListenError::EmptyFd)?;

        // 3. Reconstruct MuxChannel and establish remoc connection
        let mux = MuxChannel::from_fd(fd).context(FromFdSnafu)?;
        let (sink, stream) = mux.split().context(ClientSplitSnafu)?;
        let conn_fd_sender = sink.fd_sender();
        let conn_fd_registry = stream.fd_registry();

        let (remoc_conn, _tx, mut rx) =
            remoc::Connect::framed::<_, _, (), ConnectionBootstrap, Codec>(
                remoc::Cfg::default(),
                sink,
                stream,
            )
            .await
            .map_err(|e| IpcListenError::ClientRemocConnect {
                message: e.to_string(),
            })?;
        tokio::spawn(remoc_conn.in_current_span());

        // 4. Receive the ConnectionBootstrap from the server
        let bootstrap = rx
            .recv()
            .await
            .map_err(|e| IpcListenError::ReceiveBootstrap {
                message: e.to_string(),
            })?
            .ok_or_else(|| IpcListenError::ReceiveBootstrap {
                message: "base channel closed before bootstrap received".into(),
            })?;

        // 5. Wrap as IpcConnectionHandle
        Ok(IpcConnectionHandle::new(
            bootstrap.connection,
            conn_fd_registry,
            conn_fd_sender,
        ))
    }

    async fn shutdown(&self) -> Result<(), IpcListenError> {
        IpcListen::shutdown(&self.rpc).await.context(RpcSnafu)
    }
}
