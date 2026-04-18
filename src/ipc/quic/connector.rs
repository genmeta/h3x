//! Connector-level IPC adapters and RTC trait.
//!
//! # RTC trait
//!
//! [`IpcConnect`] defines the RPC interface for initiating outgoing connections.
//! The server side calls [`quic::Connect::connect`], creates a new
//! [`MuxChannel`] pair, queues the remote end's FD, and returns the
//! [`VarInt`] registry ID.
//!
//! # Server side
//!
//! [`ConnectAdapter`] wraps a `quic::Connect` and implements [`IpcConnect`].
//! Each `connect` call:
//! 1. Calls the inner connector to establish a real QUIC connection.
//! 2. Creates a [`MuxChannel`] pair (one for the server, one FD for the client).
//! 3. Queues the client-side FD through the parent-level [`FdSender`].
//! 4. Splits the server-side MuxChannel, establishes a remoc connection.
//! 5. Creates a [`ConnectionAdapter`] for the real connection, wraps it in
//!    an [`IpcConnectionServerShared`], spawns the RPC server.
//! 6. Sends a [`ConnectionBootstrap`] over the remoc base channel.
//! 7. Returns the FD-registry ID.
//!
//! # Client side
//!
//! [`IpcConnector`] wraps an [`IpcConnectClient`] and implements
//! [`quic::Connect`].  Each `connect` call:
//! 1. Calls the RPC method to get a FD-registry ID.
//! 2. Retrieves the MuxChannel FD from the [`FdRegistry`].
//! 3. Splits the MuxChannel, establishes a remoc connection.
//! 4. Receives the [`ConnectionBootstrap`] from the base channel.
//! 5. Wraps the result as an [`IpcConnectionHandle`].

use std::sync::Arc;

use http::uri::Authority;
use remoc::{self, RemoteSend, prelude::ServerShared};
use smallvec::smallvec;
use snafu::{ResultExt, Snafu};
use tracing::Instrument;

use super::connection::{
    ConnectionAdapter, ConnectionBootstrap, IPC_ERROR_KIND, IPC_FRAME_TYPE, IpcConnectionHandle,
    IpcConnectionServerShared,
};
use crate::{
    ipc::transport::{FdRegistry, FdSender, MuxChannel, SplitError},
    quic::{self, ConnectionError},
    rpc::quic::serde_types::SerdeAuthority,
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// IPC RTC trait for connector capability
// ---------------------------------------------------------------------------

/// Remote trait for IPC connector capability.
///
/// Each successful [`connect`](IpcConnect::connect) returns a [`VarInt`] ID
/// that the caller can pass to
/// [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds) to
/// obtain the [`MuxChannel`](crate::ipc::transport::MuxChannel) FD for the
/// new connection.
#[remoc::rtc::remote]
pub trait IpcConnect: Send + Sync {
    /// Connect to a remote server.
    ///
    /// Returns the FD-registry ID for the new connection's MuxChannel.
    async fn connect(&self, server: SerdeAuthority) -> Result<VarInt, ConnectionError>;
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error from [`IpcConnector::connect`].
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ConnectorError {
    #[snafu(display("ipc connect rpc failed"))]
    Rpc { source: ConnectionError },
    #[snafu(display("failed to retrieve mux channel fd"))]
    WaitFds {
        source: crate::ipc::transport::WaitFdsError,
    },
    #[snafu(display("no fd received from registry"))]
    EmptyFd,
    #[snafu(display("failed to reconstruct mux channel from fd"))]
    FromFd { source: std::io::Error },
    #[snafu(display("failed to split mux channel"))]
    Split { source: SplitError },
    #[snafu(display("failed to establish remoc connection: {message}"))]
    Remoc { message: String },
    #[snafu(display("failed to receive connection bootstrap"))]
    Bootstrap,
}

// ---------------------------------------------------------------------------
// Server side: ConnectAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter that wraps a `quic::Connect` and implements
/// [`IpcConnect`].
///
/// `Codec` is the remoc serialization codec used for the per-connection
/// MuxChannel remoc link.  It must match the codec used by the client-side
/// [`IpcConnector`].
pub struct ConnectAdapter<C, Codec> {
    inner: C,
    fd_sender: FdSender,
    _codec: std::marker::PhantomData<Codec>,
}

impl<C, Codec> ConnectAdapter<C, Codec> {
    pub fn new(inner: C, fd_sender: FdSender) -> Self {
        Self {
            inner,
            fd_sender,
            _codec: std::marker::PhantomData,
        }
    }
}

impl<C, Codec> IpcConnect for ConnectAdapter<C, Codec>
where
    C: quic::Connect + 'static,
    C::Connection: 'static,
    <C::Connection as quic::ManageStream>::StreamReader: Unpin + 'static,
    <C::Connection as quic::ManageStream>::StreamWriter: Unpin + 'static,
    Codec: remoc::codec::Codec,
    ConnectionBootstrap: RemoteSend,
{
    async fn connect(&self, server: SerdeAuthority) -> Result<VarInt, ConnectionError> {
        let authority = Authority::try_from(server).map_err(|e| connect_error(e, "authority"))?;
        let connection = quic::Connect::connect(&self.inner, &authority)
            .await
            .map_err(|e| connect_error(e, "connect"))?;

        // Create a MuxChannel pair for this connection.
        let (server_mux, client_fd) =
            MuxChannel::create_pair().map_err(|e| connect_error(e, "create_pair"))?;

        // Queue the client-side FD on the parent-level FdSender.
        let fd_id = self
            .fd_sender
            .queue_fds(smallvec![client_fd])
            .map_err(|e| connect_error(e, "queue_fds"))?;

        // Split the server-side MuxChannel — the remoc handshake + bootstrap
        // are spawned as a background task so we can return fd_id immediately.
        // The client needs fd_id to retrieve the FD and start its handshake;
        // blocking here would deadlock.
        let (sink, stream) = server_mux.split().map_err(|e| connect_error(e, "split"))?;

        // Inherent termination: exits when remoc handshake completes or fails.
        tokio::spawn(Self::setup_connection(connection, sink, stream).in_current_span());

        Ok(fd_id)
    }
}

impl<C, Codec> ConnectAdapter<C, Codec>
where
    C: quic::Connect + 'static,
    C::Connection: 'static,
    <C::Connection as quic::ManageStream>::StreamReader: Unpin + 'static,
    <C::Connection as quic::ManageStream>::StreamWriter: Unpin + 'static,
    Codec: remoc::codec::Codec,
    ConnectionBootstrap: RemoteSend,
{
    /// Perform the per-connection remoc handshake and bootstrap in the
    /// background.
    ///
    /// See [`ListenAdapter::setup_connection`] for the rationale.
    async fn setup_connection(
        connection: Arc<C::Connection>,
        sink: crate::ipc::transport::MuxSink,
        stream: crate::ipc::transport::MuxStream,
    ) {
        use tracing::debug;

        let conn_fd_sender = sink.fd_sender();

        let (conn, mut tx, _rx) =
            match remoc::Connect::framed::<_, _, ConnectionBootstrap, (), Codec>(
                remoc::Cfg::default(),
                sink,
                stream,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    debug!(
                        error = %snafu::Report::from_error(e),
                        "per-connection remoc handshake failed"
                    );
                    return;
                }
            };
        // Inherent termination: exits when remoc ChMux closes.
        tokio::spawn(conn.in_current_span());

        // Create the ConnectionAdapter and wrap it as an IPC RPC server.
        let adapter = ConnectionAdapter::new(connection, conn_fd_sender);
        let (server, rpc_client) = IpcConnectionServerShared::new(Arc::new(adapter), 64);
        // Inherent termination: exits when remoc ChMux closes.
        tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        );

        let bootstrap = ConnectionBootstrap {
            connection: rpc_client,
        };

        if tx.send(bootstrap).await.is_err() {
            debug!("failed to send connection bootstrap: base channel closed");
        }
    }
}

// ---------------------------------------------------------------------------
// Client side: IpcConnector
// ---------------------------------------------------------------------------

/// Client-side connector that wraps an [`IpcConnectClient`] and implements
/// [`quic::Connect`].
///
/// Created by receiving an `IpcConnectClient` from the parent-level remoc
/// connection (e.g. via `ControlPlane` RPC).
pub struct IpcConnector<Codec> {
    rpc: IpcConnectClient,
    fd_registry: FdRegistry,
    _codec: std::marker::PhantomData<Codec>,
}

impl<Codec> IpcConnector<Codec> {
    pub fn new(rpc: IpcConnectClient, fd_registry: FdRegistry) -> Self {
        Self {
            rpc,
            fd_registry,
            _codec: std::marker::PhantomData,
        }
    }
}

impl<Codec> quic::Connect for IpcConnector<Codec>
where
    Codec: remoc::codec::Codec,
    ConnectionBootstrap: RemoteSend,
{
    type Connection = IpcConnectionHandle;
    type Error = ConnectorError;

    async fn connect<'a>(
        &'a self,
        server: &'a Authority,
    ) -> Result<Arc<IpcConnectionHandle>, ConnectorError> {
        // 1. RPC: ask the server side to connect and get the fd-registry ID.
        let fd_id = IpcConnect::connect(&self.rpc, SerdeAuthority::from(server))
            .await
            .context(RpcSnafu)?;

        // 2. Retrieve the MuxChannel FD.
        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .context(WaitFdsSnafu)?;
        let fd = fds.into_iter().next().ok_or(ConnectorError::EmptyFd)?;

        // 3. Reconstruct the MuxChannel and split it.
        let mux = MuxChannel::from_fd(fd).context(FromFdSnafu)?;
        let (sink, stream) = mux.split().context(SplitSnafu)?;
        let conn_fd_sender = sink.fd_sender();
        let conn_fd_registry = stream.fd_registry();

        // 4. Establish a remoc connection on the MuxChannel.
        let (conn, _tx, mut rx) = remoc::Connect::framed::<_, _, (), ConnectionBootstrap, Codec>(
            remoc::Cfg::default(),
            sink,
            stream,
        )
        .await
        .map_err(|e| ConnectorError::Remoc {
            message: e.to_string(),
        })?;
        tokio::spawn(conn.in_current_span());

        // 5. Receive the ConnectionBootstrap from the server.
        let bootstrap = rx
            .recv()
            .await
            .map_err(|_| ConnectorError::Bootstrap)?
            .ok_or(ConnectorError::Bootstrap)?;

        // The conn_fd_sender is retained in IpcConnectionHandle for potential
        // future use (e.g. client-initiated accept_bi where the client
        // creates socketpairs and sends FDs back to the server).

        // 6. Build the IpcConnectionHandle.
        Ok(Arc::new(IpcConnectionHandle::new(
            bootstrap.connection,
            conn_fd_registry,
            conn_fd_sender,
        )))
    }
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn connect_error(err: impl std::error::Error, context: &str) -> ConnectionError {
    tracing::debug!(error = %snafu::Report::from_error(&err), context, "ipc connect error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc connect: {context}").into(),
        },
    }
}
