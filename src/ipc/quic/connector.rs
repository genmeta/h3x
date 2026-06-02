//! Connector-level IPC adapters and RTC trait.
//!
//! # RTC trait
//!
//! [`IpcConnect`] defines the RPC interface for initiating outgoing connections.
//! The server side calls [`quic::Connect::connect`], creates a new
//! [`MuxChannel`] pair, delivers the remote end's FD using the caller-chosen
//! [`VarInt`] FD transfer ID, and returns that same ID as confirmation.
//!
//! # Server side
//!
//! [`ConnectAdapter`] wraps a `quic::Connect` and implements [`IpcConnect`].
//! Each `connect` call:
//! 1. Calls the inner connector to establish a real QUIC connection.
//! 2. Creates a [`MuxChannel`] pair (one for the server, one FD for the client).
//! 3. Delivers the client-side FD through the parent-level [`FdTransfer`].
//! 4. Splits the server-side MuxChannel, establishes a remoc connection.
//! 5. Creates a [`ConnectionAdapter`] for the real connection, wraps it in
//!    an [`IpcConnectionServerShared`], spawns the RPC server.
//! 6. Sends a [`ConnectionBootstrap`] over the remoc base channel.
//! 7. Returns the caller-chosen FD transfer ID.
//!
//! # Client side
//!
//! [`IpcConnector`] wraps an [`IpcConnectClient`] and implements
//! [`quic::Connect`].  Each `connect` call:
//! 1. Reserves a caller-chosen FD transfer ID.
//! 2. Calls RPC `connect(server, fd_id)` while concurrently receiving the
//!    MuxChannel FD.
//! 3. Splits the MuxChannel, establishes a remoc connection.
//! 4. Receives the [`ConnectionBootstrap`] from the base channel.
//! 5. Wraps the result as an [`IpcConnectionHandle`].

use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use http::uri::Authority;
use remoc::{self, RemoteSend, prelude::ServerShared};
use smallvec::smallvec;
use snafu::{ResultExt, Snafu};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::connection::{
    ConnectionAdapter, ConnectionBootstrap, IPC_ERROR_KIND, IPC_FRAME_TYPE, IpcConnectionHandle,
    IpcConnectionServerShared,
};
use crate::{
    error::Code,
    ipc::transport::{FdTransfer, MuxChannel, SplitError, TakeFdsError},
    quic::{self, ConnectionError},
    rpc::quic::serde_types::SerdeAuthority,
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// IPC RTC trait for connector capability
// ---------------------------------------------------------------------------

/// Remote trait for IPC connector capability.
///
/// Each successful [`connect`](IpcConnect::connect) echoes the receiver-chosen
/// FD transfer ID after the associated [`MuxChannel`] FD has been
/// acknowledged by the receiver.
#[remoc::rtc::remote]
pub trait IpcConnect: Send + Sync {
    /// Connect to a remote server.
    ///
    /// Returns the caller-chosen FD transfer ID for the new connection's
    /// MuxChannel.
    async fn connect(
        &self,
        server: SerdeAuthority,
        fd_id: VarInt,
    ) -> Result<VarInt, ConnectionError>;
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
    #[snafu(display("unexpected connection fd count"))]
    TakeFd { source: TakeFdsError },
    #[snafu(display("ipc connect returned mismatched fd id {actual}, expected {expected}"))]
    FdIdMismatch { expected: VarInt, actual: VarInt },
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
    fd_transfer: FdTransfer,
    tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
    _codec: std::marker::PhantomData<Codec>,
}

impl<C, Codec> ConnectAdapter<C, Codec> {
    pub fn new(inner: C, fd_transfer: FdTransfer) -> Self {
        Self {
            inner,
            fd_transfer,
            tasks: Mutex::new(Vec::new()),
            _codec: std::marker::PhantomData,
        }
    }

    fn spawn_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let handle = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));
        let mut tasks = self
            .tasks
            .lock()
            .expect("connect adapter task registry should not be poisoned");
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
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
    async fn connect(
        &self,
        server: SerdeAuthority,
        fd_id: VarInt,
    ) -> Result<VarInt, ConnectionError> {
        let authority = Authority::try_from(server).map_err(|e| connect_error(e, "authority"))?;
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let connection = tokio::select! {
            biased;
            _ = delivery.cancelled() => return Err(connect_cancelled("connect")),
            result = quic::Connect::connect(&self.inner, &authority) => {
                result.map_err(|e| connect_error(e, "connect"))?
            }
        };

        // Create a MuxChannel pair for this connection.
        let (server_mux, client_fd) =
            MuxChannel::create_pair().map_err(|e| connect_error(e, "create_pair"))?;

        if let Err(error) = delivery.deliver(smallvec![client_fd]).await {
            close_cancelled_connection(connection.as_ref(), "deliver");
            return Err(connect_error(error, "deliver fd"));
        }

        // Split the server-side MuxChannel — the remoc handshake + bootstrap
        // are spawned as a background task after the FD delivery has been acked.
        let (sink, stream) = server_mux.split().map_err(|e| connect_error(e, "split"))?;

        self.spawn_task(Self::setup_connection(connection, sink, stream));

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
        let conn_fd_transfer = stream.fd_transfer(conn_fd_sender);

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
        let remoc_task = AbortOnDropHandle::new(tokio::spawn(conn.in_current_span()));

        // Create the ConnectionAdapter and wrap it as an IPC RPC server.
        let adapter = ConnectionAdapter::new(connection, conn_fd_transfer);
        let (server, rpc_client) = IpcConnectionServerShared::new(Arc::new(adapter), 64);
        let server_task = AbortOnDropHandle::new(tokio::spawn(
            (async move {
                let _ = server.serve(true).await;
            })
            .in_current_span(),
        ));

        let bootstrap = ConnectionBootstrap {
            connection: rpc_client,
        };

        if tx.send(bootstrap).await.is_err() {
            debug!("failed to send connection bootstrap: base channel closed");
            return;
        }

        let _ = futures::future::join(remoc_task, server_task).await;
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
    fd_transfer: FdTransfer,
    _codec: std::marker::PhantomData<Codec>,
}

impl<Codec> IpcConnector<Codec> {
    pub fn new(rpc: IpcConnectClient, fd_transfer: FdTransfer) -> Self {
        Self {
            rpc,
            fd_transfer,
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
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        let rpc = async {
            let actual = IpcConnect::connect(&self.rpc, SerdeAuthority::from(server), fd_id)
                .await
                .context(RpcSnafu)?;
            if actual != fd_id {
                return Err(ConnectorError::FdIdMismatch {
                    expected: fd_id,
                    actual,
                });
            }
            Ok(())
        };
        let receive = async { receiver.await.context(WaitFdsSnafu) };

        let ((), received) = futures::future::try_join(rpc, receive).await?;
        let fd = received.into_one().context(TakeFdSnafu)?;

        // 3. Reconstruct the MuxChannel and split it.
        let mux = MuxChannel::from_fd(fd).context(FromFdSnafu)?;
        let (sink, stream) = mux.split().context(SplitSnafu)?;
        let conn_fd_transfer = stream.fd_transfer(sink.fd_sender());

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
        let remoc_task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = conn.await;
            }
            .in_current_span(),
        ));

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
            conn_fd_transfer,
            remoc_task,
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

fn connect_cancelled(context: &str) -> ConnectionError {
    tracing::debug!(context, "ipc connect fd transfer cancelled");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc connect: {context} cancelled").into(),
        },
    }
}

fn close_cancelled_connection(connection: &impl quic::Lifecycle, context: &'static str) {
    quic::Lifecycle::close(
        connection,
        Code::H3_REQUEST_CANCELLED,
        format!("ipc connect {context} cancelled").into(),
    );
}
