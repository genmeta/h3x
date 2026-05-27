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
use tracing::{Instrument, debug};

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
    debug!(error = %snafu::Report::from_error(&err), context, "ipc listener error");
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
                debug!(error = %snafu::Report::from_error(e), "per-connection remoc handshake failed");
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
            debug!("failed to send connection bootstrap: base channel closed");
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

    async fn accept(&mut self) -> Result<Arc<IpcConnectionHandle>, IpcListenError> {
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
        Ok(Arc::new(IpcConnectionHandle::new(
            bootstrap.connection,
            conn_fd_registry,
            conn_fd_sender,
        )))
    }

    async fn shutdown(&self) -> Result<(), IpcListenError> {
        IpcListen::shutdown(&self.rpc).await.context(RpcSnafu)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        future::Future,
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt, future::pending, task::noop_waker};
    use remoc::prelude::ServerSharedMut;
    use smallvec::smallvec;
    use tokio::{
        sync::{RwLock, mpsc, oneshot},
        task::JoinHandle,
        time::{Duration, timeout},
    };
    use tracing::Instrument;

    use super::*;
    use crate::{
        error::Code,
        ipc::transport::{FdRegistry, MuxChannel, MuxSink, MuxStream},
        quic::{self, StreamError, TransportError},
    };

    fn test_connection_error(reason: &str) -> ConnectionError {
        ConnectionError::Transport {
            source: TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: reason.to_owned().into(),
            },
        }
    }

    #[derive(Debug)]
    struct NoAgent;

    impl dhttp_identity::identity::LocalAgent for NoAgent {
        fn name(&self) -> &str {
            "none"
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
        ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl dhttp_identity::identity::RemoteAgent for NoAgent {
        fn name(&self) -> &str {
            "none"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    struct NeverReadStream;

    impl quic::GetStreamId for NeverReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, StreamError>> {
            let _ = self;
            Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl quic::StopStream for NeverReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for NeverReadStream {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let _ = self;
            Poll::Ready(None)
        }
    }

    struct NeverWriteStream;

    impl quic::GetStreamId for NeverWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, StreamError>> {
            let _ = self;
            Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl quic::CancelStream for NeverWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for NeverWriteStream {
        type Error = StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            let _ = self;
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    struct TestConnection;

    impl quic::ManageStream for TestConnection {
        type StreamReader = NeverReadStream;
        type StreamWriter = NeverWriteStream;

        async fn open_bi(&self) -> Result<(NeverReadStream, NeverWriteStream), ConnectionError> {
            Err(test_connection_error("open_bi should not be called"))
        }

        async fn open_uni(&self) -> Result<NeverWriteStream, ConnectionError> {
            Err(test_connection_error("open_uni should not be called"))
        }

        async fn accept_bi(&self) -> Result<(NeverReadStream, NeverWriteStream), ConnectionError> {
            Err(test_connection_error("accept_bi should not be called"))
        }

        async fn accept_uni(&self) -> Result<NeverReadStream, ConnectionError> {
            Err(test_connection_error("accept_uni should not be called"))
        }
    }

    impl quic::WithLocalAgent for TestConnection {
        type LocalAgent = NoAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAgent for TestConnection {
        type RemoteAgent = NoAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for TestConnection {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> ConnectionError {
            pending().await
        }
    }

    struct QueuedListen {
        rx: mpsc::Receiver<Arc<TestConnection>>,
        shutdown_error: Option<ConnectionError>,
    }

    impl quic::Listen for QueuedListen {
        type Connection = TestConnection;
        type Error = ConnectionError;

        async fn accept(&mut self) -> Result<Arc<TestConnection>, ConnectionError> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| test_connection_error("listener closed"))
        }

        async fn shutdown(&self) -> Result<(), ConnectionError> {
            match &self.shutdown_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
    }

    struct ErrorListen {
        accept_error: ConnectionError,
        shutdown_error: ConnectionError,
    }

    impl quic::Listen for ErrorListen {
        type Connection = TestConnection;
        type Error = ConnectionError;

        async fn accept(&mut self) -> Result<Arc<TestConnection>, ConnectionError> {
            Err(self.accept_error.clone())
        }

        async fn shutdown(&self) -> Result<(), ConnectionError> {
            Err(self.shutdown_error.clone())
        }
    }

    struct ParentTransport {
        fd_sender: FdSender,
        fd_registry: FdRegistry,
        sink: MuxSink,
        stream: MuxStream,
    }

    impl ParentTransport {
        fn new() -> Self {
            let (server_mux, client_mux) = MuxChannel::pair_for_test().expect("mux pair");
            let (server_sink, _server_stream) = server_mux.split().expect("server split");
            let (_client_sink, client_stream) = client_mux.split().expect("client split");
            Self {
                fd_sender: server_sink.fd_sender(),
                fd_registry: client_stream.fd_registry(),
                sink: server_sink,
                stream: client_stream,
            }
        }

        fn fd_sender(&self) -> FdSender {
            self.fd_sender.clone()
        }

        fn fd_registry(&self) -> FdRegistry {
            self.fd_registry.clone()
        }

        async fn drive_once(&mut self) {
            timeout(Duration::from_secs(1), async {
                self.sink
                    .send(Bytes::new())
                    .await
                    .expect("drive transport send");
                let frame = self
                    .stream
                    .next()
                    .await
                    .expect("transport stream item")
                    .expect("transport frame");
                assert!(frame.is_empty(), "expected empty driver frame");
            })
            .await
            .expect("parent transport drive timeout");
        }
    }

    struct StaticIpcListen {
        accept_result: Result<VarInt, ConnectionError>,
        shutdown_result: Result<(), ConnectionError>,
        parent_transport: Option<ParentTransport>,
    }

    impl IpcListen for StaticIpcListen {
        async fn accept(&mut self) -> Result<VarInt, ConnectionError> {
            let fd_id = self.accept_result.clone()?;
            if let Some(parent_transport) = self.parent_transport.as_mut() {
                parent_transport.drive_once().await;
            }
            Ok(fd_id)
        }

        async fn shutdown(&self) -> Result<(), ConnectionError> {
            self.shutdown_result.clone()
        }
    }

    struct DrivingListenAdapter<Codec> {
        inner: ListenAdapter<QueuedListen, Codec>,
        parent_transport: ParentTransport,
    }

    impl<Codec> IpcListen for DrivingListenAdapter<Codec>
    where
        Codec: remoc::codec::Codec,
    {
        async fn accept(&mut self) -> Result<VarInt, ConnectionError> {
            let fd_id = IpcListen::accept(&mut self.inner).await?;
            self.parent_transport.drive_once().await;
            Ok(fd_id)
        }

        async fn shutdown(&self) -> Result<(), ConnectionError> {
            IpcListen::shutdown(&self.inner).await
        }
    }

    fn spawn_rpc_server<T>(server_impl: T) -> (IpcListenClient, JoinHandle<()>)
    where
        T: IpcListen + 'static,
    {
        let (server, client) =
            IpcListenServerSharedMut::new(Arc::new(RwLock::new(server_impl)), 64);
        let task = tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        );
        (client, task)
    }

    async fn setup_listener_pair() -> (
        IpcListener<remoc::codec::Default>,
        mpsc::Sender<Arc<TestConnection>>,
        JoinHandle<()>,
    ) {
        let (conn_tx, conn_rx) = mpsc::channel(1);
        let parent_transport = ParentTransport::new();
        let fd_sender = parent_transport.fd_sender();
        let fd_registry = parent_transport.fd_registry();
        let adapter = DrivingListenAdapter {
            inner: ListenAdapter::<_, remoc::codec::Default>::new(
                QueuedListen {
                    rx: conn_rx,
                    shutdown_error: None,
                },
                fd_sender,
            ),
            parent_transport,
        };
        let (client, server_task) = spawn_rpc_server(adapter);
        let listener = IpcListener::new(client, fd_registry);
        (listener, conn_tx, server_task)
    }

    #[test]
    fn ipc_listen_error_wraps_context() {
        let error = ipc_listen_error(io::Error::other("boom"), "split mux");
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.kind, IPC_ERROR_KIND);
        assert_eq!(source.frame_type, IPC_FRAME_TYPE);
        assert_eq!(source.reason, "ipc listen: split mux");
    }

    #[tokio::test]
    async fn listen_adapter_accept_maps_inner_error() {
        let parent_transport = ParentTransport::new();
        let mut adapter = ListenAdapter::<_, remoc::codec::Default>::new(
            ErrorListen {
                accept_error: test_connection_error("inner accept failed"),
                shutdown_error: test_connection_error("inner shutdown failed"),
            },
            parent_transport.fd_sender(),
        );

        let error = IpcListen::accept(&mut adapter)
            .await
            .expect_err("accept should fail");
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason, "ipc listen: accept");
    }

    #[tokio::test]
    async fn listen_adapter_shutdown_maps_inner_error() {
        let parent_transport = ParentTransport::new();
        let adapter = ListenAdapter::<_, remoc::codec::Default>::new(
            ErrorListen {
                accept_error: test_connection_error("inner accept failed"),
                shutdown_error: test_connection_error("inner shutdown failed"),
            },
            parent_transport.fd_sender(),
        );

        let error = IpcListen::shutdown(&adapter)
            .await
            .expect_err("shutdown should fail");
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason, "ipc listen: shutdown");
    }

    #[tokio::test]
    async fn listen_adapter_accept_maps_queue_fd_error_when_parent_transport_is_closed() {
        let parent_transport = ParentTransport::new();
        let fd_sender = parent_transport.fd_sender();
        drop(parent_transport);

        let (conn_tx, conn_rx) = mpsc::channel(1);
        conn_tx
            .send(Arc::new(TestConnection))
            .await
            .expect("send test connection");
        drop(conn_tx);

        let mut adapter = ListenAdapter::<_, remoc::codec::Default>::new(
            QueuedListen {
                rx: conn_rx,
                shutdown_error: None,
            },
            fd_sender,
        );

        let error = IpcListen::accept(&mut adapter)
            .await
            .expect_err("closed parent transport should fail queue_fds");
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason, "ipc listen: queue fd");
    }

    #[tokio::test]
    async fn setup_connection_returns_when_peer_is_closed() {
        let (server_mux, client_mux) = MuxChannel::pair_for_test().expect("mux pair");
        let (sink, stream) = server_mux.split().expect("server split");
        drop(client_mux);

        timeout(
            Duration::from_secs(1),
            ListenAdapter::<QueuedListen, remoc::codec::Default>::setup_connection(
                Arc::new(TestConnection),
                sink,
                stream,
            ),
        )
        .await
        .expect("setup_connection should finish when the peer is gone");
    }

    #[tokio::test]
    async fn setup_connection_returns_when_bootstrap_receiver_is_closed() {
        let (server_mux, client_mux) = MuxChannel::pair_for_test().expect("mux pair");
        let (server_sink, server_stream) = server_mux.split().expect("server split");
        let (client_sink, client_stream) = client_mux.split().expect("client split");

        let peer_task = tokio::spawn(
            async move {
                let (_remoc_conn, _tx, rx) =
                    remoc::Connect::framed::<_, _, (), ConnectionBootstrap, remoc::codec::Default>(
                        remoc::Cfg::default(),
                        client_sink,
                        client_stream,
                    )
                    .await
                    .expect("client handshake");
                drop(rx);
            }
            .in_current_span(),
        );

        timeout(
            Duration::from_secs(1),
            ListenAdapter::<QueuedListen, remoc::codec::Default>::setup_connection(
                Arc::new(TestConnection),
                server_sink,
                server_stream,
            ),
        )
        .await
        .expect("setup_connection should finish after bootstrap send failure");
        timeout(Duration::from_secs(1), peer_task)
            .await
            .expect("peer task timeout")
            .expect("peer task panicked");
    }

    #[tokio::test]
    async fn ipc_listener_accept_and_shutdown_succeed_via_adapter() {
        let (mut listener, conn_tx, server_task) = setup_listener_pair().await;
        conn_tx
            .send(Arc::new(TestConnection))
            .await
            .expect("send test connection");

        let handle = timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
            .expect("accept succeeds");
        assert!(quic::Lifecycle::check(handle.as_ref()).is_ok());
        assert!(
            timeout(Duration::from_secs(1), quic::Listen::shutdown(&listener))
                .await
                .expect("shutdown timeout")
                .is_ok()
        );

        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accepted_handle_forwards_connection_rpc_methods() {
        let (mut listener, conn_tx, server_task) = setup_listener_pair().await;
        conn_tx
            .send(Arc::new(TestConnection))
            .await
            .expect("send test connection");

        let handle = timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
            .expect("accept succeeds");

        assert!(
            quic::WithLocalAgent::local_agent(handle.as_ref())
                .await
                .expect("local agent rpc")
                .is_none()
        );
        assert!(
            quic::WithRemoteAgent::remote_agent(handle.as_ref())
                .await
                .expect("remote agent rpc")
                .is_none()
        );

        let open_error = match quic::ManageStream::open_bi(handle.as_ref()).await {
            Ok(_) => panic!("open_bi error should propagate over ipc"),
            Err(error) => error,
        };
        let ConnectionError::Transport { source } = open_error else {
            panic!("expected open_bi transport error");
        };
        assert!(source.reason.contains("open_bi should not be called"));

        conn_tx
            .send(Arc::new(TestConnection))
            .await
            .expect("send second test connection");
        let open_uni_handle = timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("second accept timeout")
            .expect("second accept succeeds");

        let open_uni_error = match quic::ManageStream::open_uni(open_uni_handle.as_ref()).await {
            Ok(_) => panic!("open_uni error should propagate over ipc"),
            Err(error) => error,
        };
        let ConnectionError::Transport { source } = open_uni_error else {
            panic!("expected open_uni transport error");
        };
        assert!(source.reason.contains("open_uni should not be called"));

        conn_tx
            .send(Arc::new(TestConnection))
            .await
            .expect("send third test connection");
        let accept_handle = timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("third accept timeout")
            .expect("third accept succeeds");

        let accept_error = match quic::ManageStream::accept_bi(accept_handle.as_ref()).await {
            Ok(_) => panic!("accept_bi error should propagate over ipc"),
            Err(error) => error,
        };
        let ConnectionError::Transport { source } = accept_error else {
            panic!("expected accept_bi transport error");
        };
        assert!(source.reason.contains("accept_bi should not be called"));

        conn_tx
            .send(Arc::new(TestConnection))
            .await
            .expect("send fourth test connection");
        drop(conn_tx);
        let accept_uni_handle =
            timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
                .await
                .expect("fourth accept timeout")
                .expect("fourth accept succeeds");

        let accept_uni_error =
            match quic::ManageStream::accept_uni(accept_uni_handle.as_ref()).await {
                Ok(_) => panic!("accept_uni error should propagate over ipc"),
                Err(error) => error,
            };
        let ConnectionError::Transport { source } = accept_uni_error else {
            panic!("expected accept_uni transport error");
        };
        assert!(source.reason.contains("accept_uni should not be called"));

        drop(handle);
        drop(open_uni_handle);
        drop(accept_handle);
        drop(accept_uni_handle);
        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_rpc_error() {
        let parent_transport = ParentTransport::new();
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Err(test_connection_error("rpc accept failed")),
            shutdown_result: Ok(()),
            parent_transport: Some(parent_transport),
        });
        let mut listener =
            IpcListener::<remoc::codec::Default>::new(client, ParentTransport::new().fd_registry());

        let error = match quic::Listen::accept(&mut listener).await {
            Ok(_) => panic!("rpc failure should surface"),
            Err(error) => error,
        };
        assert!(matches!(error, IpcListenError::Rpc { .. }));

        let converted = ConnectionError::from(IpcListenError::EmptyFd);
        let ConnectionError::Transport { source } = converted else {
            panic!("expected transport error");
        };
        assert!(source.reason.contains("no fd received from registry"));

        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_shutdown_returns_rpc_error() {
        let parent_transport = ParentTransport::new();
        let fd_registry = parent_transport.fd_registry();
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(VarInt::from_u32(0)),
            shutdown_result: Err(test_connection_error("rpc shutdown failed")),
            parent_transport: Some(parent_transport),
        });
        let listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);

        let error = quic::Listen::shutdown(&listener)
            .await
            .expect_err("shutdown should fail");
        assert!(matches!(error, IpcListenError::Rpc { .. }));

        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_wait_fd_error_when_fd_id_already_has_waiter() {
        let parent_transport = ParentTransport::new();
        let fd_id = VarInt::from_u32(7);
        let fd_registry = parent_transport.fd_registry();
        let waiter_registry = fd_registry.clone();
        let mut pending_wait = Box::pin(waiter_registry.wait_fds(fd_id));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(pending_wait.as_mut().poll(&mut cx).is_pending());

        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(fd_id),
            shutdown_result: Ok(()),
            parent_transport: None,
        });
        let mut listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);

        let error = match timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
        {
            Ok(_) => panic!("duplicate fd waiter should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, IpcListenError::WaitFd { .. }));

        drop(listener);
        drop(pending_wait);
        drop(parent_transport);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_wait_fd_error_when_registry_is_closed() {
        let parent_transport = ParentTransport::new();
        let fd_registry = parent_transport.fd_registry();
        drop(parent_transport);
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(VarInt::from_u32(0)),
            shutdown_result: Ok(()),
            parent_transport: None,
        });
        let mut listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);

        let error = match quic::Listen::accept(&mut listener).await {
            Ok(_) => panic!("closed registry should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, IpcListenError::WaitFd { .. }));

        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_from_fd_error_for_non_socket_fd() {
        let parent_transport = ParentTransport::new();
        let fd_id = parent_transport
            .fd_sender()
            .queue_fds(smallvec![
                std::fs::File::open("/dev/null")
                    .expect("open /dev/null")
                    .into()
            ])
            .expect("queue file fd");
        let fd_registry = parent_transport.fd_registry();
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(fd_id),
            shutdown_result: Ok(()),
            parent_transport: Some(parent_transport),
        });
        let mut listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);

        let error = match timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
        {
            Ok(_) => panic!("non-socket fd should fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            IpcListenError::FromFd { .. } | IpcListenError::ClientSplit { .. }
        ));

        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_client_remoc_connect_error() {
        let parent_transport = ParentTransport::new();
        let (server_mux, client_fd) = MuxChannel::create_pair().expect("mux pair");
        let fd_id = parent_transport
            .fd_sender()
            .queue_fds(smallvec![client_fd])
            .expect("queue mux fd");
        let fd_registry = parent_transport.fd_registry();
        drop(server_mux);
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(fd_id),
            shutdown_result: Ok(()),
            parent_transport: Some(parent_transport),
        });
        let mut listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);

        let error = match timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
        {
            Ok(_) => panic!("handshake should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, IpcListenError::ClientRemocConnect { .. }));

        drop(listener);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_receive_bootstrap_error_when_channel_closes() {
        let parent_transport = ParentTransport::new();
        let (server_mux, client_fd) = MuxChannel::create_pair().expect("mux pair");
        let fd_id = parent_transport
            .fd_sender()
            .queue_fds(smallvec![client_fd])
            .expect("queue mux fd");
        let fd_registry = parent_transport.fd_registry();
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(fd_id),
            shutdown_result: Ok(()),
            parent_transport: Some(parent_transport),
        });
        let mut listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);

        let peer_task = tokio::spawn(
            async move {
                let (sink, stream) = server_mux.split().expect("server split");
                let (_remoc_conn, tx, _rx) =
                    remoc::Connect::framed::<_, _, ConnectionBootstrap, (), remoc::codec::Default>(
                        remoc::Cfg::default(),
                        sink,
                        stream,
                    )
                    .await
                    .expect("server handshake");
                drop(tx);
            }
            .in_current_span(),
        );

        let error = match timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
        {
            Ok(_) => panic!("missing bootstrap should fail"),
            Err(error) => error,
        };
        match error {
            IpcListenError::ReceiveBootstrap { message } => {
                assert!(
                    !message.is_empty(),
                    "receive-bootstrap error message should not be empty"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        drop(listener);
        timeout(Duration::from_secs(1), peer_task)
            .await
            .expect("peer task timeout")
            .expect("peer task panicked");
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_listener_accept_returns_receive_bootstrap_none_when_sender_closes_gracefully() {
        let parent_transport = ParentTransport::new();
        let (server_mux, client_fd) = MuxChannel::create_pair().expect("mux pair");
        let fd_id = parent_transport
            .fd_sender()
            .queue_fds(smallvec![client_fd])
            .expect("queue mux fd");
        let fd_registry = parent_transport.fd_registry();
        let (client, server_task) = spawn_rpc_server(StaticIpcListen {
            accept_result: Ok(fd_id),
            shutdown_result: Ok(()),
            parent_transport: Some(parent_transport),
        });
        let mut listener = IpcListener::<remoc::codec::Default>::new(client, fd_registry);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let peer_task = tokio::spawn(
            async move {
                let (sink, stream) = server_mux.split().expect("server split");
                let (remoc_conn, tx, _rx) =
                    remoc::Connect::framed::<_, _, ConnectionBootstrap, (), remoc::codec::Default>(
                        remoc::Cfg::default(),
                        sink,
                        stream,
                    )
                    .await
                    .expect("server handshake");
                let remoc_task = tokio::spawn(remoc_conn.in_current_span());
                drop(tx);

                let _ = shutdown_rx.await;
                remoc_task.abort();
                let _ = remoc_task.await;
            }
            .in_current_span(),
        );

        let error = match timeout(Duration::from_secs(1), quic::Listen::accept(&mut listener))
            .await
            .expect("accept timeout")
        {
            Ok(_) => panic!("missing bootstrap should fail"),
            Err(error) => error,
        };
        match error {
            IpcListenError::ReceiveBootstrap { message } => {
                assert_eq!(message, "base channel closed before bootstrap received");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        drop(listener);
        let _ = shutdown_tx.send(());
        timeout(Duration::from_secs(1), peer_task)
            .await
            .expect("peer task timeout")
            .expect("peer task panicked");
        server_task.abort();
        let _ = server_task.await;
    }
}
