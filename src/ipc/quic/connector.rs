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

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        io,
        pin::Pin,
        sync::{Arc, Mutex as StdMutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt, future::pending};
    use remoc::prelude::ServerShared;
    use serde::{
        Deserialize,
        de::{IntoDeserializer, value::Error as ValueError},
    };
    use smallvec::smallvec;
    use tokio::{
        sync::{Mutex, Notify},
        task::JoinHandle,
        time::{Duration, timeout},
    };
    use tracing::Instrument;

    use super::*;
    use crate::{
        error::Code,
        ipc::transport::{MuxChannel, MuxSink, MuxStream},
        quic::{self, StreamError, TransportError},
        util::set_once::SetOnce,
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

    fn assert_transport_reason(error: ConnectionError, expected_reason: &str) {
        let ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.kind, IPC_ERROR_KIND);
        assert_eq!(source.frame_type, IPC_FRAME_TYPE);
        assert_eq!(source.reason, expected_reason);
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

    struct TestLifecycle {
        terminal_error: SetOnce<ConnectionError>,
        close_calls: StdMutex<Vec<(Code, Cow<'static, str>)>>,
        close_notify: Notify,
    }

    impl TestLifecycle {
        fn new() -> Self {
            Self {
                terminal_error: SetOnce::new(),
                close_calls: StdMutex::new(Vec::new()),
                close_notify: Notify::new(),
            }
        }

        fn set_terminal_error(&self, error: ConnectionError) {
            let _ = self.terminal_error.set(error);
        }

        fn record_close(&self, code: Code, reason: Cow<'static, str>) {
            self.close_calls
                .lock()
                .expect("close calls mutex poisoned")
                .push((code, reason));
            self.close_notify.notify_waiters();
        }

        async fn wait_for_close_call(&self) -> (Code, Cow<'static, str>) {
            loop {
                let notified = self.close_notify.notified();
                if let Some(call) = self
                    .close_calls
                    .lock()
                    .expect("close calls mutex poisoned")
                    .first()
                    .cloned()
                {
                    return call;
                }
                notified.await;
            }
        }
    }

    struct TestConnection {
        lifecycle: Arc<TestLifecycle>,
    }

    impl TestConnection {
        fn new() -> (Arc<Self>, Arc<TestLifecycle>) {
            let lifecycle = Arc::new(TestLifecycle::new());
            let connection = Arc::new(Self {
                lifecycle: lifecycle.clone(),
            });
            (connection, lifecycle)
        }
    }

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
        fn close(&self, code: Code, reason: Cow<'static, str>) {
            self.lifecycle.record_close(code, reason);
        }

        fn check(&self) -> Result<(), ConnectionError> {
            match self.lifecycle.terminal_error.peek() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn closed(&self) -> ConnectionError {
            match self.lifecycle.terminal_error.peek() {
                Some(error) => error,
                None => pending().await,
            }
        }
    }

    struct RecordingConnect {
        connection: Arc<TestConnection>,
        authorities: Arc<StdMutex<Vec<String>>>,
    }

    impl quic::Connect for RecordingConnect {
        type Connection = TestConnection;
        type Error = ConnectionError;

        async fn connect<'a>(
            &'a self,
            server: &'a Authority,
        ) -> Result<Arc<TestConnection>, ConnectionError> {
            self.authorities
                .lock()
                .expect("authority mutex poisoned")
                .push(server.as_str().to_owned());
            Ok(self.connection.clone())
        }
    }

    struct FailingConnect {
        error: ConnectionError,
    }

    impl quic::Connect for FailingConnect {
        type Connection = TestConnection;
        type Error = ConnectionError;

        async fn connect<'a>(
            &'a self,
            _server: &'a Authority,
        ) -> Result<Arc<TestConnection>, ConnectionError> {
            Err(self.error.clone())
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

    struct StaticIpcConnect {
        connect_result: Result<VarInt, ConnectionError>,
        parent_transport: Option<Mutex<ParentTransport>>,
    }

    impl IpcConnect for StaticIpcConnect {
        async fn connect(&self, _server: SerdeAuthority) -> Result<VarInt, ConnectionError> {
            let fd_id = self.connect_result.clone()?;
            if let Some(parent_transport) = &self.parent_transport {
                parent_transport.lock().await.drive_once().await;
            }
            Ok(fd_id)
        }
    }

    struct DrivingConnectAdapter<Codec, C> {
        inner: ConnectAdapter<C, Codec>,
        parent_transport: Mutex<ParentTransport>,
    }

    impl<Codec, C> IpcConnect for DrivingConnectAdapter<Codec, C>
    where
        Codec: remoc::codec::Codec,
        C: quic::Connect<Connection = TestConnection, Error = ConnectionError> + 'static,
        ConnectionBootstrap: RemoteSend,
    {
        async fn connect(&self, server: SerdeAuthority) -> Result<VarInt, ConnectionError> {
            let fd_id = IpcConnect::connect(&self.inner, server).await?;
            self.parent_transport.lock().await.drive_once().await;
            Ok(fd_id)
        }
    }

    fn spawn_rpc_server<T>(server_impl: T) -> (IpcConnectClient, JoinHandle<()>)
    where
        T: IpcConnect + 'static,
    {
        let (server, client) = IpcConnectServerShared::new(Arc::new(server_impl), 64);
        let task = tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        );
        (client, task)
    }

    #[test]
    fn connect_error_wraps_context() {
        assert_transport_reason(
            connect_error(io::Error::other("boom"), "split"),
            "ipc connect: split",
        );
    }

    #[tokio::test]
    async fn connect_adapter_returns_fd_id_and_records_server_authority() {
        let (connection, _lifecycle) = TestConnection::new();
        let authorities = Arc::new(StdMutex::new(Vec::new()));
        let mut parent_transport = ParentTransport::new();
        let adapter = ConnectAdapter::<_, remoc::codec::Default>::new(
            RecordingConnect {
                connection,
                authorities: authorities.clone(),
            },
            parent_transport.fd_sender(),
        );
        let authority = Authority::from_static("server.example:443");

        let fd_id = IpcConnect::connect(&adapter, SerdeAuthority::from(&authority))
            .await
            .expect("connect succeeds");
        parent_transport.drive_once().await;
        let fds = parent_transport
            .fd_registry()
            .wait_fds(fd_id)
            .await
            .expect("fd is registered");

        assert_eq!(fds.len(), 1, "expected exactly one mux fd");
        assert_eq!(
            authorities
                .lock()
                .expect("authority mutex poisoned")
                .as_slice(),
            [authority.as_str()]
        );
    }

    #[tokio::test]
    async fn connect_adapter_maps_invalid_authority() {
        let (connection, _lifecycle) = TestConnection::new();
        let authorities = Arc::new(StdMutex::new(Vec::new()));
        let parent_transport = ParentTransport::new();
        let adapter = ConnectAdapter::<_, remoc::codec::Default>::new(
            RecordingConnect {
                connection,
                authorities: authorities.clone(),
            },
            parent_transport.fd_sender(),
        );
        let invalid =
            SerdeAuthority::deserialize(serde::de::value::SeqDeserializer::<_, ValueError>::new(
                ["not a valid authority"]
                    .into_iter()
                    .map(|value| value.into_deserializer()),
            ))
            .expect("deserialize invalid wrapper");

        let error = IpcConnect::connect(&adapter, invalid)
            .await
            .expect_err("invalid authority should fail");

        assert_transport_reason(error, "ipc connect: authority");
        assert!(
            authorities
                .lock()
                .expect("authority mutex poisoned")
                .is_empty(),
            "inner connector should not be called for invalid authority"
        );
    }

    #[tokio::test]
    async fn connect_adapter_maps_inner_connect_error() {
        let parent_transport = ParentTransport::new();
        let adapter = ConnectAdapter::<_, remoc::codec::Default>::new(
            FailingConnect {
                error: test_connection_error("inner connect failed"),
            },
            parent_transport.fd_sender(),
        );

        let error = IpcConnect::connect(
            &adapter,
            SerdeAuthority::from(&Authority::from_static("server.example")),
        )
        .await
        .expect_err("inner connect should fail");

        assert_transport_reason(error, "ipc connect: connect");
    }

    #[tokio::test]
    async fn connect_adapter_maps_queue_fds_error_when_parent_transport_is_closed() {
        let (connection, _lifecycle) = TestConnection::new();
        let parent_transport = ParentTransport::new();
        let fd_sender = parent_transport.fd_sender();
        drop(parent_transport);
        let adapter = ConnectAdapter::<_, remoc::codec::Default>::new(
            RecordingConnect {
                connection,
                authorities: Arc::new(StdMutex::new(Vec::new())),
            },
            fd_sender,
        );

        let error = IpcConnect::connect(
            &adapter,
            SerdeAuthority::from(&Authority::from_static("server.example")),
        )
        .await
        .expect_err("closed fd sender should fail");

        assert_transport_reason(error, "ipc connect: queue_fds");
    }

    #[tokio::test]
    async fn setup_connection_returns_when_peer_is_closed() {
        let (connection, _lifecycle) = TestConnection::new();
        let (server_mux, client_mux) = MuxChannel::pair_for_test().expect("mux pair");
        let (sink, stream) = server_mux.split().expect("server split");
        drop(client_mux);

        timeout(
            Duration::from_secs(1),
            ConnectAdapter::<RecordingConnect, remoc::codec::Default>::setup_connection(
                connection, sink, stream,
            ),
        )
        .await
        .expect("setup_connection should finish when peer is gone");
    }

    #[tokio::test]
    async fn setup_connection_returns_when_bootstrap_receiver_is_closed() {
        let (connection, _lifecycle) = TestConnection::new();
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
            ConnectAdapter::<RecordingConnect, remoc::codec::Default>::setup_connection(
                connection,
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
    async fn ipc_connector_maps_rpc_error() {
        let parent_transport = ParentTransport::new();
        let fd_registry = parent_transport.fd_registry();
        let (client, server_task) = spawn_rpc_server(StaticIpcConnect {
            connect_result: Err(test_connection_error("rpc connect failed")),
            parent_transport: None,
        });
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);

        let error =
            match quic::Connect::connect(&connector, &Authority::from_static("server.example"))
                .await
            {
                Ok(_) => panic!("rpc failure should surface"),
                Err(error) => error,
            };

        assert!(matches!(error, ConnectorError::Rpc { .. }));

        drop(connector);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_connector_returns_wait_fds_error_when_registry_is_closed() {
        let parent_transport = ParentTransport::new();
        let fd_registry = parent_transport.fd_registry();
        drop(parent_transport);
        let (client, server_task) = spawn_rpc_server(StaticIpcConnect {
            connect_result: Ok(VarInt::from_u32(0)),
            parent_transport: None,
        });
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);

        let error =
            match quic::Connect::connect(&connector, &Authority::from_static("server.example"))
                .await
            {
                Ok(_) => panic!("closed registry should fail"),
                Err(error) => error,
            };

        assert!(matches!(error, ConnectorError::WaitFds { .. }));

        drop(connector);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_connector_returns_from_fd_or_split_error_for_non_socket_fd() {
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
        let (client, server_task) = spawn_rpc_server(StaticIpcConnect {
            connect_result: Ok(fd_id),
            parent_transport: Some(Mutex::new(parent_transport)),
        });
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);

        let error = match timeout(
            Duration::from_secs(1),
            quic::Connect::connect(&connector, &Authority::from_static("server.example")),
        )
        .await
        .expect("connect timeout")
        {
            Ok(_) => panic!("non-socket fd should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConnectorError::FromFd { .. } | ConnectorError::Split { .. }
        ));

        drop(connector);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_connector_returns_remoc_error_when_server_mux_is_closed() {
        let parent_transport = ParentTransport::new();
        let (server_mux, client_fd) = MuxChannel::create_pair().expect("mux pair");
        let fd_id = parent_transport
            .fd_sender()
            .queue_fds(smallvec![client_fd])
            .expect("queue mux fd");
        let fd_registry = parent_transport.fd_registry();
        drop(server_mux);
        let (client, server_task) = spawn_rpc_server(StaticIpcConnect {
            connect_result: Ok(fd_id),
            parent_transport: Some(Mutex::new(parent_transport)),
        });
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);

        let error = match timeout(
            Duration::from_secs(1),
            quic::Connect::connect(&connector, &Authority::from_static("server.example")),
        )
        .await
        .expect("connect timeout")
        {
            Ok(_) => panic!("handshake should fail"),
            Err(error) => error,
        };

        assert!(matches!(error, ConnectorError::Remoc { .. }));

        drop(connector);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_connector_returns_bootstrap_error_when_channel_closes() {
        let parent_transport = ParentTransport::new();
        let (server_mux, client_fd) = MuxChannel::create_pair().expect("mux pair");
        let fd_id = parent_transport
            .fd_sender()
            .queue_fds(smallvec![client_fd])
            .expect("queue mux fd");
        let fd_registry = parent_transport.fd_registry();
        let (client, server_task) = spawn_rpc_server(StaticIpcConnect {
            connect_result: Ok(fd_id),
            parent_transport: Some(Mutex::new(parent_transport)),
        });
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);

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

        let error = match timeout(
            Duration::from_secs(1),
            quic::Connect::connect(&connector, &Authority::from_static("server.example")),
        )
        .await
        .expect("connect timeout")
        {
            Ok(_) => panic!("missing bootstrap should fail"),
            Err(error) => error,
        };

        assert!(matches!(error, ConnectorError::Bootstrap));

        drop(connector);
        timeout(Duration::from_secs(1), peer_task)
            .await
            .expect("peer task timeout")
            .expect("peer task panicked");
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_connector_connected_handle_forwards_connection_rpc_methods() {
        let (connection, lifecycle) = TestConnection::new();
        let authorities = Arc::new(StdMutex::new(Vec::new()));
        let parent_transport = ParentTransport::new();
        let fd_registry = parent_transport.fd_registry();
        let adapter = DrivingConnectAdapter::<remoc::codec::Default, _> {
            inner: ConnectAdapter::new(
                RecordingConnect {
                    connection,
                    authorities,
                },
                parent_transport.fd_sender(),
            ),
            parent_transport: Mutex::new(parent_transport),
        };
        let (client, server_task) = spawn_rpc_server(adapter);
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);
        let handle = quic::Connect::connect(&connector, &Authority::from_static("server.example"))
            .await
            .expect("connect succeeds");

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

        let accept_handle =
            quic::Connect::connect(&connector, &Authority::from_static("server.example"))
                .await
                .expect("second connect succeeds");
        let accept_error = match quic::ManageStream::accept_bi(accept_handle.as_ref()).await {
            Ok(_) => panic!("accept_bi error should propagate over ipc"),
            Err(error) => error,
        };
        let ConnectionError::Transport { source } = accept_error else {
            panic!("expected accept_bi transport error");
        };
        assert!(source.reason.contains("accept_bi should not be called"));

        quic::Lifecycle::close(
            accept_handle.as_ref(),
            Code::H3_NO_ERROR,
            Cow::Borrowed("client requested close"),
        );
        let (code, reason) = timeout(Duration::from_secs(1), lifecycle.wait_for_close_call())
            .await
            .expect("close rpc timeout");
        assert_eq!(code, Code::H3_NO_ERROR);
        assert_eq!(reason, Cow::Borrowed("client requested close"));

        drop(handle);
        drop(accept_handle);
        drop(connector);
        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn ipc_connector_connects_via_adapter_and_propagates_lifecycle_error() {
        let (connection, lifecycle) = TestConnection::new();
        let authorities = Arc::new(StdMutex::new(Vec::new()));
        let parent_transport = ParentTransport::new();
        let fd_registry = parent_transport.fd_registry();
        let adapter = DrivingConnectAdapter::<remoc::codec::Default, _> {
            inner: ConnectAdapter::new(
                RecordingConnect {
                    connection,
                    authorities: authorities.clone(),
                },
                parent_transport.fd_sender(),
            ),
            parent_transport: Mutex::new(parent_transport),
        };
        let (client, server_task) = spawn_rpc_server(adapter);
        let connector = IpcConnector::<remoc::codec::Default>::new(client, fd_registry);
        let authority = Authority::from_static("server.example:443");

        let handle = quic::Connect::connect(&connector, &authority)
            .await
            .expect("connect succeeds");
        assert!(quic::Lifecycle::check(handle.as_ref()).is_ok());
        assert_eq!(
            authorities
                .lock()
                .expect("authority mutex poisoned")
                .as_slice(),
            [authority.as_str()]
        );

        lifecycle.set_terminal_error(test_connection_error("connection reset by peer"));

        let closed = timeout(
            Duration::from_secs(1),
            quic::Lifecycle::closed(handle.as_ref()),
        )
        .await
        .expect("closed timeout");
        match closed {
            ConnectionError::Transport { source } => {
                assert!(source.reason.contains("connection reset by peer"));
            }
            other => panic!("expected transport error, got {other:?}"),
        }
        assert!(quic::Lifecycle::check(handle.as_ref()).is_err());

        drop(handle);
        drop(connector);
        server_task.abort();
        let _ = server_task.await;
    }
}
