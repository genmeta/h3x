//! Integration tests for the IPC capability layer.
//!
//! Verifies the full round-trip: server-side adapters wrap mock QUIC
//! connections / listeners / connectors, and client-side handles transparently
//! implement the `quic::*` traits over IPC.

use std::{
    borrow::Cow,
    collections::VecDeque,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, StreamExt, future::pending};
use remoc::prelude::{ServerShared, ServerSharedMut};
use tokio::sync::{Mutex, mpsc};

use crate::{
    error::Code,
    ipc::{
        quic::{
            IpcConnectServerShared, IpcListenServerSharedMut,
            connector::{ConnectAdapter, IpcConnector},
            listener::{IpcListener, ListenAdapter},
        },
        transport::MuxChannel,
    },
    quic::{self, ConnectionError, StreamError, TransportError},
    util::set_once::SetOnce,
    varint::VarInt,
};

// =========================================================================
// Test helpers
// =========================================================================

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(100);

fn next_stream_id() -> VarInt {
    VarInt::from_u32(NEXT_STREAM_ID.fetch_add(2, Ordering::Relaxed))
}

fn test_connection_error(reason: &str) -> ConnectionError {
    ConnectionError::Transport {
        source: TransportError {
            kind: VarInt::from_u32(0x01),
            frame_type: VarInt::from_u32(0x00),
            reason: reason.to_owned().into(),
        },
    }
}

// ---------------------------------------------------------------------------
// TestLifecycle: simple lifecycle that can be alive or have a terminal error
// ---------------------------------------------------------------------------

struct TestLifecycle {
    terminal_error: SetOnce<ConnectionError>,
}

impl TestLifecycle {
    fn new() -> Self {
        Self {
            terminal_error: SetOnce::new(),
        }
    }

    fn set_terminal_error(&self, error: ConnectionError) {
        let _ = self.terminal_error.set(error);
    }
}

impl quic::Lifecycle for TestLifecycle {
    fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

    fn check(&self) -> Result<(), ConnectionError> {
        match self.terminal_error.peek() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn closed(&self) -> ConnectionError {
        match self.terminal_error.peek() {
            Some(error) => error,
            None => pending().await,
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelReader: mpsc-backed ReadStream
// ---------------------------------------------------------------------------

struct ChannelReader {
    stream_id: VarInt,
    rx: mpsc::Receiver<Bytes>,
}

impl quic::GetStreamId for ChannelReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl quic::StopStream for ChannelReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.get_mut().rx.close();
        Poll::Ready(Ok(()))
    }
}

impl Stream for ChannelReader {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx).map(|opt| opt.map(Ok))
    }
}

// ReadStream blanket impl exists for S: StopStream + GetStreamId + Stream<Item = Result<Bytes, StreamError>> + Send + Any

// ---------------------------------------------------------------------------
// ChannelWriter: mpsc-backed WriteStream
// ---------------------------------------------------------------------------

struct ChannelWriter {
    stream_id: VarInt,
    tx: Option<mpsc::Sender<Bytes>>,
}

impl quic::GetStreamId for ChannelWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl quic::CancelStream for ChannelWriter {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.get_mut().tx = None;
        Poll::Ready(Ok(()))
    }
}

impl Sink<Bytes> for ChannelWriter {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.tx.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(StreamError::Connection {
                source: test_connection_error("writer closed"),
            }))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if let Some(tx) = &this.tx {
            tx.try_send(item).map_err(|_| StreamError::Connection {
                source: test_connection_error("send failed"),
            })
        } else {
            Err(StreamError::Connection {
                source: test_connection_error("writer closed"),
            })
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().tx = None;
        Poll::Ready(Ok(()))
    }
}

// WriteStream blanket impl exists for S: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + Send + Any

// ---------------------------------------------------------------------------
// StreamableConnection: mock connection that supports actual data transfer
// ---------------------------------------------------------------------------

/// Data-plane handles returned to the test after pushing a bidi stream pair.
struct BiStreamTestHandles {
    /// Send data into the ChannelReader (simulates incoming QUIC data).
    tx_to_reader: mpsc::Sender<Bytes>,
    /// Receive data from the ChannelWriter (data sent by the client via pipe).
    rx_from_writer: mpsc::Receiver<Bytes>,
}

struct StreamableConnection {
    lifecycle: Arc<TestLifecycle>,
    bidi_streams: Mutex<VecDeque<(ChannelReader, ChannelWriter)>>,
}

impl StreamableConnection {
    fn new() -> (Arc<Self>, Arc<TestLifecycle>) {
        let lc = Arc::new(TestLifecycle::new());
        let conn = Arc::new(Self {
            lifecycle: lc.clone(),
            bidi_streams: Mutex::new(VecDeque::new()),
        });
        (conn, lc)
    }

    /// Pre-fill one bidi stream pair. Returns test handles to inject/read data.
    async fn push_bidi(&self) -> BiStreamTestHandles {
        let stream_id = next_stream_id();
        let (reader_tx, reader_rx) = mpsc::channel(64);
        let (writer_tx, writer_rx) = mpsc::channel(64);
        let reader = ChannelReader {
            stream_id,
            rx: reader_rx,
        };
        let writer = ChannelWriter {
            stream_id,
            tx: Some(writer_tx),
        };
        self.bidi_streams.lock().await.push_back((reader, writer));
        BiStreamTestHandles {
            tx_to_reader: reader_tx,
            rx_from_writer: writer_rx,
        }
    }
}

impl quic::ManageStream for StreamableConnection {
    type StreamReader = ChannelReader;
    type StreamWriter = ChannelWriter;

    async fn open_bi(&self) -> Result<(ChannelReader, ChannelWriter), ConnectionError> {
        self.bidi_streams
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| test_connection_error("no bidi streams available"))
    }

    async fn open_uni(&self) -> Result<ChannelWriter, ConnectionError> {
        Err(test_connection_error("open_uni not implemented"))
    }

    async fn accept_bi(&self) -> Result<(ChannelReader, ChannelWriter), ConnectionError> {
        Err(test_connection_error("accept_bi not implemented"))
    }

    async fn accept_uni(&self) -> Result<ChannelReader, ConnectionError> {
        Err(test_connection_error("accept_uni not implemented"))
    }
}

impl quic::Lifecycle for StreamableConnection {
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

// Dummy agent types for WithLocalAgent / WithRemoteAgent
#[derive(Debug)]
struct NoAgent;

impl crate::quic::agent::LocalAgent for NoAgent {
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
    ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, crate::quic::agent::SignError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl crate::quic::agent::RemoteAgent for NoAgent {
    fn name(&self) -> &str {
        "none"
    }

    fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
        &[]
    }
}

impl quic::WithLocalAgent for StreamableConnection {
    type LocalAgent = NoAgent;
    async fn local_agent(&self) -> Result<Option<NoAgent>, ConnectionError> {
        Ok(None)
    }
}

impl quic::WithRemoteAgent for StreamableConnection {
    type RemoteAgent = NoAgent;
    async fn remote_agent(&self) -> Result<Option<NoAgent>, ConnectionError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// MockListen: feeds connections via mpsc channel
// ---------------------------------------------------------------------------

struct MockListen {
    rx: mpsc::Receiver<Arc<StreamableConnection>>,
}

impl quic::Listen for MockListen {
    type Connection = Arc<StreamableConnection>;
    type Error = ConnectionError;

    async fn accept(&mut self) -> Result<Arc<StreamableConnection>, ConnectionError> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| test_connection_error("listener closed"))
    }

    async fn shutdown(&self) -> Result<(), ConnectionError> {
        Ok(())
    }
}

// Arc<StreamableConnection> needs Connection trait blanket impls
impl quic::ManageStream for Arc<StreamableConnection> {
    type StreamReader = ChannelReader;
    type StreamWriter = ChannelWriter;

    async fn open_bi(&self) -> Result<(ChannelReader, ChannelWriter), ConnectionError> {
        StreamableConnection::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<ChannelWriter, ConnectionError> {
        StreamableConnection::open_uni(self).await
    }

    async fn accept_bi(&self) -> Result<(ChannelReader, ChannelWriter), ConnectionError> {
        StreamableConnection::accept_bi(self).await
    }

    async fn accept_uni(&self) -> Result<ChannelReader, ConnectionError> {
        StreamableConnection::accept_uni(self).await
    }
}

impl quic::Lifecycle for Arc<StreamableConnection> {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        StreamableConnection::close(self, code, reason);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        StreamableConnection::check(self)
    }

    async fn closed(&self) -> ConnectionError {
        StreamableConnection::closed(self).await
    }
}

impl quic::WithLocalAgent for Arc<StreamableConnection> {
    type LocalAgent = NoAgent;
    async fn local_agent(&self) -> Result<Option<NoAgent>, ConnectionError> {
        Ok(None)
    }
}

impl quic::WithRemoteAgent for Arc<StreamableConnection> {
    type RemoteAgent = NoAgent;
    async fn remote_agent(&self) -> Result<Option<NoAgent>, ConnectionError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// MockConnect: connects to a pre-staged connection
// ---------------------------------------------------------------------------

struct MockConnect {
    conn: Mutex<Option<Arc<StreamableConnection>>>,
}

impl quic::Connect for MockConnect {
    type Connection = Arc<StreamableConnection>;
    type Error = ConnectionError;

    async fn connect<'a>(
        &'a self,
        _server: &'a http::uri::Authority,
    ) -> Result<Arc<StreamableConnection>, ConnectionError> {
        self.conn
            .lock()
            .await
            .take()
            .ok_or_else(|| test_connection_error("no connection staged"))
    }
}

// =========================================================================
// Tests
// =========================================================================

/// Establish a listen pair (server ListenAdapter ↔ client IpcListener).
///
/// Returns (IpcListener, connection_sender) so tests can inject connections.
async fn setup_listen_pair() -> (
    IpcListener<remoc::codec::Default>,
    mpsc::Sender<Arc<StreamableConnection>>,
) {
    use super::IpcListenClient;

    let (conn_tx, conn_rx) = mpsc::channel(4);
    let mock_listen = MockListen { rx: conn_rx };

    let (server_mux, client_mux) = MuxChannel::pair_for_test().unwrap();

    let (server_sink, server_stream) = server_mux.split().unwrap();
    let fd_sender = server_sink.fd_sender();

    let (client_sink, client_stream) = client_mux.split().unwrap();
    let client_fd_registry = client_stream.fd_registry();

    // Both sides must handshake concurrently
    let server_task = tokio::spawn(async move {
        let (remoc_conn, mut tx, _rx) =
            remoc::Connect::framed::<_, _, IpcListenClient, (), remoc::codec::Default>(
                remoc::Cfg::default(),
                server_sink,
                server_stream,
            )
            .await
            .unwrap();
        tokio::spawn(remoc_conn);

        let adapter = ListenAdapter::<_, remoc::codec::Default>::new(mock_listen, fd_sender);
        let (server, listen_client) =
            IpcListenServerSharedMut::new(Arc::new(tokio::sync::RwLock::new(adapter)), 64);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        tx.send(listen_client).await.unwrap();
    });

    let client_task = tokio::spawn(async move {
        let (remoc_conn, _tx, mut rx) =
            remoc::Connect::framed::<_, _, (), IpcListenClient, remoc::codec::Default>(
                remoc::Cfg::default(),
                client_sink,
                client_stream,
            )
            .await
            .unwrap();
        tokio::spawn(remoc_conn);

        let listen_client = rx.recv().await.unwrap().unwrap();
        IpcListener::new(listen_client, client_fd_registry)
    });

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    server_result.unwrap();
    let listener = client_result.unwrap();
    (listener, conn_tx)
}

#[tokio::test]
async fn listen_accept_bootstrap() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    // Inject a StreamableConnection (no bidi streams needed for this test)
    let (conn, _lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    // Client accepts — should get IpcConnectionHandle
    let handle = quic::Listen::accept(&mut listener).await.unwrap();
    assert!(quic::Lifecycle::check(&handle).is_ok());

    // Agent should be None since mock returns None
    let local = quic::WithLocalAgent::local_agent(&handle).await.unwrap();
    assert!(local.is_none());
    let remote = quic::WithRemoteAgent::remote_agent(&handle).await.unwrap();
    assert!(remote.is_none());
}

#[tokio::test]
async fn connect_roundtrip() {
    use super::IpcConnectClient;

    let (conn, _lc) = StreamableConnection::new();
    let mock_connect = MockConnect {
        conn: Mutex::new(Some(conn)),
    };

    let (server_mux, client_mux) = MuxChannel::pair_for_test().unwrap();

    let (server_sink, server_stream) = server_mux.split().unwrap();
    let fd_sender = server_sink.fd_sender();

    let (client_sink, client_stream) = client_mux.split().unwrap();
    let client_fd_registry = client_stream.fd_registry();

    // Both sides must handshake concurrently
    let server_task = tokio::spawn(async move {
        let (remoc_conn, mut tx, _rx) =
            remoc::Connect::framed::<_, _, IpcConnectClient, (), remoc::codec::Default>(
                remoc::Cfg::default(),
                server_sink,
                server_stream,
            )
            .await
            .unwrap();
        tokio::spawn(remoc_conn);

        let adapter = ConnectAdapter::<_, remoc::codec::Default>::new(mock_connect, fd_sender);
        let (server, connect_client) = IpcConnectServerShared::new(Arc::new(adapter), 64);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        tx.send(connect_client).await.unwrap();
    });

    let client_task = tokio::spawn(async move {
        let (remoc_conn, _tx, mut rx) =
            remoc::Connect::framed::<_, _, (), IpcConnectClient, remoc::codec::Default>(
                remoc::Cfg::default(),
                client_sink,
                client_stream,
            )
            .await
            .unwrap();
        tokio::spawn(remoc_conn);

        let connect_client = rx.recv().await.unwrap().unwrap();
        IpcConnector::<remoc::codec::Default>::new(connect_client, client_fd_registry)
    });

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    server_result.unwrap();
    let connector = client_result.unwrap();

    let authority: http::uri::Authority = "test.example".parse().unwrap();
    let handle = quic::Connect::connect(&connector, &authority)
        .await
        .unwrap();
    assert!(quic::Lifecycle::check(&handle).is_ok());
}

#[tokio::test]
async fn lifecycle_propagation() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();
    assert!(quic::Lifecycle::check(&handle).is_ok());

    // close() should not panic
    quic::Lifecycle::close(&handle, Code::H3_NO_ERROR, "test shutdown".into());

    // Inject terminal error on the server side
    let err = test_connection_error("connection reset by peer");
    lc.set_terminal_error(err);

    // closed() should return the error
    let terminal = quic::Lifecycle::closed(&handle).await;
    match terminal {
        ConnectionError::Transport { source } => {
            assert!(source.reason.contains("connection reset by peer"));
        }
        other => panic!("expected transport error, got {other:?}"),
    }

    // check() should now return Err
    assert!(quic::Lifecycle::check(&handle).is_err());
}

#[tokio::test]
async fn open_bi_data_transfer() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, _lc) = StreamableConnection::new();
    let mut test_handles = conn.push_bidi().await;
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    // Open a bidi stream through the IPC chain
    let (mut reader, mut writer) = quic::ManageStream::open_bi(&handle).await.unwrap();

    // Server → Client: inject data into the mock QUIC reader → bridge → pipe → PipeReader
    test_handles
        .tx_to_reader
        .send(Bytes::from_static(b"hello from server"))
        .await
        .unwrap();

    let chunk = reader.next().await.unwrap().unwrap();
    assert_eq!(chunk.as_ref(), b"hello from server");

    // Client → Server: PipeWriter → pipe → bridge → mock QUIC writer → test rx
    use futures::SinkExt;
    writer
        .send(Bytes::from_static(b"hello from client"))
        .await
        .unwrap();

    let received = test_handles.rx_from_writer.recv().await.unwrap();
    assert_eq!(received.as_ref(), b"hello from client");
}

#[tokio::test]
async fn open_bi_unavailable() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    // Use a StreamableConnection with no bidi streams pre-filled
    let (conn, _lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    // open_bi should fail because no streams are in the queue
    let result = quic::ManageStream::open_bi(&handle).await;
    assert!(result.is_err());
}
