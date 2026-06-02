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
use futures::{Sink, SinkExt, Stream, StreamExt, future::pending};
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

fn assert_connection_reason(error: &ConnectionError, expected: &str) {
    match error {
        ConnectionError::Transport { source } => {
            assert!(source.reason.contains(expected), "{source:?}");
        }
        error => panic!("expected transport error containing {expected:?}, got {error:?}"),
    }
}

fn assert_stream_reason(error: &StreamError, expected: &str) {
    match error {
        StreamError::Connection { source } => assert_connection_reason(source, expected),
        error => panic!("expected connection stream error containing {expected:?}, got {error:?}"),
    }
}

fn expect_connection_error<T>(
    result: Result<T, ConnectionError>,
    context: &str,
) -> ConnectionError {
    match result {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
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

/// Data-plane handle for a uni write stream (server opens, client reads).
struct UniWriteTestHandles {
    /// Receive data written by the client through the IPC bridge.
    rx_from_writer: mpsc::Receiver<Bytes>,
}

/// Data-plane handle for a uni read stream (server accepts, client reads).
struct UniReadTestHandles {
    /// Send data into the mock QUIC reader (simulates incoming QUIC data).
    tx_to_reader: mpsc::Sender<Bytes>,
}

struct StreamableConnection {
    lifecycle: Arc<TestLifecycle>,
    bidi_streams: Mutex<VecDeque<(ChannelReader, ChannelWriter)>>,
    uni_write_streams: Mutex<VecDeque<ChannelWriter>>,
    uni_read_streams: Mutex<VecDeque<ChannelReader>>,
}

impl StreamableConnection {
    fn new() -> (Arc<Self>, Arc<TestLifecycle>) {
        let lc = Arc::new(TestLifecycle::new());
        let conn = Arc::new(Self {
            lifecycle: lc.clone(),
            bidi_streams: Mutex::new(VecDeque::new()),
            uni_write_streams: Mutex::new(VecDeque::new()),
            uni_read_streams: Mutex::new(VecDeque::new()),
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

    /// Pre-fill one uni write stream (for `open_uni`).
    /// The mock returns a `ChannelWriter`; the test gets a receiver.
    async fn push_uni_writer(&self) -> UniWriteTestHandles {
        let stream_id = next_stream_id();
        let (writer_tx, writer_rx) = mpsc::channel(64);
        let writer = ChannelWriter {
            stream_id,
            tx: Some(writer_tx),
        };
        self.uni_write_streams.lock().await.push_back(writer);
        UniWriteTestHandles {
            rx_from_writer: writer_rx,
        }
    }

    /// Pre-fill one uni read stream (for `accept_uni`).
    /// The mock returns a `ChannelReader`; the test gets a sender.
    async fn push_uni_reader(&self) -> UniReadTestHandles {
        let stream_id = next_stream_id();
        let (reader_tx, reader_rx) = mpsc::channel(64);
        let reader = ChannelReader {
            stream_id,
            rx: reader_rx,
        };
        self.uni_read_streams.lock().await.push_back(reader);
        UniReadTestHandles {
            tx_to_reader: reader_tx,
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
        self.uni_write_streams
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| test_connection_error("no uni write streams available"))
    }

    async fn accept_bi(&self) -> Result<(ChannelReader, ChannelWriter), ConnectionError> {
        Err(test_connection_error("accept_bi not implemented"))
    }

    async fn accept_uni(&self) -> Result<ChannelReader, ConnectionError> {
        self.uni_read_streams
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| test_connection_error("no uni read streams available"))
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

// Dummy authority types for WithLocalAuthority / WithRemoteAuthority
#[derive(Debug)]
struct NoAuthority;

impl dhttp_identity::identity::LocalAuthority for NoAuthority {
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
    ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl dhttp_identity::identity::RemoteAuthority for NoAuthority {
    fn name(&self) -> &str {
        "none"
    }

    fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
        &[]
    }
}

impl quic::WithLocalAuthority for StreamableConnection {
    type LocalAuthority = NoAuthority;
    async fn local_authority(&self) -> Result<Option<NoAuthority>, ConnectionError> {
        Ok(None)
    }
}

impl quic::WithRemoteAuthority for StreamableConnection {
    type RemoteAuthority = NoAuthority;
    async fn remote_authority(&self) -> Result<Option<NoAuthority>, ConnectionError> {
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
    type Connection = StreamableConnection;
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

// ---------------------------------------------------------------------------
// MockConnect: connects to a pre-staged connection
// ---------------------------------------------------------------------------

struct MockConnect {
    conn: Mutex<Option<Arc<StreamableConnection>>>,
}

impl quic::Connect for MockConnect {
    type Connection = StreamableConnection;
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
    let server_fd_transfer = server_stream.fd_transfer(server_sink.fd_sender());

    let (client_sink, client_stream) = client_mux.split().unwrap();
    let client_fd_transfer = client_stream.fd_transfer(client_sink.fd_sender());

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

        let adapter =
            ListenAdapter::<_, remoc::codec::Default>::new(mock_listen, server_fd_transfer);
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
        IpcListener::new(listen_client, client_fd_transfer)
    });

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    server_result.unwrap();
    let listener = client_result.unwrap();
    (listener, conn_tx)
}

#[tokio::test]
async fn direct_lifecycle_and_stream_helpers_cover_control_paths() {
    use quic::{CancelStreamExt, GetStreamIdExt, StopStreamExt};

    let lifecycle = TestLifecycle::new();
    assert!(quic::Lifecycle::check(&lifecycle).is_ok());
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            quic::Lifecycle::closed(&lifecycle),
        )
        .await
        .is_err(),
        "open lifecycle should keep closed() pending"
    );
    let terminal = test_connection_error("direct lifecycle terminal");
    lifecycle.set_terminal_error(terminal);
    assert_connection_reason(
        &quic::Lifecycle::check(&lifecycle).expect_err("terminal lifecycle should fail check"),
        "direct lifecycle terminal",
    );
    assert_connection_reason(
        &quic::Lifecycle::closed(&lifecycle).await,
        "direct lifecycle terminal",
    );

    let (reader_tx, reader_rx) = mpsc::channel(1);
    let mut reader = ChannelReader {
        stream_id: VarInt::from_u32(401),
        rx: reader_rx,
    };
    assert_eq!(
        reader.stream_id().await.expect("reader stream id"),
        VarInt::from_u32(401)
    );
    reader_tx
        .send(Bytes::from_static(b"direct reader"))
        .await
        .expect("send reader bytes");
    assert_eq!(
        reader
            .next()
            .await
            .expect("reader item")
            .expect("reader ok"),
        Bytes::from_static(b"direct reader")
    );
    reader
        .stop(VarInt::from_u32(402))
        .await
        .expect("stop reader");
    assert!(
        reader_tx
            .send(Bytes::from_static(b"after stop"))
            .await
            .is_err(),
        "stopped reader should close its receiver"
    );

    let (writer_tx, mut writer_rx) = mpsc::channel(1);
    let mut writer = ChannelWriter {
        stream_id: VarInt::from_u32(403),
        tx: Some(writer_tx),
    };
    assert_eq!(
        writer.stream_id().await.expect("writer stream id"),
        VarInt::from_u32(403)
    );
    writer
        .send(Bytes::from_static(b"direct writer"))
        .await
        .expect("send writer bytes");
    assert_eq!(
        writer_rx.recv().await.expect("writer bytes"),
        Bytes::from_static(b"direct writer")
    );
    writer.close().await.expect("close writer");
    assert!(
        writer_rx.recv().await.is_none(),
        "closed writer should drop its sender"
    );
    let error = writer
        .send(Bytes::from_static(b"after close"))
        .await
        .expect_err("closed writer should reject writes");
    assert_stream_reason(&error, "writer closed");

    let (writer_tx, mut writer_rx) = mpsc::channel(1);
    let mut writer = ChannelWriter {
        stream_id: VarInt::from_u32(404),
        tx: Some(writer_tx),
    };
    writer
        .cancel(VarInt::from_u32(405))
        .await
        .expect("cancel writer");
    assert!(
        writer_rx.recv().await.is_none(),
        "canceled writer should drop its sender"
    );

    let (writer_tx, _writer_rx) = mpsc::channel(1);
    let mut writer = ChannelWriter {
        stream_id: VarInt::from_u32(406),
        tx: Some(writer_tx),
    };
    Pin::new(&mut writer)
        .start_send(Bytes::from_static(b"first"))
        .expect("first try_send should fit");
    let error = Pin::new(&mut writer)
        .start_send(Bytes::from_static(b"second"))
        .expect_err("full channel should fail start_send");
    assert_stream_reason(&error, "send failed");
}

#[tokio::test]
async fn direct_connection_agent_listener_and_connector_helpers_cover_errors() {
    let (conn, lifecycle) = StreamableConnection::new();
    assert_connection_reason(
        &expect_connection_error(
            quic::ManageStream::open_bi(conn.as_ref()).await,
            "empty bidi queue should fail",
        ),
        "no bidi streams available",
    );
    assert_connection_reason(
        &expect_connection_error(
            quic::ManageStream::open_uni(conn.as_ref()).await,
            "empty uni writer queue should fail",
        ),
        "no uni write streams available",
    );
    assert_connection_reason(
        &expect_connection_error(
            quic::ManageStream::accept_bi(conn.as_ref()).await,
            "accept_bi helper is intentionally unavailable",
        ),
        "accept_bi not implemented",
    );
    assert_connection_reason(
        &expect_connection_error(
            quic::ManageStream::accept_uni(conn.as_ref()).await,
            "empty uni reader queue should fail",
        ),
        "no uni read streams available",
    );

    quic::Lifecycle::close(conn.as_ref(), Code::H3_NO_ERROR, "direct close".into());
    quic::Lifecycle::check(conn.as_ref()).expect("connection should start live");
    lifecycle.set_terminal_error(test_connection_error("direct connection terminal"));
    assert_connection_reason(
        &quic::Lifecycle::check(conn.as_ref()).expect_err("terminal connection should fail check"),
        "direct connection terminal",
    );
    assert_connection_reason(
        &quic::Lifecycle::closed(conn.as_ref()).await,
        "direct connection terminal",
    );

    assert!(
        quic::WithLocalAuthority::local_authority(conn.as_ref())
            .await
            .expect("local authority helper should succeed")
            .is_none()
    );
    assert!(
        quic::WithRemoteAuthority::remote_authority(conn.as_ref())
            .await
            .expect("remote authority helper should succeed")
            .is_none()
    );

    let authority = NoAuthority;
    assert_eq!(
        dhttp_identity::identity::LocalAuthority::name(&authority),
        "none"
    );
    assert_eq!(
        dhttp_identity::identity::RemoteAuthority::name(&authority),
        "none"
    );
    assert!(dhttp_identity::identity::LocalAuthority::cert_chain(&authority).is_empty());
    assert!(dhttp_identity::identity::RemoteAuthority::cert_chain(&authority).is_empty());
    assert_eq!(
        dhttp_identity::identity::LocalAuthority::sign_algorithm(&authority),
        rustls::SignatureAlgorithm::ED25519
    );
    assert!(
        dhttp_identity::identity::LocalAuthority::sign(
            &authority,
            rustls::SignatureScheme::ED25519,
            b"payload",
        )
        .await
        .expect("no-authority signing should succeed")
        .is_empty()
    );

    let (tx, rx) = mpsc::channel(1);
    let mut listener = MockListen { rx };
    quic::Listen::shutdown(&listener)
        .await
        .expect("mock listener shutdown should succeed");
    drop(tx);
    assert_connection_reason(
        &expect_connection_error(
            quic::Listen::accept(&mut listener).await,
            "closed listener should fail accept",
        ),
        "listener closed",
    );

    let authority = "direct.example:443"
        .parse::<http::uri::Authority>()
        .expect("authority parses");
    let connector = MockConnect {
        conn: Mutex::new(None),
    };
    assert_connection_reason(
        &expect_connection_error(
            quic::Connect::connect(&connector, &authority).await,
            "unstaged connector should fail",
        ),
        "no connection staged",
    );

    let (conn, _lifecycle) = StreamableConnection::new();
    let connector = MockConnect {
        conn: Mutex::new(Some(conn.clone())),
    };
    let connected = quic::Connect::connect(&connector, &authority)
        .await
        .expect("staged connector should return connection");
    assert!(Arc::ptr_eq(&conn, &connected));
    assert_connection_reason(
        &expect_connection_error(
            quic::Connect::connect(&connector, &authority).await,
            "staged connection should be consumed",
        ),
        "no connection staged",
    );
}

#[tokio::test]
async fn listen_accept_bootstrap() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    // Inject a StreamableConnection (no bidi streams needed for this test)
    let (conn, _lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    // Client accepts — should get IpcConnectionHandle
    let handle = quic::Listen::accept(&mut listener).await.unwrap();
    assert!(quic::Lifecycle::check(handle.as_ref()).is_ok());

    // Authority should be None since mock returns None
    let local = quic::WithLocalAuthority::local_authority(handle.as_ref())
        .await
        .unwrap();
    assert!(local.is_none());
    let remote = quic::WithRemoteAuthority::remote_authority(handle.as_ref())
        .await
        .unwrap();
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
    let server_fd_transfer = server_stream.fd_transfer(server_sink.fd_sender());

    let (client_sink, client_stream) = client_mux.split().unwrap();
    let client_fd_transfer = client_stream.fd_transfer(client_sink.fd_sender());

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

        let adapter =
            ConnectAdapter::<_, remoc::codec::Default>::new(mock_connect, server_fd_transfer);
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
        IpcConnector::<remoc::codec::Default>::new(connect_client, client_fd_transfer)
    });

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    server_result.unwrap();
    let connector = client_result.unwrap();

    let authority: http::uri::Authority = "test.example".parse().unwrap();
    let handle = quic::Connect::connect(&connector, &authority)
        .await
        .unwrap();
    assert!(quic::Lifecycle::check(handle.as_ref()).is_ok());
}

#[tokio::test]
async fn lifecycle_propagation() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();
    assert!(quic::Lifecycle::check(handle.as_ref()).is_ok());

    // close() should not panic
    quic::Lifecycle::close(handle.as_ref(), Code::H3_NO_ERROR, "test shutdown".into());

    // Inject terminal error on the server side
    let err = test_connection_error("connection reset by peer");
    lc.set_terminal_error(err);

    // closed() should return the error
    let terminal = quic::Lifecycle::closed(handle.as_ref()).await;
    match terminal {
        ConnectionError::Transport { source } => {
            assert!(source.reason.contains("connection reset by peer"));
        }
        other => panic!("expected transport error, got {other:?}"),
    }

    // check() should now return Err
    assert!(quic::Lifecycle::check(handle.as_ref()).is_err());
}

#[tokio::test]
async fn open_bi_data_transfer() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, _lc) = StreamableConnection::new();
    let mut test_handles = conn.push_bidi().await;
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    // Open a bidi stream through the IPC chain
    let (mut reader, mut writer) = quic::ManageStream::open_bi(handle.as_ref()).await.unwrap();

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
    let result = quic::ManageStream::open_bi(handle.as_ref()).await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Phase 4: Uni-directional stream tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_uni_data_transfer() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, _lc) = StreamableConnection::new();
    let mut test_handles = conn.push_uni_writer().await;
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    // Open a uni stream — the client gets a writer
    let mut writer = quic::ManageStream::open_uni(handle.as_ref()).await.unwrap();

    // Client → Server: PipeWriter → pipe → bridge → mock QUIC writer → test rx
    use futures::SinkExt;
    writer.send(Bytes::from_static(b"uni hello")).await.unwrap();

    let received = test_handles.rx_from_writer.recv().await.unwrap();
    assert_eq!(received.as_ref(), b"uni hello");
}

#[tokio::test]
async fn accept_uni_data_transfer() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, _lc) = StreamableConnection::new();
    let test_handles = conn.push_uni_reader().await;
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    // Accept a uni stream — the client gets a reader
    let mut reader = quic::ManageStream::accept_uni(handle.as_ref())
        .await
        .unwrap();

    // Server → Client: inject data into mock QUIC reader → bridge → pipe → client
    test_handles
        .tx_to_reader
        .send(Bytes::from_static(b"uni from server"))
        .await
        .unwrap();

    let chunk = reader.next().await.unwrap().unwrap();
    assert_eq!(chunk.as_ref(), b"uni from server");
}

#[tokio::test]
async fn open_uni_unavailable() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    // No uni streams pre-filled
    let (conn, _lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    let result = quic::ManageStream::open_uni(handle.as_ref()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn accept_uni_unavailable() {
    let (mut listener, conn_tx) = setup_listen_pair().await;

    let (conn, _lc) = StreamableConnection::new();
    conn_tx.send(conn).await.unwrap();

    let handle = quic::Listen::accept(&mut listener).await.unwrap();

    let result = quic::ManageStream::accept_uni(handle.as_ref()).await;
    assert!(result.is_err());
}
