use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::*;

#[derive(Default)]
struct Io {
    bytes: VecDeque<u8>,
    writes_before_failure: Option<usize>,
    stop_codes: Option<Arc<Mutex<Vec<u64>>>>,
    cancel_codes: Option<Arc<Mutex<Vec<u64>>>>,
}

impl Io {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.iter().copied().collect(),
            ..Self::default()
        }
    }

    fn fail_after_writes(writes: usize) -> Self {
        Self {
            writes_before_failure: Some(writes),
            ..Self::default()
        }
    }

    fn recording_stops(codes: Arc<Mutex<Vec<u64>>>) -> Self {
        Self {
            stop_codes: Some(codes),
            ..Self::default()
        }
    }

    fn recording_cancels(codes: Arc<Mutex<Vec<u64>>>) -> Self {
        Self {
            cancel_codes: Some(codes),
            ..Self::default()
        }
    }
}

impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while buf.remaining() > 0 {
            let Some(byte) = self.bytes.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(writes) = &mut self.writes_before_failure {
            if *writes == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "control stream write failed",
                )));
            }
            *writes -= 1;
        }
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl StopSending for Io {
    fn stop(&mut self, code: u64) {
        if let Some(codes) = &self.stop_codes {
            codes.lock().unwrap().push(code);
        }
    }
}

impl CancelStream for Io {
    fn cancel(&mut self, code: u64) {
        if let Some(codes) = &self.cancel_codes {
            codes.lock().unwrap().push(code);
        }
    }
}

impl crate::TransportError for Io {
    fn map_error(error: io::Error) -> crate::Error {
        crate::Error::from_stream_io(error)
    }
}

type BiStream = (u64, (Io, Io));

struct TestTransport {
    open: Mutex<Option<Option<BiStream>>>,
    accept: Mutex<Option<Result<BiStream>>>,
    closes: AtomicUsize,
    uni_writes_before_failure: Option<usize>,
    open_ready: Option<Arc<tokio::sync::Notify>>,
}

impl TestTransport {
    fn new(open: Option<BiStream>, accept: Result<BiStream>) -> Self {
        Self {
            open: Mutex::new(Some(open)),
            accept: Mutex::new(Some(accept)),
            closes: AtomicUsize::new(0),
            uni_writes_before_failure: None,
            open_ready: None,
        }
    }

    fn failing_goaway(mut self) -> Self {
        self.uni_writes_before_failure = Some(1);
        self
    }

    fn wait_to_open(mut self, ready: Arc<tokio::sync::Notify>) -> Self {
        self.open_ready = Some(ready);
        self
    }
}

impl Transport for TestTransport {
    type StreamReader = Io;
    type StreamWriter = Io;

    fn role(&self) -> crate::Role {
        crate::Role::Client
    }
    async fn open_bi(&self) -> Result<Option<(u64, (Io, Io))>> {
        if let Some(ready) = &self.open_ready {
            ready.notified().await;
        }
        Ok(self.open.lock().unwrap().take().unwrap())
    }
    async fn accept_bi(&self) -> Result<(u64, (Io, Io))> {
        self.accept.lock().unwrap().take().unwrap()
    }
    async fn open_uni(&self) -> Result<Option<(u64, Io)>> {
        Ok(Some((
            2,
            self.uni_writes_before_failure
                .map_or_else(Io::default, Io::fail_after_writes),
        )))
    }
    async fn accept_uni(&self) -> Result<(u64, Io)> {
        Err(ErrorCode::InternalError.connection("unused"))
    }
    fn close(&self, _: String, _: u64) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn connection(transport: TestTransport) -> H3Connection<TestTransport> {
    let settings = Arc::new(Settings::default());
    H3Connection {
        transport: Arc::new(transport),
        qpack: ArcQpack::new(&settings).unwrap(),
        control: Arc::new(control::Control::new(settings)),
        bi_streams: ArcBiStreams::new(crate::Role::Client),
    }
}

#[tokio::test]
async fn bidirectional_admission_reports_transport_and_identifier_errors() {
    let error = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("accept failed")),
    ))
    .open_bi()
    .await
    .err()
    .expect("opening an unavailable stream must fail");
    assert_eq!(error.code, ErrorCode::StreamCreationError);

    let invalid = (1_u64 << 62, (Io::default(), Io::default()));
    let invalid_connection = connection(TestTransport::new(None, Ok(invalid)));
    let error = invalid_connection
        .accept_bi()
        .await
        .err()
        .expect("accepting an invalid stream identifier must fail");
    assert_eq!(error.code, ErrorCode::InternalError);

    let opened = connection(TestTransport::new(
        Some((0, (Io::default(), Io::default()))),
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    assert!(opened.open_bi().await.is_ok());
    let accepted = connection(TestTransport::new(
        None,
        Ok((1, (Io::default(), Io::default()))),
    ));
    assert!(accepted.accept_bi().await.is_ok());
}

#[tokio::test]
async fn open_bi_rejects_both_halves_if_peer_goaway_arrives_while_pending() {
    let ready = Arc::new(tokio::sync::Notify::new());
    let stop_codes = Arc::new(Mutex::new(Vec::new()));
    let cancel_codes = Arc::new(Mutex::new(Vec::new()));
    let connection = connection(
        TestTransport::new(
            Some((
                0,
                (
                    Io::recording_stops(stop_codes.clone()),
                    Io::recording_cancels(cancel_codes.clone()),
                ),
            )),
            Err(ErrorCode::InternalError.connection("unused")),
        )
        .wait_to_open(ready.clone()),
    );
    let mut opening = Box::pin(connection.open_bi());

    poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    connection
        .bi_streams
        .lock()
        .unwrap()
        .on_goaway(
            qbase::sid::StreamId::new(crate::Role::Client, qbase::sid::Dir::Bi, 0),
            connection.qpack.clone(),
        )
        .unwrap();

    ready.notify_one();
    let error = match opening.await {
        Ok(_) => panic!("peer GOAWAY must reject a stream returned after admission closed"),
        Err(error) => error,
    };

    assert_eq!(error.code, ErrorCode::RequestRejected);
    assert!(matches!(error, Error::Stream(_)));
    assert_eq!(
        *stop_codes.lock().unwrap(),
        [ErrorCode::RequestRejected.as_u64()]
    );
    assert_eq!(
        *cancel_codes.lock().unwrap(),
        [ErrorCode::RequestRejected.as_u64()]
    );
}

#[tokio::test]
async fn local_goaway_blocks_opening_and_accepting() {
    let connection = connection(TestTransport::new(
        Some((0, (Io::default(), Io::default()))),
        Ok((1, (Io::default(), Io::default()))),
    ));
    connection
        .bi_streams
        .lock()
        .unwrap()
        .goaway(connection.qpack())
        .unwrap();
    assert_eq!(
        connection.accept_bi().await.err().unwrap().code,
        ErrorCode::RequestRejected
    );
    assert_eq!(
        connection.open_bi().await.err().unwrap().code,
        ErrorCode::RequestRejected
    );
}

#[tokio::test]
async fn unidirectional_stream_types_and_duplicates_fail_the_connection() {
    let client_push = reject_push_stream(Role::Client);
    assert_eq!(client_push.code, ErrorCode::IdError);
    assert!(matches!(client_push, Error::Connection(_)));
    let server_push = reject_push_stream(Role::Server);
    assert_eq!(server_push.code, ErrorCode::StreamCreationError);
    assert!(matches!(server_push, Error::Connection(_)));

    for bytes in [
        &[][..],
        &[1][..],
        &[2][..],
        &[3][..],
        &[0][..],
        &[0, 4, 0, 7, 1, 0][..],
    ] {
        let connection = connection(TestTransport::new(
            None,
            Err(ErrorCode::InternalError.connection("unused")),
        ));
        connection
            .clone()
            .receive_uni(Io::from(bytes), Arc::new(AtomicU8::new(0)))
            .await;
        if !bytes.is_empty() {
            assert!(connection.qpack().error().is_some());
        }
    }

    let connection = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    connection
        .clone()
        .receive_uni(Io::from(&[0]), Arc::new(AtomicU8::new(1)))
        .await;
    assert_eq!(
        connection.qpack().error().unwrap().code,
        ErrorCode::StreamCreationError
    );
}

#[tokio::test]
async fn goaway_notifies_local_waiters_and_closes_after_peer_goaway() {
    let connection = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    let local = connection.local_goaway();
    let qpack = connection.qpack.clone();
    connection
        .bi_streams
        .lock()
        .unwrap()
        .on_goaway(
            qbase::sid::StreamId::new(crate::Role::Client, qbase::sid::Dir::Bi, 0),
            qpack.clone(),
        )
        .unwrap();
    let transport = connection.transport.clone();
    let control = connection.control.clone();
    let control_transport = transport.clone();
    let control_qpack = qpack.clone();
    control
        .open_uni_and_send_setting(control_transport, control_qpack)
        .await
        .unwrap();
    let shutdown = connection.goaway();
    local.await;
    assert_eq!(transport.closes.load(Ordering::SeqCst), 0);
    shutdown.await.unwrap();
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn goaway_waits_for_local_settings() {
    let connection = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    let control = connection.control.clone();
    let transport = connection.transport.clone();
    let qpack = connection.qpack.clone();
    let bi_streams = connection.bi_streams.clone();
    let mut shutdown = Box::pin(connection.goaway());

    poll_fn(|cx| {
        assert!(shutdown.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(transport.closes.load(Ordering::SeqCst), 0);

    control
        .open_uni_and_send_setting(transport.clone(), qpack.clone())
        .await
        .unwrap();
    bi_streams
        .lock()
        .unwrap()
        .on_goaway(
            qbase::sid::StreamId::new(crate::Role::Client, qbase::sid::Dir::Bi, 0),
            qpack,
        )
        .unwrap();

    shutdown.await.unwrap();
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn goaway_write_failure_fails_and_closes_the_connection() {
    let connection = connection(
        TestTransport::new(None, Err(ErrorCode::InternalError.connection("unused")))
            .failing_goaway(),
    );
    connection
        .control
        .open_uni_and_send_setting(connection.transport.clone(), connection.qpack.clone())
        .await
        .unwrap();
    let transport = connection.transport.clone();
    let qpack = connection.qpack.clone();

    let error = connection.goaway().await.unwrap_err();

    assert_eq!(error.code, ErrorCode::ClosedCriticalStream);
    assert_eq!(qpack.error(), Some(error));
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn constructor_starts_critical_stream_tasks_and_io_supports_writes() {
    let probe = TestTransport::new(None, Err(ErrorCode::InternalError.connection("unused")));
    assert_eq!(
        probe.accept_uni().await.err().unwrap().code,
        ErrorCode::InternalError
    );
    let connection = H3Connection::new(
        TestTransport::new(None, Err(ErrorCode::InternalError.connection("unused"))),
        Settings::default(),
    )
    .unwrap();
    tokio::task::yield_now().await;
    assert!(connection.qpack().error().is_some());

    let mut io = Io::default();
    io.write_all(b"test").await.unwrap();
    io.flush().await.unwrap();
    io.shutdown().await.unwrap();
}

#[tokio::test]
async fn pool_registers_and_drains_established_connections() {
    let pool = crate::Pool::new(|_: u8| async {
        Err::<H3Connection<TestTransport>, crate::Error>(
            ErrorCode::InternalError.connection("factory should not run"),
        )
    });
    let rejected = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    let connection = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));

    assert!(pool.insert(1, connection.clone()).is_ok());
    assert!(pool.insert(1, connection.clone()).is_err());
    assert!(pool.insert(1, rejected.clone()).is_err());
    assert!(!pool.remove_connection(&1, &rejected));
    let registered = pool.get(&1).await.unwrap();
    assert!(Arc::ptr_eq(&registered.transport, &connection.transport));
    assert_eq!(pool.drain().len(), 1);
    assert!(!pool.remove(&1));
}

#[tokio::test]
async fn pool_keeps_one_connection_from_each_direction() {
    let pool = crate::Pool::new(|_: u8| async {
        Ok::<_, crate::Error>(connection(TestTransport::new(
            None,
            Err(ErrorCode::InternalError.connection("unused")),
        )))
    });
    let outbound = pool.get(&1).await.unwrap();
    assert!(pool.insert(1, outbound.clone()).is_err());
    let inbound = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    let rejected = connection(TestTransport::new(
        None,
        Err(ErrorCode::InternalError.connection("unused")),
    ));
    assert!(pool.insert(1, inbound.clone()).is_ok());
    assert!(pool.insert(1, rejected.clone()).is_err());
    assert!(!pool.remove_connection(&1, &rejected));
    let reused = pool.get(&1).await.unwrap();
    assert!(Arc::ptr_eq(&reused.transport, &outbound.transport));
    assert!(pool.remove_connection(&1, &outbound));
    let reused = pool.get(&1).await.unwrap();
    assert!(Arc::ptr_eq(&reused.transport, &inbound.transport));
    assert_eq!(pool.drain().len(), 1);
}
