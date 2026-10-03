use std::{
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::*;
use crate::ErrorCode;

#[derive(Clone, Default)]
struct Io {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<Mutex<Vec<(usize, usize)>>>,
    cancels: Arc<Mutex<Vec<u64>>>,
    shutdowns: Arc<AtomicUsize>,
}

impl AsyncWrite for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes
            .lock()
            .unwrap()
            .push((buf.as_ptr() as usize, buf.len()));
        self.bytes.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

impl CancelStream for Io {
    fn cancel(&mut self, code: u64) {
        self.cancels.lock().unwrap().push(code);
    }
}

impl TransportError for Io {
    fn map_error(error: io::Error) -> Error {
        Error::from_stream_io(error)
    }
}

fn events() -> StreamEventHandler {
    Arc::new(|_| {})
}

struct FailingIo(Error);

impl AsyncWrite for FailingIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self.0.clone().into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.0.clone().into()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.0.clone().into()))
    }
}

impl CancelStream for FailingIo {
    fn cancel(&mut self, _: u64) {}
}

impl TransportError for FailingIo {
    fn map_error(error: io::Error) -> Error {
        Error::from_stream_io(error)
    }
}

#[tokio::test]
async fn terminal_write_errors_report_their_scope() {
    for error in [
        ErrorCode::RequestCancelled.stream("stream stopped"),
        ErrorCode::InternalError.connection("connection failed"),
    ] {
        for operation in 0..3 {
            let reported = Arc::new(Mutex::new(Vec::new()));
            let captured = reported.clone();
            let mut stream = H3WriteStream::new(4, FailingIo(error.clone()), events());
            let shared = stream.state.clone();
            stream.events = Arc::new(move |event| {
                assert!(shared.0.try_lock().is_ok(), "notify outside the state lock");
                captured.lock().unwrap().push(event);
            });
            for _ in 0..2 {
                let result = match operation {
                    0 => stream.write_all(b"x").await,
                    1 => stream.flush().await,
                    _ => stream.shutdown().await,
                };
                assert_eq!(Error::from_stream_io(result.unwrap_err()), error);
            }
            drop(stream);
            assert_eq!(reported.lock().unwrap().as_slice(), [Err(error.clone())]);
        }
    }
}

#[tokio::test]
async fn write_shutdown_notifies_finish_once() {
    let io = Io::default();
    let bytes = io.bytes.clone();
    let cancels = io.cancels.clone();
    let shutdowns = io.shutdowns.clone();
    let completed = Arc::new(AtomicUsize::new(0));
    let count = completed.clone();
    let mut stream = H3WriteStream::new(
        4,
        io,
        Arc::new(move |event| {
            if event.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    let _registered = stream.state.clone();
    assert_eq!(stream.stream_id(), 4);
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    AsyncWriteExt::shutdown(&mut stream).await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        stream.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(&*bytes.lock().unwrap(), b"hello");
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    (&stream).cancel(7);
    assert!(cancels.lock().unwrap().is_empty());
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reject_and_explicit_cancel_report_expected_codes() {
    fn reject<W: CancelStream>(stream: &H3WriteStream<W>) -> bool {
        let error = ErrorCode::RequestRejected.stream("request rejected by GOAWAY");
        stream
            .state
            .fail(error.clone(), |io| io.cancel(error.code.as_u64()))
    }

    let io = Io::default();
    let cancels = io.cancels.clone();
    let mut stream = H3WriteStream::new(8, io, events());
    assert!(reject(&stream));
    assert!(!reject(&stream));
    assert_eq!(
        &*cancels.lock().unwrap(),
        &[ErrorCode::RequestRejected.as_u64()]
    );
    assert_eq!(
        stream.write_all(b"x").await.unwrap_err().kind(),
        io::ErrorKind::Other
    );

    let io = Io::default();
    let cancels = io.cancels.clone();
    let completed = Arc::new(AtomicUsize::new(0));
    let count = completed.clone();
    let stream = H3WriteStream::new(
        12,
        io,
        Arc::new(move |event| {
            let _ = event;
            count.fetch_add(1, Ordering::SeqCst);
        }),
    );
    (&stream).cancel(9);
    assert_eq!(
        &*cancels.lock().unwrap(),
        &[ErrorCode::InternalError.as_u64()]
    );
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    (&stream).cancel(10);
    assert_eq!(
        &*cancels.lock().unwrap(),
        &[ErrorCode::InternalError.as_u64()]
    );
}

#[tokio::test]
async fn message_writers_pass_owned_payload_to_transport_without_copying() {
    for response in [false, true] {
        let data = Bytes::from(vec![42; frame::MAX_DATA_CHUNK + 17]);
        let address = data.as_ptr() as usize;
        let io = Io::default();
        let writes = io.writes.clone();
        let stream = H3WriteStream::new(0, io, events());
        let qpack = crate::qpack::tests::qpack();
        if response {
            let mut body = crate::ArcWndBuf::new(data.len());
            body.write_bytes(data.clone()).await.unwrap();
            body.shutdown().await.unwrap();
            stream
                .write_response(
                    http::Response::new(window_body(body)),
                    http::Method::GET,
                    qpack,
                )
                .await
                .unwrap();
        } else {
            stream
                .write_request(
                    http::Request::builder()
                        .uri("https://example.com/")
                        .body(http_body_util::Full::new(data))
                        .unwrap(),
                    qpack,
                )
                .await
                .unwrap();
        }
        let writes = writes.lock().unwrap();
        assert!(writes.contains(&(address, frame::MAX_DATA_CHUNK)));
        assert!(writes.contains(&(address + frame::MAX_DATA_CHUNK, 17)));
    }
}

#[tokio::test]
async fn message_writers_shutdown_the_underlying_send_stream() {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://example.com/")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let request_io = Io::default();
    let request_cancels = request_io.cancels.clone();
    let request_shutdowns = request_io.shutdowns.clone();
    let request_completed = Arc::new(AtomicUsize::new(0));
    let completed = request_completed.clone();
    let shutdowns = request_shutdowns.clone();
    let request_stream = H3WriteStream::new(
        0,
        request_io,
        Arc::new(move |event| {
            if event.is_ok() {
                assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    request_stream
        .write_request(request, crate::qpack::tests::qpack())
        .await
        .unwrap();
    assert_eq!(request_shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(request_completed.load(Ordering::SeqCst), 1);
    assert!(request_cancels.lock().unwrap().is_empty());

    let mut response_body = crate::ArcWndBuf::new(1);
    response_body.shutdown().await.unwrap();
    let response: http::Response<crate::Body> = http::Response::new(window_body(response_body));
    let response_io = Io::default();
    let response_cancels = response_io.cancels.clone();
    let response_shutdowns = response_io.shutdowns.clone();
    let response_completed = Arc::new(AtomicUsize::new(0));
    let completed = response_completed.clone();
    let shutdowns = response_shutdowns.clone();
    let response_stream = H3WriteStream::new(
        0,
        response_io,
        Arc::new(move |event| {
            if event.is_ok() {
                assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    response_stream
        .write_response(response, http::Method::GET, crate::qpack::tests::qpack())
        .await
        .unwrap();
    assert_eq!(response_shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(response_completed.load(Ordering::SeqCst), 1);
    assert!(response_cancels.lock().unwrap().is_empty());
}

#[tokio::test]
async fn body_cancellation_aborts_request_and_response_writers() {
    let request_body = crate::ArcWndBuf::new(1);
    let request_producer = request_body.clone();
    let request: http::Request<crate::Body> = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://example.com/upload")
        .body(window_body(request_body))
        .unwrap();
    let request_io = Io::default();
    let request_cancels = request_io.cancels.clone();
    let request_writer = tokio::spawn(
        H3WriteStream::new(0, request_io, events())
            .write_request(request, crate::qpack::tests::qpack()),
    );
    tokio::task::yield_now().await;
    request_producer.cancel(ErrorCode::RequestCancelled.as_u64());
    assert_eq!(
        request_writer.await.unwrap().unwrap_err().code,
        ErrorCode::RequestCancelled
    );
    assert_eq!(
        &*request_cancels.lock().unwrap(),
        &[ErrorCode::RequestCancelled.as_u64()]
    );

    let response_body = crate::ArcWndBuf::new(1);
    let response_producer = response_body.clone();
    let response: http::Response<crate::Body> = http::Response::new(window_body(response_body));
    let response_io = Io::default();
    let response_cancels = response_io.cancels.clone();
    let response_writer =
        tokio::spawn(H3WriteStream::new(0, response_io, events()).write_response(
            response,
            http::Method::GET,
            crate::qpack::tests::qpack(),
        ));
    tokio::task::yield_now().await;
    response_producer.cancel(ErrorCode::RequestCancelled.as_u64());
    assert_eq!(
        response_writer.await.unwrap().unwrap_err().code,
        ErrorCode::RequestCancelled
    );
    assert_eq!(
        &*response_cancels.lock().unwrap(),
        &[ErrorCode::RequestCancelled.as_u64()]
    );
}

#[tokio::test]
async fn qpack_failure_releases_unpolled_request_and_response_sources() {
    for response in [false, true] {
        let qpack = crate::qpack::tests::qpack();
        qpack.on_connection_error(ErrorCode::InternalError.connection("qpack failed"));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let guard = scopeguard::guard(tx, |tx| {
            let _ = tx.send(());
        });
        let source = http_body_util::StreamBody::new(futures::stream::poll_fn(move |_| {
            let _ = &guard;
            std::task::Poll::Pending::<
                Option<std::result::Result<http_body::Frame<Bytes>, crate::BoxError>>,
            >
        }))
        .boxed_unsync();
        let stream = H3WriteStream::new(0, Io::default(), events());
        let result = if response {
            stream
                .write_response(http::Response::new(source), http::Method::GET, qpack)
                .await
        } else {
            stream
                .write_request(http::Request::new(source), qpack)
                .await
        };
        assert_eq!(result.unwrap_err().code, ErrorCode::InternalError);
        rx.await.unwrap();
    }
}

#[tokio::test]
async fn dropping_pending_message_releases_source_and_cancels_transport_once() {
    for response in [false, true] {
        let io = Io::default();
        let cancels = io.cancels.clone();
        let (dropped, observed) = tokio::sync::oneshot::channel();
        let source_guard = scopeguard::guard(dropped, |tx| {
            let _ = tx.send(());
        });
        let source = http_body_util::StreamBody::new(futures::stream::poll_fn(move |_| {
            let _ = &source_guard;
            Poll::Pending::<Option<std::result::Result<http_body::Frame<Bytes>, crate::BoxError>>>
        }))
        .boxed_unsync();
        let stream = H3WriteStream::new(0, io, events());
        let qpack = crate::qpack::tests::qpack();
        let mut sending: Pin<Box<dyn Future<Output = crate::Result<()>>>> = if response {
            Box::pin(stream.write_response(http::Response::new(source), http::Method::GET, qpack))
        } else {
            Box::pin(stream.write_request(http::Request::new(source), qpack))
        };
        std::future::poll_fn(|cx| {
            assert!(sending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(sending);
        assert_eq!(observed.await, Ok(()));
        assert_eq!(
            *cancels.lock().unwrap(),
            [ErrorCode::RequestCancelled.as_u64()]
        );
    }
}

fn window_body(window: crate::ArcWndBuf) -> crate::Body {
    let frames = futures::stream::try_unfold(window, |window| async move {
        let bytes = window
            .read_chunk(crate::frame::MAX_DATA_CHUNK)
            .await
            .map_err(Error::from_stream_io)?;
        Ok::<_, Error>((!bytes.is_empty()).then(|| (http_body::Frame::data(bytes), window)))
    });
    http_body_util::StreamBody::new(frames)
        .map_err(Into::into)
        .boxed_unsync()
}
