use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use super::*;

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    flush_ready: bool,
    fail_flush: bool,
    finished: bool,
}

struct Writer(Arc<Mutex<Output>>);
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let output = self.0.lock().unwrap();
        if output.fail_flush {
            Poll::Ready(Err(ErrorCode::H3_REQUEST_CANCELLED
                .reason("peer stopped acceptance")
                .into()))
        } else if output.flush_ready {
            Poll::Ready(Ok(()))
        } else {
            // These tests explicitly poll again after changing the gate.
            Poll::Pending
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.lock().unwrap().finished = true;
        Poll::Ready(Ok(()))
    }
}

async fn incoming(method: Method, qpack: &ArcQpack) -> Request {
    let head = headers::RequestHead::new("https://example.com:443/", method).unwrap();
    let mut fields = Vec::new();
    fields.put_head(&head).unwrap();
    let mut wire = Vec::new();
    wire.put_frame(
        &Frame::new(Headers {
            field_section: qpack.encode(0, fields).unwrap(),
        })
        .unwrap(),
    );
    read_request(
        crate::test_support::read_stream(0, Cursor::new(wire)),
        qpack.clone(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn acceptance_flushes_frozen_headers_before_sending_queued_data() {
    let connection = crate::test_support::connection().await;
    let request = incoming(Method::CONNECT, connection.qpack()).await;
    let mut response = Response::default().streaming(8);
    response.set_status(StatusCode::OK);
    response.set_header(header::SERVER, HeaderValue::from_static("original"));
    let mut retained = response.clone();
    let mut producer = response.body();
    producer.write_all(b"queued").await.unwrap();
    let output = Arc::new(Mutex::new(Output::default()));
    let mut accepting = Box::pin(accept_connect(
        &request,
        response,
        crate::test_support::write_stream(0, Writer(output.clone())),
        connection.qpack().clone(),
    ));
    retained.set_status(StatusCode::FORBIDDEN);
    retained.set_header(header::SERVER, HeaderValue::from_static("changed"));
    assert!(
        accepting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let wire = output.lock().unwrap().bytes.clone();
    let mut input = wire.as_slice();
    let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
        panic!("expected HEADERS")
    };
    let head = headers::be_response(
        connection
            .qpack()
            .decode(0, frame.payload.field_section)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(head.status().unwrap(), StatusCode::OK);
    assert_eq!(head.headers[header::SERVER], "original");
    assert!(input.is_empty(), "DATA must wait for HEADERS flush");
    output.lock().unwrap().flush_ready = true;
    tokio::time::timeout(Duration::from_secs(1), accepting)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !output.lock().unwrap().finished,
        "acceptance must not wait for producer FIN"
    );
    producer.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !output.lock().unwrap().finished {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let wire = output.lock().unwrap().bytes.clone();
    let mut input = wire.as_slice();
    assert!(matches!(
        be_frame(&mut input).await.unwrap(),
        H3Frame::Headers(_)
    ));
    assert!(matches!(
        be_frame(&mut input).await.unwrap(),
        H3Frame::Data(_)
    ));
    assert_eq!(input, b"queued");
    request.into_body().stop().await;
}

#[tokio::test]
async fn acceptance_rejects_invalid_metadata_before_sending() {
    for case in [
        "method",
        "status",
        "informational",
        "missing status",
        "length",
    ] {
        let connection = crate::test_support::connection().await;
        let request = incoming(
            if case == "method" {
                Method::GET
            } else {
                Method::CONNECT
            },
            connection.qpack(),
        )
        .await;
        let mut response = Response::default().streaming(1);
        if case != "missing status" {
            response.set_status(match case {
                "status" => StatusCode::FORBIDDEN,
                "informational" => StatusCode::CONTINUE,
                _ => StatusCode::OK,
            });
        }
        if case == "length" {
            response.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        let mut producer = response.body();
        let output = Arc::new(Mutex::new(Output::default()));
        let send = crate::test_support::TestStream::new(Writer(output.clone()));
        let cancelled = send.cancelled.clone();
        let accepting = accept_connect(
            &request,
            response,
            H3WriteStream::new(0, send),
            connection.qpack().clone(),
        );
        assert_eq!(
            producer.write(b"x").await.unwrap_err().code,
            ErrorCode::H3_MESSAGE_ERROR
        );
        assert_eq!(
            accepting.await.unwrap_err().code,
            ErrorCode::H3_MESSAGE_ERROR
        );
        assert!(output.lock().unwrap().bytes.is_empty());
        assert_eq!(
            *cancelled.lock().unwrap(),
            [ErrorCode::H3_MESSAGE_ERROR.as_u64()]
        );
        assert!(connection.qpack().error().is_none());
        request.into_body().stop().await;
    }
}

#[tokio::test]
async fn failed_or_cancelled_acceptance_wakes_producer_and_cancels_sending() {
    for reset in [false, true] {
        let connection = crate::test_support::connection().await;
        let request = incoming(Method::CONNECT, connection.qpack()).await;
        let mut response = Response::default().streaming(1);
        response.set_status(StatusCode::OK);
        let mut producer = response.body();
        producer.write_all(b"x").await.unwrap();
        let output = Arc::new(Mutex::new(Output::default()));
        let send = crate::test_support::TestStream::new(Writer(output.clone()));
        let cancelled = send.cancelled.clone();
        let mut accepting = Box::pin(accept_connect(
            &request,
            response,
            H3WriteStream::new(0, send),
            connection.qpack().clone(),
        ));
        assert!(
            accepting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        if reset {
            producer.clone().reset().await.unwrap();
        } else {
            output.lock().unwrap().fail_flush = true;
        }
        let error = tokio::time::timeout(Duration::from_secs(1), accepting)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::H3_REQUEST_CANCELLED);
        assert_eq!(producer.write(b"blocked").await.unwrap_err(), error);
        if reset {
            assert_eq!(*cancelled.lock().unwrap(), [error.code.as_u64()]);
        } else {
            // The transport failure already closed this direction; do not reset it twice.
            assert!(cancelled.lock().unwrap().is_empty());
        }
        assert!(connection.qpack().error().is_none());
        request.into_body().stop().await;
    }
}
