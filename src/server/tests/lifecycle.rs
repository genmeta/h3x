use super::*;

#[tokio::test]
async fn dropping_last_producer_does_not_finish_or_cancel_sending() {
    use std::task::{Context, Waker};
    let mut response = Response::<Bytes>::default();
    response.set_status(StatusCode::OK);
    let response = response.streaming(1);
    let producer = response.body_handle();
    let buffer = response.message.body_stream();
    let mut sending = Box::pin(crate::server::write_streaming_response(
        response,
        crate::test_support::write_stream(0, tokio::io::sink()),
        crate::test_support::connection().await.qpack().clone(),
        &Method::GET,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(sending.as_mut().poll(&mut cx).is_pending());
    drop(producer);
    assert!(sending.as_mut().poll(&mut cx).is_pending());
    // Only an explicit buffer error terminates the send operation.
    buffer.on_error(
        ErrorCode::H3_REQUEST_CANCELLED.with_reason("test cancels the response producer"),
    );
    assert_eq!(
        (sending.await).map_err(ErrorCode::from),
        Err(ErrorCode::H3_REQUEST_CANCELLED)
    );
}

#[tokio::test]
async fn finished_response_producer_can_drop_before_or_during_send() {
    use std::{
        task::{Context, Waker},
        time::Duration,
    };

    for started in [false, true] {
        let mut response = Response::<Bytes>::default();
        response.set_status(StatusCode::OK);
        let response = response.streaming(5);
        let mut producer = response.clone();
        let mut encoded = Vec::new();
        let mut sending = Box::pin(super::respond(
            response,
            crate::test_support::write_stream(0, &mut encoded),
            crate::test_support::connection().await.qpack().clone(),
            &Method::GET,
        ));
        if started {
            assert!(
                sending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        assert_eq!(producer.write(b"hello").await.unwrap(), 5);
        producer.finish().await.unwrap();
        drop(producer);
        tokio::time::timeout(Duration::from_secs(1), sending)
            .await
            .expect("a finished body must drain after its producer drops")
            .unwrap();

        let mut input = encoded.as_slice();
        assert!(matches!(
            be_frame(&mut input).await.unwrap(),
            H3Frame::Headers(_)
        ));
        let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("the finished response must retain its body");
        };
        assert_eq!(frame.length.into_u64(), 5);
        assert_eq!(input, b"hello");
    }
}

#[tokio::test]
async fn buffered_body_snapshots_and_shared_streams() {
    let message = Message::<headers::RequestHead, Bytes>::post("https://example.com/echo?q=1")
        .unwrap()
        .with_body(crate::Body::new(Bytes::from_static(b"request")));
    let request = common::request::Request::<Read, _>::from(ArcMessage::from(message));
    let mut incoming = common::request::Request::<Write, _>::from(request.message.test_direction());
    incoming.set_body(Bytes::from_static(b"changed"));
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.authority(), "example.com");
    assert_eq!(request.scheme(), "https");
    assert_eq!(request.path(), "/echo?q=1");
    assert_eq!(request.body(), Bytes::from_static(b"request"));

    let mut response = Response::default();
    response
        .set_status(StatusCode::CREATED)
        .set_body(request.body());
    let outgoing = common::response::Response::<Read, _>::from(response.message.test_direction());
    assert_eq!(outgoing.status(), StatusCode::CREATED);
    assert_eq!(outgoing.body(), Bytes::from_static(b"request"));

    let message = Message::<headers::RequestHead, Bytes>::get("https://example.com/")
        .unwrap()
        .with_body(crate::Body::new(ArcWndBuf::new(2)));
    let mut request = common::request::Request::<Read, _>::from(ArcMessage::from(message));
    let mut incoming = common::request::Request::<Write, _>::from(request.message.test_direction());
    let message = Message::<headers::ResponseHead, Bytes>::default()
        .with_body(crate::Body::new(ArcWndBuf::new(2)));
    let mut response = Response::from(ArcMessage::from(message));
    response.set_status(StatusCode::OK);
    let mut outgoing =
        common::response::Response::<Read, _>::from(response.message.test_direction());
    let ((), (), ()) = tokio::join!(
        async {
            assert_eq!(incoming.write(b"ping").await.unwrap(), 2);
            assert_eq!(incoming.write(b"ng").await.unwrap(), 2);
            incoming.finish().await.unwrap();
        },
        async {
            let mut buf = [0; 2];
            while request.read_all(&mut buf).await.unwrap() != 0 {
                assert_eq!(response.write(buf).await.unwrap(), 2);
            }
            response.finish().await.unwrap();
        },
        async {
            let mut buf = [0; 4];
            assert_eq!(outgoing.read_all(&mut buf).await.unwrap(), 4);
            assert_eq!(&buf, b"ping");
            assert_eq!(outgoing.read(&mut buf).await.unwrap(), 0);
            assert_eq!(outgoing.status(), StatusCode::OK);
        }
    );
    request.stop().await;
    assert_eq!(
        ErrorCode::from(incoming.write(b"x").await.unwrap_err()),
        ErrorCode::H3_REQUEST_CANCELLED
    );
    response.reset().await.unwrap();
    assert_eq!(
        ErrorCode::from(outgoing.read(&mut [0]).await.unwrap_err()),
        ErrorCode::H3_REQUEST_CANCELLED
    );
}

#[tokio::test]
async fn streaming_response_termination_reaches_the_producer() {
    use std::{
        future::Future,
        task::{Context, Waker},
        time::Duration,
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        for (error, started) in [
            (ErrorCode::H3_REQUEST_CANCELLED, true),
            (ErrorCode::H3_REQUEST_CANCELLED, false),
            (ErrorCode::H3_REQUEST_REJECTED, true),
            (ErrorCode::H3_INTERNAL_ERROR, true),
            (ErrorCode::H3_INTERNAL_ERROR, false),
        ] {
            let mut response = Response::<Bytes>::default();
            response.set_status(StatusCode::OK);
            let response = response.streaming(1);
            let mut producer = response.clone();
            let bi = Arc::new(crate::protocol::stream::bi::BiStreams::default());
            let qpack = crate::test_support::connection().await;
            let (send, recv) = bi
                .insert(0, crate::test_support::Reader, crate::test_support::Writer)
                .unwrap();
            drop(recv);
            let mut sending = Box::pin(super::respond(
                response,
                send,
                qpack.qpack().clone(),
                &Method::GET,
            ));
            if started {
                assert!(
                    sending
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            if error == ErrorCode::H3_REQUEST_CANCELLED {
                drop(sending);
                producer.clone().reset().await.unwrap();
            } else {
                if error == ErrorCode::H3_REQUEST_REJECTED {
                    for id in bi.goaway(0) {
                        qpack.qpack().cancel(id).unwrap();
                    }
                } else {
                    let _ = crate::Transport::close(
                        qpack.transport.as_ref(),
                        "test terminates the connection during response upload".into(),
                        error.as_u64(),
                    );
                    // These test writers are independent of the transport; apply
                    // the connection's stream closure before resuming body I/O.
                    bi.close(error.with_reason("test closes the stream during response upload"));
                }
                // Resume body I/O so the send operation observes the terminal stream.
                producer.write(b"x").await.unwrap();
                assert_eq!((sending.await).map_err(ErrorCode::from), Err(error));
            }
            assert_eq!(
                (producer.write(b"x").await).map_err(ErrorCode::from),
                Err(error)
            );
            assert_eq!(
                (producer.finish().await).map_err(ErrorCode::from),
                Err(error)
            );
        }
    })
    .await
    .expect("response termination must reach the producer when sending resumes");
}

#[tokio::test]
async fn explicit_stop_stops_pump_when_body_write_resumes() {
    let (mut send, recv) = duplex(64);
    send.write_all(&request_frames(b"", None)).await.unwrap();
    let request = super::accept(
        crate::test_support::read_stream(4, recv),
        crate::test_support::connection().await.qpack().clone(),
    )
    .await
    .unwrap();
    assert!(matches!(&request, Request::Streaming(_)));
    tokio::task::yield_now().await; // Let the receive pump wait for another frame.
    request.into_body().stop().await;
    send.write_all(&[0, 1, b'x']).await.unwrap();
    tokio::task::yield_now().await;
    assert!(send.write_all(b"x").await.is_err());
}

#[test]
fn explicit_stop_cancels_body_after_request_pump_is_dropped() {
    use std::task::{Context, Poll, Waker};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let (request, _peer) = runtime.block_on(async {
        let (mut send, recv) = duplex(64);
        send.write_all(&request_frames(b"", None)).await.unwrap();
        let Request::Streaming(request) = super::accept(
            crate::test_support::read_stream(4, recv),
            crate::test_support::connection().await.qpack().clone(),
        )
        .await
        .unwrap() else {
            panic!("expected streaming request");
        };
        tokio::task::yield_now().await;
        (request, send)
    });
    // The body outlives the receive task aborted by runtime shutdown.
    drop(runtime);
    let mut remaining = request.message.clone();
    let mut stopping = Box::pin(crate::ReadStream::stop(request));
    assert!(
        stopping
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    let mut bytes = [0];
    let mut reading = Box::pin(crate::ReadStream::read(&mut remaining, &mut bytes));
    assert_eq!(
        (reading
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())))
        .map(|result| result.map_err(ErrorCode::from)),
        Poll::Ready(Err(ErrorCode::H3_REQUEST_CANCELLED))
    );
}

#[tokio::test]
async fn explicit_stop_stops_a_pump_blocked_on_full_window() {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::{
        io::{AsyncRead, ReadBuf},
        sync::oneshot,
    };

    struct Tracked {
        bytes: io::Cursor<Vec<u8>>,
        dropped: Option<oneshot::Sender<()>>,
    }
    impl AsyncRead for Tracked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.bytes).poll_read(cx, buf)
        }
    }
    impl Drop for Tracked {
        fn drop(&mut self) {
            let _ = self.dropped.take().unwrap().send(());
        }
    }
    let (dropped, mut observed) = oneshot::channel();
    let reader = Tracked {
        bytes: io::Cursor::new(request_frames(&vec![b'x'; frame::MAX_DATA_CHUNK * 4], None)),
        dropped: Some(dropped),
    };
    let request = crate::server::read_request(
        crate::test_support::read_stream(0, reader),
        crate::test_support::connection().await.qpack().clone(),
    )
    .await
    .unwrap();
    let body = request.into_body();
    // The source is immediately ready; the pump runs until the window fills.
    tokio::task::yield_now().await;
    assert!(matches!(
        observed.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    body.stop().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), observed)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dropping_received_body_does_not_stop_network_reads() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (mut send, recv) = duplex(64);
        send.write_all(&request_frames(b"", None)).await.unwrap();
        let Request::Streaming(request) = crate::server::read_request(
            crate::test_support::read_stream(0, recv),
            crate::test_support::connection().await.qpack().clone(),
        )
        .await
        .unwrap() else {
            panic!("expected stream");
        };
        let mut buffer = request.message.body_stream();
        drop(request.into_body());
        send.write_all(&[0, 1, b'x']).await.unwrap();
        let mut bytes = [0];
        buffer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, *b"x");
        // Subsequent body I/O observes cancellation; dropping Body did not cancel it.
        buffer.on_error(
            ErrorCode::H3_REQUEST_CANCELLED.with_reason("test cancels the response producer"),
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_body_stop_notifies_transport_while_network_or_window_is_blocked() {
    use crate::test_support::TestStream;

    for full in [false, true] {
        let payload = if full {
            vec![b'x'; frame::MAX_DATA_CHUNK * 2]
        } else {
            Vec::new()
        };
        let wire = request_frames(&payload, None);
        let (mut peer, recv) = duplex(wire.len() + 1);
        peer.write_all(&wire).await.unwrap();
        let recv = TestStream::new(recv);
        let stopped = recv.stopped.clone();
        let request = crate::server::read_request(
            H3ReadStream::new(0, recv),
            crate::test_support::connection().await.qpack().clone(),
        )
        .await
        .unwrap();
        tokio::task::yield_now().await;
        assert!(stopped.lock().unwrap().is_empty());
        request.into_body().stop().await;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while stopped.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            *stopped.lock().unwrap(),
            [ErrorCode::H3_REQUEST_CANCELLED.as_u64()]
        );
    }
}
