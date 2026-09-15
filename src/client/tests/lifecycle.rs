use std::{
    io::Cursor,
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::{io::AsyncReadExt, time::timeout};

use super::*;
use crate::{ReadResponse, WriteRequest, WriteStream};

fn response_headers() -> Vec<u8> {
    let mut response = Message::<Bytes>::default();
    response.set_status(StatusCode::OK);
    response.set_header(http::header::CONTENT_LENGTH, "0".parse().unwrap());
    let mut encoded = Vec::new();
    encoded.put_frame(
        &Frame::new(Headers {
            field_section: crate::test_support::connection()
                .qpack()
                .encode(0, response.fields())
                .unwrap(),
        })
        .unwrap(),
    );
    encoded
}

#[tokio::test]
async fn reset_wakes_a_blocked_producer_after_upload_is_dropped() {
    let message = Message::<Bytes>::post("https://example.com/upload")
        .unwrap()
        .with_body(crate::Body::from_storage(ArcWndBuf::new(1)));
    let mut producer = Request::from(ArcMessage::from(message));
    producer.write(b"x").await.unwrap();
    let sending = send_streaming_request(
        &producer,
        H3WriteStream::new(0, tokio::io::sink()),
        crate::test_support::connection(),
    )
    .unwrap();
    let cancelling = producer.clone();
    let mut writing = Box::pin(producer.write(b"y"));
    assert!(
        writing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(sending);
    cancelling.reset().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), writing).await.unwrap(),
        Err(Error::H3_REQUEST_CANCELLED)
    );
    assert_eq!(producer.finish().await, Err(Error::H3_REQUEST_CANCELLED));
}

#[tokio::test]
async fn reset_wakes_a_blocked_producer_after_request_is_dropped() {
    let message = Message::<Bytes>::post("https://example.com/upload")
        .unwrap()
        .with_body(crate::Body::from_storage(ArcWndBuf::new(1)));
    let mut producer = Request::from(ArcMessage::from(message));
    producer.write(b"x").await.unwrap();
    let waiting = request(
        producer.clone(),
        H3ReadStream::new(0, tokio::io::empty()),
        H3WriteStream::new(0, tokio::io::sink()),
        crate::test_support::connection(),
    );
    let cancelling = producer.clone();
    let mut writing = Box::pin(producer.write(b"y"));
    assert!(
        writing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(waiting);
    cancelling.reset().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), writing).await.unwrap(),
        Err(Error::H3_REQUEST_CANCELLED)
    );
    assert_eq!(producer.finish().await, Err(Error::H3_REQUEST_CANCELLED));
}

#[tokio::test]
async fn cancelling_response_wait_drops_unfinished_uploads() {
    timeout(Duration::from_secs(5), async {
        for (streaming, finished) in [(false, false), (true, false), (true, true)] {
            let mut producer = Request::streaming_post("https://example.com/upload").unwrap();
            let outgoing: common::Request<Write> = if streaming {
                producer.clone().into()
            } else {
                Request::post("https://example.com/upload")
                    .unwrap()
                    .body(Bytes::from_static(b"payload"))
                    .into()
            };
            let (send, mut peer_recv) = tokio::io::duplex(1);
            let (mut peer_send, recv) = tokio::io::duplex(1);
            let mut waiting = Box::pin(request(
                outgoing,
                H3ReadStream::new(0, recv),
                H3WriteStream::new(0, send),
                crate::test_support::connection(),
            ));
            assert!(
                waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if streaming {
                producer.write(b"payload").await.unwrap();
                if finished {
                    producer.finish().await.unwrap();
                }
            }
            drop(waiting);
            if streaming {
                producer.clone().reset().await.unwrap();
                assert_eq!(producer.write(b"x").await, Err(Error::H3_REQUEST_CANCELLED));
                assert_eq!(producer.finish().await, Err(Error::H3_REQUEST_CANCELLED));
            }
            let mut partial = Vec::new();
            peer_recv.read_to_end(&mut partial).await.unwrap();
            assert!(partial.len() <= 1);
            assert!(peer_send.write_all(b"x").await.is_err());
        }
    })
    .await
    .expect("cancelling the response wait must release both transport halves");
}

#[tokio::test]
async fn early_response_keeps_both_body_modes_sending() {
    timeout(Duration::from_secs(5), async {
        for (streaming, finished_before_sending) in [(false, false), (true, false), (true, true)] {
            let mut producer = Request::streaming_post("https://example.com/upload").unwrap();
            if finished_before_sending {
                producer.write(b"payload").await.unwrap();
                producer.finish().await.unwrap();
            }
            let outgoing: common::Request<Write> = if streaming {
                producer.clone().into()
            } else {
                Request::post("https://example.com/upload")
                    .unwrap()
                    .body(Bytes::from_static(b"payload"))
                    .into()
            };
            let (send, mut recv) = tokio::io::duplex(1);
            let response = request(
                outgoing,
                H3ReadStream::new(0, Cursor::new(response_headers())),
                H3WriteStream::new(0, send),
                crate::test_support::connection(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            drop(response);
            if streaming && !finished_before_sending {
                producer.write(b"payload").await.unwrap();
                producer.finish().await.unwrap();
            }
            drop(producer);
            let mut encoded = Vec::new();
            recv.read_to_end(&mut encoded).await.unwrap();
            let mut input = encoded.as_slice();
            assert!(matches!(
                be_frame(&mut input).await.unwrap(),
                H3Frame::Headers(_)
            ));
            let H3Frame::Data(data) = be_frame(&mut input).await.unwrap() else {
                panic!("the upload must retain its body after response delivery");
            };
            assert_eq!(data.length.into_u64(), 7);
            assert_eq!(input, b"payload");
        }
    })
    .await
    .expect("an early response must return while the upload is blocked");
}

#[tokio::test]
async fn cancelling_response_wait_preserves_a_completed_upload() {
    timeout(Duration::from_secs(5), async {
        let mut producer = Request::streaming_post("https://example.com/upload").unwrap();
        let (send, mut peer_recv) = tokio::io::duplex(64);
        let (_peer_send, recv) = tokio::io::duplex(1);
        let mut waiting = Box::pin(request(
            producer.clone(),
            H3ReadStream::new(0, recv),
            H3WriteStream::new(0, send),
            crate::test_support::connection(),
        ));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        producer.write(b"payload").await.unwrap();
        producer.finish().await.unwrap();
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let mut encoded = Vec::new();
        peer_recv.read_to_end(&mut encoded).await.unwrap();
        drop(waiting);
        producer.finish().await.unwrap();
        assert!(encoded.ends_with(b"payload"));
    })
    .await
    .expect("a completed upload must not wait for its response to send FIN");
}

#[tokio::test]
async fn producer_fin_does_not_complete_transport_shutdown() {
    use std::{
        io,
        sync::atomic::{AtomicBool, Ordering},
        task::Poll,
    };

    struct ShutdownWriter {
        ready: bool,
        polled: Arc<AtomicBool>,
    }

    impl AsyncWrite for ShutdownWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.polled.store(true, Ordering::SeqCst);
            if self.ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    for ready in [false, true] {
        let mut producer = Request::streaming_post("https://example.com/upload").unwrap();
        producer.write(b"x").await.unwrap();
        producer.finish().await.unwrap();
        let polled = Arc::new(AtomicBool::new(false));
        let mut sending = Box::pin(
            send_streaming_request(
                &producer,
                H3WriteStream::new(
                    0,
                    ShutdownWriter {
                        ready,
                        polled: polled.clone(),
                    },
                ),
                crate::test_support::connection(),
            )
            .unwrap(),
        );
        let result = sending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        assert!(polled.load(Ordering::SeqCst));
        assert_eq!(
            result,
            if ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        );
        drop(sending);
        // Producer FIN remains successful independently of transport shutdown.
        assert_eq!(producer.finish().await, Ok(()));
    }
}

#[tokio::test]
async fn write_failure_after_idle_body_preserves_the_response() {
    timeout(Duration::from_secs(5), async {
        let mut producer = Request::streaming_post("https://example.com/upload").unwrap();
        let (send, mut peer_recv) = tokio::io::duplex(64);
        let (mut peer_send, recv) = tokio::io::duplex(64);
        let mut waiting = Box::pin(request(
            producer.clone(),
            H3ReadStream::new(0, recv),
            H3WriteStream::new(0, send),
            crate::test_support::connection(),
        ));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(matches!(
            be_frame(&mut peer_recv).await.unwrap(),
            H3Frame::Headers(_)
        ));
        drop(peer_recv);
        // There is no independent STOP observer while the upload waits for body data.
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(producer.write(b"x").await, Ok(1));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(producer.write(b"x").await, Err(Error::H3_INTERNAL_ERROR));
        peer_send.write_all(&response_headers()).await.unwrap();
        peer_send.shutdown().await.unwrap();
        assert_eq!(waiting.await.unwrap().status(), StatusCode::OK);
    })
    .await
    .expect("a failed upload must still receive the peer's valid response");
}

#[tokio::test]
async fn explicit_reset_stops_an_upload_waiting_on_network() {
    timeout(Duration::from_secs(5), async {
        let request = Request::streaming_post("https://example.com/upload").unwrap();
        let mut body = request.message.0.lock().unwrap().body_stream();
        let (send, mut recv) = tokio::io::duplex(1);
        let sending = tokio::spawn(
            send_streaming_request(
                &request,
                H3WriteStream::new(0, send),
                crate::test_support::connection(),
            )
            .unwrap(),
        );
        tokio::task::yield_now().await; // HEADERS cannot fit in the transport buffer.
        drop(request.clone());
        tokio::task::yield_now().await;
        body.flush().await.unwrap();

        request.reset().await.unwrap();
        assert_eq!(
            Error::from(body.read(&mut [0]).await.unwrap_err()),
            Error::H3_REQUEST_CANCELLED
        );
        assert_eq!(sending.await.unwrap(), Err(Error::H3_REQUEST_CANCELLED));
        let mut partial = Vec::new();
        recv.read_to_end(&mut partial).await.unwrap();
        assert!(!partial.is_empty());
    })
    .await
    .expect("reset must wake the blocked upload");
}

#[tokio::test]
async fn finished_producer_can_drop_while_upload_waits_on_network() {
    timeout(Duration::from_secs(5), async {
        let mut request = Request::streaming_post("https://example.com/upload").unwrap();
        let (send, mut recv) = tokio::io::duplex(1);
        let sending = tokio::spawn(
            send_streaming_request(
                &request,
                H3WriteStream::new(0, send),
                crate::test_support::connection(),
            )
            .unwrap(),
        );
        tokio::task::yield_now().await;
        assert_eq!(request.write(b"payload").await.unwrap(), 7);
        request.finish().await.unwrap();
        drop(request);

        let mut encoded = Vec::new();
        recv.read_to_end(&mut encoded).await.unwrap();
        sending.await.unwrap().unwrap();
        let mut input = encoded.as_slice();
        assert!(matches!(
            be_frame(&mut input).await.unwrap(),
            H3Frame::Headers(_)
        ));
        let H3Frame::Data(data) = be_frame(&mut input).await.unwrap() else {
            panic!("the finished upload must retain its body");
        };
        assert_eq!(data.length.into_u64(), 7);
        assert_eq!(input, b"payload");
    })
    .await
    .expect("a finished producer must allow its upload to drain and send FIN");
}

#[tokio::test]
async fn explicit_stop_stops_a_receive_waiting_on_network() {
    timeout(Duration::from_secs(5), async {
        let mut message = Message::<Bytes>::default();
        message.set_status(StatusCode::OK);
        let qpack = crate::test_support::connection();
        let mut headers = Vec::new();
        headers.put_frame(
            &Frame::new(Headers {
                field_section: qpack.qpack().encode(0, message.fields()).unwrap(),
            })
            .unwrap(),
        );
        let (mut send, recv) = tokio::io::duplex(64);
        send.write_all(&headers).await.unwrap();
        let response = read_response(H3ReadStream::new(0, recv), qpack, None)
            .await
            .unwrap();
        assert!(matches!(response, Response::Streaming(_)));
        tokio::task::yield_now().await;
        response.into_body().stop().await;
        tokio::task::yield_now().await;
        assert!(send.write_all(b"x").await.is_err());
    })
    .await
    .expect("stop must terminate the receive task");
}

#[test]
fn explicit_stop_cancels_body_after_response_pump_is_dropped() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let (response, _peer) = runtime.block_on(async {
        let mut message = Message::<Bytes>::default();
        message.set_status(StatusCode::OK);
        let qpack = crate::test_support::connection();
        let mut headers = Vec::new();
        headers.put_frame(
            &Frame::new(Headers {
                field_section: qpack.qpack().encode(0, message.fields()).unwrap(),
            })
            .unwrap(),
        );
        let (mut send, recv) = tokio::io::duplex(64);
        send.write_all(&headers).await.unwrap();
        let Response::Streaming(response) = read_response(H3ReadStream::new(0, recv), qpack, None)
            .await
            .unwrap()
        else {
            panic!("expected streaming response");
        };
        tokio::task::yield_now().await;
        (response, send)
    });
    // Runtime shutdown drops the receive future without executing its error branch.
    drop(runtime);
    let mut remaining = response.message.clone();
    let mut stopping = Box::pin(crate::ReadStream::stop(response));
    assert!(
        stopping
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    let mut bytes = [0];
    let mut reading = Box::pin(crate::ReadStream::read(&mut remaining, &mut bytes));
    assert_eq!(
        reading
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(Error::H3_REQUEST_CANCELLED))
    );
}

#[tokio::test]
async fn streaming_response_keeps_message_error_after_transport_eof() {
    let mut message = Message::<Bytes>::default();
    message.set_status(StatusCode::OK);
    message.set_header(
        http::header::CONTENT_LENGTH,
        (frame::MAX_BUFFERED_FRAME_PAYLOAD + 1)
            .to_string()
            .parse()
            .unwrap(),
    );
    let qpack = crate::test_support::connection();
    let mut encoded = Vec::new();
    encoded.put_frame(
        &Frame::new(Headers {
            field_section: qpack.qpack().encode(0, message.fields()).unwrap(),
        })
        .unwrap(),
    );
    let Response::Streaming(mut response) =
        read_response(H3ReadStream::new(0, Cursor::new(encoded)), qpack, None)
            .await
            .unwrap()
    else {
        panic!("expected streaming response");
    };
    assert_eq!(response.read(&mut [0]).await, Err(Error::H3_MESSAGE_ERROR));
    assert_eq!(response.read(&mut [0]).await, Err(Error::H3_MESSAGE_ERROR));
}
