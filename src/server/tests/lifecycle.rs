use super::*;

#[tokio::test]
async fn dropping_last_response_producer_cancels_live_send() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
        time::Duration,
    };

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    for started in [true, false] {
        let mut response = Response::<Bytes>::default();
        response.set_status(StatusCode::OK);
        let response = response.streaming(1);
        let producer = response.clone();
        let mut body = response.message.0.lock().unwrap().body_stream();
        let mut sending = Box::pin(super::respond(
            response,
            H3WriteStream::new(0, tokio::io::sink()),
            crate::protocol::qpack::tests::shared(),
            &Method::GET,
        ));
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        if started {
            // The sink cannot block HEADERS, so the sender must be waiting for body data.
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            drop(producer.clone());
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            body.flush().await.unwrap();
        }

        let previous_wakes = wakes.0.load(Ordering::SeqCst);
        drop(producer);
        if started {
            assert!(
                wakes.0.load(Ordering::SeqCst) > previous_wakes,
                "dropping the last producer must wake the live sender"
            );
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), &mut sending)
                .await
                .expect("the sender must cancel without peer or connection termination"),
            Err(Error::H3_REQUEST_CANCELLED)
        );
        assert_eq!(
            Error::from(body.flush().await.unwrap_err()),
            Error::H3_REQUEST_CANCELLED
        );
    }
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
            H3WriteStream::new(0, &mut encoded),
            crate::protocol::qpack::tests::shared(),
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
async fn server_views_share_buffered_and_streaming_messages() {
    let message = Message::<Bytes>::post("https://example.com/echo?q=1").unwrap();
    let request = common::request::Request::<Read, _>::from(ArcMessage::from(message));
    let mut incoming = common::request::Request::<Write, _>::from(request.message.clone());
    incoming.set_body(Bytes::from_static(b"request"));
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.authority(), "example.com");
    assert_eq!(request.scheme(), "https");
    assert_eq!(request.path(), "/echo?q=1");
    assert_eq!(request.body(), Bytes::from_static(b"request"));

    let mut response = Response::default();
    let outgoing = common::response::Response::<Read, _>::from(response.message.clone());
    response
        .set_status(StatusCode::CREATED)
        .set_body(request.body());
    assert_eq!(outgoing.status(), StatusCode::CREATED);
    assert_eq!(outgoing.body(), Bytes::from_static(b"request"));

    let message = Message::<Bytes>::default().with_body(ArcWndBuf::new(2));
    let mut request = common::request::Request::<Read, _>::from(ArcMessage::from(message));
    let mut incoming = common::request::Request::<Write, _>::from(request.message.clone());
    let message = Message::<Bytes>::default().with_body(ArcWndBuf::new(2));
    let mut response = Response::from(ArcMessage::from(message));
    let mut outgoing = common::response::Response::<Read, _>::from(response.message.clone());
    response.set_status(StatusCode::OK);
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
        incoming.write(b"x").await.unwrap_err(),
        Error::H3_REQUEST_CANCELLED
    );
    response.reset().await.unwrap();
    assert_eq!(
        outgoing.read(&mut [0]).await.unwrap_err(),
        Error::H3_REQUEST_CANCELLED
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
            (Error::H3_REQUEST_CANCELLED, true),
            (Error::H3_REQUEST_CANCELLED, false),
            (Error::H3_REQUEST_REJECTED, true),
            (Error::H3_INTERNAL_ERROR, true),
            (Error::H3_INTERNAL_ERROR, false),
        ] {
            let mut response = Response::<Bytes>::default();
            response.set_status(StatusCode::OK);
            let response = response.streaming(1);
            let mut producer = response.clone();
            let bi = Arc::new(crate::protocol::stream::bi::BiStreams::default());
            let qpack = Qpack::new(
                Arc::new(crate::test_support::TestTransport::default()),
                &crate::Settings::default(),
                bi.clone(),
            )
            .unwrap();
            let (send, recv) = bi
                .insert(0, crate::test_support::Reader, crate::test_support::Writer)
                .unwrap();
            drop(recv);
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let mut sending = Box::pin(super::respond(
                response,
                send.with_stop_signal(async move { stopped.await.unwrap() }),
                qpack.clone(),
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
            if error == Error::H3_REQUEST_CANCELLED {
                drop(sending);
            } else {
                if error == Error::H3_REQUEST_REJECTED {
                    stop.send(error).unwrap();
                } else {
                    qpack.on_error(error);
                }
                assert_eq!(sending.await, Err(error));
            }
            assert_eq!(producer.write(b"x").await, Err(error));
            assert_eq!(producer.finish().await, Err(error));
        }
    })
    .await
    .expect("response termination must notify an idle body producer");
}

#[tokio::test]
async fn dropping_streaming_request_stops_a_pump_waiting_on_network() {
    let (mut send, recv) = duplex(64);
    send.write_all(&request_frames(b"", None)).await.unwrap();
    let request = super::accept(
        H3ReadStream::new(4, recv),
        crate::protocol::qpack::tests::shared(),
    )
    .await
    .unwrap();
    assert!(matches!(&request, Request::Streaming(_)));
    tokio::task::yield_now().await; // Let the receive pump wait for another frame.
    drop(request);
    tokio::task::yield_now().await;
    assert!(send.write_all(b"x").await.is_err());
}

#[test]
fn cancelling_request_pump_publishes_an_error_without_returning() {
    use std::task::{Context, Poll, Waker};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let (mut request, _peer) = runtime.block_on(async {
        let (mut send, recv) = duplex(64);
        send.write_all(&request_frames(b"", None)).await.unwrap();
        let Request::Streaming(request) = super::accept(
            H3ReadStream::new(4, recv),
            crate::protocol::qpack::tests::shared(),
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
    let mut bytes = [0];
    let mut reading = Box::pin(request.read(&mut bytes));
    assert_eq!(
        reading
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(Error::H3_REQUEST_CANCELLED))
    );
}
