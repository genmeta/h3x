use super::*;

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
            (Error::H3_REQUEST_REJECTED, true),
            (Error::H3_INTERNAL_ERROR, true),
            (Error::H3_INTERNAL_ERROR, false),
        ] {
            let mut response = Response::<Bytes>::default();
            response.set_status(StatusCode::OK);
            let response = response.streaming(1);
            let mut producer = response.clone();
            let qpack = Arc::new(Qpack::default());
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let mut sending = Box::pin(super::respond(
                response,
                H3WriteStream::new(0, tokio::io::sink())
                    .with_stop_signal(async move { stopped.await.unwrap() }),
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
    let request = super::accept(H3ReadStream::new(4, recv), Arc::new(Qpack::default()))
        .await
        .unwrap();
    assert!(matches!(&request, Request::Streaming(_)));
    tokio::task::yield_now().await; // Let the receive pump wait for another frame.
    drop(request);
    tokio::task::yield_now().await;
    assert!(send.write_all(b"x").await.is_err());
}
