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
