use support::connection_pair;
mod support;

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use h3x::{Body, BoxError, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use http::{Method, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use tokio::io::AsyncWriteExt;

fn full(bytes: &'static [u8]) -> Body {
    Full::new(Bytes::from_static(bytes))
        .map_err(Into::into)
        .boxed_unsync()
}
async fn collect(body: Body) -> Bytes {
    body.collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn content_length_request_and_response() {
    let (client, server) = connection_pair();
    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request = rs.read_request(server.qpack().clone()).await.unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/echo");
        assert_eq!(collect(request.into_body()).await, "hello");
        let response = http::Response::builder()
            .header("content-length", "5")
            .body(full(b"world"))
            .unwrap();
        ws.write_response(response, Method::POST, server.qpack().clone())
            .await
            .unwrap();
    });
    let (ws, rs) = client.open_bi().await.unwrap();
    let request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/echo")
        .header("content-length", "5")
        .body(full(b"hello"))
        .unwrap();
    let ((), response) = tokio::try_join!(
        ws.write_request(request, client.qpack().clone()),
        rs.read_response(Method::POST, client.qpack().clone())
    )
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(collect(response.into_body()).await, "world");
    serving.await.unwrap();
}

#[tokio::test]
async fn completed_request_write_keeps_response_read_open() {
    let (client, server) = connection_pair();
    let (ws, rs) = client.open_bi().await.unwrap();
    let (peer_ws, peer_rs) = server.accept_bi().await.unwrap();
    let request = http::Request::builder()
        .uri("https://example.com/")
        .body(full(b"request complete"))
        .unwrap();
    ws.write_request(request, client.qpack().clone())
        .await
        .unwrap();
    let request = peer_rs.read_request(server.qpack().clone()).await.unwrap();
    assert_eq!(collect(request.into_body()).await, "request complete");
    let mut receiving = Box::pin(rs.read_response(Method::GET, client.qpack().clone()));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut receiving)
            .await
            .is_err()
    );
    peer_ws
        .write_response(
            http::Response::new(full(b"response complete")),
            Method::GET,
            server.qpack().clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        collect(receiving.await.unwrap().into_body()).await,
        "response complete"
    );
}

#[tokio::test]
async fn request_and_response_trailers_follow_streamed_data() {
    fn source(data: &'static [u8]) -> Body {
        let mut fields = http::HeaderMap::new();
        fields.append("x-checksum", http::HeaderValue::from_static("a"));
        fields.append("x-checksum", http::HeaderValue::from_static("b"));
        StreamBody::new(futures::stream::iter([
            Ok::<_, BoxError>(Frame::data(Bytes::from_static(data))),
            Ok(Frame::trailers(fields)),
        ]))
        .boxed_unsync()
    }
    let (client, server) = connection_pair();
    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request = rs.read_request(server.qpack().clone()).await.unwrap();
        let received = request.into_body().collect().await.unwrap();
        assert_eq!(
            received
                .trailers()
                .unwrap()
                .get_all("x-checksum")
                .iter()
                .count(),
            2
        );
        assert_eq!(received.to_bytes(), "hello");
        ws.write_response(
            http::Response::new(source(b"world")),
            Method::POST,
            server.qpack().clone(),
        )
        .await
        .unwrap();
    });
    let (ws, rs) = client.open_bi().await.unwrap();
    let request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/")
        .body(source(b"hello"))
        .unwrap();
    let ((), response) = tokio::try_join!(
        ws.write_request(request, client.qpack().clone()),
        rs.read_response(Method::POST, client.qpack().clone())
    )
    .unwrap();
    let received = response.into_body().collect().await.unwrap();
    assert_eq!(
        received
            .trailers()
            .unwrap()
            .get_all("x-checksum")
            .iter()
            .count(),
        2
    );
    assert_eq!(received.to_bytes(), "world");
    serving.await.unwrap();
}

#[tokio::test]
async fn websocket_over_extended_connect() {
    const CLIENT: &[u8] = b"\x81\x82\x01\x02\x03\x04\x69\x6b";
    const SERVER: &[u8] = b"\x81\x02ok";
    let (client, server) = connection_pair();
    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request = rs.read_request(server.qpack().clone()).await.unwrap();
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.extensions().get::<Arc<str>>().unwrap().as_ref(),
            "websocket"
        );
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().path(), "/chat");
        let response = http::Response::builder()
            .header("sec-websocket-protocol", "chat")
            .body(full(SERVER))
            .unwrap();
        ws.write_response(response, Method::CONNECT, server.qpack().clone())
            .await
            .unwrap();
        assert_eq!(collect(request.into_body()).await, CLIENT);
    });
    let (ws, rs) = client.open_bi().await.unwrap();
    let (release, released) = tokio::sync::oneshot::channel();
    let source = StreamBody::new(async_stream::stream! {
        released.await.unwrap();
        yield Ok::<_, BoxError>(Frame::data(Bytes::from_static(CLIENT)));
    })
    .boxed_unsync();
    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri("wss://example.com/chat")
        .extension(Arc::<str>::from("websocket"))
        .body(source)
        .unwrap();
    let sending = tokio::spawn(ws.write_request(request, client.qpack().clone()));
    let response = rs
        .read_response(Method::CONNECT, client.qpack().clone())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    release.send(()).unwrap();
    assert_eq!(collect(response.into_body()).await, SERVER);
    sending.await.unwrap().unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn known_frame_after_trailers_is_rejected() {
    for suffix in [&b"\x00\x00"[..], &b"\x01\x02\x00\x00"[..]] {
        let (client, server) = connection_pair();
        let (_unused_direction_1, rs) = client.open_bi().await.unwrap();
        let (mut ws, _unused_direction_2) = server.accept_bi().await.unwrap();
        ws.write_all(b"\x01\x03\x00\x00\xd9\x01\x02\x00\x00")
            .await
            .unwrap();
        ws.write_all(suffix).await.unwrap();
        ws.shutdown().await.unwrap();
        let response = rs
            .read_response(Method::GET, client.qpack().clone())
            .await
            .unwrap();
        let error = response.into_body().collect().await.unwrap_err();
        assert!(
            error.to_string().contains("frame received after trailers"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn trailers_followed_by_fin_are_accepted() {
    let (client, server) = connection_pair();
    let (_unused_direction_3, rs) = client.open_bi().await.unwrap();
    let (mut ws, _unused_direction_4) = server.accept_bi().await.unwrap();
    ws.write_all(b"\x01\x03\x00\x00\xd9\x01\x02\x00\x00")
        .await
        .unwrap();
    ws.shutdown().await.unwrap();
    let response = rs
        .read_response(Method::GET, client.qpack().clone())
        .await
        .unwrap();
    assert!(collect(response.into_body()).await.is_empty());
}
