mod support;

use std::sync::Arc;

use h3x::{
    R, ReadRequest, ReadResponse, Request, Response, W, WndBuf, WriteRequest, WriteResponse,
};
use http::{Method, StatusCode, header};
use support::connection_pair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn content_length_request_and_response() {
    let (client, server) = connection_pair();

    // Server: accept one request stream, read the request from `rs`, then write
    // its response to the paired `ws`.
    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request: Request<R> = rs.read_request(server.qpack().clone()).await.unwrap();
        let method = request.method().clone();

        assert_eq!(method, Method::POST);
        assert_eq!(request.path(), "/echo");
        let body = collect(request.into_body()).await;
        assert_eq!(body, "hello");

        let response: Response<W> = http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, "5")
            .body(finished_body(b"world").await)
            .unwrap()
            .into();
        ws.write_response(response, method, server.qpack().clone())
            .await
            .unwrap();
    });

    // Client: open a request stream. `ws` sends the request and the paired `rs`
    // receives the response. Drive both message futures concurrently.
    let (ws, rs) = client.open_bi().await.unwrap();
    let request: Request<W> = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/echo")
        .header(header::CONTENT_LENGTH, "5")
        .body(finished_body(b"hello").await)
        .unwrap()
        .into();
    let writing = ws.write_request(request, client.qpack().clone());
    let receiving = rs.read_response(Method::POST, client.qpack().clone());
    let ((), response): ((), Response<R>) = tokio::try_join!(writing, receiving).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(collect(response.into_body()).await, "world");
    serving.await.unwrap();
}

#[tokio::test]
async fn streaming_request_and_response() {
    let (client, server) = connection_pair();

    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request: Request<R> = rs.read_request(server.qpack().clone()).await.unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.path(), "/early-response");
        let request_body = request.into_body();

        let response_window = WndBuf::new(1);
        let mut response_body = response_window.clone();
        let response: Response<W> = http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, "5")
            .body(response_window)
            .unwrap()
            .into();

        // Keep the handler's request-body read and response-body write in this
        // task. `write_response` must send HEADERS while the body work waits for
        // the client to start uploading only after it receives those HEADERS.
        let writing = ws.write_response(response, Method::POST, server.qpack().clone());
        let handling_body = async move {
            assert_eq!(collect(request_body).await, "hello");
            response_body.write_all(b"world").await?;
            response_body.shutdown().await.map_err(h3x::Error::from)
        };
        tokio::try_join!(writing, handling_body).unwrap();
    });

    let (ws, rs) = client.open_bi().await.unwrap();
    let request_window = WndBuf::new(1);
    let mut request_body = request_window.clone();
    let request: Request<W> = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/early-response")
        .header(header::CONTENT_LENGTH, "5")
        .body(request_window)
        .unwrap()
        .into();
    let uploading = tokio::spawn(ws.write_request(request, client.qpack().clone()));

    let response: Response<R> = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        rs.read_response(Method::POST, client.qpack().clone()),
    )
    .await
    .expect("response HEADERS must arrive before the request body is produced")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    request_body.write_all(b"hello").await.unwrap();
    request_body.shutdown().await.unwrap();
    assert_eq!(collect(response.into_body()).await, "world");

    uploading.await.unwrap().unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn request_and_response_trailers_are_shared_and_sent_after_body() {
    let (client, server) = connection_pair();

    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let mut request: Request<R> = rs.read_request(server.qpack().clone()).await.unwrap();
        let method = request.method().clone();
        let mut request_body = Vec::new();
        request.read_to_end(&mut request_body).await.unwrap();
        assert_eq!(request_body, b"hello");
        assert_eq!(request.trailers().get_all("x-checksum").iter().count(), 2);

        let mut response: Response<W> = http::Response::new(WndBuf::new(1)).into();
        let outgoing = response.clone();
        let writing = ws.write_response(outgoing, method, server.qpack().clone());
        let producing = async {
            response.write_all(b"world").await?;
            response.set_trailer(
                http::HeaderName::from_static("x-result"),
                http::HeaderValue::from_static("ok"),
            );
            response.shutdown().await.map_err(h3x::Error::from)
        };
        tokio::try_join!(writing, producing).unwrap();
    });

    let (ws, rs) = client.open_bi().await.unwrap();
    let mut request: Request<W> = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/trailers")
        .body(WndBuf::new(1))
        .unwrap()
        .into();
    let outgoing = request.clone();
    let writing = ws.write_request(outgoing, client.qpack().clone());
    let producing = async {
        request.write_all(b"hello").await?;
        request
            .set_trailer(
                http::HeaderName::from_static("x-checksum"),
                http::HeaderValue::from_static("a"),
            )
            .append_trailer(
                http::HeaderName::from_static("x-checksum"),
                http::HeaderValue::from_static("b"),
            );
        request.shutdown().await.map_err(h3x::Error::from)
    };
    let receiving = rs.read_response(Method::POST, client.qpack().clone());
    let ((), (), mut response) = tokio::try_join!(writing, producing, receiving).unwrap();

    let mut response_body = Vec::new();
    response.read_to_end(&mut response_body).await.unwrap();
    assert_eq!(response_body, b"world");
    assert_eq!(response.trailers()["x-result"], "ok");
    serving.await.unwrap();
}

#[tokio::test]
async fn websocket_over_extended_connect() {
    // h3x transports WebSocket wire bytes without interpreting them. This is a
    // masked client text frame ("hi") and an unmasked server text frame ("ok").
    const CLIENT_FRAME: &[u8] = b"\x81\x82\x01\x02\x03\x04\x69\x6b";
    const SERVER_FRAME: &[u8] = b"\x81\x02ok";

    let (client, server) = connection_pair();

    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request: Request<R> = rs.read_request(server.qpack().clone()).await.unwrap();
        let method = request.method().clone();

        // RFC 9220 represents WebSocket as an extended CONNECT request.
        assert_eq!(method, Method::CONNECT);
        assert_eq!(request.protocol(), Some("websocket"));
        assert_eq!(request.scheme(), "https");
        assert_eq!(request.path(), "/chat");
        assert_eq!(request.headers()["sec-websocket-protocol"], "chat");
        let mut request_body: WndBuf = request.into_body();

        // A successful CONNECT response has a streaming body and no
        // Content-Length. Sending its HEADERS accepts the tunnel.
        let response_window = WndBuf::new(4);
        let mut response_body = response_window.clone();
        let response: Response<W> = http::Response::builder()
            .status(StatusCode::OK)
            .header("sec-websocket-protocol", "chat")
            .body(response_window)
            .unwrap()
            .into();
        let writing = ws.write_response(response, method, server.qpack().clone());
        let exchanging = async move {
            response_body.write_all(SERVER_FRAME).await?;
            response_body.shutdown().await.map_err(h3x::Error::from)?;
            let mut received = Vec::new();
            request_body.read_to_end(&mut received).await?;
            assert_eq!(received, CLIENT_FRAME);
            Ok::<_, h3x::Error>(())
        };
        tokio::try_join!(writing, exchanging).unwrap();
    });

    let (ws, rs) = client.open_bi().await.unwrap();
    let request_window = WndBuf::new(4);
    let mut request_body = request_window.clone();
    let request: Request<W> = http::Request::builder()
        .method(Method::CONNECT)
        .uri("wss://example.com/chat")
        .extension(Arc::<str>::from("websocket"))
        .header("sec-websocket-protocol", "chat")
        .body(request_window)
        .unwrap()
        .into();

    // CONNECT data is held until the peer accepts with final 2xx HEADERS.
    let uploading = tokio::spawn(ws.write_request(request, client.qpack().clone()));
    let response: Response<R> = rs
        .read_response(Method::CONNECT, client.qpack().clone())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["sec-websocket-protocol"], "chat");
    let mut response_body: WndBuf = response.into_body();

    // After the handshake, the request and response bodies are the two tunnel
    // directions and can be driven independently.
    let sending = async move {
        request_body.write_all(CLIENT_FRAME).await?;
        request_body.shutdown().await.map_err(h3x::Error::from)
    };
    let receiving = async move {
        let mut received = Vec::new();
        response_body.read_to_end(&mut received).await?;
        Ok::<_, h3x::Error>(received)
    };
    let ((), frame) = tokio::try_join!(sending, receiving).unwrap();
    assert_eq!(frame, SERVER_FRAME);
    uploading.await.unwrap().unwrap();

    serving.await.unwrap();
}

#[test]
fn websocket_uri_schemes_are_normalized() {
    fn request(uri: &str, protocol: &str) -> Request<W> {
        http::Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .extension(Arc::<str>::from(protocol))
            .body(WndBuf::new(1))
            .unwrap()
            .into()
    }

    assert_eq!(
        request("ws://example.com/chat", "websocket").scheme(),
        "http"
    );
    assert_eq!(
        request("wss://example.com/chat", "websocket").scheme(),
        "https"
    );
    assert_eq!(
        request("http://example.com/chat", "websocket").scheme(),
        "http"
    );
    assert_eq!(
        request("https://example.com/chat", "websocket").scheme(),
        "https"
    );

    // Other Extended CONNECT protocols keep their original scheme.
    assert_eq!(
        request("wss://example.com/chat", "connect-udp").scheme(),
        "wss"
    );

    // Metadata setters apply the same normalization as initial construction.
    let mut request = request("https://example.com/chat", "websocket");
    request.set_uri("ws://example.com/other".parse().unwrap());
    assert_eq!(request.scheme(), "http");

    let mut request: Request<W> = http::Request::builder()
        .method(Method::GET)
        .uri("wss://example.com/chat")
        .extension(Arc::<str>::from("websocket"))
        .body(WndBuf::new(1))
        .unwrap()
        .into();
    assert_eq!(request.scheme(), "wss");
    request.set_method(Method::CONNECT);
    assert_eq!(request.scheme(), "https");

    let mut request: Request<W> = http::Request::builder()
        .method(Method::CONNECT)
        .uri("wss://example.com/chat")
        .body(WndBuf::new(1))
        .unwrap()
        .into();
    request.set_protocol("websocket");
    assert_eq!(request.protocol(), Some("websocket"));
    assert_eq!(request.scheme(), "https");
}

#[tokio::test]
async fn any_frame_after_trailers_is_rejected() {
    // QPACK prefix followed by static :status = 200, then empty trailers.
    for suffix in [
        &b"\x00\x00"[..],
        &b"\x01\x02\x00\x00"[..],
        &b"\x21\x00"[..],
        &b"\x21"[..],
    ] {
        let (client, server) = connection_pair();
        let (_ws, rs) = client.open_bi().await.unwrap();
        let (mut ws, _rs) = server.accept_bi().await.unwrap();
        ws.write_all(b"\x01\x03\x00\x00\xd9\x01\x02\x00\x00")
            .await
            .unwrap();
        ws.write_all(suffix).await.unwrap();
        ws.shutdown().await.unwrap();
        let response: Response<R> = rs
            .read_response(Method::GET, client.qpack().clone())
            .await
            .unwrap();
        let error = response
            .into_body()
            .read_to_end(&mut Vec::new())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("frame received after trailers"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn trailers_followed_by_fin_are_accepted() {
    let (client, server) = connection_pair();
    let (_ws, rs) = client.open_bi().await.unwrap();
    let (mut ws, _rs) = server.accept_bi().await.unwrap();
    // Unknown extension before trailers remains skippable.
    ws.write_all(b"\x01\x03\x00\x00\xd9\x21\x00\x01\x02\x00\x00")
        .await
        .unwrap();
    ws.shutdown().await.unwrap();
    let response: Response<R> = rs
        .read_response(Method::GET, client.qpack().clone())
        .await
        .unwrap();
    assert_eq!(
        response
            .into_body()
            .read_to_end(&mut Vec::new())
            .await
            .unwrap(),
        0
    );
}

async fn finished_body(bytes: &[u8]) -> WndBuf {
    let mut body = WndBuf::new(bytes.len().max(1));
    body.write_all(bytes).await.unwrap();
    body.shutdown().await.unwrap();
    body
}

async fn collect(mut body: WndBuf) -> String {
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}
