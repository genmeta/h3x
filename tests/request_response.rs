mod support;

use std::sync::Arc;

use h3x::{
    IncomingRequest, IncomingResponse, ReadMeesage, ReadRequest, ReadResponse, Request, Response,
    WndBuf, WriteMessage, WriteRequest,
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
        let request: IncomingRequest = rs.read_message(server.qpack().clone()).await.unwrap();
        let method = request.method();

        assert_eq!(method, Method::POST);
        assert_eq!(request.path(), "/echo");
        let body = collect(request.into_body()).await;
        assert_eq!(body, "hello");

        let response: Response = http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, "5")
            .body(finished_body(b"world").await)
            .unwrap()
            .into();
        ws.write_message(response, server.qpack().clone())
            .await
            .unwrap();
    });

    // Client: open a request stream. `ws` sends the request and the paired `rs`
    // receives the response. Drive both message futures concurrently.
    let (ws, rs) = client.open_bi().await.unwrap();
    let request: Request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/echo")
        .header(header::CONTENT_LENGTH, "5")
        .body(finished_body(b"hello").await)
        .unwrap()
        .into();
    let writing = ws.write_message(request, client.qpack().clone());
    let receiving = rs.read_message(client.qpack().clone());
    let ((), response): ((), IncomingResponse) = tokio::try_join!(writing, receiving).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(collect(response.into_body()).await, "world");
    serving.await.unwrap();
}

#[tokio::test]
async fn streaming_request_and_response() {
    let (client, server) = connection_pair();

    let serving = tokio::spawn(async move {
        let (ws, rs) = server.accept_bi().await.unwrap();
        let request: IncomingRequest = rs.read_message(server.qpack().clone()).await.unwrap();
        let method = request.method();

        assert_eq!(method, Method::POST);
        assert_eq!(collect(request.into_body()).await, "streamed request");

        // A streaming writer drains the WndBuf while the producer fills it.
        // Drive both futures concurrently, otherwise a bounded buffer can stall.
        let response_window = WndBuf::new(4);
        let mut response_body = response_window.clone();
        let response: Response = http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, "17")
            .body(response_window)
            .unwrap()
            .into();
        let writing = ws.write_message(response, server.qpack().clone());
        let producing = async move {
            response_body.write_all(b"streamed response").await?;
            response_body.shutdown().await.map_err(h3x::Error::from)
        };
        tokio::try_join!(writing, producing).unwrap();
    });

    let (ws, rs) = client.open_bi().await.unwrap();
    let request_window = WndBuf::new(4);
    let mut request_body = request_window.clone();
    let request: Request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/upload")
        .header(header::CONTENT_LENGTH, "16")
        .body(request_window)
        .unwrap()
        .into();

    let writing = ws.write_message(request, client.qpack().clone());
    let receiving = rs.read_message(client.qpack().clone());
    let producing = async move {
        request_body.write_all(b"streamed request").await?;
        request_body.shutdown().await.map_err(h3x::Error::from)
    };
    let ((), response, ()): ((), IncomingResponse, ()) =
        tokio::try_join!(writing, receiving, producing).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(collect(response.into_body()).await, "streamed response");
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
        let request: IncomingRequest = rs.read_message(server.qpack().clone()).await.unwrap();
        let method = request.method();

        // RFC 9220 represents WebSocket as an extended CONNECT request.
        assert_eq!(method, Method::CONNECT);
        assert_eq!(request.protocol().as_deref(), Some("websocket"));
        assert_eq!(request.scheme(), "https");
        assert_eq!(request.path(), "/chat");
        assert_eq!(request.headers()["sec-websocket-protocol"], "chat");
        let mut request_body: WndBuf = request.into_body();

        // A successful CONNECT response has a streaming body and no
        // Content-Length. Sending its HEADERS accepts the tunnel.
        let response_window = WndBuf::new(4);
        let mut response_body = response_window.clone();
        let response: Response = http::Response::builder()
            .status(StatusCode::OK)
            .header("sec-websocket-protocol", "chat")
            .body(response_window)
            .unwrap()
            .into();
        let writing = ws.write_message(response, server.qpack().clone());
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
    let request: Request = http::Request::builder()
        .method(Method::CONNECT)
        .uri("wss://example.com/chat")
        .extension(Arc::<str>::from("websocket"))
        .header("sec-websocket-protocol", "chat")
        .body(request_window)
        .unwrap()
        .into();

    // CONNECT data is held until the peer accepts with final 2xx HEADERS.
    let uploading = tokio::spawn(ws.write_message(request, client.qpack().clone()));
    let response: IncomingResponse = rs.read_message(client.qpack().clone()).await.unwrap();
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
    fn request(uri: &str, protocol: &str) -> Request {
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

    let mut request: Request = http::Request::builder()
        .method(Method::GET)
        .uri("wss://example.com/chat")
        .extension(Arc::<str>::from("websocket"))
        .body(WndBuf::new(1))
        .unwrap()
        .into();
    assert_eq!(request.scheme(), "wss");
    request.set_method(Method::CONNECT);
    assert_eq!(request.scheme(), "https");

    let mut request: Request = http::Request::builder()
        .method(Method::CONNECT)
        .uri("wss://example.com/chat")
        .body(WndBuf::new(1))
        .unwrap()
        .into();
    request.set_protocol("websocket");
    assert_eq!(request.protocol().as_deref(), Some("websocket"));
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
        let response: IncomingResponse = rs.read_message(client.qpack().clone()).await.unwrap();
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
    let response: IncomingResponse = rs.read_message(client.qpack().clone()).await.unwrap();
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
