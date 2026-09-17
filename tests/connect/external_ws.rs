//! Opt-in test against an independent HTTP/1.1 WebSocket server.
//! Only the test adapter performs Upgrade; the relay copies raw frame bytes.
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::{client::generate_key, derive_accept_key},
        protocol::{
            CloseFrame, Role as WsRole,
            frame::{
                Frame,
                coding::{CloseCode, Data, OpCode},
            },
        },
    },
};

use super::*;

async fn upstream_handshake(addr: std::net::SocketAddr) -> (TcpStream, http::Response<()>) {
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let key = generate_key();
    socket.write_all(format!(
        "GET /echo HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: h3x-test\r\n\r\n"
    ).as_bytes()).await.unwrap();
    // Read only the handshake. A greeting following 101 stays in the socket.
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(
            bytes.len() < 16 * 1024,
            "upstream handshake exceeds test limit"
        );
        bytes.push(socket.read_u8().await.unwrap());
    }
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut fields);
    assert!(response.parse(&bytes).unwrap().is_complete());
    assert_eq!(response.code, Some(101));
    let mut headers = http::HeaderMap::new();
    for field in response.headers.iter() {
        headers.append(
            http::HeaderName::from_bytes(field.name.as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(field.value).unwrap(),
        );
    }
    assert!(
        headers["upgrade"]
            .as_bytes()
            .eq_ignore_ascii_case(b"websocket")
    );
    assert!(headers.get_all("connection").iter().any(|v| {
        v.to_str()
            .unwrap()
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    }));
    assert_eq!(
        headers["sec-websocket-accept"],
        derive_accept_key(key.as_bytes())
    );
    assert_eq!(headers["sec-websocket-protocol"], "h3x-test");
    assert!(!headers.contains_key("sec-websocket-extensions"));
    let accepted = http::Response::builder()
        .status(200)
        .header(
            "sec-websocket-protocol",
            headers["sec-websocket-protocol"].clone(),
        )
        .body(())
        .unwrap();
    (socket, accepted)
}

#[tokio::test]
#[ignore = "requires tests/connect/ws_echo.py on H3X_WS_ADDR (default 127.0.0.1:8765)"]
async fn external_ws_echo() {
    let addr: std::net::SocketAddr = std::env::var("H3X_WS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8765".into())
        .parse()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        let (a, b) = pair(4096).await;
        let ((), ()) = tokio::join!(
            async {
                let request = client::Request::connect("ws://echo.example/echo")
                    .unwrap()
                    .header(
                        "sec-websocket-protocol".parse().unwrap(),
                        "h3x-test".parse().unwrap(),
                    );
                let (response, tunnel) = connect(request, &a).await.unwrap();
                assert_eq!(response.headers()["sec-websocket-protocol"], "h3x-test");
                // The CONNECT handshake is complete; don't send an H1 Upgrade inside DATA.
                let mut ws = WebSocketStream::from_raw_socket(tunnel, WsRole::Client, None).await;
                assert_eq!(
                    ws.next().await.unwrap().unwrap(),
                    Message::Text("ready".into())
                );
                println!("PASS 101 + immediate greeting, subprotocol selection");
                for message in [
                    Message::Text("hello, h3x — 你好".into()),
                    Message::Binary((0..=255).collect()),
                    Message::Binary((0..256 * 1024).map(|n| (n % 251) as u8).collect()),
                ] {
                    ws.send(message.clone()).await.unwrap();
                    assert_eq!(ws.next().await.unwrap().unwrap(), message);
                }
                println!("PASS UTF-8 text, binary, 256 KiB message across DATA frames");
                ws.send(Message::Frame(Frame::message(
                    b"frag-".to_vec(),
                    OpCode::Data(Data::Text),
                    false,
                )))
                .await
                .unwrap();
                ws.send(Message::Frame(Frame::message(
                    b"mented".to_vec(),
                    OpCode::Data(Data::Continue),
                    true,
                )))
                .await
                .unwrap();
                assert_eq!(
                    ws.next().await.unwrap().unwrap(),
                    Message::Text("frag-mented".into())
                );
                println!("PASS masked fragmented WebSocket message");
                ws.send(Message::Ping(b"h3x-ping".to_vec())).await.unwrap();
                assert_eq!(
                    ws.next().await.unwrap().unwrap(),
                    Message::Pong(b"h3x-ping".to_vec())
                );
                println!("PASS Ping/Pong");
                let close = CloseFrame {
                    code: CloseCode::Normal,
                    reason: "test done".into(),
                };
                ws.send(Message::Close(Some(close.clone()))).await.unwrap();
                assert_eq!(
                    ws.next().await.unwrap().unwrap(),
                    Message::Close(Some(close))
                );
                ws.get_mut().finish().await.unwrap();
                assert_eq!(ws.get_mut().read(&mut [0]).await.unwrap(), 0);
                println!("PASS Close handshake and bidirectional EOF");
            },
            async {
                let (send, mut recv) = b.accept_bi().await.unwrap();
                let head = server::read_request_head(&mut recv, b.qpack())
                    .await
                    .unwrap();
                assert_eq!(
                    head.extensions()
                        .get::<h3x::Protocol>()
                        .unwrap()
                        .as_str(),
                    "websocket"
                );
                assert_eq!(head.headers()["sec-websocket-protocol"], "h3x-test");
                // Backend comes from test configuration, not the request authority.
                let (mut upstream, response) = upstream_handshake(addr).await;
                let mut tunnel = accept_connect(response, send, recv, b.qpack().clone(), head)
                    .await
                    .unwrap();
                let (sent, received) = io::copy_bidirectional(&mut tunnel, &mut upstream)
                    .await
                    .unwrap();
                assert!(sent > 256 * 1024 && received > 256 * 1024);
                println!("PASS raw relay: {sent} bytes upstream, {received} bytes downstream");
            }
        );
    })
    .await
    .expect("external WS test timed out");
}

async fn incoming_handshake(socket: &mut TcpStream) -> http::Request<()> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(
            bytes.len() < 16 * 1024,
            "incoming handshake exceeds test limit"
        );
        bytes.push(socket.read_u8().await.unwrap());
    }
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut fields);
    assert!(parsed.parse(&bytes).unwrap().is_complete());
    assert_eq!(parsed.version, Some(1));
    let mut request = http::Request::builder()
        .method(parsed.method.unwrap())
        .uri(parsed.path.unwrap())
        .version(http::Version::HTTP_11)
        .body(())
        .unwrap();
    for field in parsed.headers.iter() {
        request.headers_mut().append(
            http::HeaderName::from_bytes(field.name.as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(field.value).unwrap(),
        );
    }
    request
}

#[tokio::test]
#[ignore = "listens on H3X_WS_LISTEN (default 127.0.0.1:8766); run tests/connect/ws_client.py"]
async fn external_ws_incoming() {
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::server::{create_response, write_response};
    let addr: std::net::SocketAddr = std::env::var("H3X_WS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8766".into())
        .parse()
        .unwrap();
    assert!(
        addr.ip().is_loopback(),
        "test ingress must only listen on loopback"
    );
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("READY ws://{addr}/echo?mode=reverse; run tests/connect/ws_client.py");
    tokio::time::timeout(Duration::from_secs(90), async {
        let (a, b) = pair(4096).await;
        let ((), ()) = tokio::join!(async {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let h1 = incoming_handshake(&mut socket).await;
                let mut upgrade = create_response(&h1).unwrap();
                let mut request = client::Request::connect(&format!("ws://echo.example{}",h1.uri())).unwrap();
                for name in ["sec-websocket-protocol", "origin"] {
                    request = request.header(name.parse().unwrap(), h1.headers()[name].clone());
                }
                // Do not send 101 until the H3 server accepts this request.
                match connect(request, &a).await {
                    Ok((response, mut tunnel)) => {
                        assert_eq!(response.headers()["sec-websocket-protocol"], "h3x-test");
                        upgrade.headers_mut().insert("sec-websocket-protocol", response.headers()["sec-websocket-protocol"].clone());
                        let mut bytes = Vec::new();
                        write_response(&mut bytes, &upgrade).unwrap();
                        socket.write_all(&bytes).await.unwrap();
                        let (sent,received) = io::copy_bidirectional(&mut socket,&mut tunnel).await.unwrap();
                        assert!(sent > 256*1024 && received > 256*1024);
                        println!("PASS external client raw relay: {sent} bytes to H3, {received} bytes from H3");
                    }
                    Err(client::ConnectError::Rejected(response)) => {
                        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
                        let status = response.status();
                        let body = response.into_body().collect().await.unwrap();
                        let rejection = http::Response::builder().status(status)
                            .header("content-length",body.len()).header("connection","close").body(()).unwrap();
                        let mut bytes = Vec::new();
                        write_response(&mut bytes,&rejection).unwrap();
                        bytes.extend_from_slice(&body);
                        socket.write_all(&bytes).await.unwrap();
                        socket.shutdown().await.unwrap();
                        println!("PASS H3 403 propagated without sending 101");
                    }
                    Err(error) => panic!("CONNECT failed: {error}"),
                }
            }
        }, async {
            for _ in 0..2 {
                let (send, mut recv) = b.accept_bi().await.unwrap();
                let head = server::read_request_head(&mut recv,b.qpack()).await.unwrap();
                assert_eq!(head.extensions().get::<h3x::Protocol>().unwrap().as_str(),"websocket");
                assert_eq!(head.headers()["sec-websocket-protocol"],"h3x-test");
                assert_eq!(head.headers()["origin"],"https://external.example");
                assert!(!head.headers().contains_key("sec-websocket-key"));
                if head.uri().path() == "/reject" {
                    drop(recv);
                    let mut response = server::Response::default();
                    response.set_status(http::StatusCode::FORBIDDEN).set_body(Bytes::from_static(b"denied"));
                    server::write_bytes_response(response,send,b.qpack().clone(),head.method()).await.unwrap();
                    continue;
                }
                assert_eq!(head.uri().path_and_query().unwrap().as_str(),"/echo?mode=reverse");
                let response = http::Response::builder().status(200).header("sec-websocket-protocol","h3x-test").body(()).unwrap();
                let tunnel = accept_connect(response,send,recv,b.qpack().clone(),head).await.unwrap();
                let mut ws = WebSocketStream::from_raw_socket(tunnel,WsRole::Server,None).await;
                ws.send(Message::Text("h3-ready".into())).await.unwrap();
                let mut echoed = 0;
                let mut ping_seen = false;
                loop {
                    match ws.next().await.expect("client closed without WS Close").unwrap() {
                        message @ (Message::Text(_) | Message::Binary(_)) => {
                            ws.send(message).await.unwrap();
                            echoed += 1;
                        }
                        Message::Ping(payload) => {
                            assert_eq!(payload,b"reverse-ping");
                            ping_seen = true;
                            ws.flush().await.unwrap(); // endpoint codec queued Pong
                        }
                        Message::Close(close) => {
                            assert_eq!(close.unwrap().code,CloseCode::Normal);
                            ws.flush().await.unwrap(); // endpoint codec queued Close response
                            break;
                        }
                        message => panic!("unexpected WS message: {message:?}"),
                    }
                }
                assert_eq!(echoed,4);
                assert!(ping_seen);
                ws.get_mut().finish().await.unwrap();
                assert_eq!(ws.get_mut().read(&mut [0]).await.unwrap(),0);
                println!("PASS H3 server: 4 echoed messages, Ping/Pong, Close, bidirectional EOF");
            }
        });
    }).await.expect("reverse external WS test timed out");
}
