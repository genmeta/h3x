mod support;

use h3x::{ErrorCode, R, ReadMeesage, ReadResponse, Response, W, WndBuf, WriteMessage};
use support::connection_pair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Literal-only QPACK lets these tests inject arbitrary fields directly.
fn headers(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut block = vec![0, 0];
    for (name, value) in fields {
        assert!(name.len() < 134 && value.len() < 127);
        if name.len() < 7 {
            block.push(0x20 | name.len() as u8);
        } else {
            block.extend([0x27, (name.len() - 7) as u8]);
        }
        block.extend(name.as_bytes());
        block.push(value.len() as u8);
        block.extend(value.as_bytes());
    }
    assert!(block.len() < 16384);
    let mut frame = vec![1];
    if block.len() < 64 {
        frame.push(block.len() as u8);
    } else {
        frame.extend(((block.len() as u16) | 0x4000).to_be_bytes());
    }
    frame.extend(block);
    frame
}

async fn receive(wire: Vec<u8>) -> Result<Response<R>, h3x::Error> {
    let (client, server) = connection_pair();
    let (_request_writer, rs) = client.open_bi().await.unwrap();
    let (mut ws, _request_reader) = server.accept_bi().await.unwrap();
    ws.write_all(&wire).await.unwrap();
    ws.shutdown().await.unwrap();
    rs.read_message(client.qpack().clone()).await
}

#[tokio::test]
async fn informational_response_and_unknown_frames_before_final_headers() {
    let mut wire = vec![0x21, 2, 0xaa, 0xbb];
    wire.extend(headers(&[(":status", "103"), ("link", "</style.css>")]));
    wire.extend(headers(&[(":status", "200"), ("content-length", "3")]));
    wire.extend([0, 3, b'a', b'b', b'c']);
    wire.extend(headers(&[("x-checksum", "ok")]));
    let response = receive(wire).await.unwrap();
    let body = collect(response.into_body()).await;
    assert_eq!(body, "abc");
}

#[tokio::test]
async fn content_length_mismatches_are_accepted() {
    for (length, data) in [
        ("4", vec![0, 3, b'a', b'b', b'c']),
        ("2", vec![0, 3, b'a', b'b', b'c']),
    ] {
        let mut wire = headers(&[(":status", "200"), ("content-length", length)]);
        wire.extend(data);
        let response = receive(wire).await.unwrap();
        let body = collect(response.into_body()).await;
        assert_eq!(body, "abc");
    }
}

#[tokio::test]
async fn data_after_trailers_is_rejected() {
    for trailer in [headers(&[]), headers(&[(":status", "200")])] {
        let mut wire = headers(&[(":status", "200"), ("content-length", "0")]);
        wire.extend(trailer);
        wire.extend([0, 0]);
        let error = h3x::Error::from(
            receive(wire)
                .await
                .unwrap()
                .into_body()
                .read_to_end(&mut Vec::new())
                .await
                .unwrap_err(),
        );
        assert!(matches!(
            error.code,
            ErrorCode::H3_FRAME_UNEXPECTED | ErrorCode::H3_MESSAGE_ERROR
        ));
    }
}

#[tokio::test]
async fn truncated_streaming_data_error_reaches_body_consumer() {
    let mut wire = headers(&[(":status", "200")]);
    wire.extend([0, 4, b'a']);
    let response = receive(wire).await.unwrap();
    let mut body: WndBuf = response.into_body();
    let error = body.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(h3x::Error::from(error).code, ErrorCode::H3_FRAME_ERROR);
}

#[tokio::test]
async fn incoming_head_body_is_streamed_without_length_validation() {
    let wire = headers(&[(":status", "200"), ("content-length", "123")]);
    let response = receive(wire.clone()).await.unwrap();
    assert!(collect(response.into_body()).await.is_empty());
    let mut invalid = wire;
    invalid.extend([0, 1, b'x']);
    let response = receive(invalid).await.unwrap();
    assert_eq!(collect(response.into_body()).await, "x");
}

#[tokio::test]
async fn outgoing_body_is_streamed_without_length_validation() {
    for length in ["0", "2", "4", "invalid"] {
        let (client, server) = connection_pair();
        let (_ws, rs) = client.open_bi().await.unwrap();
        let (ws, _rs) = server.accept_bi().await.unwrap();
        let response: Response<W> = http::Response::builder()
            .header("content-length", length)
            .body(finished_body(b"abc").await)
            .unwrap()
            .into();
        ws.write_message(response, server.qpack().clone())
            .await
            .unwrap();
        let response: Response<R> = rs.read_message(client.qpack().clone()).await.unwrap();
        assert_eq!(collect(response.into_body()).await, "abc");
    }
}

#[tokio::test]
async fn oversized_streaming_body_allows_producer_to_finish() {
    let (client, server) = connection_pair();
    let (_ws, rs) = client.open_bi().await.unwrap();
    let (ws, _rs) = server.accept_bi().await.unwrap();
    let window = WndBuf::new(1);
    let mut producer = window.clone();
    producer.write_all(b"x").await.unwrap();
    let response: Response<W> = http::Response::builder()
        .header("content-length", "0")
        .body(window)
        .unwrap()
        .into();
    let writing = ws.write_message(response, server.qpack().clone());
    let producing = async {
        producer.write_all(b"y").await.unwrap();
        producer.shutdown().await.unwrap();
    };
    let (result, ()) = tokio::join!(writing, producing);
    result.unwrap();
    let response: Response<R> = rs.read_message(client.qpack().clone()).await.unwrap();
    assert_eq!(collect(response.into_body()).await, "xy");
}

#[tokio::test]
async fn headers_are_stored_without_protocol_validation() {
    let wire = headers(&[
        ("connection", "close"),
        (":status", "201"),
        (":status", "200"),
        (":method", "GET"),
        ("content-length", "0"),
        ("x-tag", "a"),
        ("x-tag", "b"),
    ]);
    let response = receive(wire).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let regular = response.headers();
    assert_eq!(regular["connection"], "close");
    assert_eq!(regular.get_all("x-tag").iter().count(), 2);
    assert!(regular.get(":status").is_none());
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

#[tokio::test]
async fn content_length_returns_body_before_data_arrives() {
    let (client, server) = connection_pair();
    let (_ws, rs) = client.open_bi().await.unwrap();
    let (mut ws, _rs) = server.accept_bi().await.unwrap();
    ws.write_all(&headers(&[(":status", "200"), ("content-length", "3")]))
        .await
        .unwrap();
    let response: Response<R> = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        rs.read_message(client.qpack().clone()),
    )
    .await
    .expect("headers must return without waiting for DATA or FIN")
    .unwrap();
    ws.write_all(&[0, 3, b'a', b'b', b'c']).await.unwrap();
    ws.shutdown().await.unwrap();
    assert_eq!(collect(response.into_body()).await, "abc");
}
