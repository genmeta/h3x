use support::connection_pair;
mod support;

use bytes::Bytes;
use h3x::{Body, ErrorCode, ReadResponse, WriteResponse};
use http_body_util::{BodyExt, Full};
use tokio::io::AsyncWriteExt;

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

async fn receive(wire: Vec<u8>) -> h3x::Result<http::Response<Body>> {
    let (client, server) = connection_pair();
    let (mut _unused_direction_1, rs) = client.open_bi().await.unwrap();
    let (mut ws, _unused_direction_2) = server.accept_bi().await.unwrap();
    ws.write_all(&wire).await.unwrap();
    ws.shutdown().await.unwrap();
    _unused_direction_1.shutdown().await.unwrap();
    rs.read_response(http::Method::GET, client.qpack().clone())
        .await
}

#[tokio::test]
async fn informational_response_and_unknown_frames_before_final_headers() {
    let mut wire = vec![0x21, 2, 0xaa, 0xbb];
    wire.extend(headers(&[(":status", "103"), ("link", "</style.css>")]));
    wire.extend(headers(&[(":status", "200"), ("content-length", "3")]));
    wire.extend([0, 3, b'a', b'b', b'c']);
    wire.extend(headers(&[("x-checksum", "ok")]));
    let received = receive(wire)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(received.trailers().unwrap()["x-checksum"], "ok");
    assert_eq!(received.to_bytes(), "abc");
}

#[tokio::test]
async fn content_length_does_not_change_body_storage_or_current_validation() {
    for length in ["0", "2", "4", "invalid"] {
        let (client, server) = connection_pair();
        let (_unused_direction_3, rs) = client.open_bi().await.unwrap();
        let (ws, _unused_direction_4) = server.accept_bi().await.unwrap();
        let response = http::Response::builder()
            .header("content-length", length)
            .body(
                Full::new(Bytes::from_static(b"abc"))
                    .map_err(Into::into)
                    .boxed_unsync(),
            )
            .unwrap();
        ws.write_response(response, http::Method::GET, server.qpack().clone())
            .await
            .unwrap();
        let response = rs
            .read_response(http::Method::GET, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "abc"
        );
    }
}

#[tokio::test]
async fn truncated_streaming_data_error_reaches_body_consumer() {
    let mut wire = headers(&[(":status", "200")]);
    wire.extend([0, 4, b'a']);
    let error = receive(wire)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<h3x::Error>().unwrap().code,
        ErrorCode::FrameError
    );
}

#[tokio::test]
async fn malformed_response_pseudo_headers_are_rejected() {
    for fields in [
        vec![(":status", "201"), (":status", "200")],
        vec![(":method", "GET"), (":status", "200")],
        vec![("x-tag", "a"), (":status", "200")],
    ] {
        assert_eq!(
            receive(headers(&fields)).await.unwrap_err().code,
            ErrorCode::MessageError
        );
    }
}

#[tokio::test]
async fn repeated_regular_headers_are_preserved() {
    let response = receive(headers(&[
        (":status", "200"),
        ("x-tag", "a"),
        ("x-tag", "b"),
    ]))
    .await
    .unwrap();
    assert_eq!(response.headers().get_all("x-tag").iter().count(), 2);
}

#[tokio::test]
async fn responses_without_content_reject_incoming_trailers() {
    for status in ["204", "304"] {
        let mut wire = headers(&[(":status", status)]);
        wire.extend(headers(&[("x-checksum", "unexpected")]));
        let error = receive(wire)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<h3x::Error>().unwrap().code,
            ErrorCode::MessageError
        );
    }
}

#[tokio::test]
async fn content_length_returns_body_before_data_arrives() {
    let (client, server) = connection_pair();
    let (_unused_direction_5, rs) = client.open_bi().await.unwrap();
    let (mut ws, _unused_direction_6) = server.accept_bi().await.unwrap();
    ws.write_all(&headers(&[(":status", "200"), ("content-length", "3")]))
        .await
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        rs.read_response(http::Method::GET, client.qpack().clone()),
    )
    .await
    .unwrap()
    .unwrap();
    ws.write_all(&[0, 3, b'a', b'b', b'c']).await.unwrap();
    ws.shutdown().await.unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "abc"
    );
}

#[tokio::test]
async fn dropping_a_backpressured_body_unblocks_sender_without_failing_connection() {
    let (client, server) = connection_pair();
    let (_unused_direction_7, rs) = client.open_bi().await.unwrap();
    let (mut ws, _unused_direction_8) = server.accept_bi().await.unwrap();
    let mut wire = headers(&[(":status", "200")]);
    wire.extend([0, 0x80, 0x02, 0x00, 0x00]);
    wire.resize(wire.len() + 128 * 1024, b'x');
    let mut sending = tokio::spawn(async move { ws.write_all(&wire).await });
    let response = rs
        .read_response(http::Method::GET, client.qpack().clone())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut sending)
            .await
            .is_err()
    );
    drop(response);
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), sending)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(h3x::Error::from(error).code, ErrorCode::NoError);
    let (_unused_direction_9, rs) = client.open_bi().await.unwrap();
    let (mut ws, _unused_direction_10) = server.accept_bi().await.unwrap();
    ws.write_all(&headers(&[(":status", "204")])).await.unwrap();
    ws.shutdown().await.unwrap();
    assert_eq!(
        rs.read_response(http::Method::GET, client.qpack().clone())
            .await
            .unwrap()
            .status(),
        204
    );
}
