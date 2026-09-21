mod support;

use h3x::{ErrorCode, R, ReadResponse, Request, Response, Trailers, W, WndBuf, WriteResponse};
use qrecovery::{recv::StopSending, send::CancelStream};
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
    let mut response = receive(wire).await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"abc");
    assert_eq!(response.trailers()["x-checksum"], "ok");
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
            ErrorCode::FrameUnexpected | ErrorCode::MessageError
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
    assert_eq!(h3x::Error::from(error).code, ErrorCode::FrameError);
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
        ws.write_response(response, http::Method::GET, server.qpack().clone())
            .await
            .unwrap();
        let response: Response<R> = rs
            .read_response(http::Method::GET, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(collect(response.into_body()).await, "abc");
    }
}

#[tokio::test]
async fn head_response_omits_outgoing_body() {
    let (client, server) = connection_pair();
    let (_ws, rs) = client.open_bi().await.unwrap();
    let (ws, _rs) = server.accept_bi().await.unwrap();
    let response: Response<W> = http::Response::builder()
        .body(finished_body(b"not sent").await)
        .unwrap()
        .into();

    ws.write_response(response, http::Method::HEAD, server.qpack().clone())
        .await
        .unwrap();
    let mut response = rs
        .read_response(http::Method::HEAD, client.qpack().clone())
        .await
        .unwrap();
    let mut bytes = Vec::new();
    response.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn responses_without_content_omit_outgoing_trailers() {
    for status in [http::StatusCode::NO_CONTENT, http::StatusCode::NOT_MODIFIED] {
        let (client, server) = connection_pair();
        let (_ws, rs) = client.open_bi().await.unwrap();
        let (ws, _rs) = server.accept_bi().await.unwrap();
        let response: Response<W> = http::Response::builder()
            .status(status)
            .body(finished_body(b"").await)
            .unwrap()
            .into();
        response.set_trailer(
            http::HeaderName::from_static("x-checksum"),
            http::HeaderValue::from_static("not-sent"),
        );

        ws.write_response(response, http::Method::GET, server.qpack().clone())
            .await
            .unwrap();
        let mut response = rs
            .read_response(http::Method::GET, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.read_to_end(&mut Vec::new()).await.unwrap(), 0);
        assert!(response.trailers().is_empty());
    }
}

#[tokio::test]
async fn responses_without_content_reject_incoming_trailers() {
    for status in ["204", "304"] {
        let mut wire = headers(&[(":status", status)]);
        wire.extend(headers(&[("x-checksum", "unexpected")]));
        let mut response = receive(wire).await.unwrap();
        let error = response.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(h3x::Error::from(error).code, ErrorCode::MessageError);
        assert!(response.trailers().is_empty());
    }
}

#[tokio::test]
async fn head_response_closes_an_unconsumed_body_producer() {
    let (client, server) = connection_pair();
    let (_ws, rs) = client.open_bi().await.unwrap();
    let (ws, _rs) = server.accept_bi().await.unwrap();
    let window = WndBuf::new(1);
    let mut producer = window.clone();
    producer.write_all(b"x").await.unwrap();
    let response: Response<W> = http::Response::builder().body(window).unwrap().into();

    let writing = ws.write_response(response, http::Method::HEAD, server.qpack().clone());
    let producing = async {
        let error = producer.write_all(b"y").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::join!(writing, producing)
    })
    .await
    .expect("an omitted response body must release its producer");
    result.unwrap();

    let response = rs
        .read_response(http::Method::HEAD, client.qpack().clone())
        .await
        .unwrap();
    assert!(collect(response.into_body()).await.is_empty());
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
    let writing = ws.write_response(response, http::Method::GET, server.qpack().clone());
    let producing = async {
        producer.write_all(b"y").await.unwrap();
        producer.shutdown().await.unwrap();
    };
    let (result, ()) = tokio::join!(writing, producing);
    result.unwrap();
    let response: Response<R> = rs
        .read_response(http::Method::GET, client.qpack().clone())
        .await
        .unwrap();
    assert_eq!(collect(response.into_body()).await, "xy");
}

#[tokio::test]
async fn repeated_regular_headers_are_preserved() {
    let wire = headers(&[(":status", "200"), ("x-tag", "a"), ("x-tag", "b")]);
    let response = receive(wire).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers().get_all("x-tag").iter().count(), 2);
}

#[tokio::test]
async fn malformed_response_pseudo_headers_are_rejected() {
    for fields in [
        vec![(":status", "201"), (":status", "200")],
        vec![(":method", "GET"), (":status", "200")],
        vec![("x-tag", "a"), (":status", "200")],
    ] {
        let error = match receive(headers(&fields)).await {
            Ok(_) => panic!("malformed response was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::MessageError);
    }
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
async fn message_parts_transfer_between_io_directions_without_copying_body() {
    let request: Request<W> = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://example.com/wasm")
        .body(finished_body(b"request").await)
        .unwrap()
        .into();
    request.set_trailer(
        http::HeaderName::from_static("x-request-trailer"),
        http::HeaderValue::from_static("preserved"),
    );
    let (head, body) = request.into_parts();
    let mut request = Request::<R>::from_parts(head, body);
    let mut bytes = Vec::new();
    request.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(bytes, b"request");
    assert_eq!(request.trailers()["x-request-trailer"], "preserved");

    let response: Response<W> = http::Response::builder()
        .status(http::StatusCode::CREATED)
        .body(finished_body(b"response").await)
        .unwrap()
        .into();
    response.set_trailer(
        http::HeaderName::from_static("x-response-trailer"),
        http::HeaderValue::from_static("preserved"),
    );
    let (head, body) = response.into_parts();
    let mut response = Response::<R>::from_parts(head, body);
    bytes.clear();
    response.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::CREATED);
    assert_eq!(bytes, b"response");
    assert_eq!(response.trailers()["x-response-trailer"], "preserved");
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
        rs.read_response(http::Method::GET, client.qpack().clone()),
    )
    .await
    .expect("headers must return without waiting for DATA or FIN")
    .unwrap();
    ws.write_all(&[0, 3, b'a', b'b', b'c']).await.unwrap();
    ws.shutdown().await.unwrap();
    assert_eq!(collect(response.into_body()).await, "abc");
}

#[tokio::test]
async fn aborting_an_incoming_body_stops_an_idle_transport_read() {
    let (client, server) = connection_pair();
    let (_request_writer, rs) = client.open_bi().await.unwrap();
    let (mut ws, _request_reader) = server.accept_bi().await.unwrap();
    ws.write_all(&headers(&[(":status", "200")])).await.unwrap();

    let mut response = rs
        .read_response(http::Method::GET, client.qpack().clone())
        .await
        .unwrap();
    response.stop(ErrorCode::RequestCancelled.as_u64());

    let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Err(error) = ws.write_all(&[0, 0]).await {
                break error;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("message stop must interrupt the pending network read");
    assert!(matches!(
        h3x::Error::from(error).code,
        ErrorCode::RequestCancelled | ErrorCode::InternalError
    ));
}

#[tokio::test]
async fn aborting_a_backpressured_body_does_not_fail_the_connection() {
    let (client, server) = connection_pair();
    let (_request_writer, rs) = client.open_bi().await.unwrap();
    let (mut ws, _request_reader) = server.accept_bi().await.unwrap();

    let mut wire = headers(&[(":status", "200")]);
    // A four-byte QUIC varint encoding of 128 KiB. This is larger than both
    // the body window and the test transport buffer, so the receiver must be
    // blocked writing to the full body window before the sender can finish.
    wire.extend([0, 0x80, 0x02, 0x00, 0x00]);
    wire.resize(wire.len() + 128 * 1024, b'x');
    let mut writing = tokio::spawn(async move { ws.write_all(&wire).await });

    let mut response = rs
        .read_response(http::Method::GET, client.qpack().clone())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut writing)
            .await
            .is_err(),
        "sender should be backpressured by the full body window"
    );
    response.stop(ErrorCode::RequestCancelled.as_u64());
    let error = response.read(&mut [0; 1]).await.unwrap_err();
    assert!(matches!(h3x::Error::from(error), h3x::Error::Stream(_)));

    let (_request_writer, rs) = client.open_bi().await.unwrap();
    let (mut ws, _request_reader) = server.accept_bi().await.unwrap();
    ws.write_all(&headers(&[(":status", "204")])).await.unwrap();
    ws.shutdown().await.unwrap();
    let response = rs
        .read_response(http::Method::GET, client.qpack().clone())
        .await
        .expect("cancelling one body must leave the connection usable");
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);

    writing.abort();
}

#[tokio::test]
async fn directional_messages_expose_transport_cancellation() {
    let mut request: Request<R> =
        Request::from_parts(http::Request::new(()).into_parts().0, WndBuf::new(1));
    request.stop(ErrorCode::RequestCancelled.as_u64());
    let error = request.read(&mut [0]).await.unwrap_err();
    assert_eq!(h3x::Error::from(error).code, ErrorCode::RequestCancelled);

    let mut response: Response<W> = http::Response::new(WndBuf::new(1)).into();
    response.cancel(ErrorCode::InternalError.as_u64());
    let error = response.write_all(b"x").await.unwrap_err();
    assert_eq!(h3x::Error::from(error).code, ErrorCode::InternalError);
}

#[tokio::test]
async fn message_accessors_mutators_and_io_delegation() {
    let mut request: Request<W> = http::Request::builder()
        .uri("ws://example.com/initial")
        .body(WndBuf::new(16))
        .unwrap()
        .into();
    request
        .set_protocol("websocket")
        .set_method(http::Method::CONNECT)
        .set_uri("wss://example.com/chat".parse().unwrap())
        .set_header(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("a"),
        )
        .append_header(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("b"),
        );
    request
        .set_trailer(
            http::HeaderName::from_static("x-checksum"),
            http::HeaderValue::from_static("one"),
        )
        .append_trailer(
            http::HeaderName::from_static("x-checksum"),
            http::HeaderValue::from_static("two"),
        );
    assert_eq!(request.uri(), "https://example.com/chat");
    assert_eq!(request.protocol(), Some("websocket"));
    assert_eq!(request.headers().get_all("x-tag").iter().count(), 2);
    assert_eq!(request.trailers().get_all("x-checksum").iter().count(), 2);
    let _ = request.body();

    let mut request_clone = request.clone();
    request_clone.write_all(b"request").await.unwrap();
    request_clone.flush().await.unwrap();
    request_clone.shutdown().await.unwrap();
    let http_request: http::Request<WndBuf> = request.into();
    let request: Request<W> = http_request.into();
    assert_eq!(collect(request.into_body()).await, "request");

    let mut response: Response<W> = http::Response::new(WndBuf::new(16)).into();
    response
        .set_status(http::StatusCode::CREATED)
        .set_header(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("a"),
        )
        .append_header(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("b"),
        );
    response
        .set_trailer(
            http::HeaderName::from_static("x-checksum"),
            http::HeaderValue::from_static("one"),
        )
        .append_trailer(
            http::HeaderName::from_static("x-checksum"),
            http::HeaderValue::from_static("two"),
        );
    assert_eq!(response.headers().get_all("x-tag").iter().count(), 2);
    assert_eq!(response.trailers().get_all("x-checksum").iter().count(), 2);
    let _ = response.body();

    let mut response_clone = response.clone();
    response_clone.write_all(b"response").await.unwrap();
    response_clone.flush().await.unwrap();
    response_clone.shutdown().await.unwrap();
    let http_response: http::Response<WndBuf> = response.into();
    let response: Response<W> = http_response.into();
    assert_eq!(collect(response.into_body()).await, "response");

    let trailers = Trailers::new();
    assert!(trailers.is_empty());

    let mut outgoing_request: Request<W> = http::Request::new(WndBuf::new(1)).into();
    outgoing_request.cancel(ErrorCode::RequestCancelled.as_u64());
    assert_eq!(
        h3x::Error::from(outgoing_request.write_all(b"x").await.unwrap_err()).code,
        ErrorCode::RequestCancelled
    );

    let mut incoming_response: Response<R> =
        Response::from_parts(http::Response::new(()).into_parts().0, WndBuf::new(1));
    incoming_response.stop(ErrorCode::RequestCancelled.as_u64());
    assert_eq!(
        h3x::Error::from(incoming_response.read(&mut [0]).await.unwrap_err()).code,
        ErrorCode::RequestCancelled
    );
}
