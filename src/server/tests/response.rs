use super::*;

async fn write_bytes_response<W: AsyncWrite + Unpin>(
    response: Response<Bytes>,
    send: W,
) -> Result<()> {
    super::write_bytes_response(
        response,
        crate::test_support::write_stream(0, send),
        crate::test_support::connection().await.qpack().clone(),
        &Method::GET,
    )
    .await
}

async fn write_streaming_response<W: AsyncWrite + Unpin>(
    response: Response<ArcWndBuf>,
    send: W,
) -> Result<()> {
    super::write_streaming_response(
        response,
        crate::test_support::write_stream(0, send),
        crate::test_support::connection().await.qpack().clone(),
        &Method::GET,
    )
    .await
}

#[tokio::test]
async fn respond_sends_head_response_without_data() {
    for buffered in [true, false] {
        let mut response = Response::<Bytes>::default();
        response.set_status(StatusCode::OK);
        response.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        let response: common::Response<Write> = if buffered {
            response.into()
        } else {
            let mut response = response.streaming(1);
            response.finish().await.unwrap();
            response.into()
        };
        let mut encoded = Vec::new();
        super::respond(
            response,
            crate::test_support::write_stream(4, &mut encoded),
            crate::test_support::connection().await.qpack().clone(),
            &Method::HEAD,
        )
        .await
        .unwrap();

        let mut input = encoded.as_slice();
        let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected HEADERS")
        };
        let fields = crate::test_support::connection()
            .await
            .qpack()
            .decode(4, frame.payload.field_section)
            .await
            .unwrap();
        let head = headers::be_response(fields).unwrap();
        assert_eq!(head.status().unwrap(), StatusCode::OK);
        assert_eq!(head.headers[header::CONTENT_LENGTH], "5");
        assert!(input.is_empty(), "HEAD response must not contain DATA");
    }
}

#[tokio::test]
async fn respond_rejects_length_mismatch_and_forbidden_body() {
    for buffered in [true, false] {
        for (method, body) in [(Method::GET, &b""[..]), (Method::HEAD, &b"hello"[..])] {
            let mut response = Response::<Bytes>::default();
            response.set_status(StatusCode::OK);
            response.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
            let response: common::Response<Write> = if buffered {
                response.set_body(Bytes::copy_from_slice(body));
                response.into()
            } else {
                let mut response = response.streaming(5);
                assert_eq!(response.write(body).await.unwrap(), body.len());
                response.finish().await.unwrap();
                response.into()
            };
            let producer = match &response {
                common::Response::Streaming(response) => Some(response.clone()),
                _ => None,
            };
            let mut encoded = Vec::new();
            assert_eq!(
                (super::respond(
                    response,
                    crate::test_support::write_stream(4, &mut encoded),
                    crate::test_support::connection().await.qpack().clone(),
                    &method,
                )
                .await)
                    .map_err(ErrorCode::from),
                Err(ErrorCode::H3_MESSAGE_ERROR),
                "method={method}, buffered={buffered}"
            );
            if let Some(mut producer) = producer {
                assert_eq!(
                    (producer.write(b"x").await).map_err(ErrorCode::from),
                    Err(ErrorCode::H3_MESSAGE_ERROR)
                );
                assert_eq!(
                    (producer.finish().await).map_err(ErrorCode::from),
                    Err(ErrorCode::H3_MESSAGE_ERROR)
                );
            }

            // Streaming validation may follow HEADERS, but must precede DATA.
            let mut input = encoded.as_slice();
            if !input.is_empty() {
                assert!(matches!(
                    be_frame(&mut input).await.unwrap(),
                    H3Frame::Headers(_)
                ));
            }
            assert!(input.is_empty(), "invalid response must not contain DATA");
        }
    }
}

#[tokio::test]
async fn writes_buffered_and_streaming_response_frames() {
    let mut fixed_response = Response::default();
    fixed_response
        .set_status(StatusCode::CREATED)
        .set_body(Bytes::from_static(b"hello"));
    fixed_response.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
    let mut encoded = Vec::new();
    write_bytes_response(fixed_response, &mut encoded)
        .await
        .unwrap();
    let mut input = encoded.as_slice();
    let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
        panic!("expected HEADERS")
    };
    assert_eq!(
        headers::be_response(
            qpack::be_field_section(&frame.payload.field_section)
                .unwrap()
                .1
        )
        .unwrap()
        .status()
        .unwrap(),
        StatusCode::CREATED
    );
    let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
        panic!("expected DATA")
    };
    assert_eq!(frame.length.into_u64(), 5);
    assert_eq!(input, b"hello");

    let message = Message::<headers::ResponseHead, Bytes>::default()
        .with_body(crate::Body::new(ArcWndBuf::new(2)));
    let mut response = Response::from(message);
    response.set_status(StatusCode::OK);
    let mut producer = Response::from(response.message.clone());
    let mut encoded = Vec::new();
    let (sent, produced) = tokio::join!(write_streaming_response(response, &mut encoded), async {
        let mut body = &b"stream"[..];
        while !body.is_empty() {
            let count = producer.write(body).await?;
            body = &body[count..];
        }
        producer.finish().await
    });
    sent.unwrap();
    produced.unwrap();
    let mut input = encoded.as_slice();
    let H3Frame::Headers(_) = be_frame(&mut input).await.unwrap() else {
        panic!("expected HEADERS")
    };
    let mut body = Vec::new();
    while !input.is_empty() {
        let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected DATA")
        };
        let count = frame.length.into_u64() as usize;
        body.extend_from_slice(&input[..count]);
        input = &input[count..];
    }
    assert_eq!(body, b"stream");

    let mut fixed_response = Response::default();
    fixed_response
        .set_status(StatusCode::CREATED)
        .set_body(Bytes::from_static(b"hello"));
    fixed_response.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
    let mut output = Vec::new();
    assert_eq!(
        ErrorCode::from(
            write_bytes_response(fixed_response, &mut output)
                .await
                .unwrap_err()
        ),
        ErrorCode::H3_MESSAGE_ERROR
    );
    assert!(output.is_empty());

    let message = Message::<headers::ResponseHead, Bytes>::default()
        .with_body(crate::Body::new(ArcWndBuf::new(1)));
    let mut response = Response::from(message);
    response.set_status(StatusCode::OK);
    let mut producer = Response::from(response.message.clone());
    let (writer, reader) = duplex(1);
    drop(reader);
    let (sent, produced) = tokio::join!(write_streaming_response(response, writer), async {
        producer.write(b"a").await?;
        producer.write(b"b").await
    });
    assert_eq!(
        ErrorCode::from(sent.unwrap_err()),
        ErrorCode::H3_INTERNAL_ERROR
    );
    assert_eq!(
        ErrorCode::from(produced.unwrap_err()),
        ErrorCode::H3_INTERNAL_ERROR
    );
}

#[tokio::test]
async fn response_writers_freeze_metadata_and_buffered_body_on_creation() {
    for streaming in [false, true] {
        let connection = crate::test_support::connection().await;
        let mut response = Response::<Bytes>::default();
        response.set_status(StatusCode::OK);
        response.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        let mut wire = Vec::new();
        if streaming {
            let response = response.streaming(16);
            let mut retained = Response::from(response.message.clone());
            let sending = super::write_streaming_response(
                response,
                crate::test_support::write_stream(0, &mut wire),
                connection.qpack().clone(),
                &Method::GET,
            );
            retained.set_status(StatusCode::NO_CONTENT);
            retained.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
            retained.write(b"old").await.unwrap();
            retained.finish().await.unwrap();
            sending.await.unwrap();
        } else {
            response.set_body(Bytes::from_static(b"old"));
            let mut retained = Response::from(response.message.clone());
            let sending = super::write_bytes_response(
                response,
                crate::test_support::write_stream(0, &mut wire),
                connection.qpack().clone(),
                &Method::GET,
            );
            retained.set_status(StatusCode::NO_CONTENT);
            retained.set_header(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
            retained.set_body(Bytes::from_static(b"new body"));
            sending.await.unwrap();
        }
        let mut input = wire.as_slice();
        let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected HEADERS");
        };
        let head = headers::be_response(
            connection
                .qpack()
                .decode(0, frame.payload.field_section)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(head.status().unwrap(), StatusCode::OK);
        assert_eq!(head.headers[header::CONTENT_LENGTH], "3");
        assert!(matches!(
            be_frame(&mut input).await.unwrap(),
            H3Frame::Data(_)
        ));
        assert_eq!(input, b"old");
    }
}

#[tokio::test]
async fn response_validation_cannot_be_changed_after_operation_creation() {
    for streaming in [false, true] {
        let connection = crate::test_support::connection().await;
        let response = Response::<Bytes>::default(); // Missing final status.
        let ws = crate::test_support::write_stream(0, tokio::io::sink());
        let error = if streaming {
            let response = response.streaming(1);
            let mut retained = Response::from(response.message.clone());
            let mut producer = response.body();
            let sending = super::write_streaming_response(
                response,
                ws,
                connection.qpack().clone(),
                &Method::GET,
            );
            retained.set_status(StatusCode::OK);
            // The send future has not been polled.
            assert_eq!(
                producer.write(b"x").await.unwrap_err().code,
                ErrorCode::H3_MESSAGE_ERROR
            );
            sending.await.unwrap_err()
        } else {
            let mut retained = Response::from(response.message.clone());
            let sending =
                super::write_bytes_response(response, ws, connection.qpack().clone(), &Method::GET);
            retained.set_status(StatusCode::OK);
            sending.await.unwrap_err()
        };
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
    }
}
