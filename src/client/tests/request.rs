use super::*;

async fn write_bytes_request<W: AsyncWrite + Unpin + Send + 'static>(
    request: &Request<Bytes>,
    send: W,
) -> Result<()> {
    let connection = crate::test_support::connection().await;
    super::send_bytes_request(
        request,
        crate::test_support::write_stream(0, send),
        connection.qpack(),
    )?
    .await
}

async fn write_streaming_request<W: AsyncWrite + Unpin + Send + 'static>(
    request: &Request<ArcWndBuf>,
    send: W,
) -> Result<()> {
    let connection = crate::test_support::connection().await;
    super::send_streaming_request(
        request,
        crate::test_support::write_stream(0, send),
        connection.qpack(),
    )?
    .await
}

fn be_request(input: &[u8]) -> Result<(&[u8], headers::RequestHead)> {
    let (input, fields) = qpack::be_field_section(input)?;
    Ok((input, headers::be_request(fields)?))
}

#[tokio::test]
async fn request_frames_and_errors() {
    for (method, url, body) in [
        (
            Method::POST,
            "https://example.com/a?q=1",
            Bytes::from_static(b"hello"),
        ),
        (Method::GET, "https://example.com/", Bytes::new()),
    ] {
        let req = Request::new(url, method.clone())
            .unwrap()
            .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))
            .with_body(crate::Body::new(body.clone()));
        // A tiny buffer forces partial writes and backpressure.
        let (writer, mut reader) = duplex(3);
        let (sent, received) = tokio::join!(write_bytes_request(&req, writer), async {
            let mut received = Vec::new();
            reader.read_to_end(&mut received).await.unwrap();
            received
        });
        sent.unwrap();
        let mut input = received.as_slice();
        let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected HEADERS")
        };
        let (_, parts) = be_request(&frame.payload.field_section).unwrap();
        assert_eq!(parts.method, method);
        assert_eq!(parts.uri.to_string(), url);
        assert_eq!(parts.headers[header::CONTENT_TYPE], "text/plain");
        if !body.is_empty() {
            let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
                panic!("expected DATA")
            };
            assert_eq!(frame.length.into_u64(), body.len() as u64);
            assert_eq!(input, body.as_ref());
            input = &input[body.len()..];
        }
        assert!(input.is_empty());
    }
    for url in ["example.com:443", "ws://example.com/chat"] {
        let request = Request::<Bytes>::connect(url).unwrap();
        assert!(
            write_bytes_request(&request, tokio::io::sink())
                .await
                .is_err()
        );
    }
    let req = Request::<Bytes>::get("https://example.com/")
        .unwrap()
        .header(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
    let (writer, mut reader) = duplex(3);
    assert_eq!(
        ErrorCode::from(write_bytes_request(&req, writer).await.unwrap_err()),
        ErrorCode::H3_MESSAGE_ERROR
    );
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await.unwrap();
    assert!(output.is_empty());
    let req = Request::<Bytes>::get("https://example.com/").unwrap();
    let (writer, reader) = duplex(3);
    drop(reader);
    assert_eq!(
        ErrorCode::from(write_bytes_request(&req, writer).await.unwrap_err()),
        ErrorCode::H3_INTERNAL_ERROR
    );
}

#[tokio::test]
async fn streaming_request_frames_and_errors() {
    for (body, length, valid) in [
        (&b"hello"[..], None, true),
        (&b"hello"[..], Some("5"), true),
        (&b""[..], Some("0"), true),
        (&b"hello"[..], Some("2"), false),
        (&b"hello"[..], Some("6"), false),
        (&b"hello"[..], Some("invalid"), false),
    ] {
        let mut message =
            Message::<headers::RequestHead, Bytes>::post("https://example.com/upload").unwrap();
        if let Some(length) = length {
            message.set_header(header::CONTENT_LENGTH, length.parse().unwrap());
        }
        let req = Request::from(message.with_body(crate::Body::new(ArcWndBuf::new(2))));
        let mut producer = Request::from(req.message.clone());
        let (writer, mut reader) = duplex(3);
        let (sent, produced, received) = tokio::join!(
            write_streaming_request(&req, writer),
            async {
                let mut remaining = body;
                while !remaining.is_empty() {
                    let count = producer.write(remaining).await?;
                    remaining = &remaining[count..];
                }
                producer.finish().await
            },
            async {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).await.unwrap();
                bytes
            }
        );
        if !valid {
            assert_eq!(
                ErrorCode::from(sent.unwrap_err()),
                ErrorCode::H3_MESSAGE_ERROR
            );
            assert_eq!(
                ErrorCode::from(producer.write(b"x").await.unwrap_err()),
                ErrorCode::H3_MESSAGE_ERROR
            );
            continue;
        }
        sent.unwrap();
        produced.unwrap();
        let mut input = received.as_slice();
        let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected HEADERS")
        };
        let (_, parts) = be_request(&frame.payload.field_section).unwrap();
        assert_eq!(parts.uri, "https://example.com/upload");
        let mut decoded = Vec::new();
        while !input.is_empty() {
            let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
                panic!("expected DATA")
            };
            let count = frame.length.into_u64() as usize;
            assert!((1..=2).contains(&count));
            decoded.extend_from_slice(&input[..count]);
            input = &input[count..];
        }
        assert_eq!(decoded, body);
    }
    let req = Request::from(
        Message::<headers::RequestHead, Bytes>::post("https://example.com/")
            .unwrap()
            .with_body(crate::Body::new(ArcWndBuf::new(1))),
    );
    let mut producer = Request::from(req.message.clone());
    let (writer, reader) = duplex(1);
    drop(reader);
    let (sent, produced) = tokio::join!(write_streaming_request(&req, writer), async {
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
