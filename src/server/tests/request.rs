use super::*;

async fn read_request<R: AsyncRead + Unpin + Send + 'static>(recv: R) -> Result<Request> {
    super::accept(
        crate::test_support::read_stream(0, recv),
        crate::test_support::connection().await.qpack().clone(),
    )
    .await
}

#[tokio::test]
async fn preserves_request_headers_through_message_roundtrip() {
    for buffered in [true, false] {
        let mut fields: Vec<_> = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
            ("accept", "text/plain"),
            ("accept", "text/html"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
        ]
        .into_iter()
        .map(|(name, value)| qpack::Field {
            never_index: name == "cookie",
            name: Bytes::from_static(name.as_bytes()),
            value: Bytes::from_static(value.as_bytes()),
        })
        .collect();
        if buffered {
            fields.push(qpack::Field {
                never_index: false,
                name: Bytes::from_static(b"content-length"),
                value: Bytes::from_static(b"0"),
            });
        }
        let mut encoded = Vec::new();
        encoded.put_frame(
            &Frame::new(Headers {
                field_section: crate::test_support::connection()
                    .await
                    .qpack()
                    .encode(0, fields)
                    .unwrap(),
            })
            .unwrap(),
        );

        let Request::Streaming(mut request) = read_request(Cursor::new(encoded)).await.unwrap()
        else {
            panic!("incoming requests are always streaming")
        };
        assert_eq!(request.read(&mut [0]).await.unwrap(), 0);
        let fields = {
            let head = request.message.head.lock().unwrap();
            let mut fields = Vec::new();
            fields.put_request(&head).unwrap();
            fields
        };
        let frame = Frame::new(Headers {
            field_section: crate::test_support::connection()
                .await
                .qpack()
                .encode(4, fields)
                .unwrap(),
        })
        .unwrap();
        let fields = crate::test_support::connection()
            .await
            .qpack()
            .decode(4, frame.payload.field_section)
            .await
            .unwrap();
        let head = headers::be_request(fields).unwrap();
        assert_eq!(head.method, Method::GET);
        assert_eq!(head.uri, "https://example.com/");
        assert_eq!(
            head.headers
                .get_all(header::ACCEPT)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["text/plain", "text/html"],
            "buffered={buffered}"
        );
        assert_eq!(head.headers.get_all(header::COOKIE).iter().count(), 1);
        assert_eq!(head.headers[header::COOKIE], "a=1; b=2");
        assert!(head.headers[header::COOKIE].is_sensitive());
    }
}

#[tokio::test]
async fn reads_buffered_and_streaming_request_frames() {
    let crate::common::Request::Streaming(mut request) =
        read_request(Cursor::new(request_frames(b"hello", Some("5"))))
            .await
            .unwrap()
    else {
        panic!("incoming requests are always streaming")
    };
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.authority(), "example.com");
    assert_eq!(request.scheme(), "https");
    assert_eq!(request.path(), "/echo?q=1");
    let mut body = [0; 5];
    assert_eq!(request.read_all(&mut body).await.unwrap(), body.len());
    assert_eq!(&body, b"hello");

    let crate::common::Request::Streaming(mut request) =
        read_request(Cursor::new(request_frames(b"streaming", None)))
            .await
            .unwrap()
    else {
        panic!("expected streaming request")
    };
    let mut body = [0; 9];
    assert_eq!(request.read_all(&mut body).await.unwrap(), body.len());
    assert_eq!(&body, b"streaming");

    let crate::common::Request::Streaming(mut request) =
        read_request(Cursor::new(request_frames(b"short", Some("6"))))
            .await
            .unwrap()
    else {
        panic!("incoming requests are always streaming")
    };
    assert_eq!(
        (request.read_all(&mut [0; 6]).await).map_err(ErrorCode::from),
        Err(ErrorCode::H3_MESSAGE_ERROR)
    );
    let mut encoded = request_frames(b"short", None);
    encoded.pop();
    let crate::common::Request::Streaming(mut request) =
        read_request(Cursor::new(encoded)).await.unwrap()
    else {
        panic!("expected streaming request")
    };
    assert_eq!(
        ErrorCode::from(request.read_all(&mut [0; 5]).await.unwrap_err()),
        ErrorCode::H3_FRAME_ERROR
    );
}

#[tokio::test]
async fn known_length_request_returns_before_body_and_fin() {
    use std::time::Duration;

    let (mut writer, reader) = duplex(1024);
    writer
        .write_all(&request_frames(b"", Some("5")))
        .await
        .unwrap();
    let Request::Streaming(mut request) =
        tokio::time::timeout(Duration::from_secs(5), read_request(reader))
            .await
            .expect("request headers must be delivered before the fixed-length body")
            .unwrap()
    else {
        panic!("incoming requests are always streaming")
    };

    let mut body = Vec::new();
    body.put_frame(&Frame::new(Data(5)).unwrap());
    body.extend_from_slice(b"hello");
    writer.write_all(&body).await.unwrap();
    writer.shutdown().await.unwrap();

    let mut received = [0; 5];
    assert_eq!(request.read_all(&mut received).await.unwrap(), 5);
    assert_eq!(&received, b"hello");
}

#[tokio::test]
async fn requests_skip_unknown_frames_before_headers_between_data_and_before_fin() {
    let unknown = &[0x21, 3, 2, 0, 0x40, 0x22, 0, 0x40, 0x40, 0][..];
    for (length, chunks) in [
        (Some("5"), &[&b"he"[..], &b"llo"[..]][..]),
        (None, &[&b"he"[..], &b"llo"[..]][..]),
        (Some("0"), &[][..]),
    ] {
        let mut encoded = unknown.to_vec();
        encoded.extend_from_slice(&request_frames(b"", length));
        encoded.extend_from_slice(unknown);
        for chunk in chunks {
            encoded.put_frame(&Frame::new(Data(chunk.len())).unwrap());
            encoded.extend_from_slice(chunk);
            encoded.extend_from_slice(unknown);
        }
        let (mut writer, reader) = duplex(1);
        let ((), ()) = tokio::join!(
            async {
                writer.write_all(&encoded).await.unwrap();
                writer.shutdown().await.unwrap();
            },
            async {
                let expected = chunks.concat();
                let Request::Streaming(mut request) = read_request(reader).await.unwrap() else {
                    panic!("incoming requests are always streaming")
                };
                let mut body = [0; 8];
                assert_eq!(request.read_all(&mut body).await.unwrap(), expected.len());
                assert_eq!(&body[..expected.len()], expected);
                assert_eq!(request.read(&mut body).await.unwrap(), 0);
            }
        );
    }
}

#[tokio::test]
async fn unknown_frames_do_not_hide_invalid_request_frames() {
    for (invalid, expected) in [
        (&[2, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[6, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[8, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[9, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[3, 1, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[4, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[5, 3, 0, 0, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[7, 1, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[13, 1, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[0x40][..], ErrorCode::H3_FRAME_ERROR),
        (&[0x21][..], ErrorCode::H3_FRAME_ERROR),
        (&[0x21, 0x40][..], ErrorCode::H3_FRAME_ERROR),
        (&[0x21, 2, 0][..], ErrorCode::H3_FRAME_ERROR),
    ] {
        for before_headers in [true, false] {
            let mut encoded = if before_headers {
                Vec::new()
            } else {
                request_frames(b"", Some("0"))
            };
            encoded.extend_from_slice(&[0x21, 0]);
            encoded.extend_from_slice(invalid);
            if before_headers {
                assert_eq!(
                    ErrorCode::from(read_request(Cursor::new(encoded)).await.err().unwrap()),
                    expected
                );
            } else {
                let Request::Streaming(mut request) =
                    read_request(Cursor::new(encoded)).await.unwrap()
                else {
                    panic!("incoming requests are always streaming")
                };
                assert_eq!(
                    (request.read(&mut [0]).await).map_err(ErrorCode::from),
                    Err(expected)
                );
            }
        }
    }
    for (suffix, expected) in [
        (&[][..], ErrorCode::H3_FRAME_ERROR),
        (&[0x21, 0][..], ErrorCode::H3_FRAME_ERROR),
        (&[0, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
    ] {
        let encoded = [&[0x21, 0][..], suffix].concat();
        assert_eq!(
            ErrorCode::from(read_request(Cursor::new(encoded)).await.err().unwrap()),
            expected
        );
    }
    let mut encoded = request_frames(b"", Some("1"));
    encoded.extend_from_slice(&[0x21, 1, b'x']);
    let Request::Streaming(mut request) = read_request(Cursor::new(encoded)).await.unwrap() else {
        panic!("incoming requests are always streaming")
    };
    assert_eq!(
        (request.read(&mut [0]).await).map_err(ErrorCode::from),
        Err(ErrorCode::H3_MESSAGE_ERROR)
    );
}

#[tokio::test]
async fn malformed_request_stops_transport_with_message_error() {
    use crate::test_support::TestStream;

    for stage in ["headers", "body", "trailers"] {
        let connection = crate::test_support::connection().await;
        let mut wire = match stage {
            "headers" => request_frames(b"", Some("invalid")),
            "body" => request_frames(b"xx", Some("1")),
            _ => request_frames(b"", None),
        };
        if stage == "trailers" {
            let mut fields = Vec::new();
            fields
                .put_field_section(vec![qpack::Field {
                    never_index: false,
                    name: Bytes::from_static(b":method"),
                    value: Bytes::from_static(b"GET"),
                }])
                .unwrap();
            wire.put_frame(
                &Frame::new(Headers {
                    field_section: fields.into(),
                })
                .unwrap(),
            );
        }
        let (mut peer, recv) = duplex(4096);
        peer.write_all(&wire).await.unwrap();
        // Keep the peer open: parsing must terminate QUIC without waiting for FIN/Drop.
        let recv = TestStream::new(recv);
        let stopped = recv.stopped.clone();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            match crate::server::read_request(
                H3ReadStream::new(0, recv),
                connection.qpack().clone(),
            )
            .await
            {
                Err(error) => error,
                Ok(request) => request.into_body().collect().await.unwrap_err(),
            }
        })
        .await
        .unwrap();
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR, "{stage}");
        assert_eq!(
            *stopped.lock().unwrap(),
            [ErrorCode::H3_MESSAGE_ERROR.as_u64()],
            "{stage}"
        );
        assert!(connection.qpack().error().is_none());
    }
}
