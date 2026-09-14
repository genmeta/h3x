use super::*;

async fn read_request<R: AsyncRead + Unpin + Send + 'static>(recv: R) -> Result<Request> {
    super::accept(H3ReadStream::new(0, recv), Arc::new(Qpack::default())).await
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
                field_section: Qpack::default().encode(0, fields).unwrap(),
            })
            .unwrap(),
        );

        let fields = match read_request(Cursor::new(encoded)).await.unwrap() {
            Request::Bytes(request) => {
                assert!(buffered);
                request.message.0.lock().unwrap().fields()
            }
            Request::Streaming(mut request) => {
                assert!(!buffered);
                assert_eq!(request.read(&mut [0]).await.unwrap(), 0);
                request.message.0.lock().unwrap().fields()
            }
        };
        let frame = Frame::new(Headers {
            field_section: Qpack::default().encode(4, fields).unwrap(),
        })
        .unwrap();
        let fields = Qpack::default()
            .decode(4, frame.payload.field_section)
            .await
            .unwrap();
        let parts = headers::request_parts(fields).unwrap();
        assert_eq!(parts.method, Method::GET);
        assert_eq!(parts.uri, "https://example.com/");
        assert_eq!(
            parts
                .headers
                .get_all(header::ACCEPT)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["text/plain", "text/html"],
            "buffered={buffered}"
        );
        assert_eq!(parts.headers.get_all(header::COOKIE).iter().count(), 1);
        assert_eq!(parts.headers[header::COOKIE], "a=1; b=2");
        assert!(parts.headers[header::COOKIE].is_sensitive());
    }
}

#[tokio::test]
async fn reads_buffered_and_streaming_request_frames() {
    let crate::common::Request::Bytes(request) =
        read_request(Cursor::new(request_frames(b"hello", Some("5"))))
            .await
            .unwrap()
    else {
        panic!("expected bytes request")
    };
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.authority(), "example.com");
    assert_eq!(request.scheme(), "https");
    assert_eq!(request.path(), "/echo?q=1");
    assert_eq!(request.body(), "hello");

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

    assert_eq!(
        read_request(Cursor::new(request_frames(b"short", Some("6"))))
            .await
            .err()
            .unwrap(),
        Error::H3_MESSAGE_ERROR
    );
    let mut encoded = request_frames(b"short", None);
    encoded.pop();
    let crate::common::Request::Streaming(mut request) =
        read_request(Cursor::new(encoded)).await.unwrap()
    else {
        panic!("expected streaming request")
    };
    assert_eq!(
        request.read_all(&mut [0; 5]).await.unwrap_err(),
        Error::H3_FRAME_ERROR
    );
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
                match read_request(reader).await.unwrap() {
                    Request::Bytes(request) => {
                        assert!(length.is_some());
                        assert_eq!(request.body(), expected);
                    }
                    Request::Streaming(mut request) => {
                        assert!(length.is_none());
                        let mut body = [0; 8];
                        assert_eq!(request.read_all(&mut body).await.unwrap(), expected.len());
                        assert_eq!(&body[..expected.len()], expected);
                        assert_eq!(request.read(&mut body).await.unwrap(), 0);
                    }
                }
            }
        );
    }
}

#[tokio::test]
async fn unknown_frames_do_not_hide_invalid_request_frames() {
    for (invalid, expected) in [
        (&[2, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[6, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[8, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[9, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[3, 1, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[4, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[5, 3, 0, 0, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[7, 1, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[13, 1, 0][..], Error::H3_FRAME_UNEXPECTED),
        (&[0x40][..], Error::H3_FRAME_ERROR),
        (&[0x21][..], Error::H3_FRAME_ERROR),
        (&[0x21, 0x40][..], Error::H3_FRAME_ERROR),
        (&[0x21, 2, 0][..], Error::H3_FRAME_ERROR),
    ] {
        for before_headers in [true, false] {
            let mut encoded = if before_headers {
                Vec::new()
            } else {
                request_frames(b"", Some("0"))
            };
            encoded.extend_from_slice(&[0x21, 0]);
            encoded.extend_from_slice(invalid);
            assert_eq!(
                read_request(Cursor::new(encoded)).await.err().unwrap(),
                expected
            );
        }
    }
    for (suffix, expected) in [
        (&[][..], Error::H3_FRAME_ERROR),
        (&[0x21, 0][..], Error::H3_FRAME_ERROR),
        (&[0, 0][..], Error::H3_FRAME_UNEXPECTED),
    ] {
        let encoded = [&[0x21, 0][..], suffix].concat();
        assert_eq!(
            read_request(Cursor::new(encoded)).await.err().unwrap(),
            expected
        );
    }
    let mut encoded = request_frames(b"", Some("1"));
    encoded.extend_from_slice(&[0x21, 1, b'x']);
    assert_eq!(
        read_request(Cursor::new(encoded)).await.err().unwrap(),
        Error::H3_MESSAGE_ERROR
    );
}
