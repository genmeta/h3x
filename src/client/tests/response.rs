use super::*;
use crate::protocol::frame::Data;

async fn read_response<R: AsyncRead + Unpin + Send + 'static>(recv: R) -> Result<Response> {
    let connection = crate::test_support::connection();
    super::read_response(H3ReadStream::new(0, recv), connection.qpack().clone(), None).await
}

#[tokio::test]
async fn preserves_set_cookie_headers_through_message_roundtrip() {
    let cookies = [
        "a=1; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT",
        "b=2; Path=/; HttpOnly",
    ];
    for buffered in [true, false] {
        let mut fields = vec![qpack::Field {
            never_index: false,
            name: Bytes::from_static(b":status"),
            value: Bytes::from_static(b"200"),
        }];
        for cookie in cookies {
            fields.push(qpack::Field {
                never_index: true,
                name: Bytes::from_static(b"set-cookie"),
                value: Bytes::from_static(cookie.as_bytes()),
            });
        }
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
                    .qpack()
                    .encode(0, fields)
                    .unwrap(),
            })
            .unwrap(),
        );

        let Response::Streaming(response) = read_response(Cursor::new(encoded)).await.unwrap()
        else {
            panic!("incoming responses are always streaming")
        };
        let outgoing = crate::server::Response::from(response.message.test_direction());
        let mut reencoded = Vec::new();
        let send = H3WriteStream::new(4, &mut reencoded);
        let qpack = crate::test_support::connection();
        crate::server::write_streaming_response(outgoing, send, qpack, &Method::GET)
            .await
            .unwrap();
        // Keep the receive handle alive until the shared body reaches EOF.
        drop(response);

        let H3Frame::Headers(frame) = be_frame(&mut reencoded.as_slice()).await.unwrap() else {
            panic!("expected HEADERS")
        };
        let fields = crate::test_support::connection()
            .qpack()
            .decode(4, frame.payload.field_section)
            .await
            .unwrap();
        let head = headers::be_response(fields).unwrap();
        assert_eq!(head.status().unwrap(), StatusCode::OK);
        assert_eq!(
            head.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            cookies,
            "buffered={buffered}"
        );
        assert!(
            head.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .all(HeaderValue::is_sensitive)
        );
    }
}

#[tokio::test]
async fn response_content_length_and_streaming() {
    fn headers(output: &mut Vec<u8>, status: &'static str, length: Option<&'static str>) {
        let mut fields = vec![qpack::Field {
            never_index: false,
            name: Bytes::from_static(b":status"),
            value: Bytes::from_static(status.as_bytes()),
        }];
        if let Some(length) = length {
            fields.push(qpack::Field {
                never_index: false,
                name: Bytes::from_static(b"content-length"),
                value: Bytes::from_static(length.as_bytes()),
            });
        }
        let mut field_section = Vec::new();
        field_section.put_field_section(fields).unwrap();
        let field_section = Bytes::from(field_section);
        output.put_frame(&Frame::<Headers>::new(Headers { field_section }).unwrap());
    }
    let unknown = &[0x21, 3, 2, 0, 0x40, 0x22, 0, 0x40, 0x40, 0][..];
    for (length, extension) in [
        (Some("5"), &[][..]),
        (None, &[][..]),
        (Some("5"), unknown),
        (None, unknown),
    ] {
        let mut encoded = extension.to_vec();
        headers(&mut encoded, "103", None);
        encoded.extend_from_slice(extension);
        headers(&mut encoded, "200", length);
        encoded.extend_from_slice(extension);
        for chunk in [&b"he"[..], &b"llo"[..]] {
            encoded.put_frame(&Frame::<Data>::new(Data(chunk.len())).unwrap());
            encoded.extend_from_slice(chunk);
            encoded.extend_from_slice(extension);
        }
        let (mut writer, reader) = duplex(2);
        let ((), ()) = tokio::join!(
            async {
                writer.write_all(&encoded).await.unwrap();
                writer.shutdown().await.unwrap();
            },
            async {
                let crate::common::Response::Streaming(mut response) =
                    read_response(reader).await.unwrap()
                else {
                    panic!("incoming responses are always streaming")
                };
                assert_eq!(response.status(), StatusCode::OK);
                let mut buf = [0; 8];
                assert_eq!(response.read_all(&mut buf).await.unwrap(), 5);
                assert_eq!(&buf[..5], b"hello");
            }
        );
    }
    for length in ["0", "2", "6", "invalid"] {
        let mut encoded = Vec::new();
        headers(&mut encoded, "200", Some(length));
        encoded.put_frame(&Frame::<Data>::new(Data(5)).unwrap());
        encoded.extend_from_slice(b"hello");
        if length == "invalid" {
            assert!(matches!(
                read_response(Cursor::new(encoded)).await,
                Err(ErrorCode::H3_MESSAGE_ERROR)
            ));
            continue;
        }
        let crate::common::Response::Streaming(mut response) =
            read_response(Cursor::new(encoded)).await.unwrap()
        else {
            panic!("incoming responses are always streaming")
        };
        assert_eq!(
            response.read(&mut [0; 8]).await,
            Err(ErrorCode::H3_MESSAGE_ERROR)
        );
    }
    for (status, length) in [("200", Some("0")), ("204", None), ("304", Some("100"))] {
        let mut encoded = unknown.to_vec();
        headers(&mut encoded, status, length);
        encoded.extend_from_slice(unknown);
        let crate::common::Response::Streaming(mut response) =
            read_response(Cursor::new(encoded)).await.unwrap()
        else {
            panic!("incoming responses are always streaming")
        };
        assert_eq!(response.read(&mut [0]).await.unwrap(), 0);
    }
    // Unknown-length responses return after HEADERS, before body bytes arrive.
    let (mut writer, reader) = duplex(1024);
    let mut encoded = Vec::new();
    headers(&mut encoded, "200", None);
    writer.write_all(&encoded).await.unwrap();
    let crate::common::Response::Streaming(mut response) = read_response(reader).await.unwrap()
    else {
        panic!("expected streaming")
    };
    encoded.clear();
    encoded.put_frame(&Frame::<Data>::new(Data(5)).unwrap());
    encoded.extend_from_slice(b"hi");
    writer.write_all(&encoded).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(
        response.read(&mut [0; 5]).await.unwrap_err(),
        ErrorCode::H3_FRAME_ERROR
    );

    let mut encoded = Vec::new();
    headers(&mut encoded, "200", Some("0"));
    encoded.push(0x40); // Truncated frame type is not a clean EOF.
    let crate::common::Response::Streaming(mut response) =
        read_response(Cursor::new(encoded)).await.unwrap()
    else {
        panic!("incoming responses are always streaming")
    };
    assert_eq!(
        response.read(&mut [0]).await,
        Err(ErrorCode::H3_FRAME_ERROR)
    );

    for (suffix, expected) in [
        (&[2, 0][..], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[0x21, 2, 0][..], ErrorCode::H3_FRAME_ERROR),
    ] {
        let mut encoded = Vec::new();
        headers(&mut encoded, "200", None);
        encoded.extend_from_slice(unknown);
        encoded.extend_from_slice(suffix);
        let crate::common::Response::Streaming(mut response) =
            read_response(Cursor::new(encoded)).await.unwrap()
        else {
            panic!("expected streaming response")
        };
        assert_eq!(response.read(&mut [0]).await.unwrap_err(), expected);
    }
}
