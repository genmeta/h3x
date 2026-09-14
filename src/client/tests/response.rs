use super::*;

async fn read_response<R: AsyncRead + Unpin + Send + 'static>(recv: R) -> Result<Response> {
    super::read_response(H3ReadStream::new(0, recv), Arc::new(Qpack::default()), None).await
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
    for length in [Some("5"), None] {
        let mut encoded = Vec::new();
        headers(&mut encoded, "103", None);
        headers(&mut encoded, "200", length);
        for chunk in [&b"he"[..], &b"llo"[..]] {
            encoded.put_frame(&Frame::<Data>::new(Data(chunk.len())).unwrap());
            encoded.extend_from_slice(chunk);
        }
        let (mut writer, reader) = duplex(2);
        let ((), ()) = tokio::join!(
            async {
                writer.write_all(&encoded).await.unwrap();
                writer.shutdown().await.unwrap();
            },
            async {
                match read_response(reader).await.unwrap() {
                    crate::common::Response::Bytes(response) => {
                        assert!(length.is_some());
                        assert_eq!(response.status(), StatusCode::OK);
                        assert_eq!(response.body(), "hello");
                    }
                    crate::common::Response::Streaming(mut response) => {
                        assert!(length.is_none());
                        assert_eq!(response.status(), StatusCode::OK);
                        let mut buf = [0; 8];
                        assert_eq!(response.read_all(&mut buf).await.unwrap(), 5);
                        assert_eq!(&buf[..5], b"hello");
                    }
                }
            }
        );
    }
    for length in ["0", "2", "6", "invalid"] {
        let mut encoded = Vec::new();
        headers(&mut encoded, "200", Some(length));
        encoded.put_frame(&Frame::<Data>::new(Data(5)).unwrap());
        encoded.extend_from_slice(b"hello");
        let result = read_response(Cursor::new(encoded)).await;
        assert!(matches!(result, Err(Error::H3_MESSAGE_ERROR)));
    }
    for (status, length) in [("200", Some("0")), ("204", None), ("304", Some("100"))] {
        let mut encoded = Vec::new();
        headers(&mut encoded, status, length);
        let crate::common::Response::Bytes(response) =
            read_response(Cursor::new(encoded)).await.unwrap()
        else {
            panic!("expected empty fixed body")
        };
        assert!(response.body().is_empty());
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
        Error::H3_FRAME_ERROR
    );

    let mut encoded = Vec::new();
    headers(&mut encoded, "200", Some("0"));
    encoded.push(0x40); // Truncated frame type is not a clean EOF.
    assert!(matches!(
        read_response(Cursor::new(encoded)).await,
        Err(Error::H3_FRAME_ERROR)
    ));
}
