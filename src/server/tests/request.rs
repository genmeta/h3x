use super::*;

async fn read_request<R: AsyncRead + Unpin + Send + 'static>(recv: R) -> Result<Request> {
    super::accept(H3ReadStream::new(0, recv), Arc::new(Qpack::default())).await
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
