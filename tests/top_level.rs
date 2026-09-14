use std::sync::Arc;

use bytes::Bytes;
use h3x::{
    H3ReadStream, H3WriteStream, Qpack, ReadBody, ReadRequest, ReadResponse, ReadStream, WriteBody,
    WriteRequest, WriteResponse, WriteStream, client, server,
};
use http::{Method, StatusCode, header};
use tokio::io::duplex;

#[tokio::test]
async fn request_accept_and_respond() {
    let (client_send, server_recv) = duplex(64);
    let (server_send, client_recv) = duplex(64);
    let request = client::Request::post("https://example.com/echo")
        .unwrap()
        .header(header::CONTENT_LENGTH, "5".parse().unwrap())
        .body(Bytes::from_static(b"hello"));

    let (response, served) = tokio::join!(
        client::request(
            request,
            H3ReadStream::new(0, client_recv),
            H3WriteStream::new(0, client_send),
            Arc::new(Qpack::default())
        ),
        async {
            let request = server::accept(
                H3ReadStream::new(0, server_recv),
                Arc::new(Qpack::default()),
            )
            .await?;
            assert_eq!(request.method(), Method::POST);
            let method = request.method();
            let server::Request::Bytes(request) = request else {
                panic!("expected buffered request")
            };
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.body(), b"hello"[..]);

            let mut response = server::Response::default();
            response.set_status(StatusCode::OK).set_body(request.body());
            server::respond(
                response,
                H3WriteStream::new(0, server_send),
                Arc::new(Qpack::default()),
                &method,
            )
            .await
        }
    );

    served.unwrap();
    let response = response.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let client::Response::Streaming(mut response) = response else {
        panic!("expected unknown-length response stream")
    };
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = [0; 5];
    assert_eq!(response.read_all(&mut body).await.unwrap(), body.len());
    assert_eq!(&body, b"hello");
}

#[tokio::test]
async fn streaming_echo() {
    let (client_send, server_recv) = duplex(64);
    let (server_send, client_recv) = duplex(64);

    let request = client::Request::streaming_post("https://example.com/echo").unwrap();
    let mut upload = request.clone();
    let sentences = ["Hello. ", "Hi. ", "Bye."];
    let expected = sentences.concat().into_bytes();

    let (response, uploaded, served) = tokio::join!(
        client::request(
            request,
            H3ReadStream::new(0, client_recv),
            H3WriteStream::new(0, client_send),
            Arc::new(Qpack::default())
        ),
        async {
            for sentence in sentences {
                assert_eq!(upload.write(sentence).await?, sentence.len());
            }
            upload.finish().await
        },
        async {
            let request = server::accept(
                H3ReadStream::new(0, server_recv),
                Arc::new(Qpack::default()),
            )
            .await?;
            let method = request.method();
            let server::Request::Streaming(mut request) = request else {
                panic!("expected streaming request")
            };

            let mut response = server::Response::default();
            response.set_status(StatusCode::OK);
            let response = response.streaming(2);
            let mut echo = response.clone();

            let (sent, echoed) = tokio::join!(
                server::respond(
                    response,
                    H3WriteStream::new(0, server_send),
                    Arc::new(Qpack::default()),
                    &method,
                ),
                async {
                    let mut buf = [0; 3];
                    loop {
                        let count = request.read(&mut buf).await?;
                        if count == 0 {
                            return echo.finish().await;
                        }
                        let mut remaining = &buf[..count];
                        while !remaining.is_empty() {
                            let count = echo.write(remaining).await?;
                            remaining = &remaining[count..];
                        }
                    }
                }
            );
            sent?;
            echoed
        }
    );

    uploaded.unwrap();
    served.unwrap();
    let response = response.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let client::Response::Streaming(mut response) = response else {
        panic!("expected streaming response")
    };
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = vec![0; expected.len()];
    assert_eq!(response.read_all(&mut body).await.unwrap(), expected.len());
    assert_eq!(body, expected);
}
