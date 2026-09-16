mod support;

use std::{
    future::Future,
    task::{Context, Waker},
    time::Duration,
};

use bytes::Bytes;
use h3x::{
    Body, ErrorCode, H3ReadStream, H3WriteStream, ReadRequest, ReadResponse, W, WndBuf,
    WriteRequest, WriteResponse, client, server,
};
use http::{Method, StatusCode, header};
use tokio::{
    io::{AsyncReadExt, duplex},
    time::timeout,
};

#[tokio::test]
async fn directional_bodies_echo_with_backpressure() {
    timeout(Duration::from_secs(5), async {
        let connection = support::connection();
        let (cs, sr) = duplex(7);
        let (ss, cr) = duplex(7);
        let mut upload = Body::<WndBuf, W>::with_capacity(3);
        let request = client::Request::post("https://example.com/echo")
            .unwrap()
            .with_body(upload.clone());
        let receiving = client::write_streaming_request(
            request,
            H3WriteStream::new(0, cs),
            H3ReadStream::new(0, cr),
            connection.qpack().clone(),
        )
        .unwrap();
        let payload = vec![b'x'; 128 * 1024];
        let (received, produced, served) = tokio::join!(
            async { receiving.await?.into_body().collect().await },
            async {
                upload.write_all(&payload).await?;
                upload.finish().await
            },
            async {
                let request =
                    server::read_request(H3ReadStream::new(0, sr), connection.clone()).await?;
                let method = request.method();
                let mut input = request.into_body();
                let mut output = Body::<WndBuf, W>::with_capacity(2);
                let mut response = server::Response::default().with_body(output.clone());
                response.set_status(StatusCode::OK);
                let (sent, produced) = tokio::join!(
                    server::write_streaming_response(
                        response,
                        H3WriteStream::new(0, ss),
                        connection.clone(),
                        &method
                    ),
                    async {
                        let mut buf = [0; 11];
                        loop {
                            let n = input.read(&mut buf).await?;
                            if n == 0 {
                                return output.finish().await;
                            }
                            output.write_all(&buf[..n]).await?;
                        }
                    }
                );
                sent?;
                produced
            }
        );
        assert!(
            produced.is_ok() && served.is_ok(),
            "produce={produced:?}, serve={served:?}, receive={received:?}"
        );
        assert_eq!(received.unwrap(), payload);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn response_does_not_wait_for_upload_to_finish() {
    let connection = support::connection();
    let mut encoded = Vec::new();
    let mut response = server::Response::default();
    response
        .set_status(StatusCode::OK)
        .set_header(header::CONTENT_LENGTH, "12".parse().unwrap());
    // HEAD carries a nonzero Content-Length but no DATA.
    server::write_bytes_response(
        response,
        H3WriteStream::new(0, &mut encoded),
        connection.clone(),
        &Method::HEAD,
    )
    .await
    .unwrap();
    let (send, mut peer) = duplex(1);
    let request = client::Request::head("https://example.com/")
        .unwrap()
        .with_body(Body::<Bytes, W>::new(Bytes::new()));
    let receiving = client::write_bytes_request(
        request,
        H3WriteStream::new(0, send),
        H3ReadStream::new(0, std::io::Cursor::new(encoded)),
        connection.qpack().clone(),
    )
    .unwrap();
    let response = timeout(Duration::from_secs(1), receiving)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.into_body().collect().await.unwrap().is_empty());
    // Upload starts in the background and may remain backpressured after delivery.
    let mut bytes = [0];
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut bytes))
            .await
            .unwrap()
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn dropping_response_future_preserves_upload() {
    let connection = support::connection();
    let mut producer = Body::<WndBuf, W>::with_capacity(1);
    let request = client::Request::post("https://example.com/")
        .unwrap()
        .with_body(producer.clone());
    let (send, mut peer) = duplex(1);
    let receiving = client::write_streaming_request(
        request,
        H3WriteStream::new(0, send),
        H3ReadStream::new(0, tokio::io::empty()),
        connection.qpack().clone(),
    )
    .unwrap();
    drop(receiving);
    timeout(Duration::from_secs(2), async {
        let (produced, received) = tokio::join!(
            async {
                producer.write_all(b"hello").await?;
                producer.finish().await
            },
            async {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                bytes
            }
        );
        produced.unwrap();
        assert!(!received.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_reset_wakes_producer_after_upload_is_dropped() {
    let connection = support::connection();
    let mut producer = Body::<WndBuf, W>::with_capacity(1);
    let request = client::Request::post("https://example.com/")
        .unwrap()
        .with_body(producer.clone());
    let receiving = client::write_streaming_request(
        request,
        H3WriteStream::new(0, tokio::io::sink()),
        H3ReadStream::new(0, tokio::io::empty()),
        connection.qpack().clone(),
    )
    .unwrap();
    producer.write_all(b"x").await.unwrap();
    let cancelling = producer.clone();
    let mut blocked = Box::pin(producer.write_all(b"y"));
    assert!(
        blocked
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(receiving);
    assert!(
        blocked
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    cancelling.reset().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), blocked).await.unwrap(),
        Err(ErrorCode::H3_REQUEST_CANCELLED)
    );
}
