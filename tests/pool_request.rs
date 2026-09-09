use bytes::Bytes;
use h3x::{Chunk, Error, Fixed, client::Request};

#[tokio::test]
async fn public_request_entry_points_keep_their_execution_contracts() {
    let request = Request::new(http::Method::POST, "https://peer.test/", Fixed::default()).unwrap();
    assert!(matches!(request.await, Err(Error::NotInitialized)));
    let streaming = Request::new(http::Method::POST, "https://peer.test/", Chunk).unwrap();
    assert!(matches!(streaming.await, Err(Error::NotInitialized)));
    let invalid = Request::new(
        http::Method::POST,
        "https://peer.test/",
        Fixed::from(Bytes::from_static(b"data")),
    )
    .unwrap()
    .header("content-length", "3")
    .unwrap();
    assert!(matches!(invalid.await, Err(Error::InvalidMessage { .. })));
}
