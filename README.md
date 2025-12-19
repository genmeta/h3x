[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/h3x)](https://www.apache.org/licenses/LICENSE-2.0)

High-performance asynchronous DHTTP/3 implementation in Rust.

- **Peer-to-Peer**: Extends [HTTP3(RFC9114)](https://datatracker.ietf.org/doc/html/rfc9114) to *DHTTP/3*, allowing both sides of the connection to initiate and handle HTTP3 requests (achieved by disabling server push).
- **Asynchronous I/O**: Built on the Rust asynchronous ecosystem, providing high-performance I/O processing capabilities.
- **Zero-Copy**: Achieves full-link *zero-copy* from the QUIC layer to the application layer.
- **Multipath QUIC**: Integrates the `gm-quic` implementation, featuring efficient transmission, robust authentication capabilities, and high extensibility.
- **Future Extensions**: Plans to support important extensions such as [Extended CONNECT (RFC9220)](https://datatracker.ietf.org/doc/html/rfc9220) and [WebTransport over HTTP/3 (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-14).

### Examples

> ⚠️ Currently, h3x is in the early stages of development, and the API may undergo significant changes.

h3x integrates `gm_quic` by default. Initiate QUIC connections via `QuicClient` and listen QUIC connections via `QuicListeners`.

```rust
use bytes::Buf;

async fn client_example(
    quic_connector: gm_quic::prelude::QuicClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut h3_client = h3x::client::Client::builder()
        .connector(quic_connector)
        .build();

    // Initiate GET request
    // The request stream is automatically closed when dropped
    let (.., mut response) = h3_client
        .new_request()
        .set_uri("https://localhost:4433/hello_world".parse()?)
        .get()
        .await?;

    // Check response status code
    assert_eq!(response.status().await?, http::StatusCode::OK);

    // Read response body
    let mut response_bytes = response.read_all().await?;
    let response_bytes = response_bytes.copy_to_bytes(response_bytes.remaining());
    println!("Response: {:?}", response_bytes);

    Ok(())
}

async fn server_example(
    quic_listener: gm_quic::prelude::QuicListeners,
) -> Result<(), Box<dyn std::error::Error>> {
    let servers = h3x::server::Servers::builder()
        .listener(quic_listener)
        .build();

    // Define handler function
    let hello_world_service =
        async |request: &mut h3x::server::Request, response: &mut h3x::server::Response| {
            response
                .set_status(http::StatusCode::OK)
                .unwrap()
                .set_body(&b"Hello, World!"[..])
                .unwrap();
        };

    // Register router
    let localhost_router = h3x::server::Router::new().get("/hello_world", hello_world_service);
    // Start server
    servers.serve("localhost", localhost_router).run().await;

    Ok(())
}
```