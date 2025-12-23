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
use gm_quic::prelude::{BindUri, handy::ToCertificate};

async fn client_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("tests/keychain/localhost/ca.cert").to_certificate(),
    );
    let h3_client = h3x::client::builder()
        .with_root_certificates(roots)
        .without_identity()?
        .build();

    // Initiate GET request
    // The request stream is automatically closed when dropped
    let (_, mut response) = h3_client
        .new_request()
        .get("localhost:4433/hello_world".parse()?)
        .await?;

    // Check response status code
    assert_eq!(response.status(), http::StatusCode::OK);

    let text = response.read_to_string().await?;
    println!("Response: {:?}", text);

    Ok(())
}

async fn server_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = h3x::server::builder()
        .without_client_cert_verifier()?
        .build();

    let hello_world = async |request: &mut h3x::server::Request,
                             response: &mut h3x::server::Response| {
        response
            .set_status(http::StatusCode::OK)
            .set_body(&b"Hello, World!"[..]);
    };

    app.add_server(
        "localhost",
        include_bytes!("tests/keychain/localhost/server.cert"),
        include_bytes!("tests/keychain/localhost/server.key"),
        None,
        [BindUri::from("inet://[::1]:4433")],
        h3x::server::Router::new().get("/hello_world", hello_world),
    )?
    .run()
    .await;

    Ok(())
}
```