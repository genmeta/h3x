[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/h3x)](https://www.apache.org/licenses/LICENSE-2.0)

High-performance asynchronous DHTTP/3 implementation in Rust.

- **Peer-to-Peer**: Extends [HTTP3(RFC9114)](https://datatracker.ietf.org/doc/html/rfc9114) to *DHTTP/3*, allowing both sides of the connection to initiate and handle HTTP3 requests (achieved by disabling server push).
- **Asynchronous I/O**: Built on the Rust asynchronous ecosystem, providing high-performance I/O processing capabilities.
- **Zero-Copy**: Achieves full-link *zero-copy* from the QUIC layer to the application layer.
- **Multipath QUIC**: Integrates the `dquic` implementation, featuring efficient transmission, robust authentication capabilities, and high extensibility.
- **Hyper / Tower Compatibility** *(feature `hyper`, enabled by default)*: Provides `TowerService` and `HyperService` adapters to run existing Tower or hyper services (e.g. `axum`) over DHTTP/3. Since h3x cannot construct hyper's internal types, the `h3x::hyper` module provides its own alternatives for upgrade and protocol negotiation.
- **Remoc** *(feature `remoc`, experimental)*: Optional [`remoc`](https://crates.io/crates/remoc) integration for remote trait calls (RTC) over QUIC connections. This is an experimental feature and the API may change.
- **Extended CONNECT**: Supports [Extended CONNECT (RFC9220)](https://datatracker.ietf.org/doc/html/rfc9220) for protocol tunneling over HTTP/3.
- **Future Extensions**: Plans to support extensions such as [WebTransport over HTTP/3 (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-14).

### Examples

> ⚠️ Currently, h3x is in the early stages of development, and the API may undergo significant changes.

h3x includes `dquic` as its built-in QUIC backend (feature `dquic`, enabled by default). The `h3x::dquic` module exposes wrapped types for HTTP/3 transport over `dquic`.

```rust
use h3x::dquic::{
    H3Client, H3Servers,
    prelude::{BindUri, handy::ToCertificate},
};

async fn client_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("tests/keychain/localhost/ca.cert").to_certificate(),
    );
    let h3_client = H3Client::builder()
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
    let mut app = H3Servers::builder()
        .without_client_cert_verifier()?
        .listen()?;

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
    )
    .await?;

    app.run().await;

    Ok(())
}

```

#### Hyper / Tower Integration

h3x provides adapters to bridge the Tower / hyper service ecosystem into DHTTP/3, available under the `hyper` feature (enabled by default).

- `TowerService(S)` — wraps a `tower::Service` (e.g. an axum `Router`)
- `HyperService(S)` — wraps a `hyper::service::Service`

> **API note:** h3x cannot construct hyper's internal types directly, so the `h3x::hyper` module provides its own alternatives:
> - `h3x::hyper::upgrade` — stream takeover for Extended CONNECT tunnels (instead of `hyper::upgrade`)
> - `h3x::hyper::ext::Protocol` — protocol indication in CONNECT requests (instead of `hyper::ext::Protocol`)

```rust
use axum::{Router, body::Body, routing::get};
use h3x::{
    dquic::{H3Client, H3Servers, prelude::{BindUri, handy::ToCertificate}},
    hyper::server::TowerService,
};

async fn serve_axum_over_dhttp3() -> Result<(), Box<dyn std::error::Error>> {
    // Build a standard Tower service — here an axum Router
    let router = Router::new()
        .route("/hello", get(|| async { "Hello from DHTTP/3!" }));

    // Wrap it with TowerService to bridge into h3x
    let service = TowerService(router.into_service());

    let mut app = H3Servers::builder()
        .without_client_cert_verifier()?
        .listen()?;

    app.add_server(
        "localhost",
        include_bytes!("tests/keychain/localhost/server.cert"),
        include_bytes!("tests/keychain/localhost/server.key"),
        None,
        [BindUri::from("inet://[::1]:4433")],
        service,
    )
    .await?;

    app.run().await;
    Ok(())
}

// Client side — execute requests with hyper Body types
async fn hyper_client_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(
        include_bytes!("tests/keychain/localhost/ca.cert").to_certificate(),
    );
    let h3_client = H3Client::builder()
        .with_root_certificates(roots)
        .without_identity()?
        .build();

    let connection = h3_client.connect("localhost:4433".parse()?).await?;

    let response = connection
        .execute_hyper_request(
            http::Request::get("https://localhost:4433/hello")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    Ok(())
}
```