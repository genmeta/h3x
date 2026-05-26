[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/h3x)](https://www.apache.org/licenses/LICENSE-2.0)

High-performance asynchronous DHTTP/3 implementation in Rust.

- **Peer-to-Peer**: Extends [HTTP3(RFC9114)](https://datatracker.ietf.org/doc/html/rfc9114) to *DHTTP/3*, allowing both sides of the connection to initiate and handle HTTP3 requests (achieved by disabling server push).
- **Asynchronous I/O**: Built on the Rust asynchronous ecosystem, providing high-performance I/O processing capabilities.
- **Zero-Copy**: Achieves full-link *zero-copy* from the QUIC layer to the application layer.
- **Multipath QUIC**: Integrates the `dquic` implementation, featuring efficient transmission, robust authentication capabilities, and high extensibility.
- **Hyper / Tower Compatibility** *(feature `hyper`, enabled by default)*: Provides `TowerService` and `HyperService` adapters to run existing Tower or hyper services (e.g. `axum`) over DHTTP/3. Since h3x cannot construct hyper's internal types, the `h3x::hyper` module provides its own alternatives for upgrade and protocol negotiation.
- **RPC / IPC** *(features `rpc` and `ipc`, experimental)*: Optional [`remoc`](https://crates.io/crates/remoc) integration for remote trait calls (RTC) over QUIC connections, with optional IPC transport support. Consumers must select exactly one `remoc/default-codec-*` feature; h3x tests use the bincode codec through a dev-dependency.
- **Extended CONNECT**: Supports [Extended CONNECT (RFC9220)](https://datatracker.ietf.org/doc/html/rfc9220) for protocol tunneling over HTTP/3.
- **Future Extensions**: Plans to support extensions such as [WebTransport over HTTP/3 (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-14).

### Examples

> ⚠️ Currently, h3x is in the early stages of development, and the API may undergo significant changes.

h3x includes `dquic` as its built-in QUIC backend (feature `dquic`, enabled by default). Wrap a `QuicEndpoint` in an `H3Endpoint` to get HTTP/3 client and server semantics on top of QUIC.

```rust,no_run
use h3x::{dquic::QuicEndpoint, endpoint::H3Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = H3Endpoint::new(QuicEndpoint::new().await);

    let mut response = endpoint.get("https://example.com:4433/hello".parse()?).await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    println!("{}", response.read_to_string().await?);
    Ok(())
}
```

```rust,no_run
use std::sync::Arc;
use h3x::{
    dquic::{Identity, Name, QuicEndpoint},
    endpoint::{H3Endpoint, server::{Request, Response, Service}},
};

async fn hello(_req: &mut Request, resp: &mut Response) {
    resp.set_status(http::StatusCode::OK).set_body(&b"Hello, World!"[..]);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Arc::new(Identity {
        name: Name::from_static("localhost")?,
        certs: todo!("load your certificate chain"),
        key: todo!("load your private key"),
        ocsp: Arc::new(None),
    });
    let endpoint = H3Endpoint::new(
        QuicEndpoint::builder()
            .identity(identity)
            .bind(Arc::new(vec!["127.0.0.1:4433".parse()?]))
            .build().await,
    );

    let service = Service::new().get("/hello", hello);
    endpoint.serve(service).await?;
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

```rust,no_run
use std::sync::Arc;
use axum::{Router as AxumRouter, routing::get};
use h3x::{
    dquic::{Identity, Name, QuicEndpoint},
    endpoint::H3Endpoint,
    hyper::server::TowerService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let router = AxumRouter::new()
        .route("/hello", get(|| async { "Hello from DHTTP/3!" }));
    let service = TowerService(router.into_service());

    let identity = Arc::new(Identity {
        name: Name::from_static("localhost")?,
        certs: todo!("load your certificate chain"),
        key: todo!("load your private key"),
        ocsp: Arc::new(None),
    });
    H3Endpoint::new(
        QuicEndpoint::builder()
            .identity(identity)
            .bind(Arc::new(vec!["127.0.0.1:4433".parse()?]))
            .build().await,
    )
    .serve(service)
    .await?;
    Ok(())
}
```

```rust,no_run
use h3x::{dquic::QuicEndpoint, endpoint::H3Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = H3Endpoint::new(QuicEndpoint::new().await);

    let mut response = endpoint.get("https://example.com:4433/hello".parse()?).await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response.read_to_bytes().await?;
    println!("{}", String::from_utf8_lossy(&body));
    Ok(())
}
```

### Testing and Coverage

h3x uses one canonical test entrypoint for local development and CI:

```bash
cargo test --all-features --all-targets
```

All feature-gated paths, including `rpc`, `ipc`, `webtransport`, `dquic`, and `hyper`, must compile and test through that command. The dev-dependency on `remoc` selects the bincode default codec for tests so `rpc`/`ipc` can compile under `--all-features`.

Documentation is checked with warnings denied for all non-`rpc`/`ipc` features:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --no-default-features --features dquic,hyper,serde,testing,webtransport
```

Coverage uses `cargo-llvm-cov` directly:

```bash
cargo llvm-cov clean
mkdir -p target/llvm-cov
cargo llvm-cov \
  --all-features \
  --all-targets \
  --summary-only \
  --json \
  --output-path target/llvm-cov/coverage.json \
  --fail-under-lines 62 \
  --fail-under-functions 56 \
  --fail-under-regions 64
cargo llvm-cov report --lcov --output-path target/llvm-cov/lcov.info
cargo llvm-cov report --html --output-dir target/llvm-cov
```

The HTML report entrypoint is:

```text
target/llvm-cov/html/index.html
```

The initial coverage gate preserves the current baseline. Raise the gate only in commits that add meaningful tests or remove dead code.
