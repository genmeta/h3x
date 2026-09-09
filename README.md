<p align="center">
  <img src="https://media.dhttp.net/img/h3x/h3x-logo.svg" alt="h3x" width="100%" />
</p>

<p align="center">
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/github/license/genmeta/h3x" alt="License: Apache-2.0" /></a>
  <a href="https://github.com/genmeta/h3x/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/genmeta/h3x/ci.yml" alt="Build Status" /></a>
  <a href="https://codecov.io/gh/genmeta/h3x"><img src="https://codecov.io/gh/genmeta/h3x/graph/badge.svg" alt="codecov" /></a>
  <a href="https://crates.io/crates/h3x"><img src="https://img.shields.io/crates/v/h3x.svg" alt="crates.io" /></a>
  <a href="https://docs.rs/h3x/"><img src="https://docs.rs/h3x/badge.svg" alt="Documentation" /></a>
  <a href="https://github.com/genmeta/h3x/network/dependencies"><img src="https://img.shields.io/deps-rs/repo/github/genmeta/h3x" alt="Dependencies" /></a>
  <img src="https://img.shields.io/crates/msrv/h3x" alt="MSRV" />
</p>

h3x is the symmetric HTTP/3 protocol core used by [dhttp](https://github.com/genmeta/dhttp). It runs on an already-established QUIC connection and provides streaming `http::Request` / `http::Response` APIs.

The crate has three layers: `client` / `server` for outgoing and incoming messages, `runtime` for identity, pooling and services, and `protocol` for HTTP/3. See [the architecture](design/architecture.md). The protocol adopts an established transport directly as `T: transport::Connection`; authentication facts remain in the runtime.

**Protocol API:** `protocol::new` returns one `Connection` supporting both outgoing requests and incoming acceptance. Share it with `Arc` when needed. `runtime::Connection::protocol()` exposes this connection; `Connection::transport()` borrows its existing QUIC transport without retaining another handle.

Public message paths are separate: `client::Request` builds and executes outgoing requests, and `client::Response` carries the authenticated reply. `server::Request` combines an HTTP request with a required local identity and an optional remote connection identity; `server::Response` combines an HTTP response with the same identities, inherited through `request.response(message)`; `server::ResponseSender` sends the reply on the accepted stream. Client and server describe each request's direction, not the QUIC endpoint role. `Request` and `Response` are not re-exported at the crate root.

## Server-Initiated Requests

Beneath the hood of a standard QUIC connection, both endpoints have equal ability to concurrently open bidirectional or unidirectional streams. However, the baseline HTTP/3 specification deliberately leaves server-initiated bidirectional streams unexploited. As explicitly stipulated in [**RFC 9114 - HTTP/3 Section 6.1**](https://datatracker.ietf.org/doc/html/rfc9114#section-6.1):

> HTTP/3 does not use server-initiated bidirectional streams, though an extension could define a use for these streams. Clients MUST treat receipt of a server-initiated bidirectional stream as a connection error of type H3_STREAM_CREATION_ERROR unless such an extension has been negotiated.

Either peer can initiate a request and receive its response on the reverse direction of the same bidirectional stream. Construction returns `Connection`; local sends and incoming stream acceptance are independent.

```rust,ignore
use h3x::{Error, Settings, protocol, transport};
use http_body_util::{BodyExt, Full};

async fn request<T: transport::Connection>(
    transport: T,
) -> Result<(), Error> {
    let connection = protocol::new(transport, Settings::default()).await?;
    let request = http::Request::builder()
        .method("POST")
        .uri("https://example.test/echo")
        .body(Full::new(bytes::Bytes::from_static(b"hello")))
        .unwrap();

    let response = connection.request(request).await?;
    response.into_body().collect().await?;
    connection.shutdown().await
}
```

`Connection::accept(&self)` returns `http::Request<ChunkBody>` and a `ResponseSender`. `Connection::request` takes the request directly and returns the final response without first waiting for upload completion. `Connection::request_streaming` takes the headers and returns BodyWriter/ResponseFuture after HEADERS are committed. ResponseSender retains the one-shot right to reply to an accepted request; its send completes after FIN. Protocol responses are standard `http::Response<ChunkBody>` values. The API layer attaches runtime authentication facts to its own `Response`; `Executing` waits for either a fixed-request response or a streaming response.

`Connection::close` closes immediately; `Connection::shutdown(&self)` drains admitted requests. Shutdown can be initiated only once; later calls return `InvalidState`. Dropping the connection closes its transport; when shared through `Arc`, this happens after the last owner is dropped. Acceptance is serialized without blocking concurrent request sending. The caller decides how long to wait and may explicitly close after a timeout. There is no public connection driver or outbound work queue. Protocol `closed()` waits for protocol resources only. The separate `runtime::shutdown()` stops and joins native dialing and service tasks; it currently performs a forced runtime stop, not automatic graceful draining.

## Dynamic QPACK

Dynamic QPACK is enabled by advertising non-zero local limits:

```rust
let mut settings = h3x::Settings::default();
settings.set_qpack_max_table_capacity(4096);
settings.set_qpack_blocked_streams(16);
```

h3x owns one encoder stream, one decoder stream, and both dynamic-table states for the lifetime of the connection. Its encoder inserts reusable fields but only references entries acknowledged by the peer, avoiding encoder-created blocked streams. Its decoder accepts peer-created blocked field sections up to the advertised limit and wakes waiting request decoders when new insertions arrive.

## WebTransport

The optional `webtransport` module retains the draft-16 protocol codecs and session helpers. Connection initialization and upgrade integration are still pending in this API skeleton; do not treat an enabled feature or a successful library check as a working WebTransport connection.

## Native runtime boundary

On native targets, pooling and the runtime are included by default. `init` registers already configured QUIC clients/listeners once. `Pool::get` returns `Arc<runtime::Connection>`; use `protocol()` for the HTTP/3 connection and `remote_authority()` for authenticated identity. The protocol connection no longer exposes identity or reuse-target accessors. `Arc<dquic::prelude::Connection>` directly implements the transport trait.

`Endpoint` lives in `src/endpoint.rs`. Client messages live in `src/client/` and are exported as `client::Request` and `client::Response`; server messages are available through `server`. Client requests build `http::Request` directly and client responses wrap `http::Response`. Ordinary HTTP send/receive and Body budgets are wired; protocol behavior verification and WebTransport integration remain pending.

`Endpoint::listen` accepts any `tower_service::Service<Request<ChunkBody>>` whose response body implements `http_body::Body<Data = Bytes>`. Listening is available on native targets without a framework feature; an Axum router implements this service interface directly, so h3x does not depend on Axum.

`Request::new(method, url, body)` constructs an anonymous request; `with_identity(endpoint)` selects a local identity. `request()` and `identity()` expose the stored HTTP message and identity. `header(name, value)` returns `Result<Self, Error>` and validates immediately. `Response::authority()` always returns an authenticated `RemoteAuthority`. Service request extensions contain `LocalAuthority` and `RemoteAuthority` when available; anonymous peers have no remote authority.

Services registered with `Endpoint::listen` receive `server::Request`. Use `request()` to inspect the HTTP message, `local_authority()` / `remote_authority()` for connection identities, and `into_http()` when adapting to a service accepting `http::Request`. Anonymous peers have no remote authority; HTTP headers never establish identity.

Stream I/O uses `dquic::prelude::StreamReader` and `StreamWriter` directly. The connection interface returns these concrete types; h3x has no custom receive/send stream traits or stream adapters. `StopSending` and `CancelStream` provide native cancellation. Frame submission uses `SinkExt::feed` so it does not wait for ACKs after every frame; normal FIN still uses the native close completion.
