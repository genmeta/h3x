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

h3x deliberately does not connect, listen, resolve DNS names, inspect TLS identities, pool connections, or run application services. A transport adapter implements `h3x::transport::Connection`; dhttp owns the surrounding endpoint and identity policy.

## Server-Initiated Requests

Beneath the hood of a standard QUIC connection, both endpoints have equal ability to concurrently open bidirectional or unidirectional streams. However, the baseline HTTP/3 specification deliberately leaves server-initiated bidirectional streams unexploited. As explicitly stipulated in [**RFC 9114 - HTTP/3 Section 6.1**](https://datatracker.ietf.org/doc/html/rfc9114#section-6.1):

> HTTP/3 does not use server-initiated bidirectional streams, though an extension could define a use for these streams. Clients MUST treat receipt of a server-initiated bidirectional stream as a connection error of type H3_STREAM_CREATION_ERROR unless such an extension has been negotiated.

h3x uses these bidirectional streams as a negotiated symmetric `b"h3"` profile: either peer can initiate one request and receive one final response on the reverse direction of the same stream. Both peers use the same streaming `Connection::request` and `Connection::accept` API.

```rust,no_run
use h3x::{Connection, Error, transport};
use http::{Request, Response};
use http_body_util::Empty;

async fn send<T: transport::Connection>(
    h3: &Connection<T>,
    request: Request<()>,
) -> Result<Response<h3x::Body>, Error> {
    let (head, ()) = request.into_parts();
    let stream = h3.request(head).await?;
    stream.finish().await?;
    stream.response().await
}

async fn accept_one<T: transport::Connection>(h3: &Connection<T>) -> Result<(), Error> {
    if let Some((_request, response)) = h3.accept().await? {
        response.send(Response::new(Empty::<bytes::Bytes>::new())).await?;
    }
    Ok(())
}
```

Request body writes and response reads are independent. Callers can drive `RequestStream::write` and `RequestStream::response` concurrently without a background body pump. `accept` returns a decoded request and its single-use response right.

## Dynamic QPACK

Dynamic QPACK is enabled by advertising non-zero local limits:

```rust
let mut settings = h3x::Settings::default();
settings.set_qpack_max_table_capacity(4096);
settings.set_qpack_blocked_streams(16);
```

h3x owns one encoder stream, one decoder stream, and both dynamic-table states for the lifetime of the connection. Its encoder inserts reusable fields but only references entries acknowledged by the peer, avoiding encoder-created blocked streams. Its decoder accepts peer-created blocked field sections up to the advertised limit and wakes waiting request decoders when new insertions arrive.

## WebTransport

The optional `webtransport` feature implements WebTransport over HTTP/3 draft 16 without changing `ALPN` (`b"h3"`). Create the connection with `Connection::new_webtransport`; the transport adapter must additionally implement `transport::webtransport::Connection`, including QUIC DATAGRAM and negotiated `RESET_STREAM_AT` support.

The module provides extended CONNECT, bidirectional and unidirectional WebTransport streams, HTTP Datagrams, `WT_DRAIN_SESSION`, `WT_CLOSE_SESSION`, application error-code mapping, and reliable stream reset. Without WebTransport session flow-control negotiation, h3x deliberately permits one active session per HTTP/3 connection and ignores flow-control capsules.

Authorization remains above h3x. A server first resolves the HTTP request and applies its identity, Origin, and URL policy, then accepts it:

```rust,no_run
# #[cfg(feature = "webtransport")]
# use h3x::{Connection, Error, transport};
# #[cfg(feature = "webtransport")]
# async fn accept_webtransport<T: transport::webtransport::Connection>(
#     h3: &Connection<T>,
# ) -> Result<(), Error> {
let (request, response_sender) = h3.accept().await?.expect("connection is accepting requests");
if h3x::webtransport::is_request(&request) {
    // Authorize `request` before accepting the session.
    let session = h3x::webtransport::accept(
        request,
        response_sender,
        http::Response::new(()),
    )
    .await?;
    let (_receive, _send) = session.accept_bi().await?;
}
# Ok(())
# }
```
