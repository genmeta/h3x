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

h3x is an HTTP/3 library implemented for [dquic](https://github.com/genmeta/dquic). It provides familiar APIs for `Request` and `Response`. It is not recommended for direct use; use [dhttp](https://github.com/genmeta/dhttp) instead.

## Connection Lifecycle

Construct `H3Connection<T>` inside a Tokio runtime. Connection initialization starts
the unidirectional stream accept task and the control and QPACK writers.
`accept_bi().await` directly accepts and registers a peer bidirectional stream,
returning `(write, read)`. Applications drive request acceptance; there is no
background bidirectional stream queue.

Read and write handles own only their direction's state:
`H3ReadStream<R>` and `H3WriteStream<W>`. The connection observes those states
through weak references. Dropping an application handle cancels its direction;
connection references cannot keep transport halves alive. Draining waits directly
on each direction's terminal state, with separate I/O and drain waiters.
Custom receive/send types must implement `qrecovery::recv::StopSending` and
`qrecovery::send::CancelStream`, respectively. HTTP/3 calls these explicitly with
the protocol error code before releasing unfinished directions; it does not rely
on the underlying transport's `Drop` implementation.

Client request operations take `connection.qpack().clone()` and depend only on
compression state. `connection.qpack()` exposes that state as `Qpack`, which has
no transport dependency. Connection initialization explicitly starts both
QPACK writers; the connection owns critical-stream failures and transport termination.
Local encoding errors, including oversized fields, fail only the current operation.

`goaway(self).await` writes the local GOAWAY, waits for the peer GOAWAY and
admitted requests to finish, then closes QUIC with `H3_NO_ERROR`. Control and
QPACK remain available during this wait. Receiving a peer GOAWAY alone updates
the peer boundary and rejects affected requests; it does not initiate local
GOAWAY, draining, or transport closure.

Peer STOP/reset errors are observed through transport write, flush, or shutdown.
There is no independent STOP notification input while waiting for body data.
Applications finish or reset outgoing bodies and stop incoming bodies explicitly.
Stream termination wakes pending network I/O and connection drain waiters;
tasks waiting for body data or buffer space resume when the application advances
or cancels the body.

## Request and Response I/O

`write_bytes_request` accepts an existing Bytes body; `write_streaming_request`
accepts a WndBuf body. Both take `(request, write_stream, read_stream, qpack)`,
start the upload in an internal task, and return an
`IntoFuture<Output = Result<Response>>`.
The response future carries the request method automatically, including HEAD
semantics. CONNECT uses the dedicated handshake API described below. Uploads continue independently after an early response or after
the response future is dropped. Use the body producer's `finish()` or `reset()` to
terminate a streaming upload.
If upload fails before a response is ready, the response future returns that
failure. A response already ready takes priority; receiving it does not abort upload.

```rust,no_run
# use h3x::{Body, WndBuf, W, ArcQpack, H3ReadStream, H3WriteStream, WriteRequest, Result, client};
# async fn example<RS, WS>(rs: H3ReadStream<RS>, ws: H3WriteStream<WS>, qpack: ArcQpack) -> Result<()>
# where RS: qrecovery::recv::StopSending + tokio::io::AsyncRead + Unpin + Send + 'static,
# WS: qrecovery::send::CancelStream + tokio::io::AsyncWrite + Unpin + Send + 'static {
let mut upload = Body::<WndBuf, W>::with_capacity(16 * 1024);
let request = client::Request::post("https://example.com/upload")?
    .with_body(upload.clone());
let response = client::write_streaming_request(request, ws, rs, qpack)?;

let (received, produced) = tokio::join!(
    async { response.await?.into_body().collect().await },
    async {
        upload.write_all(b"hello").await?;
        upload.finish().await
    },
);
produced?;
let response_bytes = received?;
# Ok(())
# }
```

Server entry points are `read_request(rs, qpack)`,
`write_bytes_response(response, ws, qpack, &method)`, and
`write_streaming_response(response, ws, qpack, &method)`. Pass `connection.qpack().clone()` as `qpack`. Obtain `method` from the
original request before consuming it. Both writers finish their transport direction
only after sending the body. Drive streaming production concurrently with writing.

`Body<Bytes, W>` and `Body<WndBuf, W>` are outgoing bodies. `with_body` attaches a body;
`body_handle` retains a producer independently of the outgoing message. Incoming
messages expose `into_body()`, with `read`, `collect`, and `stop` operations. Individual
body variants have direction `R`; incoming body handles cannot write or finish.
Existing message-level body access and streaming constructors remain available.

Messages own `Body<B, IO>` through `ArcMessage<Body<B, IO>>`. A body handle owns only
its storage, so extracting it releases the message headers when no other message
owner remains. Sharing a body between messages does not share or overwrite their
headers. Body stores `B` directly: Bytes clones are independent snapshots, while
WndBuf clones share the buffer using its own synchronization. There is no outer
lock or application-owner counter. `WndBuf` storage lives in `common::wnd_buf`.

For incoming WndBuf bodies, a shared receive task starts after headers are parsed.
A full window pauses network reads; consuming bytes resumes them. Valid transport
EOF marks the buffer finished, leaving unread bytes available to the application.
Content-Length alone does not finish reception: trailing frames and EOF are still
validated. Errors reach waiting readers through the buffer. Calling `stop` cancels
the task even while it is waiting for network input or space. Dropping a Body does
not signal EOF or cancellation.
Small known-length bodies are collected as Bytes before the message is returned.

Dropping the response future does not stop its internal upload task. Use `reset()`
to cancel an outgoing body and wake blocked operations. A successful producer
`finish()` means no more data will be supplied; the internal task then drains the
buffer and finishes the transport direction. Cloning or dropping Body adds no
implicit finish/reset/stop behavior.

## Errors

`h3x::Result<T>` returns `h3x::Error`, which contains a protocol `code` and a
descriptive `reason`. Use `error.code` for protocol decisions and `error.reason`
for diagnostics. `Error` contains only `code` and `reason`, and implements
`std::error::Error` and `Display` with `thiserror`. Underlying error details are
included in `reason`; there is no source chain. Streams retain raw I/O errors
until a protocol boundary classifies them. Wrapping an `Error` in `io::Error`
preserves the protocol code and reason.

```rust
use h3x::{Error, ErrorCode};

let error = Error::new(ErrorCode::H3_MESSAGE_ERROR, "missing pseudo-header :status");
assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
assert_eq!(Error::from(std::io::Error::from(error.clone())), error);
```

Transport adapters return `Error` from `terminated()` and retain the supplied
close reason. Construct failures with `Error::new(code, reason)` or
`code.with_reason(reason)`, supplying the context at the point of failure.

## Server-Initiated Requests

Beneath the hood of a standard QUIC connection, both endpoints have equal ability to concurrently open bidirectional or unidirectional streams. However, the baseline HTTP/3 specification deliberately leaves server-initiated bidirectional streams unexploited. As explicitly stipulated in [**RFC 9114 - HTTP/3 Section 6.1**](https://datatracker.ietf.org/doc/html/rfc9114#section-6.1):

> HTTP/3 does not use server-initiated bidirectional streams, though an extension could define a use for these streams. Clients MUST treat receipt of a server-initiated bidirectional stream as a connection error of type H3_STREAM_CREATION_ERROR unless such an extension has been negotiated.

h3x uses exactly these server-initiated bidirectional streams so that the "server" can initiate requests to the "client."

## CONNECT and WebSocket tunnels

Extended CONNECT support is enabled and advertised automatically by both
`Settings::default()` and `Settings::new(...)`; no opt-in is required.
`Request::connect("ws://host/path")` and `Request::connect("wss://host/path")`
construct WebSocket CONNECT requests, mapping their schemes to HTTP/HTTPS and
setting `Sec-WebSocket-Version: 13`. They preserve the path and query and reject
userinfo and fragments. `Request::connect("host:443")` constructs plain CONNECT.
Construction does not dial a backend or open an HTTP/3 stream.

```rust,no_run
# use h3x::{client, H3Connection, Transport};
# async fn connect<T: Transport>(connection: &H3Connection<T>) -> Result<(), Box<dyn std::error::Error>> {
let request = client::Request::connect("wss://home.example/api/websocket")?;
match client::connect(request, connection).await? {
    client::ConnectOutcome::Connected { response, mut tunnel } => {
        assert!(response.status().is_success());
        // Drive tunnel with AsyncRead/AsyncWrite, or copy_bidirectional.
        // Only send WebSocket frame bytes after the handshake succeeds.
        tunnel.finish().await?;
    }
    client::ConnectOutcome::Rejected(response) => {
        // Status, headers, and ordinary response body remain available.
    }
}
# Ok(()) }
```

The client waits for peer SETTINGS before sending Extended CONNECT. Unsupported
peers return `ConnectError::NotSupported` without closing the connection. Plain
CONNECT requires no extension negotiation. A successful handshake returns after
final 2xx HEADERS, without waiting for DATA or FIN. Handshake bodies must be empty.

On the server, retain the read direction until the application chooses how to
handle the request. `read_request_head` borrows the stream and returns an
`http::Request<()>` containing metadata only. It reads exactly through the initial
HEADERS, so no caller-side `BufReader` or connection-owning wrapper is needed:

```rust,no_run
# use h3x::{server, H3Connection, Transport};
# async fn accept<T: Transport>(connection: H3Connection<T>) -> h3x::Result<()> {
let (send, mut recv) = connection.accept_bi().await?;
let head = server::read_request_head(&mut recv, connection.qpack()).await?;
if head.method() == http::Method::CONNECT {
    let protocol = head.extensions().get::<h3x::ext::Protocol>();
    // Route and authorize here; finish any upstream handshake before accepting.
    let tunnel = server::accept_connect(
        http::Response::new(()), send, recv, connection.qpack().clone(), head.method(),
    ).await?;
    // Pass ownership of tunnel to application I/O or relay code.
} else {
    let request = server::read_request_body(head, recv, connection.qpack().clone())?;
    // Use existing response writers with send and connection.qpack().clone().
}
# Ok(()) }
```

To reject CONNECT, drop the receive stream and use `write_bytes_response` or
`write_streaming_response` with `Method::CONNECT` and a non-2xx status. Stopping
reception leaves the response write direction usable. Ordinary request writers
reject CONNECT, and ordinary response writers reject successful CONNECT; use
`client::connect` / `server::accept_connect` instead. The existing
`read_request(recv, qpack)` remains available for ordinary HTTP.

`Tunnel` implements Tokio `AsyncRead` and `AsyncWrite`. It strips HTTP/3 DATA
framing and preserves all payload bytes, including WebSocket masks, fragmentation,
and negotiated compression. It has no body pump or background task. Accepted
writes own at most 16 KiB of payload per pending frame; `flush()` drains it and
flushes the transport. `finish()` / `shutdown()` drain and close only the send
direction, while `abort()` discards pending data and cancels both directions.
Dropping unfinished stream halves cancels them. Reads retain partial frame headers
across cancellation, skip unknown frames with bounded memory, and preserve bytes
following handshake HEADERS. The DATA reader holds `H3ReadStream` directly; stream parameters and tunnel
members do not require a `BufReader` wrapper. Prohibited frames after acceptance produce a
connection-level protocol error; ordinary tunnel cancellation stays stream-local.
GOAWAY stops admission while existing tunnels remain registered for draining.

This library provides the HTTP/3 capability only. Trusted backend routing,
HTTP/1.1 Upgrade conversion, TLS dialing, subprotocol/extension validation, and
relay timeouts belong to the proxy/application. No WebSocket message codec is
included. See [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) and
[RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4).
