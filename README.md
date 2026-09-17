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

`goaway(self).await` stops accepting peer requests on every clone, writes the
local GOAWAY, waits for the peer GOAWAY and admitted requests to finish, then
closes QUIC with `H3_NO_ERROR` and applies the terminal state to H3 waiters.
Await `goaway()` to completion: cancelling it during a GOAWAY write is not safe.
Pool-managed draining continues independently of shutdown waiters. Control and
QPACK remain available during draining. On a connection managed directly by the
application, receiving a peer GOAWAY only updates the peer boundary and rejects
affected requests. A managing `Pool` also retires and drains that connection.

Peer STOP/reset errors are observed through transport write, flush, or shutdown.
There is no independent STOP notification input while waiting for body data.
Applications finish or reset outgoing bodies and stop incoming bodies explicitly.
Stream termination wakes pending network I/O and connection drain waiters;
tasks waiting for body data or buffer space resume when the application advances
or cancels the body.

## Connection Pool

`Pool<K, T, E>` shares connections by a caller-defined key implementing
`Clone + Eq + Hash + Send + Sync + 'static`. Equal keys must permit reuse of the
same authenticated connection; keep credentials and connection configuration in
the factory, and use a different key or `remove(&key)` when identity policy changes.

`Pool::new(factory)` accepts an asynchronous `Fn(K)` returning
`Result<H3Connection<T>, E>`. The factory must complete the QUIC handshake,
authentication and ALPN `h3` verification before returning an initialized H3
connection, and reclaim unreturned resources when cancelled. Do not return a
connection already managed by another pool.

- `get(&key).await` reuses a connection or merges concurrent calls into one
  factory execution for that key. Different keys connect independently. Cancelling
  the first caller cancels the shared build with `PoolError::BuildCancelled`;
  cancelling another waiter does not affect the build.
- `remove(&key)` revokes the current build or removes the current connection
  from reuse and starts GOAWAY. Existing handles can still open streams until peer
  GOAWAY or transport close. A replacement can connect while older generations
  drain. Already admitted requests can finish without returning a handle to the pool.
- Peer GOAWAY, local draining and connection failure trigger automatic retirement.
  Each retired generation has its own deadline; expiration explicitly closes its
  transport and waits for H3 cleanup.
- `shutdown().await` permanently stops allocation and waits for cancelled builds
  and managed connections to finish cleanup. Cancelling this waiter does not stop
  shutdown. Dropping the last pool owner immediately closes remaining connections.

`Pool::with_config(factory, PoolConfig { ... })` configures the whole-factory
`connect_timeout` (default 10 seconds) and each connection's `drain_timeout`
(default `Some(30 seconds)`, or `None` for unbounded draining). Build cancellation
is cooperative: a revoked creator must be polled or dropped before shutdown can
finish. The pool does not send or automatically retry requests; after `get`, use
`connection.open_bi().await` and the normal request APIs.

## Request and Response I/O

`write_bytes_request` accepts an existing Bytes body; `write_streaming_request`
accepts a WndBuf body. Both take `(request, write_stream, read_stream, qpack)`,
start the upload in an internal task, and return an
`IntoFuture<Output = Result<Response>>`.
The response future carries the request method automatically, including HEAD
semantics. CONNECT uses the same streaming entry point, with handshake behavior
described below. Ordinary uploads continue independently after an early response or after
the response future is dropped. Use the body producer's `finish()` or `reset()` to
terminate a streaming upload.
Upload failures cancel the write direction and notify streaming body producers;
they do not fail the response future. Response reception continues independently,
so callers should apply a timeout or cancel the response future when appropriate.
Receiving a response does not abort upload.

```rust,no_run
# use h3x::{Body, WndBuf, W, ArcQpack, H3ReadStream, H3WriteStream, WriteRequest, Result, client};
# async fn example<RS, WS>(rs: H3ReadStream<RS>, ws: H3WriteStream<WS>, qpack: ArcQpack) -> Result<()>
# where RS: qrecovery::recv::StopSending + tokio::io::AsyncRead + Unpin + Send + 'static,
# WS: qrecovery::send::CancelStream + tokio::io::AsyncWrite + Unpin + Send + 'static {
let request = client::Request::streaming_post("https://example.com/upload")?;
let mut upload = request.body();
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
`body()` retains a producer independently of the outgoing message. Incoming
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
Incoming bodies are returned as streaming handles after HEADERS, including bodies
with a known Content-Length.

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

CONNECT uses the same streaming body handles as ordinary requests and responses.
`Request::connect` returns `Request<WndBuf>`. Retain `request.body()` before sending:

```rust,no_run
# use h3x::{client, ReadResponse, H3Connection, Transport};
# async fn connect<T: Transport>(connection: &H3Connection<T>) -> Result<(), Box<dyn std::error::Error>> {
let request = client::Request::connect("wss://home.example/api/websocket")?;
let mut send = request.body();
let (ws, rs) = connection.open_bi().await?;
let response = client::write_streaming_request(
    request, ws, rs, connection.qpack().clone(),
)?.await?;
if response.status().is_success() {
    let mut recv = response.into_body();
    // Exchange application bytes with send.write_all(...) and recv.read(...).
    send.finish().await?; // The receive direction remains open.
    recv.stop().await;
} else {
    let status = response.status();
    let rejection = response.into_body().collect().await?;
}
# Ok(()) }
```

The CONNECT response future drives the handshake. No DATA is sent before final
2xx HEADERS, even if the application has already queued bytes in the body window.
After acceptance, background tasks send and receive DATA through the same bounded
buffers used for ordinary streaming HTTP. Extended CONNECT assumes peer support
without waiting for peer SETTINGS. Dropping a pending handshake cancels both stream
directions; explicitly reset the retained body when abandoning the handshake.
Rejection cancels production while
preserving the response's status, headers, and body. `client::connect` is also
available as a convenience: it returns the same response on success and
`ConnectError::Rejected(response)` for non-2xx responses.

The server reads CONNECT with `read_request` and accepts it by sending a streaming
2xx response. Complete routing, authorization, and any upstream handshake before
starting the response writer:

```rust,no_run
# use h3x::{server, ReadRequest, WriteResponse, H3Connection, Transport};
# async fn accept<T: Transport>(connection: H3Connection<T>) -> h3x::Result<()> {
let (ws, rs) = connection.accept_bi().await?;
let request = server::read_request(rs, connection.qpack().clone()).await?;
let method = request.method();
let mut recv = request.into_body();
let mut response = server::Response::default();
response.set_status(http::StatusCode::OK);
let response = response.streaming(16 * 1024);
let mut send = response.body();
let writing = server::write_streaming_response(
    response, ws, connection.qpack().clone(), &method,
);
let (sent, produced) = tokio::join!(writing, async {
    let mut buf = [0; 4096];
    loop {
        let n = recv.read(&mut buf).await?;
        if n == 0 { break; }
        send.write_all(&buf[..n]).await?;
    }
    send.finish().await
});
sent?;
produced?;
# Ok(()) }
```

`read_request_head` and `read_request_body` remain available when the application
needs to inspect headers before starting reception. To reject CONNECT, stop the
request body and send a non-2xx response with either response writer.
Successful responses must use the streaming writer and omit Content-Length.

There is no separate `Tunnel` type. Outgoing `Body<WndBuf, W>` implements Tokio
`AsyncWrite`; incoming `Body<WndBuf, R>` implements `AsyncRead`. Applications can
relay the two directions independently or combine them for a duplex codec.
`finish()` / `shutdown()` finish production; the sender drains buffered DATA and
then sends FIN. `flush()` exposes buffered bytes to the sender without waiting
for transport delivery. `reset()` cancels sending and `stop()` cancels receiving;
dropping a body alone has no implicit cancellation behavior.

CONNECT preserves all DATA payload bytes, including WebSocket masks,
fragmentation, and negotiated compression. Unknown frames are skipped; trailing
HEADERS and other prohibited frames produce a connection-level protocol error.
Ordinary cancellation stays stream-local. GOAWAY stops admission while existing
streams remain registered for draining until both directions finish or cancel.

This library provides the HTTP/3 capability only. Trusted backend routing,
HTTP/1.1 Upgrade conversion, TLS dialing, subprotocol/extension validation, and
relay timeouts belong to the proxy/application. No WebSocket message codec is
included. See [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) and
[RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4).
