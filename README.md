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
The response future carries the request method automatically, including HEAD and
CONNECT semantics. Uploads continue independently after an early response or after
the response future is dropped. Use the body producer's `finish()` or `reset()` to
terminate a streaming upload.
If upload fails before a response is ready, the response future returns that
failure. A response already ready takes priority; receiving it does not abort upload.

```rust,no_run
# use h3x::{Body, WndBuf, W, ArcQpack, H3ReadStream, H3WriteStream, WriteRequest, Result, client};
# async fn example<RS, WS>(rs: H3ReadStream<RS>, ws: H3WriteStream<WS>, qpack: ArcQpack) -> Result<()>
# where RS: tokio::io::AsyncRead + Unpin + Send + 'static,
# WS: tokio::io::AsyncWrite + Unpin + Send + 'static {
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
