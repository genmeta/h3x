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
the unidirectional stream accept task and control and QPACK writers.
`control.sync_control_with(...)` opens and owns the local control stream, writes SETTINGS, then
waits for the local admission boundary to freeze, then writes GOAWAY once.
`Control` holds only local and peer settings. The stream view notifies shutdown
waiters of the actual write result separately from freezing. The uni dispatcher calls
`receive_control` with the peer reader and callbacks. Admission boundaries and
stream registration remain protected by the same `BiStreams` lock.
`accept_bi().await` directly accepts and registers a peer bidirectional stream,
returning `(write, read)`. Applications drive request acceptance; there is no
background bidirectional stream queue.

Read and write handles own only their direction's state:
`H3ReadStream<R>` and `H3WriteStream<W>`. The connection stores a registered handle for each direction, sharing its state
with the application handle. Dropping an application handle removes its registration
without explicitly cancelling transport I/O. Read and write directions are registered independently in `BiStreams` and removed
immediately by completion callbacks on terminal I/O, cancellation, or handle drop.
Draining waits until both registries are empty. `BiStreams` owns the drain
notification; application handles only carry a completion callback and keep
their own separate I/O waker.
Explicitly cancelling either direction cancels its peer direction and the
request's QPACK state.
Each direction stores `Result<H3Stream, Error>`. `H3Stream` contains only active
I/O and the normal finished state; GOAWAY rejection, cancellation, protocol
failure, and terminal transport I/O failure are retained as the first H3 error.
Direction completion is reported as `Result<(), Error>`, so normal and failed
completion share registry cleanup while failures additionally propagate to the
paired direction, QPACK, or the connection according to their scope.
Custom receive/send types must implement `qrecovery::recv::StopSending` and
`qrecovery::send::CancelStream`, respectively. HTTP/3 calls these explicitly with
the protocol error code before releasing unfinished directions; it does not rely
on the underlying transport's `Drop` implementation.

Client request operations take `connection.qpack().clone()` and depend only on
compression state. `connection.qpack()` exposes that state as `Qpack`, which has
no stored transport dependency. Connection initialization explicitly starts both
QPACK writers; the connection owns critical-stream failures and transport termination.
Local encoding errors, including oversized fields, fail only the current operation.

`goaway(self).await` stops opening and accepting bidirectional streams on every
clone, writes the local GOAWAY, waits for the peer GOAWAY and admitted requests
to finish, then closes QUIC with `H3_NO_ERROR` and applies the terminal state to
H3 waiters.
Calling `goaway()` freezes admission immediately. Once frozen, GOAWAY sending continues in
the control task if the caller is cancelled; await shutdown to finish draining.
Control and QPACK remain available during draining. On a connection managed directly by the
application, receiving a peer GOAWAY only updates the peer boundary and rejects
affected requests. A managing `Pool` removes that connection from reuse.

Peer STOP/reset errors are observed through transport write, flush, or shutdown.
There is no independent STOP notification input while waiting for body data.
Applications finish or cancel outgoing bodies and stop incoming bodies explicitly.
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

- `get(&key).await` reuses a connection or serializes construction for that key
  using an asynchronous entry lock. Different keys connect independently.
  Cancelling or failing construction allows the next waiter to try again.
- `remove(&key)` removes the entry from reuse without sending GOAWAY or closing
  the transport. Calls already holding the removed entry may still finish and
  return its connection; they do not reinsert it or modify a replacement entry.
- Local GOAWAY automatically removes the entry. The pool does not call `accept_bi`;
  the component routing peer-initiated streams must own that receive loop and remove
  the connection after a terminal accept error.
  Removal is asynchronous; `get` may return the connection before its observer runs.
  Existing handles and admitted requests remain owned by the application.
- The pool has no shutdown or draining state. Dropping it releases cached handles
  without forcibly closing transports; applications manage connection shutdown.

The factory controls connection timeouts, and `get` returns factory errors directly.
The pool does not send or automatically retry requests; after `get`, use `connection.open_bi().await` and the normal request APIs.

## Request and Response I/O

Construct outgoing messages with `http::Request::builder()` and
`http::Response::builder()`, then convert them with `.into()`. Request and
response metadata is exposed through inherent methods. Outgoing values also have
inherent setters; request setters accept a parsed `http::Uri` and `http::Method`.

```rust
use h3x::ArcWndBuf;
use h3x::{Request, Response, W};

let mut request: Request<W> = http::Request::builder()
    .method(http::Method::POST)
    .uri("https://example.com/upload")
    .version(http::Version::HTTP_3)
    .body(ArcWndBuf::new(8192))?
    .into();
request.set_method(http::Method::PUT);
assert_eq!(request.method(), http::Method::PUT);

let mut response: Response<W> = http::Response::builder()
    .version(http::Version::HTTP_3)
    .body(ArcWndBuf::new(8192))?
    .into();
response.set_status(http::StatusCode::CREATED);
assert_eq!(response.status(), http::StatusCode::CREATED);
# Ok::<(), http::Error>(())
```

Use `WndBuf` as the builder's body for streaming requests and responses. Before
handing a value to its stream writer, clone `request.body()` or `response.body()`
when another future will produce a streaming body. Converting back to
`http::Request` / `http::Response` preserves metadata and the shared body.
The public `into_parts` and `from_parts` methods transfer message metadata and
body ownership without copying them, including through host adapters.

The four protocol I/O traits live on the stream directions. Responses take the
original request method so HEAD and CONNECT response semantics can be applied:

```rust,ignore
use h3x::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};

let incoming_request = rs.read_request(qpack.clone()).await?;
let request_method = incoming_request.method().clone();
ws.write_response(outgoing_response, request_method, qpack.clone()).await?;

ws.write_request(outgoing_request, qpack.clone()).await?;
let incoming_response = rs.read_response(method, qpack).await?;
```

Each write future encodes metadata, sends HEADERS and DATA, and finishes its
transport direction. Drive writing, streaming production, and response reception
concurrently. No upload task is started implicitly by a stream writer. Failures
are returned directly and wake streaming producers with the same error.

`Request` and `Response` store an `ArcWndBuf` directly (also exported as
`WndBuf`). `Request<R>` and `Response<R>` implement Tokio `AsyncRead`;
`Request<W>` and `Response<W>` implement Tokio `AsyncWrite`.

```rust,ignore
use tokio::io::AsyncReadExt;

let mut bytes = Vec::new();
response.read_to_end(&mut bytes).await?;
```

Messages also contain shared `Trailers` storage. Outgoing `Request<W>` and
`Response<W>` values can be cloned: their initial metadata is copied while the
body and trailers remain shared. Set or append every outgoing trailer before
shutting down the body. The stream writer drains DATA, reads the trailers after
body EOF, sends a trailing HEADERS frame when they are non-empty, and then sends
FIN.

```rust,ignore
let outgoing = request.clone();
let writing = tokio::spawn(stream.write_request(outgoing, qpack));

request.write_all(payload).await?;
request.set_trailer(
    http::HeaderName::from_static("x-checksum"),
    http::HeaderValue::from_static("ok"),
);
request.shutdown().await?;
writing.await??;
```

For incoming messages, drain the body to EOF before reading the synchronous
trailer snapshot:

```rust,ignore
let mut bytes = Vec::new();
response.read_to_end(&mut bytes).await?;
let trailers = response.trailers();
```

ArcWndBuf clones share the buffer.
Use Tokio's `AsyncReadExt` / `AsyncWriteExt` directly with ArcWndBuf. Call
`shutdown().await` on the producer to finish production. The polled write future
drains the buffer and sends FIN. Use `stop(code)` or `cancel(code)` on the window
to cancel reception or sending. The directional messages expose the same
operations: `Request<R>` / `Response<R>` implement `StopSending`, while
`Request<W>` / `Response<W>` implement `CancelStream`. Host adapters should use
the message-level operation. Cloning or dropping a window does not implicitly
finish or cancel it.

For incoming ArcWndBuf bodies, a receive task starts after headers are parsed.
A full window pauses network reads; consuming bytes resumes them. Valid transport
EOF finishes the buffer, leaving unread bytes available. Errors reach waiting
readers through the window, and cancellation wakes the receive task even while
it is waiting for network input or space.

All incoming messages return after final HEADERS with an ArcWndBuf body.
DATA, trailers, and FIN are processed by the receive task; subsequent errors
are reported when reading the body. Content-Length does not select body storage.
The sender still checks declared lengths while streaming.

## Errors

`h3x::Result<T>` returns `h3x::Error`, which contains a protocol `code` and a
descriptive `reason`. Use `error.code` for protocol decisions and `error.reason`
for diagnostics. Its `Stream` and `Connection` variants specify whether handling
the error aborts one request or the entire HTTP/3 connection. Error construction
requires this scope to be selected explicitly. Underlying error details are included
in `reason`; there is no source chain. Streams retain raw I/O errors until a protocol
boundary classifies them. Wrapping an `Error` in `io::Error` preserves its scope,
protocol code, and reason.

```rust
use h3x::{Error, ErrorCode};

let error = ErrorCode::MessageError.stream("missing pseudo-header :status");
assert_eq!(error.code, ErrorCode::MessageError);
assert_eq!(Error::from(std::io::Error::from(error.clone())), error);
```

Transport adapters report connection failures through open/accept and stream I/O,
retaining the supplied close reason. Construct failures with `code.stream(reason)` or
`code.connection(reason)`, supplying both the context and scope at the point of failure.

## Server-Initiated Requests

Beneath the hood of a standard QUIC connection, both endpoints have equal ability to concurrently open bidirectional or unidirectional streams. However, the baseline HTTP/3 specification deliberately leaves server-initiated bidirectional streams unexploited. As explicitly stipulated in [**RFC 9114 - HTTP/3 Section 6.1**](https://datatracker.ietf.org/doc/html/rfc9114#section-6.1):

> HTTP/3 does not use server-initiated bidirectional streams, though an extension could define a use for these streams. Clients MUST treat receipt of a server-initiated bidirectional stream as a connection error of type H3_STREAM_CREATION_ERROR unless such an extension has been negotiated.

h3x uses exactly these server-initiated bidirectional streams so that the "server" can initiate requests to the "client."

## CONNECT and WebSocket tunnels

Extended CONNECT support is enabled and advertised automatically by both
`Settings::default()` and `Settings::new(...)`; no opt-in is required.
For CONNECT, drive `write_request` concurrently with response reception and keep
the request body window empty until `read_response` returns a successful response.
The writer flushes HEADERS before waiting for body data. The caller controls
handshake acceptance, rejection, and cancellation; on rejection cancel the
retained request body producer. Extended CONNECT assumes peer support without
waiting for peer SETTINGS.

The server uses `read_request` for both ordinary HTTP and CONNECT and branches
on `request.method()`. Send a 2xx response with `write_response` to accept a tunnel,
passing `Method::CONNECT` and omitting Content-Length. Drive writing
concurrently with body production and request reception. Stop the incoming body
and cancel the retained producer when abandoning an exchange.

There is no separate `Tunnel` type. Use `into_body()` to extract the ArcWndBuf. It implements Tokio `AsyncRead` and `AsyncWrite`, so
the tunnel directions can use Tokio copy helpers or application codecs directly.
`shutdown()` finishes production; the sender drains buffered DATA and sends FIN.
`flush()` exposes buffered bytes without waiting for transport delivery.
`cancel(code)` cancels sending and `stop(code)` cancels receiving; dropping a
window alone has no implicit cancellation behavior.

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

ArcWndBuf cancellation uses `qrecovery::recv::StopSending` and
`qrecovery::send::CancelStream`: import the trait and call `stop(code)` on an
incoming body or `cancel(code)` on an outgoing streaming body. Both are synchronous;
the callback forwards the supplied code to both transport directions and cancels
the request's QPACK state. Unknown codes are mapped to `InternalError`.

Extended CONNECT stores `:protocol` as an `Arc<str>` in request extensions
(`http::Request::builder().extension(Arc::<str>::from("websocket"))`).
That extension type is reserved for `:protocol`; the token is stored separately from ordinary fields. `ReadRequest::protocol()` returns `Option<Arc<str>>`.
For WebSocket CONNECT requests, outgoing `ws://` and `wss://` URIs are normalized
to the required `http://` and `https://` target schemes respectively.
