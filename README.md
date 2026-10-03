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
with the application handle. Dropping an unfinished read handle sends STOP_SENDING;
dropping an unfinished write handle sends RESET_STREAM. Both use
`H3_REQUEST_CANCELLED` and remove the affected stream registrations. Handles that
already reached EOF/FIN or an error do not cancel again. Read and write directions are registered independently in `BiStreams` and removed
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
Applications finish or abort write futures and drop unused incoming bodies.
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

Request writing accepts `http::Request<B>` with a standard HTTP body.
Read operations return `http::Request<Body>` or `http::Response<Body>`, and response
writing accepts `http::Response<Body>`. `h3x::Body` is an
`UnsyncBoxBody<Bytes, BoxError>`; use `BodyExt::map_err` and `boxed_unsync` when
preparing a response body. An existing `h3x::Body` can be passed directly.

```rust
use bytes::Bytes;
use h3x::Body;
use http_body_util::{Empty, Full};

let request = http::Request::builder()
    .method(http::Method::POST)
    .uri("https://example.com/upload")
    .body(Full::new(Bytes::from_static(b"hello")))?;
let empty_request = http::Request::builder()
    .uri("https://example.com/")
    .body(Empty::<Bytes>::new())?;
let response: http::Response<Body> = http::Response::new(Body::default());
# Ok::<(), http::Error>(())
```

Applications configure metadata with the standard HTTP APIs. Custom `Request<R/W>`,
`Response<R/W>` and shared `Trailers` are no longer public message types.

`write_request` is generic over `B: http_body::Body<Data = Bytes> + Send`, with
`B::Error: Into<BoxError>`. Pass `Empty<Bytes>`, `Full<Bytes>`, `StreamBody`, or an
existing boxed `Body` directly. The source is pinned inside the write future, so
it does not need `Unpin`. Empty bodies send headers and finish the write direction.
An existing `WndBuf` has a separate implementation that consumes its shared
window directly.

```rust,ignore
use h3x::{ReadRequest, WriteResponse};
use http_body_util::BodyExt;

let request = reader.read_request(connection.qpack().clone()).await?;
let method = request.method().clone();
let response = router.oneshot(request.map(axum::body::Body::new)).await?;
writer
    .write_response(
        response.map(|body| body.map_err(Into::into).boxed_unsync()),
        method,
        connection.qpack().clone(),
    )
    .await?;
```

Read operations return after headers. DATA, trailers, EOF and subsequent errors
are delivered through `BodyExt::frame` or `BodyExt::collect`:

```rust,ignore
use http_body_util::BodyExt;

let collected = response.into_body().collect().await?;
let trailers = collected.trailers();
let bytes = collected.to_bytes();
```

To produce trailers, use a `StreamBody` of `Frame::data` values followed by one
`Frame::trailers` and EOF. h3x preserves duplicate fields and sensitive flags.
Frames after trailers are rejected as a local source error. HEAD/204/304 response
sources are dropped without polling. Responses still take the request method.

### Buffering and ownership

Bounded windows remain inside h3x: received DATA uses an 8 KiB window and outgoing
Body frames feed a 64 KiB window. The receive task starts after headers. Writers
poll body production and encoding concurrently within the write future, without
spawning an extra producer task. A full window pauses its producer.

Window chunk transfers share `Bytes` payloads without copying them. Capacity
bounds queued bytes, not backing allocations or data retained by the application.
QUIC and Wasm memory copies are separate from these window transfers.
`ArcWndBuf`/`WndBuf` remain available as byte-buffer utilities; applications do
not need them to send or receive HTTP messages.

Dropping an incoming Body closes a local oneshot sender captured by its frame
stream. The background receive task waits on that receiver alongside its I/O and
stops reception with `H3_NO_ERROR` when the Body is abandoned, allowing an early
response to proceed. The channel carries only lifetime notification; all payload
bytes still use WndBuf. Window clones have no drop policy.

Read and write handles both cancel unfinished work in `Drop`, using their existing
terminal state. This also covers message futures that are never polled; there are
no per-handle cancellation flags or scope guards. Raw I/O users must finish the
needed direction explicitly: discarding an unfinished handle now means cancelling
it, not merely removing its registration. Source errors retain their original cause.
The application still owns the relationship between upload and response lifetimes.

Drive request writing concurrently with response reading so early response
headers do not wait for upload EOF. For example, spawn the write future and keep
its JoinHandle; finish or abort it as required by the application's exchange
lifecycle. Peer stop/reset is observed on subsequent transport I/O; the transport
interface has no independent stop subscription while a source remains Pending.

## Errors

`h3x::Result<T>` returns `h3x::Error`, which contains a protocol `code` and a
descriptive `reason`. Use `error.code` for protocol decisions and `error.reason`
for diagnostics. Its `Stream` and `Connection` variants specify whether handling
the error aborts one request or the entire HTTP/3 connection. Error construction
requires this scope to be selected explicitly. Outgoing Body failures retain their original error through `Error::source`;
protocol failures keep their descriptive `reason`. Streams retain raw I/O errors until a protocol
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
For CONNECT, drive `write_request` concurrently with response reception and use
a streaming Body whose data producer can wait for the successful response.
The caller controls acceptance, rejection and cancellation. Abort the send future
and drop the response Body when abandoning the exchange. Extended CONNECT assumes
peer support without waiting for peer SETTINGS.

The server branches on `request.method()` and sends a 2xx response to accept a
tunnel, passing `Method::CONNECT`. Both directions carry ordinary Body DATA frames.
An application can bridge AsyncRead/AsyncWrite with a streaming producer and
consumer at its own boundary. There is no separate Tunnel type.

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

Extended CONNECT stores `:protocol` as an `Arc<str>` in request extensions
(`http::Request::builder().extension(Arc::<str>::from("websocket"))`).
That extension type is reserved for `:protocol`; read it through
`request.extensions().get::<Arc<str>>()`.
For WebSocket CONNECT requests, outgoing `ws://` and `wss://` URIs are normalized
to the required `http://` and `https://` target schemes respectively.
