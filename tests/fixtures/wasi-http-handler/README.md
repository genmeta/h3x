# WASI HTTP handler fixtures

Each directory under `handlers/` exports a `wasi:http/incoming-handler`.
The inbound test server loads three components and uses Axum to route
`POST` requests by path:

- `/read-request-then-respond` consumes the complete request before committing
  the response.
- `/respond-then-read-request` commits the response headers, consumes the
  complete request, and only then writes the response body.
- `/stream-response-until-cancelled` writes a response until the host cancels
  its body.

`outgoing-client` is a separate client fixture used by
`tests/wasmtime_wasi_http_outgoing.rs`. Its incoming handler is only the test
entry point: the component itself creates a WASI HTTP `OutgoingRequest`, calls
`wasi:http/outgoing-handler.handle`, writes the request body, and reads the
returned response body and trailers. A test-only `WasiHttpHooks::send_request`
implementation bridges the standard host request to `h3x::Request<W>`:

```text
WASM OutgoingRequest -> Wasmtime http::Request<HyperOutgoingBody>
  -> h3x Request<W> / ArcWndBuf -> HTTP/3 HEADERS and DATA
  -> h3x test peer -> Response<R> -> WASI IncomingResponse -> WASM
```

The tests exercise real WASM components and h3x framing/QPACK over the existing
in-memory transport, not a network QUIC/TLS handshake. The client sends two
requests on the same connection in every scenario: the selected case followed
by a healthy request, including after cancellation.

- 42 combinations: seven request modes (no body resource, explicit empty,
  small, streaming, streaming with Content-Length, streaming with trailers,
  trailers only) crossed with six response modes (empty, small, streaming,
  streaming with Content-Length, streaming with trailers, trailers only).
- HEAD with a nonzero Content-Length and no response body, and a 204 response
  after a streaming upload.
- Response headers received before any upload data, and a duplex exchange
  that alternates request and response chunks before upload EOF.
- An unfinished upload body dropped by WASM, a peer stopping the upload,
  WASM dropping a partially read response, and a peer resetting the response.
- 14 graceful upload-stop cases: the peer uses `H3_NO_ERROR` before or after
  response headers, crossed with empty, small, streaming, Content-Length,
  trailers, trailers-only, and 204 responses. WASM observes its upload writer
  closing, drops the unfinished outgoing body, and still reads the complete
  response and trailers. Both host upload tasks must retain `NoError`, and a
  healthy follow-up request must succeed on the same connection.

Streaming payloads are 160 KiB, larger than the transport buffer, and the host
body bridge uses a 257-byte window. Duplicate headers and duplicate trailers
are checked at their destinations. Whole-request cancellation uses
`RequestCancelled`, which cancels both directions of the exchange in h3x;
graceful upload termination uses `NoError` and preserves the response.
Neither should poison the connection. Early-response synchronization ensures that
reset cases exercise body errors after headers, without relying on sleeps.

Run the outgoing tests with:

```sh
cargo test --test wasmtime_wasi_http_outgoing
```

Each handler is built into its own component in the parent directory. The
generated components are committed so normal builds and CI do not need a
WebAssembly target or component tooling.

After changing the handler, install `wasm-tools` and run:

```sh
./tests/fixtures/wasi-http-handler/regenerate.sh
```

Commit the regenerated component together with the source change.
