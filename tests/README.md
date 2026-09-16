# Test organization

- Put tests of public APIs and client/server round trips in this directory. These
  integration tests import `h3x` as an external consumer would.
- Keep small unit tests in a `#[cfg(test)] mod tests` beside the implementation.
- When tests make an implementation hard to read, extract them to the module's
  `tests.rs`. Split larger suites by behavior under its `tests/` directory, as in
  `src/client/tests/`, `src/server/tests/`, and `src/protocol/connection/tests/`.
- Keep shared fixtures in the suite's `tests.rs` and helpers used by just one
  behavior group in that group's file. A directory does not need several files
  to be useful; avoid extra nesting for a small test.
- Test shared protocol behavior in its owning module instead of duplicating it
  for each caller. Body trailer rules, for example, belong in `common::body`.
- Keep internal tests inside the crate when they need private state or test-only
  helpers. Do not widen the public API just to move a test into this directory.

Run the full suite with the same test concurrency as CI:

```sh
cargo test --workspace -- --test-threads=1
```

Filter by module to run one suite, for example:

```sh
cargo test client::tests -- --test-threads=1
```

## External WebSocket interoperability

The opt-in `external_ws_echo` test connects to an independent Python WebSocket
server over TCP. Its HTTP/3 leg uses the existing `MemoryTransport`; this verifies
H3 CONNECT/DATA and WebSocket byte forwarding, not QUIC or WSS/TLS interoperability.
The Upgrade adapter lives only in the test, and the relay never decodes messages.

Start the peer in one terminal:

```sh
python3 -m venv /tmp/h3x-ws-venv
/tmp/h3x-ws-venv/bin/python -m pip install websockets==17.1
/tmp/h3x-ws-venv/bin/python tests/connect/ws_echo.py
```

Run the test from the repository root in another terminal:

```sh
cargo test --test connect external_ws_echo -- --ignored --nocapture
```

Use `H3X_WS_PORT` for the server and `H3X_WS_ADDR=127.0.0.1:<port>` for the test to
change the port. Stop the echo server with Ctrl-C afterwards. The test is ignored
in the regular suite, requires the supplied greeting/subprotocol behavior, and has
a 30-second timeout. Python dependencies stay outside the repository; Rust WS
libraries are dev-dependencies only.

It checks Upgrade/Accept validation, subprotocol selection, an immediate server
greeting, UTF-8 text, binary, a 256 KiB message spanning multiple DATA frames,
masked fragmentation, Ping/Pong, Close, and both transport EOF directions.
Compression is disabled in this fixture.

### External client to the H3 server

The reverse test exposes an HTTP/1.1 WS ingress on loopback, translates its
handshake to H3 CONNECT, then forwards raw frame bytes to a WebSocket endpoint on
the h3x server tunnel. It waits for the H3 response before sending HTTP 101.
The H3 leg still uses `MemoryTransport`.

Start the Rust test first:

```sh
cargo test --test connect external_ws_incoming -- --ignored --nocapture
```

After `READY` appears, run the independent Python client in another terminal,
using the same virtual environment installed above:

```sh
/tmp/h3x-ws-venv/bin/python tests/connect/ws_client.py
```

Both commands must succeed. The test exits after the client's echo and rejection
connections, or fails after 90 seconds. `H3X_WS_LISTEN=127.0.0.1:<port>` overrides
the default port 8766 for both commands. It covers text, binary, 256 KiB messages,
masked fragmentation, subprotocol and Origin forwarding, Ping/Pong, Close/EOF,
and an H3 403 returned as HTTP 403 with its body instead of an early HTTP 101.
