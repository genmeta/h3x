# WASI HTTP handler fixtures

Each directory under `handlers/` implements one `wasi:http/incoming-handler`
behavior. The test server loads all three components and uses Axum to route
`POST` requests by path:

- `/read-request-then-respond` consumes the complete request before committing
  the response.
- `/respond-then-read-request` commits the response headers, consumes the
  complete request, and only then writes the response body.
- `/stream-response-until-cancelled` writes a response until the host cancels
  its body.

Each handler is built into its own component in the parent directory. The
generated components are committed so normal builds and CI do not need a
WebAssembly target or component tooling.

After changing the handler, install `wasm-tools` and run:

```sh
./tests/fixtures/wasi-http-handler/regenerate.sh
```

Commit the regenerated component together with the source change.
