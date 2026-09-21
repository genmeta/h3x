# WASI HTTP handler fixture

`src/lib.rs` implements the `wasi:http/incoming-handler` exercised by
`tests/wasmtime_wasi_http.rs`. The generated component is committed as
`../wasi-http-handler.wasm`, so normal builds and CI do not need a WebAssembly
target or component tooling.

After changing the handler, install `wasm-tools` and run:

```sh
./tests/fixtures/wasi-http-handler/regenerate.sh
```

Commit the regenerated component together with the source change.
