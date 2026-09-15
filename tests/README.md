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
