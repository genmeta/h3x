#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd "$(dirname "$0")" && pwd)"

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "wasm-tools is required: cargo install wasm-tools" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown
cargo build \
  --manifest-path "$fixture_dir/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --target-dir "$fixture_dir/target" \
  --release
wasm-tools component new \
  "$fixture_dir/target/wasm32-unknown-unknown/release/wasi_http_handler.wasm" \
  -o "$fixture_dir/../wasi-http-handler.wasm"
