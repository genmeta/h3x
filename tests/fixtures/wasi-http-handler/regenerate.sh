#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd "$(dirname "$0")" && pwd)"

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "wasm-tools is required: cargo install wasm-tools" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown

build_handler() {
  package="$1"
  output="$2"
  artifact="${package//-/_}"

  cargo build \
    --manifest-path "$fixture_dir/Cargo.toml" \
    --package "$package" \
    --target wasm32-unknown-unknown \
    --target-dir "$fixture_dir/target" \
    --release
  wasm-tools component new \
    "$fixture_dir/target/wasm32-unknown-unknown/release/$artifact.wasm" \
    -o "$fixture_dir/../$output"
}

build_handler \
  wasi-http-read-request-then-respond \
  wasi-http-read-request-then-respond.wasm
build_handler \
  wasi-http-respond-then-read-request \
  wasi-http-respond-then-read-request.wasm
build_handler \
  wasi-http-stream-response-until-cancelled \
  wasi-http-stream-response-until-cancelled.wasm
