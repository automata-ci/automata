#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo "macOS checks require an Apple Silicon macOS host" >&2
  exit 1
fi

cargo fmt --all -- --check
cargo clippy \
  --locked \
  --workspace \
  --exclude automata-ci-service-proxy \
  --lib \
  --bins \
  --all-features \
  -- \
  -D warnings
cargo test \
  --locked \
  --all-features \
  --no-fail-fast \
  -p automata-ci \
  -p automata-ci-runner \
  -p automata-ci-sandbox-macos
swift build \
  -c release \
  --package-path crates/automata-ci-sandbox-macos/swift
