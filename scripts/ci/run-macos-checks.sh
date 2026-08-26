#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo "macOS checks require an Apple Silicon macOS host" >&2
  exit 1
fi

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
TMPDIR="$repository_root/target/macos-tmp"
export TMPDIR
install -d -m 0700 -- "$TMPDIR"

if [ "$(node --version)" != v24.19.0 ]; then
  echo "macOS checks require Node.js 24.19.0" >&2
  exit 1
fi

"$repository_root/scripts/ui/reproduce-renderer-in-profile.sh"
cargo fmt --all -- --check
cargo clippy \
  --locked \
  --workspace \
  --exclude automata-ci-service-proxy \
  --all-targets \
  --all-features \
  -- \
  -D warnings
cargo test \
  --locked \
  --workspace \
  --exclude automata-ci-service-proxy \
  --all-targets \
  --all-features \
  --no-fail-fast
cargo test \
  --locked \
  --workspace \
  --exclude automata-ci-service-proxy \
  --doc \
  --all-features
RUSTDOCFLAGS='-D warnings' cargo doc \
  --locked \
  --workspace \
  --exclude automata-ci-service-proxy \
  --all-features \
  --no-deps
swift build \
  -c release \
  --package-path crates/automata-ci-sandbox-macos/swift
