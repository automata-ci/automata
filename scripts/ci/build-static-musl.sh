#!/usr/bin/env bash
set -euo pipefail

readonly target="x86_64-unknown-linux-musl"
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
readonly repo_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_dir}/lib/target-paths.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ -f "$repo_root/Cargo.toml" ]] || die "Cargo.toml is missing from $repo_root"
[[ -f "$repo_root/Cargo.lock" ]] || die "Cargo.lock is required because distribution builds use --locked"
command -v cargo >/dev/null 2>&1 || die "cargo is not available on PATH"
automata_init_target_root "${repo_root}"
automata_set_target_tmpdir \
  "${repo_root}" \
  "${repo_root}/target/task-tmp/static-build"
target_directory="${CARGO_TARGET_DIR:-target}"
if [[ "${target_directory}" != /* ]]; then
  target_directory="${repo_root}/${target_directory}"
fi
target_directory="$(
  automata_canonical_target_path "${target_directory}" "Cargo target directory"
)"
install -d -m 0755 -- "${target_directory}"
export CARGO_TARGET_DIR="${target_directory}"

build_git_sha="${AUTOMATA_BUILD_GIT_SHA:-}"
if [[ -z "$build_git_sha" ]]; then
  command -v git >/dev/null 2>&1 || die "git is required to resolve build provenance"
  build_git_sha="$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
    || die "distribution builds require a committed Git HEAD or AUTOMATA_BUILD_GIT_SHA"
fi
if [[ ! "$build_git_sha" =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$ ]]; then
  die "AUTOMATA_BUILD_GIT_SHA must be a complete 40- or 64-character Git object ID"
fi
export AUTOMATA_BUILD_GIT_SHA="${build_git_sha,,}"
export AUTOMATA_RELEASE_BUILD="${AUTOMATA_RELEASE_BUILD:-1}"

cd "$repo_root"

# Explicit --bin arguments are an invariant: the public distribution still has
# exactly two executables, irrespective of future workspace members.
cargo build \
  --locked \
  --release \
  --target "$target" \
  --bin automata \
  --bin automata-runner

# This non-publishable binary exists only as input to its scratch helper image.
# It is deliberately outside the public distribution archive above.
cargo build \
  --locked \
  --release \
  --target "$target" \
  --package automata-ci-service-proxy \
  --bin automata-ci-service-proxy
