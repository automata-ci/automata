#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_node_version="v24.19.0"
readonly expected_npm_version="11.17.0"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/third-party-license-prepare"
[[ "$(node --version)" == "${expected_node_version}" ]] || \
    die "Node.js 24.19.0 is required"
[[ "$(npm --version)" == "${expected_npm_version}" ]] || \
    die "npm 11.17.0 is required"
renderer_input="$(
    automata_canonical_exact_target_child \
        "${repository_root}/target/third-party-license-input/renderer" \
        "renderer license input"
)"
readonly renderer_input
install -d -m 0755 -- "${renderer_input}/src"
install -m 0644 -- \
    "${repository_root}/ui/renderer/wrapper.Cargo.toml" \
    "${renderer_input}/Cargo.toml"
install -m 0644 -- \
    "${repository_root}/ui/renderer/wrapper.Cargo.lock" \
    "${renderer_input}/Cargo.lock"
install -m 0644 -- "${repository_root}/LICENSE" "${renderer_input}/LICENSE-MIT"
install -m 0644 -- /dev/null "${renderer_input}/src/lib.rs"

# Both fetches are integrity-pinned by checked-in lockfiles. The subsequent
# notice generator itself is offline and fails if either source set is absent.
cargo fetch \
    --manifest-path "${renderer_input}/Cargo.toml" \
    --locked \
    --target wasm32-wasip2
npm --prefix "${repository_root}/ui" ci \
    --omit=dev \
    --ignore-scripts

printf 'Prepared locked Cargo and npm license sources\n'
