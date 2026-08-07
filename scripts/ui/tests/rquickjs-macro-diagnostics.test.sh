#!/usr/bin/env bash
set -euo pipefail

test_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${test_directory}/../../.." && pwd -P)"
canonical_macro="${repository_root}/ui/renderer/vendor/rquickjs-macro-0.10.0"
fixture_directory="${test_directory}/fixtures/rquickjs-macro-diagnostics"
scratch_root="${repository_root}/target/task-tmp/rquickjs-macro-diagnostics"
mkdir -p -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
cleanup() {
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

workspace="${scratch_directory}/workspace"
copied_macro="${workspace}/rquickjs-macro"
case_directory="${workspace}/diagnostic-case"
mkdir -p -- "${copied_macro}" "${case_directory}/src"
cp -a -- "${canonical_macro}/." "${copied_macro}/"
install -m 0644 -- "${fixture_directory}/workspace.Cargo.toml" "${workspace}/Cargo.toml"
install -m 0644 -- "${fixture_directory}/workspace.Cargo.lock" "${workspace}/Cargo.lock"
install -m 0644 -- \
    "${fixture_directory}/diagnostic-case.Cargo.toml" \
    "${case_directory}/Cargo.toml"
install -m 0644 -- "${fixture_directory}/array.rs" "${case_directory}/src/main.rs"
mkdir -p -- \
    "${scratch_directory}/cargo-home" \
    "${scratch_directory}/tmp" \
    "${scratch_directory}/target"
export CARGO_HOME="${scratch_directory}/cargo-home"
export CARGO_TARGET_DIR="${scratch_directory}/target"
export CARGO_TERM_COLOR=never
export TMPDIR="${scratch_directory}/tmp"

# Hydrate one empty, private Cargo home from the committed lock. Every compile
# below is then both locked and offline, so ambient developer caches cannot
# mask a missing dependency and macro diagnostics never contact the network.
cargo fetch \
    --locked \
    --manifest-path "${workspace}/Cargo.toml"
cargo test \
    --offline \
    --locked \
    --manifest-path "${workspace}/Cargo.toml" \
    --package rquickjs-macro \
    --tests
cargo deny \
    --manifest-path "${workspace}/Cargo.toml" \
    --locked \
    --config "${repository_root}/deny.toml" \
    check advisories bans licenses sources

readonly expected_diagnostic='unsupported #[methods] self type; expected a path, parenthesized type, or tuple of supported types'

for fixture in array reference tuple-array; do
    case "${fixture}" in
        array)
            expected_location='src/main.rs:4:6'
            ;;
        reference)
            expected_location='src/main.rs:6:6'
            ;;
        tuple-array)
            expected_location='src/main.rs:6:15'
            ;;
    esac
    install -m 0644 -- "${fixture_directory}/${fixture}.rs" "${case_directory}/src/main.rs"

    log="${scratch_directory}/${fixture}.log"
    if cargo check \
        --offline \
        --locked \
        --manifest-path "${workspace}/Cargo.toml" \
        --package rquickjs-macro-diagnostic-case \
        >"${log}" 2>&1; then
        echo "unsupported ${fixture} self type unexpectedly compiled" >&2
        exit 1
    fi
    grep -Fq -- "error: ${expected_diagnostic}" "${log}" || {
        echo "unsupported ${fixture} self type did not produce the contract diagnostic" >&2
        sed -n '1,160p' "${log}" >&2
        exit 1
    }
    grep -Fq -- "${expected_location}" "${log}" || {
        echo "unsupported ${fixture} diagnostic was not bound to the self-type span" >&2
        sed -n '1,160p' "${log}" >&2
        exit 1
    }
    if grep -Eq -- 'procedural macro panicked|not yet implemented|panicked at' "${log}"; then
        echo "unsupported ${fixture} self type panicked inside the procedural macro" >&2
        exit 1
    fi
done

echo "rquickjs #[methods] self-type diagnostics verified without procedural-macro panics"
