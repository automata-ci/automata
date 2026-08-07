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

copied_macro="${scratch_directory}/rquickjs-macro"
mkdir -p -- "${copied_macro}"
cp -a -- "${canonical_macro}/." "${copied_macro}/"
# The reviewed package is a path dependency of the generated wrapper and is
# intentionally not a member of Automata's root workspace. Make only this
# scratch copy an isolated workspace so Cargo can run its integration test.
printf '\n[workspace]\n' >> "${copied_macro}/Cargo.toml"
mkdir -p -- "${scratch_directory}/tmp" "${scratch_directory}/target"
export CARGO_TARGET_DIR="${scratch_directory}/target"
export CARGO_TERM_COLOR=never
export TMPDIR="${scratch_directory}/tmp"

cargo test \
    --offline \
    --manifest-path "${copied_macro}/Cargo.toml" \
    --tests

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
    case_directory="${scratch_directory}/${fixture}"
    mkdir -p -- "${case_directory}/src"
    install -m 0644 -- "${fixture_directory}/${fixture}.rs" "${case_directory}/src/main.rs"
    printf '%s\n' \
        '[package]' \
        "name = \"rquickjs-macro-${fixture}\"" \
        'version = "0.0.0"' \
        'edition = "2021"' \
        'publish = false' \
        '' \
        '[workspace]' \
        '' \
        '[dependencies]' \
        "rquickjs-macro = { path = \"${copied_macro}\" }" \
        > "${case_directory}/Cargo.toml"

    log="${scratch_directory}/${fixture}.log"
    if cargo check --offline --manifest-path "${case_directory}/Cargo.toml" \
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
