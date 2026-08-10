#!/usr/bin/env bash
set -euo pipefail

mode="${1:-verify}"
if (( $# > 1 )); then
    echo "usage: $0 [verify|regenerate|audit]" >&2
    exit 2
fi
case "${mode}" in
    verify | regenerate | audit) ;;
    *)
        echo "usage: $0 [verify|regenerate|audit]" >&2
        exit 2
        ;;
esac

tool_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly tool_directory
crate_root="$(CDPATH='' cd -- "${tool_directory}/.." && pwd -P)"
readonly crate_root
repository_root="$(CDPATH='' cd -- "${crate_root}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"

automata_init_target_root "${repository_root}"
nominal_scratch_parent="${AUTOMATA_PROTOBUF_CODEGEN_SCRATCH_DIR:-${repository_root}/target/agent-scratch}"
if [[ "${nominal_scratch_parent}" != /* ]]; then
    nominal_scratch_parent="${repository_root}/${nominal_scratch_parent}"
fi
scratch_parent="$(
    automata_canonical_exact_target_child \
        "${nominal_scratch_parent}" \
        "protobuf codegen scratch parent"
)"
install -d -m 0700 -- "${scratch_parent}"
revalidated_scratch_parent="$(
    automata_canonical_exact_target_child \
        "${scratch_parent}" \
        "protobuf codegen scratch parent"
)"
[[ "${revalidated_scratch_parent}" == "${scratch_parent}" ]] || {
    echo "protobuf codegen scratch parent changed during initialization" >&2
    exit 1
}
readonly scratch_parent

scratch=''
cleanup() {
    local cleanup_path

    [[ -n "${scratch}" ]] || return 0
    cleanup_path="$(
        automata_canonical_exact_target_child \
            "${scratch}" \
            "protobuf codegen cleanup path"
    )" || {
        echo "refusing to clean an uncontained protobuf codegen path" >&2
        return 0
    }
    if [[ ! -d "${cleanup_path}" || -L "${cleanup_path}" \
        || "${cleanup_path}" != "${scratch}" \
        || "${cleanup_path}" != "${scratch_parent}"/automata-ci-protocol-protobuf-codegen.* ]]; then
        echo "refusing to clean an unexpected protobuf codegen path" >&2
        return 0
    fi
    rm -rf -- "${cleanup_path}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

umask 077
scratch="$(mktemp -d "${scratch_parent}/automata-ci-protocol-protobuf-codegen.XXXXXXXX")"
scratch="$(
    automata_canonical_exact_target_child \
        "${scratch}" \
        "protobuf codegen scratch directory"
)"
[[ "${scratch}" == "${scratch_parent}"/automata-ci-protocol-protobuf-codegen.* ]] || {
    echo "mktemp returned an unexpected protobuf codegen path" >&2
    exit 1
}

install -d -m 0700 -- \
    "${scratch}/src" \
    "${scratch}/generated" \
    "${scratch}/cargo-target" \
    "${scratch}/temp"
cp -- "${tool_directory}/codegen.Cargo.toml" "${scratch}/Cargo.toml"
cp -- "${tool_directory}/codegen.Cargo.lock" "${scratch}/Cargo.lock"
cp -- "${tool_directory}/codegen.rs" "${scratch}/src/main.rs"

readonly schema="${crate_root}/proto/automata/runner/v1/runner.proto"
readonly checked_in="${crate_root}/src/generated/automata.runner.v1.rs"
readonly candidate="${scratch}/generated/automata.runner.v1.rs"
readonly cargo_command="${CARGO:-cargo}"

TMPDIR="${scratch}/temp" CARGO_TARGET_DIR="${scratch}/cargo-target" \
    "${cargo_command}" run --quiet --locked --manifest-path "${scratch}/Cargo.toml" -- \
    "${schema}" "${crate_root}/proto" "${scratch}/generated"

verify_candidate() {
    if ! cmp -s -- "${checked_in}" "${candidate}"; then
        echo "checked-in prost DTOs are stale; regeneration diff follows:" >&2
        diff -u -- "${checked_in}" "${candidate}" >&2 || true
        exit 1
    fi
    echo "protobuf DTO verification passed"
}

case "${mode}" in
    verify | audit)
        verify_candidate
        ;;
    regenerate)
        cp -- "${candidate}" "${checked_in}"
        echo "regenerated ${checked_in}"
        echo "review the diff and update proto/automata/runner/v1/PROVENANCE.sha256"
        sha256sum "${schema}" "${checked_in}"
        ;;
esac

if [[ "${mode}" == audit ]]; then
    TMPDIR="${scratch}/temp" CARGO_TARGET_DIR="${scratch}/cargo-target" \
        "${cargo_command}" deny --manifest-path "${scratch}/Cargo.toml" \
        --config "${repository_root}/deny.toml" --locked check
fi
