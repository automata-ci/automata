#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_cyclonedx_version="cargo-cyclonedx-cyclonedx 0.5.9"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"
automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/renderer-sbom"
nominal_wrapper_directory="${repository_root}/target/ui-renderer-wrapper/source"
wrapper_directory="$(
    automata_canonical_exact_target_child \
        "${nominal_wrapper_directory}" \
        "renderer wrapper source directory"
)"
raw_sbom="${wrapper_directory}/renderer_cdylib.cdx.json"
output_path="${1:-${repository_root}/ui/renderer/renderer.cdx.json}"
readonly wrapper_directory raw_sbom output_path

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(( $# <= 1 )) || die "usage: $0 [OUTPUT_PATH]"
[[ -f "${wrapper_directory}/Cargo.toml" ]] || \
    die "renderer wrapper source is missing; run regenerate-renderer.sh first"
[[ ! -e "${raw_sbom}" ]] || die "refusing to overwrite ${raw_sbom}"
[[ "$(cargo cyclonedx --version)" == "${expected_cyclonedx_version}" ]] || \
    die "cargo-cyclonedx 0.5.9 is required"

mapfile -t components < <(
    find "${repository_root}/ui/renderer/assets" -maxdepth 1 -type f \
        -name 'renderer-*.wasm' -print | LC_ALL=C sort
)
[[ "${#components[@]}" -eq 1 ]] || die "expected exactly one renderer component"
component_sha256="$(sha256sum "${components[0]}" | awk '{print $1}')"
readonly component_sha256

scratch_root="$(
    automata_canonical_target_child \
        "${repository_root}/target/sbom-generation" \
        "renderer SBOM scratch directory"
)"
mkdir -p -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/renderer.XXXXXXXX")"
readonly scratch_directory
cleanup() {
    rm -f -- "${raw_sbom}"
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

SOURCE_DATE_EPOCH=0 cargo cyclonedx \
    --manifest-path "${wrapper_directory}/Cargo.toml" \
    --format json \
    --describe binaries \
    --target wasm32-wasip2 \
    --no-default-features \
    --features p2,encoding \
    --no-build-deps \
    --license-strict \
    --spec-version 1.5
[[ -f "${raw_sbom}" ]] || die "cargo-cyclonedx did not produce ${raw_sbom}"
mv -- "${raw_sbom}" "${scratch_directory}/raw.cdx.json"

node "${repository_root}/scripts/ci/normalize-cyclonedx.mjs" \
    "${scratch_directory}/raw.cdx.json" \
    "${scratch_directory}/renderer.cdx.json" \
    "${repository_root}" \
    0 \
    "${component_sha256}"
mkdir -p -- "$(dirname -- "${output_path}")"
install -m 0644 -- "${scratch_directory}/renderer.cdx.json" "${output_path}"
printf 'Created %s\n' "${output_path}"
