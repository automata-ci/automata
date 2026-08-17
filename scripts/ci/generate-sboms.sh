#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly target="x86_64-unknown-linux-musl"
readonly expected_cyclonedx_version="cargo-cyclonedx-cyclonedx 0.5.9"
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

(( $# <= 1 )) || die "usage: $0 [OUTPUT_DIRECTORY]"
automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/sbom-generation"
output_directory="${1:-${repository_root}/target/distribution-input/sbom}"
if [[ "${output_directory}" != /* ]]; then
    output_directory="${repository_root}/${output_directory}"
fi
output_directory="$(
    automata_canonical_target_child "${output_directory}" "SBOM output"
)"
readonly output_directory

[[ "$(cargo cyclonedx --version)" == "${expected_cyclonedx_version}" ]] || \
    die "cargo-cyclonedx 0.5.9 is required"
[[ "$(node --version)" == "${expected_node_version}" ]] || \
    die "Node.js 24.19.0 is required"
[[ "$(npm --version)" == "${expected_npm_version}" ]] || \
    die "npm 11.17.0 is required"
embedded_runtime_input="${repository_root}/ui/embedded-runtime"
readonly embedded_runtime_input
node "${script_directory}/verify-embedded-ui-runtime.mjs"

source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -z "${source_date_epoch}" ]]; then
    source_date_epoch="$(git -C "${repository_root}" show -s --format=%ct HEAD 2>/dev/null)" || \
        die "SOURCE_DATE_EPOCH or a committed Git HEAD is required"
fi
[[ "${source_date_epoch}" =~ ^[0-9]+$ ]] || \
    die "SOURCE_DATE_EPOCH must be Unix seconds"
readonly source_date_epoch

target_directory="${CARGO_TARGET_DIR:-target}"
if [[ "${target_directory}" != /* ]]; then
    target_directory="${repository_root}/${target_directory}"
fi
target_directory="$(
    automata_canonical_target_path "${target_directory}" "Cargo target directory"
)"
automata_binary="${target_directory}/${target}/release/automata"
runner_binary="${target_directory}/${target}/release/automata-runner"
service_proxy_binary="${target_directory}/${target}/release/automata-ci-service-proxy"
sandbox_guest_binary="${target_directory}/${target}/release/automata-ci-sandbox-guest"
readonly \
    target_directory \
    automata_binary \
    runner_binary \
    service_proxy_binary \
    sandbox_guest_binary
[[ -x "${automata_binary}" ]] || die "missing executable ${automata_binary}"
[[ -x "${runner_binary}" ]] || die "missing executable ${runner_binary}"
[[ -x "${service_proxy_binary}" ]] || \
    die "missing executable ${service_proxy_binary}"
[[ -x "${sandbox_guest_binary}" ]] || \
    die "missing executable ${sandbox_guest_binary}"

automata_raw="${repository_root}/crates/automata-ci/automata_bin.cdx.json"
runner_raw="${repository_root}/crates/automata-ci-runner/automata-runner_bin.cdx.json"
service_proxy_raw="${repository_root}/crates/automata-ci-service-proxy/automata-ci-service-proxy_bin.cdx.json"
sandbox_guest_raw="${repository_root}/crates/automata-ci-sandbox-guest/automata-ci-sandbox-guest_bin.cdx.json"
readonly automata_raw runner_raw service_proxy_raw sandbox_guest_raw
[[ ! -e "${automata_raw}" ]] || die "refusing to overwrite ${automata_raw}"
[[ ! -e "${runner_raw}" ]] || die "refusing to overwrite ${runner_raw}"
[[ ! -e "${service_proxy_raw}" ]] || die "refusing to overwrite ${service_proxy_raw}"
[[ ! -e "${sandbox_guest_raw}" ]] || die "refusing to overwrite ${sandbox_guest_raw}"

scratch_root="$(
    automata_canonical_target_child \
        "${repository_root}/target/sbom-generation" \
        "SBOM scratch directory"
)"
mkdir -p -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/release.XXXXXXXX")"
readonly scratch_directory
cleanup() {
    rm -f -- \
        "${automata_raw}" \
        "${runner_raw}" \
        "${service_proxy_raw}" \
        "${sandbox_guest_raw}"
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

generate_rust_sbom() {
    local package="$1"
    local manifest="$2"
    local raw_path="$3"
    local binary_path="$4"
    local output_name="$5"

    SOURCE_DATE_EPOCH="${source_date_epoch}" cargo cyclonedx \
        --manifest-path "${manifest}" \
        --format json \
        --describe binaries \
        --target "${target}" \
        --all-features \
        --no-build-deps \
        --license-strict \
        --spec-version 1.5
    [[ -f "${raw_path}" ]] || die "cargo-cyclonedx did not produce ${raw_path}"
    mv -- "${raw_path}" "${scratch_directory}/${package}.raw.cdx.json"
    local binary_sha256
    binary_sha256="$(sha256sum "${binary_path}" | awk '{print $1}')"
    node "${script_directory}/normalize-cyclonedx.mjs" \
        "${scratch_directory}/${package}.raw.cdx.json" \
        "${scratch_directory}/${output_name}" \
        "${repository_root}" \
        "${source_date_epoch}" \
        "${binary_sha256}"
}

generate_rust_sbom \
    automata \
    "${repository_root}/crates/automata-ci/Cargo.toml" \
    "${automata_raw}" \
    "${automata_binary}" \
    automata.cdx.json
generate_rust_sbom \
    automata-runner \
    "${repository_root}/crates/automata-ci-runner/Cargo.toml" \
    "${runner_raw}" \
    "${runner_binary}" \
    automata-runner.cdx.json
generate_rust_sbom \
    automata-ci-service-proxy \
    "${repository_root}/crates/automata-ci-service-proxy/Cargo.toml" \
    "${service_proxy_raw}" \
    "${service_proxy_binary}" \
    automata-ci-service-proxy.cdx.json
generate_rust_sbom \
    automata-ci-sandbox-guest \
    "${repository_root}/crates/automata-ci-sandbox-guest/Cargo.toml" \
    "${sandbox_guest_raw}" \
    "${sandbox_guest_binary}" \
    automata-ci-sandbox-guest.cdx.json

npm --prefix "${embedded_runtime_input}" sbom \
    --omit=dev \
    --offline \
    --package-lock-only \
    --sbom-format cyclonedx \
    --sbom-type application \
    > "${scratch_directory}/ui-runtime.raw.cdx.json"
node "${script_directory}/normalize-cyclonedx.mjs" \
    "${scratch_directory}/ui-runtime.raw.cdx.json" \
    "${scratch_directory}/ui-runtime.cdx.json" \
    "${repository_root}" \
    "${source_date_epoch}"

renderer_sbom="${repository_root}/ui/renderer/renderer.cdx.json"
[[ -f "${renderer_sbom}" ]] || die "missing embedded renderer SBOM"
mapfile -t renderer_components < <(
    find "${repository_root}/crates/automata-ci-ui-renderer/assets" -maxdepth 1 -type f \
        -name 'renderer-*.wasm' -print | LC_ALL=C sort
)
[[ "${#renderer_components[@]}" -eq 1 ]] || \
    die "expected exactly one embedded renderer component"
renderer_sha256="$(sha256sum "${renderer_components[0]}" | awk '{print $1}')"
node "${script_directory}/normalize-cyclonedx.mjs" \
    "${renderer_sbom}" \
    "${scratch_directory}/renderer.cdx.json" \
    "${repository_root}" \
    0 \
    "${renderer_sha256}"
cmp --silent "${renderer_sbom}" "${scratch_directory}/renderer.cdx.json" || \
    die "embedded renderer SBOM is stale or noncanonical"

mkdir -p -- "${output_directory}"
for name in \
    automata.cdx.json \
    automata-runner.cdx.json \
    automata-ci-sandbox-guest.cdx.json \
    automata-ci-service-proxy.cdx.json \
    renderer.cdx.json \
    ui-runtime.cdx.json
do
    install -m 0444 -- "${scratch_directory}/${name}" "${output_directory}/${name}"
done
printf 'Created six CycloneDX SBOMs in %s\n' "${output_directory}"
