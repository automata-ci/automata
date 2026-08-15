#!/usr/bin/env bash
set -euo pipefail

readonly expected_profile_id="automata.dev/github-hosted-ubuntu-24-04-x64-v1"
readonly expected_image_version="automata-ubuntu-24.04-x64-v1"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
profile_directory="${repository_root}/images/github-hosted-ubuntu-24.04-x64"
readonly profile_directory

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(( $# == 0 )) || die "usage: $0"
for command in id python3 sha256sum; do
    command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done

mapfile -t profile_values < <(
    python3 - \
        "${profile_directory}/profile-manifest.json" \
        "${profile_directory}/profile-lock.json" \
        "${profile_directory}/Containerfile" \
        "${expected_profile_id}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

manifest_path, lock_path, containerfile_path, expected_profile_id = map(pathlib.Path, sys.argv[1:])
expected_profile_id = str(expected_profile_id)
manifest_bytes = manifest_path.read_bytes()
containerfile_bytes = containerfile_path.read_bytes()
manifest = json.loads(manifest_bytes)
lock = json.loads(lock_path.read_bytes())

def fail(message: str) -> None:
    raise SystemExit(f"renderer profile lock validation failed: {message}")

if manifest.get("schema_version") != 2 or lock.get("schema_version") != 2:
    fail("unsupported schema")
if manifest.get("profile_id") != expected_profile_id:
    fail("unexpected manifest profile ID")
if lock.get("profile_id") != expected_profile_id:
    fail("unexpected lock profile ID")
if lock.get("image") != manifest.get("image"):
    fail("manifest and lock image references differ")
image = manifest.get("image")
if not isinstance(image, str) or re.fullmatch(
    r"ghcr\.io/automata-ci/automata-ubuntu-24\.04-x64@sha256:[0-9a-f]{64}", image
) is None:
    fail("image is not the canonical immutable GHCR reference")
if lock.get("profile_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
    fail("manifest digest is stale")
if lock.get("containerfile_sha256") != hashlib.sha256(containerfile_bytes).hexdigest():
    fail("Containerfile digest is stale")

toolchain = manifest.get("toolchain", {})
expected_tools = {
    "node_action_runtime": "24.19.0",
    "wasm_rquickjs_cli": "0.4.1",
    "cargo_cyclonedx": "0.5.9",
    "cargo_deny": "0.20.2",
}
if any(toolchain.get(key) != value for key, value in expected_tools.items()):
    fail("renderer tool identities are stale")
print(image)
PY
)
[[ "${#profile_values[@]}" -eq 1 ]] || die "could not read the exact renderer profile image"
readonly profile_image="${profile_values[0]}"

run_reproduction() {
    [[ "${AUTOMATA_ENVIRONMENT_PROFILE_ID:-}" == "${expected_profile_id}" ]] || \
        die "renderer reproduction entered an unexpected environment profile"
    [[ "${ImageVersion:-}" == "${expected_image_version}" ]] || \
        die "renderer reproduction entered an unexpected image version"
    [[ "$(cargo deny --version)" == "cargo-deny 0.20.2" ]] || \
        die "renderer profile does not contain cargo-deny 0.20.2"

    "${script_directory}/regenerate-renderer.sh"
    for test_script in "${repository_root}"/scripts/ui/tests/*.test.sh; do
        "${test_script}"
    done
    cargo deny \
        --manifest-path "${repository_root}/target/ui-renderer-wrapper/source/Cargo.toml" \
        --locked \
        --config "${repository_root}/deny.toml" \
        check advisories bans licenses sources
}

if [[ "${AUTOMATA_ENVIRONMENT_PROFILE_ID:-}" == "${expected_profile_id}" && \
    "${ImageVersion:-}" == "${expected_image_version}" ]]; then
    run_reproduction
    exit 0
fi

case "${repository_root}" in
    *:* | *,* | *$'\n'*) die "repository path cannot be represented as a container bind mount" ;;
esac

runtime=''
if [[ "${GITHUB_ACTIONS:-}" == true ]] && command -v docker >/dev/null 2>&1; then
    runtime=docker
elif command -v podman >/dev/null 2>&1; then
    runtime=podman
elif command -v docker >/dev/null 2>&1; then
    runtime=docker
else
    die "docker or podman is required outside the attested renderer profile"
fi
readonly runtime

if ! "${runtime}" image inspect "${profile_image}" >/dev/null 2>&1; then
    if ! "${runtime}" pull "${profile_image}"; then
        die "locked renderer profile ${profile_image} is unavailable; publish that exact digest before hosted CI can reproduce the renderer"
    fi
fi
"${runtime}" image inspect "${profile_image}" >/dev/null 2>&1 || \
    die "container runtime did not resolve the locked renderer profile"

readonly container_workspace="/__w/automata/automata"
ownership_environment=()
if [[ "${runtime}" == docker ]]; then
    docker_security_options="$(docker info --format '{{json .SecurityOptions}}')" || \
        die "could not determine whether the Docker daemon is rootless"
    readonly docker_security_options
    if [[ "${docker_security_options}" != *rootless* ]]; then
        ownership_environment=(
            --env "AUTOMATA_RENDERER_HOST_UID=$(id -u)"
            --env "AUTOMATA_RENDERER_HOST_GID=$(id -g)"
        )
    fi
fi
readonly -a ownership_environment
# The single-quoted program is evaluated by the profile's Bash, where the two
# optional AUTOMATA_RENDERER_HOST_* variables are available only for a
# rootful Docker daemon. Container root already maps to the invoking user for
# rootless Podman/Docker, so chowning to the host numeric UID there would map
# files into the subordinate-ID range.
# shellcheck disable=SC2016
"${runtime}" run --rm \
    --mount "type=bind,source=${repository_root},target=${container_workspace}" \
    --workdir "${container_workspace}" \
    "${ownership_environment[@]}" \
    "${profile_image}" \
    /usr/bin/bash -euo pipefail -c '
        cleanup() {
            if [[ -z "${AUTOMATA_RENDERER_HOST_UID:-}" || \
                -z "${AUTOMATA_RENDERER_HOST_GID:-}" ]]; then
                return
            fi
            for path in \
                target/agent-scratch/ssr \
                target/ui-renderer-wrapper \
                ui/node_modules \
                ui/dist \
                ui/renderer \
                crates/automata-ci-ui-renderer/assets \
                crates/automata-ci-ui-renderer/src/generated_assets.rs \
                crates/automata-ci-ui-renderer/src/generated_contract.rs; do
                if [[ -e "${path}" || -L "${path}" ]]; then
                    chown --recursive --no-dereference \
                        "${AUTOMATA_RENDERER_HOST_UID}:${AUTOMATA_RENDERER_HOST_GID}" \
                        -- "${path}"
                fi
            done
        }
        trap cleanup EXIT
        scripts/ui/reproduce-renderer-in-profile.sh
    '
