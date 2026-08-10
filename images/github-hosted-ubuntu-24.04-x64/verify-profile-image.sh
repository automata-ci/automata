#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(( $# == 1 || $# == 3 )) || \
    die "usage: $0 <local-image-reference> [<profile-manifest> <source-commit>]"
readonly image_reference="$1"
manifest_path="${script_directory}/profile-manifest.json"
expected_revision=""
if (( $# == 3 )); then
    manifest_path="$2"
    expected_revision="$3"
fi
readonly manifest_path expected_revision

command -v podman >/dev/null 2>&1 || die "podman is required to verify the profile"
command -v python3 >/dev/null 2>&1 || die "python3 is required to verify the profile"
[[ -r "${manifest_path}" ]] || die "profile manifest is not readable: ${manifest_path}"

inspect_scratch="${repository_root}/target/task-tmp/profile-image-verify"
readonly inspect_scratch
install -d -m 0700 -- "${inspect_scratch}"
inspect_path="$(mktemp "${inspect_scratch}/inspect.XXXXXXXX.json")"
readonly inspect_path
trap 'rm -f -- "${inspect_path}"' EXIT
podman image inspect "${image_reference}" > "${inspect_path}"

mapfile -t profile_contract < <(
    python3 - "${manifest_path}" "${inspect_path}" "${expected_revision}" <<'PY'
import json
import pathlib
import re
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
inspected = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
expected_revision = sys.argv[3]

def fail(message: str) -> None:
    raise SystemExit(f"profile image contract failed: {message}")

if not isinstance(inspected, list) or len(inspected) != 1:
    fail("Podman did not return exactly one inspected image")
image = inspected[0]
config = image.get("Config") or {}
profile_id = manifest.get("profile_id")
platform = manifest.get("platform") or {}
execution = manifest.get("execution") or {}
toolchain = manifest.get("toolchain") or {}
wasi_sdk = toolchain.get("wasi_sdk") or {}
container_engine = manifest.get("job_container_engine") or {}
docker_client = container_engine.get("client")
if not isinstance(docker_client, str) or not docker_client.startswith("docker-cli-"):
    fail("profile manifest Docker client identity is invalid")

expected_architecture = {"x86_64": "amd64"}.get(platform.get("architecture"))
if image.get("Os") != platform.get("os"):
    fail("image operating system differs from the profile manifest")
if image.get("Architecture") != expected_architecture:
    fail("image architecture differs from the profile manifest")
if config.get("User") != "0:0":
    fail("image user is not the reviewed container-root identity")
if config.get("WorkingDir") != execution.get("workspace"):
    fail("image working directory differs from the profile manifest")
if config.get("Cmd") != execution.get("keepalive"):
    fail("image command differs from the profile manifest")

labels = config.get("Labels") or {}
required_labels = {
    "org.opencontainers.image.title": (
        "Automata GitHub-hosted Ubuntu 24.04 x64 compatibility profile"
    ),
    "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.licenses": "MIT",
    "io.automata.environment-profile": profile_id,
}
if expected_revision:
    if re.fullmatch(r"[0-9a-f]{40}", expected_revision) is None:
        fail("expected source revision is not a full commit SHA")
    required_labels["org.opencontainers.image.revision"] = expected_revision
    required_labels["org.opencontainers.image.version"] = profile_id
for key, expected in required_labels.items():
    if labels.get(key) != expected:
        fail(f"OCI label {key!r} differs from the reviewed contract")

environment = {}
for entry in config.get("Env") or []:
    key, separator, value = entry.partition("=")
    if separator:
        environment[key] = value
required_environment = {
    "AUTOMATA_ENVIRONMENT_PROFILE_ID": profile_id,
    "CARGO_HOME": toolchain.get("cargo_home"),
    "RUSTUP_HOME": toolchain.get("rustup_home"),
    "RUNNER_TOOL_CACHE": toolchain.get("runner_tool_cache"),
}
for key, expected in required_environment.items():
    if environment.get(key) != expected:
        fail(f"image environment {key!r} differs from the profile manifest")

runtime_values = [
    profile_id,
    toolchain.get("rust"),
    toolchain.get("node_action_runtime"),
    toolchain.get("wasm_rquickjs_cli"),
    toolchain.get("cargo_cyclonedx"),
    toolchain.get("cargo_deny"),
    toolchain.get("clang"),
    wasi_sdk.get("installation_root"),
    docker_client.removeprefix("docker-cli-"),
]
if not all(isinstance(value, str) and value for value in runtime_values):
    fail("profile manifest omits a required runtime identity")
print(*runtime_values, sep="\n")
PY
)
(( ${#profile_contract[@]} == 9 )) || die "profile manifest runtime contract is incomplete"

readonly expected_profile_id="${profile_contract[0]}"
readonly expected_rust="${profile_contract[1]}"
readonly expected_node="${profile_contract[2]}"
readonly expected_wasm_rquickjs="${profile_contract[3]}"
readonly expected_cargo_cyclonedx="${profile_contract[4]}"
readonly expected_cargo_deny="${profile_contract[5]}"
readonly expected_clang_package="${profile_contract[6]}"
readonly expected_wasi_root="${profile_contract[7]}"
readonly expected_docker_cli="${profile_contract[8]}"

podman run --rm \
    --env "EXPECTED_CARGO_CYCLONEDX=${expected_cargo_cyclonedx}" \
    --env "EXPECTED_CARGO_DENY=${expected_cargo_deny}" \
    --env "EXPECTED_CLANG_PACKAGE=${expected_clang_package}" \
    --env "EXPECTED_DOCKER_CLI=${expected_docker_cli}" \
    --env "EXPECTED_NODE=${expected_node}" \
    --env "EXPECTED_PROFILE_ID=${expected_profile_id}" \
    --env "EXPECTED_RUST=${expected_rust}" \
    --env "EXPECTED_WASI_ROOT=${expected_wasi_root}" \
    --env "EXPECTED_WASM_RQUICKJS=${expected_wasm_rquickjs}" \
    --entrypoint /bin/bash \
    "${image_reference}" -euc '
        test "$(id -u)" = 0
        test "$PWD" = /__w
        test "$AUTOMATA_ENVIRONMENT_PROFILE_ID" = "$EXPECTED_PROFILE_ID"
        rustc --version | grep -F "rustc ${EXPECTED_RUST} " >/dev/null
        test "$(node --version)" = "v${EXPECTED_NODE}"
        test "$(wasm-rquickjs --version)" = \
            "wasm-rquickjs-cli ${EXPECTED_WASM_RQUICKJS}"
        test "$(cargo cyclonedx --version)" = \
            "cargo-cyclonedx-cyclonedx ${EXPECTED_CARGO_CYCLONEDX}"
        test "$(cargo deny --version)" = "cargo-deny ${EXPECTED_CARGO_DENY}"
        test "clang-18=$(dpkg-query --show --showformat='"'"'${Version}'"'"' clang-18)" = \
            "$EXPECTED_CLANG_PACKAGE"
        test -x "${EXPECTED_WASI_ROOT}/bin/clang"
        docker --version | grep -F "Docker version ${EXPECTED_DOCKER_CLI}," >/dev/null
    '

printf 'verified profile image contract: %s\n' "${image_reference}"
