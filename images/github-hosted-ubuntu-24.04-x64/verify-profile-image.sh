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
import base64
import json
import pathlib
import re
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
inspected = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
expected_revision = sys.argv[3]

def fail(message: str) -> None:
    raise SystemExit(f"profile image contract failed: {message}")

if manifest.get("schema_version") != 2:
    fail("only profile manifest schema version 2 is supported")

if not isinstance(inspected, list) or len(inspected) != 1:
    fail("Podman did not return exactly one inspected image")
image = inspected[0]
config = image.get("Config") or {}
rootfs = image.get("RootFS") or {}
layers = rootfs.get("Layers")
profile_id = manifest.get("profile_id")
platform = manifest.get("platform") or {}
execution = manifest.get("execution") or {}
toolchain = manifest.get("toolchain") or {}
wasi_sdk = toolchain.get("wasi_sdk") or {}
container_engine = manifest.get("job_container_engine") or {}
software_inventory = manifest.get("software_inventory") or {}
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
if not isinstance(layers, list) or len(layers) != 1:
    fail("image must contain exactly one squashed filesystem layer")

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

if software_inventory.get("schema") != "automata.dev/linux-software-inventory-v1":
    fail("software inventory schema is invalid")
dpkg_query = software_inventory.get("dpkg_query")
packages = software_inventory.get("dpkg_packages")
tools = software_inventory.get("tools")
unavailable = software_inventory.get("unavailable_tools")
if dpkg_query != "/usr/bin/dpkg-query":
    fail("software inventory package query is not the reviewed absolute path")
if not isinstance(packages, dict) or not 1 <= len(packages) <= 128:
    fail("software inventory package map is missing or unbounded")
if list(packages) != sorted(packages):
    fail("software inventory package map is not canonically ordered")
for package, version in packages.items():
    if re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", package) is None:
        fail(f"software inventory package name is invalid: {package!r}")
    if not isinstance(version, str) or re.fullmatch(r"[!-~]{1,128}", version) is None:
        fail(f"software inventory package version is invalid: {package!r}")
if not isinstance(tools, dict) or not 1 <= len(tools) <= 64:
    fail("software inventory tool map is missing or unbounded")
if list(tools) != sorted(tools):
    fail("software inventory tool map is not canonically ordered")
required_tools = {
    "bash", "cargo", "clang", "g++", "gcc", "git", "install", "make",
    "node24", "python3", "rustc", "sh", "sha256sum", "sudo", "tar",
    "unzip", "xz", "zip",
}
if set(tools) != required_tools:
    fail("software inventory tool set differs from the reviewed profile")
for tool, contract in tools.items():
    if not isinstance(contract, dict):
        fail(f"software inventory tool contract is invalid: {tool!r}")
    path = contract.get("path")
    if not isinstance(path, str) or re.fullmatch(r"/[A-Za-z0-9._+/-]{1,255}", path) is None:
        fail(f"software inventory tool path is invalid: {tool!r}")
    source = contract.get("source")
    version = contract.get("version")
    if source is not None and source not in packages:
        fail(f"software inventory tool source is not pinned: {tool!r}")
    if source is None and (not isinstance(version, str) or not version):
        fail(f"software inventory standalone tool version is missing: {tool!r}")
if re.fullmatch(r"[0-9a-f]{64}", tools["node24"].get("archive_sha256", "")) is None:
    fail("software inventory Node archive checksum is invalid")
if unavailable != ["pwsh", "zstd"]:
    fail("software inventory unavailable-tool set differs from the reviewed profile")

encoded_inventory = base64.urlsafe_b64encode(
    json.dumps(
        {
            "dpkg_query": dpkg_query,
            "packages": packages,
            "tools": tools,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).decode("ascii")
print(*runtime_values, encoded_inventory, sep="\n")
PY
)
(( ${#profile_contract[@]} == 10 )) || die "profile manifest runtime contract is incomplete"

readonly expected_profile_id="${profile_contract[0]}"
readonly expected_rust="${profile_contract[1]}"
readonly expected_node="${profile_contract[2]}"
readonly expected_wasm_rquickjs="${profile_contract[3]}"
readonly expected_cargo_cyclonedx="${profile_contract[4]}"
readonly expected_cargo_deny="${profile_contract[5]}"
readonly expected_clang_package="${profile_contract[6]}"
readonly expected_wasi_root="${profile_contract[7]}"
readonly expected_docker_cli="${profile_contract[8]}"
readonly expected_software_inventory="${profile_contract[9]}"

podman run --rm \
    --env "EXPECTED_CARGO_CYCLONEDX=${expected_cargo_cyclonedx}" \
    --env "EXPECTED_CARGO_DENY=${expected_cargo_deny}" \
    --env "EXPECTED_CLANG_PACKAGE=${expected_clang_package}" \
    --env "EXPECTED_DOCKER_CLI=${expected_docker_cli}" \
    --env "EXPECTED_NODE=${expected_node}" \
    --env "EXPECTED_PROFILE_ID=${expected_profile_id}" \
    --env "EXPECTED_RUST=${expected_rust}" \
    --env "EXPECTED_SOFTWARE_INVENTORY=${expected_software_inventory}" \
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
        python3 - "$EXPECTED_SOFTWARE_INVENTORY" <<'"'"'PY'"'"'
import base64
import json
import os
import pathlib
import stat
import subprocess
import sys

inventory = json.loads(base64.urlsafe_b64decode(sys.argv[1]))
query = inventory["dpkg_query"]
probe_environment = {
    "CARGO_HOME": os.environ["CARGO_HOME"],
    "PATH": "/opt/cargo/bin:/usr/bin:/bin",
    "RUSTUP_HOME": os.environ["RUSTUP_HOME"],
}
for package, expected in inventory["packages"].items():
    result = subprocess.run(
        [query, "--show", "--showformat=${Version}", package],
        check=False,
        capture_output=True,
        env=probe_environment,
        timeout=5,
    )
    if result.returncode != 0 or result.stderr or result.stdout.decode() != expected:
        raise SystemExit(f"installed package differs from inventory: {package}")

for tool, contract in inventory["tools"].items():
    path = pathlib.Path(contract["path"])
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
        raise SystemExit(f"inventory tool is not an executable file: {tool}")

version_probes = {
    "cargo": ["--version"],
    "node24": ["--version"],
    "rustc": ["--version"],
}
for tool, arguments in version_probes.items():
    contract = inventory["tools"][tool]
    result = subprocess.run(
        [contract["path"], *arguments],
        check=False,
        capture_output=True,
        env=probe_environment,
        timeout=5,
    )
    expected = contract["version"]
    output = result.stdout.decode()
    if result.returncode != 0 or result.stderr:
        raise SystemExit(f"standalone inventory tool probe failed: {tool}")
    if tool == "node24":
        matches = output.strip() == f"v{expected}"
    else:
        matches = output.startswith(f"{tool} {expected} ")
    if not matches:
        raise SystemExit(f"standalone inventory tool version differs: {tool}")
PY
    '

printf 'verified profile image contract: %s\n' "${image_reference}"
