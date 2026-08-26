#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd -P)"
build_directory="${1:-${repository_root}/target/ui-renderer}"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(( $# <= 1 )) || die "usage: $0 [BUILD_DIRECTORY]"
if [[ "${build_directory}" != /* ]]; then
    build_directory="${repository_root}/${build_directory}"
fi
[[ -d "${build_directory}" && ! -L "${build_directory}" ]] || \
    die "renderer build must be a real directory: ${build_directory}"

python3 - \
    "${build_directory}" \
    "${repository_root}/crates/automata-ci-ui-renderer/wit/renderer.wit" \
    "${script_directory}/component-wit-provenance.py" <<'PY'
import hashlib
import json
import pathlib
import re
import subprocess
import sys

build = pathlib.Path(sys.argv[1])
wit = pathlib.Path(sys.argv[2])
provenance_tool = pathlib.Path(sys.argv[3])

def fail(message: str) -> None:
    raise SystemExit(f"renderer build verification failed: {message}")

def regular_file(path: pathlib.Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"expected a real file: {path}")
    contents = path.read_bytes()
    if not 0 < len(contents) <= maximum:
        fail(f"file size is outside 1..={maximum}: {path}")
    return contents

manifest_path = build / "manifest.json"
try:
    manifest = json.loads(regular_file(manifest_path, 64 * 1024))
except (json.JSONDecodeError, UnicodeDecodeError) as error:
    fail(f"invalid manifest.json: {error}")

expected_keys = {"schemaVersion", "component", "script", "stylesheet"}
if set(manifest) != expected_keys or manifest.get("schemaVersion") != 1:
    fail("manifest.json has an unsupported shape or schema")

assets = build / "assets"
if assets.is_symlink() or not assets.is_dir():
    fail("assets must be a real directory")

descriptions = [
    ("component", manifest.get("component"), r"renderer-([0-9a-f]{64})\.wasm", 16 * 1024 * 1024),
]
for key, prefix, suffix in (
    ("script", "client-", ".js"),
    ("stylesheet", "styles-", ".css"),
):
    value = manifest.get(key)
    if not isinstance(value, dict) or set(value) != {"file", "publicPath"}:
        fail(f"{key} manifest entry has an unsupported shape")
    filename = value.get("file")
    descriptions.append((key, filename, rf"{prefix}([0-9a-f]{{64}}){re.escape(suffix)}", 4 * 1024 * 1024))
    public_path = value.get("publicPath")
    if not isinstance(public_path, str) or re.fullmatch(
        rf"/assets/entry-client-[A-Za-z0-9_-]{{1,64}}{re.escape(suffix)}",
        public_path,
    ) is None:
        fail(f"{key} has an invalid public path")

expected_assets = set()
component_path = None
component_digest = None
for label, filename, pattern, maximum in descriptions:
    if not isinstance(filename, str) or pathlib.PurePath(filename).name != filename:
        fail(f"{label} has an invalid filename")
    match = re.fullmatch(pattern, filename)
    if match is None:
        fail(f"{label} filename is not content addressed")
    path = assets / filename
    digest = hashlib.sha256(regular_file(path, maximum)).hexdigest()
    if digest != match.group(1):
        fail(f"{label} digest differs from its filename")
    expected_assets.add(filename)
    if label == "component":
        component_path = path
        component_digest = digest

actual_assets = {entry.name for entry in assets.iterdir()}
if actual_assets != expected_assets:
    fail("assets contains an unlisted or missing file")

assert component_path is not None and component_digest is not None
wit_digest = hashlib.sha256(regular_file(wit, 1024 * 1024)).hexdigest()
subprocess.run(
    [sys.executable, str(provenance_tool), "verify", str(component_path), wit_digest],
    check=True,
)

provenance = regular_file(build / "provenance.toml", 64 * 1024)
if b'schema = 1\n' not in provenance:
    fail("provenance.toml has an unsupported schema")

try:
    sbom = json.loads(regular_file(build / "renderer.cdx.json", 4 * 1024 * 1024))
except (json.JSONDecodeError, UnicodeDecodeError) as error:
    fail(f"invalid renderer.cdx.json: {error}")
component = sbom.get("metadata", {}).get("component", {})
hashes = component.get("hashes", [])
if (
    sbom.get("bomFormat") != "CycloneDX"
    or sbom.get("specVersion") != "1.5"
    or component.get("name") != "renderer"
    or not any(
        item.get("alg") == "SHA-256" and item.get("content") == component_digest
        for item in hashes
        if isinstance(item, dict)
    )
):
    fail("renderer SBOM does not describe the component")
PY

printf 'Verified generated renderer build in %s\n' "${build_directory}"
