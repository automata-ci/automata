#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
scratch_root="${repository_root}/target/task-tmp/renderer-provenance-test"
mkdir -p -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
cleanup() {
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

component="${scratch_directory}/component.wasm"
stamped="${scratch_directory}/stamped.wasm"
first_digest="d59593c5b09a51c61b687508750b00c1cd723071d98844e82578cbbdc08eb3b8"
second_digest="7b8c98d27674059af59e301b26f72ed47a96b25565397346f7476e6baf508d67"

printf '\x00asm\x0d\x00\x01\x00' > "${component}"
python3 "${script_directory}/component-wit-provenance.py" stamp \
    "${component}" "${stamped}" "${first_digest}"
python3 "${script_directory}/component-wit-provenance.py" verify \
    "${stamped}" "${first_digest}"

if python3 "${script_directory}/component-wit-provenance.py" verify \
    "${stamped}" "${second_digest}" >/dev/null 2>&1; then
    echo "stale WIT binding unexpectedly verified" >&2
    exit 1
fi

if python3 "${script_directory}/component-wit-provenance.py" stamp \
    "${stamped}" "${scratch_directory}/duplicate.wasm" "${first_digest}" \
    >/dev/null 2>&1; then
    echo "duplicate WIT binding unexpectedly stamped" >&2
    exit 1
fi

workspace="${scratch_directory}/wrapper"
inside_manifest="${workspace}/vendor/macro/Cargo.toml"
outside_manifest="${scratch_directory}/outside/Cargo.toml"
inside_metadata="${scratch_directory}/inside-metadata.json"
outside_metadata="${scratch_directory}/outside-metadata.json"
mkdir -p -- "$(dirname -- "${inside_manifest}")" "$(dirname -- "${outside_manifest}")"
printf '%s\n' \
    '{"packages":[' \
    "{\"name\":\"renderer\",\"source\":null,\"manifest_path\":\"${workspace}/Cargo.toml\"}," \
    "{\"name\":\"macro\",\"source\":null,\"manifest_path\":\"${inside_manifest}\"}," \
    "{\"name\":\"registry\",\"source\":\"registry+https://example.invalid/index\",\"manifest_path\":\"${outside_manifest}\"}" \
    ']}' \
    > "${inside_metadata}"
python3 "${script_directory}/verify-wrapper-path-sources.py" \
    "${workspace}" "${inside_metadata}"

printf '%s\n' \
    '{"packages":[' \
    "{\"name\":\"renderer\",\"source\":null,\"manifest_path\":\"${workspace}/Cargo.toml\"}," \
    "{\"name\":\"escaped-macro\",\"source\":null,\"manifest_path\":\"${outside_manifest}\"}" \
    ']}' \
    > "${outside_metadata}"
if python3 "${script_directory}/verify-wrapper-path-sources.py" \
    "${workspace}" "${outside_metadata}" >/dev/null 2>&1; then
    echo "out-of-workspace Cargo path source unexpectedly verified" >&2
    exit 1
fi

echo "renderer WIT binding and in-workspace Cargo path provenance verified"
