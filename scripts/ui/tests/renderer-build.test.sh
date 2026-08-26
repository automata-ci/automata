#!/usr/bin/env bash
set -euo pipefail

test_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(CDPATH='' cd -- "${test_directory}/../../.." && pwd -P)"
verifier="${repository_root}/scripts/ui/verify-renderer-build.sh"
source_build="${repository_root}/target/ui-renderer"
scratch_root="${repository_root}/target/task-tmp/renderer-build-test"
mkdir -p -- "${scratch_root}"
scratch="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
cleanup() {
    rm -rf -- "${scratch}"
}
trap cleanup EXIT

"${verifier}" "${source_build}"
cp -a -- "${source_build}" "${scratch}/digest-mismatch"
script="$(find "${scratch}/digest-mismatch/assets" -maxdepth 1 -type f -name 'client-*.js')"
printf '\n// changed\n' >> "${script}"
if "${verifier}" "${scratch}/digest-mismatch" >/dev/null 2>&1; then
    printf 'error: renderer verifier accepted modified asset bytes\n' >&2
    exit 1
fi

cp -a -- "${source_build}" "${scratch}/extra-asset"
printf 'unexpected\n' > "${scratch}/extra-asset/assets/extra.txt"
if "${verifier}" "${scratch}/extra-asset" >/dev/null 2>&1; then
    printf 'error: renderer verifier accepted an unlisted asset\n' >&2
    exit 1
fi

cp -a -- "${source_build}" "${scratch}/bad-manifest"
printf '{}\n' > "${scratch}/bad-manifest/manifest.json"
if "${verifier}" "${scratch}/bad-manifest" >/dev/null 2>&1; then
    printf 'error: renderer verifier accepted an invalid manifest\n' >&2
    exit 1
fi

printf 'Renderer build verifier rejects stale and malformed outputs\n'
