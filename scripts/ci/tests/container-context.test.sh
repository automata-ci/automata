#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd)"
readonly repository_root

scratch_directory="$(mktemp -d "${repository_root}/target/container-context-test.XXXXXXXX")"
readonly scratch_directory
cleanup() {
  rm -rf -- "$scratch_directory"
}
trap cleanup EXIT

payload_directory="$scratch_directory/payload"
release_archive="$scratch_directory/release.tar.gz"
install -d -m 0700 -- "$payload_directory/sbom"
printf 'test\n' > "$payload_directory/LICENSE"
printf 'test\n' > "$payload_directory/THIRD_PARTY_LICENSES.txt"
printf 'test\n' > "$payload_directory/THIRD_PARTY_NOTICES.txt"
printf '9.8.7\n' > "$payload_directory/VERSION"
printf 'binary\n' > "$payload_directory/automata"
printf 'runner\n' > "$payload_directory/automata-runner"
for name in automata automata-runner renderer ui-runtime; do
  printf '{}\n' > "$payload_directory/sbom/${name}.cdx.json"
done
(
  cd "$payload_directory"
  sha256sum \
    LICENSE \
    THIRD_PARTY_LICENSES.txt \
    THIRD_PARTY_NOTICES.txt \
    VERSION \
    automata \
    automata-runner \
    sbom/*.cdx.json \
    >SHA256SUMS
  tar -czf "$release_archive" \
    LICENSE \
    SHA256SUMS \
    THIRD_PARTY_LICENSES.txt \
    THIRD_PARTY_NOTICES.txt \
    VERSION \
    automata \
    automata-runner \
    sbom
)

"$repository_root/scripts/ci/prepare-container-context.sh" \
  "$release_archive" \
  "$scratch_directory/context" \
  9.8.7

[[ -f "$scratch_directory/context/sbom/renderer.cdx.json" ]]

rm -f -- "$payload_directory/sbom/renderer.cdx.json"
(
  cd "$payload_directory"
  sha256sum \
    LICENSE \
    THIRD_PARTY_LICENSES.txt \
    THIRD_PARTY_NOTICES.txt \
    VERSION \
    automata \
    automata-runner \
    sbom/*.cdx.json \
    >SHA256SUMS
  tar -czf "$scratch_directory/incomplete.tar.gz" \
    LICENSE \
    SHA256SUMS \
    THIRD_PARTY_LICENSES.txt \
    THIRD_PARTY_NOTICES.txt \
    VERSION \
    automata \
    automata-runner \
    sbom
)

failure_log="$scratch_directory/incomplete.log"
if "$repository_root/scripts/ci/prepare-container-context.sh" \
  "$scratch_directory/incomplete.tar.gz" \
  "$scratch_directory/incomplete-context" \
  9.8.7 >"$failure_log" 2>&1; then
  printf 'container context accepted a missing Containerfile COPY source\n' >&2
  exit 1
fi
grep -F \
  'COPY source is absent from release context: sbom/renderer.cdx.json' \
  "$failure_log" >/dev/null

printf 'container release context contract verified\n'
