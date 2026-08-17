#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

die() {
  printf 'sandbox-guest-context: %s\n' "$*" >&2
  exit 1
}

if (( $# != 2 )); then
  die "usage: $0 CONTEXT VERSION"
fi
context="$1"
version="$2"
readonly version
[[ -n "$version" && ${#version} -le 120 && "$version" != *$'\n'* && "$version" != *$'\r'* ]] \
  || die "version must be one bounded non-empty line"

automata_init_target_root "$repository_root"
if [[ "$context" != /* ]]; then
  context="${repository_root}/${context}"
fi
context="$(automata_canonical_target_child "$context" "sandbox-guest image context")"
readonly context
if [[ -e "$context" ]]; then
  [[ -d "$context" && -z "$(find "$context" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || die "context must be an absent or empty target directory"
else
  install -d -m 0700 -- "$context"
fi

target_directory="${CARGO_TARGET_DIR:-target}"
if [[ "$target_directory" != /* ]]; then
  target_directory="${repository_root}/${target_directory}"
fi
target_directory="$(automata_canonical_target_path "$target_directory" "Cargo target directory")"
binary="${target_directory}/x86_64-unknown-linux-musl/release/automata-ci-sandbox-guest"
sbom="${target_directory}/distribution-input/sbom/automata-ci-sandbox-guest.cdx.json"
license_directory="${target_directory}/distribution-input/licenses"
containerfile="${repository_root}/images/automata-sandbox-guest.Containerfile"
readonly target_directory binary sbom license_directory containerfile

for required in \
  "$binary" \
  "$repository_root/LICENSE" \
  "$sbom" \
  "$license_directory/THIRD_PARTY_LICENSES.txt" \
  "$license_directory/THIRD_PARTY_NOTICES.txt" \
  "$containerfile"
do
  [[ -f "$required" && ! -L "$required" ]] \
    || die "required image input is missing"
done
"${script_directory}/verify-sandbox-guest-static.sh" "$binary"

install -m 0555 -- "$binary" "$context/automata-ci-sandbox-guest"
install -m 0444 -- "$repository_root/LICENSE" "$context/LICENSE"
install -m 0444 -- \
  "$license_directory/THIRD_PARTY_LICENSES.txt" \
  "$context/THIRD_PARTY_LICENSES.txt"
install -m 0444 -- \
  "$license_directory/THIRD_PARTY_NOTICES.txt" \
  "$context/THIRD_PARTY_NOTICES.txt"
install -m 0444 -- "$containerfile" "$context/Containerfile"
install -d -m 0755 -- "$context/sbom"
install -m 0444 -- "$sbom" "$context/sbom/automata-ci-sandbox-guest.cdx.json"
chmod 0555 -- "$context/sbom"
printf '%s\n' "$version" > "$context/VERSION"
chmod 0444 -- "$context/VERSION"

printf 'Prepared sandbox-guest image context at %s\n' "$context"
