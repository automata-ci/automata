#!/usr/bin/env bash
set -euo pipefail

readonly target="x86_64-unknown-linux-musl"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root

die() {
  printf 'sandbox-guest-static: %s\n' "$*" >&2
  exit 1
}

if (( $# > 1 )); then
  die "usage: $0 [BINARY]"
fi
binary="${1:-${repository_root}/target/${target}/release/automata-ci-sandbox-guest}"
readonly binary

command -v readelf >/dev/null 2>&1 || die "readelf is required"
[[ -f "$binary" && -x "$binary" ]] || die "static guest executable is missing"
readelf --file-header --wide "$binary" >/dev/null \
  || die "guest is not a readable ELF executable"
if readelf --program-headers --wide "$binary" | grep -Eq '^[[:space:]]*INTERP[[:space:]]'; then
  die "guest contains a PT_INTERP program header"
fi
if readelf --dynamic --wide "$binary" 2>/dev/null | grep -Eq '\(NEEDED\)'; then
  die "guest contains a dynamic dependency"
fi

scratch_directory="$(mktemp -d "${repository_root}/target/sandbox-guest-static.XXXXXXXX")"
readonly scratch_directory
cleanup() {
  rm -rf -- "$scratch_directory"
}
trap cleanup EXIT

set +e
"$binary" >"$scratch_directory/stdout" 2>"$scratch_directory/stderr"
status=$?
set -e
(( status != 0 )) || die "guest accepted an absent fixed command"
[[ ! -s "$scratch_directory/stdout" ]] || die "failed guest wrote to stdout"
[[ ! -s "$scratch_directory/stderr" ]] || die "failed guest wrote to stderr"

set +e
"$binary" unsupported-command \
  >"$scratch_directory/unknown-stdout" \
  2>"$scratch_directory/unknown-stderr"
status=$?
set -e
(( status != 0 )) || die "guest accepted an unsupported fixed command"
[[ ! -s "$scratch_directory/unknown-stdout" ]] \
  || die "unsupported command wrote to stdout"
[[ ! -s "$scratch_directory/unknown-stderr" ]] \
  || die "unsupported command wrote to stderr"

printf 'Static sandbox guest verified: %s\n' \
  "$(sha256sum "$binary" | awk '{print $1}')"
