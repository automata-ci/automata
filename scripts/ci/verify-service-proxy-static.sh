#!/usr/bin/env bash
set -euo pipefail

readonly target="x86_64-unknown-linux-musl"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root

die() {
  printf 'service-proxy-static: %s\n' "$*" >&2
  exit 1
}

if (( $# > 1 )); then
  die "usage: $0 [BINARY]"
fi
binary="${1:-${repository_root}/target/${target}/release/automata-ci-service-proxy}"
readonly binary

command -v readelf >/dev/null 2>&1 || die "readelf is required"
[[ -f "$binary" && -x "$binary" ]] || die "static helper executable is missing"
readelf --file-header --wide "$binary" >/dev/null \
  || die "helper is not a readable ELF executable"
if readelf --program-headers --wide "$binary" | grep -Eq '^[[:space:]]*INTERP[[:space:]]'; then
  die "helper contains a PT_INTERP program header"
fi
if readelf --dynamic --wide "$binary" 2>/dev/null | grep -Eq '\(NEEDED\)'; then
  die "helper contains a dynamic dependency"
fi

scratch_directory="$(mktemp -d "${repository_root}/target/service-proxy-static.XXXXXXXX")"
readonly scratch_directory
cleanup() {
  rm -rf -- "$scratch_directory"
}
trap cleanup EXIT

set +e
"$binary" >"$scratch_directory/stdout" 2>"$scratch_directory/stderr"
status=$?
set -e
(( status != 0 )) || die "helper accepted an absent protocol command"
[[ ! -s "$scratch_directory/stdout" ]] || die "failed helper wrote to stdout"
cmp -s "$scratch_directory/stderr" <(
  printf 'automata-ci-service-proxy: usage-invalid\n'
) || die "failed helper diagnostic was not the closed static category"

set +e
"$binary" serve-results-v1 \
  >"$scratch_directory/results-stdout" 2>"$scratch_directory/results-stderr"
status=$?
set -e
(( status != 0 )) || die "helper accepted an incomplete Results command"
[[ ! -s "$scratch_directory/results-stdout" ]] \
  || die "incomplete Results command wrote to stdout"
cmp -s "$scratch_directory/results-stderr" <(
  printf 'automata-ci-service-proxy: configuration-invalid\n'
) || die "helper does not implement the protocol 2 Results capability"

marker='sensitive-helper-image-marker'
set +e
"$binary" serve-v1 "tcp|${marker}|80|0" \
  >"$scratch_directory/marker-stdout" 2>"$scratch_directory/marker-stderr"
status=$?
set -e
(( status != 0 )) || die "helper accepted a malformed mapping"
[[ ! -s "$scratch_directory/marker-stdout" ]] || die "malformed input wrote to stdout"
if grep -F "$marker" "$scratch_directory/marker-stderr" >/dev/null; then
  die "helper reflected untrusted input"
fi
cmp -s "$scratch_directory/marker-stderr" <(
  printf 'automata-ci-service-proxy: configuration-invalid\n'
) || die "malformed input diagnostic was not the closed static category"

printf 'Static service-proxy helper verified: %s\n' \
  "$(sha256sum "$binary" | awk '{print $1}')"
