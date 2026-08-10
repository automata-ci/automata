#!/usr/bin/env bash
set -euo pipefail

readonly maximum_inventory_bytes=$((1024 * 1024))
readonly maximum_runners=10000
readonly maximum_generation_timestamp=4102444800
inventory_snapshot=''

cleanup_inventory_snapshot() {
  if [[ -n "$inventory_snapshot" ]] && [[ -f "$inventory_snapshot" ]]; then
    rm -f -- "$inventory_snapshot"
  fi
}

trap cleanup_inventory_snapshot EXIT

if [[ $# -ne 1 ]]; then
  printf 'usage: %s INVENTORY.json\n' "${0##*/}" >&2
  exit 2
fi

readonly inventory_path="$1"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory

require_private_temporary_parent() {
  local canonical_parent

  if [[ -z ${TMPDIR:-} ]] || [[ "$TMPDIR" != /* ]]; then
    printf '%s\n' 'TMPDIR must name an explicit absolute private directory' >&2
    return 1
  fi
  temporary_parent="${TMPDIR%/}"
  [[ -n "$temporary_parent" ]] || temporary_parent=/
  if [[ -L "$temporary_parent" ]] || [[ ! -d "$temporary_parent" ]] ||
    ! canonical_parent="$(realpath -e -- "$temporary_parent")" ||
    [[ "$canonical_parent" != "$temporary_parent" ]] ||
    [[ "$(stat -c '%u' -- "$temporary_parent")" != "$(id -u)" ]] ||
    [[ "$(stat -c '%a' -- "$temporary_parent")" != 700 ]] ||
    [[ ! -w "$temporary_parent" ]] || [[ ! -x "$temporary_parent" ]]; then
    printf '%s\n' 'TMPDIR must be an owner-only, non-symlink, writable directory' >&2
    return 1
  fi
}

temporary_parent=''
require_private_temporary_parent
readonly temporary_parent
inventory_snapshot="$(mktemp "$temporary_parent/automata-runner-inventory.XXXXXXXX")"
readonly inventory_snapshot
if ! "$script_directory/bounded-file-snapshot.py" \
  "$inventory_path" "$maximum_inventory_bytes" > "$inventory_snapshot"; then
  printf '%s\n' 'runner inventory could not be snapshotted safely' >&2
  exit 1
fi

if ! inventory_json="$(jq --compact-output --exit-status \
  --argjson maximum_runners "$maximum_runners" \
  --argjson maximum_generation_timestamp "$maximum_generation_timestamp" '
    def identity:
      type == "string"
      and test("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
      and . != "replace-me"
      and . != "replace-me-unique";
    if (
      type == "object"
      and (keys | sort) == ["generated_at_seconds", "runners", "schema"]
      and .schema == 2
      and (.generated_at_seconds | type == "number")
      and (.generated_at_seconds | floor == .)
      and (
        .generated_at_seconds > 0
        and .generated_at_seconds <= $maximum_generation_timestamp
      )
      and (.runners | type == "array")
      and (.runners | length > 0 and length <= $maximum_runners)
      and all(
        .runners[];
        type == "object"
        and (keys | sort) == ["cluster", "environment", "instance"]
        and (.instance | identity)
        and (.cluster | identity)
        and (.environment | identity)
      )
      and ([.runners[].instance] | length == (unique | length))
    ) then . else error("invalid runner inventory") end
  ' "$inventory_snapshot")"; then
  printf '%s\n' 'runner inventory is invalid, unbounded, or contains duplicate identities' >&2
  exit 1
fi
readonly inventory_json

printf '%s\n' \
  '# HELP automata_ci_runner_inventory_generation_timestamp_seconds Unix timestamp when the independent desired-runner inventory was last generated.' \
  '# TYPE automata_ci_runner_inventory_generation_timestamp_seconds gauge' \
  "automata_ci_runner_inventory_generation_timestamp_seconds $(jq --raw-output '.generated_at_seconds' <<< "$inventory_json")" \
  '# HELP automata_ci_runner_inventory_expected Independently inventoried runners expected to publish node-local scrape health.' \
  '# TYPE automata_ci_runner_inventory_expected gauge'
jq --raw-output '
  .runners
  | sort_by(.instance)
  | .[]
  | "automata_ci_runner_inventory_expected{job=\"automata-runner\",instance=\"\(.instance)\",cluster=\"\(.cluster)\",environment=\"\(.environment)\"} 1"
' <<< "$inventory_json"
