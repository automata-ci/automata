#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "$script_directory/../../.." && pwd)"
benchmark="$repository_root/scripts/ci/benchmark-postgres-tests.sh"

help="$($benchmark --help 2>&1)"
grep -F -- '--namespace benchmark_NAME' <<<"$help" >/dev/null
grep -F -- '--output-dir ABSOLUTE_NEW_DIRECTORY' <<<"$help" >/dev/null
grep -F -- '--cargo-jobs 1..2' <<<"$help" >/dev/null
grep -F -- 'memory.max no greater' <<<"$help" >/dev/null
grep -F -- 'resource bounds' <<<"$help" >/dev/null

expect_usage_failure() {
  local expected="$1"
  shift
  local diagnostic
  local status
  set +e
  diagnostic="$($benchmark "$@" 2>&1)"
  status=$?
  set -e
  if (( status != 2 )); then
    printf 'expected benchmark argument rejection status 2, got %d\n' "$status" >&2
    exit 1
  fi
  grep -F -- "$expected" <<<"$diagnostic" >/dev/null
}

expect_usage_failure '--namespace is required'
expect_usage_failure \
  '--namespace must match benchmark_[a-z0-9_]+' \
  --namespace ordinary \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 30 \
  --cargo-jobs 1
expect_usage_failure \
  '--runs must be an integer from 1 through 20' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 21 \
  --timeout-seconds 30 \
  --cargo-jobs 1
expect_usage_failure \
  '--runs must be an integer from 1 through 20' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 18446744073709551617 \
  --timeout-seconds 30 \
  --cargo-jobs 1
expect_usage_failure \
  '--runs must be an integer from 1 through 20' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 08 \
  --timeout-seconds 30 \
  --cargo-jobs 1
expect_usage_failure \
  '--timeout-seconds must be an integer from 30 through 1800' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 030 \
  --cargo-jobs 1
expect_usage_failure \
  '--timeout-seconds must be an integer from 30 through 1800' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 18446744073709551646 \
  --cargo-jobs 1
expect_usage_failure \
  '--cargo-jobs must be 1 or 2' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 30 \
  --cargo-jobs 3
expect_usage_failure \
  '--cargo-jobs must be 1 or 2' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 30 \
  --cargo-jobs 08
expect_usage_failure \
  '--cargo-jobs must be 1 or 2' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 30 \
  --cargo-jobs 18446744073709551617
expect_usage_failure \
  '--output-dir must be absolute' \
  --namespace benchmark_static \
  --output-dir relative \
  --runs 1 \
  --timeout-seconds 30 \
  --cargo-jobs 1

printf 'PostgreSQL benchmark wrapper contract verified\n'
