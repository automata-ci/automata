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

grep -F -- 'AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_ISOLATED' "$benchmark" >/dev/null
grep -F -- 'AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_SERVER_BOUNDED' "$benchmark" >/dev/null
grep -F -- '/sys/fs/cgroup/cgroup.controllers' "$benchmark" >/dev/null
grep -F -- 'current cgroup memory.max is unlimited' "$benchmark" >/dev/null
grep -F -- '12 GiB benchmark ceiling' "$benchmark" >/dev/null
grep -F -- 'memory_event_value oom' "$benchmark" >/dev/null
grep -F -- 'memory_event_value oom_kill' "$benchmark" >/dev/null
grep -F -- 'flock --exclusive --nonblock' "$benchmark" >/dev/null
grep -F -- './scripts/ci/verify-postgres-version.sh' "$benchmark" >/dev/null
grep -F -- 'scripts/ci/fingerprint-workspace.py' "$benchmark" >/dev/null
grep -F -- 'AUTOMATA_TEST_TEMPLATE_FINGERPRINT' "$benchmark" >/dev/null
grep -F -- 'AUTOMATA_TEST_TIMINGS_DIR' "$benchmark" >/dev/null
grep -F -- 'AUTOMATA_TEST_TIMING_INVOCATION' "$benchmark" >/dev/null
grep -F -- 'AUTOMATA_TEST_TIMING_RUN' "$benchmark" >/dev/null
grep -F -- 'run-postgres-tests.sh --defer-cleanup' "$benchmark" >/dev/null
grep -F -- '--example postgres-test-cleanup' "$benchmark" >/dev/null
# These assertions deliberately match unexpanded source expressions.
# shellcheck disable=SC2016
grep -F -- 'private_state_directory="$output_directory/private-state"' "$benchmark" >/dev/null
# shellcheck disable=SC2016
grep -F -- 'cleanup_executable="$private_state_directory/postgres-test-cleanup"' "$benchmark" >/dev/null
grep -F -- 'pg_try_advisory_lock' "$benchmark" >/dev/null
[[ "$(grep -Fc -- './scripts/ci/psql-test-database.py' "$benchmark")" == 4 ]]
# shellcheck disable=SC2016
if grep -F -- '--dbname="$AUTOMATA_TEST_DATABASE_URL"' "$benchmark" >/dev/null; then
  printf 'benchmark must not expose the database URL in process arguments\n' >&2
  exit 1
fi
grep -F -- 'coproc POSTGRES_NAMESPACE_LOCK' "$benchmark" >/dev/null
grep -F -- 'release_postgres_namespace_lock' "$benchmark" >/dev/null
grep -F -- 'namespace_lock_keepalive_fd' "$benchmark" >/dev/null
grep -F -- 'left by an interrupted benchmark' "$benchmark" >/dev/null
if grep -F -- 'reservation_database=' "$benchmark" >/dev/null; then
  printf 'benchmark namespace ownership must not use a crash-split reservation database\n' >&2
  exit 1
fi
grep -F -- '--kill-after=30s' "$benchmark" >/dev/null
grep -F -- 'INCOMPLETE.json' "$benchmark" >/dev/null
grep -F -- '.manifest.json.tmp.' "$benchmark" >/dev/null
grep -F -- 'timing records for requested run' "$benchmark" >/dev/null
grep -F -- 'workspace identity changed during the benchmark' "$benchmark" >/dev/null
grep -F -- 'time.monotonic_ns()' "$benchmark" >/dev/null
grep -F -- 'benchmark run log has' "$benchmark" >/dev/null
grep -F -- 'invalid benchmark monotonic duration' "$benchmark" >/dev/null

trap_body="$(sed -n '/^cleanup_benchmark_namespace()/,/^}/p' "$benchmark")"
if grep -F -- 'cargo ' <<<"$trap_body" >/dev/null; then
  printf 'benchmark EXIT cleanup must not invoke Cargo\n' >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -F -- '"$cleanup_executable"' <<<"$trap_body" >/dev/null

printf 'PostgreSQL benchmark wrapper contract verified\n'
