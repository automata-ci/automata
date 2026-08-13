#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--plan] [--defer-cleanup]\n' "$0" >&2
}

plan=false
defer_cleanup=false
while (( $# > 0 )); do
  case "$1" in
    --plan)
      if [[ "$plan" == true ]]; then
        usage
        exit 2
      fi
      plan=true
      ;;
    --defer-cleanup)
      if [[ "$defer_cleanup" == true ]]; then
        usage
        exit 2
      fi
      defer_cleanup=true
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
# shellcheck source=scripts/ci/postgres-test-environment.sh
source "$repository_root/scripts/ci/postgres-test-environment.sh"

run_command() {
  if [[ "$plan" == true ]]; then
    printf 'RUN'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

run_bounded_tests() {
  local argument
  local bounded=false
  for argument in "$@"; do
    if [[ "$argument" =~ ^--test-threads=[1-9][0-9]*$ ]]; then
      bounded=true
    fi
  done
  if [[ "$bounded" != true ]]; then
    printf 'error: PostgreSQL test command has no libtest thread limit\n' >&2
    exit 2
  fi
  run_command "$@"
}

if [[ "$plan" != true ]]; then
  if [[ -z "${AUTOMATA_TEST_DATABASE_URL:-}" ]]; then
    printf 'error: AUTOMATA_TEST_DATABASE_URL is required\n' >&2
    exit 2
  fi
  if [[ "$defer_cleanup" == true && -z "${AUTOMATA_TEST_DATABASE_NAMESPACE:-}" ]]; then
    printf 'error: --defer-cleanup requires an explicit AUTOMATA_TEST_DATABASE_NAMESPACE\n' >&2
    exit 2
  fi
  automata_configure_postgres_test_namespace

  if [[ "$defer_cleanup" != true ]]; then
    cleanup_postgres_tests() {
      local primary_status=$?
      local cleanup_status=0
      trap - EXIT
      set +e
      automata_cleanup_postgres_test_namespace
      cleanup_status=$?
      if (( cleanup_status != 0 )); then
        printf 'error: PostgreSQL namespace cleanup failed with status %d\n' \
          "$cleanup_status" >&2
        if (( primary_status == 0 )); then
          primary_status=$cleanup_status
        fi
      fi
      exit "$primary_status"
    }
    trap cleanup_postgres_tests EXIT
  fi
fi

printf 'PostgreSQL lane: Store current-schema suites\n' >&2
run_bounded_tests cargo test \
  -p automata-ci-store \
  --test store_postgres_execution \
  --test store_postgres_orchestration \
  --test store_postgres_provider \
  --test store_postgres_security \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=4

printf 'PostgreSQL lane: fixture self-tests\n' >&2
run_bounded_tests cargo test \
  -p automata-ci-postgres-test-support \
  --test postgres_18 \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=1

printf 'PostgreSQL lane: adapter packages\n' >&2
run_bounded_tests cargo test \
  -p automata-ci-auth-postgres \
  -p automata-ci-runner-auth-postgres \
  -p automata-ci-secret-postgres \
  --test auth_postgres \
  --test runner_auth_postgres \
  --test secret_postgres \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=4

printf 'PostgreSQL lane: GitHub Results integration\n' >&2
run_bounded_tests cargo test \
  -p automata-ci-results-github \
  --test postgres_artifacts \
  --test postgres_cache \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=4

printf 'PostgreSQL lane: end-to-end provider matrix\n' >&2
run_bounded_tests cargo test \
  -p automata-ci \
  --test github_provider_end_to_end_matrix \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=1
