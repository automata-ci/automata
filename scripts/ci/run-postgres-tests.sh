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

run_ignored_tests() {
  if [[ "$plan" == true ]]; then
    run_command "$@"
    return
  fi

  local argument
  local listing
  local selected_count
  local replaced=false
  local -a list_command=()
  for argument in "$@"; do
    if [[ "$argument" == --test-threads=* ]]; then
      list_command+=(--list)
      replaced=true
    else
      list_command+=("$argument")
    fi
  done
  if [[ "$replaced" != true ]]; then
    printf 'error: PostgreSQL test command has no libtest thread limit\n' >&2
    exit 2
  fi
  listing="$(LLVM_PROFILE_FILE=/dev/null "${list_command[@]}")"
  selected_count="$(python3 scripts/ci/check-ignored-test-list.py <<<"$listing")"
  printf 'PostgreSQL command selected %d ignored test(s)\n' "$selected_count" >&2
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
run_ignored_tests cargo test \
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

printf 'PostgreSQL lane: fixture and adapter packages\n' >&2
run_ignored_tests cargo test \
  -p automata-ci-postgres-test-support \
  -p automata-ci-auth-postgres \
  -p automata-ci-runner-auth-postgres \
  -p automata-ci-secret-postgres \
  --tests \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=4

printf 'PostgreSQL lane: GitHub Results integration\n' >&2
run_ignored_tests cargo test \
  -p automata-ci-results-github \
  --test postgres_artifacts \
  --test postgres_cache \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=4

printf 'PostgreSQL lane: end-to-end provider matrix\n' >&2
run_ignored_tests cargo test \
  -p automata-ci \
  --test github_provider_end_to_end_matrix \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=1
