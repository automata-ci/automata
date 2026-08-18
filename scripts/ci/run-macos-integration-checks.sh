#!/usr/bin/env bash
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  printf '%s\n' \
    'error: macOS integration checks require Bash 4 or newer; install Homebrew bash and put /opt/homebrew/bin first in PATH' \
    >&2
  exit 2
fi

usage() {
  printf 'usage: %s [--plan]\n' "$0" >&2
}

plan=false
if (( $# > 0 )); then
  if (( $# != 1 )) || [[ "$1" != --plan ]]; then
    usage
    exit 2
  fi
  plan=true
fi

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

run_command() {
  if [[ "$plan" == true ]]; then
    printf 'RUN'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

run_test() {
  local label=$1
  shift
  printf 'macOS integration: %s\n' "$label" >&2
  run_command "$@"
}

if [[ "$plan" != true ]]; then
  if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    printf '%s\n' 'error: macOS integration checks require an Apple Silicon macOS host' >&2
    exit 2
  fi
  if ! command -v node >/dev/null 2>&1 || [[ "$(node --version)" != v24.19.0 ]]; then
    printf '%s\n' 'error: macOS integration checks require Node.js 24.19.0' >&2
    exit 2
  fi

  required_environment=(
    AUTOMATA_TEST_DATABASE_URL
    AUTOMATA_TEST_S3_ENDPOINT
    AUTOMATA_TEST_S3_BUCKET
    AUTOMATA_TEST_S3_ACCESS_KEY
    AUTOMATA_TEST_S3_SECRET_KEY
    AUTOMATA_TEST_S3_KMS_KEY_ID
    AUTOMATA_TEST_UPLOAD_ARTIFACT_ACTION_ROOT
    AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE
    AUTOMATA_TEST_DOWNLOAD_ARTIFACT_ACTION_ROOT
    AUTOMATA_TEST_ACTIONS_DOWNLOAD_ARTIFACT_MODULE
    AUTOMATA_TEST_CACHE_ACTION_ROOT
    AUTOMATA_TEST_ACTIONS_CACHE_MODULE
  )
  for name in "${required_environment[@]}"; do
    if [[ -z "${!name:-}" ]]; then
      printf 'error: %s is required\n' "$name" >&2
      exit 2
    fi
  done

  # shellcheck source=scripts/ci/postgres-test-environment.sh
  source "$repository_root/scripts/ci/postgres-test-environment.sh"
  automata_configure_postgres_test_namespace
  cleanup_macos_integration() {
    local primary_status=$?
    local cleanup_status=0
    trap - EXIT
    set +e
    automata_cleanup_postgres_test_namespace
    cleanup_status=$?
    if (( cleanup_status != 0 )); then
      printf 'error: macOS integration namespace cleanup failed with status %d\n' \
        "$cleanup_status" >&2
      if (( primary_status == 0 )); then
        primary_status=$cleanup_status
      fi
    fi
    exit "$primary_status"
  }
  trap cleanup_macos_integration EXIT
fi

run_test 'RustFS blob contract' \
  cargo test -p automata-ci-blob-s3 --test blob_s3 --locked -- \
  rustfs_contract:: --ignored --test-threads=1
run_test 'GitHub action materialization through RustFS' \
  cargo test -p automata-ci-action --test live_github_rustfs --locked -- \
  --ignored --test-threads=1
run_test 'checkout action pipeline through RustFS' \
  cargo test -p automata-ci-action-actions --test live_checkout_pipeline --locked -- \
  --ignored --test-threads=1
run_test 'runner artifact results through RustFS' \
  cargo test -p automata-ci-runner-results --test rustfs_results --locked -- \
  --ignored --test-threads=1
run_test 'runner cache results through RustFS' \
  cargo test -p automata-ci-runner-results --test cache_rustfs --locked -- \
  --ignored --test-threads=1
run_test 'workflow admission through PostgreSQL and RustFS' \
  cargo test -p automata-ci-workflow-service --test live_admission --locked -- \
  --ignored --test-threads=1
run_test 'exact artifact and cache clients through real stores' \
  cargo test -p automata-ci-runner-results --test exact_client_real_store --locked \
  exact_clients_cross_real_http_postgres_and_object_storage -- \
  --ignored --test-threads=1
