#!/usr/bin/env bash

# Shared by the direct PostgreSQL runner and service-aware coverage. Callers
# remain responsible for `set -euo pipefail` and for installing an EXIT trap.

automata_configure_postgres_test_namespace() {
  if [[ -z "${AUTOMATA_TEST_DATABASE_NAMESPACE:-}" ]]; then
    printf -v AUTOMATA_TEST_DATABASE_NAMESPACE 'local_%x_%x_%x' \
      "$(date +%s)" "$(( $$ & 0xfffff ))" "$RANDOM"
  fi
  if [[ ! "$AUTOMATA_TEST_DATABASE_NAMESPACE" =~ ^[a-z0-9_]{1,27}$ ]]; then
    printf '%s\n' \
      'error: AUTOMATA_TEST_DATABASE_NAMESPACE must be 1-27 lowercase ASCII letters, digits, or underscores' \
      >&2
    return 2
  fi
  export AUTOMATA_TEST_DATABASE_NAMESPACE
  printf 'PostgreSQL test namespace: %s\n' "$AUTOMATA_TEST_DATABASE_NAMESPACE" >&2
}

automata_cleanup_postgres_test_namespace() {
  LLVM_PROFILE_FILE=/dev/null cargo run \
    -p automata-ci-postgres-test-support \
    --example postgres-test-cleanup \
    --locked \
    -q
}
