#!/usr/bin/env bash

# Shared by the direct PostgreSQL runner and service-aware coverage. Callers
# remain responsible for `set -euo pipefail` and for installing an EXIT trap.

automata_configure_postgres_test_instrumentation() {
  if [[ -n "${AUTOMATA_TEST_TEMPLATE_FINGERPRINT:-}" ]]; then
    if [[ ! "$AUTOMATA_TEST_TEMPLATE_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]]; then
      printf '%s\n' \
        'error: AUTOMATA_TEST_TEMPLATE_FINGERPRINT must be a 64-character lowercase hexadecimal SHA-256 digest' \
        >&2
      return 2
    fi
    export AUTOMATA_TEST_TEMPLATE_FINGERPRINT
  elif [[ -v AUTOMATA_TEST_TEMPLATE_FINGERPRINT ]]; then
    printf '%s\n' \
      'error: AUTOMATA_TEST_TEMPLATE_FINGERPRINT must not be empty when set' \
      >&2
    return 2
  fi

  if [[ -n "${AUTOMATA_TEST_TIMINGS_DIR:-}" ]]; then
    if [[ "$AUTOMATA_TEST_TIMINGS_DIR" != /* ]]; then
      printf '%s\n' \
        'error: AUTOMATA_TEST_TIMINGS_DIR must be an absolute path' >&2
      return 2
    fi
    if [[ ! -d "$AUTOMATA_TEST_TIMINGS_DIR" || -L "$AUTOMATA_TEST_TIMINGS_DIR" || ! -w "$AUTOMATA_TEST_TIMINGS_DIR" ]]; then
      printf '%s\n' \
        'error: AUTOMATA_TEST_TIMINGS_DIR must be an existing, writable, non-symlink directory' \
        >&2
      return 2
    fi
    local canonical_timings_dir
    canonical_timings_dir="$(realpath -e -- "$AUTOMATA_TEST_TIMINGS_DIR")"
    if [[ "$canonical_timings_dir" != "$AUTOMATA_TEST_TIMINGS_DIR" ]]; then
      printf '%s\n' \
        'error: AUTOMATA_TEST_TIMINGS_DIR must already be a canonical path with no symlink components' \
        >&2
      return 2
    fi
    if [[ ! "${AUTOMATA_TEST_TIMING_INVOCATION:-}" =~ ^[a-z0-9_]{1,64}$ ]]; then
      printf '%s\n' \
        'error: AUTOMATA_TEST_TIMING_INVOCATION must be 1-64 lowercase ASCII letters, digits, or underscores when timings are enabled' \
        >&2
      return 2
    fi
    if [[ ! "${AUTOMATA_TEST_TIMING_RUN:-}" =~ ^(0|[1-9][0-9]{0,9})$ ]] \
      || (( AUTOMATA_TEST_TIMING_RUN > 4294967295 )); then
      printf '%s\n' \
        'error: AUTOMATA_TEST_TIMING_RUN must be a canonical unsigned 32-bit decimal integer when timings are enabled' \
        >&2
      return 2
    fi
    export AUTOMATA_TEST_TIMINGS_DIR
    export AUTOMATA_TEST_TIMING_INVOCATION
    export AUTOMATA_TEST_TIMING_RUN
    printf 'PostgreSQL test timings: %s\n' "$AUTOMATA_TEST_TIMINGS_DIR" >&2
  elif [[ -v AUTOMATA_TEST_TIMINGS_DIR ]]; then
    printf '%s\n' \
      'error: AUTOMATA_TEST_TIMINGS_DIR must not be empty when set' >&2
    return 2
  fi
}

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
  automata_configure_postgres_test_instrumentation
}

automata_cleanup_postgres_test_namespace() {
  LLVM_PROFILE_FILE=/dev/null cargo run \
    -p automata-ci-postgres-test-support \
    --example postgres-test-cleanup \
    --locked \
    -q
}
