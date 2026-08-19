#!/usr/bin/env bash
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  printf '%s\n' \
    'error: physical macOS checks require Bash 4 or newer; install Homebrew bash and put /opt/homebrew/bin first in PATH' \
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

repetitions=${AUTOMATA_MACOS_PHYSICAL_REPETITIONS:-1}
if [[ ! "$repetitions" =~ ^[1-9][0-9]*$ ]] || (( repetitions > 10 )); then
  printf '%s\n' 'error: AUTOMATA_MACOS_PHYSICAL_REPETITIONS must be an integer from 1 through 10' >&2
  exit 2
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
  printf 'physical macOS: %s\n' "$label" >&2
  run_command "$@"
}

assert_directory_empty() {
  local label=$1
  local directory=$2
  if [[ ! -d "$directory" ]]; then
    printf 'error: %s directory does not exist: %s\n' "$label" "$directory" >&2
    exit 2
  fi
  if [[ -n "$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    printf 'error: %s directory is not empty: %s\n' "$label" "$directory" >&2
    exit 2
  fi
}

if [[ "$plan" != true ]]; then
  if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    printf '%s\n' 'error: physical macOS checks require an Apple Silicon macOS host' >&2
    exit 2
  fi

  required_environment=(
    AUTOMATA_MACOS_VM_HELPER
    AUTOMATA_MACOS_VM_HELPER_SHA256
    AUTOMATA_MACOS_VM_HELPER_REQUIREMENT
    AUTOMATA_MACOS_VM_TEMPLATE_MANIFEST
    AUTOMATA_MACOS_VM_TEMPLATE_SHA256
    AUTOMATA_MACOS_VM_STORAGE_ROOT
    AUTOMATA_MACOS_VM_STORAGE_VOLUME_UUID
    AUTOMATA_MACOS_VM_STORAGE_QUOTA_BYTES
  )
  for name in "${required_environment[@]}"; do
    if [[ -z "${!name:-}" ]]; then
      printf 'error: %s is required\n' "$name" >&2
      exit 2
    fi
  done

  export CARGO_INCREMENTAL=0
  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repository_root/target/macos-physical}
  install -d -m 0700 "$CARGO_TARGET_DIR"
  if [[ "$(stat -f %d "$CARGO_TARGET_DIR")" == \
    "$(stat -f %d "$AUTOMATA_MACOS_VM_STORAGE_ROOT")" ]]; then
    printf '%s\n' \
      'error: CARGO_TARGET_DIR must not share the VM storage filesystem; build artifacts consume required clone headroom' \
      >&2
    exit 2
  fi
  available_kib=$(df -Pk "$CARGO_TARGET_DIR" | awk 'END {print $4}')
  if (( available_kib < 8 * 1024 * 1024 )); then
    printf 'error: CARGO_TARGET_DIR requires at least 8 GiB available; found %s KiB\n' \
      "$available_kib" >&2
    exit 2
  fi

  export AUTOMATA_MACOS_PHYSICAL_HELPER=$AUTOMATA_MACOS_VM_HELPER
  export AUTOMATA_MACOS_PHYSICAL_MANIFEST=$AUTOMATA_MACOS_VM_TEMPLATE_MANIFEST
  export AUTOMATA_MACOS_PHYSICAL_ATTEMPT_ROOT=${AUTOMATA_MACOS_PHYSICAL_ATTEMPT_ROOT:-$(dirname "$AUTOMATA_MACOS_VM_STORAGE_ROOT")/proxy-tests}
  install -d -m 0700 "$AUTOMATA_MACOS_PHYSICAL_ATTEMPT_ROOT"
  assert_directory_empty 'provider attempts' "$AUTOMATA_MACOS_VM_STORAGE_ROOT/attempts"
  assert_directory_empty 'runtime proxy attempts' "$AUTOMATA_MACOS_PHYSICAL_ATTEMPT_ROOT"
fi

for ((iteration = 1; iteration <= repetitions; iteration++)); do
  run_test "shipped runner success, timeout, and cancellation ($iteration/$repetitions)" \
    cargo test -p automata-ci-runner --test runner --locked \
    macos_vm_runner_process_e2e:: -- \
    --ignored --nocapture --test-threads=1
done
run_test 'helper loss during VM launch recovery and slot reuse' \
  cargo test -p automata-ci-sandbox-macos --test macos_provider --locked \
  provider_recovers_an_interrupted_launch_and_reuses_the_slot -- \
  --ignored --exact --nocapture --test-threads=1
run_test 'live helper loss cleanup and slot reuse' \
  cargo test -p automata-ci-sandbox-macos --test macos_provider --locked \
  provider_cleans_up_and_reuses_slot_after_live_helper_loss -- \
  --ignored --exact --nocapture --test-threads=1
run_test 'helper loss during VM destroy cleanup and slot reuse' \
  cargo test -p automata-ci-sandbox-macos --test macos_provider --locked \
  provider_completes_destroy_when_the_helper_dies_during_quiescence -- \
  --ignored --exact --nocapture --test-threads=1
run_test 'live VM orphan recovery after owner loss' \
  cargo test -p automata-ci-sandbox-macos --test macos_provider --locked \
  provider_reconciles_a_live_orphan_after_owner_process_loss -- \
  --ignored --exact --nocapture --test-threads=1
run_test 'allowlisted Virtio-socket runtime proxy' \
  cargo test -p automata-ci-sandbox-macos --lib --locked \
  runtime_proxy::tests::physical_guest_reaches_an_allowlisted_origin_through_the_vsock_proxy -- \
  --ignored --exact --nocapture --test-threads=1

if [[ "$plan" != true ]]; then
  assert_directory_empty 'provider attempts' "$AUTOMATA_MACOS_VM_STORAGE_ROOT/attempts"
  assert_directory_empty 'runtime proxy attempts' "$AUTOMATA_MACOS_PHYSICAL_ATTEMPT_ROOT"
fi
