#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--plan] OUTPUT_DIRECTORY LANE [LANE ...]\n' "$0" >&2
  printf 'lanes: ordinary postgres s3 podman github-live node-live\n' >&2
}

plan=false
if [[ "${1-}" == "--plan" ]]; then
  plan=true
  shift
fi
if (( $# < 2 )); then
  usage
  exit 2
fi

output_directory="$1"
shift
lanes=("$@")
known_lanes=(ordinary postgres s3 podman github-live node-live)

declare -A selected=()
for lane in "${lanes[@]}"; do
  known=false
  for candidate in "${known_lanes[@]}"; do
    if [[ "$lane" == "$candidate" ]]; then
      known=true
      break
    fi
  done
  if [[ "$known" != true ]] || [[ -n "${selected[$lane]+present}" ]]; then
    usage
    exit 2
  fi
  selected[$lane]=1
done

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
output_directory="$(realpath -m -- "$output_directory")"
if [[ "$output_directory" != "$repository_root/"* ]]; then
  printf 'error: coverage output must be inside the repository\n' >&2
  exit 2
fi
output_relative="${output_directory#"$repository_root/"}"
if ! git check-ignore --quiet --no-index -- "$output_relative/"; then
  printf 'error: coverage output must be ignored by Git\n' >&2
  exit 2
fi
policy="$repository_root/scripts/ci/rust-coverage-policy.json"

require_environment() {
  local variable
  for variable in "$@"; do
    if [[ -z "${!variable-}" ]]; then
      printf 'error: coverage lane requires %s\n' "$variable" >&2
      exit 2
    fi
  done
}

run_command() {
  if [[ "$plan" == true ]]; then
    printf 'RUN'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

run_ignored_command() {
  if [[ "$plan" == true ]]; then
    run_command "$@"
    return
  fi
  local argument
  local replaced=false
  local listing
  local selected_count
  local -a list_command=()
  for argument in "$@"; do
    if [[ "$argument" == '--test-threads=1' ]]; then
      list_command+=(--list)
      replaced=true
    else
      list_command+=("$argument")
    fi
  done
  if [[ "$replaced" != true ]]; then
    printf 'error: ignored coverage command has no list insertion point\n' >&2
    exit 2
  fi
  listing="$(
    LLVM_PROFILE_FILE=/dev/null "${list_command[@]}"
  )"
  if ! selected_count="$(
    python3 scripts/ci/check-ignored-test-list.py <<<"$listing"
  )"; then
    printf 'command:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    exit 2
  fi
  printf 'coverage command selected %d ignored test(s)\n' "$selected_count" >&2
  run_command "$@"
}

run_ordinary() {
  run_command cargo test \
    --workspace \
    --exclude automata-ci-ui-renderer \
    --all-targets \
    --all-features \
    --locked \
    --no-fail-fast
}

run_postgres() {
  run_ignored_command cargo test -p automata-ci-store --tests --all-features --locked -- \
    --ignored --test-threads=1
  for package in \
    automata-ci-auth-postgres \
    automata-ci-runner-auth-postgres \
    automata-ci-secret-postgres
  do
    run_ignored_command cargo test -p "$package" --tests --all-features --locked -- \
      --ignored --test-threads=1
  done
  run_ignored_command cargo test -p automata-ci-results-github --test postgres_artifacts \
    --all-features --locked -- --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-results-github --test postgres_cache \
    --all-features --locked -- --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci --test github_provider_end_to_end_matrix \
    --all-features --locked -- --ignored --test-threads=1
}

run_s3() {
  run_ignored_command cargo test -p automata-ci-blob-s3 --test rustfs_contract \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-action --test live_github_rustfs \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-action-github --test live_checkout_pipeline \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-results-github --test rustfs_results \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-results-github --test cache_rustfs \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-workflow-service --test live_admission \
    --all-features --locked -- \
    --ignored --test-threads=1
}

run_podman() {
  run_ignored_command cargo test -p automata-ci-sandbox-podman --test live_rootless \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-runner --all-features --locked \
    podman_probe::tests:: -- \
    --ignored --test-threads=1
}

run_github_live() {
  run_ignored_command cargo test -p automata-ci-github --test live_repository_snapshot \
    --all-features --locked -- \
    --ignored --test-threads=1
}

run_node_live() {
  run_ignored_command cargo test -p automata-ci-results-github --test http_compatibility \
    --all-features --locked -- \
    --ignored --test-threads=1
  run_ignored_command cargo test -p automata-ci-results-github --test cache_http \
    --all-features --locked -- \
    --ignored --test-threads=1
}

validate_lane_environment() {
  case "$1" in
    postgres)
      require_environment AUTOMATA_TEST_DATABASE_URL
      ;;
    s3)
      require_environment \
        AUTOMATA_TEST_DATABASE_URL \
        AUTOMATA_TEST_S3_ENDPOINT \
        AUTOMATA_TEST_S3_BUCKET \
        AUTOMATA_TEST_S3_ACCESS_KEY \
        AUTOMATA_TEST_S3_SECRET_KEY
      ;;
    podman)
      require_environment \
        HOME XDG_RUNTIME_DIR AUTOMATA_LIVE_ROOTLESS_PODMAN \
        AUTOMATA_PODMAN_APPROVED_HELPERS AUTOMATA_PODMAN_TEST_IMAGE \
        AUTOMATA_PODMAN_TEST_SERVICE_IMAGE AUTOMATA_PODMAN_TEST_SERVICE_PROXY_IMAGE \
        AUTOMATA_TEST_STATIC_RUNNER AUTOMATA_TEST_PODMAN_BINARY \
        AUTOMATA_TEST_PODMAN_STATE_ROOT AUTOMATA_TEST_PODMAN_HOME \
        AUTOMATA_TEST_PODMAN_RUNTIME AUTOMATA_TEST_PODMAN_APPROVED_HELPERS \
        AUTOMATA_TEST_CONMON AUTOMATA_TEST_OCI_RUNTIME AUTOMATA_TEST_CATATONIT \
        AUTOMATA_TEST_SECCOMP_PROFILE
      ;;
    node-live)
      require_environment \
        AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE AUTOMATA_TEST_ACTIONS_CACHE_MODULE
      ;;
    ordinary | github-live) ;;
  esac
}

if [[ "$plan" == true ]]; then
  for lane in "${lanes[@]}"; do
    "run_${lane//-/_}"
  done
  exit 0
fi

install -d -m 0755 -- "$repository_root/target"
coverage_lock="$repository_root/target/llvm-cov-target.lock"
if [[ "${AUTOMATA_COVERAGE_LOCK_HELD-}" != "$coverage_lock" ]]; then
  set +e
  AUTOMATA_COVERAGE_LOCK_HELD="$coverage_lock" \
    flock --exclusive --nonblock --close --conflict-exit-code 73 \
    "$coverage_lock" "$0" "$output_directory" "${lanes[@]}"
  locked_status=$?
  set -e
  if (( locked_status == 73 )); then
    printf 'error: another Rust coverage run owns the instrumented target\n' >&2
    exit 2
  fi
  exit "$locked_status"
fi
unset AUTOMATA_COVERAGE_LOCK_HELD

install -d -m 0755 -- "$output_directory"
rm -f -- \
  "$output_directory/coverage.lcov" \
  "$output_directory/manifest.json" \
  "$output_directory/summary.json"
coverage_stage="$(mktemp -d "$output_directory/.rust-coverage-stage.XXXXXX")"
publish_complete=false
cleanup_stage() {
  if [[ "${publish_complete-}" != true ]]; then
    rm -f -- \
      "$output_directory/coverage.lcov" \
      "$output_directory/manifest.json" \
      "$output_directory/summary.json"
  fi
  if [[ -n "${coverage_stage-}" ]]; then
    find "$coverage_stage" -depth -mindepth 1 -delete 2>/dev/null || true
    rmdir -- "$coverage_stage" 2>/dev/null || true
  fi
}
trap cleanup_stage EXIT
for lane in "${lanes[@]}"; do
  validate_lane_environment "$lane"
done
ignore_regex="$(
  python3 -c \
    'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["report_scope"]["ignore_filename_regex"])' \
    "$policy"
)"
if [[ "$(cargo llvm-cov --version)" != 'cargo-llvm-cov 0.8.7' ]]; then
  printf 'error: cargo-llvm-cov 0.8.7 is required\n' >&2
  exit 2
fi
source_snapshot="$(
  python3 scripts/ci/fingerprint-workspace.py --repository "$repository_root"
)"
IFS=' ' read -r source_head source_content_digest source_state_token source_entry_count source_extra <<<"$source_snapshot"
if [[ -z "$source_head" || -z "$source_content_digest" || -z "$source_state_token" || -z "$source_entry_count" || -n "$source_extra" ]]; then
  printf 'error: workspace fingerprint returned an invalid record\n' >&2
  exit 2
fi

export CARGO_TARGET_DIR="$repository_root/target/llvm-cov-target"
coverage_environment="$(
  cargo llvm-cov show-env \
    --sh \
    --remap-path-prefix
)"
# The evaluated assignments come from the exact pinned cargo-llvm-cov binary.
# shellcheck disable=SC2294
eval "$coverage_environment"
# Cleaning after applying show-env removes stale non-instrumented artifacts from
# the same target directory that the raw cargo commands below will reuse.
cargo llvm-cov clean --workspace

for lane in "${lanes[@]}"; do
  "run_${lane//-/_}"
done

cargo llvm-cov report \
  --remap-path-prefix \
  --ignore-filename-regex="$ignore_regex" \
  --json \
  --summary-only \
  --output-path "$coverage_stage/summary.json"
cargo llvm-cov report \
  --remap-path-prefix \
  --ignore-filename-regex="$ignore_regex" \
  --lcov \
  --output-path "$coverage_stage/coverage.lcov"

guard_arguments=()
for lane in "${lanes[@]}"; do
  guard_arguments+=(--lane "$lane")
done
set +e
python3 scripts/ci/check-rust-coverage.py \
  --policy "$policy" \
  --summary "$coverage_stage/summary.json" \
  --lcov "$coverage_stage/coverage.lcov" \
  --manifest "$coverage_stage/manifest.json" \
  --source-head "$source_head" \
  --source-content-digest "$source_content_digest" \
  --source-state-token "$source_state_token" \
  --source-entry-count "$source_entry_count" \
  "${guard_arguments[@]}"
checker_status=$?
set -e
if (( checker_status > 1 )); then
  exit "$checker_status"
fi

final_source_snapshot="$(
  python3 scripts/ci/fingerprint-workspace.py --repository "$repository_root"
)"
if [[ "$final_source_snapshot" != "$source_snapshot" ]]; then
  printf 'error: workspace source changed during Rust coverage collection\n' >&2
  exit 2
fi

# Each rename is atomic within the output directory; publishing the manifest
# last makes it the completion marker consumed by CI artifact upload.
mv -- "$coverage_stage/summary.json" "$output_directory/summary.json"
mv -- "$coverage_stage/coverage.lcov" "$output_directory/coverage.lcov"
mv -- "$coverage_stage/manifest.json" "$output_directory/manifest.json"
rmdir -- "$coverage_stage"
coverage_stage=""
publish_complete=true
if (( checker_status != 0 )); then
  exit "$checker_status"
fi
