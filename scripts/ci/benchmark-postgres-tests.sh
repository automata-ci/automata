#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: benchmark-postgres-tests.sh \
  --namespace benchmark_NAME \
  --output-dir ABSOLUTE_NEW_DIRECTORY \
  --runs 1..20 \
  --timeout-seconds 30..1800 \
  --cargo-jobs 1..2

Required environment:
  AUTOMATA_TEST_DATABASE_URL
  AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_ISOLATED=1
  AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_SERVER_BOUNDED=1

The caller must already be inside a cgroup-v2 scope with memory.max no greater
than 12 GiB. The disposable PostgreSQL server must have its own reviewed
resource bounds. The wrapper never creates or changes a host cgroup.
EOF
}

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 2
}

require_argument() {
  local option="$1"
  local remaining="$2"
  if (( remaining < 2 )); then
    fail "$option requires a value"
  fi
}

namespace=
output_directory=
runs=
timeout_seconds=
cargo_jobs=
while (( $# > 0 )); do
  case "$1" in
    --namespace)
      require_argument "$1" "$#"
      namespace="$2"
      shift 2
      ;;
    --output-dir)
      require_argument "$1" "$#"
      output_directory="$2"
      shift 2
      ;;
    --runs)
      require_argument "$1" "$#"
      runs="$2"
      shift 2
      ;;
    --timeout-seconds)
      require_argument "$1" "$#"
      timeout_seconds="$2"
      shift 2
      ;;
    --cargo-jobs)
      require_argument "$1" "$#"
      cargo_jobs="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$namespace" ]] || fail '--namespace is required'
[[ -n "$output_directory" ]] || fail '--output-dir is required'
[[ -n "$runs" ]] || fail '--runs is required'
[[ -n "$timeout_seconds" ]] || fail '--timeout-seconds is required'
[[ -n "$cargo_jobs" ]] || fail '--cargo-jobs is required'

if [[ ! "$namespace" =~ ^benchmark_[a-z0-9_]+$ || ${#namespace} -gt 27 ]]; then
  fail '--namespace must match benchmark_[a-z0-9_]+ and be at most 27 bytes'
fi
if [[ ! "$runs" =~ ^([1-9]|1[0-9]|20)$ ]]; then
  fail '--runs must be an integer from 1 through 20'
fi
if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] \
  || (( ${#timeout_seconds} > 4 )) \
  || (( timeout_seconds < 30 || timeout_seconds > 1800 )); then
  fail '--timeout-seconds must be an integer from 30 through 1800'
fi
if [[ ! "$cargo_jobs" =~ ^[12]$ ]]; then
  fail '--cargo-jobs must be 1 or 2'
fi
[[ "$output_directory" == /* ]] || fail '--output-dir must be absolute'
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] \
  || fail '--output-dir must not already exist'

if [[ "$(uname -s)" != Linux ]]; then
  fail 'PostgreSQL benchmarks require Linux cgroup-v2 containment'
fi
if [[ "${AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_ISOLATED:-}" != 1 ]]; then
  fail 'set AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_ISOLATED=1 only for a disposable isolated PostgreSQL server'
fi
if [[ "${AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_SERVER_BOUNDED:-}" != 1 ]]; then
  fail 'set AUTOMATA_POSTGRES_BENCHMARK_CONFIRM_SERVER_BOUNDED=1 only after applying reviewed resource bounds to the PostgreSQL server'
fi
if [[ -z "${AUTOMATA_TEST_DATABASE_URL:-}" ]]; then
  fail 'AUTOMATA_TEST_DATABASE_URL is required'
fi

required_commands=(
  basename
  cargo
  chmod
  cp
  date
  dirname
  env
  flock
  git
  mkdir
  mv
  psql
  python3
  realpath
  rm
  rmdir
  timeout
  uname
)
for command in "${required_commands[@]}"; do
  command -v "$command" >/dev/null \
    || fail "required command is unavailable: $command"
done

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(git -C "$script_directory" rev-parse --show-toplevel)"
repository_root="$(realpath -e -- "$repository_root")"
readonly repository_root
cd "$repository_root"

git_common_directory="$(git rev-parse --path-format=absolute --git-common-dir)"
git_common_directory="$(realpath -e -- "$git_common_directory")"
[[ -d "$git_common_directory" && ! -L "$git_common_directory" ]] \
  || fail 'Git common directory must be a canonical non-symlink directory'
benchmark_lock_path="$git_common_directory/automata-postgres-benchmark.lock"
exec {benchmark_lock_fd}>"$benchmark_lock_path"
if ! flock --exclusive --nonblock "$benchmark_lock_fd"; then
  fail 'another PostgreSQL benchmark holds the repository benchmark lock'
fi

case "$output_directory/" in
  "$repository_root"/*)
    fail '--output-dir must be outside the repository'
    ;;
esac
output_parent="$(dirname -- "$output_directory")"
output_name="$(basename -- "$output_directory")"
if [[ "$output_name" == . || "$output_name" == .. || ! "$output_name" =~ ^[A-Za-z0-9._-]+$ ]]; then
  fail '--output-dir final component must contain only ASCII letters, digits, dot, underscore, or hyphen'
fi
[[ -d "$output_parent" && ! -L "$output_parent" && -w "$output_parent" ]] \
  || fail '--output-dir parent must be an existing, writable, non-symlink directory'
canonical_output_parent="$(realpath -e -- "$output_parent")"
if [[ "$canonical_output_parent" != "$output_parent" ]]; then
  fail '--output-dir parent must already be canonical and contain no symlink components'
fi

[[ -r /sys/fs/cgroup/cgroup.controllers ]] \
  || fail 'cgroup v2 is required; /sys/fs/cgroup/cgroup.controllers is unavailable'
cgroup_path=
while IFS=: read -r hierarchy controllers path; do
  if [[ "$hierarchy" == 0 && -z "$controllers" ]]; then
    cgroup_path="$path"
    break
  fi
done </proc/self/cgroup
[[ "$cgroup_path" == /* ]] || fail 'could not resolve the current cgroup-v2 path'

memory_limit_file="/sys/fs/cgroup${cgroup_path%/}/memory.max"
memory_events_file="/sys/fs/cgroup${cgroup_path%/}/memory.events"
memory_limit_file="$(realpath -e -- "$memory_limit_file")" \
  || fail 'current cgroup has no readable memory.max'
memory_events_file="$(realpath -e -- "$memory_events_file")" \
  || fail 'current cgroup has no readable memory.events'
for cgroup_file in "$memory_limit_file" "$memory_events_file"; do
  case "$cgroup_file" in
    /sys/fs/cgroup/memory.max | /sys/fs/cgroup/memory.events | /sys/fs/cgroup/*/memory.max | /sys/fs/cgroup/*/memory.events) ;;
    *) fail 'resolved cgroup file escaped /sys/fs/cgroup' ;;
  esac
done

IFS= read -r memory_limit_bytes <"$memory_limit_file"
if [[ "$memory_limit_bytes" == max ]]; then
  fail 'current cgroup memory.max is unlimited; enter a finite memory-limited cgroup before benchmarking'
fi
if [[ ! "$memory_limit_bytes" =~ ^[1-9][0-9]*$ ]]; then
  fail 'current cgroup memory.max is not a positive byte limit'
fi
maximum_memory_limit_bytes=$((12 * 1024 * 1024 * 1024))
if (( ${#memory_limit_bytes} > ${#maximum_memory_limit_bytes} )); then
  fail 'current cgroup memory.max exceeds the 12 GiB benchmark ceiling'
fi
if (( memory_limit_bytes > maximum_memory_limit_bytes )); then
  fail 'current cgroup memory.max exceeds the 12 GiB benchmark ceiling'
fi

memory_event_value() {
  local requested="$1"
  local key
  local value
  local observed=
  while read -r key value; do
    if [[ "$key" == "$requested" ]]; then
      if [[ -n "$observed" || ! "$value" =~ ^[0-9]+$ ]]; then
        return 1
      fi
      observed="$value"
    fi
  done <"$memory_events_file"
  [[ -n "$observed" ]] || return 1
  printf '%s\n' "$observed"
}

monotonic_now_ns() {
  python3 - <<'PY'
import time

print(time.monotonic_ns())
PY
}

baseline_oom="$(memory_event_value oom)" \
  || fail 'current cgroup memory.events has no canonical oom counter'
baseline_oom_kill="$(memory_event_value oom_kill)" \
  || fail 'current cgroup memory.events has no canonical oom_kill counter'

./scripts/ci/verify-postgres-version.sh
workspace_fingerprint="$(
  python3 scripts/ci/fingerprint-workspace.py --repository "$repository_root"
)"
read -r source_head source_content_sha256 source_state_token source_path_count extra \
  <<<"$workspace_fingerprint"
if [[ -n "${extra:-}" \
  || ! "$source_head" =~ ^[0-9a-f]{40}$ \
  || ! "$source_content_sha256" =~ ^[0-9a-f]{64}$ \
  || ! "$source_state_token" =~ ^[0-9a-f]{64}$ \
  || ! "$source_path_count" =~ ^[0-9]+$ ]]; then
  fail 'workspace fingerprint helper returned a malformed identity'
fi

invocation_started_unix_ns="$(date +%s%N)"
if [[ ! "$invocation_started_unix_ns" =~ ^[1-9][0-9]+$ ]]; then
  fail 'date did not return a positive UNIX-nanosecond timestamp'
fi
invocation="${namespace}_p$$_${invocation_started_unix_ns}"
if [[ ! "$invocation" =~ ^[a-z0-9_]{1,64}$ ]]; then
  fail 'generated timing invocation identity is not canonical'
fi

umask 077
mkdir -m 0700 -- "$output_directory"
private_state_directory="$output_directory/private-state"
timings_directory="$output_directory/timings"
mkdir -m 0700 -- "$private_state_directory" "$timings_directory"
incomplete_marker="$output_directory/INCOMPLETE.json"
manifest_path="$output_directory/manifest.json"
manifest_temporary="$output_directory/.manifest.json.tmp.$$"
runs_log="$output_directory/runs.jsonl"

write_incomplete_marker() {
  local temporary="$output_directory/.INCOMPLETE.json.tmp.$$"
  printf '%s\n' \
    '{' \
    '  "schema": "automata-postgres-test-benchmark-state/v1",' \
    '  "status": "incomplete",' \
    "  \"invocation\": \"$invocation\"" \
    '}' \
    >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$incomplete_marker"
}
write_incomplete_marker

export AUTOMATA_TEST_DATABASE_NAMESPACE="$namespace"
export AUTOMATA_TEST_TEMPLATE_FINGERPRINT="$source_content_sha256"
export AUTOMATA_TEST_TIMINGS_DIR="$timings_directory"
export AUTOMATA_TEST_TIMING_INVOCATION="$invocation"
export AUTOMATA_TEST_TIMING_RUN=0
export CARGO_BUILD_JOBS="$cargo_jobs"
export CARGO_INCREMENTAL=0

# shellcheck source=scripts/ci/postgres-test-environment.sh
source "$repository_root/scripts/ci/postgres-test-environment.sh"
automata_configure_postgres_test_namespace

cleanup_timeout_seconds=180
cleanup_required=false
cleanup_executable="$private_state_directory/postgres-test-cleanup"
benchmark_complete=false
namespace_lock_held=false
namespace_lock_pid=
namespace_lock_read_fd=
namespace_lock_write_fd=
namespace_lock_keepalive_fd=

release_postgres_namespace_lock() {
  if [[ "$namespace_lock_held" != true ]]; then
    return 0
  fi
  local release_status=0
  namespace_lock_held=false
  printf '\\q\n' >&"$namespace_lock_write_fd" || release_status=$?
  exec {namespace_lock_write_fd}>&- || release_status=$?
  exec {namespace_lock_keepalive_fd}>&- || release_status=$?
  wait "$namespace_lock_pid" || release_status=$?
  exec {namespace_lock_read_fd}<&- || release_status=$?
  namespace_lock_pid=
  namespace_lock_read_fd=
  namespace_lock_write_fd=
  namespace_lock_keepalive_fd=
  return "$release_status"
}

cleanup_benchmark_namespace() {
  local primary_status=$?
  local cleanup_status=0
  local current_oom=
  local current_oom_kill=
  trap - EXIT HUP INT TERM
  set +e

  if [[ "$cleanup_required" == true && -x "$cleanup_executable" ]]; then
    AUTOMATA_TEST_TIMING_RUN=0 timeout \
      --signal=TERM \
      --kill-after=30s \
      "${cleanup_timeout_seconds}s" \
      env LLVM_PROFILE_FILE=/dev/null "$cleanup_executable"
    cleanup_status=$?
    if (( cleanup_status != 0 )); then
      printf 'error: PostgreSQL benchmark namespace cleanup failed with status %d\n' \
        "$cleanup_status" >&2
      if (( primary_status == 0 )); then
        primary_status=$cleanup_status
      fi
    else
      cleanup_required=false
    fi
  elif [[ "$cleanup_required" == true ]]; then
    printf '%s\n' 'error: PostgreSQL benchmark cleanup executable is unavailable' >&2
    if (( primary_status == 0 )); then
      primary_status=2
    fi
  fi

  release_postgres_namespace_lock
  local lock_release_status=$?
  if (( lock_release_status != 0 )); then
    printf 'error: PostgreSQL benchmark namespace lock release failed with status %d\n' \
      "$lock_release_status" >&2
    if (( primary_status == 0 )); then
      primary_status=$lock_release_status
    fi
  fi

  current_oom="$(memory_event_value oom)"
  current_oom_kill="$(memory_event_value oom_kill)"
  if [[ ! "$current_oom" =~ ^[0-9]+$ || ! "$current_oom_kill" =~ ^[0-9]+$ ]]; then
    printf '%s\n' 'error: could not reread canonical cgroup OOM counters' >&2
    if (( primary_status == 0 )); then
      primary_status=2
    fi
  elif (( current_oom > baseline_oom || current_oom_kill > baseline_oom_kill )); then
    printf 'error: cgroup OOM counters increased (oom %s -> %s, oom_kill %s -> %s)\n' \
      "$baseline_oom" "$current_oom" "$baseline_oom_kill" "$current_oom_kill" >&2
    if (( primary_status == 0 )); then
      primary_status=1
    fi
  fi

  rm -f -- "$private_state_directory/cargo-build.jsonl"
  if [[ "$cleanup_required" != true ]]; then
    rm -f -- \
      "$cleanup_executable" \
      "$private_state_directory/cleanup-source.txt"
  fi
  rmdir -- "$private_state_directory" 2>/dev/null || true

  if [[ "$benchmark_complete" != true && "$primary_status" == 0 ]]; then
    primary_status=2
  fi
  if (( primary_status != 0 )) || [[ "$benchmark_complete" != true ]]; then
    benchmark_complete=false
    rm -f -- "$manifest_path" "$manifest_temporary"
    write_incomplete_marker
  fi
  exit "$primary_status"
}
trap cleanup_benchmark_namespace EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

build_messages="$private_state_directory/cargo-build.jsonl"
timeout \
  --signal=TERM \
  --kill-after=30s \
  "${cleanup_timeout_seconds}s" \
  cargo build \
    -p automata-ci-postgres \
    --features test-support \
    --example postgres-test-cleanup \
    --locked \
    --message-format=json-render-diagnostics \
    >"$build_messages"
cleanup_source="$(
  python3 - "$build_messages" <<'PY'
import json
import pathlib
import sys

messages = pathlib.Path(sys.argv[1])
executables = []
with messages.open("r", encoding="utf-8") as source:
    for line in source:
        message = json.loads(line)
        target = message.get("target", {})
        if (
            message.get("reason") == "compiler-artifact"
            and target.get("name") == "postgres-test-cleanup"
            and "example" in target.get("kind", [])
            and isinstance(message.get("executable"), str)
        ):
            executables.append(message["executable"])
if len(executables) != 1:
    raise SystemExit("cleanup build did not report exactly one example executable")
candidate = pathlib.Path(executables[0])
if candidate.is_symlink():
    raise SystemExit("cleanup build artifact is a symlink")
executable = candidate.resolve(strict=True)
if not executable.is_file():
    raise SystemExit("cleanup build artifact is not a regular non-symlink file")
print(executable)
PY
)"
[[ "$cleanup_source" == /* && -f "$cleanup_source" && ! -L "$cleanup_source" && -x "$cleanup_source" ]] \
  || fail 'cleanup build artifact path is not an executable regular file'
cp -- "$cleanup_source" "$cleanup_executable"
chmod 0700 "$cleanup_executable"
printf '%s\n' "$cleanup_source" >"$private_state_directory/cleanup-source.txt"
rm -- "$build_messages"

# Hold one database-global session lock for the complete benchmark. The local
# Git lock prevents duplicate worktrees on this host; this PostgreSQL lock also
# excludes wrappers on other hosts. The coprocess owns the session and waits on
# its stdin, so normal close and abrupt parent death both release the lock.
namespace_lock_expression="pg_catalog.hashtextextended('automata-ci-postgres-benchmark:${namespace}', 6482851405936141723)"
coproc POSTGRES_NAMESPACE_LOCK {
  PGAPPNAME="automata-postgres-benchmark-${namespace}" \
    ./scripts/ci/psql-test-database.py \
      --no-psqlrc \
      --set=ON_ERROR_STOP=1 \
      --tuples-only \
      --no-align \
      --quiet
}
namespace_lock_pid="$POSTGRES_NAMESPACE_LOCK_PID"
namespace_lock_read_fd="${POSTGRES_NAMESPACE_LOCK[0]}"
namespace_lock_write_fd="${POSTGRES_NAMESPACE_LOCK[1]}"
namespace_lock_held=true
# Bash marks the native coprocess descriptors close-on-exec. Duplicate the
# write end to an ordinary inherited descriptor so a live timeout/Cargo/test
# descendant retains the database lock if only the wrapper is killed. The
# session releases after the last workload descendant exits.
exec {namespace_lock_keepalive_fd}>&"$namespace_lock_write_fd"
printf 'SELECT pg_catalog.pg_try_advisory_lock(%s);\n' \
  "$namespace_lock_expression" >&"$namespace_lock_write_fd"
if ! IFS= read -r namespace_lock_acquired <&"$namespace_lock_read_fd"; then
  fail 'PostgreSQL namespace lock session exited before acquisition'
fi
if [[ "$namespace_lock_acquired" != t ]]; then
  fail 'another PostgreSQL benchmark owns the requested namespace'
fi

# Once the database lock is held, every canonical benchmark-prefixed database
# is either ours or a crash leftover from an earlier owner of this same lock.
# Enable recovery before inspecting the namespace so every later failure gets
# another cleanup attempt from the EXIT path.
cleanup_required=true
reserved_database_count="$(
  ./scripts/ci/psql-test-database.py \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --tuples-only \
    --no-align \
    --command="SELECT count(*) FROM pg_catalog.pg_database WHERE pg_catalog.left(datname, pg_catalog.length('at_${namespace}_')) = 'at_${namespace}_'"
)"
reserved_database_count="${reserved_database_count//[[:space:]]/}"
if [[ "$reserved_database_count" != 0 ]]; then
  printf 'Recovering %s PostgreSQL database(s) left by an interrupted benchmark\n' \
    "$reserved_database_count" >&2
  AUTOMATA_TEST_TIMING_RUN=0 timeout \
    --signal=TERM \
    --kill-after=30s \
    "${cleanup_timeout_seconds}s" \
    env LLVM_PROFILE_FILE=/dev/null "$cleanup_executable"
  reserved_database_count="$(
    ./scripts/ci/psql-test-database.py \
      --no-psqlrc \
      --set=ON_ERROR_STOP=1 \
      --tuples-only \
      --no-align \
      --command="SELECT count(*) FROM pg_catalog.pg_database WHERE pg_catalog.left(datname, pg_catalog.length('at_${namespace}_')) = 'at_${namespace}_'"
  )"
  reserved_database_count="${reserved_database_count//[[:space:]]/}"
  if [[ "$reserved_database_count" != 0 ]]; then
    fail "namespace recovery left $reserved_database_count PostgreSQL database(s)"
  fi
fi

for (( run_number = 1; run_number <= runs; run_number++ )); do
  export AUTOMATA_TEST_TIMING_RUN="$run_number"
  started_unix_ns="$(date +%s%N)"
  started_monotonic_ns="$(monotonic_now_ns)"
  if [[ ! "$started_unix_ns" =~ ^[1-9][0-9]+$ \
    || ! "$started_monotonic_ns" =~ ^[1-9][0-9]+$ ]]; then
    fail 'benchmark clocks did not return canonical positive nanosecond timestamps'
  fi
  set +e
  timeout \
    --signal=TERM \
    --kill-after=30s \
    "${timeout_seconds}s" \
    ./scripts/ci/run-postgres-tests.sh --defer-cleanup
  run_status=$?
  set -e
  finished_monotonic_ns="$(monotonic_now_ns)"
  if [[ ! "$finished_monotonic_ns" =~ ^[1-9][0-9]+$ ]]; then
    fail 'benchmark monotonic clock returned an invalid interval'
  fi
  elapsed_ns="$(
    python3 - "$started_monotonic_ns" "$finished_monotonic_ns" <<'PY'
import sys

started = int(sys.argv[1])
finished = int(sys.argv[2])
if finished < started:
    raise SystemExit("monotonic clock moved backwards")
print(finished - started)
PY
  )" || fail 'benchmark monotonic clock returned an invalid interval'
  printf \
    '{"schema":"automata-postgres-test-benchmark-run/v1","invocation":"%s","run":%d,"status":%d,"started_unix_ns":%d,"elapsed_ns":%d}\n' \
    "$invocation" "$run_number" "$run_status" "$started_unix_ns" "$elapsed_ns" \
    >>"$runs_log"
  if (( run_status != 0 )); then
    printf 'error: PostgreSQL benchmark run %d failed with status %d\n' \
      "$run_number" "$run_status" >&2
    exit "$run_status"
  fi
done

# Successful publication requires explicit namespace cleanup in the normal
# path. The EXIT trap is recovery only and uses the same private executable.
export AUTOMATA_TEST_TIMING_RUN=0
timeout \
  --signal=TERM \
  --kill-after=30s \
  "${cleanup_timeout_seconds}s" \
  env LLVM_PROFILE_FILE=/dev/null "$cleanup_executable"

reserved_database_count="$(
  ./scripts/ci/psql-test-database.py \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --tuples-only \
    --no-align \
    --command="SELECT count(*) FROM pg_catalog.pg_database WHERE pg_catalog.left(datname, pg_catalog.length('at_${namespace}_')) = 'at_${namespace}_'"
)"
reserved_database_count="${reserved_database_count//[[:space:]]/}"
if [[ "$reserved_database_count" != 0 ]]; then
  fail "namespace cleanup left $reserved_database_count reserved PostgreSQL database(s)"
fi
cleanup_required=false
release_postgres_namespace_lock \
  || fail 'PostgreSQL benchmark namespace lock session did not exit cleanly'

final_fingerprint="$(
  python3 scripts/ci/fingerprint-workspace.py --repository "$repository_root"
)"
if [[ "$final_fingerprint" != "$workspace_fingerprint" ]]; then
  fail 'workspace identity changed during the benchmark'
fi

final_oom="$(memory_event_value oom)" \
  || fail 'could not reread the cgroup oom counter'
final_oom_kill="$(memory_event_value oom_kill)" \
  || fail 'could not reread the cgroup oom_kill counter'
if (( final_oom > baseline_oom || final_oom_kill > baseline_oom_kill )); then
  fail "cgroup OOM counters increased (oom $baseline_oom -> $final_oom, oom_kill $baseline_oom_kill -> $final_oom_kill)"
fi

run_record_count="$(
  python3 - "$runs_log" "$invocation" "$runs" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
invocation = sys.argv[2]
runs = int(sys.argv[3])
raw = path.read_bytes()
if not raw or not raw.endswith(b"\n"):
    raise SystemExit("benchmark run log is empty or has a partial final line")
lines = raw.splitlines()
if len(lines) != runs:
    raise SystemExit(f"benchmark run log has {len(lines)} records, expected {runs}")
required_keys = {
    "schema",
    "invocation",
    "run",
    "status",
    "started_unix_ns",
    "elapsed_ns",
}
for expected_run, raw_line in enumerate(lines, start=1):
    try:
        record = json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid benchmark run JSON at line {expected_run}: {error}") from error
    if not isinstance(record, dict) or set(record) != required_keys:
        raise SystemExit(f"unexpected benchmark run fields at line {expected_run}")
    if record["schema"] != "automata-postgres-test-benchmark-run/v1":
        raise SystemExit(f"unexpected benchmark run schema at line {expected_run}")
    if record["invocation"] != invocation or record["run"] != expected_run:
        raise SystemExit(f"benchmark run identity mismatch at line {expected_run}")
    if type(record["status"]) is not int or record["status"] != 0:
        raise SystemExit(f"benchmark run was not successful at line {expected_run}")
    if type(record["started_unix_ns"]) is not int or record["started_unix_ns"] <= 0:
        raise SystemExit(f"invalid benchmark wall-clock start at line {expected_run}")
    if type(record["elapsed_ns"]) is not int or record["elapsed_ns"] < 0:
        raise SystemExit(f"invalid benchmark monotonic duration at line {expected_run}")
print(len(lines))
PY
)"
if [[ "$run_record_count" != "$runs" ]]; then
  fail 'benchmark run validator returned an invalid record count'
fi

timing_record_count="$(
  python3 - "$timings_directory" "$invocation" "$runs" <<'PY'
import json
import pathlib
import re
import sys

directory = pathlib.Path(sys.argv[1]).resolve(strict=True)
invocation = sys.argv[2]
runs = int(sys.argv[3])
if not directory.is_dir() or directory.is_symlink():
    raise SystemExit("timing output is not a regular directory")

filename = re.compile(r"postgres-test-timings-([1-9][0-9]*)[.]jsonl")
operations = {
    "template_prepare",
    "template_reuse",
    "clone",
    "test_body",
    "cleanup",
    "namespace_cleanup",
}
details = {
    "prepared_template",
    "empty_template0",
    "test_database",
    "exact_template",
    "complete_namespace",
}
outcomes = {"success", "completed", "error", "panic", "cancelled", "incomplete"}
required_keys = {
    "schema",
    "pid",
    "invocation",
    "run",
    "operation",
    "detail",
    "outcome",
    "started_unix_ns",
    "elapsed_ns",
}
operations_by_run = {run: set() for run in range(1, runs + 1)}
namespace_cleanup_success = False
record_count = 0
paths = sorted(directory.iterdir())
if not paths:
    raise SystemExit("timing output contains no files")
for path in paths:
    match = filename.fullmatch(path.name)
    if match is None or not path.is_file() or path.is_symlink():
        raise SystemExit(f"invalid timing output entry: {path.name}")
    filename_pid = int(match.group(1))
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise SystemExit(f"timing file is empty or has a partial final line: {path.name}")
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        try:
            record = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SystemExit(f"invalid timing JSON {path.name}:{line_number}: {error}") from error
        if not isinstance(record, dict) or set(record) != required_keys:
            raise SystemExit(f"unexpected timing schema fields: {path.name}:{line_number}")
        if record["schema"] != "automata-postgres-test-timing/v1":
            raise SystemExit(f"unexpected timing schema: {path.name}:{line_number}")
        if type(record["pid"]) is not int or record["pid"] != filename_pid:
            raise SystemExit(f"timing PID does not match its file: {path.name}:{line_number}")
        if record["invocation"] != invocation:
            raise SystemExit(f"timing invocation mismatch: {path.name}:{line_number}")
        if type(record["run"]) is not int or not 0 <= record["run"] <= runs:
            raise SystemExit(f"timing run is out of range: {path.name}:{line_number}")
        if record["operation"] not in operations:
            raise SystemExit(f"unknown timing operation: {path.name}:{line_number}")
        if record["detail"] not in details or record["outcome"] not in outcomes:
            raise SystemExit(f"unknown timing detail or outcome: {path.name}:{line_number}")
        if type(record["started_unix_ns"]) is not int or record["started_unix_ns"] <= 0:
            raise SystemExit(f"invalid timing start: {path.name}:{line_number}")
        if type(record["elapsed_ns"]) is not int or record["elapsed_ns"] < 0:
            raise SystemExit(f"invalid timing duration: {path.name}:{line_number}")
        if record["run"] > 0:
            operations_by_run[record["run"]].add(record["operation"])
        if (
            record["run"] == 0
            and record["operation"] == "namespace_cleanup"
            and record["detail"] == "complete_namespace"
            and record["outcome"] == "success"
        ):
            namespace_cleanup_success = True
        record_count += 1

required_run_operations = {"clone", "test_body", "cleanup"}
for run, observed_operations in operations_by_run.items():
    missing = sorted(required_run_operations - observed_operations)
    if missing:
        raise SystemExit(f"timing records for requested run {run} are missing operations: {missing}")
if not namespace_cleanup_success:
    raise SystemExit("timing records do not prove successful invocation-level namespace cleanup")
print(record_count)
PY
)"
if [[ ! "$timing_record_count" =~ ^[1-9][0-9]*$ ]]; then
  fail 'timing validator returned an invalid record count'
fi

rm -- "$cleanup_executable" "$private_state_directory/cleanup-source.txt"
rmdir -- "$private_state_directory"

printf '%s\n' \
  '{' \
  '  "schema": "automata-postgres-test-benchmark/v1",' \
  '  "status": "complete",' \
  "  \"invocation\": \"$invocation\"," \
  "  \"invocation_started_unix_ns\": $invocation_started_unix_ns," \
  "  \"source_head\": \"$source_head\"," \
  "  \"source_content_sha256\": \"$source_content_sha256\"," \
  "  \"source_path_count\": $source_path_count," \
  "  \"namespace\": \"$namespace\"," \
  "  \"runs\": $runs," \
  "  \"timeout_seconds\": $timeout_seconds," \
  "  \"cargo_jobs\": $cargo_jobs," \
  "  \"cgroup_memory_max_bytes\": $memory_limit_bytes," \
  "  \"baseline_oom\": $baseline_oom," \
  "  \"final_oom\": $final_oom," \
  "  \"baseline_oom_kill\": $baseline_oom_kill," \
  "  \"final_oom_kill\": $final_oom_kill," \
  "  \"run_record_count\": $run_record_count," \
  "  \"timing_record_count\": $timing_record_count" \
  '}' \
  >"$manifest_temporary"
chmod 0600 "$manifest_temporary"

# A manifest is the success boundary. Keep the explicit incomplete marker on
# every earlier exit, and suppress catchable signals across the two-file state
# transition so the EXIT trap cannot expose a partial success publication.
trap '' HUP INT TERM
mv -- "$manifest_temporary" "$manifest_path"
rm -- "$incomplete_marker"
benchmark_complete=true
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'PostgreSQL benchmark results: %s\n' "$output_directory" >&2
