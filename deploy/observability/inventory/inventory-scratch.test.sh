#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_directory/../../.." && pwd -P)"
scratch_parent="$repository_root/target/task-tmp"
scratch_prefix="$scratch_parent/inventory-scratch-test."
system_mktemp="$(type -P mktemp)"
system_stat="$(type -P stat)"
unset -f mktemp stat 2> /dev/null || true
scratch_root=''

cleanup() {
  case "$scratch_root" in
    "$scratch_prefix"????????)
      if [[ ! -L "$scratch_root" ]] && [[ -d "$scratch_root" ]]; then
        rm -rf -- "$scratch_root"
      fi
      ;;
    '') ;;
    *)
      printf 'refusing to clean unexpected inventory scratch path: %s\n' \
        "$scratch_root" >&2
      ;;
  esac
}
trap cleanup EXIT

install -d -m 0700 -- "$scratch_parent"
scratch_root="$("$system_mktemp" -d "${scratch_prefix}XXXXXXXX")"
if [[ "$scratch_root" != "$scratch_prefix"???????? ]] ||
  [[ -L "$scratch_root" ]] || [[ ! -d "$scratch_root" ]] ||
  [[ "$(realpath -e -- "$scratch_root")" != "$scratch_root" ]] ||
  [[ "$(stat -c '%u' -- "$scratch_root")" != "$(id -u)" ]] ||
  [[ "$(stat -c '%a' -- "$scratch_root")" != 700 ]]; then
  printf '%s\n' 'inventory scratch allocation escaped its private prefix' >&2
  exit 1
fi
readonly scratch_parent scratch_prefix system_mktemp system_stat scratch_root
private_temporary="$scratch_root/private"
fake_bin="$scratch_root/bin"
nonowner_bin="$scratch_root/nonowner-bin"
readonly private_temporary fake_bin nonowner_bin

install -d -m 0700 -- "$private_temporary" "$fake_bin" "$nonowner_bin"

expect_scratch_rejection() {
  local expected="$1"
  local expected_marker="$2"
  shift 2
  local stderr_path="$scratch_root/stderr"

  if "$@" 2> "$stderr_path"; then
    printf 'inventory tool accepted invalid scratch: %s\n' "$expected" >&2
    exit 1
  fi
  if ! grep -Fq 'TMPDIR must' "$stderr_path"; then
    printf 'inventory tool did not explain scratch rejection: %s\n' "$expected" >&2
    exit 1
  fi
  if [[ -n "$expected_marker" ]] &&
    ! grep -Fxq "$expected_marker" "$stderr_path"; then
    printf 'inventory tool did not exercise the expected rejection: %s\n' \
      "$expected" >&2
    exit 1
  fi
}

expect_both_tools_reject_scratch() {
  local expected="$1"
  local expected_marker="$2"
  shift 2

  expect_scratch_rejection "$expected-renderer" "$expected_marker" \
    "$@" "$script_directory/render-runner-inventory.sh" missing.json
  expect_scratch_rejection "$expected-validator" "$expected_marker" \
    "$@" "$script_directory/validate-runner-deployment.sh" \
    missing-agent.yml missing-inventory.json missing-staged.prom missing-published.prom
}

expect_both_tools_reject_scratch unset '' env -u TMPDIR
expect_both_tools_reject_scratch relative '' env TMPDIR=relative

install -d -m 0700 -- "$scratch_root/real-parent"
ln -s -- "$scratch_root/real-parent" "$scratch_root/link-parent"
expect_both_tools_reject_scratch symlink '' \
  env TMPDIR="$scratch_root/link-parent"

install -d -m 0755 -- "$scratch_root/shared"
expect_both_tools_reject_scratch shared '' \
  env TMPDIR="$scratch_root/shared"

cat > "$nonowner_bin/stat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == -c ]] && [[ ${2:-} == '%u' ]]; then
  printf '%s\n' 'AUTOMATA_TEST_NONOWNER_STAT' >&2
  printf '%s\n' "$FAKE_STAT_UID"
  exit 0
fi
exec "$REAL_STAT" "$@"
EOF
chmod 0700 -- "$nonowner_bin/stat"
expect_both_tools_reject_scratch nonowner AUTOMATA_TEST_NONOWNER_STAT \
  env \
  PATH="$nonowner_bin:$PATH" \
  REAL_STAT="$system_stat" \
  FAKE_STAT_UID="$(( $(id -u) + 1 ))" \
  TMPDIR="$private_temporary"

cat > "$fake_bin/mktemp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$FAKE_MKTEMP_COUNT_FILE" ]]; then
  count="$(< "$FAKE_MKTEMP_COUNT_FILE")"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_MKTEMP_COUNT_FILE"
if ((count == 2)); then
  printf '%s\n' 'AUTOMATA_TEST_INJECTED_MKTEMP_FAILURE' >&2
  exit 73
fi
exec "$REAL_MKTEMP" "$@"
EOF
chmod 0700 -- "$fake_bin/mktemp"

if PATH="$fake_bin:$PATH" \
  REAL_MKTEMP="$system_mktemp" \
  FAKE_MKTEMP_COUNT_FILE="$scratch_root/mktemp-count" \
  TMPDIR="$private_temporary" \
  "$script_directory/validate-runner-deployment.sh" \
  missing-agent.yml missing-inventory.json missing-staged.prom missing-published.prom \
  > "$scratch_root/stdout" 2> "$scratch_root/stderr"; then
  printf '%s\n' 'validator unexpectedly survived injected second allocation failure' >&2
  exit 1
fi

if [[ ! -f "$scratch_root/mktemp-count" ]] ||
  [[ "$(< "$scratch_root/mktemp-count")" != 2 ]] ||
  ! grep -Fxq 'AUTOMATA_TEST_INJECTED_MKTEMP_FAILURE' "$scratch_root/stderr"; then
  printf '%s\n' 'validator did not reach the injected second allocation failure' >&2
  exit 1
fi

if find "$private_temporary" -mindepth 1 -print -quit | grep -q .; then
  printf '%s\n' 'validator leaked an earlier snapshot after allocation failure' >&2
  exit 1
fi

printf '%s\n' 'runner inventory scratch contract verified'
