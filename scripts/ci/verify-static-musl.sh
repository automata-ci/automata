#!/usr/bin/env bash
set -euo pipefail

readonly target="x86_64-unknown-linux-musl"
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
readonly repo_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_dir}/lib/target-paths.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

resolve_target_dir() {
  local configured="${CARGO_TARGET_DIR:-target}"
  if [[ "$configured" = /* ]]; then
    printf '%s\n' "$configured"
  else
    printf '%s/%s\n' "$repo_root" "$configured"
  fi
}

automata_init_target_root "${repo_root}"
automata_set_target_tmpdir \
  "${repo_root}" \
  "${repo_root}/target/task-tmp/static-verify"
target_dir=''
automata_binary=''
runner_binary=''
if (( $# == 0 )); then
  target_dir="$(resolve_target_dir)"
  target_dir="$(
    automata_canonical_target_path "${target_dir}" "Cargo target directory"
  )"
  automata_binary="$target_dir/$target/release/automata"
  runner_binary="$target_dir/$target/release/automata-runner"
elif (( $# == 2 )); then
  target_dir="${AUTOMATA_CANONICAL_TARGET_ROOT}"
  automata_binary="$1"
  runner_binary="$2"
else
  die "usage: $0 [PATH_TO_AUTOMATA PATH_TO_AUTOMATA_RUNNER]"
fi
readonly target_dir automata_binary runner_binary

command -v readelf >/dev/null 2>&1 || die "readelf is required (install binutils)"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

expected_version="${AUTOMATA_EXPECTED_VERSION:-}"
[[ -n "$expected_version" ]] \
  || die "AUTOMATA_EXPECTED_VERSION is required for distribution verification"

expected_git_sha="${AUTOMATA_EXPECTED_GIT_SHA:-${AUTOMATA_BUILD_GIT_SHA:-}}"
if [[ -z "$expected_git_sha" ]] && command -v git >/dev/null 2>&1; then
  expected_git_sha="$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)"
fi
if [[ ! "$expected_git_sha" =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$ ]]; then
  die "AUTOMATA_EXPECTED_GIT_SHA must be a complete 40- or 64-character Git object ID"
fi
expected_git_sha="${expected_git_sha,,}"
readonly expected_version expected_git_sha

verify_elf() {
  local binary="$1"
  local expected_name="$2"
  local version_output

  [[ -f "$binary" ]] || die "$expected_name was not built at $binary"
  [[ -x "$binary" ]] || die "$binary is not executable"

  readelf --file-header --wide "$binary" >/dev/null \
    || die "$binary is not a readable ELF executable"

  if readelf --program-headers --wide "$binary" | grep -Eq '^[[:space:]]*INTERP[[:space:]]'; then
    die "$binary contains a PT_INTERP program header"
  fi

  if readelf --dynamic --wide "$binary" 2>/dev/null | grep -Eq '\(NEEDED\)'; then
    die "$binary contains a DT_NEEDED dynamic dependency"
  fi

  version_output="$("$binary" --version)" \
    || die "$binary --version failed"
  [[ "$version_output" == "$expected_name $expected_version ($expected_git_sha)" ]] \
    || die "$binary --version returned unexpected provenance: $version_output"

  printf '%s\n' "$version_output"
  sha256sum "$binary"
}

verify_elf "$automata_binary" automata
verify_elf "$runner_binary" automata-runner

runtime="${AUTOMATA_SCRATCH_RUNTIME:-auto}"
case "$runtime" in
  auto)
    if command -v docker >/dev/null 2>&1; then
      runtime=docker
    elif command -v podman >/dev/null 2>&1; then
      runtime=podman
    else
      runtime=none
    fi
    ;;
  docker | podman | none) ;;
  *) die "AUTOMATA_SCRATCH_RUNTIME must be auto, docker, podman, or none" ;;
esac

if [[ "$runtime" == none ]]; then
  printf 'No container runtime found; direct --version smoke tests passed.\n'
  exit 0
fi

command -v "$runtime" >/dev/null 2>&1 \
  || die "AUTOMATA_SCRATCH_RUNTIME requests $runtime, but it is not available on PATH"

scratch_root="${AUTOMATA_CI_SCRATCH_DIR:-$repo_root/target/ci-scratch}"
if [[ "${scratch_root}" != /* ]]; then
  scratch_root="${repo_root}/${scratch_root}"
fi
scratch_root="$(
  automata_canonical_target_child "${scratch_root}" "static verification scratch directory"
)"
readonly scratch_root
install -d -m 0700 -- "$scratch_root"
scratch_dir="$(mktemp -d "$scratch_root/automata-static-smoke.XXXXXX")"
image_tag="automata-static-smoke:${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"

cleanup() {
  "$runtime" image rm --force "$image_tag" >/dev/null 2>&1 || true
  if [[ -n "${scratch_dir:-}" && -d "$scratch_dir" ]]; then
    rm -rf -- "$scratch_dir"
  fi
}
trap cleanup EXIT

cp -- "$automata_binary" "$scratch_dir/automata"
cp -- "$runner_binary" "$scratch_dir/automata-runner"
chmod 0555 "$scratch_dir/automata" "$scratch_dir/automata-runner"
printf '%s\n' \
  'FROM scratch' \
  'COPY automata /automata' \
  'COPY automata-runner /automata-runner' \
  'ENTRYPOINT ["/automata"]' \
  >"$scratch_dir/Containerfile"

"$runtime" build \
  --quiet \
  --file "$scratch_dir/Containerfile" \
  --tag "$image_tag" \
  "$scratch_dir"

"$runtime" run --rm --entrypoint /automata "$image_tag" --version
"$runtime" run --rm --entrypoint /automata-runner "$image_tag" --version
printf 'Static binaries executed from a scratch image.\n'
