#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
unset GZIP TAR_OPTIONS

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
  "${repo_root}/target/task-tmp/static-package"
target_dir="$(resolve_target_dir)"
target_dir="$(
  automata_canonical_target_path "${target_dir}" "Cargo target directory"
)"
readonly target_dir
automata_binary="$target_dir/$target/release/automata"
runner_binary="$target_dir/$target/release/automata-runner"
readonly automata_binary runner_binary
[[ -x "$automata_binary" ]] || die "missing executable $automata_binary"
[[ -x "$runner_binary" ]] || die "missing executable $runner_binary"

sbom_dir="${AUTOMATA_SBOM_DIR:-$target_dir/distribution-input/sbom}"
readonly sbom_dir
readonly sbom_names=(
  automata.cdx.json
  automata-runner.cdx.json
  renderer.cdx.json
  ui-runtime.cdx.json
)
for sbom_name in "${sbom_names[@]}"; do
  [[ -f "$sbom_dir/$sbom_name" ]] || die "missing SBOM $sbom_dir/$sbom_name"
done

license_dir="${AUTOMATA_LICENSE_DIR:-$target_dir/distribution-input/licenses}"
readonly license_dir
readonly license_names=(
  THIRD_PARTY_LICENSES.txt
  THIRD_PARTY_NOTICES.txt
)
for license_name in "${license_names[@]}"; do
  [[ -f "$license_dir/$license_name" ]] || \
    die "missing third-party license material $license_dir/$license_name"
done

expected_version="${AUTOMATA_EXPECTED_VERSION:-}"
[[ -n "$expected_version" ]] || die "AUTOMATA_EXPECTED_VERSION is required"

source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -z "$source_date_epoch" ]]; then
  command -v git >/dev/null 2>&1 || die "git is required to derive SOURCE_DATE_EPOCH"
  source_date_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD 2>/dev/null)" \
    || die "SOURCE_DATE_EPOCH or a committed Git HEAD is required"
fi
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be Unix seconds"
readonly source_date_epoch

umask 022

distribution_dir="$(
  automata_canonical_exact_target_child \
    "$target_dir/distribution" \
    "distribution directory"
)"
archive_name="automata-$expected_version-$target.tar.gz"
archive_path="$distribution_dir/$archive_name"
checksum_path="$archive_path.sha256"
readonly distribution_dir archive_name archive_path checksum_path

mkdir -p -- "$distribution_dir"
staging_dir="$(mktemp -d "$distribution_dir/.staging-$target.XXXXXXXX")"
readonly staging_dir
cleanup() {
  if [[ -n "${staging_dir:-}" && -d "$staging_dir" ]]; then
    chmod u+w -- "$staging_dir" "$staging_dir/sbom" 2>/dev/null || true
    rm -rf -- "$staging_dir"
  fi
}
trap cleanup EXIT

install -m 0555 -- "$automata_binary" "$staging_dir/automata"
install -m 0555 -- "$runner_binary" "$staging_dir/automata-runner"
install -m 0444 -- "$repo_root/LICENSE" "$staging_dir/LICENSE"
for license_name in "${license_names[@]}"; do
  install -m 0444 -- "$license_dir/$license_name" "$staging_dir/$license_name"
done
install -d -m 0755 -- "$staging_dir/sbom"
for sbom_name in "${sbom_names[@]}"; do
  install -m 0444 -- "$sbom_dir/$sbom_name" "$staging_dir/sbom/$sbom_name"
done
chmod 0555 -- "$staging_dir/sbom"
(
  cd "$staging_dir"
  sha256sum \
    LICENSE \
    THIRD_PARTY_LICENSES.txt \
    THIRD_PARTY_NOTICES.txt \
    automata \
    automata-runner \
    sbom/*.cdx.json \
    >SHA256SUMS
  chmod 0444 SHA256SUMS
)

tar \
  --create \
  --gzip \
  --file "$archive_path" \
  --directory "$staging_dir" \
  --sort=name \
  --mtime="@$source_date_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  LICENSE \
  SHA256SUMS \
  THIRD_PARTY_LICENSES.txt \
  THIRD_PARTY_NOTICES.txt \
  automata \
  automata-runner \
  sbom

(
  cd "$distribution_dir"
  sha256sum "$archive_name" >"$archive_name.sha256"
  sha256sum --check "$archive_name.sha256"
)

tar --list --file "$archive_path"
printf 'Created %s and %s\n' "$archive_path" "$checksum_path"
