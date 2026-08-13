#!/usr/bin/env bash
set -euo pipefail

readonly version="1.72.0"
destination="${1:?usage: install-buf.sh DESTINATION_DIRECTORY}"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "$script_directory/../.." && pwd)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"
automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
  "${repository_root}" \
  "${repository_root}/target/task-tmp/buf-install"
if [[ "${destination}" != /* ]]; then
  destination="${repository_root}/${destination}"
fi
destination="$(
  automata_canonical_target_child "${destination}" "Buf destination"
)"
readonly destination

case "$(uname -m)" in
  x86_64)
    readonly release_arch="x86_64"
    readonly expected_sha256="a9c6186cf6fcf062b247345e1b7b12c26f580c1b2a4bbf4d3fe080abf85ceee8"
    ;;
  aarch64)
    readonly release_arch="aarch64"
    readonly expected_sha256="7641bd7e06a37a54cbb8c789f53465899def96196ab5c08057432f781a15d517"
    ;;
  *)
    printf 'error: Buf bootstrap does not support architecture %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

readonly archive_name="buf-Linux-${release_arch}.tar.gz"
readonly release_url="https://github.com/bufbuild/buf/releases/download/v${version}/${archive_name}"
scratch_root="${AUTOMATA_CI_SCRATCH_DIR:-$repository_root/target/ci-scratch}"
if [[ "${scratch_root}" != /* ]]; then
  scratch_root="${repository_root}/${scratch_root}"
fi
scratch_root="$(
  automata_canonical_target_child "${scratch_root}" "Buf scratch directory"
)"
readonly scratch_root
install -d -m 0700 -- "$scratch_root"
temporary_dir="$(mktemp -d "$scratch_root/buf.XXXXXXXX")"
readonly temporary_dir
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT

curl \
  --fail \
  --location \
  --proto '=https' \
  --retry 3 \
  --show-error \
  --silent \
  --tlsv1.2 \
  --output "$temporary_dir/$archive_name" \
  "$release_url"

printf '%s  %s\n' "$expected_sha256" "$temporary_dir/$archive_name" \
  | sha256sum --check --strict
tar \
  --extract \
  --file "$temporary_dir/$archive_name" \
  --directory "$temporary_dir" \
  buf/bin/buf
install -d -m 0755 -- "$destination"
install -m 0555 -- "$temporary_dir/buf/bin/buf" "$destination/buf"
"$destination/buf" --version
