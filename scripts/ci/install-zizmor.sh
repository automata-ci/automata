#!/usr/bin/env bash
set -euo pipefail

readonly version="1.29.0"
destination="${1:?usage: install-zizmor.sh DESTINATION_DIRECTORY}"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "$script_directory/../.." && pwd)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"
automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
  "${repository_root}" \
  "${repository_root}/target/task-tmp/zizmor-install"
if [[ "${destination}" != /* ]]; then
  destination="${repository_root}/${destination}"
fi
destination="$(
  automata_canonical_target_child "${destination}" "zizmor destination"
)"
readonly destination

case "$(uname -m)" in
  x86_64)
    readonly release_arch="x86_64"
    readonly expected_sha256="dd96df044a6e8538d5f423790f453bdd03d49e5b2bcc38214acc41a2f1297839"
    ;;
  aarch64)
    readonly release_arch="aarch64"
    readonly expected_sha256="415eaa7c0a06479a701b8e44a3e812c1047decc848ec4bede7bd6bbf49f22d20"
    ;;
  *)
    printf 'error: zizmor bootstrap does not support architecture %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

readonly archive_name="zizmor-${release_arch}-unknown-linux-gnu.tar.gz"
readonly release_url="https://github.com/zizmorcore/zizmor/releases/download/v${version}/${archive_name}"
scratch_root="${AUTOMATA_CI_SCRATCH_DIR:-$repository_root/target/ci-scratch}"
if [[ "${scratch_root}" != /* ]]; then
  scratch_root="${repository_root}/${scratch_root}"
fi
scratch_root="$(
  automata_canonical_target_child "${scratch_root}" "zizmor scratch directory"
)"
readonly scratch_root
install -d -m 0700 -- "$scratch_root"
temporary_dir="$(mktemp -d "$scratch_root/zizmor.XXXXXXXX")"
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

printf '%s  %s\n' "$expected_sha256" "$temporary_dir/$archive_name" |
  sha256sum --check --strict
tar \
  --extract \
  --gzip \
  --file "$temporary_dir/$archive_name" \
  --directory "$temporary_dir" \
  zizmor
install -d -m 0755 -- "$destination"
install -m 0555 -- "$temporary_dir/zizmor" "$destination/zizmor"
"$destination/zizmor" --version
