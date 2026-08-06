#!/usr/bin/env bash
set -euo pipefail

readonly version="1.7.12"
destination="${1:?usage: install-actionlint.sh DESTINATION_DIRECTORY}"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "$script_directory/../.." && pwd)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"
automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
  "${repository_root}" \
  "${repository_root}/target/task-tmp/actionlint-install"
if [[ "${destination}" != /* ]]; then
  destination="${repository_root}/${destination}"
fi
destination="$(
  automata_canonical_target_child "${destination}" "actionlint destination"
)"
readonly destination

case "$(uname -m)" in
  x86_64)
    readonly release_arch="amd64"
    readonly expected_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
    ;;
  aarch64)
    readonly release_arch="arm64"
    readonly expected_sha256="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"
    ;;
  *)
    printf 'error: actionlint bootstrap does not support architecture %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

readonly archive_name="actionlint_${version}_linux_${release_arch}.tar.gz"
readonly release_url="https://github.com/rhysd/actionlint/releases/download/v${version}/${archive_name}"
scratch_root="${AUTOMATA_CI_SCRATCH_DIR:-$repository_root/target/ci-scratch}"
if [[ "${scratch_root}" != /* ]]; then
  scratch_root="${repository_root}/${scratch_root}"
fi
scratch_root="$(
  automata_canonical_target_child "${scratch_root}" "actionlint scratch directory"
)"
readonly scratch_root
install -d -m 0700 -- "$scratch_root"
temporary_dir="$(mktemp -d "$scratch_root/actionlint.XXXXXXXX")"
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

printf '%s  %s\n' "$expected_sha256" "$temporary_dir/$archive_name" | sha256sum --check --strict
tar --extract --file "$temporary_dir/$archive_name" --directory "$temporary_dir" actionlint
install -d -m 0755 -- "$destination"
install -m 0555 -- "$temporary_dir/actionlint" "$destination/actionlint"
"$destination/actionlint" -version
