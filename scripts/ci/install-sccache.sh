#!/usr/bin/env bash
set -euo pipefail

readonly version="0.17.0"
readonly target="x86_64-unknown-linux-musl"
readonly checksum="67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006"
readonly archive_name="sccache-v${version}-${target}.tar.gz"
readonly download_url="https://github.com/mozilla/sccache/releases/download/v${version}/${archive_name}"
readonly install_root="${RUNNER_TEMP:?RUNNER_TEMP is required}/sccache-v${version}"
readonly archive="${install_root}/${archive_name}"
readonly bin_dir="${install_root}/bin"

install -d -m 0755 -- "${install_root}" "${bin_dir}"
curl --fail --location --retry 3 --retry-all-errors --output "${archive}" "${download_url}"
printf '%s  %s\n' "${checksum}" "${archive}" | sha256sum --check --strict
tar --extract --gzip --file "${archive}" --directory "${install_root}"
install -m 0755 \
  "${install_root}/sccache-v${version}-${target}/sccache" \
  "${bin_dir}/sccache"
printf '%s\n' "${bin_dir}" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
