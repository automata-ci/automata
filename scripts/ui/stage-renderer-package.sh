#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd -P)"
build_directory="${repository_root}/target/ui-renderer"
package_directory="${repository_root}/crates/automata-ci-ui-renderer/generated"

(( $# == 0 )) || {
    printf 'usage: %s\n' "$0" >&2
    exit 1
}

"${script_directory}/verify-renderer-build.sh" "${build_directory}"
rm -rf -- "${package_directory}"
install -d -m 0755 -- "${package_directory}/assets"
install -m 0644 -- "${build_directory}/manifest.json" "${package_directory}/manifest.json"
while IFS= read -r -d '' asset; do
    install -m 0644 -- "${asset}" "${package_directory}/assets/${asset##*/}"
done < <(find "${build_directory}/assets" -maxdepth 1 -type f -print0 | sort -z)
printf 'Staged renderer build for Cargo packaging in %s\n' "${package_directory}"
