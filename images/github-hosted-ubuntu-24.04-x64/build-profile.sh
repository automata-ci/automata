#!/usr/bin/env bash
set -euo pipefail

readonly image_repository="ghcr.io/automata-ci/automata-ubuntu-24.04-x64"
script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(( $# == 0 )) || die "usage: $0"
command -v podman >/dev/null 2>&1 || die "podman is required to build the profile"

automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/profile-image-build"

readonly build_tag="${image_repository}:profile-build"
podman build \
    --file "${script_directory}/Containerfile" \
    --format oci \
    --pull=always \
    --timestamp 0 \
    --tag "${build_tag}" \
    "${script_directory}"

local_image_digest="$(podman image inspect "${build_tag}" --format '{{.Digest}}')"
[[ "${local_image_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    die "podman returned an invalid local image digest: ${local_image_digest}"

printf 'local_image=%s@%s\n' "${image_repository}" "${local_image_digest}"
printf '%s\n' \
    'The local storage digest is not a registry identity: a push may recompress layers.' \
    'For an authorized publication, capture the registry digest with podman push --digestfile,' \
    'then pull and attest that exact remote digest before updating profile-manifest.json.'
