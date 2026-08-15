#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

die() {
  printf 'service-proxy-candidate: %s\n' "$*" >&2
  exit 1
}

if (( $# != 2 )); then
  die "usage: $0 CONTEXT OUTPUT_DIRECTORY"
fi
context="$1"
output_directory="$2"
[[ "$context" == /* ]] || context="${repository_root}/${context}"
[[ "$output_directory" == /* ]] || output_directory="${repository_root}/${output_directory}"
automata_init_target_root "$repository_root"
context="$(automata_canonical_exact_target_child "$context" "service-proxy context")"
output_directory="$(
  automata_canonical_exact_target_child \
    "$output_directory" \
    "service-proxy candidate output"
)"
automata_set_target_tmpdir \
  "$repository_root" \
  "${repository_root}/target/task-tmp/service-proxy-candidate"
readonly context output_directory
[[ -d "$context" && ! -L "$context" ]] || die "prepared context is missing"
[[ ! -e "$output_directory" ]] || die "output directory already exists"

builder="${AUTOMATA_SERVICE_PROXY_OCI_BUILDER:-podman}"
case "$builder" in
  podman | buildah-chroot) ;;
  *) die "AUTOMATA_SERVICE_PROXY_OCI_BUILDER must be podman or buildah-chroot" ;;
esac
process_probe="${AUTOMATA_SERVICE_PROXY_PROCESS_PROBE:-required}"
case "$process_probe" in
  required | metadata-only) ;;
  *) die "AUTOMATA_SERVICE_PROXY_PROCESS_PROBE must be required or metadata-only" ;;
esac
if [[ "$builder" == podman ]]; then
  runtime="${AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME:-podman}"
  [[ "$runtime" == podman ]] || die "Podman candidate builds require the Podman runtime"
  command -v podman >/dev/null 2>&1 || die "Podman is unavailable"
else
  runtime="${AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME:-buildah}"
  [[ "$runtime" == buildah ]] || \
    die "buildah-chroot candidate builds require the Buildah image runtime"
  command -v buildah >/dev/null 2>&1 || die "Buildah is unavailable"
  [[ "$process_probe" == metadata-only ]] || \
    die "buildah-chroot candidate builds require metadata-only process verification"
fi
readonly builder process_probe runtime

install -d -m 0700 -- "$output_directory"

# Rootless OverlayFS records its private origin/impure bookkeeping as PAX
# xattrs in exported layers on Ubuntu's Podman 4.x stack. Build this tiny
# scratch image in an isolated VFS store so builder-only overlay metadata can
# never enter the immutable candidate or its reviewed digest.
storage_directory="$(mktemp -d "$TMPDIR/podman-vfs.XXXXXXXX")"
storage_config="$storage_directory/storage.conf"
storage_graphroot="$storage_directory/graphroot"
storage_runroot="$storage_directory/runroot"
install -d -m 0700 -- "$storage_graphroot" "$storage_runroot"
install -m 0600 /dev/null "$storage_config"
printf '%s\n' \
  '[storage]' \
  'driver = "vfs"' \
  "graphroot = \"$storage_graphroot\"" \
  "runroot = \"$storage_runroot\"" >"$storage_config"
unset STORAGE_DRIVER STORAGE_OPTS
export CONTAINERS_STORAGE_CONF="$storage_config"
readonly storage_directory storage_config storage_graphroot storage_runroot

tag="localhost/automata-ci/service-proxy:candidate-${BASHPID}"
readonly tag
cleanup() {
  case "$builder" in
    podman) podman image rm --force "$tag" >/dev/null 2>&1 || true ;;
    buildah-chroot) buildah rmi --force "$tag" >/dev/null 2>&1 || true ;;
  esac
  if [[ "$storage_directory" == "$TMPDIR"/podman-vfs.* \
    && -d "$storage_directory" \
    && ! -L "$storage_directory" ]]; then
    rm -rf -- "$storage_directory"
  fi
}
trap cleanup EXIT

mapfile -t source_values < <(python3 - "$context/source-provenance.json" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
contents = path.read_bytes()
document = json.loads(contents)
print(document["release"]["version"])
print(document["release"]["revision"])
print(document["release"]["created"])
print(document["release"]["source_date_epoch"])
print(document["artifacts"]["binary_sha256"])
print(document["artifacts"]["sbom_sha256"])
print(hashlib.sha256(contents).hexdigest())
PY
)
(( ${#source_values[@]} == 7 )) || die "source provenance is incomplete"
version="${source_values[0]}"
revision="${source_values[1]}"
created="${source_values[2]}"
source_date_epoch="${source_values[3]}"
binary_sha256="${source_values[4]}"
sbom_sha256="${source_values[5]}"
source_sha256="${source_values[6]}"
readonly version revision created source_date_epoch binary_sha256 sbom_sha256 source_sha256

build_arguments=(
  --build-arg "AUTOMATA_CREATED=${created}"
  --build-arg "AUTOMATA_REVISION=${revision}"
  --build-arg "AUTOMATA_SERVICE_PROXY_BINARY_SHA256=${binary_sha256}"
  --build-arg "AUTOMATA_SERVICE_PROXY_SBOM_SHA256=${sbom_sha256}"
  --build-arg "AUTOMATA_SERVICE_PROXY_SOURCE_SHA256=${source_sha256}"
  --build-arg "AUTOMATA_VERSION=${version}"
  --file "$context/Containerfile"
  --format oci
  --identity-label=false
  --pull=never
  --timestamp "$source_date_epoch"
  --tag "$tag"
)
readonly -a build_arguments
if [[ "$builder" == podman ]]; then
  env -u SOURCE_DATE_EPOCH podman build \
    "${build_arguments[@]}" \
    --network none \
    "$context"
  AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME="$runtime" \
    AUTOMATA_SERVICE_PROXY_PROCESS_PROBE="$process_probe" \
    "${script_directory}/verify-service-proxy-image.sh" \
    "$tag" "$version" "$revision" "$created"
else
  # Chroot isolation in the nested Automata job cannot create another network
  # namespace. Host networking is inert because this exact reviewed scratch
  # Containerfile contains metadata and local COPY instructions, but no RUN.
  python3 "${script_directory}/validate-service-proxy-buildah-containerfile.py" \
    "$context/Containerfile"
  env -u SOURCE_DATE_EPOCH buildah bud \
    "${build_arguments[@]}" \
    --isolation chroot \
    --network host \
    "$context"
  AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME="$runtime" \
    AUTOMATA_SERVICE_PROXY_PROCESS_PROBE="$process_probe" \
    "${script_directory}/verify-service-proxy-image.sh" \
    "$tag" "$version" "$revision" "$created"
fi

oci_archive="$output_directory/automata-service-proxy.oci.tar"
candidate="$output_directory/automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar"
if [[ "$builder" == podman ]]; then
  podman save --format oci-archive --output "$oci_archive" "$tag"
else
  buildah push "$tag" "oci-archive:${oci_archive}"
fi
candidate_arguments=(
  --context "$context"
  --oci-archive "$oci_archive"
  --output "$candidate"
)
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  candidate_arguments+=(--github-output "$GITHUB_OUTPUT")
fi
python3 "${script_directory}/service-proxy-candidate.py" "${candidate_arguments[@]}"
rm -f -- "$oci_archive"
printf 'Prepared unpublished service-proxy OCI candidate at %s\n' "$candidate"
