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
install -d -m 0700 -- "$output_directory"

runtime="${AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME:-podman}"
[[ "$runtime" == podman ]] || die "candidate builds require the Podman OCI builder"
command -v podman >/dev/null 2>&1 || die "Podman is unavailable"

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

tag="localhost/automata-ci/service-proxy:candidate-${BASHPID}"
readonly tag
cleanup() {
  podman image rm --force "$tag" >/dev/null 2>&1 || true
}
trap cleanup EXIT

podman build \
  --build-arg "AUTOMATA_CREATED=${created}" \
  --build-arg "AUTOMATA_REVISION=${revision}" \
  --build-arg "AUTOMATA_SERVICE_PROXY_BINARY_SHA256=${binary_sha256}" \
  --build-arg "AUTOMATA_SERVICE_PROXY_SBOM_SHA256=${sbom_sha256}" \
  --build-arg "AUTOMATA_SERVICE_PROXY_SOURCE_SHA256=${source_sha256}" \
  --build-arg "AUTOMATA_VERSION=${version}" \
  --file "$context/Containerfile" \
  --format oci \
  --network none \
  --pull=never \
  --timestamp "$source_date_epoch" \
  --tag "$tag" \
  "$context"

AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME=podman \
  "${script_directory}/verify-service-proxy-image.sh" \
  "$tag" "$version" "$revision" "$created"

oci_archive="$output_directory/automata-service-proxy.oci.tar"
candidate="$output_directory/automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar"
podman save --format oci-archive --output "$oci_archive" "$tag"
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
