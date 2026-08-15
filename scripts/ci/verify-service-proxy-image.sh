#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

die() {
  printf 'service-proxy-image: %s\n' "$*" >&2
  exit 1
}

if (( $# != 4 )); then
  die "usage: $0 IMAGE VERSION REVISION CREATED"
fi
image="$1"
version="$2"
revision="$3"
created="$4"
readonly image version revision created

runtime="${AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME:-auto}"
if [[ "$runtime" == auto ]]; then
  if command -v podman >/dev/null 2>&1; then
    runtime=podman
  elif command -v docker >/dev/null 2>&1; then
    runtime=docker
  else
    die "a container runtime is required"
  fi
fi
case "$runtime" in
  docker | podman) ;;
  *) die "container runtime must be docker, podman, or auto" ;;
esac
command -v "$runtime" >/dev/null 2>&1 || die "requested runtime is unavailable"

process_probe="${AUTOMATA_SERVICE_PROXY_PROCESS_PROBE:-required}"
case "$process_probe" in
  required | metadata-only) ;;
  *) die "AUTOMATA_SERVICE_PROXY_PROCESS_PROBE must be required or metadata-only" ;;
esac
readonly process_probe

automata_init_target_root "$repository_root"
automata_set_target_tmpdir \
  "$repository_root" \
  "$repository_root/target/task-tmp/service-proxy-image"
scratch_directory="$(mktemp -d "$TMPDIR/service-proxy-image.XXXXXXXX")"
readonly scratch_directory
cleanup() {
  rm -rf -- "$scratch_directory"
}
trap cleanup EXIT
"$runtime" image inspect "$image" > "$scratch_directory/inspection.json" \
  || die "candidate image is unavailable"
python3 - "$scratch_directory/inspection.json" "$version" "$revision" "$created" <<'PY'
import json
import pathlib
import sys

version, revision, created = sys.argv[2:5]
documents = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
if not isinstance(documents, list) or len(documents) != 1:
    raise SystemExit("service-proxy-image: image inspection was not singular")
config = documents[0].get("Config")
if not isinstance(config, dict):
    raise SystemExit("service-proxy-image: image configuration is missing")
labels = config.get("Labels")
expected = {
    "org.opencontainers.image.created": created,
    "org.opencontainers.image.licenses": "MIT",
    "org.opencontainers.image.revision": revision,
    "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.version": version,
    "io.automata.service-proxy.protocol-version": "1",
}
if not isinstance(labels, dict) or any(labels.get(k) != v for k, v in expected.items()):
    raise SystemExit("service-proxy-image: candidate labels differ")
for name in (
    "io.automata.service-proxy.binary.sha256",
    "io.automata.service-proxy.sbom.sha256",
    "io.automata.service-proxy.source.sha256",
):
    value = labels.get(name)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SystemExit("service-proxy-image: candidate digest label is invalid")
if config.get("Entrypoint") != ["/usr/libexec/automata-ci-service-proxy"]:
    raise SystemExit("service-proxy-image: candidate entrypoint differs")
if config.get("User") != "65532:65532":
    raise SystemExit("service-proxy-image: candidate user differs")
PY

if [[ "$process_probe" == metadata-only ]]; then
  printf 'Service-proxy image metadata verified; process probe is covered by the static binary contract\n'
  exit 0
fi

set +e
"$runtime" run --rm --network none --read-only "$image" \
  >"$scratch_directory/stdout" 2>"$scratch_directory/stderr"
status=$?
set -e
(( status != 0 )) || die "candidate accepted an absent protocol command"
[[ ! -s "$scratch_directory/stdout" ]] || die "candidate failure wrote to stdout"
cmp -s "$scratch_directory/stderr" <(
  printf 'automata-ci-service-proxy: usage-invalid\n'
) || die "candidate process diagnostic differs"

printf 'Service-proxy image process and metadata verified\n'
