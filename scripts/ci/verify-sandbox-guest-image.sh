#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

die() {
  printf 'sandbox-guest-image: %s\n' "$*" >&2
  exit 1
}

if (( $# != 5 )); then
  die "usage: $0 CONTEXT VERSION REVISION CREATED SOURCE_DATE_EPOCH"
fi
context="$1"
version="$2"
revision="$3"
created="$4"
source_date_epoch="$5"
readonly version revision created source_date_epoch

[[ -n "$version" && ${#version} -le 120 && "$version" != *$'\n'* && "$version" != *$'\r'* ]] \
  || die "version must be one bounded non-empty line"
[[ "$revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
  || die "revision must be one complete lowercase Git object ID"
[[ -n "$created" && "$created" != *$'\n'* && "$created" != *$'\r'* ]] \
  || die "created timestamp must be one non-empty line"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] \
  || die "SOURCE_DATE_EPOCH must be Unix seconds"
(( ${#source_date_epoch} <= 10 && 10#$source_date_epoch <= 8589934591 )) \
  || die "SOURCE_DATE_EPOCH exceeds the canonical archive limit"
command -v docker >/dev/null 2>&1 || die "Docker is required"
command -v python3 >/dev/null 2>&1 || die "Python 3 is required"
python3 - "$created" "$source_date_epoch" <<'PY'
import datetime
import re
import sys

created, source_date_epoch = sys.argv[1:]
if re.fullmatch(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})",
    created,
) is None:
    raise SystemExit("sandbox-guest-image: created timestamp is not canonical RFC 3339")
try:
    parsed = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
except ValueError:
    raise SystemExit("sandbox-guest-image: created timestamp is invalid") from None
if parsed.utcoffset() is None or int(parsed.timestamp()) != int(source_date_epoch):
    raise SystemExit("sandbox-guest-image: release timestamps differ")
PY

automata_init_target_root "$repository_root"
if [[ "$context" != /* ]]; then
  context="${repository_root}/${context}"
fi
context="$(
  automata_canonical_exact_target_child \
    "$context" \
    "sandbox-guest image context"
)"
readonly context
[[ -d "$context" && ! -L "$context" ]] \
  || die "sandbox-guest image context is missing"

for required in \
  Containerfile \
  LICENSE \
  THIRD_PARTY_LICENSES.txt \
  THIRD_PARTY_NOTICES.txt \
  VERSION \
  automata-ci-sandbox-guest \
  sbom/automata-ci-sandbox-guest.cdx.json
do
  [[ -f "$context/$required" && ! -L "$context/$required" ]] \
    || die "prepared image context is missing $required"
done
[[ -d "$context/sbom" && ! -L "$context/sbom" ]] \
  || die "prepared image context has an invalid SBOM directory"
actual_context_entries="$(
  find -P "$context" -mindepth 1 -printf '%P\n' | LC_ALL=C sort
)"
expected_context_entries="$({
  printf '%s\n' \
    Containerfile \
    LICENSE \
    THIRD_PARTY_LICENSES.txt \
    THIRD_PARTY_NOTICES.txt \
    VERSION \
    automata-ci-sandbox-guest \
    sbom \
    sbom/automata-ci-sandbox-guest.cdx.json
})"
readonly actual_context_entries expected_context_entries
[[ "$actual_context_entries" == "$expected_context_entries" ]] \
  || die "prepared image context has a noncanonical entry set"
cmp -s "$context/Containerfile" \
  "$repository_root/images/automata-sandbox-guest.Containerfile" \
  || die "prepared image context has a stale Containerfile"
cmp -s "$context/VERSION" <(printf '%s\n' "$version") \
  || die "prepared image context has a stale VERSION"

automata_set_target_tmpdir \
  "$repository_root" \
  "$repository_root/target/task-tmp/sandbox-guest-image"
scratch_directory="$(mktemp -d "$TMPDIR/sandbox-guest-image.XXXXXXXX")"
image_suffix="${scratch_directory##*.}"
image="automata-ci/sandbox-guest-verification:${image_suffix}"
readonly scratch_directory image_suffix image
image_built=0
cleanup() {
  local cleanup_status=$?
  trap - EXIT
  if (( image_built )); then
    docker image rm --force "$image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$scratch_directory"
  exit "$cleanup_status"
}
trap cleanup EXIT

docker build \
  --no-cache \
  --network none \
  --platform linux/amd64 \
  --pull=false \
  --file "$context/Containerfile" \
  --tag "$image" \
  --build-arg "AUTOMATA_CREATED=$created" \
  --build-arg "AUTOMATA_REVISION=$revision" \
  --build-arg "AUTOMATA_VERSION=$version" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  "$context" \
  || die "Docker failed to build the sandbox-guest image"
image_built=1

docker image inspect "$image" >"$scratch_directory/inspection.json" \
  || die "Docker failed to inspect the sandbox-guest image"
python3 - \
  "$scratch_directory/inspection.json" \
  "$version" \
  "$revision" \
  "$created" <<'PY'
import json
import pathlib
import sys


def fail(message: str) -> None:
    raise SystemExit(f"sandbox-guest-image: {message}")


try:
    inspection = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
except (OSError, json.JSONDecodeError):
    fail("image inspection is not valid JSON")
version, revision, created = sys.argv[2:5]
if not isinstance(inspection, list) or len(inspection) != 1:
    fail("image inspection was not singular")
image = inspection[0]
if not isinstance(image, dict):
    fail("image inspection entry is invalid")
if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
    fail("image platform is not linux/amd64")
if image.get("Variant") not in (None, ""):
    fail("image declares an unexpected platform variant")
rootfs = image.get("RootFS")
if not isinstance(rootfs, dict) or rootfs.get("Type") != "layers":
    fail("image root filesystem is invalid")

config = image.get("Config")
if not isinstance(config, dict):
    fail("image configuration is missing")
expected_labels = {
    "io.automata.sandbox-guest.protocol-version": "3",
    "org.opencontainers.image.created": created,
    "org.opencontainers.image.description": (
        "Fixed protocol guest for Automata local job sandboxes"
    ),
    "org.opencontainers.image.documentation": (
        "https://github.com/automata-ci/automata/blob/main/"
        "crates/automata-ci-sandbox-guest/README.md"
    ),
    "org.opencontainers.image.licenses": "MIT",
    "org.opencontainers.image.revision": revision,
    "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.title": "Automata Sandbox Guest",
    "org.opencontainers.image.url": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.version": version,
}
if config.get("Labels") != expected_labels:
    fail("image labels differ")
if config.get("Entrypoint") != ["/usr/local/bin/automata-ci-sandbox-guest"]:
    fail("image entrypoint differs")
if config.get("User") != "65532:65532":
    fail("image user differs")
if config.get("Env") != [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
]:
    fail("image environment differs")
if config.get("WorkingDir") != "/":
    fail("image working directory differs")
for field in (
    "Cmd",
    "ExposedPorts",
    "Healthcheck",
    "OnBuild",
    "Shell",
    "StopSignal",
    "Volumes",
):
    if config.get(field) is not None:
        fail(f"image declares an unexpected {field} setting")
PY

probe_silent_nonzero() {
  local probe_name="$1"
  local status
  shift
  set +e
  docker run \
    --rm \
    --network none \
    --read-only \
    --security-opt no-new-privileges \
    --cap-drop ALL \
    "$image" \
    "$@" \
    >"$scratch_directory/${probe_name}.stdout" \
    2>"$scratch_directory/${probe_name}.stderr"
  status=$?
  set -e
  (( status != 0 )) || die "$probe_name invocation unexpectedly succeeded"
  [[ ! -s "$scratch_directory/${probe_name}.stdout" ]] \
    || die "$probe_name invocation wrote to stdout"
  [[ ! -s "$scratch_directory/${probe_name}.stderr" ]] \
    || die "$probe_name invocation wrote to stderr"
}

probe_silent_nonzero empty
probe_silent_nonzero unsupported unsupported-command

printf 'Sandbox-guest image process and metadata verified\n'
