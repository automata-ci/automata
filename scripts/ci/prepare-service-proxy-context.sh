#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly script_directory repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

die() {
  printf 'service-proxy-context: %s\n' "$*" >&2
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
python3 - "$created" "$source_date_epoch" <<'PY'
import datetime
import re
import sys

created, source_date_epoch = sys.argv[1:]
if re.fullmatch(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})",
    created,
) is None:
    raise SystemExit("service-proxy-context: created timestamp is not canonical RFC 3339")
try:
    parsed = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
except ValueError:
    raise SystemExit("service-proxy-context: created timestamp is invalid") from None
if parsed.utcoffset() is None or int(parsed.timestamp()) != int(source_date_epoch):
    raise SystemExit("service-proxy-context: release timestamps differ")
PY

automata_init_target_root "$repository_root"
if [[ "$context" != /* ]]; then
  context="${repository_root}/${context}"
fi
context="$(automata_canonical_target_child "$context" "service-proxy image context")"
readonly context
if [[ -e "$context" ]]; then
  [[ -d "$context" && -z "$(find "$context" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || die "context must be an absent or empty target directory"
else
  install -d -m 0700 -- "$context"
fi

target_directory="${CARGO_TARGET_DIR:-target}"
if [[ "$target_directory" != /* ]]; then
  target_directory="${repository_root}/${target_directory}"
fi
target_directory="$(automata_canonical_target_path "$target_directory" "Cargo target directory")"
binary="${target_directory}/x86_64-unknown-linux-musl/release/automata-ci-service-proxy"
sbom="${target_directory}/distribution-input/sbom/automata-ci-service-proxy.cdx.json"
license_directory="${target_directory}/distribution-input/licenses"
containerfile="${repository_root}/images/service-proxy/Containerfile"
readonly target_directory binary sbom license_directory containerfile

"${script_directory}/verify-service-proxy-static.sh" "$binary"
for required in \
  "$sbom" \
  "$license_directory/THIRD_PARTY_LICENSES.txt" \
  "$license_directory/THIRD_PARTY_NOTICES.txt" \
  "$containerfile"
do
  [[ -f "$required" && ! -L "$required" ]] || die "required image input is missing"
done

install -m 0555 -- "$binary" "$context/automata-ci-service-proxy"
install -m 0444 -- "$repository_root/LICENSE" "$context/LICENSE"
install -m 0444 -- \
  "$license_directory/THIRD_PARTY_LICENSES.txt" \
  "$context/THIRD_PARTY_LICENSES.txt"
install -m 0444 -- \
  "$license_directory/THIRD_PARTY_NOTICES.txt" \
  "$context/THIRD_PARTY_NOTICES.txt"
install -m 0444 -- "$containerfile" "$context/Containerfile"
install -d -m 0755 -- "$context/sbom"
install -m 0444 -- "$sbom" "$context/sbom/automata-ci-service-proxy.cdx.json"
chmod 0555 -- "$context/sbom"
printf '%s\n' "$version" > "$context/VERSION"
chmod 0444 -- "$context/VERSION"

python3 - \
  "$context" "$version" "$revision" "$created" "$source_date_epoch" <<'PY'
import hashlib
import json
import pathlib
import sys

context = pathlib.Path(sys.argv[1])
version, revision, created = sys.argv[2:5]
source_date_epoch = int(sys.argv[5])

def digest(relative: str) -> str:
    return hashlib.sha256((context / relative).read_bytes()).hexdigest()

document = {
    "artifacts": {
        "binary_sha256": digest("automata-ci-service-proxy"),
        "containerfile_sha256": digest("Containerfile"),
        "sbom_sha256": digest("sbom/automata-ci-service-proxy.cdx.json"),
    },
    "release": {
        "created": created,
        "revision": revision,
        "source_date_epoch": source_date_epoch,
        "version": version,
    },
    "schema_version": 1,
}
(context / "source-provenance.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
chmod 0444 -- "$context/source-provenance.json"
printf 'Prepared service-proxy image context at %s\n' "$context"
