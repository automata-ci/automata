#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly repository_root

die() {
  printf 'prepare-container-context: %s\n' "$*" >&2
  exit 1
}

if (( $# != 3 )); then
  die "usage: $0 ARCHIVE CONTEXT_DIRECTORY EXPECTED_VERSION"
fi

archive="$1"
context_directory="$2"
expected_version="$3"
readonly archive context_directory expected_version

[[ -f "$archive" ]] || die "release archive does not exist: $archive"
[[ -n "$expected_version" && "$expected_version" != *$'\n'* ]] \
  || die "expected version must be one non-empty line"

if [[ -e "$context_directory" ]]; then
  [[ -d "$context_directory" ]] || die "context path is not a directory: $context_directory"
  [[ -z "$(find "$context_directory" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || die "context directory is not empty: $context_directory"
else
  install -d -m 0700 -- "$context_directory"
fi

tar -xzf "$archive" -C "$context_directory" \
  LICENSE \
  SHA256SUMS \
  THIRD_PARTY_LICENSES.txt \
  THIRD_PARTY_NOTICES.txt \
  VERSION \
  automata \
  automata-runner \
  sbom

(
  cd "$context_directory"
  sha256sum --check --strict SHA256SUMS
)

[[ "$(wc -l < "$context_directory/VERSION")" -eq 1 ]] \
  || die "release VERSION must contain exactly one line"
actual_version="$(<"$context_directory/VERSION")"
[[ "$actual_version" == "$expected_version" ]] \
  || die "release version $actual_version does not match expected version $expected_version"

# Keep the archive/context contract coupled to both Containerfiles. Docker
# otherwise reports a missing COPY source only after publication has begun.
python3 - "$repository_root" "$context_directory" <<'PY'
import pathlib
import shlex
import sys

repository_root = pathlib.Path(sys.argv[1])
context = pathlib.Path(sys.argv[2]).resolve()
containerfiles = (
    repository_root / "images/automata.Containerfile",
    repository_root / "images/automata-runner.Containerfile",
)

for containerfile in containerfiles:
    logical_lines: list[str] = []
    pending = ""
    for physical_line in containerfile.read_text(encoding="utf-8").splitlines():
        stripped = physical_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending += stripped
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical_lines.append(pending)
        pending = ""
    if pending:
        raise SystemExit(f"{containerfile}: unterminated continuation")

    for line in logical_lines:
        fields = shlex.split(line, comments=True, posix=True)
        if not fields or fields[0].upper() != "COPY":
            continue
        arguments = [field for field in fields[1:] if not field.startswith("--")]
        if len(arguments) < 2:
            raise SystemExit(f"{containerfile}: unsupported COPY instruction: {line}")
        for source in arguments[:-1]:
            if any(character in source for character in "$*?["):
                raise SystemExit(
                    f"{containerfile}: COPY source must be an exact context path: {source}"
                )
            resolved = (context / source).resolve()
            if context not in resolved.parents and resolved != context:
                raise SystemExit(f"{containerfile}: COPY source escapes context: {source}")
            if not resolved.exists():
                raise SystemExit(
                    f"{containerfile}: COPY source is absent from release context: {source}"
                )
PY

printf 'Prepared verified image context at %s\n' "$context_directory"
