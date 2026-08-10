#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly repository_root

python3 - "${repository_root}/Cargo.toml" <<'PY'
import pathlib
import re
import sys
import tomllib

manifest_path = pathlib.Path(sys.argv[1])
version = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["workspace"]["package"]["version"]
if not isinstance(version, str) or re.fullmatch(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
    version,
) is None:
    raise SystemExit("workspace.package.version is not a supported semantic version")
print(version)
PY
