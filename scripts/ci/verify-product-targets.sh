#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repo_root

cargo metadata --manifest-path "$repo_root/Cargo.toml" --no-deps --format-version 1 \
  | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
actual = sorted(
    (package["name"], target["name"])
    for package in metadata["packages"]
    for target in package["targets"]
    if "bin" in target["kind"]
)
expected = [
    ("automata", "automata"),
    ("automata-runner", "automata-runner"),
]

if actual != expected:
    print(f"error: expected exactly two product binaries {expected}, found {actual}", file=sys.stderr)
    raise SystemExit(1)

print("product binary policy verified: automata, automata-runner")
'
