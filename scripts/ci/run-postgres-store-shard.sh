#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s SHARD_NUMBER SHARD_COUNT\n' "$0" >&2
}

if (( $# != 2 )) || [[ ! "$1" =~ ^[1-9][0-9]*$ ]] || [[ ! "$2" =~ ^[1-9][0-9]*$ ]]; then
  usage
  exit 2
fi

shard_number="$1"
shard_count="$2"
if (( shard_number > shard_count )); then
  usage
  exit 2
fi

metadata="$(cargo metadata --format-version 1 --no-deps --locked)"
assignment="$(
  python3 -c '
import json
from pathlib import Path
import sys

metadata = json.load(sys.stdin)
packages = [package for package in metadata["packages"] if package["name"] == "automata-ci-store"]
if len(packages) != 1:
    raise SystemExit(f"expected one automata-ci-store package, found {len(packages)}")
weighted_targets = []
for target in packages[0]["targets"]:
    if target["kind"] != ["test"]:
        continue
    source = Path(target["src_path"]).read_text(encoding="utf-8")
    weighted_targets.append((target["name"], max(1, source.count("#[ignore"))))
if not weighted_targets:
    raise SystemExit("automata-ci-store has no integration-test targets")
shard_number = int(sys.argv[1]) - 1
shard_count = int(sys.argv[2])
loads = [0] * shard_count
shards = [[] for _ in range(shard_count)]
for name, weight in sorted(weighted_targets, key=lambda item: (-item[1], item[0])):
    selected = min(range(shard_count), key=lambda index: (loads[index], index))
    shards[selected].append(name)
    loads[selected] += weight
print(f"{len(weighted_targets)}\t{loads[shard_number]}")
print("\n".join(sorted(shards[shard_number])))
' "$shard_number" "$shard_count" <<<"$metadata"
)"
mapfile -t assignment_lines <<<"$assignment"
IFS=$'\t' read -r target_count shard_weight <<<"${assignment_lines[0]}"
selected_targets=("${assignment_lines[@]:1}")

if (( ${#selected_targets[@]} == 0 )); then
  printf 'shard %d/%d selected no integration-test targets\n' \
    "$shard_number" "$shard_count" >&2
  exit 1
fi

printf 'shard %d/%d selected %d of %d integration-test targets (weight %d):\n' \
  "$shard_number" "$shard_count" "${#selected_targets[@]}" "$target_count" "$shard_weight"
printf '  %s\n' "${selected_targets[@]}"

cargo_targets=()
for target in "${selected_targets[@]}"; do
  cargo_targets+=(--test "$target")
done
cargo test \
  -p automata-ci-store \
  "${cargo_targets[@]}" \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=1

printf 'shard %d/%d completed %d of %d integration-test targets\n' \
  "$shard_number" "$shard_count" "${#selected_targets[@]}" "$target_count"
