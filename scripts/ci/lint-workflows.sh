#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
actionlint="$repository_root/target/ci-tools/actionlint"
if [[ ! -x "$actionlint" ]]; then
  printf 'error: install actionlint before linting workflows\n' >&2
  exit 2
fi

# `resources` is Automata's validated per-job resource extension. Keep all of
# actionlint's GitHub dialect checks while admitting exactly that extra key.
"$actionlint" \
  -ignore '^unexpected key "resources" for "job" section\.' \
  "$repository_root"/.ci/workflows/*.yml
