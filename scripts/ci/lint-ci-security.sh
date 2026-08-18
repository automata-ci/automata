#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
readonly repository_root
zizmor="$repository_root/target/ci-tools/zizmor"
readonly zizmor
if [[ ! -x "$zizmor" ]]; then
  printf 'error: install zizmor before linting CI definitions\n' >&2
  exit 2
fi
shopt -s nullglob
workflow_files=(
  "$repository_root"/.ci/workflows/*.yml
  "$repository_root"/.ci/workflows/*.yaml
)
readonly workflow_files
if (( ${#workflow_files[@]} == 0 )); then
  printf 'error: no CI workflows found to audit\n' >&2
  exit 2
fi

"$zizmor" \
  "${workflow_files[@]}" \
  "$repository_root/.github/dependabot.yml" \
  --config "$repository_root/.ci/zizmor.yml" \
  --offline \
  --collect all \
  --min-confidence low \
  --min-severity informational \
  --no-ignores \
  --persona auditor \
  --strict-collection
