#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"

if [[ $# -ne 1 ]]; then
    printf 'usage: %s TARGET_OUTPUT_ROOT\n' "$0" >&2
    exit 2
fi

automata_init_target_root "${repository_root}"
output_root="$1"
if [[ "${output_root}" != /* ]]; then
    output_root="${repository_root}/${output_root}"
fi
output_root="$(
    automata_canonical_exact_target_child \
        "${output_root}" \
        "dogfood snapshot output"
)"
if [[ -e "${output_root}" || -L "${output_root}" ]]; then
    automata_target_path_error "dogfood snapshot output already exists"
    exit 1
fi

scratch_root="${AUTOMATA_CANONICAL_TARGET_ROOT}/dogfood-snapshot-index"
install -d -m 0700 -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/capture.XXXXXXXX")"
snapshot_index="${scratch_directory}/index"

cleanup() {
    rm -f -- "${snapshot_index}" "${snapshot_index}.lock"
    rmdir -- "${scratch_directory}" 2>/dev/null || true
}
trap cleanup EXIT

GIT_INDEX_FILE="${snapshot_index}" git -C "${repository_root}" read-tree HEAD
GIT_INDEX_FILE="${snapshot_index}" git -C "${repository_root}" add -A -- .
snapshot_tree="$(
    GIT_INDEX_FILE="${snapshot_index}" git -C "${repository_root}" write-tree
)"
snapshot_commit="$(
    GIT_AUTHOR_NAME='Automata Dogfood' \
    GIT_AUTHOR_EMAIL='dogfood@automata.invalid' \
    GIT_COMMITTER_NAME='Automata Dogfood' \
    GIT_COMMITTER_EMAIL='dogfood@automata.invalid' \
    git -C "${repository_root}" commit-tree \
        "${snapshot_tree}" \
        -p HEAD <<'EOF'
Automata local dogfood snapshot
EOF
)"

bare_repository="${output_root}/GoNeuralAI/automata"
install -d -m 0755 -- "${output_root}/GoNeuralAI"
git init --quiet --bare "${bare_repository}"
git -C "${repository_root}" push \
    --quiet \
    "${bare_repository}" \
    "${snapshot_commit}:refs/heads/main"
git --git-dir="${bare_repository}" symbolic-ref HEAD refs/heads/main
git --git-dir="${bare_repository}" update-server-info

published_commit="$(
    git --git-dir="${bare_repository}" rev-parse --verify refs/heads/main
)"
if [[ "${published_commit}" != "${snapshot_commit}" ]]; then
    automata_target_path_error "published dogfood snapshot does not match its commit"
    exit 1
fi

printf 'commit=%s\n' "${snapshot_commit}"
printf 'http_root=%s\n' "${output_root}"
