#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/ci/lib/target-paths.sh
# shellcheck disable=SC1091
source "${repository_root}/scripts/ci/lib/target-paths.sh"

if [[ -n "${GIT_INDEX_FILE+x}" ]]; then
    automata_target_path_error \
        "integration snapshots require the default Git index; unset GIT_INDEX_FILE"
    exit 1
fi

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
        "integration snapshot output"
)"
if [[ -e "${output_root}" || -L "${output_root}" ]]; then
    automata_target_path_error "integration snapshot output already exists"
    exit 1
fi

default_index="$(git -C "${repository_root}" rev-parse --git-path index)"
if [[ "${default_index}" != /* ]]; then
    default_index="${repository_root}/${default_index}"
fi
if [[ -L "${default_index}" || ! -f "${default_index}" ]]; then
    automata_target_path_error "default Git index must be a regular, non-symbolic-link file"
    exit 1
fi

require_reviewed_index() {
    local _untracked_path

    if ! git -C "${repository_root}" diff \
        --quiet \
        --no-ext-diff \
        --ignore-submodules=none \
        --; then
        automata_target_path_error \
            "repository has unstaged tracked changes; review and stage or discard them"
        return 1
    fi
    git -C "${repository_root}" ls-files \
        --others \
        --exclude-standard \
        -z \
        -- >/dev/null
    if IFS= read -r -d '' _untracked_path < <(
        git -C "${repository_root}" ls-files \
            --others \
            --exclude-standard \
            -z \
            --
    ); then
        automata_target_path_error \
            "repository has nonignored untracked paths; review and stage or ignore them"
        return 1
    fi
    if [[ -n "$(git -C "${repository_root}" ls-files --unmerged --)" ]]; then
        automata_target_path_error "default Git index contains unmerged entries"
        return 1
    fi
}

require_stable_index_tree() {
    local current_tree

    require_reviewed_index || return 1
    current_tree="$(git -C "${repository_root}" write-tree)" || return 1
    if [[ "${current_tree}" != "${snapshot_tree}" ]]; then
        automata_target_path_error "default Git index changed while creating the snapshot"
        return 1
    fi
}

require_reviewed_index
snapshot_tree="$(git -C "${repository_root}" write-tree)"
require_stable_index_tree
snapshot_commit="$(
    GIT_AUTHOR_NAME='Automata Integration' \
    GIT_AUTHOR_EMAIL='integration@automata.invalid' \
    GIT_COMMITTER_NAME='Automata Integration' \
    GIT_COMMITTER_EMAIL='integration@automata.invalid' \
    git -C "${repository_root}" commit-tree \
        "${snapshot_tree}" \
        -p HEAD <<'EOF'
Automata local integration snapshot
EOF
)"

publication_stage=''
publication_prefix="${AUTOMATA_CANONICAL_TARGET_ROOT}/integration-snapshot-stage."

cleanup() {
    local publication_suffix

    if [[ -n "${publication_stage}" ]]; then
        case "${publication_stage}" in
            "${publication_prefix}"*)
                publication_suffix="${publication_stage#"${publication_prefix}"}"
                if [[ -n "${publication_suffix}" && "${publication_suffix}" != */* ]]; then
                    rm -rf -- "${publication_stage}"
                else
                    automata_target_path_error \
                        "refusing to clean an unexpected integration snapshot staging path"
                fi
                ;;
            *)
                automata_target_path_error \
                    "refusing to clean an unexpected integration snapshot staging path"
                ;;
        esac
    fi
}
trap cleanup EXIT

output_parent="$(dirname -- "${output_root}")"
install -d -m 0755 -- "${output_parent}"
confirmed_output_root="$(
    automata_canonical_exact_target_child \
        "${output_root}" \
        "integration snapshot output"
)"
if [[ "${confirmed_output_root}" != "${output_root}" ]]; then
    automata_target_path_error "integration snapshot output changed during validation"
    exit 1
fi

publication_stage="$(
    mktemp -d "${publication_prefix}XXXXXXXX"
)"
case "${publication_stage}" in
    "${publication_prefix}"*)
        publication_suffix="${publication_stage#"${publication_prefix}"}"
        if [[ -z "${publication_suffix}" || "${publication_suffix}" == */* ]]; then
            automata_target_path_error "mktemp returned an unexpected staging path"
            exit 1
        fi
        ;;
    *)
        automata_target_path_error "mktemp returned an unexpected staging path"
        exit 1
        ;;
esac
chmod 0755 -- "${publication_stage}"

bare_repository="${publication_stage}/automata-ci/automata"
install -d -m 0755 -- "${publication_stage}/automata-ci"
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
    automata_target_path_error "published integration snapshot does not match its commit"
    exit 1
fi
require_stable_index_tree

mv -T --no-clobber -- "${publication_stage}" "${output_root}"
if [[ -e "${publication_stage}" || -L "${publication_stage}" ]]; then
    automata_target_path_error "integration snapshot output appeared during publication"
    exit 1
fi
publication_stage=''

printf 'commit=%s\n' "${snapshot_commit}"
printf 'http_root=%s\n' "${output_root}"
