#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd)"
readonly repository_root

scratch_root="${repository_root}/target/task-tmp/integration-snapshot-test"
install -d -m 0700 -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
readonly scratch_directory
cleanup() {
    case "${scratch_directory}" in
        "${scratch_root}"/case.*) rm -rf -- "${scratch_directory}" ;;
        *) printf 'refusing to clean unexpected test scratch: %s\n' "${scratch_directory}" >&2 ;;
    esac
}
trap cleanup EXIT

fixture="${scratch_directory}/repository"
install -d -m 0700 -- \
    "${fixture}/scripts/dev" \
    "${fixture}/scripts/ci/lib"
install -m 0755 -- \
    "${repository_root}/scripts/dev/create-integration-snapshot.sh" \
    "${fixture}/scripts/dev/create-integration-snapshot.sh"
install -m 0644 -- \
    "${repository_root}/scripts/ci/lib/target-paths.sh" \
    "${fixture}/scripts/ci/lib/target-paths.sh"
printf 'target/\n' > "${fixture}/.gitignore"
printf 'committed\n' > "${fixture}/tracked.txt"
git -C "${fixture}" init --quiet
git -C "${fixture}" config user.name 'Snapshot Contract'
git -C "${fixture}" config user.email 'snapshot@automata.invalid'
git -C "${fixture}" add -- .
git -C "${fixture}" commit --quiet -m 'fixture baseline'

printf 'reviewed and staged\n' > "${fixture}/tracked.txt"
git -C "${fixture}" add -- tracked.txt
(
    cd "${fixture}"
    TMPDIR="${fixture}/target/task-tmp" \
        ./scripts/dev/create-integration-snapshot.sh target/snapshot-success
)
published_repository="${fixture}/target/snapshot-success/automata-ci/automata"
[[ "$(git --git-dir="${published_repository}" show main:tracked.txt)" == \
    'reviewed and staged' ]]

untracked_secret='AUTOMATA_TOKEN=untracked-secret-shaped-value'
printf '%s\n' "${untracked_secret}" > "${fixture}/untracked-secret.env"
untracked_secret_oid="$(
    printf '%s\n' "${untracked_secret}" |
        git -C "${fixture}" hash-object --stdin
)"
if git -C "${fixture}" cat-file -e "${untracked_secret_oid}^{blob}" 2>/dev/null; then
    printf 'untracked secret fixture unexpectedly existed as a Git blob\n' >&2
    exit 1
fi
untracked_log="${fixture}/target/untracked-secret.log"
if (
    cd "${fixture}"
    TMPDIR="${fixture}/target/task-tmp" \
        ./scripts/dev/create-integration-snapshot.sh target/untracked-rejected
) >"${untracked_log}" 2>&1; then
    printf 'snapshot accepted a nonignored untracked secret\n' >&2
    exit 1
fi
grep -F 'repository has nonignored untracked paths' "${untracked_log}" >/dev/null
[[ ! -e "${fixture}/target/untracked-rejected" ]]
if git -C "${fixture}" cat-file -e "${untracked_secret_oid}^{blob}" 2>/dev/null; then
    printf 'rejected untracked secret was written as a Git blob\n' >&2
    exit 1
fi
rm -f -- "${fixture}/untracked-secret.env"

unstaged_secret='AUTOMATA_TOKEN=unstaged-secret-shaped-value'
printf '%s\n' "${unstaged_secret}" > "${fixture}/tracked.txt"
unstaged_secret_oid="$(
    printf '%s\n' "${unstaged_secret}" |
        git -C "${fixture}" hash-object --stdin
)"
if git -C "${fixture}" cat-file -e "${unstaged_secret_oid}^{blob}" 2>/dev/null; then
    printf 'unstaged secret fixture unexpectedly existed as a Git blob\n' >&2
    exit 1
fi
unstaged_log="${fixture}/target/unstaged-secret.log"
if (
    cd "${fixture}"
    TMPDIR="${fixture}/target/task-tmp" \
        ./scripts/dev/create-integration-snapshot.sh target/unstaged-rejected
) >"${unstaged_log}" 2>&1; then
    printf 'snapshot accepted an unstaged tracked secret\n' >&2
    exit 1
fi
grep -F 'repository has unstaged tracked changes' "${unstaged_log}" >/dev/null
[[ ! -e "${fixture}/target/unstaged-rejected" ]]
if git -C "${fixture}" cat-file -e "${unstaged_secret_oid}^{blob}" 2>/dev/null; then
    printf 'rejected unstaged secret was written as a Git blob\n' >&2
    exit 1
fi
git -C "${fixture}" checkout-index --force -- tracked.txt

alternate_log="${fixture}/target/alternate-index.log"
if (
    cd "${fixture}"
    GIT_INDEX_FILE="${fixture}/target/alternate-index" \
    TMPDIR="${fixture}/target/task-tmp" \
        ./scripts/dev/create-integration-snapshot.sh target/alternate-rejected
) >"${alternate_log}" 2>&1; then
    printf 'snapshot accepted an alternate Git index\n' >&2
    exit 1
fi
grep -F 'integration snapshots require the default Git index' "${alternate_log}" >/dev/null
[[ ! -e "${fixture}/target/alternate-rejected" ]]

real_git="$(command -v git)"
wrapper_directory="${fixture}/target/failing-bin"
install -d -m 0700 -- "${wrapper_directory}"
# The generated wrapper must expand these values when it runs, not while the
# regression test writes it.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    'if [ "${AUTOMATA_SNAPSHOT_FAIL_UPDATE_SERVER_INFO:-}" = 1 ]; then' \
    '  for argument do' \
    '    [ "$argument" != update-server-info ] || exit 88' \
    '  done' \
    'fi' \
    "exec \"${real_git}\" \"\$@\"" \
    > "${wrapper_directory}/git"
chmod 0755 -- "${wrapper_directory}/git"
publication_failure_log="${fixture}/target/publication-failure.log"
if (
    cd "${fixture}"
    AUTOMATA_SNAPSHOT_FAIL_UPDATE_SERVER_INFO=1 \
    PATH="${wrapper_directory}:${PATH}" \
    TMPDIR="${fixture}/target/task-tmp" \
        ./scripts/dev/create-integration-snapshot.sh target/publication-failed
) >"${publication_failure_log}" 2>&1; then
    printf 'snapshot unexpectedly survived injected publication failure\n' >&2
    exit 1
fi
[[ ! -e "${fixture}/target/publication-failed" ]]
if compgen -G "${fixture}/target/integration-snapshot-stage.*" >/dev/null; then
    printf 'snapshot left a publication staging directory after failure\n' >&2
    exit 1
fi

printf 'integration snapshot contract verified\n'
