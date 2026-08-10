#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

fake_runtime() {
    local runtime="${0##*/}"
    local command="${1:-}"
    local image_count=0
    local mount_count=0
    local workdir_count=0
    local remove_count=0

    : "${FAKE_RUNTIME_LOG:?}"
    : "${FAKE_RUNTIME_ENV_LOG:?}"
    : "${FAKE_PULL_STATE:?}"
    : "${FAKE_EXPECTED_IMAGE:?}"
    : "${FAKE_REPOSITORY_ROOT:?}"
    printf '%s:%s\n' "${runtime}" "${command}" >> "${FAKE_RUNTIME_LOG}"

    case "${command}" in
        image)
            [[ "$#" -eq 3 && "${2:-}" == inspect && \
                "${3:-}" == "${FAKE_EXPECTED_IMAGE}" ]] || \
                fail "unexpected ${runtime} image inspection"
            [[ -e "${FAKE_PULL_STATE}" ]]
            ;;
        pull)
            [[ "$#" -eq 2 && "${2:-}" == "${FAKE_EXPECTED_IMAGE}" ]] || \
                fail "unexpected ${runtime} pull"
            : > "${FAKE_PULL_STATE}"
            ;;
        info)
            [[ "${runtime}" == docker && "$#" -eq 3 && \
                "${2:-}" == --format && \
                "${3:-}" == '{{json .SecurityOptions}}' ]] || \
                fail "unexpected ${runtime} information request"
            printf '%s\n' "${FAKE_DOCKER_SECURITY_OPTIONS:-[]}"
            ;;
        run)
            shift
            while (( $# > 0 )); do
                case "$1" in
                    --rm)
                        remove_count=$((remove_count + 1))
                        shift
                        ;;
                    --mount)
                        (( $# >= 2 )) || fail "missing ${runtime} mount value"
                        [[ "$2" == \
                            "type=bind,source=${FAKE_REPOSITORY_ROOT},target=/__w/automata/automata" ]] || \
                            fail "unexpected ${runtime} repository mount"
                        mount_count=$((mount_count + 1))
                        shift 2
                        ;;
                    --workdir)
                        (( $# >= 2 )) || fail "missing ${runtime} workdir value"
                        [[ "$2" == /__w/automata/automata ]] || \
                            fail "unexpected ${runtime} workdir"
                        workdir_count=$((workdir_count + 1))
                        shift 2
                        ;;
                    --env)
                        (( $# >= 2 )) || fail "missing ${runtime} environment value"
                        printf '%s\n' "$2" >> "${FAKE_RUNTIME_ENV_LOG}"
                        shift 2
                        ;;
                    "${FAKE_EXPECTED_IMAGE}")
                        image_count=$((image_count + 1))
                        shift
                        ;;
                    *)
                        shift
                        ;;
                esac
            done
            [[ "${image_count}" -eq 1 && "${mount_count}" -eq 1 && \
                "${workdir_count}" -eq 1 && "${remove_count}" -eq 1 ]] || \
                fail "incomplete ${runtime} profile launch"
            ;;
        *)
            fail "unexpected fake runtime command: ${runtime} ${command}"
            ;;
    esac
}

case "${0##*/}" in
    docker | podman)
        fake_runtime "$@"
        exit 0
        ;;
esac

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"

automata_init_target_root "${repository_root}"
scratch_root="$(
    automata_canonical_exact_target_child \
        "${repository_root}/target/task-tmp/renderer-profile-launcher-test" \
        "renderer profile launcher test root"
)"
readonly scratch_root
install -d -m 0700 -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
readonly scratch_directory
cleanup() {
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

fake_repository="${scratch_directory}/workspace"
fake_profile_directory="${fake_repository}/images/github-hosted-ubuntu-24.04-x64"
fake_script_directory="${fake_repository}/scripts/ui"
fake_bin_directory="${scratch_directory}/bin"
readonly fake_repository fake_profile_directory fake_script_directory fake_bin_directory
install -d -m 0755 -- \
    "${fake_profile_directory}" \
    "${fake_script_directory}" \
    "${fake_bin_directory}"
install -m 0755 -- \
    "${repository_root}/scripts/ui/reproduce-renderer-in-profile.sh" \
    "${fake_script_directory}/reproduce-renderer-in-profile.sh"
for profile_file in Containerfile profile-lock.json profile-manifest.json; do
    install -m 0644 -- \
        "${repository_root}/images/github-hosted-ubuntu-24.04-x64/${profile_file}" \
        "${fake_profile_directory}/${profile_file}"
done
install -m 0755 -- "${BASH_SOURCE[0]}" \
    "${fake_bin_directory}/docker"
install -m 0755 -- "${BASH_SOURCE[0]}" \
    "${fake_bin_directory}/podman"

expected_image="$(
    python3 - "${fake_profile_directory}/profile-manifest.json" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_bytes())["image"])
PY
)"
readonly expected_image

run_case() {
    local label="$1"
    local github_actions="$2"
    local docker_security_options="$3"
    local expected_runtime="$4"
    local runtime_log="${scratch_directory}/${label}.runtime.log"
    local environment_log="${scratch_directory}/${label}.environment.log"
    local pull_state="${scratch_directory}/${label}.pulled"
    local actual_log=''
    local expected_log=''
    local -a ownership=()

    : > "${runtime_log}"
    env -u AUTOMATA_ENVIRONMENT_PROFILE_ID -u ImageVersion \
        PATH="${fake_bin_directory}:${PATH}" \
        GITHUB_ACTIONS="${github_actions}" \
        FAKE_RUNTIME_LOG="${runtime_log}" \
        FAKE_RUNTIME_ENV_LOG="${environment_log}" \
        FAKE_PULL_STATE="${pull_state}" \
        FAKE_EXPECTED_IMAGE="${expected_image}" \
        FAKE_REPOSITORY_ROOT="${fake_repository}" \
        FAKE_DOCKER_SECURITY_OPTIONS="${docker_security_options}" \
        "${fake_script_directory}/reproduce-renderer-in-profile.sh"

    actual_log="$(<"${runtime_log}")"
    expected_log="${expected_runtime}:image
${expected_runtime}:pull
${expected_runtime}:image"
    if [[ "${expected_runtime}" == docker ]]; then
        expected_log+=$'\ndocker:info'
    fi
    expected_log+=$'\n'"${expected_runtime}:run"
    [[ "${actual_log}" == "${expected_log}" ]] || \
        fail "unexpected runtime sequence for ${label}: ${actual_log}"

    if [[ "${label}" == rootful-docker ]]; then
        mapfile -t ownership < "${environment_log}"
        [[ "${#ownership[@]}" -eq 2 && \
            "${ownership[0]}" == "AUTOMATA_RENDERER_HOST_UID=$(id -u)" && \
            "${ownership[1]}" == "AUTOMATA_RENDERER_HOST_GID=$(id -g)" ]] || \
            fail "rootful Docker did not receive exact host ownership"
    elif [[ -s "${environment_log}" ]]; then
        fail "${label} unexpectedly received host ownership"
    fi
}

run_case rootless-podman false '[]' podman
run_case rootless-docker true '["name=rootless"]' docker
run_case rootful-docker true '["name=seccomp,profile=builtin"]' docker

printf '\n# stale test input\n' >> "${fake_profile_directory}/Containerfile"
stale_runtime_log="${scratch_directory}/stale.runtime.log"
stale_error_log="${scratch_directory}/stale.error.log"
: > "${stale_runtime_log}"
if env -u AUTOMATA_ENVIRONMENT_PROFILE_ID -u ImageVersion \
    PATH="${fake_bin_directory}:${PATH}" \
    GITHUB_ACTIONS=false \
    FAKE_RUNTIME_LOG="${stale_runtime_log}" \
    FAKE_RUNTIME_ENV_LOG="${scratch_directory}/stale.environment.log" \
    FAKE_PULL_STATE="${scratch_directory}/stale.pulled" \
    FAKE_EXPECTED_IMAGE="${expected_image}" \
    FAKE_REPOSITORY_ROOT="${fake_repository}" \
    "${fake_script_directory}/reproduce-renderer-in-profile.sh" \
    >"${stale_error_log}" 2>&1; then
    fail "renderer launcher accepted a stale Containerfile digest"
fi
grep -Fq -- 'Containerfile digest is stale' "${stale_error_log}" || \
    fail "renderer launcher did not identify the stale Containerfile digest"
[[ ! -s "${stale_runtime_log}" ]] || \
    fail "renderer launcher contacted a runtime before validating its lock"

printf '%s\n' \
    'renderer profile launcher validated its lock and rootless/rootful runtime boundaries'
