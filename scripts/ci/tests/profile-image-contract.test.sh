#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

if [[ "${0##*/}" == podman ]]; then
    : "${FAKE_PODMAN_LOG:?}"
    case "${1:-} ${2:-}" in
        'image inspect')
            printf 'inspect\n' >> "${FAKE_PODMAN_LOG}"
            cat <<'JSON'
[{"Os":"linux","Architecture":"amd64","Config":{"User":"0:0","WorkingDir":"/__w","Cmd":["/bin/sleep","infinity"],"Labels":{"org.opencontainers.image.title":"Automata GitHub-hosted Ubuntu 24.04 x64 compatibility profile","org.opencontainers.image.source":"https://github.com/automata-ci/automata","org.opencontainers.image.licenses":"MIT","org.opencontainers.image.revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","org.opencontainers.image.version":"automata.dev/github-hosted-ubuntu-24-04-x64-v1","io.automata.environment-profile":"automata.dev/github-hosted-ubuntu-24-04-x64-v1"},"Env":["AUTOMATA_ENVIRONMENT_PROFILE_ID=automata.dev/github-hosted-ubuntu-24-04-x64-v1","CARGO_HOME=/opt/cargo","RUSTUP_HOME=/opt/rustup","RUNNER_TOOL_CACHE=/opt/hostedtoolcache"]},"RootFS":{"Layers":["sha256:1111111111111111111111111111111111111111111111111111111111111111"]}}]
JSON
            ;;
        'run --rm')
            printf 'run\n' >> "${FAKE_PODMAN_LOG}"
            ;;
        *)
            fail "unexpected fake Podman request: $*"
            ;;
    esac
    exit 0
fi

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"

automata_init_target_root "${repository_root}"
scratch_root="$(
    automata_canonical_exact_target_child \
        "${repository_root}/target/task-tmp/profile-image-contract-test" \
        "profile image contract test root"
)"
readonly scratch_root
install -d -m 0700 -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
readonly scratch_directory
cleanup() {
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

fake_bin="${scratch_directory}/bin"
fake_log="${scratch_directory}/podman.log"
profile_directory="${repository_root}/images/github-hosted-ubuntu-24.04-x64"
readonly fake_bin fake_log profile_directory
install -d -m 0700 -- "${fake_bin}"
install -m 0755 -- "${BASH_SOURCE[0]}" "${fake_bin}/podman"

run_verifier() {
    env \
        PATH="${fake_bin}:${PATH}" \
        FAKE_PODMAN_LOG="${fake_log}" \
        "${profile_directory}/verify-profile-image.sh" "$@"
}

: > "${fake_log}"
run_verifier 'registry.example/profile@sha256:1111111111111111111111111111111111111111111111111111111111111111' \
    >/dev/null
[[ "$(<"${fake_log}")" == $'inspect\nrun' ]] || \
    fail 'valid schema-v2 profile did not reach the isolated image probe'

invalid_manifest="${scratch_directory}/invalid-profile-manifest.json"
readonly invalid_manifest
python3 - "${profile_directory}/profile-manifest.json" "${invalid_manifest}" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
del manifest["software_inventory"]["tools"]["node24"]
pathlib.Path(sys.argv[2]).write_text(json.dumps(manifest, indent=2) + "\n")
PY

: > "${fake_log}"
if run_verifier \
    'registry.example/profile@sha256:1111111111111111111111111111111111111111111111111111111111111111' \
    "${invalid_manifest}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    >"${scratch_directory}/invalid.stdout" \
    2>"${scratch_directory}/invalid.stderr"; then
    fail 'profile verifier accepted a missing required tool'
fi
grep -Fq -- \
    'software inventory tool set differs from the reviewed profile' \
    "${scratch_directory}/invalid.stderr" || \
    fail 'profile verifier did not retain the stable inventory failure reason'
[[ "$(<"${fake_log}")" == inspect ]] || \
    fail 'invalid inventory reached the image execution probe'

printf '%s\n' 'profile image schema-v2 inventory contract passed'
