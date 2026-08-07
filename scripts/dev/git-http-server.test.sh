#!/usr/bin/env bash
set -euo pipefail

repository_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly server_script="${repository_root}/scripts/dev/git-http-server.py"

# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"
automata_init_target_root "${repository_root}"
readonly test_root="${AUTOMATA_CANONICAL_TARGET_ROOT}/git-http-server-tests"
install -d -m 0700 -- "${test_root}"
test_directory="$(mktemp -d "${test_root}/run.XXXXXXXX")"
readonly test_directory
readonly project_root="${test_directory}/projects"
readonly scratch_directory="${test_directory}/scratch"
readonly source_repository="${test_directory}/source"
readonly bare_repository="${project_root}/Example/fixture"
readonly shallow_clone="${test_directory}/shallow"
readonly exact_fetch="${test_directory}/exact"
readonly server_stdout="${test_directory}/server.stdout"
readonly server_stderr="${test_directory}/server.stderr"
server_pid=""

cleanup() {
    if [[ -n "${server_pid}" ]]; then
        kill "${server_pid}" >/dev/null 2>&1 || true
        wait "${server_pid}" 2>/dev/null || true
    fi
    rm -rf -- "${test_directory}"
}
trap cleanup EXIT

fail() {
    printf 'test failure: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_command curl
require_command git
require_command python3
require_command realpath

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "${label} unexpectedly succeeded"
    fi
}

install -d -m 0700 -- "${scratch_directory}" "${source_repository}"
install -d -m 0755 -- "${project_root}/Example"
export TMPDIR="${scratch_directory}"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export NO_PROXY=127.0.0.1
export no_proxy=127.0.0.1

git init --quiet --initial-branch=main "${source_repository}"
printf 'first\n' >"${source_repository}/fixture.txt"
git -C "${source_repository}" add fixture.txt
git -C "${source_repository}" \
    -c user.name='Automata Git HTTP Test' \
    -c user.email='git-http-test@automata.invalid' \
    commit --quiet --message=first
printf 'second\n' >>"${source_repository}/fixture.txt"
git -C "${source_repository}" add fixture.txt
git -C "${source_repository}" \
    -c user.name='Automata Git HTTP Test' \
    -c user.email='git-http-test@automata.invalid' \
    commit --quiet --message=second
expected_commit="$(git -C "${source_repository}" rev-parse --verify 'HEAD^{commit}')"
readonly expected_commit

git init --quiet --bare "${bare_repository}"
git -C "${source_repository}" push \
    --quiet "${bare_repository}" "${expected_commit}:refs/heads/main"
git --git-dir="${bare_repository}" symbolic-ref HEAD refs/heads/main

git_http_backend="$(realpath --canonicalize-existing -- "$(git --exec-path)/git-http-backend")"
readonly git_http_backend
[[ "${git_http_backend}" = /* && -x "${git_http_backend}" ]] ||
    fail "git-http-backend is not an absolute executable"

expect_failure "wildcard listener" \
    python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 0.0.0.0 \
    --port 8088
expect_failure "carrier-grade NAT listener" \
    python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 100.64.0.8 \
    --port 8088
expect_failure "loopback listener without test opt-in" \
    python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 127.0.0.1 \
    --port 0
expect_failure "non-canonical test port" \
    python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 127.0.0.1 \
    --port +0 \
    --allow-loopback-test-listener

python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 127.0.0.1 \
    --port 0 \
    --allow-loopback-test-listener \
    >"${server_stdout}" 2>"${server_stderr}" &
server_pid=$!

listen_url=""
for _attempt in {1..100}; do
    if [[ -s "${server_stdout}" ]]; then
        IFS= read -r readiness <"${server_stdout}" || true
        if [[ "${readiness:-}" =~ ^listening=(http://127\.0\.0\.1:[1-9][0-9]*/)$ ]]; then
            listen_url="${BASH_REMATCH[1]}"
            break
        fi
    fi
    kill -0 "${server_pid}" 2>/dev/null || fail "server exited before readiness"
    sleep 0.05
done
[[ -n "${listen_url}" ]] || fail "server did not become ready"
readonly listen_url
readonly repository_url="${listen_url}Example/fixture"

git clone --quiet --depth 1 --no-tags "${repository_url}" "${shallow_clone}"
[[ "$(git -C "${shallow_clone}" rev-parse --verify 'HEAD^{commit}')" == "${expected_commit}" ]] ||
    fail "shallow clone did not check out the exact commit"
[[ "$(git -C "${shallow_clone}" rev-list --count HEAD)" == 1 ]] ||
    fail "clone was not shallow"
[[ -s "${shallow_clone}/.git/shallow" ]] || fail "shallow boundary is absent"

git init --quiet "${exact_fetch}"
git -C "${exact_fetch}" remote add origin "${repository_url}"
git -C "${exact_fetch}" -c protocol.version=2 fetch \
    --quiet \
    --no-tags \
    --prune \
    --no-recurse-submodules \
    --depth=1 \
    origin \
    "+${expected_commit}:refs/remotes/origin/main"
[[ "$(git -C "${exact_fetch}" rev-parse --verify 'refs/remotes/origin/main^{commit}')" == "${expected_commit}" ]] ||
    fail "exact-SHA shallow fetch did not preserve the requested commit"

status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request DELETE "${repository_url}/info/refs?service=git-upload-pack")"
[[ "${status}" == 405 ]] || fail "unsupported method was not rejected"
status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --path-as-is "${listen_url}%2e%2e/Example/fixture/info/refs?service=git-upload-pack")"
[[ "${status}" == 404 ]] || fail "encoded traversal was not rejected"

header_status="$(python3 - "${listen_url}" <<'PY'
import socket
import sys
from urllib.parse import urlsplit

endpoint = urlsplit(sys.argv[1])
with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5) as connection:
    connection.sendall(
        b"GET /Example/fixture/info/refs?service=git-upload-pack HTTP/1.1\r\n"
        + f"Host: {endpoint.hostname}:{endpoint.port}\r\n".encode("ascii")
        + b"X-Fill: "
        + (b"a" * (33 * 1024))
        + b"\r\n\r\n"
    )
    response = connection.recv(128).split(b"\r\n", 1)[0]
print(response.decode("ascii"))
PY
)"
[[ "${header_status}" == 'HTTP/1.0 431 Request Header Fields Too Large' ]] ||
    fail "oversized headers were not rejected"

[[ ! -s "${server_stderr}" ]] || fail "successful contract emitted backend diagnostics"
printf 'smart Git HTTP shallow-clone contract verified\n'
