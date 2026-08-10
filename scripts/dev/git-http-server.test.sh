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
blocking_backend_group=""
declare -a auxiliary_server_pids=()
declare -a client_pids=()

process_is_live() {
    local pid="$1"
    local state
    state="$(ps -o stat= -p "${pid}" 2>/dev/null)" || return 1
    [[ -n "${state}" && "${state}" != Z* ]]
}

wait_until_not_live() {
    local pid="$1"
    local attempts="${2:-250}"
    local attempt
    for ((attempt = 0; attempt < attempts; attempt += 1)); do
        process_is_live "${pid}" || return 0
        sleep 0.02
    done
    ! process_is_live "${pid}"
}

terminate_and_reap() {
    local pid="$1"
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 0
    if process_is_live "${pid}"; then
        kill -TERM "${pid}" >/dev/null 2>&1 || true
        if ! wait_until_not_live "${pid}" 150; then
            kill -KILL "${pid}" >/dev/null 2>&1 || true
            wait_until_not_live "${pid}" 150 || true
        fi
    fi
    if ! process_is_live "${pid}"; then
        wait "${pid}" 2>/dev/null || true
    fi
}

cleanup() {
    local pid
    if [[ "${blocking_backend_group}" =~ ^[1-9][0-9]*$ ]]; then
        kill -KILL -- "-${blocking_backend_group}" >/dev/null 2>&1 || true
    fi
    for pid in "${auxiliary_server_pids[@]}"; do
        [[ -n "${pid}" ]] || continue
        terminate_and_reap "${pid}"
    done
    if [[ -n "${server_pid}" ]]; then
        terminate_and_reap "${server_pid}"
    fi
    for pid in "${client_pids[@]}"; do
        [[ -n "${pid}" ]] || continue
        terminate_and_reap "${pid}"
    done
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
require_command ps
require_command realpath

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "${label} unexpectedly succeeded"
    fi
}

wait_for_listen_url() {
    local label="$1"
    local pid="$2"
    local stdout_path="$3"
    local readiness=""
    local url=""

    for _attempt in {1..200}; do
        if [[ -s "${stdout_path}" ]]; then
            IFS= read -r readiness <"${stdout_path}" || true
            if [[ "${readiness:-}" =~ ^listening=(http://127\.0\.0\.1:[1-9][0-9]*/)$ ]]; then
                url="${BASH_REMATCH[1]}"
                break
            fi
        fi
        kill -0 "${pid}" 2>/dev/null || fail "${label} exited before readiness"
        sleep 0.02
    done
    [[ -n "${url}" ]] || fail "${label} did not become ready"
    printf '%s\n' "${url}"
}

started_client_pid=""
start_response_client() {
    local url="$1"
    local stderr_path="$2"
    python3 - "${url}" 2>"${stderr_path}" <<'PY' &
import socket
import sys
from urllib.parse import urlsplit

endpoint = urlsplit(sys.argv[1])
with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5) as connection:
    connection.settimeout(30)
    connection.sendall(
        b"GET /Example/fixture/info/refs?service=git-upload-pack HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n\r\n"
    )
    while connection.recv(4096):
        pass
PY
    started_client_pid=$!
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
expect_failure "deadline override on a production listener" \
    python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 192.168.0.8 \
    --port 8088 \
    --request-deadline-seconds 1

python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${scratch_directory}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 127.0.0.1 \
    --port 0 \
    --allow-loopback-test-listener \
    >"${server_stdout}" 2>"${server_stderr}" &
server_pid=$!

listen_url="$(wait_for_listen_url "server" "${server_pid}" "${server_stdout}")"
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

slow_stdout="${test_directory}/slow-server.stdout"
slow_stderr="${test_directory}/slow-server.stderr"
slow_scratch="${test_directory}/slow-scratch"
install -d -m 0700 -- "${slow_scratch}"
python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${slow_scratch}" \
    --git-http-backend "${git_http_backend}" \
    --listen-address 127.0.0.1 \
    --port 0 \
    --request-deadline-seconds 1.5 \
    --allow-loopback-test-listener \
    >"${slow_stdout}" 2>"${slow_stderr}" &
slow_server_pid=$!
slow_server_index="${#auxiliary_server_pids[@]}"
auxiliary_server_pids+=("${slow_server_pid}")
slow_url="$(
    wait_for_listen_url "deadline test server" "${slow_server_pid}" "${slow_stdout}"
)"

python3 - "${slow_url}" <<'PY'
import socket
import sys
import time
from urllib.parse import urlsplit

MAX_WAIT_SECONDS = 5.0
POLL_SECONDS = 0.02
REQUEST = (
    b"GET /Example/fixture/info/refs?service=git-upload-pack HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n\r\n"
)

endpoint = urlsplit(sys.argv[1])
address = (endpoint.hostname, endpoint.port)


def response_status() -> bytes:
    with socket.create_connection(address, timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(REQUEST)
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response).split(b"\r\n", 1)[0]


slow_connections = []
for _ in range(8):
    connection = socket.create_connection(address, timeout=2)
    connection.setblocking(False)
    connection.send(b"G")
    slow_connections.append(connection)

next_drip = time.monotonic()
saturation_deadline = time.monotonic() + MAX_WAIT_SECONDS
while True:
    now = time.monotonic()
    if now >= next_drip:
        for connection in slow_connections:
            try:
                connection.send(b"x")
            except (BlockingIOError, OSError):
                pass
        next_drip = now + 0.05
    status = response_status()
    if status == b"HTTP/1.0 503 Service Unavailable":
        break
    if now >= saturation_deadline:
        raise SystemExit(f"request slots did not saturate: {status!r}")
    time.sleep(POLL_SECONDS)

closed = [False] * len(slow_connections)
release_deadline = time.monotonic() + MAX_WAIT_SECONDS
while not all(closed):
    now = time.monotonic()
    if now >= next_drip:
        for index, connection in enumerate(slow_connections):
            if closed[index]:
                continue
            try:
                connection.send(b"x")
            except (BlockingIOError, OSError):
                closed[index] = True
        next_drip = now + 0.05
    for index, connection in enumerate(slow_connections):
        if closed[index]:
            continue
        try:
            if connection.recv(1) == b"":
                closed[index] = True
        except BlockingIOError:
            pass
        except OSError:
            closed[index] = True
    if time.monotonic() >= release_deadline:
        raise SystemExit("absolute request deadline did not release slowloris slots")
    time.sleep(POLL_SECONDS)

for connection in slow_connections:
    connection.close()

success_deadline = time.monotonic() + MAX_WAIT_SECONDS
while True:
    status = response_status()
    if status == b"HTTP/1.0 200 OK":
        break
    if time.monotonic() >= success_deadline:
        raise SystemExit(f"released request slot did not serve Git: {status!r}")
    time.sleep(POLL_SECONDS)

print("absolute slowloris deadline and slot release verified")
PY

kill "${slow_server_pid}"
if ! wait_until_not_live "${slow_server_pid}" 250; then
    kill -KILL "${slow_server_pid}" >/dev/null 2>&1 || true
    wait_until_not_live "${slow_server_pid}" 250 || true
    fail "deadline test server did not stop within the cleanup bound"
fi
if ! wait "${slow_server_pid}"; then
    fail "deadline test server did not shut down cleanly"
fi
auxiliary_server_pids[slow_server_index]=""
if [[ -s "${slow_stderr}" ]]; then
    sed 's/^/deadline server: /' "${slow_stderr}" >&2
    fail "deadline contract emitted diagnostics"
fi

blocking_backend="${test_directory}/blocking-git-http-backend"
blocking_scratch="${test_directory}/blocking-scratch"
blocking_stdout="${test_directory}/blocking-server.stdout"
blocking_stderr="${test_directory}/blocking-server.stderr"
blocking_client_stderr="${test_directory}/blocking-client.stderr"
install -d -m 0700 -- "${blocking_scratch}"
# The single-quoted fixture is expanded only when the fake backend executes.
# shellcheck disable=SC2016
printf '%s' '#!/usr/bin/env bash
set -euo pipefail
marker="${TMPDIR:?}/blocking-backend.pids"
/usr/bin/python3 -c "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.pause()" &
child_pid=$!
printf "%s %s\\n" "$$" "${child_pid}" >"${marker}"
trap "" TERM
printf "%b" "Content-Type: application/x-git-upload-pack-advertisement\\r\\n\\r\\n"
while true; do
    wait "${child_pid}" || true
done
' >"${blocking_backend}"
chmod 0700 "${blocking_backend}"

backend_deadline_scratch="${test_directory}/backend-deadline-scratch"
backend_deadline_stdout="${test_directory}/backend-deadline-server.stdout"
backend_deadline_stderr="${test_directory}/backend-deadline-server.stderr"
backend_deadline_client_stderr="${test_directory}/backend-deadline-client.stderr"
install -d -m 0700 -- "${backend_deadline_scratch}"
python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${backend_deadline_scratch}" \
    --git-http-backend "${blocking_backend}" \
    --listen-address 127.0.0.1 \
    --port 0 \
    --request-deadline-seconds 3 \
    --allow-loopback-test-listener \
    >"${backend_deadline_stdout}" 2>"${backend_deadline_stderr}" &
backend_deadline_server_pid=$!
backend_deadline_server_index="${#auxiliary_server_pids[@]}"
auxiliary_server_pids+=("${backend_deadline_server_pid}")
backend_deadline_url="$(
    wait_for_listen_url \
        "backend-deadline server" \
        "${backend_deadline_server_pid}" \
        "${backend_deadline_stdout}"
)"

start_response_client "${backend_deadline_url}" "${backend_deadline_client_stderr}"
backend_deadline_client_pid="${started_client_pid}"
backend_deadline_client_index="${#client_pids[@]}"
client_pids+=("${backend_deadline_client_pid}")

backend_deadline_marker="${backend_deadline_scratch}/blocking-backend.pids"
for _attempt in {1..250}; do
    [[ -s "${backend_deadline_marker}" ]] && break
    process_is_live "${backend_deadline_server_pid}" ||
        fail "backend-deadline server exited before backend registration"
    sleep 0.02
done
[[ -s "${backend_deadline_marker}" ]] ||
    fail "deadline backend did not publish its process group"
read -r deadline_backend_pid deadline_backend_child_pid <"${backend_deadline_marker}"
[[ "${deadline_backend_pid}" =~ ^[1-9][0-9]*$ ]] ||
    fail "invalid deadline backend PID marker"
[[ "${deadline_backend_child_pid}" =~ ^[1-9][0-9]*$ ]] ||
    fail "invalid deadline backend child PID marker"
blocking_backend_group="${deadline_backend_pid}"

for _attempt in {1..250}; do
    if ! process_is_live "${deadline_backend_pid}" &&
        ! process_is_live "${deadline_backend_child_pid}"; then
        break
    fi
    sleep 0.02
done
process_is_live "${deadline_backend_pid}" &&
    fail "backend process survived the absolute request deadline"
process_is_live "${deadline_backend_child_pid}" &&
    fail "backend process-group child survived the absolute request deadline"
blocking_backend_group=""

wait_until_not_live "${backend_deadline_client_pid}" 250 ||
    fail "deadline-expired request handler did not release its client"
if ! wait "${backend_deadline_client_pid}"; then
    fail "backend-deadline client reported an error"
fi
client_pids[backend_deadline_client_index]=""
process_is_live "${backend_deadline_server_pid}" ||
    fail "request deadline stopped the listening server"

kill -TERM "${backend_deadline_server_pid}"
wait_until_not_live "${backend_deadline_server_pid}" 250 ||
    fail "backend-deadline server did not stop within the cleanup bound"
if ! wait "${backend_deadline_server_pid}"; then
    fail "backend-deadline server did not shut down cleanly"
fi
auxiliary_server_pids[backend_deadline_server_index]=""
[[ ! -s "${backend_deadline_client_stderr}" ]] ||
    fail "backend-deadline client emitted diagnostics"
[[ ! -s "${backend_deadline_stderr}" ]] ||
    fail "backend deadline cleanup emitted diagnostics"

python3 "${server_script}" \
    --project-root "${project_root}" \
    --scratch-directory "${blocking_scratch}" \
    --git-http-backend "${blocking_backend}" \
    --listen-address 127.0.0.1 \
    --port 0 \
    --request-deadline-seconds 20 \
    --allow-loopback-test-listener \
    >"${blocking_stdout}" 2>"${blocking_stderr}" &
blocking_server_pid=$!
blocking_server_index="${#auxiliary_server_pids[@]}"
auxiliary_server_pids+=("${blocking_server_pid}")
blocking_url="$(
    wait_for_listen_url \
        "blocking-backend server" "${blocking_server_pid}" "${blocking_stdout}"
)"

start_response_client "${blocking_url}" "${blocking_client_stderr}"
blocking_client_pid="${started_client_pid}"
blocking_client_index="${#client_pids[@]}"
client_pids+=("${blocking_client_pid}")

blocking_marker="${blocking_scratch}/blocking-backend.pids"
for _attempt in {1..250}; do
    [[ -s "${blocking_marker}" ]] && break
    process_is_live "${blocking_server_pid}" ||
        fail "blocking-backend server exited before backend registration"
    sleep 0.02
done
[[ -s "${blocking_marker}" ]] || fail "blocking backend did not publish its process group"
read -r blocking_backend_pid blocking_child_pid <"${blocking_marker}"
[[ "${blocking_backend_pid}" =~ ^[1-9][0-9]*$ ]] || fail "invalid backend PID marker"
[[ "${blocking_child_pid}" =~ ^[1-9][0-9]*$ ]] || fail "invalid backend child PID marker"
blocking_backend_group="${blocking_backend_pid}"
process_is_live "${blocking_backend_pid}" || fail "blocking backend is not live"
process_is_live "${blocking_child_pid}" || fail "blocking backend child is not live"

kill -TERM "${blocking_server_pid}"
for _attempt in {1..250}; do
    process_is_live "${blocking_server_pid}" || break
    sleep 0.02
done
process_is_live "${blocking_server_pid}" && fail "SIGTERM did not stop the server"
if ! wait "${blocking_server_pid}"; then
    fail "SIGTERM backend cleanup reported failure"
fi
auxiliary_server_pids[blocking_server_index]=""

for _attempt in {1..250}; do
    if ! process_is_live "${blocking_backend_pid}" &&
        ! process_is_live "${blocking_child_pid}"; then
        break
    fi
    sleep 0.02
done
process_is_live "${blocking_backend_pid}" && fail "backend process survived shutdown"
process_is_live "${blocking_child_pid}" && fail "backend process-group child survived shutdown"

for _attempt in {1..250}; do
    process_is_live "${blocking_client_pid}" || break
    sleep 0.02
done
process_is_live "${blocking_client_pid}" && fail "request handler survived server shutdown"
if ! wait "${blocking_client_pid}"; then
    fail "blocking-backend client reported an error"
fi
client_pids[blocking_client_index]=""
[[ ! -s "${blocking_client_stderr}" ]] || fail "blocking client emitted diagnostics"
[[ ! -s "${blocking_stderr}" ]] || fail "shutdown cleanup emitted diagnostics"
blocking_backend_group=""

printf '%s\n' \
    'smart Git HTTP shallow-clone contract verified' \
    'absolute request deadline contract verified' \
    'absolute backend deadline and process-group cleanup verified' \
    'SIGTERM backend process-group cleanup verified'
