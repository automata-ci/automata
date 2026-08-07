#!/usr/bin/env bash
set -euo pipefail

repository_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly firewall_script="${repository_root}/scripts/dev/results-firewall.sh"
readonly example_config="${repository_root}/deploy/dev/results-firewall.env.example"
readonly test_address="192.168.50.8"
readonly test_port="18081"

# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"
automata_init_target_root "${repository_root}"
readonly test_work_root="${AUTOMATA_CANONICAL_TARGET_ROOT}/results-firewall-tests"
install -d -m 0700 -- "${test_work_root}"
test_work_directory="$(mktemp -d "${test_work_root}/run.XXXXXXXX")"
readonly test_work_directory

cleanup() {
    rm -f -- \
        "${test_work_directory}/config-link" \
        "${test_work_directory}/config-directory-link"
    rmdir -- "${test_work_directory}"
}
trap cleanup EXIT

fail() {
    printf 'test failure: %s\n' "$*" >&2
    exit 1
}

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "${label} unexpectedly succeeded"
    fi
}

expected_rules="$({
    printf '%s\n' \
        'table inet automata_results_guard {' \
        $'\tcomment "automata-results-firewall:v1"' \
        $'\tchain results_input {' \
        $'\t\ttype filter hook input priority -10; policy accept;' \
        $'\t\tip daddr 192.168.50.8 tcp dport 18081 iifname != "lo" drop comment "automata-results-firewall:deny-non-loopback:v1"' \
        $'\t}' \
        '}'
})"
actual_rules="$(${firewall_script} render --listen-address "${test_address}" --port "${test_port}")"
[[ "${actual_rules}" == "${expected_rules}" ]] || fail "rendered policy changed"

config_rules="$(${firewall_script} render --config "${example_config}")"
explicit_example_rules="$(${firewall_script} render --listen-address 192.168.0.8 --port 8081)"
[[ "${config_rules}" == "${explicit_example_rules}" ]] || fail "config parsing changed"

ln -s -- "${example_config}" "${test_work_directory}/config-link"
expect_failure "symbolic-link config" \
    "${firewall_script}" render --config "${test_work_directory}/config-link"
ln -s -- "${repository_root}/deploy/dev" "${test_work_directory}/config-directory-link"
expect_failure "symbolic-link config directory" \
    "${firewall_script}" render \
    --config "${test_work_directory}/config-directory-link/results-firewall.env.example"

expect_failure "wildcard address" \
    "${firewall_script}" render --listen-address 0.0.0.0 --port "${test_port}"
expect_failure "public address" \
    "${firewall_script}" render --listen-address 203.0.113.8 --port "${test_port}"
expect_failure "loopback address" \
    "${firewall_script}" render --listen-address 127.0.0.1 --port "${test_port}"
expect_failure "non-canonical address" \
    "${firewall_script}" render --listen-address 192.168.050.8 --port "${test_port}"
expect_failure "address injection" \
    "${firewall_script}" render --listen-address '192.168.50.8;flush ruleset' --port "${test_port}"
expect_failure "privileged port" \
    "${firewall_script}" render --listen-address "${test_address}" --port 80
expect_failure "out-of-range port" \
    "${firewall_script}" render --listen-address "${test_address}" --port 65536
expect_failure "port injection" \
    "${firewall_script}" render --listen-address "${test_address}" --port '18081;drop'
expect_failure "missing address" \
    "${firewall_script}" render --port "${test_port}"
expect_failure "unknown option" \
    "${firewall_script}" render --listen-address "${test_address}" --port "${test_port}" --force

if command -v sudo >/dev/null 2>&1 &&
    command -v unshare >/dev/null 2>&1 &&
    command -v ip >/dev/null 2>&1 &&
    command -v nft >/dev/null 2>&1 &&
    command -v nsenter >/dev/null 2>&1 &&
    command -v python3 >/dev/null 2>&1 &&
    command -v curl >/dev/null 2>&1 &&
    sudo -n true 2>/dev/null; then
    sudo -n unshare --net -- env \
        AUTOMATA_FIREWALL_SCRIPT="${firewall_script}" \
        AUTOMATA_FIREWALL_TEST_ADDRESS="${test_address}" \
        AUTOMATA_FIREWALL_TEST_PORT="${test_port}" \
        bash -euo pipefail -c '
            peer_pid=""
            server_pid=""
            cleanup_namespace_test() {
                if [[ -n "${server_pid}" ]]; then
                    kill "${server_pid}" >/dev/null 2>&1 || true
                    wait "${server_pid}" 2>/dev/null || true
                fi
                if [[ -n "${peer_pid}" ]]; then
                    kill "${peer_pid}" >/dev/null 2>&1 || true
                    wait "${peer_pid}" 2>/dev/null || true
                fi
            }
            trap cleanup_namespace_test EXIT

            ip link set lo up
            unshare --net -- sleep 30 &
            peer_pid=$!
            ip link add automata-test0 type veth peer name automata-peer0
            ip link set automata-peer0 netns "${peer_pid}"
            ip address add "${AUTOMATA_FIREWALL_TEST_ADDRESS}/24" dev automata-test0
            ip link set automata-test0 up
            nsenter --target "${peer_pid}" --net \
                ip address add 192.168.50.9/24 dev automata-peer0
            nsenter --target "${peer_pid}" --net ip link set automata-peer0 up
            nsenter --target "${peer_pid}" --net ip link set lo up

            "${AUTOMATA_FIREWALL_SCRIPT}" apply \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            "${AUTOMATA_FIREWALL_SCRIPT}" audit \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            "${AUTOMATA_FIREWALL_SCRIPT}" apply \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"

            python3 -m http.server "${AUTOMATA_FIREWALL_TEST_PORT}" \
                --bind "${AUTOMATA_FIREWALL_TEST_ADDRESS}" >/dev/null 2>&1 &
            server_pid=$!
            curl --silent --output /dev/null \
                --retry 10 --retry-connrefused --retry-delay 0 --max-time 3 \
                "http://${AUTOMATA_FIREWALL_TEST_ADDRESS}:${AUTOMATA_FIREWALL_TEST_PORT}/"
            ! nsenter --target "${peer_pid}" --net \
                curl --silent --show-error --output /dev/null \
                --connect-timeout 1 --max-time 2 \
                "http://${AUTOMATA_FIREWALL_TEST_ADDRESS}:${AUTOMATA_FIREWALL_TEST_PORT}/" \
                2>/dev/null

            nft add rule inet automata_results_guard results_input counter
            ! "${AUTOMATA_FIREWALL_SCRIPT}" audit \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            ! "${AUTOMATA_FIREWALL_SCRIPT}" apply \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            ! "${AUTOMATA_FIREWALL_SCRIPT}" remove \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            nft list table inet automata_results_guard >/dev/null

            nft delete table inet automata_results_guard
            "${AUTOMATA_FIREWALL_SCRIPT}" apply \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            "${AUTOMATA_FIREWALL_SCRIPT}" remove \
                --listen-address "${AUTOMATA_FIREWALL_TEST_ADDRESS}" \
                --port "${AUTOMATA_FIREWALL_TEST_PORT}"
            ! nft list table inet automata_results_guard >/dev/null 2>&1
        '
else
    printf '%s\n' \
        'namespace integration skipped: required privilege or networking command unavailable'
fi

printf 'results firewall contract verified\n'
