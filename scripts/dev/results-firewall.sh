#!/usr/bin/env bash
set -euo pipefail

readonly table_family="inet"
readonly table_name="automata_results_guard"
readonly chain_name="results_input"
readonly table_identity="automata-results-firewall:v1"
readonly rule_identity="automata-results-firewall:deny-non-loopback:v1"

usage() {
    cat >&2 <<'EOF'
usage: results-firewall.sh ACTION --listen-address PRIVATE_IPV4 --port PORT
       results-firewall.sh ACTION --config CONFIG_FILE

Actions:
  render  Print the complete nftables transaction without changing the host.
  audit   Verify that the exact expected table is installed and the address is local.
  apply   Atomically create the table, or do nothing when it is already exact.
  remove  Delete only the table whose complete identity matches the expected table.

The address and port are always explicit. PORT must be an unprivileged TCP port
(1024-65535), and PRIVATE_IPV4 must be an RFC 1918 address without leading
zeroes. audit and apply additionally require that the address is assigned to a
non-loopback interface on this host. A config file is parsed as data (never
sourced), must contain only AUTOMATA_RESULTS_LISTEN_ADDRESS and
AUTOMATA_RESULTS_LISTEN_PORT assignments, and must not traverse symlinks.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

validate_private_ipv4() {
    local value="$1"
    local octet
    local -a octets

    IFS='.' read -r -a octets <<<"${value}"
    [[ ${#octets[@]} -eq 4 ]] || return 1

    for octet in "${octets[@]}"; do
        [[ "${octet}" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        ((10#${octet} <= 255)) || return 1
    done

    local first=$((10#${octets[0]}))
    local second=$((10#${octets[1]}))

    ((first == 10)) ||
        ((first == 172 && second >= 16 && second <= 31)) ||
        ((first == 192 && second == 168))
}

validate_port() {
    local value="$1"

    [[ "${value}" =~ ^[1-9][0-9]{3,4}$ ]] || return 1
    ((10#${value} >= 1024 && 10#${value} <= 65535))
}

read_config() {
    local config_path="$1"
    local canonical_path
    local nominal_path
    local line
    local line_number=0
    local config_address=""
    local config_port=""

    require_command realpath
    [[ -f "${config_path}" && ! -L "${config_path}" ]] ||
        fail "config path must be an existing regular file, not a symbolic link"
    canonical_path="$(realpath --canonicalize-existing -- "${config_path}")" ||
        fail "could not resolve config path"
    nominal_path="$(realpath --canonicalize-existing --no-symlinks -- "${config_path}")" ||
        fail "could not validate config path"
    [[ "${canonical_path}" == "${nominal_path}" ]] ||
        fail "config path must not contain symbolic-link components"

    while IFS= read -r line || [[ -n "${line}" ]]; do
        ((line_number += 1))
        case "${line}" in
            ''|'#'*)
                ;;
            AUTOMATA_RESULTS_LISTEN_ADDRESS=*)
                [[ -z "${config_address}" ]] ||
                    fail "duplicate listen address in config line ${line_number}"
                config_address="${line#*=}"
                ;;
            AUTOMATA_RESULTS_LISTEN_PORT=*)
                [[ -z "${config_port}" ]] ||
                    fail "duplicate listen port in config line ${line_number}"
                config_port="${line#*=}"
                ;;
            *)
                fail "unsupported config entry on line ${line_number}"
                ;;
        esac
    done <"${canonical_path}"

    [[ -n "${config_address}" ]] || fail "config does not define a listen address"
    [[ -n "${config_port}" ]] || fail "config does not define a listen port"
    printf '%s\t%s\n' "${config_address}" "${config_port}"
}

render_rules() {
    local listen_address="$1"
    local listen_port="$2"

    printf '%s\n' \
        "table ${table_family} ${table_name} {" \
        $'\tcomment "'"${table_identity}"$'"' \
        $'\tchain '"${chain_name}"' {' \
        $'\t\ttype filter hook input priority -10; policy accept;' \
        $'\t\tip daddr '"${listen_address}"' tcp dport '"${listen_port}"' iifname != "lo" drop comment "'"${rule_identity}"$'"' \
        $'\t}' \
        '}'
}

require_root() {
    ((EUID == 0)) || fail "this action requires root; inspect render output before using sudo"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_host_address() {
    local expected_address="$1"
    local address_interface
    local address_family
    local address_cidr
    local _address_index
    local _address_tail
    local found_interface=""

    require_command ip
    while read -r _address_index address_interface address_family address_cidr _address_tail; do
        if [[ "${address_family}" == "inet" && "${address_cidr%/*}" == "${expected_address}" ]]; then
            found_interface="${address_interface}"
            break
        fi
    done < <(ip -4 -o address show)

    [[ -n "${found_interface}" ]] ||
        fail "listen address ${expected_address} is not assigned to this host"
    [[ "${found_interface}" != "lo" ]] ||
        fail "listen address must be assigned to a non-loopback interface"
}

read_current_table() {
    nft -nn list table "${table_family}" "${table_name}" 2>/dev/null
}

read_current_table_with_handles() {
    nft -nn -a list table "${table_family}" "${table_name}" 2>/dev/null
}

strip_handles() {
    local line
    local first=true

    while IFS= read -r line; do
        line="${line%% # handle [0-9]*}"
        if [[ "${first}" == true ]]; then
            first=false
        else
            printf '\n'
        fi
        printf '%s' "${line}"
    done
}

table_handle() {
    local first_line="${1%%$'\n'*}"

    if [[ "${first_line}" =~ ^table[[:space:]]+inet[[:space:]]+automata_results_guard[[:space:]]+\{[[:space:]]+#[[:space:]]handle[[:space:]]+([0-9]+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

audit_table() {
    local expected="$1"
    local current

    current="$(read_current_table)" || fail "Automata Results firewall table is absent"
    [[ "${current}" == "${expected}" ]] ||
        fail "Automata Results firewall table differs from the exact expected policy"
    printf 'Automata Results firewall policy is exact.\n'
}

apply_table() {
    local expected="$1"
    local current

    if current="$(read_current_table)"; then
        [[ "${current}" == "${expected}" ]] ||
            fail "refusing to replace a present table whose exact identity or policy differs"
        printf 'Automata Results firewall policy is already exact; no change made.\n'
        return 0
    fi

    # One nft batch is one atomic netlink transaction. This script never flushes
    # a ruleset and never replaces a table that was observed in a different form.
    printf '%s\n' "${expected}" | nft -f -
    audit_table "${expected}" >/dev/null
    printf 'Automata Results firewall policy applied atomically.\n'
}

remove_table() {
    local expected="$1"
    local current_with_handles
    local current
    local handle

    if ! current_with_handles="$(read_current_table_with_handles)"; then
        printf 'Automata Results firewall policy is absent; no change made.\n'
        return 0
    fi

    current="$(strip_handles <<<"${current_with_handles}")"
    [[ "${current}" == "${expected}" ]] ||
        fail "refusing to remove a table whose complete identity or policy differs"
    handle="$(table_handle "${current_with_handles}")" ||
        fail "refusing to remove a table without an exact numeric table handle"

    # Address the already-verified table by its kernel handle. If it is replaced
    # concurrently, deletion fails instead of targeting the replacement by name.
    printf 'delete table %s handle %s\n' "${table_family}" "${handle}" | nft -f -
    if read_current_table >/dev/null; then
        fail "table still exists after removal"
    fi
    printf 'Automata Results firewall policy removed.\n'
}

main() {
    local action="${1:-}"
    local listen_address=""
    local listen_port=""
    local config_path=""

    [[ -n "${action}" ]] || {
        usage
        exit 2
    }
    shift

    while (($# > 0)); do
        case "$1" in
            --listen-address)
                (($# >= 2)) || fail "--listen-address requires a value"
                [[ -z "${listen_address}" ]] || fail "--listen-address may be specified only once"
                listen_address="$2"
                shift 2
                ;;
            --port)
                (($# >= 2)) || fail "--port requires a value"
                [[ -z "${listen_port}" ]] || fail "--port may be specified only once"
                listen_port="$2"
                shift 2
                ;;
            --config)
                (($# >= 2)) || fail "--config requires a value"
                [[ -z "${config_path}" ]] || fail "--config may be specified only once"
                config_path="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                fail "unknown argument: $1"
                ;;
        esac
    done

    [[ "${action}" =~ ^(render|audit|apply|remove)$ ]] || fail "unknown action: ${action}"
    if [[ -n "${config_path}" ]]; then
        [[ -z "${listen_address}" && -z "${listen_port}" ]] ||
            fail "--config cannot be combined with explicit address or port options"
        local config_values
        config_values="$(read_config "${config_path}")"
        IFS=$'\t' read -r listen_address listen_port <<<"${config_values}"
    fi
    [[ -n "${listen_address}" ]] || fail "--listen-address is required"
    [[ -n "${listen_port}" ]] || fail "--port is required"
    validate_private_ipv4 "${listen_address}" ||
        fail "--listen-address must be a canonical RFC 1918 IPv4 address"
    validate_port "${listen_port}" ||
        fail "--port must be a canonical integer from 1024 through 65535"

    local expected
    expected="$(render_rules "${listen_address}" "${listen_port}")"

    case "${action}" in
        render)
            printf '%s\n' "${expected}"
            ;;
        audit)
            require_root
            require_command nft
            require_host_address "${listen_address}"
            audit_table "${expected}"
            ;;
        apply)
            require_root
            require_command nft
            require_host_address "${listen_address}"
            apply_table "${expected}"
            ;;
        remove)
            require_root
            require_command nft
            remove_table "${expected}"
            ;;
    esac
}

main "$@"
