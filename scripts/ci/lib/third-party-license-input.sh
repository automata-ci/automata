#!/usr/bin/env bash

# Shared renderer-license input routing. Callers initialize target containment
# and TMPDIR through target-paths.sh before using these functions.

automata_third_party_license_input_error() {
    printf 'error: %s\n' "$*" >&2
    return 1
}

automata_third_party_license_renderer_input() {
    local _automata_repository_root="$1"
    local _automata_default_input="${_automata_repository_root}/target/third-party-license-input/renderer"
    local _automata_candidate="${_automata_default_input}"
    local _automata_canonical
    local _automata_test_mode="${AUTOMATA_THIRD_PARTY_LICENSE_TEST_MODE:-}"
    local _automata_test_override="${AUTOMATA_TEST_THIRD_PARTY_LICENSE_RENDERER_INPUT:-}"

    if [[ -n "${_automata_test_mode}" || -n "${_automata_test_override}" ]]; then
        if [[ "${_automata_test_mode}" != "1" || -z "${_automata_test_override}" ]]; then
            automata_third_party_license_input_error \
                "renderer input test override requires explicit test mode and destination" || \
                return 1
        fi
        if [[ "${_automata_test_override}" != /* ]]; then
            automata_third_party_license_input_error \
                "renderer input test override must be absolute" || return 1
        fi
        _automata_candidate="${_automata_test_override}"
    fi

    _automata_canonical="$(
        automata_canonical_exact_target_child \
            "${_automata_candidate}" \
            "renderer license input"
    )" || return 1
    if [[ "${_automata_test_mode}" == "1" ]]; then
        case "${_automata_canonical}" in
            "${TMPDIR}"/*) ;;
            *)
                automata_third_party_license_input_error \
                    "renderer input test override must resolve beneath TMPDIR" || return 1
                ;;
        esac
    fi
    printf '%s\n' "${_automata_canonical}"
}

automata_third_party_license_lock_path() {
    local _automata_repository_root="$1"
    local _automata_test_mode="${AUTOMATA_THIRD_PARTY_LICENSE_TEST_MODE:-}"
    local _automata_candidate

    # Resolve the input even though only the lock path is returned, so a test
    # override can never select a lock without passing the same containment
    # checks as the destructive preparation path.
    automata_third_party_license_renderer_input \
        "${_automata_repository_root}" >/dev/null || return 1
    if [[ "${_automata_test_mode}" == "1" ]]; then
        _automata_candidate="${TMPDIR}/.third-party-license-input.prepare.lock"
    else
        _automata_candidate="${_automata_repository_root}/target/third-party-license-input/.prepare.lock"
    fi
    automata_canonical_exact_target_child \
        "${_automata_candidate}" \
        "third-party license input lock"
}
