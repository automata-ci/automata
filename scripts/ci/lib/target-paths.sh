#!/usr/bin/env bash

# Shared canonical containment helpers for CI scripts. This file is sourced;
# callers retain their own strict-mode and error-reporting policy. Namespaced
# locals avoid Bash dynamic-scope collisions with readonly caller variables.

automata_target_path_error() {
    printf 'error: %s\n' "$*" >&2
    return 1
}

automata_realpath_existing() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).resolve(strict=True))
PY
}

automata_realpath_missing() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).resolve(strict=False))
PY
}

automata_lexical_absolute_path() {
    python3 - "$1" <<'PY'
import os
import sys

print(os.path.abspath(os.path.normpath(sys.argv[1])))
PY
}

automata_init_target_root() {
    local _automata_repository_root="$1"
    local _automata_nominal_target="${_automata_repository_root}/target"
    local _automata_canonical_target

    command -v python3 >/dev/null 2>&1 || \
        automata_target_path_error "python3 is required" || return 1
    if [[ -L "${_automata_nominal_target}" ]]; then
        automata_target_path_error \
            "repository target directory must not be a symbolic link" || return 1
    fi
    if [[ -e "${_automata_nominal_target}" && ! -d "${_automata_nominal_target}" ]]; then
        automata_target_path_error \
            "repository target path is not a directory" || return 1
    fi
    if [[ ! -e "${_automata_nominal_target}" ]]; then
        install -d -m 0755 -- "${_automata_nominal_target}" || return 1
    fi
    _automata_canonical_target="$(
        automata_realpath_existing "${_automata_nominal_target}"
    )" || return 1
    if [[ "${_automata_canonical_target}" != "${_automata_nominal_target}" ]]; then
        automata_target_path_error \
            "repository target directory must resolve inside the repository" || return 1
    fi
    AUTOMATA_CANONICAL_TARGET_ROOT="${_automata_canonical_target}"
    export AUTOMATA_CANONICAL_TARGET_ROOT
}

automata_canonical_target_path() {
    local _automata_candidate="$1"
    local _automata_label="$2"
    local _automata_canonical

    [[ -n "${AUTOMATA_CANONICAL_TARGET_ROOT:-}" ]] || \
        automata_target_path_error "target root containment is not initialized" || return 1
    _automata_canonical="$(
        automata_realpath_missing "${_automata_candidate}"
    )" || return 1
    case "${_automata_canonical}" in
        "${AUTOMATA_CANONICAL_TARGET_ROOT}")
            printf '%s\n' "${_automata_canonical}"
            ;;
        "${AUTOMATA_CANONICAL_TARGET_ROOT}"/*)
            printf '%s\n' "${_automata_canonical}"
            ;;
        *)
            automata_target_path_error \
                "${_automata_label} must resolve beneath the repository target directory" || \
                return 1
            ;;
    esac
}

automata_canonical_target_child() {
    local _automata_candidate="$1"
    local _automata_label="$2"
    local _automata_canonical

    _automata_canonical="$(
        automata_canonical_target_path "${_automata_candidate}" "${_automata_label}"
    )" || return 1
    if [[ "${_automata_canonical}" == "${AUTOMATA_CANONICAL_TARGET_ROOT}" ]]; then
        automata_target_path_error \
            "${_automata_label} must be a child of the repository target directory" || \
            return 1
    fi
    printf '%s\n' "${_automata_canonical}"
}

automata_canonical_exact_target_child() {
    local _automata_candidate="$1"
    local _automata_label="$2"
    local _automata_canonical
    local _automata_nominal

    _automata_canonical="$(
        automata_canonical_target_child \
            "${_automata_candidate}" \
            "${_automata_label}"
    )" || return 1
    _automata_nominal="$(
        automata_lexical_absolute_path "${_automata_candidate}"
    )" || return 1
    if [[ "${_automata_canonical}" != "${_automata_nominal}" ]]; then
        automata_target_path_error \
            "${_automata_label} must not contain symbolic links" || return 1
    fi
    printf '%s\n' "${_automata_canonical}"
}

automata_set_target_tmpdir() {
    local _automata_repository_root="$1"
    local _automata_default_candidate="$2"
    local _automata_candidate="${TMPDIR:-${_automata_default_candidate}}"
    local _automata_canonical

    if [[ "${_automata_candidate}" != /* ]]; then
        _automata_candidate="${_automata_repository_root}/${_automata_candidate}"
    fi
    _automata_canonical="$(
        automata_canonical_target_child "${_automata_candidate}" "TMPDIR"
    )" || return 1
    install -d -m 0700 -- "${_automata_canonical}" || return 1
    TMPDIR="${_automata_canonical}"
    export TMPDIR
}
