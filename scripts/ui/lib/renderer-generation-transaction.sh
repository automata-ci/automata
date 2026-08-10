#!/usr/bin/env bash

# This file is sourced by the renderer regenerator and verifier. It owns the
# persistent rollback boundary for the checked-in renderer set across process
# death and SIGKILL. It does not claim power-loss atomicity; callers retain
# their own strict-mode and error-reporting policy.

AUTOMATA_RENDERER_TRANSACTION_FORMAT='automata-renderer-publication-v2'
AUTOMATA_RENDERER_TRANSACTION_TEMP_SUFFIX='.automata-renderer-publishing'

automata_renderer_transaction_error() {
    printf 'error: %s\n' "$*" >&2
    return 1
}

automata_renderer_transaction_valid_identifier() {
    local _automata_identifier="${1:-}"

    (( $# == 1 )) || return 1
    [[ "${_automata_identifier}" != . && "${_automata_identifier}" != .. && \
        "${_automata_identifier}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
}

automata_renderer_transaction_configure_state() {
    local _automata_state_directory="${1:-}"
    local _automata_scratch_root="${2:-}"
    local _automata_directory=''
    local _automata_parent=''

    (( $# == 2 )) || {
        automata_renderer_transaction_error \
            "renderer transaction state configuration requires state and scratch directories"
        return
    }
    for _automata_directory in "${_automata_state_directory}" "${_automata_scratch_root}"; do
        [[ "${_automata_directory}" == /* && "${_automata_directory}" != / ]] || {
            automata_renderer_transaction_error \
                "renderer transaction paths must be absolute non-root paths"
            return
        }
        if [[ -e "${_automata_directory}" || -L "${_automata_directory}" ]]; then
            [[ -d "${_automata_directory}" && ! -L "${_automata_directory}" ]] || {
                automata_renderer_transaction_error \
                    "renderer transaction paths must be real directories when present"
                return
            }
        fi
    done
    if [[ ! -e "${_automata_state_directory}" && \
        ! -L "${_automata_state_directory}" ]]; then
        _automata_parent="${_automata_state_directory%/*}"
        [[ -d "${_automata_parent}" && ! -L "${_automata_parent}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction state parent must be a real directory"
            return
        }
    fi
    AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY="${_automata_state_directory}"
    AUTOMATA_RENDERER_TRANSACTION_SCRATCH_ROOT="${_automata_scratch_root}"
    AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT="${_automata_state_directory}/preparing"
    AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT="${_automata_state_directory}/active"
    AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT="${_automata_state_directory}/committed"
    AUTOMATA_RENDERER_TRANSACTION_ACTIVE=0
}

automata_renderer_transaction_configure_cleanup() {
    local _automata_temporary_directory="${1:-}"
    local _automata_state_directory="${2:-}"
    local _automata_scratch_root="${_automata_temporary_directory%/*}"
    local _automata_transaction_id="${_automata_temporary_directory##*/}"

    (( $# == 2 )) || {
        automata_renderer_transaction_error \
            "renderer transaction configuration requires temporary and state directories"
        return
    }
    automata_renderer_transaction_configure_state \
        "${_automata_state_directory}" "${_automata_scratch_root}" || return
    [[ -d "${_automata_temporary_directory}" && \
        ! -L "${_automata_temporary_directory}" && \
        "${_automata_temporary_directory}" == \
            "${_automata_scratch_root}/${_automata_transaction_id}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction temporary directory is unsafe"
        return
    }
    automata_renderer_transaction_valid_identifier "${_automata_transaction_id}" || {
        automata_renderer_transaction_error \
            "renderer transaction identifier is unsafe"
        return
    }
    case "${_automata_state_directory}" in
        "${_automata_temporary_directory}" | "${_automata_temporary_directory}"/*)
            automata_renderer_transaction_error \
                "renderer transaction state must survive temporary cleanup"
            return
            ;;
    esac
    case "${_automata_temporary_directory}" in
        "${_automata_state_directory}" | "${_automata_state_directory}"/*)
            automata_renderer_transaction_error \
                "renderer transaction temporary directory must not overlap state"
            return
            ;;
    esac

    AUTOMATA_RENDERER_TRANSACTION_TEMPORARY_DIRECTORY="${_automata_temporary_directory}"
    AUTOMATA_RENDERER_TRANSACTION_ID="${_automata_transaction_id}"
}

automata_renderer_transaction_set_live_paths() {
    local _automata_asset_directory="${1:-}"
    local _automata_generated_contract="${2:-}"
    local _automata_generated_assets="${3:-}"
    local _automata_sums_file="${4:-}"
    local _automata_provenance_file="${5:-}"
    local _automata_sbom_file="${6:-}"
    local _automata_parent=''
    local _automata_path=''

    (( $# == 6 )) || {
        automata_renderer_transaction_error \
            "renderer transaction requires the complete checked-in renderer set"
        return
    }
    [[ -n "${AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY:-}" ]] || {
        automata_renderer_transaction_error "renderer transaction is not configured"
        return
    }

    _automata_parent="${_automata_asset_directory%/*}"
    [[ -n "${_automata_parent}" && -d "${_automata_parent}" && \
        ! -L "${_automata_parent}" && "${_automata_asset_directory}" != / ]] || {
        automata_renderer_transaction_error \
            "renderer asset parent must be a real non-root directory"
        return
    }
    if [[ -e "${_automata_asset_directory}" || -L "${_automata_asset_directory}" ]]; then
        [[ -d "${_automata_asset_directory}" && ! -L "${_automata_asset_directory}" ]] || {
            automata_renderer_transaction_error \
                "renderer asset path must be a real directory when present"
            return
        }
    fi

    for _automata_path in \
        "${_automata_generated_contract}" \
        "${_automata_generated_assets}" \
        "${_automata_sums_file}" \
        "${_automata_provenance_file}" \
        "${_automata_sbom_file}"; do
        _automata_parent="${_automata_path%/*}"
        [[ -n "${_automata_parent}" && -d "${_automata_parent}" && \
            ! -L "${_automata_parent}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction destination parent must be a real directory"
            return
        }
        if [[ -e "${_automata_path}" || -L "${_automata_path}" ]]; then
            [[ -f "${_automata_path}" && ! -L "${_automata_path}" ]] || {
                automata_renderer_transaction_error \
                    "renderer transaction destination must be a real file when present"
                return
            }
        fi
    done

    AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY="${_automata_asset_directory}"
    AUTOMATA_RENDERER_TRANSACTION_GENERATED_CONTRACT="${_automata_generated_contract}"
    AUTOMATA_RENDERER_TRANSACTION_GENERATED_ASSETS="${_automata_generated_assets}"
    AUTOMATA_RENDERER_TRANSACTION_SUMS_FILE="${_automata_sums_file}"
    AUTOMATA_RENDERER_TRANSACTION_PROVENANCE_FILE="${_automata_provenance_file}"
    AUTOMATA_RENDERER_TRANSACTION_SBOM_FILE="${_automata_sbom_file}"
}

automata_renderer_transaction_read_id() {
    local _automata_backup_root="${1:-}"
    local _automata_transaction_id=''
    local -a _automata_format_lines=()

    (( $# == 1 )) || {
        automata_renderer_transaction_error \
            "renderer transaction metadata lookup requires one backup path"
        return
    }
    [[ -d "${_automata_backup_root}" && ! -L "${_automata_backup_root}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction backup is not a real directory"
        return
    }
    [[ -f "${_automata_backup_root}/FORMAT" && \
        ! -L "${_automata_backup_root}/FORMAT" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction backup format is absent or unsupported"
        return
    }
    mapfile -t _automata_format_lines < "${_automata_backup_root}/FORMAT"
    (( ${#_automata_format_lines[@]} == 2 )) || {
        automata_renderer_transaction_error \
            "renderer transaction backup metadata is incomplete"
        return
    }
    _automata_transaction_id="${_automata_format_lines[1]}"
    if [[ "${_automata_format_lines[0]}" != \
        "${AUTOMATA_RENDERER_TRANSACTION_FORMAT}" ]] || \
        ! automata_renderer_transaction_valid_identifier \
            "${_automata_transaction_id}"; then
        automata_renderer_transaction_error \
            "renderer transaction backup format is absent or unsupported"
        return
    fi
    AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID="${_automata_transaction_id}"
}

automata_renderer_transaction_validate_backup() {
    local _automata_backup_root="$1"
    local _automata_entry=''
    local -a _automata_invalid_assets=()

    automata_renderer_transaction_read_id "${_automata_backup_root}" || return
    [[ -d "${_automata_backup_root}/assets" && \
        ! -L "${_automata_backup_root}/assets" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction asset backup is invalid"
        return
    }
    for _automata_entry in \
        generated_contract.rs \
        generated_assets.rs \
        SHA256SUMS \
        PROVENANCE.toml \
        renderer.cdx.json; do
        [[ -f "${_automata_backup_root}/${_automata_entry}" && \
            ! -L "${_automata_backup_root}/${_automata_entry}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction backup is incomplete"
            return
        }
    done
    while IFS= read -r _automata_entry; do
        case "${_automata_entry}" in
            FORMAT | assets | generated_contract.rs | generated_assets.rs | \
                SHA256SUMS | PROVENANCE.toml | renderer.cdx.json) ;;
            *)
                automata_renderer_transaction_error \
                    "renderer transaction backup contains an unknown entry"
                return
                ;;
        esac
    done < <(
        find "${_automata_backup_root}" -mindepth 1 -maxdepth 1 -printf '%f\n'
    )
    mapfile -t _automata_invalid_assets < <(
        find "${_automata_backup_root}/assets" \
            -mindepth 1 -maxdepth 1 ! -type f -print
    )
    [[ "${#_automata_invalid_assets[@]}" -eq 0 ]] || {
        automata_renderer_transaction_error \
            "renderer transaction backup contains a non-file asset"
        return
    }
}

automata_renderer_transaction_remove_scratch() {
    local _automata_transaction_id="${1:-}"
    local _automata_scratch_root="${AUTOMATA_RENDERER_TRANSACTION_SCRATCH_ROOT:-}"
    local _automata_scratch_directory=''

    if (( $# != 1 )) || \
        ! automata_renderer_transaction_valid_identifier \
            "${_automata_transaction_id}"; then
        automata_renderer_transaction_error \
            "renderer transaction scratch cleanup received an unsafe identifier"
        return
    fi
    [[ -n "${_automata_scratch_root}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction scratch cleanup is not configured"
        return
    }
    if [[ ! -e "${_automata_scratch_root}" && \
        ! -L "${_automata_scratch_root}" ]]; then
        return 0
    fi
    [[ -d "${_automata_scratch_root}" && ! -L "${_automata_scratch_root}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction scratch root is unsafe"
        return
    }
    _automata_scratch_directory="${_automata_scratch_root}/${_automata_transaction_id}"
    if [[ ! -e "${_automata_scratch_directory}" && \
        ! -L "${_automata_scratch_directory}" ]]; then
        return 0
    fi
    [[ -d "${_automata_scratch_directory}" && \
        ! -L "${_automata_scratch_directory}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction scratch path is unsafe"
        return
    }
    rm -rf -- "${_automata_scratch_directory}"
}

automata_renderer_transaction_sweep_orphan_scratch() {
    local _automata_scratch_root="${AUTOMATA_RENDERER_TRANSACTION_SCRATCH_ROOT:-}"
    local _automata_scratch_directory=''
    local _automata_scratch_name=''

    [[ -n "${_automata_scratch_root}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction scratch sweep is not configured"
        return
    }
    if [[ ! -e "${_automata_scratch_root}" && \
        ! -L "${_automata_scratch_root}" ]]; then
        return 0
    fi
    [[ -d "${_automata_scratch_root}" && ! -L "${_automata_scratch_root}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction scratch root is unsafe"
        return
    }
    while IFS= read -r -d '' _automata_scratch_directory; do
        _automata_scratch_name="${_automata_scratch_directory##*/}"
        [[ "${_automata_scratch_name}" =~ ^regenerate\.[A-Za-z0-9]{8}$ ]] || \
            continue
        if [[ "${_automata_scratch_name}" == \
            "${AUTOMATA_RENDERER_TRANSACTION_ID:-}" ]]; then
            continue
        fi
        [[ -d "${_automata_scratch_directory}" && \
            ! -L "${_automata_scratch_directory}" ]] || {
            automata_renderer_transaction_error \
                "renderer orphan scratch path is unsafe"
            return
        }
        rm -rf -- "${_automata_scratch_directory}"
    done < <(
        find "${_automata_scratch_root}" -mindepth 1 -maxdepth 1 \
            -name 'regenerate.????????' -print0 | LC_ALL=C sort -z
    )
}

automata_renderer_transaction_atomic_copy() {
    local _automata_copy_kind="$1"
    local _automata_source="$2"
    local _automata_destination="$3"
    local _automata_parent="${_automata_destination%/*}"
    local _automata_basename="${_automata_destination##*/}"
    local _automata_temporary_file=
    local _automata_compare_source="${_automata_source}"

    [[ -f "${_automata_source}" && ! -L "${_automata_source}" && \
        -d "${_automata_parent}" && ! -L "${_automata_parent}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction atomic copy received an invalid path"
        return
    }
    if [[ -e "${_automata_destination}" || -L "${_automata_destination}" ]]; then
        [[ -f "${_automata_destination}" && ! -L "${_automata_destination}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction refuses to replace a non-file destination"
            return
        }
    fi
    _automata_temporary_file="${_automata_parent}/.${_automata_basename}${AUTOMATA_RENDERER_TRANSACTION_TEMP_SUFFIX}"
    if [[ -e "${_automata_temporary_file}" || -L "${_automata_temporary_file}" ]]; then
        [[ -f "${_automata_temporary_file}" && ! -L "${_automata_temporary_file}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction temporary publication path is unsafe"
            return
        }
        rm -f -- "${_automata_temporary_file}"
    fi

    case "${_automata_copy_kind}" in
        publish) install -m 0644 -- "${_automata_source}" "${_automata_temporary_file}" ;;
        restore) cp -a -- "${_automata_source}" "${_automata_temporary_file}" ;;
        *)
            automata_renderer_transaction_error \
                "renderer transaction atomic copy kind is unsupported"
            return
            ;;
    esac
    mv -fT -- "${_automata_temporary_file}" "${_automata_destination}"
    cmp --silent -- "${_automata_compare_source}" "${_automata_destination}" || {
        automata_renderer_transaction_error \
            "renderer transaction atomic copy verification failed"
        return
    }
}

automata_renderer_transaction_publish_file() {
    (( $# == 2 )) || {
        automata_renderer_transaction_error \
            "renderer publication requires source and destination files"
        return
    }
    automata_renderer_transaction_atomic_copy publish "$1" "$2"
}

automata_renderer_transaction_restore_file() {
    (( $# == 2 )) || {
        automata_renderer_transaction_error \
            "renderer restoration requires backup and destination files"
        return
    }
    automata_renderer_transaction_atomic_copy restore "$1" "$2"
}

automata_renderer_transaction_remove_resolved_backup() {
    if ! rm -rf -- "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}"; then
        automata_renderer_transaction_error \
            "renderer transaction committed-backup cleanup is deferred"
        return
    fi
}

automata_renderer_transaction_resolve_active() {
    [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 1 && \
        -d "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction has no valid active backup to resolve"
        return
    }
    [[ ! -e "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction committed state already exists"
        return
    }
    mv -T -- \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}"
    AUTOMATA_RENDERER_TRANSACTION_ACTIVE=0
    automata_renderer_transaction_remove_resolved_backup || true
    return 0
}

automata_renderer_transaction_rollback() {
    local _automata_backup_root="${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT:-}"
    local _automata_assets_ready=1
    local _automata_generated_assets_ready=0
    local _automata_restore_failed=0
    local _automata_source=''
    local _automata_live_asset=''
    local _automata_transaction_id=''
    local -a _automata_backup_assets=()

    [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 1 ]] || return 0
    automata_renderer_transaction_validate_backup "${_automata_backup_root}" || return
    _automata_transaction_id="${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}"

    if [[ ! -e "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" ]]; then
        install -d -m 0755 -- "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" || \
            _automata_assets_ready=0
    fi
    [[ -d "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" ]] || \
        _automata_assets_ready=0

    mapfile -d '' -t _automata_backup_assets < <(
        find "${_automata_backup_root}/assets" -maxdepth 1 -type f -print0 \
            | LC_ALL=C sort -z
    )
    if (( _automata_assets_ready == 1 )); then
        for _automata_source in "${_automata_backup_assets[@]}"; do
            automata_renderer_transaction_restore_file \
                "${_automata_source}" \
                "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}/${_automata_source##*/}" || \
                _automata_assets_ready=0
        done
        chmod --reference="${_automata_backup_root}/assets" \
            "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" || \
            _automata_assets_ready=0
    fi

    if (( _automata_assets_ready == 1 )); then
        if automata_renderer_transaction_restore_file \
            "${_automata_backup_root}/generated_assets.rs" \
            "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_ASSETS}"; then
            _automata_generated_assets_ready=1
        else
            _automata_restore_failed=1
        fi
    else
        automata_renderer_transaction_error \
            "renderer rollback retained current Rust because backup assets are incomplete" || \
            true
        _automata_restore_failed=1
    fi

    automata_renderer_transaction_restore_file \
        "${_automata_backup_root}/generated_contract.rs" \
        "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_CONTRACT}" || \
        _automata_restore_failed=1
    automata_renderer_transaction_restore_file \
        "${_automata_backup_root}/SHA256SUMS" \
        "${AUTOMATA_RENDERER_TRANSACTION_SUMS_FILE}" || \
        _automata_restore_failed=1
    automata_renderer_transaction_restore_file \
        "${_automata_backup_root}/PROVENANCE.toml" \
        "${AUTOMATA_RENDERER_TRANSACTION_PROVENANCE_FILE}" || \
        _automata_restore_failed=1
    automata_renderer_transaction_restore_file \
        "${_automata_backup_root}/renderer.cdx.json" \
        "${AUTOMATA_RENDERER_TRANSACTION_SBOM_FILE}" || \
        _automata_restore_failed=1

    if (( _automata_generated_assets_ready == 1 )); then
        while IFS= read -r -d '' _automata_live_asset; do
            if [[ ! -f "${_automata_backup_root}/assets/${_automata_live_asset##*/}" || \
                -L "${_automata_backup_root}/assets/${_automata_live_asset##*/}" ]]; then
                rm -f -- "${_automata_live_asset}" || _automata_restore_failed=1
            fi
        done < <(
            find "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" \
                -maxdepth 1 -type f -print0 | LC_ALL=C sort -z
        )
    fi

    if ! diff -qr -- "${_automata_backup_root}/assets" \
        "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" >/dev/null; then
        _automata_restore_failed=1
    fi
    cmp --silent -- "${_automata_backup_root}/generated_contract.rs" \
        "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_CONTRACT}" 2>/dev/null || \
        _automata_restore_failed=1
    cmp --silent -- "${_automata_backup_root}/generated_assets.rs" \
        "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_ASSETS}" 2>/dev/null || \
        _automata_restore_failed=1
    cmp --silent -- "${_automata_backup_root}/SHA256SUMS" \
        "${AUTOMATA_RENDERER_TRANSACTION_SUMS_FILE}" 2>/dev/null || \
        _automata_restore_failed=1
    cmp --silent -- "${_automata_backup_root}/PROVENANCE.toml" \
        "${AUTOMATA_RENDERER_TRANSACTION_PROVENANCE_FILE}" 2>/dev/null || \
        _automata_restore_failed=1
    cmp --silent -- "${_automata_backup_root}/renderer.cdx.json" \
        "${AUTOMATA_RENDERER_TRANSACTION_SBOM_FILE}" 2>/dev/null || \
        _automata_restore_failed=1

    (( _automata_restore_failed == 0 )) || {
        automata_renderer_transaction_error \
            "renderer rollback is incomplete; the active backup was preserved"
        return
    }
    automata_renderer_transaction_remove_scratch \
        "${_automata_transaction_id}" || return
    automata_renderer_transaction_resolve_active
}

automata_renderer_transaction_recover() {
    local _automata_entry=''
    local _automata_state=''
    local _automata_present_count=0
    local _automata_present_state=''
    local _automata_recovery_id=''

    automata_renderer_transaction_set_live_paths "$@" || return
    # Callers hold the stable exclusive renderer-directory lock. Sweeping this
    # script's exact mktemp namespace closes the unavoidable SIGKILL window
    # between scratch allocation and the first complete journal record.
    automata_renderer_transaction_sweep_orphan_scratch || return
    if [[ ! -e "${AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY}" ]]; then
        return 0
    fi
    [[ -d "${AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction state directory is unsafe"
        return
    }
    while IFS= read -r _automata_entry; do
        case "${_automata_entry}" in
            preparing | active | committed) ;;
            *)
                automata_renderer_transaction_error \
                    "renderer transaction state contains an unknown entry"
                return
                ;;
        esac
    done < <(
        find "${AUTOMATA_RENDERER_TRANSACTION_STATE_DIRECTORY}" \
            -mindepth 1 -maxdepth 1 -printf '%f\n'
    )
    for _automata_state in \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}"; do
        if [[ -e "${_automata_state}" || -L "${_automata_state}" ]]; then
            [[ -d "${_automata_state}" && ! -L "${_automata_state}" ]] || {
                automata_renderer_transaction_error \
                    "renderer transaction state path is unsafe"
                return
            }
            _automata_present_count=$((_automata_present_count + 1))
            _automata_present_state="${_automata_state}"
        fi
    done
    (( _automata_present_count <= 1 )) || {
        automata_renderer_transaction_error \
            "renderer transaction has ambiguous durable state"
        return
    }

    case "${_automata_present_state}" in
        "") return 0 ;;
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}")
            if [[ -e "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/FORMAT" || \
                -L "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/FORMAT" ]]; then
                if automata_renderer_transaction_read_id \
                    "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}" \
                    2>/dev/null; then
                    _automata_recovery_id="${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}"
                    automata_renderer_transaction_remove_scratch \
                        "${_automata_recovery_id}" || return
                fi
            fi
            # Preparing is published before any live mutation. An absent or
            # torn FORMAT can therefore be discarded rather than stranding
            # recovery; the exact production scratch namespace was swept above.
            rm -rf -- "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}"
            ;;
        "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}")
            # The active-to-committed rename is the process-crash commit point.
            # Cleanup may itself have been killed after deleting any subset of
            # the backup, so no backup completeness is required in this phase.
            automata_renderer_transaction_remove_resolved_backup
            ;;
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}")
            automata_renderer_transaction_validate_backup \
                "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" || return
            _automata_recovery_id="${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}"
            automata_renderer_transaction_remove_scratch \
                "${_automata_recovery_id}" || return
            AUTOMATA_RENDERER_TRANSACTION_ACTIVE=1
            automata_renderer_transaction_rollback || return
            if [[ -e "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}" || \
                -L "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}" ]]; then
                automata_renderer_transaction_remove_resolved_backup
            fi
            ;;
    esac
}

automata_renderer_transaction_begin() {
    local _automata_path=''

    automata_renderer_transaction_set_live_paths "$@" || return
    [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 0 ]] || {
        automata_renderer_transaction_error "renderer transaction is already active"
        return
    }
    automata_renderer_transaction_valid_identifier \
        "${AUTOMATA_RENDERER_TRANSACTION_ID:-}" || {
        automata_renderer_transaction_error \
            "renderer transaction cannot begin without a unique identifier"
        return
    }
    for _automata_path in \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_COMMITTED_ROOT}"; do
        [[ ! -e "${_automata_path}" && ! -L "${_automata_path}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction state was not recovered before begin"
            return
        }
    done
    [[ -d "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" && \
        ! -L "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction cannot back up a missing asset directory"
        return
    }
    for _automata_path in \
        "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_CONTRACT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_ASSETS}" \
        "${AUTOMATA_RENDERER_TRANSACTION_SUMS_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PROVENANCE_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_SBOM_FILE}"; do
        [[ -f "${_automata_path}" && ! -L "${_automata_path}" ]] || {
            automata_renderer_transaction_error \
                "renderer transaction cannot back up an incomplete live set"
            return
        }
    done

    install -d -m 0700 -- "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}"
    # Record the scratch identity before copying the backup. A process killed
    # during preparation leaves live files untouched, and the next owner can
    # remove both the partial backup and its exact scratch directory.
    printf '%s\n%s\n' \
        "${AUTOMATA_RENDERER_TRANSACTION_FORMAT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_ID}" \
        > "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/FORMAT"
    chmod 0600 -- "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/FORMAT"
    cp -a -- \
        "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/assets"
    cp -a -- "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_CONTRACT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/generated_contract.rs"
    cp -a -- "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_ASSETS}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/generated_assets.rs"
    cp -a -- "${AUTOMATA_RENDERER_TRANSACTION_SUMS_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/SHA256SUMS"
    cp -a -- "${AUTOMATA_RENDERER_TRANSACTION_PROVENANCE_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/PROVENANCE.toml"
    cp -a -- "${AUTOMATA_RENDERER_TRANSACTION_SBOM_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/renderer.cdx.json"
    diff -qr -- \
        "${AUTOMATA_RENDERER_TRANSACTION_ASSET_DIRECTORY}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/assets" >/dev/null
    cmp --silent -- "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_CONTRACT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/generated_contract.rs"
    cmp --silent -- "${AUTOMATA_RENDERER_TRANSACTION_GENERATED_ASSETS}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/generated_assets.rs"
    cmp --silent -- "${AUTOMATA_RENDERER_TRANSACTION_SUMS_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/SHA256SUMS"
    cmp --silent -- "${AUTOMATA_RENDERER_TRANSACTION_PROVENANCE_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/PROVENANCE.toml"
    cmp --silent -- "${AUTOMATA_RENDERER_TRANSACTION_SBOM_FILE}" \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}/renderer.cdx.json"
    automata_renderer_transaction_validate_backup \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}"
    [[ "${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}" == \
        "${AUTOMATA_RENDERER_TRANSACTION_ID}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction backup identifier changed during preparation"
        return
    }
    mv -T -- \
        "${AUTOMATA_RENDERER_TRANSACTION_PREPARING_ROOT}" \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}"
    AUTOMATA_RENDERER_TRANSACTION_ACTIVE=1
}

automata_renderer_transaction_owner_marker() {
    [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 1 ]] || {
        automata_renderer_transaction_error \
            "renderer transaction owner marker requires an active transaction"
        return
    }
    automata_renderer_transaction_validate_backup \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" || return
    [[ "${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}" == \
        "${AUTOMATA_RENDERER_TRANSACTION_ID:-}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction owner marker does not match this transaction"
        return
    }
    printf '%s/FORMAT\n' "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}"
}

automata_renderer_transaction_owner_id() {
    [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 1 ]] || {
        automata_renderer_transaction_error \
            "renderer transaction owner identifier requires an active transaction"
        return
    }
    automata_renderer_transaction_validate_backup \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" || return
    [[ "${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}" == \
        "${AUTOMATA_RENDERER_TRANSACTION_ID:-}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction owner identifier does not match this transaction"
        return
    }
    printf '%s\n' "${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}"
}

automata_renderer_transaction_require_verifier_access() {
    local _automata_state_directory="${1:-}"
    local _automata_supplied_marker="${2:-}"
    local _automata_supplied_id="${3:-}"
    local _automata_active_root="${_automata_state_directory}/active"
    local _automata_expected_marker="${_automata_active_root}/FORMAT"
    local _automata_entry=''
    local _automata_present_count=0
    local _automata_present_state=''

    (( $# == 3 )) || {
        automata_renderer_transaction_error \
            "renderer verifier transaction check requires state, marker, and identifier arguments"
        return
    }
    if [[ ! -e "${_automata_state_directory}" && ! -L "${_automata_state_directory}" ]]; then
        [[ -z "${_automata_supplied_marker}" && \
            -z "${_automata_supplied_id}" ]] || {
            automata_renderer_transaction_error \
                "renderer verifier received inactive transaction ownership"
            return
        }
        return 0
    fi
    [[ -d "${_automata_state_directory}" && ! -L "${_automata_state_directory}" ]] || {
        automata_renderer_transaction_error \
            "renderer transaction verifier state is unsafe"
        return
    }
    while IFS= read -r _automata_entry; do
        case "${_automata_entry}" in
            preparing | active | committed)
                _automata_present_count=$((_automata_present_count + 1))
                _automata_present_state="${_automata_entry}"
                ;;
            *)
                automata_renderer_transaction_error \
                    "renderer transaction verifier state contains an unknown entry"
                return
                ;;
        esac
    done < <(
        find "${_automata_state_directory}" \
            -mindepth 1 -maxdepth 1 -printf '%f\n'
    )
    (( _automata_present_count <= 1 )) || {
        automata_renderer_transaction_error \
            "renderer transaction verifier state is ambiguous"
        return
    }
    if (( _automata_present_count == 0 )); then
        [[ -z "${_automata_supplied_marker}" && \
            -z "${_automata_supplied_id}" ]] || {
            automata_renderer_transaction_error \
                "renderer verifier received inactive transaction ownership"
            return
        }
        return 0
    fi
    [[ "${_automata_present_state}" == active ]] || {
        automata_renderer_transaction_error \
            "renderer verification refuses an unresolved publication transaction"
        return
    }
    automata_renderer_transaction_validate_backup "${_automata_active_root}" || return
    [[ "${_automata_supplied_marker}" == "${_automata_expected_marker}" && \
        "${_automata_supplied_id}" == \
            "${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}" ]] || {
        automata_renderer_transaction_error \
            "renderer verification refuses an active publication transaction"
        return
    }
}

automata_renderer_transaction_commit() {
    local _automata_transaction_id=''

    [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 1 ]] || {
        automata_renderer_transaction_error \
            "renderer transaction cannot commit without an active backup"
        return
    }
    automata_renderer_transaction_validate_backup \
        "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE_ROOT}" || return
    _automata_transaction_id="${AUTOMATA_RENDERER_TRANSACTION_VALIDATED_ID}"
    automata_renderer_transaction_remove_scratch \
        "${_automata_transaction_id}" || return
    automata_renderer_transaction_resolve_active
}

automata_renderer_transaction_exit() {
    local _automata_original_status=$?
    local _automata_final_status="${_automata_original_status}"

    trap - EXIT
    set +e
    if [[ "${AUTOMATA_RENDERER_TRANSACTION_ACTIVE:-0}" == 1 ]]; then
        if (( _automata_original_status == 0 )); then
            automata_renderer_transaction_error \
                "renderer regeneration exited with an uncommitted transaction" || true
            _automata_final_status=1
        fi
        if ! automata_renderer_transaction_rollback; then
            automata_renderer_transaction_error \
                "renderer rollback failed; the persistent active backup was preserved" || true
            _automata_final_status=125
        fi
    fi
    if [[ -n "${AUTOMATA_RENDERER_TRANSACTION_TEMPORARY_DIRECTORY:-}" && \
        -d "${AUTOMATA_RENDERER_TRANSACTION_TEMPORARY_DIRECTORY}" ]]; then
        if ! rm -rf -- "${AUTOMATA_RENDERER_TRANSACTION_TEMPORARY_DIRECTORY}"; then
            automata_renderer_transaction_error \
                "renderer transaction temporary cleanup failed" || true
            _automata_final_status=125
        fi
    fi
    exit "${_automata_final_status}"
}
