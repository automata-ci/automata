#!/usr/bin/env bash
set -euo pipefail

test_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${test_directory}/../../.." && pwd -P)"
transaction_helper="${repository_root}/scripts/ui/lib/renderer-generation-transaction.sh"
regenerator="${repository_root}/scripts/ui/regenerate-renderer.sh"
verifier="${repository_root}/scripts/ui/verify-renderer-assets.sh"
scratch_root="${repository_root}/target/task-tmp/renderer-atomicity-test"
mkdir -p -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
test_phase='initialization'
cleanup() {
    local status=$?
    if (( status != 0 )); then
        printf 'renderer atomicity test failed: phase=%s status=%s\n' \
            "${test_phase}" "${status}" >&2
        while IFS= read -r -d '' log_file; do
            printf '%s\n' "--- ${log_file##*/} ---" >&2
            sed -n '1,120p' "${log_file}" >&2
        done < <(find "${scratch_directory}" -maxdepth 1 -type f \
            -name '*.log' -print0 | LC_ALL=C sort -z)
    fi
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

baseline_directory="${scratch_directory}/baseline"
live_directory="${scratch_directory}/live"
mkdir -p -- "${baseline_directory}/assets"
printf 'old component\n' > "${baseline_directory}/assets/renderer-old.wasm"
printf 'old client\n' > "${baseline_directory}/assets/client-old.js"
printf 'old style\n' > "${baseline_directory}/assets/styles-old.css"
printf 'old generated contract\n' > "${baseline_directory}/generated_contract.rs"
printf 'asset=renderer-old.wasm\n' > "${baseline_directory}/generated_assets.rs"
printf 'old checksums\n' > "${baseline_directory}/SHA256SUMS"
printf 'old provenance\n' > "${baseline_directory}/PROVENANCE.toml"
printf 'old sbom\n' > "${baseline_directory}/renderer.cdx.json"
chmod 0600 -- "${baseline_directory}/PROVENANCE.toml"

reset_case() {
    local case_name="$1"

    rm -rf -- "${live_directory}" \
        "${scratch_directory}/state-${case_name}" \
        "${scratch_directory}/temporary-${case_name}" \
        "${scratch_directory}/restart-${case_name}"
    cp -a -- "${baseline_directory}" "${live_directory}"
    mkdir -p -- \
        "${scratch_directory}/state-${case_name}" \
        "${scratch_directory}/temporary-${case_name}"
}

assert_live_set_is_unchanged() {
    diff -qr -- "${baseline_directory}" "${live_directory}" >/dev/null || {
        echo "renderer transaction did not restore the complete live set" >&2
        return 1
    }
    [[ "$(stat -c '%a' "${live_directory}/PROVENANCE.toml")" == 600 ]] || {
        echo "renderer transaction did not restore checked-in file metadata" >&2
        return 1
    }
}

assert_generated_asset_exists() {
    local generated_file="$1"
    local asset_directory="$2"
    local asset_name=''

    asset_name="$(sed -n 's/^asset=//p' "${generated_file}")"
    [[ -n "${asset_name}" && -f "${asset_directory}/${asset_name}" ]] || {
        echo "generated Rust fixture points at a missing asset" >&2
        return 1
    }
}

run_fault_case() {
    local fault="$1"
    local expected_status="$2"
    local state_directory="${scratch_directory}/state-${fault}"
    local temporary_directory="${scratch_directory}/temporary-${fault}"
    local status=0

    reset_case "${fault}"
    set +e
    bash -euo pipefail -c '
        transaction_helper="$1"
        temporary_directory="$2"
        state_directory="$3"
        live_directory="$4"
        fault="$5"
        # shellcheck source=scripts/ui/lib/renderer-generation-transaction.sh
        source "${transaction_helper}"
        automata_renderer_transaction_configure_cleanup \
            "${temporary_directory}" "${state_directory}"
        trap automata_renderer_transaction_exit EXIT
        live_paths=(
            "${live_directory}/assets"
            "${live_directory}/generated_contract.rs"
            "${live_directory}/generated_assets.rs"
            "${live_directory}/SHA256SUMS"
            "${live_directory}/PROVENANCE.toml"
            "${live_directory}/renderer.cdx.json"
        )
        automata_renderer_transaction_recover "${live_paths[@]}"
        automata_renderer_transaction_begin "${live_paths[@]}"

        printf "new component\n" > "${temporary_directory}/renderer-new.wasm"
        printf "asset=renderer-new.wasm\n" > "${temporary_directory}/generated_assets.rs"
        automata_renderer_transaction_publish_file \
            "${temporary_directory}/renderer-new.wasm" \
            "${live_directory}/assets/renderer-new.wasm"
        automata_renderer_transaction_publish_file \
            "${temporary_directory}/generated_assets.rs" \
            "${live_directory}/generated_assets.rs"
        [[ -f "${live_directory}/assets/renderer-new.wasm" ]]

        printf "new generated contract\n" > "${live_directory}/generated_contract.rs"
        printf "new checksums\n" > "${live_directory}/SHA256SUMS"
        printf "new provenance\n" > "${live_directory}/PROVENANCE.toml"
        if [[ "${fault}" == sbom ]]; then
            printf "partial candidate sbom\n" > \
                "${temporary_directory}/candidate-renderer.cdx.json"
            exit 71
        fi
        printf "new sbom\n" > "${live_directory}/renderer.cdx.json"
        [[ "${fault}" == verifier ]]
        exit 72
    ' bash \
        "${transaction_helper}" \
        "${temporary_directory}" \
        "${state_directory}" \
        "${live_directory}" \
        "${fault}"
    status=$?
    set -e

    [[ "${status}" -eq "${expected_status}" ]] || {
        echo "${fault} fault returned ${status}, expected ${expected_status}" >&2
        return 1
    }
    [[ ! -e "${temporary_directory}" ]]
    [[ ! -e "${state_directory}/active" ]]
    assert_live_set_is_unchanged
}

run_fault_case sbom 71
run_fault_case verifier 72

test_phase='preparing-recovery'
# A kill after the preparation journal is written but before the backup is
# complete cannot have changed live files. Restart removes that exact scratch
# and the partial preparing directory without attempting a rollback.
reset_case preparing-kill
preparing_kill_temporary="${scratch_directory}/temporary-preparing-kill"
preparing_kill_state="${scratch_directory}/state-preparing-kill"
set +e
bash -euo pipefail -c '
    source "$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    cp() {
        kill -KILL "${BASHPID}"
    }
    automata_renderer_transaction_begin \
        "${live_directory}/assets" \
        "${live_directory}/generated_contract.rs" \
        "${live_directory}/generated_assets.rs" \
        "${live_directory}/SHA256SUMS" \
        "${live_directory}/PROVENANCE.toml" \
        "${live_directory}/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${preparing_kill_temporary}" \
    "${preparing_kill_state}" \
    "${live_directory}" \
    >"${scratch_directory}/preparing-kill.log" 2>&1 &
preparing_kill_pid=$!
wait "${preparing_kill_pid}" 2>/dev/null
preparing_kill_status=$?
set -e
[[ "${preparing_kill_status}" -eq 137 && \
    -f "${preparing_kill_state}/preparing/FORMAT" && \
    -d "${preparing_kill_temporary}" ]]
assert_live_set_is_unchanged
preparing_restart="${scratch_directory}/restart-preparing-kill"
mkdir -p -- "${preparing_restart}"
bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_configure_cleanup "$2" "$3"
    trap automata_renderer_transaction_exit EXIT
    automata_renderer_transaction_recover \
        "$4/assets" \
        "$4/generated_contract.rs" \
        "$4/generated_assets.rs" \
        "$4/SHA256SUMS" \
        "$4/PROVENANCE.toml" \
        "$4/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${preparing_restart}" \
    "${preparing_kill_state}" \
    "${live_directory}"
assert_live_set_is_unchanged
[[ ! -e "${preparing_kill_state}/preparing" && \
    ! -e "${preparing_kill_temporary}" ]]

# The two smaller preparation windows have either no journal or a torn FORMAT.
# The exclusive restart owner safely sweeps only regenerate.XXXXXXXX scratch,
# and discards partial preparing because live publication has not begun.
orphan_scratch_root="${scratch_directory}/orphan-scratch-root"
orphan_state="${scratch_directory}/orphan-state"
orphan_temporary="${orphan_scratch_root}/regenerate.Ab12Cd34"
mkdir -p -- "${orphan_temporary}" "${orphan_state}"
bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_configure_state "$2" "$3"
    automata_renderer_transaction_recover \
        "$4/assets" \
        "$4/generated_contract.rs" \
        "$4/generated_assets.rs" \
        "$4/SHA256SUMS" \
        "$4/PROVENANCE.toml" \
        "$4/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${orphan_state}" \
    "${orphan_scratch_root}" \
    "${live_directory}"
[[ ! -e "${orphan_temporary}" ]]
assert_live_set_is_unchanged

torn_scratch_root="${scratch_directory}/torn-scratch-root"
torn_state="${scratch_directory}/torn-state"
torn_temporary="${torn_scratch_root}/regenerate.Zy98Xw76"
mkdir -p -- "${torn_temporary}" "${torn_state}/preparing"
printf '%s' 'automata-renderer-publication-' > "${torn_state}/preparing/FORMAT"
bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_configure_state "$2" "$3"
    automata_renderer_transaction_recover \
        "$4/assets" \
        "$4/generated_contract.rs" \
        "$4/generated_assets.rs" \
        "$4/SHA256SUMS" \
        "$4/PROVENANCE.toml" \
        "$4/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${torn_state}" \
    "${torn_scratch_root}" \
    "${live_directory}"
[[ ! -e "${torn_temporary}" && ! -e "${torn_state}/preparing" ]]
assert_live_set_is_unchanged

reset_case commit
commit_directory="${scratch_directory}/temporary-commit"
commit_state="${scratch_directory}/state-commit"
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    # shellcheck source=scripts/ui/lib/renderer-generation-transaction.sh
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    live_paths=(
        "${live_directory}/assets"
        "${live_directory}/generated_contract.rs"
        "${live_directory}/generated_assets.rs"
        "${live_directory}/SHA256SUMS"
        "${live_directory}/PROVENANCE.toml"
        "${live_directory}/renderer.cdx.json"
    )
    automata_renderer_transaction_recover "${live_paths[@]}"
    automata_renderer_transaction_begin "${live_paths[@]}"
    printf "committed generated contract\n" > "${live_directory}/generated_contract.rs"
    automata_renderer_transaction_commit
' bash \
    "${transaction_helper}" \
    "${commit_directory}" \
    "${commit_state}" \
    "${live_directory}"
grep -Fqx -- 'committed generated contract' "${live_directory}/generated_contract.rs"
[[ ! -e "${commit_directory}" && ! -e "${commit_state}/active" ]]

reset_case rollback-failure
test_phase='verifier-lock-custody'
rollback_failure_temporary="${scratch_directory}/temporary-rollback-failure"
rollback_failure_state="${scratch_directory}/state-rollback-failure"
set +e
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    # shellcheck source=scripts/ui/lib/renderer-generation-transaction.sh
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    live_paths=(
        "${live_directory}/assets"
        "${live_directory}/generated_contract.rs"
        "${live_directory}/generated_assets.rs"
        "${live_directory}/SHA256SUMS"
        "${live_directory}/PROVENANCE.toml"
        "${live_directory}/renderer.cdx.json"
    )
    automata_renderer_transaction_recover "${live_paths[@]}"
    automata_renderer_transaction_begin "${live_paths[@]}"
    rm -f -- "${live_directory}/generated_assets.rs"
    mkdir -- "${live_directory}/generated_assets.rs"
    exit 73
' bash \
    "${transaction_helper}" \
    "${rollback_failure_temporary}" \
    "${rollback_failure_state}" \
    "${live_directory}" \
    >"${scratch_directory}/rollback-failure.log" 2>&1
rollback_failure_status=$?
set -e
[[ "${rollback_failure_status}" -eq 125 ]]
[[ ! -e "${rollback_failure_temporary}" ]]
[[ -f "${rollback_failure_state}/active/FORMAT" ]]
diff -qr -- \
    "${baseline_directory}/assets" \
    "${rollback_failure_state}/active/assets" >/dev/null
cmp --silent -- \
    "${baseline_directory}/generated_assets.rs" \
    "${rollback_failure_state}/active/generated_assets.rs"

# External verification is closed while the persistent marker is active. State
# access requires the exact marker and unique transaction identifier; the real
# verifier additionally binds that pair to its inherited exclusive lock FD.
rollback_failure_id="$(sed -n '2p' "${rollback_failure_state}/active/FORMAT")"
if bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_require_verifier_access "$2" "" ""
' bash "${transaction_helper}" "${rollback_failure_state}" \
    >/dev/null 2>&1; then
    echo "renderer verifier accepted an unowned active transaction" >&2
    exit 1
fi
if bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_require_verifier_access \
        "$2" "$2/wrong" "$3"
' bash "${transaction_helper}" "${rollback_failure_state}" \
    "${rollback_failure_id}" \
    >/dev/null 2>&1; then
    echo "renderer verifier accepted the wrong transaction marker" >&2
    exit 1
fi
if bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_require_verifier_access \
        "$2" "$2/active/FORMAT" stale-transaction
' bash "${transaction_helper}" "${rollback_failure_state}" \
    >/dev/null 2>&1; then
    echo "renderer verifier replayed a stale transaction identifier" >&2
    exit 1
fi
bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_require_verifier_access \
        "$2" "$2/active/FORMAT" "$3"
' bash "${transaction_helper}" "${rollback_failure_state}" \
    "${rollback_failure_id}"

fake_verifier_repository="${scratch_directory}/fake-verifier-repository"
mkdir -p -- \
    "${fake_verifier_repository}/scripts/ui/lib" \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction" \
    "${fake_verifier_repository}/bin"
install -m 0755 -- \
    "${verifier}" \
    "${fake_verifier_repository}/scripts/ui/verify-renderer-assets.sh"
install -m 0644 -- \
    "${transaction_helper}" \
    "${fake_verifier_repository}/scripts/ui/lib/renderer-generation-transaction.sh"
cp -a -- \
    "${rollback_failure_state}/active" \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active"
# These expansions belong to the generated probe script, not this test shell.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'exec {probe_fd}<"${FAKE_RENDERER_LOCK_PATH}"' \
    'if [[ "${FAKE_RENDERER_LOCK_MODE}" == shared ]]; then' \
    '    if flock --shared --nonblock "${probe_fd}"; then exit 87; fi' \
    'else' \
    '    if flock --exclusive --nonblock "${probe_fd}"; then exit 87; fi' \
    'fi' \
    'exit 86' \
    > "${fake_verifier_repository}/bin/node"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'exit 88' \
    > "${fake_verifier_repository}/bin/python3"
chmod 0755 -- \
    "${fake_verifier_repository}/bin/node" \
    "${fake_verifier_repository}/bin/python3"

set +e
PATH="${fake_verifier_repository}/bin:/usr/bin:/bin" \
    bash "${fake_verifier_repository}/scripts/ui/verify-renderer-assets.sh" \
    >"${scratch_directory}/verifier-default.log" 2>&1
verifier_default_status=$?
exec {fake_owner_lock_fd}<"${fake_verifier_repository}/ui/renderer"
flock --exclusive --nonblock "${fake_owner_lock_fd}"
PATH="${fake_verifier_repository}/bin:/usr/bin:/bin" \
    bash "${fake_verifier_repository}/scripts/ui/verify-renderer-assets.sh" \
    >"${scratch_directory}/verifier-concurrent-public.log" 2>&1
verifier_concurrent_public_status=$?
PATH="${fake_verifier_repository}/bin:/usr/bin:/bin" \
FAKE_RENDERER_LOCK_PATH="${fake_verifier_repository}/ui/renderer" \
FAKE_RENDERER_LOCK_MODE=shared \
    bash "${fake_verifier_repository}/scripts/ui/verify-renderer-assets.sh" \
    --transaction-owner-marker \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active/FORMAT" \
    --transaction-owner-id "${rollback_failure_id}" \
    --transaction-owner-lock-fd "${fake_owner_lock_fd}" \
    >"${scratch_directory}/verifier-owner.log" 2>&1
verifier_owner_status=$?
exec {separate_owner_lock_fd}<"${fake_verifier_repository}/ui/renderer"
PATH="${fake_verifier_repository}/bin:/usr/bin:/bin" \
    bash "${fake_verifier_repository}/scripts/ui/verify-renderer-assets.sh" \
    --transaction-owner-marker \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active/FORMAT" \
    --transaction-owner-id "${rollback_failure_id}" \
    --transaction-owner-lock-fd "${separate_owner_lock_fd}" \
    >"${scratch_directory}/verifier-separate-owner.log" 2>&1
verifier_separate_owner_status=$?
exec {separate_owner_lock_fd}<&-
exec {fake_owner_lock_fd}<&-
set -e
[[ "${verifier_default_status}" -eq 1 ]]
grep -Fq -- \
    'renderer verification refuses an active publication transaction' \
    "${scratch_directory}/verifier-default.log"
[[ "${verifier_concurrent_public_status}" -eq 1 ]]
grep -Fq -- \
    'renderer verification refuses a concurrent publication transaction' \
    "${scratch_directory}/verifier-concurrent-public.log"
[[ "${verifier_owner_status}" -eq 86 ]]
[[ "${verifier_separate_owner_status}" -eq 1 ]]
grep -Fq -- \
    'owner does not hold the exclusive publication lock' \
    "${scratch_directory}/verifier-separate-owner.log"

# With no active journal, public verification holds a shared lock through the
# first verifier subprocess; its exclusive probe must therefore fail.
mv -- \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active" \
    "${scratch_directory}/saved-fake-active"
set +e
PATH="${fake_verifier_repository}/bin:/usr/bin:/bin" \
FAKE_RENDERER_LOCK_PATH="${fake_verifier_repository}/ui/renderer" \
FAKE_RENDERER_LOCK_MODE=exclusive \
    bash "${fake_verifier_repository}/scripts/ui/verify-renderer-assets.sh" \
    >"${scratch_directory}/verifier-shared-lock.log" 2>&1
verifier_shared_lock_status=$?
set -e
[[ "${verifier_shared_lock_status}" -eq 86 ]]
mv -- \
    "${scratch_directory}/saved-fake-active" \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active"

rm -rf -- "${live_directory}/generated_assets.rs"
rollback_restart="${scratch_directory}/restart-rollback-failure"
mkdir -p -- "${rollback_restart}"
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    automata_renderer_transaction_recover \
        "${live_directory}/assets" \
        "${live_directory}/generated_contract.rs" \
        "${live_directory}/generated_assets.rs" \
        "${live_directory}/SHA256SUMS" \
        "${live_directory}/PROVENANCE.toml" \
        "${live_directory}/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${rollback_restart}" \
    "${rollback_failure_state}" \
    "${live_directory}"
assert_live_set_is_unchanged
[[ ! -e "${rollback_failure_state}/active" ]]

reset_case killed
test_phase='active-recovery'
killed_temporary="${scratch_directory}/temporary-killed"
killed_state="${scratch_directory}/state-killed"
set +e
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    live_paths=(
        "${live_directory}/assets"
        "${live_directory}/generated_contract.rs"
        "${live_directory}/generated_assets.rs"
        "${live_directory}/SHA256SUMS"
        "${live_directory}/PROVENANCE.toml"
        "${live_directory}/renderer.cdx.json"
    )
    automata_renderer_transaction_recover "${live_paths[@]}"
    automata_renderer_transaction_begin "${live_paths[@]}"
    printf "new component\n" > "${temporary_directory}/renderer-new.wasm"
    printf "asset=renderer-new.wasm\n" > "${temporary_directory}/generated_assets.rs"
    automata_renderer_transaction_publish_file \
        "${temporary_directory}/renderer-new.wasm" \
        "${live_directory}/assets/renderer-new.wasm"
    old_asset="$(sed -n "s/^asset=//p" "${live_directory}/generated_assets.rs")"
    [[ -f "${live_directory}/assets/${old_asset}" ]]
    automata_renderer_transaction_publish_file \
        "${temporary_directory}/generated_assets.rs" \
        "${live_directory}/generated_assets.rs"
    [[ -f "${live_directory}/assets/renderer-new.wasm" ]]
    kill -KILL "${BASHPID}"
' bash \
    "${transaction_helper}" \
    "${killed_temporary}" \
    "${killed_state}" \
    "${live_directory}" \
    >"${scratch_directory}/killed.log" 2>&1 &
killed_pid=$!
wait "${killed_pid}" 2>/dev/null
killed_status=$?
set -e
[[ "${killed_status}" -eq 137 ]]
[[ -d "${killed_temporary}" && -f "${killed_state}/active/FORMAT" ]]
assert_generated_asset_exists \
    "${live_directory}/generated_assets.rs" \
    "${live_directory}/assets"
killed_restart="${scratch_directory}/restart-killed"
mkdir -p -- "${killed_restart}"
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    automata_renderer_transaction_recover \
        "${live_directory}/assets" \
        "${live_directory}/generated_contract.rs" \
        "${live_directory}/generated_assets.rs" \
        "${live_directory}/SHA256SUMS" \
        "${live_directory}/PROVENANCE.toml" \
        "${live_directory}/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${killed_restart}" \
    "${killed_state}" \
    "${live_directory}"
assert_live_set_is_unchanged
[[ ! -e "${killed_state}/active" && ! -e "${killed_temporary}" ]]

# Exercise the actual entrypoint: recovery must run and remove the killed
# transaction's recorded scratch before an intentionally failing toolchain
# preflight can stop a new regeneration.
entrypoint_repository="${scratch_directory}/entrypoint-repository"
test_phase='entrypoint-recovery'
entrypoint_state="${entrypoint_repository}/ui/renderer/.regeneration-transaction"
entrypoint_scratch="${entrypoint_repository}/target/agent-scratch/ssr"
entrypoint_temporary="${entrypoint_scratch}/regenerate.entrypoint-kill"
entrypoint_crate="${entrypoint_repository}/crates/automata-ci-ui-renderer"
mkdir -p -- \
    "${entrypoint_repository}/scripts/ui/lib" \
    "${entrypoint_repository}/scripts/ci/lib" \
    "${entrypoint_state}" \
    "${entrypoint_scratch}" \
    "${entrypoint_crate}/assets" \
    "${entrypoint_crate}/src"
install -m 0755 -- \
    "${regenerator}" \
    "${entrypoint_repository}/scripts/ui/regenerate-renderer.sh"
install -m 0644 -- \
    "${transaction_helper}" \
    "${entrypoint_repository}/scripts/ui/lib/renderer-generation-transaction.sh"
install -m 0644 -- \
    "${repository_root}/scripts/ui/renderer-preflight-env.sh" \
    "${entrypoint_repository}/scripts/ui/renderer-preflight-env.sh"
install -m 0644 -- \
    "${repository_root}/scripts/ci/lib/target-paths.sh" \
    "${entrypoint_repository}/scripts/ci/lib/target-paths.sh"
cp -a -- "${baseline_directory}/assets/." "${entrypoint_crate}/assets/"
cp -a -- \
    "${baseline_directory}/generated_contract.rs" \
    "${entrypoint_crate}/src/generated_contract.rs"
cp -a -- \
    "${baseline_directory}/generated_assets.rs" \
    "${entrypoint_crate}/src/generated_assets.rs"
cp -a -- \
    "${baseline_directory}/SHA256SUMS" \
    "${entrypoint_repository}/ui/renderer/SHA256SUMS"
cp -a -- \
    "${baseline_directory}/PROVENANCE.toml" \
    "${entrypoint_repository}/ui/renderer/PROVENANCE.toml"
cp -a -- \
    "${baseline_directory}/renderer.cdx.json" \
    "${entrypoint_repository}/ui/renderer/renderer.cdx.json"
mkdir -p -- "${entrypoint_temporary}"
set +e
bash -euo pipefail -c '
    source "$1"
    temporary_directory="$2"
    state_directory="$3"
    crate_directory="$4"
    renderer_directory="$5"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    live_paths=(
        "${crate_directory}/assets"
        "${crate_directory}/src/generated_contract.rs"
        "${crate_directory}/src/generated_assets.rs"
        "${renderer_directory}/SHA256SUMS"
        "${renderer_directory}/PROVENANCE.toml"
        "${renderer_directory}/renderer.cdx.json"
    )
    automata_renderer_transaction_recover "${live_paths[@]}"
    automata_renderer_transaction_begin "${live_paths[@]}"
    printf "new component\n" > "${temporary_directory}/renderer-new.wasm"
    printf "asset=renderer-new.wasm\n" > "${temporary_directory}/generated_assets.rs"
    automata_renderer_transaction_publish_file \
        "${temporary_directory}/renderer-new.wasm" \
        "${crate_directory}/assets/renderer-new.wasm"
    automata_renderer_transaction_publish_file \
        "${temporary_directory}/generated_assets.rs" \
        "${crate_directory}/src/generated_assets.rs"
    kill -KILL "${BASHPID}"
' bash \
    "${transaction_helper}" \
    "${entrypoint_temporary}" \
    "${entrypoint_state}" \
    "${entrypoint_crate}" \
    "${entrypoint_repository}/ui/renderer" \
    >"${scratch_directory}/entrypoint-kill.log" 2>&1 &
entrypoint_kill_pid=$!
wait "${entrypoint_kill_pid}" 2>/dev/null
entrypoint_kill_status=$?
set -e
[[ "${entrypoint_kill_status}" -eq 137 && \
    -d "${entrypoint_temporary}" && -d "${entrypoint_state}/active" ]]

set +e
CARGO_HOME=/noncanonical/cargo \
RUSTUP_HOME=/noncanonical/rustup \
    bash "${entrypoint_repository}/scripts/ui/regenerate-renderer.sh" \
    >"${scratch_directory}/entrypoint-restart.log" 2>&1
entrypoint_restart_status=$?
set -e
[[ "${entrypoint_restart_status}" -eq 1 ]]
grep -Fq -- \
    'renderer regeneration requires CARGO_HOME=/opt/cargo and RUSTUP_HOME=/opt/rustup' \
    "${scratch_directory}/entrypoint-restart.log"
diff -qr -- "${baseline_directory}/assets" "${entrypoint_crate}/assets" >/dev/null
cmp --silent -- \
    "${baseline_directory}/generated_contract.rs" \
    "${entrypoint_crate}/src/generated_contract.rs"
cmp --silent -- \
    "${baseline_directory}/generated_assets.rs" \
    "${entrypoint_crate}/src/generated_assets.rs"
for entrypoint_manifest in SHA256SUMS PROVENANCE.toml renderer.cdx.json; do
    cmp --silent -- \
        "${baseline_directory}/${entrypoint_manifest}" \
        "${entrypoint_repository}/ui/renderer/${entrypoint_manifest}"
done
[[ ! -e "${entrypoint_state}/active" && ! -e "${entrypoint_temporary}" ]]

reset_case committed-kill
test_phase='committed-recovery'
committed_kill_temporary="${scratch_directory}/temporary-committed-kill"
committed_kill_state="${scratch_directory}/state-committed-kill"
set +e
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    live_paths=(
        "${live_directory}/assets"
        "${live_directory}/generated_contract.rs"
        "${live_directory}/generated_assets.rs"
        "${live_directory}/SHA256SUMS"
        "${live_directory}/PROVENANCE.toml"
        "${live_directory}/renderer.cdx.json"
    )
    automata_renderer_transaction_recover "${live_paths[@]}"
    automata_renderer_transaction_begin "${live_paths[@]}"
    printf "committed before cleanup\n" > "${temporary_directory}/generated_contract.rs"
    automata_renderer_transaction_publish_file \
        "${temporary_directory}/generated_contract.rs" \
        "${live_directory}/generated_contract.rs"
    rm() {
        local argument=""
        for argument in "$@"; do
            if [[ "${argument}" == "${state_directory}/committed" ]]; then
                command rm -f -- \
                    "${state_directory}/committed/FORMAT" \
                    "${state_directory}/committed/generated_contract.rs"
                kill -KILL "${BASHPID}"
            fi
        done
        command rm "$@"
    }
    automata_renderer_transaction_commit
' bash \
    "${transaction_helper}" \
    "${committed_kill_temporary}" \
    "${committed_kill_state}" \
    "${live_directory}" \
    >"${scratch_directory}/committed-kill.log" 2>&1 &
committed_kill_pid=$!
wait "${committed_kill_pid}" 2>/dev/null
committed_kill_status=$?
set -e
[[ "${committed_kill_status}" -eq 137 ]]
[[ ! -e "${committed_kill_state}/active" && \
    -d "${committed_kill_state}/committed" && \
    ! -e "${committed_kill_state}/committed/FORMAT" ]]
grep -Fqx -- 'committed before cleanup' "${live_directory}/generated_contract.rs"
committed_kill_restart="${scratch_directory}/restart-committed-kill"
mkdir -p -- "${committed_kill_restart}"
bash -euo pipefail -c '
    transaction_helper="$1"
    temporary_directory="$2"
    state_directory="$3"
    live_directory="$4"
    source "${transaction_helper}"
    automata_renderer_transaction_configure_cleanup \
        "${temporary_directory}" "${state_directory}"
    trap automata_renderer_transaction_exit EXIT
    automata_renderer_transaction_recover \
        "${live_directory}/assets" \
        "${live_directory}/generated_contract.rs" \
        "${live_directory}/generated_assets.rs" \
        "${live_directory}/SHA256SUMS" \
        "${live_directory}/PROVENANCE.toml" \
        "${live_directory}/renderer.cdx.json"
' bash \
    "${transaction_helper}" \
    "${committed_kill_restart}" \
    "${committed_kill_state}" \
    "${live_directory}"
grep -Fqx -- 'committed before cleanup' "${live_directory}/generated_contract.rs"
[[ ! -e "${committed_kill_state}/committed" && \
    ! -e "${committed_kill_temporary}" ]]

# Candidate verification rejects path indirection, every non-file asset entry,
# and any generated-Rust text outside the exact three-asset contract.
candidate_fixture="${scratch_directory}/candidate-fixture"
test_phase='candidate-verification'
mkdir -p -- "${candidate_fixture}/renderer" "${candidate_fixture}/assets"
cp -a -- \
    "${repository_root}/crates/automata-ci-ui-renderer/assets/." \
    "${candidate_fixture}/assets/"
cp -a -- \
    "${repository_root}/crates/automata-ci-ui-renderer/src/generated_assets.rs" \
    "${candidate_fixture}/generated_assets.rs"
for candidate_manifest in SHA256SUMS PROVENANCE.toml renderer.cdx.json; do
    cp -a -- \
        "${repository_root}/ui/renderer/${candidate_manifest}" \
        "${candidate_fixture}/renderer/${candidate_manifest}"
done
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-valid.log"

mv -- "${candidate_fixture}/renderer" "${scratch_directory}/saved-candidate-renderer"
ln -s -- "${scratch_directory}/saved-candidate-renderer" \
    "${candidate_fixture}/renderer"
set +e
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-directory-symlink.log" 2>&1
candidate_directory_symlink_status=$?
set -e
[[ "${candidate_directory_symlink_status}" -eq 1 ]]
grep -Fq -- 'renderer candidate is incomplete' \
    "${scratch_directory}/candidate-directory-symlink.log"
rm -- "${candidate_fixture}/renderer"
mv -- "${scratch_directory}/saved-candidate-renderer" \
    "${candidate_fixture}/renderer"

candidate_client="$(find "${candidate_fixture}/assets" -maxdepth 1 -type f \
    -name 'client-*.js' -print -quit)"
mv -- "${candidate_client}" "${scratch_directory}/saved-client.js"
ln -s -- "${scratch_directory}/saved-client.js" "${candidate_client}"
set +e
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-asset-symlink.log" 2>&1
candidate_asset_symlink_status=$?
set -e
[[ "${candidate_asset_symlink_status}" -eq 1 ]]
grep -Fq -- 'renderer asset entry is not a real regular file' \
    "${scratch_directory}/candidate-asset-symlink.log"
rm -- "${candidate_client}"
mv -- "${scratch_directory}/saved-client.js" "${candidate_client}"

mkdir -- "${candidate_fixture}/assets/unlisted-directory"
set +e
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-asset-directory.log" 2>&1
candidate_asset_directory_status=$?
set -e
[[ "${candidate_asset_directory_status}" -eq 1 ]]
grep -Fq -- 'renderer assets contain an unlisted or missing file' \
    "${scratch_directory}/candidate-asset-directory.log"
rmdir -- "${candidate_fixture}/assets/unlisted-directory"

mv -- \
    "${candidate_fixture}/renderer/SHA256SUMS" \
    "${scratch_directory}/saved-candidate-sums"
ln -s -- \
    "${scratch_directory}/saved-candidate-sums" \
    "${candidate_fixture}/renderer/SHA256SUMS"
set +e
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-manifest-symlink.log" 2>&1
candidate_manifest_symlink_status=$?
set -e
[[ "${candidate_manifest_symlink_status}" -eq 1 ]]
grep -Fq -- 'renderer input file is not a real file' \
    "${scratch_directory}/candidate-manifest-symlink.log"
rm -- "${candidate_fixture}/renderer/SHA256SUMS"
mv -- \
    "${scratch_directory}/saved-candidate-sums" \
    "${candidate_fixture}/renderer/SHA256SUMS"

mv -- \
    "${candidate_fixture}/generated_assets.rs" \
    "${scratch_directory}/saved-generated-assets.rs"
ln -s -- \
    "${scratch_directory}/saved-generated-assets.rs" \
    "${candidate_fixture}/generated_assets.rs"
set +e
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-rust-symlink.log" 2>&1
candidate_rust_symlink_status=$?
set -e
[[ "${candidate_rust_symlink_status}" -eq 1 ]]
grep -Fq -- 'renderer candidate is incomplete' \
    "${scratch_directory}/candidate-rust-symlink.log"
rm -- "${candidate_fixture}/generated_assets.rs"
mv -- \
    "${scratch_directory}/saved-generated-assets.rs" \
    "${candidate_fixture}/generated_assets.rs"

printf '%s\n' '// an extra include_bytes! or comment is not canonical' \
    >> "${candidate_fixture}/generated_assets.rs"
set +e
"${verifier}" --candidate "${candidate_fixture}" \
    >"${scratch_directory}/candidate-rust-contract.log" 2>&1
candidate_rust_contract_status=$?
set -e
[[ "${candidate_rust_contract_status}" -eq 1 ]]
grep -Fq -- 'generated Rust does not exactly match the renderer asset contract' \
    "${scratch_directory}/candidate-rust-contract.log"

# Ambiguous or unsafe journal phases are never treated as an inactive set.
ambiguous_state="${scratch_directory}/ambiguous-state"
mkdir -p -- "${ambiguous_state}"
cp -a -- \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active" \
    "${ambiguous_state}/active"
cp -a -- \
    "${fake_verifier_repository}/ui/renderer/.regeneration-transaction/active" \
    "${ambiguous_state}/committed"
if bash -euo pipefail -c '
    source "$1"
    automata_renderer_transaction_require_verifier_access "$2" "" ""
' bash "${transaction_helper}" "${ambiguous_state}" \
    >/dev/null 2>&1; then
    echo "renderer verifier accepted ambiguous transaction state" >&2
    exit 1
fi

line_number() {
    local file="$1"
    local pattern="$2"
    grep -nF -- "${pattern}" "${file}" | head -n 1 | cut -d: -f1
}

lock_line="$(line_number "${regenerator}" 'flock --exclusive --nonblock')"
test_phase='source-order-contract'
recover_line="$(line_number "${regenerator}" 'automata_renderer_transaction_recover')"
# These are literal source patterns.
# shellcheck disable=SC2016
preflight_line="$(line_number "${regenerator}" '[[ "${CARGO_HOME:-}" ==')"
# shellcheck disable=SC2016
scratch_allocate_line="$(line_number "${regenerator}" 'temporary_directory="$(mktemp -d')"
begin_line="$(line_number "${regenerator}" 'automata_renderer_transaction_begin')"
sync_line="$(line_number "${regenerator}" "node \"\${script_directory}/sync-render-contract.mjs\"")"
candidate_verify_line="$(line_number "${regenerator}" "    --candidate \"\${candidate_directory}\"")"
asset_publish_line="$(line_number "${regenerator}" "for staged_asset in \"\${staged_asset_files[@]}\"")"
rust_publish_line="$(line_number "${regenerator}" "automata_renderer_transaction_publish_file \"\${staged_rust}\" \"\${generated_rust}\"")"
asset_retire_line="$(line_number "${regenerator}" 'live_asset; do')"
final_verify_line="$(grep -nF -- 'verify-renderer-assets.sh"' \
    "${regenerator}" | tail -n 1 | cut -d: -f1)"
commit_line="$(line_number "${regenerator}" 'automata_renderer_transaction_commit')"
verifier_guard_line="$(line_number "${verifier}" 'automata_renderer_transaction_require_verifier_access')"
verifier_shared_lock_line="$(line_number "${verifier}" 'flock --shared --nonblock')"
verifier_sync_line="$(line_number "${verifier}" "node \"\${script_directory}/sync-render-contract.mjs\" --check")"

[[ "${lock_line}" -lt "${recover_line}" ]]
[[ "${recover_line}" -lt "${preflight_line}" ]]
[[ "${recover_line}" -lt "${scratch_allocate_line}" ]]
[[ "${recover_line}" -lt "${begin_line}" ]]
[[ "${begin_line}" -lt "${sync_line}" ]]
[[ "${candidate_verify_line}" -lt "${asset_publish_line}" ]]
[[ "${asset_publish_line}" -lt "${rust_publish_line}" ]]
[[ "${rust_publish_line}" -lt "${asset_retire_line}" ]]
[[ "${asset_retire_line}" -lt "${final_verify_line}" ]]
[[ "${final_verify_line}" -lt "${commit_line}" ]]
[[ "${verifier_shared_lock_line}" -lt "${verifier_guard_line}" ]]
[[ "${verifier_guard_line}" -lt "${verifier_sync_line}" ]]
[[ "$(grep -c -- '--transaction-owner-marker' "${regenerator}")" -eq 2 ]]
[[ "$(grep -c -- '--transaction-owner-id' "${regenerator}")" -eq 2 ]]
[[ "$(grep -c -- '--transaction-owner-lock-fd' "${regenerator}")" -eq 2 ]]
if grep -Fq -- 'target/ui-renderer-regeneration.lock' "${regenerator}"; then
    echo "renderer regenerator still uses a disposable target lock" >&2
    exit 1
fi

echo "renderer publication recovers process death and strictly verifies candidates"
