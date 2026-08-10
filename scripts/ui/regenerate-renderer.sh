#!/usr/bin/env bash
set -euo pipefail

readonly expected_wasm_rquickjs_version="wasm-rquickjs-cli 0.4.1"
readonly expected_rust_release="1.97.1"
readonly expected_rustc_version="rustc 1.97.1 (8bab26f4f 2026-07-14)"
readonly expected_cargo_version="cargo 1.97.1 (c980f4866 2026-06-30)"
readonly expected_rustfmt_version="rustfmt 1.9.0-stable (8bab26f4f6 2026-07-14)"
readonly expected_node_release="24.19.0"
readonly expected_npm_release="11.17.0"
readonly expected_cyclonedx_version="cargo-cyclonedx-cyclonedx 0.5.9"
readonly expected_clang_package="clang-18=1:18.1.3-1ubuntu1"
readonly expected_libclang_package="libclang1-18=1:18.1.3-1ubuntu1"
readonly expected_cargo_home="/opt/cargo"
readonly expected_rustup_home="/opt/rustup"
readonly expected_cargo_binary="${expected_cargo_home}/bin/cargo"
readonly expected_rustc_binary="${expected_cargo_home}/bin/rustc"
readonly expected_rustfmt_binary="${expected_cargo_home}/bin/rustfmt"
readonly expected_wasm_rquickjs_binary="${expected_cargo_home}/bin/wasm-rquickjs"
readonly expected_cyclonedx_binary="${expected_cargo_home}/bin/cargo-cyclonedx"
readonly expected_clang_binary="/usr/bin/clang-18"
readonly expected_clang_resource_directory="/usr/lib/llvm-18/lib/clang/18"
readonly expected_libclang_library="/usr/lib/x86_64-linux-gnu/libclang-18.so.18"
readonly expected_wasi_sdk_version="24.0"
readonly expected_wasi_sdk_platform="x86_64-linux"
readonly expected_wasi_sdk_archive="wasi-sdk-24.0-x86_64-linux.tar.gz"
readonly expected_wasi_sdk_archive_sha256="c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5"
readonly expected_wasi_sdk_directory="/opt/wasi-sdk-24.0"
readonly expected_wasi_clang_binary="${expected_wasi_sdk_directory}/bin/clang"
readonly expected_wasi_ar_binary="${expected_wasi_sdk_directory}/bin/ar"
readonly expected_wasi_llvm_ar_binary="${expected_wasi_sdk_directory}/bin/llvm-ar"
readonly expected_wasi_sysroot="${expected_wasi_sdk_directory}/share/wasi-sysroot"
readonly expected_wasi_clang_resource_directory="${expected_wasi_sdk_directory}/lib/clang/18"
readonly expected_wasi_clang_version="clang version 18.1.2-wasi-sdk (https://github.com/llvm/llvm-project 26a1d6601d727a96f4301d0d8647b5a42760ae0c)"
readonly expected_wasi_ar_version="LLVM version 18.1.2-wasi-sdk"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
# Keep ambient rejection filesystem-free and first so a malformed invocation
# cannot influence even interrupted-transaction recovery.
# shellcheck source=scripts/ui/renderer-preflight-env.sh
source "${script_directory}/renderer-preflight-env.sh"
automata_renderer_reject_ambient_overrides

ui_directory="${repository_root}/ui"
renderer_directory="${ui_directory}/renderer"
crate_directory="${repository_root}/crates/automata-ci-ui-renderer"
asset_directory="${crate_directory}/assets"
wit_file="${crate_directory}/wit/renderer.wit"
generated_contract="${crate_directory}/src/generated_contract.rs"
generated_rust="${crate_directory}/src/generated_assets.rs"
wrapper_lock="${renderer_directory}/wrapper.Cargo.lock"
wrapper_manifest="${renderer_directory}/wrapper.Cargo.toml"
canonical_macro_directory="${renderer_directory}/vendor/rquickjs-macro-0.10.0"
transaction_state_directory="${renderer_directory}/.regeneration-transaction"
transaction_recovery_initialized=0

initialize_renderer_transaction_recovery() {
    # The stable checked-in directory inode prevents target cleanup from
    # creating a second lock namespace while publication is active.
    local recovery_command=''

    for recovery_command in \
        chmod cmp cp diff find flock install mv realpath rm sort stat; do
        command -v "${recovery_command}" >/dev/null 2>&1 || {
            echo "required recovery command is unavailable: ${recovery_command}" >&2
            return 1
        }
    done
    [[ -d "${renderer_directory}" && ! -L "${renderer_directory}" ]] || {
        echo "renderer source directory must be a real directory" >&2
        return 1
    }
    exec {regeneration_lock_fd}<"${renderer_directory}"
    flock --exclusive --nonblock "${regeneration_lock_fd}" || {
        echo "another renderer regeneration or verification owns the checked-in set" >&2
        return 1
    }
    readonly regeneration_lock_fd
    # shellcheck source=scripts/ci/lib/target-paths.sh
    source "${repository_root}/scripts/ci/lib/target-paths.sh"
    automata_init_target_root "${repository_root}"
    scratch_directory="$(
        automata_canonical_exact_target_child \
            "${repository_root}/target/agent-scratch/ssr" \
            "renderer scratch directory"
    )"
    # shellcheck source=scripts/ui/lib/renderer-generation-transaction.sh
    source "${script_directory}/lib/renderer-generation-transaction.sh"
    automata_renderer_transaction_configure_state \
        "${transaction_state_directory}" \
        "${scratch_directory}"
    renderer_transaction_live_paths=(
        "${asset_directory}"
        "${generated_contract}"
        "${generated_rust}"
        "${renderer_directory}/SHA256SUMS"
        "${renderer_directory}/PROVENANCE.toml"
        "${renderer_directory}/renderer.cdx.json"
    )
    automata_renderer_transaction_recover "${renderer_transaction_live_paths[@]}"
    transaction_recovery_initialized=1
}

# In a real checkout, recovery and the exact orphan-scratch sweep run before
# toolchain, Cargo configuration, or new allocation. The source-directory test
# lets isolated environment-preflight fixtures remain filesystem-free.
if [[ -e "${renderer_directory}" || -L "${renderer_directory}" ]]; then
    initialize_renderer_transaction_recovery
fi

[[ "${CARGO_HOME:-}" == "${expected_cargo_home}" && \
    "${RUSTUP_HOME:-}" == "${expected_rustup_home}" ]] || {
    echo "renderer regeneration requires CARGO_HOME=${expected_cargo_home} and RUSTUP_HOME=${expected_rustup_home}" >&2
    exit 1
}

cargo_config_search_directory="${repository_root}"
while :; do
    for cargo_config in \
        "${cargo_config_search_directory}/.cargo/config" \
        "${cargo_config_search_directory}/.cargo/config.toml"; do
        [[ ! -e "${cargo_config}" && ! -L "${cargo_config}" ]] || {
            echo "renderer regeneration forbids Cargo config: ${cargo_config}" >&2
            exit 1
        }
    done
    [[ "${cargo_config_search_directory}" != / ]] || break
    cargo_config_search_directory="${cargo_config_search_directory%/*}"
    [[ -n "${cargo_config_search_directory}" ]] || \
        cargo_config_search_directory=/
done
for cargo_config in \
    "${expected_cargo_home}/config" \
    "${expected_cargo_home}/config.toml"; do
    [[ ! -e "${cargo_config}" && ! -L "${cargo_config}" ]] || {
        echo "renderer regeneration forbids Cargo config: ${cargo_config}" >&2
        exit 1
    }
done

# Cargo discovers hierarchical config from its process working directory, not
# from --manifest-path. Pin that lookup root after the complete config scan.
cd -- "${repository_root}"

for command in \
    chmod cmp cp diff find flock install mktemp mv node npm python3 readlink rm sha256sum; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "required command is unavailable: ${command}" >&2
        exit 1
    }
done
for binary in \
    "${expected_cargo_binary}" \
    "${expected_rustc_binary}" \
    "${expected_rustfmt_binary}" \
    "${expected_wasm_rquickjs_binary}" \
    "${expected_cyclonedx_binary}"; do
    [[ -x "${binary}" ]] || {
        echo "required canonical executable is unavailable: ${binary}" >&2
        exit 1
    }
done

actual_wasm_rquickjs_version="$("${expected_wasm_rquickjs_binary}" --version)"
[[ "${actual_wasm_rquickjs_version}" == "${expected_wasm_rquickjs_version}" ]] || {
    echo "expected ${expected_wasm_rquickjs_version}; found ${actual_wasm_rquickjs_version}" >&2
    exit 1
}

actual_rustc_version="$("${expected_rustc_binary}" --version)"
[[ "${actual_rustc_version}" == "${expected_rustc_version}" ]] || {
    echo "expected ${expected_rustc_version}; found ${actual_rustc_version}" >&2
    exit 1
}
actual_rust_release="${actual_rustc_version#rustc }"
actual_rust_release="${actual_rust_release%% *}"
[[ "${actual_rust_release}" == "${expected_rust_release}" ]] || {
    echo "expected rustc ${expected_rust_release}; found ${actual_rust_release}" >&2
    exit 1
}
actual_cargo_version="$("${expected_cargo_binary}" --version)"
[[ "${actual_cargo_version}" == "${expected_cargo_version}" ]] || {
    echo "expected ${expected_cargo_version}; found ${actual_cargo_version}" >&2
    exit 1
}
actual_rustfmt_version="$("${expected_rustfmt_binary}" --version)"
[[ "${actual_rustfmt_version}" == "${expected_rustfmt_version}" ]] || {
    echo "expected ${expected_rustfmt_version}; found ${actual_rustfmt_version}" >&2
    exit 1
}

actual_node_release="$(node --version | sed 's/^v//')"
[[ "${actual_node_release}" == "${expected_node_release}" ]] || {
    echo "expected node ${expected_node_release}; found ${actual_node_release}" >&2
    exit 1
}
actual_npm_release="$(npm --version)"
[[ "${actual_npm_release}" == "${expected_npm_release}" ]] || {
    echo "expected npm ${expected_npm_release}; found ${actual_npm_release}" >&2
    exit 1
}

actual_cyclonedx_version="$("${expected_cargo_binary}" cyclonedx --version)"
[[ "${actual_cyclonedx_version}" == "${expected_cyclonedx_version}" ]] || {
    echo "expected cargo-cyclonedx 0.5.9; found ${actual_cyclonedx_version}" >&2
    exit 1
}
actual_clang_package="clang-18=$(/usr/bin/dpkg-query --show --showformat='${Version}' clang-18)"
[[ "${actual_clang_package}" == "${expected_clang_package}" ]] || {
    echo "expected ${expected_clang_package}; found ${actual_clang_package}" >&2
    exit 1
}
actual_libclang_package="libclang1-18=$(/usr/bin/dpkg-query --show --showformat='${Version}' libclang1-18)"
[[ "${actual_libclang_package}" == "${expected_libclang_package}" ]] || {
    echo "expected ${expected_libclang_package}; found ${actual_libclang_package}" >&2
    exit 1
}
[[ -x "${expected_clang_binary}" ]] || {
    echo "expected Clang executable is unavailable: ${expected_clang_binary}" >&2
    exit 1
}
actual_clang_resource_directory="$("${expected_clang_binary}" --print-resource-dir)"
[[ "${actual_clang_resource_directory}" == "${expected_clang_resource_directory}" ]] || {
    echo "expected Clang resource directory ${expected_clang_resource_directory}; found ${actual_clang_resource_directory}" >&2
    exit 1
}
[[ -r "${expected_clang_resource_directory}/include/stddef.h" ]] || {
    echo "Clang resource headers are unavailable" >&2
    exit 1
}
[[ -r "${expected_libclang_library}" ]] || {
    echo "expected libclang library is unavailable: ${expected_libclang_library}" >&2
    exit 1
}
/usr/bin/python3 -c \
    'import ctypes, sys; getattr(ctypes.CDLL(sys.argv[1]), "clang_getClangVersion")' \
    "${expected_libclang_library}" || {
    echo "expected libclang C API is unavailable" >&2
    exit 1
}

[[ -d "${expected_wasi_sdk_directory}" && \
    -x "${expected_wasi_clang_binary}" && \
    -x "${expected_wasi_ar_binary}" && \
    -x "${expected_wasi_llvm_ar_binary}" ]] || {
    echo "canonical WASI SDK executables are unavailable under ${expected_wasi_sdk_directory}" >&2
    exit 1
}
[[ "$(readlink -f -- "${expected_wasi_ar_binary}")" == \
    "$(readlink -f -- "${expected_wasi_llvm_ar_binary}")" ]] || {
    echo "canonical WASI SDK ar does not resolve to llvm-ar" >&2
    exit 1
}
actual_wasi_clang_version="$("${expected_wasi_clang_binary}" --version | sed -n '1p')"
[[ "${actual_wasi_clang_version}" == "${expected_wasi_clang_version}" ]] || {
    echo "expected ${expected_wasi_clang_version}; found ${actual_wasi_clang_version}" >&2
    exit 1
}
actual_wasi_ar_version="$(
    "${expected_wasi_ar_binary}" --version \
        | sed -n '/LLVM version/{s/^[[:space:]]*//;p;q;}'
)"
[[ "${actual_wasi_ar_version}" == "${expected_wasi_ar_version}" ]] || {
    echo "expected ${expected_wasi_ar_version}; found ${actual_wasi_ar_version}" >&2
    exit 1
}
actual_wasi_clang_resource_directory="$(
    "${expected_wasi_clang_binary}" --print-resource-dir
)"
[[ "${actual_wasi_clang_resource_directory}" == \
    "${expected_wasi_clang_resource_directory}" ]] || {
    echo "expected WASI Clang resource directory ${expected_wasi_clang_resource_directory}; found ${actual_wasi_clang_resource_directory}" >&2
    exit 1
}
[[ -r "${expected_wasi_clang_resource_directory}/include/stddef.h" && \
    -r "${expected_wasi_sysroot}/include/wasm32-wasip2/stdio.h" ]] || {
    echo "canonical WASI SDK compiler or wasip2 sysroot headers are unavailable" >&2
    exit 1
}
printf '#include <stdio.h>\nint main(void) { return 0; }\n' \
    | "${expected_wasi_clang_binary}" \
        --target=wasm32-wasip2 \
        --sysroot="${expected_wasi_sysroot}" \
        -Werror \
        -fsyntax-only \
        -x c \
        - || {
    echo "canonical WASI SDK compiler/sysroot smoke test failed" >&2
    exit 1
}

# If there was no interrupted phase, acquire the same stable lock only after
# the canonical preflight. Do not allocate new scratch or begin publication
# before both recovery and that preflight are complete.
if (( transaction_recovery_initialized == 0 )); then
    initialize_renderer_transaction_recovery
fi
[[ ! -L "${transaction_state_directory}" ]] || {
    echo "renderer regeneration transaction state must not be a symbolic link" >&2
    exit 1
}
install -d -m 0700 -- "${transaction_state_directory}"
mkdir -p -- "${scratch_directory}"
export TMPDIR="${scratch_directory}"
temporary_directory="$(mktemp -d "${scratch_directory}/regenerate.XXXXXXXX")"
automata_renderer_transaction_configure_cleanup \
    "${temporary_directory}" \
    "${transaction_state_directory}"
trap automata_renderer_transaction_exit EXIT
automata_renderer_transaction_begin \
    "${renderer_transaction_live_paths[@]}"
transaction_owner_marker="$(automata_renderer_transaction_owner_marker)"
transaction_owner_id="$(automata_renderer_transaction_owner_id)"

node "${script_directory}/sync-render-contract.mjs"
npm --prefix "${ui_directory}" ci
npm --prefix "${ui_directory}" run build

nominal_wrapper_work_directory="${repository_root}/target/ui-renderer-wrapper"
nominal_wrapper_directory="${nominal_wrapper_work_directory}/source"
wrapper_work_directory="$(
    automata_canonical_exact_target_child \
        "${nominal_wrapper_work_directory}" \
        "renderer wrapper work directory"
)"
wrapper_directory="$(
    automata_canonical_exact_target_child \
        "${nominal_wrapper_directory}" \
        "renderer wrapper source directory"
)"
wrapper_target_directory="$(
    automata_canonical_exact_target_child \
        "${wrapper_work_directory}/cargo-target" \
        "renderer Cargo target directory"
)"
wrapper_candidate_directory="${temporary_directory}/wrapper-source"
"${expected_wasm_rquickjs_binary}" generate-wrapper-crate \
    --js "${ui_directory}/dist/ssr/renderer.mjs" \
    --wit "${crate_directory}/wit" \
    --world renderer \
    --target wasi-p2 \
    --output "${wrapper_candidate_directory}"
install -m 0644 -- "${wrapper_manifest}" "${wrapper_candidate_directory}/Cargo.toml"
install -m 0644 -- "${wrapper_lock}" "${wrapper_candidate_directory}/Cargo.lock"
install -d -m 0755 -- "${wrapper_candidate_directory}/vendor"
cp -a -- \
    "${canonical_macro_directory}" \
    "${wrapper_candidate_directory}/vendor/rquickjs-macro-0.10.0"
diff -qr -- \
    "${canonical_macro_directory}" \
    "${wrapper_candidate_directory}/vendor/rquickjs-macro-0.10.0" \
    >/dev/null || {
    echo "renderer wrapper macro copy differs from the reviewed source" >&2
    exit 1
}

mkdir -p -- "${wrapper_work_directory}"
if [[ ! -d "${wrapper_directory}" ]]; then
    mv -- "${wrapper_candidate_directory}" "${wrapper_directory}"
elif ! diff -qr -- "${wrapper_directory}" "${wrapper_candidate_directory}" >/dev/null; then
    verified_wrapper_directory="$(
        automata_canonical_exact_target_child \
            "${nominal_wrapper_directory}" \
            "renderer wrapper source directory"
    )"
    [[ "${verified_wrapper_directory}" == "${wrapper_directory}" ]] || {
        echo "renderer wrapper source changed during regeneration" >&2
        exit 1
    }
    rm -rf -- "${wrapper_directory}"
    mv -- "${wrapper_candidate_directory}" "${wrapper_directory}"
fi
diff -qr -- \
    "${canonical_macro_directory}" \
    "${wrapper_directory}/vendor/rquickjs-macro-0.10.0" \
    >/dev/null || {
    echo "stable renderer wrapper macro copy differs from the reviewed source" >&2
    exit 1
}
wrapper_metadata="${temporary_directory}/cargo-metadata.json"
"${expected_cargo_binary}" metadata \
    --manifest-path "${wrapper_directory}/Cargo.toml" \
    --locked \
    --format-version 1 \
    > "${wrapper_metadata}"
python3 "${script_directory}/verify-wrapper-path-sources.py" \
    "${wrapper_directory}" \
    "${wrapper_metadata}"

rust_path_remaps="--remap-path-prefix=${repository_root}=/automata --remap-path-prefix=${CARGO_HOME}=/cargo --remap-path-prefix=${RUSTUP_HOME}=/rustup --remap-path-prefix=${expected_wasi_sdk_directory}=/wasi-sdk"
c_path_remaps="-ffile-prefix-map=${repository_root}=/automata -fdebug-prefix-map=${repository_root}=/automata -ffile-prefix-map=${CARGO_HOME}=/cargo -fdebug-prefix-map=${CARGO_HOME}=/cargo -ffile-prefix-map=${RUSTUP_HOME}=/rustup -fdebug-prefix-map=${RUSTUP_HOME}=/rustup -ffile-prefix-map=${expected_wasi_sdk_directory}=/wasi-sdk -fdebug-prefix-map=${expected_wasi_sdk_directory}=/wasi-sdk"

SOURCE_DATE_EPOCH=0 \
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
CFLAGS_wasm32_wasip2="${c_path_remaps}" \
RUSTFLAGS="${rust_path_remaps}" \
CARGO_TARGET_DIR="${wrapper_target_directory}" \
RUSTC="${expected_rustc_binary}" \
LIBCLANG_PATH="${expected_libclang_library}" \
CLANG_PATH="${expected_clang_binary}" \
WASI_SDK="${expected_wasi_sdk_directory}" \
"${expected_cargo_binary}" build \
    --manifest-path "${wrapper_directory}/Cargo.toml" \
    --locked \
    --release \
    --target wasm32-wasip2 \
    --no-default-features \
    --features p2,encoding

mapfile -t script_files < <(
    find "${ui_directory}/dist/client/assets" -maxdepth 1 -type f \
        -name 'entry-client-*.js' -print | LC_ALL=C sort
)
mapfile -t style_files < <(
    find "${ui_directory}/dist/client/assets" -maxdepth 1 -type f \
        -name 'entry-client-*.css' -print | LC_ALL=C sort
)
[[ "${#script_files[@]}" -eq 1 && "${#style_files[@]}" -eq 1 ]] || {
    echo "expected exactly one Vite client script and one stylesheet" >&2
    exit 1
}

component_source="${wrapper_target_directory}/wasm32-wasip2/release/renderer.wasm"
script_source="${script_files[0]}"
style_source="${style_files[0]}"
[[ -f "${component_source}" ]] || {
    echo "wasm-rquickjs did not produce renderer.wasm" >&2
    exit 1
}

script_public_name="${script_source##*/}"
style_public_name="${style_source##*/}"
[[ "${script_public_name}" =~ ^entry-client-[A-Za-z0-9_-]+\.js$ ]] || exit 1
[[ "${style_public_name}" =~ ^entry-client-[A-Za-z0-9_-]+\.css$ ]] || exit 1

script_hash="$(sha256sum "${script_source}" | awk '{print $1}')"
style_hash="$(sha256sum "${style_source}" | awk '{print $1}')"
wit_hash="$(sha256sum "${wit_file}" | awk '{print $1}')"
wrapper_lock_hash="$(sha256sum "${wrapper_lock}" | awk '{print $1}')"
wrapper_manifest_hash="$(sha256sum "${wrapper_manifest}" | awk '{print $1}')"
wrapper_macro_patch_hash="$({
    cd -- "${renderer_directory}"
    find "vendor/rquickjs-macro-0.10.0" -type f -print0 \
        | LC_ALL=C sort -z \
        | while IFS= read -r -d '' relative_path; do
            sha256sum "${relative_path}"
        done
} | sha256sum | awk '{print $1}')"
ssr_bundle_hash="$(sha256sum "${ui_directory}/dist/ssr/renderer.mjs" | awk '{print $1}')"
package_lock_hash="$(sha256sum "${ui_directory}/package-lock.json" | awk '{print $1}')"

stamped_component="${temporary_directory}/renderer.wasm"
python3 "${script_directory}/component-wit-provenance.py" stamp \
    "${component_source}" \
    "${stamped_component}" \
    "${wit_hash}"
component_hash="$(sha256sum "${stamped_component}" | awk '{print $1}')"

component_name="renderer-${component_hash}.wasm"
script_name="client-${script_hash}.js"
style_name="styles-${style_hash}.css"
candidate_directory="${temporary_directory}/candidate"
candidate_renderer_directory="${candidate_directory}/renderer"
staged_assets="${candidate_directory}/assets"
mkdir -p -- "${staged_assets}"
mkdir -p -- "${candidate_renderer_directory}"
install -m 0644 -- "${stamped_component}" "${staged_assets}/${component_name}"
install -m 0644 -- "${script_source}" "${staged_assets}/${script_name}"
install -m 0644 -- "${style_source}" "${staged_assets}/${style_name}"

staged_rust="${candidate_directory}/generated_assets.rs"
printf '%s\n' \
    '// @generated by scripts/ui/regenerate-renderer.sh; do not edit by hand.' \
    '' \
    'pub(crate) const COMPONENT_BYTES: &[u8] = include_bytes!(' \
    "    \"../assets/${component_name}\"" \
    ');' \
    'pub(crate) const COMPONENT_SHA256: &str =' \
    "    \"${component_hash}\";" \
    '' \
    'pub(crate) const CLIENT_SCRIPT_BYTES: &[u8] = include_bytes!(' \
    "    \"../assets/${script_name}\"" \
    ');' \
    'pub(crate) const CLIENT_SCRIPT_SHA256: &str =' \
    "    \"${script_hash}\";" \
    "pub(crate) const CLIENT_SCRIPT_PATH: &str = \"/assets/${script_public_name}\";" \
    '' \
    'pub(crate) const CLIENT_STYLE_BYTES: &[u8] = include_bytes!(' \
    "    \"../assets/${style_name}\"" \
    ');' \
    'pub(crate) const CLIENT_STYLE_SHA256: &str =' \
    "    \"${style_hash}\";" \
    "pub(crate) const CLIENT_STYLE_PATH: &str = \"/assets/${style_public_name}\";" \
    > "${staged_rust}"
"${expected_rustfmt_binary}" --edition 2024 "${staged_rust}"

staged_sums="${candidate_renderer_directory}/SHA256SUMS"
printf '%s  %s\n' \
    "${script_hash}" "crates/automata-ci-ui-renderer/assets/${script_name}" \
    "${component_hash}" "crates/automata-ci-ui-renderer/assets/${component_name}" \
    "${style_hash}" "crates/automata-ci-ui-renderer/assets/${style_name}" \
    > "${staged_sums}"

staged_provenance="${candidate_renderer_directory}/PROVENANCE.toml"
printf '%s\n' \
    'schema = 1' \
    '' \
    '[tools]' \
    'wasm_rquickjs_cli = "0.4.1"' \
    "rustc = \"${actual_rust_release}\"" \
    "cargo = \"${actual_cargo_version}\"" \
    "rustfmt = \"${actual_rustfmt_version}\"" \
    "node = \"${actual_node_release}\"" \
    "npm = \"${actual_npm_release}\"" \
    "clang = \"${actual_clang_package}\"" \
    "libclang = \"${actual_libclang_package}\"" \
    "wasi_sdk_version = \"${expected_wasi_sdk_version}\"" \
    "wasi_sdk_platform = \"${expected_wasi_sdk_platform}\"" \
    "wasi_sdk_archive = \"${expected_wasi_sdk_archive}\"" \
    "wasi_sdk_archive_sha256 = \"${expected_wasi_sdk_archive_sha256}\"" \
    "wasi_sdk_installation_root = \"${expected_wasi_sdk_directory}\"" \
    "wasi_sdk_clang = \"${actual_wasi_clang_version}\"" \
    "wasi_sdk_llvm_ar = \"${actual_wasi_ar_version}\"" \
    '' \
    '[wrapper]' \
    'target = "wasm32-wasip2"' \
    'profile = "release"' \
    'features = ["p2", "encoding"]' \
    'codegen_units = 1' \
    'incremental = false' \
    'source_date_epoch = 0' \
    'repository_path_remap = "/automata"' \
    'cargo_home_path_remap = "/cargo"' \
    'rustup_home_path_remap = "/rustup"' \
    'wasi_sdk_path_remap = "/wasi-sdk"' \
    "lock_sha256 = \"${wrapper_lock_hash}\"" \
    "manifest_sha256 = \"${wrapper_manifest_hash}\"" \
    "macro_patch_sha256 = \"${wrapper_macro_patch_hash}\"" \
    "wit_sha256 = \"${wit_hash}\"" \
    "ssr_bundle_sha256 = \"${ssr_bundle_hash}\"" \
    '' \
    '[ui]' \
    "package_lock_sha256 = \"${package_lock_hash}\"" \
    "script_public_path = \"/assets/${script_public_name}\"" \
    "stylesheet_public_path = \"/assets/${style_public_name}\"" \
    '' \
    '[artifacts]' \
    "component_sha256 = \"${component_hash}\"" \
    "script_sha256 = \"${script_hash}\"" \
    "stylesheet_sha256 = \"${style_hash}\"" \
    > "${staged_provenance}"

staged_sbom="${candidate_renderer_directory}/renderer.cdx.json"
PATH="${expected_cargo_home}/bin:${PATH}" \
    "${script_directory}/generate-renderer-sbom.sh" \
        "${staged_sbom}" \
        "${staged_assets}/${component_name}"
"${script_directory}/verify-renderer-assets.sh" \
    --transaction-owner-marker "${transaction_owner_marker}" \
    --transaction-owner-id "${transaction_owner_id}" \
    --transaction-owner-lock-fd "${regeneration_lock_fd}" \
    --candidate "${candidate_directory}" \
    "${ui_directory}/dist"

# There is no cross-directory atomic rename for this checked-in set. The
# exclusive stable-directory lock is therefore the coherence barrier for
# participating multi-file verifiers. Within that window, publish every
# immutable asset first, atomically switch generated Rust, and only then retire
# predecessor assets; generated Rust consequently never names an absent asset,
# even after SIGKILL.
mapfile -d '' -t staged_asset_files < <(
    find "${staged_assets}" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z
)
for staged_asset in "${staged_asset_files[@]}"; do
    automata_renderer_transaction_publish_file \
        "${staged_asset}" \
        "${asset_directory}/${staged_asset##*/}"
done
automata_renderer_transaction_publish_file "${staged_rust}" "${generated_rust}"
automata_renderer_transaction_publish_file \
    "${staged_sums}" \
    "${renderer_directory}/SHA256SUMS"
automata_renderer_transaction_publish_file \
    "${staged_provenance}" \
    "${renderer_directory}/PROVENANCE.toml"
automata_renderer_transaction_publish_file \
    "${staged_sbom}" \
    "${renderer_directory}/renderer.cdx.json"
while IFS= read -r -d '' live_asset; do
    if [[ ! -f "${staged_assets}/${live_asset##*/}" ]]; then
        rm -f -- "${live_asset}"
    fi
done < <(
    find "${asset_directory}" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z
)

"${script_directory}/verify-renderer-assets.sh" \
    --transaction-owner-marker "${transaction_owner_marker}" \
    --transaction-owner-id "${transaction_owner_id}" \
    --transaction-owner-lock-fd "${regeneration_lock_fd}"
automata_renderer_transaction_commit
echo "renderer component and client assets regenerated"
