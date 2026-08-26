#!/usr/bin/env bash
set -euo pipefail

test_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${test_directory}/../../.." && pwd -P)"
scratch_root="${repository_root}/target/task-tmp/renderer-preflight-test"
mkdir -p -- "${scratch_root}"
scratch_directory="$(mktemp -d "${scratch_root}/case.XXXXXXXX")"
cleanup() {
    rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

helper="${repository_root}/scripts/ui/renderer-preflight-env.sh"
builder="${repository_root}/scripts/ui/build-renderer.sh"
fake_repository="${scratch_directory}/workspace"
fake_script_directory="${fake_repository}/scripts/ui"
mkdir -p -- "${fake_script_directory}"
install -m 0644 -- "${helper}" "${fake_script_directory}/renderer-preflight-env.sh"
install -m 0755 -- "${builder}" "${fake_script_directory}/build-renderer.sh"

clean_environment=(
    PATH=/usr/bin:/bin
    CARGO_HOME=/opt/cargo
    RUSTUP_HOME=/opt/rustup
    CARGO_INCREMENTAL=0
)

# shellcheck disable=SC2016
/usr/bin/env -i "${clean_environment[@]}" \
    bash -c \
    'source "$1"; automata_renderer_reject_ambient_overrides' \
    bash \
    "${helper}"

for variable in \
    LIBCLANG_PATH \
    LIBCLANG_STATIC_PATH \
    BINDGEN_EXTRA_CLANG_ARGS \
    BINDGEN_EXTRA_CLANG_ARGS_wasm32-wasip2 \
    BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip2 \
    LLVM_CONFIG_PATH \
    CLANG_PATH \
    LD_LIBRARY_PATH \
    WASI_SDK \
    WASI_SYSROOT \
    CC \
    CC_wasm32-wasip2 \
    CC_wasm32_wasip2 \
    CC_x86_64-unknown-linux-gnu \
    CC_x86_64_unknown_linux_gnu \
    TARGET_CC \
    AR \
    AR_wasm32-wasip2 \
    AR_wasm32_wasip2 \
    AR_x86_64-unknown-linux-gnu \
    TARGET_AR \
    CFLAGS \
    CFLAGS_wasm32-wasip2 \
    CFLAGS_wasm32_wasip2 \
    CFLAGS_x86_64_unknown_linux_gnu \
    TARGET_CFLAGS \
    ARFLAGS \
    RANLIBFLAGS_wasm32_wasip2 \
    CPPFLAGS \
    LDFLAGS \
    CC_KNOWN_WRAPPER_CUSTOM \
    CC_SHELL_ESCAPED_FLAGS \
    ZERO_AR_DATE \
    CPATH \
    LIBRARY_PATH \
    RUSTC \
    RUSTC_LINKER \
    RUSTC_WRAPPER \
    RUSTC_WORKSPACE_WRAPPER \
    RUSTFLAGS \
    CARGO_ENCODED_RUSTFLAGS \
    RUSTDOCFLAGS \
    CARGO_ENCODED_RUSTDOCFLAGS \
    RUSTC_BOOTSTRAP \
    RUSTUP_TOOLCHAIN \
    RUST_TARGET_PATH \
    CARGO \
    CARGO_CONFIG \
    CARGO_TARGET_DIR \
    CARGO_BUILD_RUSTFLAGS \
    CARGO_TARGET_WASM32_WASIP2_LINKER \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
    CARGO_REGISTRIES_CRATES_IO_INDEX \
    CARGO_SOURCE_CRATES_IO_REPLACE_WITH \
    SOURCE_DATE_EPOCH; do
    log="${scratch_directory}/${variable//[^A-Za-z0-9_]/_}.log"
    if /usr/bin/env -i \
        "${clean_environment[@]}" \
        "${variable}=adversarial" \
        bash "${fake_script_directory}/build-renderer.sh" \
        >"${log}" 2>&1; then
        echo "renderer build accepted ambient ${variable}" >&2
        exit 1
    fi
    grep -Fq -- "${variable}" "${log}" || {
        echo "renderer build did not identify rejected ${variable}" >&2
        exit 1
    }
    [[ ! -e "${fake_repository}/target" ]] || {
        echo "renderer build touched target before rejecting ${variable}" >&2
        exit 1
    }
done

empty_log="${scratch_directory}/empty-wasi-sdk.log"
if /usr/bin/env -i \
    "${clean_environment[@]}" \
    WASI_SDK= \
    bash "${fake_script_directory}/build-renderer.sh" \
    >"${empty_log}" 2>&1; then
    echo "renderer build accepted an empty ambient WASI_SDK" >&2
    exit 1
fi
grep -Fq -- 'WASI_SDK' "${empty_log}"
[[ ! -e "${fake_repository}/target" ]]

incremental_log="${scratch_directory}/cargo-incremental.log"
if /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    CARGO_INCREMENTAL=1 \
    bash "${fake_script_directory}/build-renderer.sh" \
    >"${incremental_log}" 2>&1; then
    echo "renderer build accepted CARGO_INCREMENTAL=1" >&2
    exit 1
fi
grep -Fq -- 'CARGO_INCREMENTAL=0' "${incremental_log}"
[[ ! -e "${fake_repository}/target" ]]

mkdir -p -- "${fake_repository}/.cargo"
install -m 0644 -- /dev/null "${fake_repository}/.cargo/config.toml"
cargo_config_log="${scratch_directory}/cargo-config.log"
if /usr/bin/env -i \
    "${clean_environment[@]}" \
    bash "${fake_script_directory}/build-renderer.sh" \
    >"${cargo_config_log}" 2>&1; then
    echo "renderer build accepted a repository Cargo config" >&2
    exit 1
fi
grep -Fq -- 'forbids Cargo config' "${cargo_config_log}"
[[ ! -e "${fake_repository}/target" ]]

echo "renderer ambient override preflight rejected adversarial inputs before mutation"
