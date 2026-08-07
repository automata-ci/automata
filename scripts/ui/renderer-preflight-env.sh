#!/usr/bin/env bash

# This file is sourced by regenerate-renderer.sh. Keep the environment check
# free of filesystem writes: it must run before target scratch or generated
# output can be created.

automata_renderer_reject_ambient_overrides() {
    local entry=''
    local name=''
    local value=''
    local base=''
    local forbidden_name=''
    local -a forbidden_names=(
        BINDGEN_EXTRA_CLANG_ARGS
        BINDGEN_EXTRA_CLANG_ARGS_wasm32-wasip2
        BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip2
        CLANG_PATH
        LIBCLANG_PATH
        LIBCLANG_STATIC_PATH
        LLVM_CONFIG_PATH
        LD_LIBRARY_PATH
        DYLD_LIBRARY_PATH
        LD_RUN_PATH
        WASI_SDK
        WASI_SYSROOT
        SDKROOT
        CPATH
        C_INCLUDE_PATH
        CPLUS_INCLUDE_PATH
        OBJC_INCLUDE_PATH
        LIBRARY_PATH
        COMPILER_PATH
        GCC_EXEC_PREFIX
        CC_ENABLE_DEBUG_OUTPUT
        CC_FORCE_DISABLE
        CC_KNOWN_WRAPPER_CUSTOM
        CC_SHELL_ESCAPED_FLAGS
        CRATE_CC_NO_DEFAULTS
        ZERO_AR_DATE
        RUSTC
        RUSTDOC
        RUSTFMT
        RUSTC_LINKER
        RUSTC_WRAPPER
        RUSTC_WORKSPACE_WRAPPER
        RUSTFLAGS
        CARGO_ENCODED_RUSTFLAGS
        RUSTDOCFLAGS
        CARGO_ENCODED_RUSTDOCFLAGS
        RUSTC_BOOTSTRAP
        RUSTUP_TOOLCHAIN
        RUSTUP_DIST_SERVER
        RUSTUP_UPDATE_ROOT
        RUST_TARGET_PATH
        CARGO
        CARGO_CONFIG
        CARGO_CONFIG_PATH
        CARGO_MANIFEST_DIR
        CARGO_TARGET_DIR
        SOURCE_DATE_EPOCH
    )
    local -a compiler_bases=(
        CC
        CXX
        AR
        RANLIB
        CFLAGS
        CXXFLAGS
        CPPFLAGS
        LDFLAGS
        ARFLAGS
        RANLIBFLAGS
        CXXSTDLIB
    )

    [[ -x /usr/bin/env ]] || {
        echo "renderer regeneration requires /usr/bin/env" >&2
        return 1
    }

    while IFS= read -r -d '' entry; do
        name="${entry%%=*}"
        value="${entry#*=}"
        for forbidden_name in "${forbidden_names[@]}"; do
            if [[ "${name}" == "${forbidden_name}" ]]; then
                echo "renderer regeneration forbids ambient ${name}" >&2
                return 1
            fi
        done
        for base in "${compiler_bases[@]}"; do
            case "${name}" in
                "${base}" | \
                    "HOST_${base}" | \
                    "TARGET_${base}" | \
                    "${base}_wasm32-wasip2" | \
                    "${base}_wasm32_wasip2" | \
                    "${base}_x86_64-unknown-linux-gnu" | \
                    "${base}_x86_64_unknown_linux_gnu")
                    echo "renderer regeneration forbids ambient ${name}" >&2
                    return 1
                    ;;
            esac
        done
        case "${name}" in
            CARGO_ALIAS_* | \
                CARGO_BUILD_* | \
                CARGO_CREDENTIAL_* | \
                CARGO_HTTP_* | \
                CARGO_NET_* | \
                CARGO_PROFILE_* | \
                CARGO_REGISTRIES_* | \
                CARGO_REGISTRY_* | \
                CARGO_SOURCE_* | \
                CARGO_TARGET_*)
                echo "renderer regeneration forbids ambient ${name}" >&2
                return 1
                ;;
        esac
        if [[ "${name}" == CARGO_INCREMENTAL && "${value}" != 0 ]]; then
            echo "renderer regeneration requires ambient CARGO_INCREMENTAL=0 when set" >&2
            return 1
        fi
    done < <(/usr/bin/env -0)
}
