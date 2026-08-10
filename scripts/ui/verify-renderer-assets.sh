#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
source_renderer_directory="${repository_root}/ui/renderer"
renderer_directory="${source_renderer_directory}"
asset_directory="${repository_root}/crates/automata-ci-ui-renderer/assets"
generated_rust="${repository_root}/crates/automata-ci-ui-renderer/src/generated_assets.rs"
readonly expected_clang_package="clang-18=1:18.1.3-1ubuntu1"
readonly expected_libclang_package="libclang1-18=1:18.1.3-1ubuntu1"
readonly expected_wasm_rquickjs_version="0.4.1"
readonly expected_rust_release="1.97.1"
readonly expected_cargo_version="cargo 1.97.1 (c980f4866 2026-06-30)"
readonly expected_rustfmt_version="rustfmt 1.9.0-stable (8bab26f4f6 2026-07-14)"
readonly expected_node_release="24.19.0"
readonly expected_npm_release="11.17.0"
readonly expected_wasi_sdk_version="24.0"
readonly expected_wasi_sdk_platform="x86_64-linux"
readonly expected_wasi_sdk_archive="wasi-sdk-24.0-x86_64-linux.tar.gz"
readonly expected_wasi_sdk_archive_sha256="c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5"
readonly expected_wasi_sdk_installation_root="/opt/wasi-sdk-24.0"
readonly expected_wasi_sdk_clang="clang version 18.1.2-wasi-sdk (https://github.com/llvm/llvm-project 26a1d6601d727a96f4301d0d8647b5a42760ae0c)"
readonly expected_wasi_sdk_llvm_ar="LLVM version 18.1.2-wasi-sdk"
transaction_owner_marker=''
transaction_owner_id=''
transaction_owner_lock_fd=''
transaction_state_directory="${source_renderer_directory}/.regeneration-transaction"
usage="usage: $0 [--transaction-owner-marker ACTIVE_FORMAT_PATH --transaction-owner-id ID --transaction-owner-lock-fd FD] [--candidate CANDIDATE_DIRECTORY] [UI_BUILD_DIRECTORY]"

while (( $# >= 1 )); do
    case "$1" in
        --transaction-owner-marker)
            (( $# >= 2 )) && [[ -z "${transaction_owner_marker}" ]] || {
                echo "${usage}" >&2
                exit 1
            }
            transaction_owner_marker="$2"
            shift 2
            ;;
        --transaction-owner-id)
            (( $# >= 2 )) && [[ -z "${transaction_owner_id}" ]] || {
                echo "${usage}" >&2
                exit 1
            }
            transaction_owner_id="$2"
            shift 2
            ;;
        --transaction-owner-lock-fd)
            (( $# >= 2 )) && [[ -z "${transaction_owner_lock_fd}" ]] || {
                echo "${usage}" >&2
                exit 1
            }
            transaction_owner_lock_fd="$2"
            shift 2
            ;;
        *) break ;;
    esac
done
if [[ -n "${transaction_owner_marker}" || -n "${transaction_owner_id}" || \
    -n "${transaction_owner_lock_fd}" ]]; then
    [[ -n "${transaction_owner_marker}" && -n "${transaction_owner_id}" && \
        "${transaction_owner_lock_fd}" =~ ^[0-9]+$ ]] || {
        echo "${usage}" >&2
        exit 1
    }
fi
for command in cmp find flock realpath stat; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "required command is unavailable: ${command}" >&2
        exit 1
    }
done
[[ -d "${source_renderer_directory}" && ! -L "${source_renderer_directory}" ]] || {
    echo "renderer source directory must be a real directory" >&2
    exit 1
}
renderer_lock_identity="$(stat -Lc '%d:%i' -- "${source_renderer_directory}")"
if [[ -n "${transaction_owner_lock_fd}" ]]; then
    [[ -e "/proc/self/fd/${transaction_owner_lock_fd}" && \
        "$(stat -Lc '%d:%i' -- "/proc/self/fd/${transaction_owner_lock_fd}")" == \
            "${renderer_lock_identity}" ]] || {
        echo "renderer verifier owner lock does not identify the renderer directory" >&2
        exit 1
    }
    flock --exclusive --nonblock "${transaction_owner_lock_fd}" || {
        echo "renderer verifier owner does not hold the exclusive publication lock" >&2
        exit 1
    }
else
    exec {verification_lock_fd}<"${source_renderer_directory}"
    [[ "$(stat -Lc '%d:%i' -- "/proc/self/fd/${verification_lock_fd}")" == \
        "$(stat -Lc '%d:%i' -- "${source_renderer_directory}")" ]] || {
        echo "renderer source directory changed while acquiring its verification lock" >&2
        exit 1
    }
    flock --shared --nonblock "${verification_lock_fd}" || {
        echo "renderer verification refuses a concurrent publication transaction" >&2
        exit 1
    }
    readonly verification_lock_fd
fi
readonly renderer_lock_identity
# shellcheck source=scripts/ui/lib/renderer-generation-transaction.sh
source "${script_directory}/lib/renderer-generation-transaction.sh"
# Public verification holds a shared stable-directory lock for the complete
# run. The regenerator's bypass is bound to the inherited exclusive lock inode,
# the exact active marker, and this transaction's unique identifier.
automata_renderer_transaction_require_verifier_access \
    "${transaction_state_directory}" \
    "${transaction_owner_marker}" \
    "${transaction_owner_id}"

for command in node python3; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "required command is unavailable: ${command}" >&2
        exit 1
    }
done
node "${script_directory}/sync-render-contract.mjs" --check

if (( $# >= 1 )) && [[ "$1" == "--candidate" ]]; then
    (( $# >= 2 )) || {
        echo "${usage}" >&2
        exit 1
    }
    candidate_directory="$2"
    shift 2
    if [[ "${candidate_directory}" != /* ]]; then
        candidate_directory="${repository_root}/${candidate_directory}"
    fi
    [[ "$(realpath --canonicalize-existing -- "${candidate_directory}" 2>/dev/null)" == \
        "$(realpath --canonicalize-missing --no-symlinks -- \
            "${candidate_directory}" 2>/dev/null)" ]] || {
        echo "renderer candidate path contains a symbolic link: ${candidate_directory}" >&2
        exit 1
    }
    [[ -d "${candidate_directory}" && ! -L "${candidate_directory}" && \
        -d "${candidate_directory}/renderer" && \
        ! -L "${candidate_directory}/renderer" && \
        -d "${candidate_directory}/assets" && \
        ! -L "${candidate_directory}/assets" && \
        -f "${candidate_directory}/generated_assets.rs" && \
        ! -L "${candidate_directory}/generated_assets.rs" ]] || {
        echo "renderer candidate is incomplete: ${candidate_directory}" >&2
        exit 1
    }
    renderer_directory="${candidate_directory}/renderer"
    asset_directory="${candidate_directory}/assets"
    generated_rust="${candidate_directory}/generated_assets.rs"
fi
if (( $# > 1 )); then
    echo "${usage}" >&2
    exit 1
fi
sums_file="${renderer_directory}/SHA256SUMS"
provenance_file="${renderer_directory}/PROVENANCE.toml"
sbom_file="${renderer_directory}/renderer.cdx.json"
readonly source_renderer_directory renderer_directory asset_directory generated_rust
readonly sums_file provenance_file sbom_file
readonly transaction_owner_marker transaction_owner_id transaction_owner_lock_fd
readonly transaction_state_directory usage

for renderer_input in \
    "${renderer_directory}" \
    "${asset_directory}" \
    "${generated_rust}" \
    "${sums_file}" \
    "${provenance_file}" \
    "${sbom_file}"; do
    if [[ "${renderer_input}" == "${renderer_directory}" || \
        "${renderer_input}" == "${asset_directory}" ]]; then
        [[ -d "${renderer_input}" && ! -L "${renderer_input}" ]] || {
            echo "renderer input directory is not a real directory: ${renderer_input}" >&2
            exit 1
        }
    else
        [[ -f "${renderer_input}" && ! -L "${renderer_input}" ]] || {
            echo "renderer input file is not a real file: ${renderer_input}" >&2
            exit 1
        }
    fi
done

read_provenance_string() {
    local key="$1"
    local line=''
    local value=''
    mapfile -t matches < <(grep -E "^${key} = \"[^\"]+\"$" "${provenance_file}")
    [[ "${#matches[@]}" -eq 1 ]] || {
        echo "expected exactly one ${key} in ${provenance_file}" >&2
        exit 1
    }
    line="${matches[0]}"
    value="${line#*\"}"
    printf '%s\n' "${value%\"}"
}

[[ "$(read_provenance_string wasm_rquickjs_cli)" == \
    "${expected_wasm_rquickjs_version}" && \
    "$(read_provenance_string rustc)" == "${expected_rust_release}" && \
    "$(read_provenance_string cargo)" == "${expected_cargo_version}" && \
    "$(read_provenance_string rustfmt)" == "${expected_rustfmt_version}" && \
    "$(read_provenance_string node)" == "${expected_node_release}" && \
    "$(read_provenance_string npm)" == "${expected_npm_release}" ]] || {
    echo "renderer provenance does not identify the canonical Rust, Node, and generator tools" >&2
    exit 1
}
[[ "$(read_provenance_string clang)" == "${expected_clang_package}" ]] || {
    echo "renderer provenance does not identify the canonical Clang package" >&2
    exit 1
}
[[ "$(read_provenance_string libclang)" == "${expected_libclang_package}" ]] || {
    echo "renderer provenance does not identify the canonical libclang package" >&2
    exit 1
}
[[ "$(read_provenance_string wasi_sdk_version)" == "${expected_wasi_sdk_version}" && \
    "$(read_provenance_string wasi_sdk_platform)" == "${expected_wasi_sdk_platform}" && \
    "$(read_provenance_string wasi_sdk_archive)" == "${expected_wasi_sdk_archive}" && \
    "$(read_provenance_string wasi_sdk_archive_sha256)" == \
        "${expected_wasi_sdk_archive_sha256}" && \
    "$(read_provenance_string wasi_sdk_installation_root)" == \
        "${expected_wasi_sdk_installation_root}" && \
    "$(read_provenance_string wasi_sdk_clang)" == "${expected_wasi_sdk_clang}" && \
    "$(read_provenance_string wasi_sdk_llvm_ar)" == \
        "${expected_wasi_sdk_llvm_ar}" ]] || {
    echo "renderer provenance does not identify the canonical WASI SDK" >&2
    exit 1
}

verify_hash() {
    local expected="$1"
    local path="$2"
    local actual=''
    actual="$(sha256sum "${path}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] || {
        echo "source hash mismatch for ${path}: expected ${expected}, found ${actual}" >&2
        exit 1
    }
}

cd -- "${repository_root}"
if [[ "${renderer_directory}" == "${source_renderer_directory}" ]]; then
    sha256sum --check --strict "${sums_file}"
else
    while read -r expected relative_path; do
        relative_path="${relative_path#\*}"
        relative_path="${relative_path# }"
        verify_hash "${expected}" "${asset_directory}/${relative_path##*/}"
    done < "${sums_file}"
fi

listed_count=0
component_asset=''
component_hash=''
script_asset=''
script_hash=''
style_asset=''
style_hash=''
while read -r expected relative_path; do
    [[ "${expected}" =~ ^[0-9a-f]{64}$ && -n "${relative_path}" ]] || {
        echo "invalid renderer checksum line" >&2
        exit 1
    }
    relative_path="${relative_path#\*}"
    relative_path="${relative_path# }"
    filename="${relative_path##*/}"
    [[ "${relative_path}" == \
        "crates/automata-ci-ui-renderer/assets/${filename}" ]] || {
        echo "renderer checksum names a non-canonical asset path: ${relative_path}" >&2
        exit 1
    }
    case "${filename}" in
        "renderer-${expected}.wasm")
            [[ -z "${component_asset}" ]] || {
                echo "renderer checksums list multiple components" >&2
                exit 1
            }
            component_asset="${filename}"
            component_hash="${expected}"
            ;;
        "client-${expected}.js")
            [[ -z "${script_asset}" ]] || {
                echo "renderer checksums list multiple client scripts" >&2
                exit 1
            }
            script_asset="${filename}"
            script_hash="${expected}"
            ;;
        "styles-${expected}.css")
            [[ -z "${style_asset}" ]] || {
                echo "renderer checksums list multiple client stylesheets" >&2
                exit 1
            }
            style_asset="${filename}"
            style_hash="${expected}"
            ;;
        *)
            echo "renderer asset is not addressed by its full SHA-256: ${relative_path}" >&2
            exit 1
            ;;
    esac
    listed_count=$((listed_count + 1))
done < "${sums_file}"
[[ "${listed_count}" -eq 3 && -n "${component_asset}" && \
    -n "${script_asset}" && -n "${style_asset}" ]] || {
    echo "renderer checksums must list one component, script, and stylesheet" >&2
    exit 1
}

mapfile -d '' -t asset_entries < <(
    find "${asset_directory}" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z
)
[[ "${#asset_entries[@]}" -eq "${listed_count}" ]] || {
    echo "renderer assets contain an unlisted or missing file" >&2
    exit 1
}

for asset_path in "${asset_entries[@]}"; do
    [[ -f "${asset_path}" && ! -L "${asset_path}" ]] || {
        echo "renderer asset entry is not a real regular file: ${asset_path}" >&2
        exit 1
    }
    relative_path="crates/automata-ci-ui-renderer/assets/${asset_path##*/}"
    grep -Fq -- "  ${relative_path}" "${sums_file}" || {
        echo "unlisted renderer asset: ${relative_path}" >&2
        exit 1
    }
done

echo "renderer assets verified (${listed_count} content-addressed files)"

mapfile -t components < <(
    find "${asset_directory}" -maxdepth 1 -type f \
        -name 'renderer-*.wasm' -print | LC_ALL=C sort
)
[[ "${#components[@]}" -eq 1 ]] || {
    echo "expected exactly one renderer component" >&2
    exit 1
}
actual_wit_hash="$(
    sha256sum "${repository_root}/crates/automata-ci-ui-renderer/wit/renderer.wit" \
        | awk '{print $1}'
)"
python3 "${script_directory}/component-wit-provenance.py" verify \
    "${components[0]}" \
    "${actual_wit_hash}"

component_sha256="$(read_provenance_string component_sha256)"
[[ "${component_sha256}" == "${component_hash}" && \
    "$(read_provenance_string script_sha256)" == "${script_hash}" && \
    "$(read_provenance_string stylesheet_sha256)" == "${style_hash}" ]] || {
    echo "renderer provenance artifact digests differ from the checksum manifest" >&2
    exit 1
}
node - "${sbom_file}" "${component_sha256}" <<'NODE'
const [sbomPath, expectedHash] = process.argv.slice(2);
const { readFileSync } = require("node:fs");
const document = JSON.parse(readFileSync(sbomPath, "utf8"));
const component = document?.metadata?.component;
const hashes = Array.isArray(component?.hashes) ? component.hashes : [];
if (
  document?.bomFormat !== "CycloneDX" ||
  document?.specVersion !== "1.5" ||
  component?.name !== "renderer" ||
  !hashes.some(
    (hash) => hash?.alg === "SHA-256" && hash?.content === expectedHash,
  )
) {
  throw new Error("renderer SBOM does not describe the staged component");
}
NODE

script_public_path="$(read_provenance_string script_public_path)"
style_public_path="$(read_provenance_string stylesheet_public_path)"
[[ "${script_public_path}" =~ ^/assets/entry-client-[A-Za-z0-9_-]+\.js$ && \
    "${style_public_path}" =~ ^/assets/entry-client-[A-Za-z0-9_-]+\.css$ ]] || {
    echo "renderer provenance contains an invalid client public path" >&2
    exit 1
}
if ! cmp --silent -- <(
    printf '%s\n' \
        '// @generated by scripts/ui/regenerate-renderer.sh; do not edit by hand.' \
        '' \
        'pub(crate) const COMPONENT_BYTES: &[u8] = include_bytes!(' \
        "    \"../assets/${component_asset}\"" \
        ');' \
        'pub(crate) const COMPONENT_SHA256: &str =' \
        "    \"${component_hash}\";" \
        '' \
        'pub(crate) const CLIENT_SCRIPT_BYTES: &[u8] = include_bytes!(' \
        "    \"../assets/${script_asset}\"" \
        ');' \
        'pub(crate) const CLIENT_SCRIPT_SHA256: &str =' \
        "    \"${script_hash}\";" \
        "pub(crate) const CLIENT_SCRIPT_PATH: &str = \"${script_public_path}\";" \
        '' \
        'pub(crate) const CLIENT_STYLE_BYTES: &[u8] = include_bytes!(' \
        "    \"../assets/${style_asset}\"" \
        ');' \
        'pub(crate) const CLIENT_STYLE_SHA256: &str =' \
        "    \"${style_hash}\";" \
        "pub(crate) const CLIENT_STYLE_PATH: &str = \"${style_public_path}\";"
) "${generated_rust}"; then
    echo "generated Rust does not exactly match the renderer asset contract" >&2
    exit 1
fi

verify_hash "$(read_provenance_string package_lock_sha256)" \
    "${repository_root}/ui/package-lock.json"
verify_hash "$(read_provenance_string wit_sha256)" \
    "${repository_root}/crates/automata-ci-ui-renderer/wit/renderer.wit"
verify_hash "$(read_provenance_string lock_sha256)" \
    "${source_renderer_directory}/wrapper.Cargo.lock"
verify_hash "$(read_provenance_string manifest_sha256)" \
    "${source_renderer_directory}/wrapper.Cargo.toml"
actual_macro_patch_hash="$({
    cd -- "${source_renderer_directory}"
    find "vendor/rquickjs-macro-0.10.0" -type f -print0 \
        | LC_ALL=C sort -z \
        | while IFS= read -r -d '' relative_path; do
            sha256sum "${relative_path}"
        done
} | sha256sum | awk '{print $1}')"
expected_macro_patch_hash="$(read_provenance_string macro_patch_sha256)"
[[ "${actual_macro_patch_hash}" == "${expected_macro_patch_hash}" ]] || {
    echo "renderer macro patch tree does not match provenance" >&2
    exit 1
}
echo "renderer source manifest, resolution, and interface provenance verified"

if (( $# == 1 )); then
    build_directory="$1"
    if [[ "${build_directory}" != /* ]]; then
        build_directory="${repository_root}/${build_directory}"
    fi
    [[ -d "${build_directory}/client/assets" && -f "${build_directory}/ssr/renderer.mjs" ]] || {
        echo "UI build directory is incomplete: ${build_directory}" >&2
        exit 1
    }

    mapfile -t built_scripts < <(
        find "${build_directory}/client/assets" -maxdepth 1 -type f \
            -name 'entry-client-*.js' -print | LC_ALL=C sort
    )
    mapfile -t built_styles < <(
        find "${build_directory}/client/assets" -maxdepth 1 -type f \
            -name 'entry-client-*.css' -print | LC_ALL=C sort
    )
    [[ "${#built_scripts[@]}" -eq 1 && "${#built_styles[@]}" -eq 1 ]] || {
        echo "expected exactly one built client script and stylesheet" >&2
        exit 1
    }

    verify_hash "$(read_provenance_string ssr_bundle_sha256)" \
        "${build_directory}/ssr/renderer.mjs"
    verify_hash "$(read_provenance_string script_sha256)" "${built_scripts[0]}"
    verify_hash "$(read_provenance_string stylesheet_sha256)" "${built_styles[0]}"

    [[ "/assets/${built_scripts[0]##*/}" == "$(read_provenance_string script_public_path)" ]] || {
        echo "built client script path differs from renderer provenance" >&2
        exit 1
    }
    [[ "/assets/${built_styles[0]##*/}" == "$(read_provenance_string stylesheet_public_path)" ]] || {
        echo "built stylesheet path differs from renderer provenance" >&2
        exit 1
    }
    echo "renderer provenance matches the current Vite build"
fi
