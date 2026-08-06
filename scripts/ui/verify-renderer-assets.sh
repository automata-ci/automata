#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
renderer_directory="${repository_root}/ui/renderer"
asset_directory="${renderer_directory}/assets"
sums_file="${renderer_directory}/SHA256SUMS"
provenance_file="${renderer_directory}/PROVENANCE.toml"

command -v node >/dev/null 2>&1 || {
    echo "required command is unavailable: node" >&2
    exit 1
}
node "${script_directory}/sync-render-contract.mjs" --check

if (( $# > 1 )); then
    echo "usage: $0 [UI_BUILD_DIRECTORY]" >&2
    exit 1
fi

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

cd -- "${renderer_directory}"
sha256sum --check --strict SHA256SUMS

listed_count=0
while read -r expected relative_path; do
    [[ -n "${expected}" && -n "${relative_path}" ]] || {
        echo "invalid renderer checksum line" >&2
        exit 1
    }
    relative_path="${relative_path#\*}"
    relative_path="${relative_path# }"
    filename="${relative_path##*/}"
    [[ "${filename}" == *"-${expected}."* ]] || {
        echo "renderer asset is not addressed by its full SHA-256: ${relative_path}" >&2
        exit 1
    }
    listed_count=$((listed_count + 1))
done < "${sums_file}"

actual_count="$(find "${asset_directory}" -maxdepth 1 -type f | wc -l)"
[[ "${actual_count}" -eq "${listed_count}" ]] || {
    echo "renderer assets contain an unlisted or missing file" >&2
    exit 1
}

while IFS= read -r asset_path; do
    relative_path="assets/${asset_path##*/}"
    grep -Fq -- "  ${relative_path}" "${sums_file}" || {
        echo "unlisted renderer asset: ${relative_path}" >&2
        exit 1
    }
done < <(find "${asset_directory}" -maxdepth 1 -type f -print | LC_ALL=C sort)

echo "renderer assets verified (${listed_count} content-addressed files)"

verify_hash "$(read_provenance_string package_lock_sha256)" \
    "${repository_root}/ui/package-lock.json"
verify_hash "$(read_provenance_string wit_sha256)" \
    "${repository_root}/crates/automata-ui-renderer/wit/renderer.wit"
verify_hash "$(read_provenance_string lock_sha256)" \
    "${renderer_directory}/wrapper.Cargo.lock"
verify_hash "$(read_provenance_string manifest_sha256)" \
    "${renderer_directory}/wrapper.Cargo.toml"
actual_macro_patch_hash="$({
    cd -- "${renderer_directory}"
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
