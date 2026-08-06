#!/usr/bin/env bash
set -euo pipefail

readonly expected_wasm_rquickjs_version="wasm-rquickjs-cli 0.4.1"
readonly expected_rust_release="1.97.1"
readonly expected_node_release="24.19.0"
readonly expected_cyclonedx_version="cargo-cyclonedx-cyclonedx 0.5.9"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${repository_root}/scripts/ci/lib/target-paths.sh"
ui_directory="${repository_root}/ui"
renderer_directory="${ui_directory}/renderer"
asset_directory="${renderer_directory}/assets"
crate_directory="${repository_root}/crates/automata-ui-renderer"
wit_file="${crate_directory}/wit/renderer.wit"
generated_rust="${crate_directory}/src/generated_assets.rs"
wrapper_lock="${renderer_directory}/wrapper.Cargo.lock"
wrapper_manifest="${renderer_directory}/wrapper.Cargo.toml"

for command in cargo diff find install mktemp node npm rustc rustfmt sha256sum wasm-rquickjs; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "required command is unavailable: ${command}" >&2
        exit 1
    }
done

automata_init_target_root "${repository_root}"
scratch_directory="$(
    automata_canonical_exact_target_child \
        "${repository_root}/target/agent-scratch/ssr" \
        "renderer scratch directory"
)"
mkdir -p -- "${scratch_directory}"
export TMPDIR="${scratch_directory}"

actual_wasm_rquickjs_version="$(wasm-rquickjs --version)"
[[ "${actual_wasm_rquickjs_version}" == "${expected_wasm_rquickjs_version}" ]] || {
    echo "expected ${expected_wasm_rquickjs_version}; found ${actual_wasm_rquickjs_version}" >&2
    exit 1
}

actual_rust_release="$(rustc --version | awk '{print $2}')"
[[ "${actual_rust_release}" == "${expected_rust_release}" ]] || {
    echo "expected rustc ${expected_rust_release}; found ${actual_rust_release}" >&2
    exit 1
}

actual_node_release="$(node --version | sed 's/^v//')"
[[ "${actual_node_release}" == "${expected_node_release}" ]] || {
    echo "expected node ${expected_node_release}; found ${actual_node_release}" >&2
    exit 1
}

actual_cyclonedx_version="$(cargo cyclonedx --version)"
[[ "${actual_cyclonedx_version}" == "${expected_cyclonedx_version}" ]] || {
    echo "expected cargo-cyclonedx 0.5.9; found ${actual_cyclonedx_version}" >&2
    exit 1
}
temporary_directory="$(mktemp -d "${scratch_directory}/regenerate.XXXXXXXX")"
cleanup() {
    if [[ -n "${temporary_directory:-}" && -d "${temporary_directory}" ]]; then
        rm -rf -- "${temporary_directory}"
    fi
}
trap cleanup EXIT

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
wasm-rquickjs generate-wrapper-crate \
    --js "${ui_directory}/dist/ssr/renderer.mjs" \
    --wit "${crate_directory}/wit" \
    --world renderer \
    --target wasi-p2 \
    --output "${wrapper_candidate_directory}"
install -m 0644 -- "${wrapper_manifest}" "${wrapper_candidate_directory}/Cargo.toml"
install -m 0644 -- "${wrapper_lock}" "${wrapper_candidate_directory}/Cargo.lock"

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

SOURCE_DATE_EPOCH=0 \
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
RUSTFLAGS="--remap-path-prefix=${repository_root}=/automata" \
CARGO_TARGET_DIR="${wrapper_target_directory}" \
cargo build \
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

component_hash="$(sha256sum "${component_source}" | awk '{print $1}')"
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

component_name="renderer-${component_hash}.wasm"
script_name="client-${script_hash}.js"
style_name="styles-${style_hash}.css"
staged_assets="${temporary_directory}/assets"
mkdir -p -- "${staged_assets}"
install -m 0644 -- "${component_source}" "${staged_assets}/${component_name}"
install -m 0644 -- "${script_source}" "${staged_assets}/${script_name}"
install -m 0644 -- "${style_source}" "${staged_assets}/${style_name}"

staged_rust="${temporary_directory}/generated_assets.rs"
printf '%s\n' \
    '// @generated by scripts/ui/regenerate-renderer.sh; do not edit by hand.' \
    '' \
    'pub(crate) const COMPONENT_BYTES: &[u8] = include_bytes!(' \
    "    \"../../../ui/renderer/assets/${component_name}\"" \
    ');' \
    'pub(crate) const COMPONENT_SHA256: &str =' \
    "    \"${component_hash}\";" \
    '' \
    'pub(crate) const CLIENT_SCRIPT_BYTES: &[u8] = include_bytes!(' \
    "    \"../../../ui/renderer/assets/${script_name}\"" \
    ');' \
    'pub(crate) const CLIENT_SCRIPT_SHA256: &str =' \
    "    \"${script_hash}\";" \
    "pub(crate) const CLIENT_SCRIPT_PATH: &str = \"/assets/${script_public_name}\";" \
    '' \
    'pub(crate) const CLIENT_STYLE_BYTES: &[u8] = include_bytes!(' \
    "    \"../../../ui/renderer/assets/${style_name}\"" \
    ');' \
    'pub(crate) const CLIENT_STYLE_SHA256: &str =' \
    "    \"${style_hash}\";" \
    "pub(crate) const CLIENT_STYLE_PATH: &str = \"/assets/${style_public_name}\";" \
    > "${staged_rust}"
rustfmt --edition 2024 "${staged_rust}"

staged_sums="${temporary_directory}/SHA256SUMS"
printf '%s  %s\n' \
    "${script_hash}" "assets/${script_name}" \
    "${component_hash}" "assets/${component_name}" \
    "${style_hash}" "assets/${style_name}" \
    > "${staged_sums}"

staged_provenance="${temporary_directory}/PROVENANCE.toml"
printf '%s\n' \
    'schema = 1' \
    '' \
    '[tools]' \
    'wasm_rquickjs_cli = "0.4.1"' \
    "rustc = \"${actual_rust_release}\"" \
    "node = \"${actual_node_release}\"" \
    "npm = \"$(npm --version)\"" \
    '' \
    '[wrapper]' \
    'target = "wasm32-wasip2"' \
    'profile = "release"' \
    'features = ["p2", "encoding"]' \
    'codegen_units = 1' \
    'incremental = false' \
    'source_date_epoch = 0' \
    'path_remap = "/automata"' \
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

find "${asset_directory}" -maxdepth 1 -type f \
    \( -name 'renderer-*.wasm' -o -name 'client-*.js' -o -name 'styles-*.css' \) \
    -delete
install -m 0644 -- "${staged_assets}"/* "${asset_directory}/"
install -m 0644 -- "${staged_rust}" "${generated_rust}"
install -m 0644 -- "${staged_sums}" "${renderer_directory}/SHA256SUMS"
install -m 0644 -- "${staged_provenance}" "${renderer_directory}/PROVENANCE.toml"

"${script_directory}/generate-renderer-sbom.sh"
"${script_directory}/verify-renderer-assets.sh"
echo "renderer component and client assets regenerated"
