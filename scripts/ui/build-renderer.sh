#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_profile_id="automata.dev/github-hosted-ubuntu-24-04-x64-v1"
readonly expected_image_version="automata-ubuntu-24.04-x64-v1"
readonly expected_wasm_rquickjs_version="wasm-rquickjs-cli 0.4.1"
readonly expected_rustc_version="rustc 1.97.1 (8bab26f4f 2026-07-14)"
readonly expected_cargo_version="cargo 1.97.1 (c980f4866 2026-06-30)"
readonly expected_node_version="v24.19.0"
readonly expected_npm_version="11.17.0"
readonly expected_cargo_home="/opt/cargo"
readonly expected_rustup_home="/opt/rustup"
readonly expected_wasi_sdk="/opt/wasi-sdk-24.0"
readonly expected_libclang="/usr/lib/x86_64-linux-gnu/libclang-18.so.18"

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../.." && pwd -P)"
ui_directory="${repository_root}/ui"
renderer_source="${ui_directory}/renderer"
renderer_crate="${repository_root}/crates/automata-ci-ui-renderer"
renderer_output="${repository_root}/target/ui-renderer"
wrapper_root="${repository_root}/target/ui-renderer-wrapper"
wrapper_directory="${wrapper_root}/source"
wrapper_target="${wrapper_root}/cargo-target"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(( $# == 0 )) || die "usage: $0"
# shellcheck source=scripts/ui/renderer-preflight-env.sh
source "${script_directory}/renderer-preflight-env.sh"
automata_renderer_reject_ambient_overrides

for cargo_config in \
    "${repository_root}/.cargo/config" \
    "${repository_root}/.cargo/config.toml" \
    "${expected_cargo_home}/config" \
    "${expected_cargo_home}/config.toml"; do
    [[ ! -e "${cargo_config}" && ! -L "${cargo_config}" ]] || \
        die "renderer build forbids Cargo config: ${cargo_config}"
done

[[ "${AUTOMATA_ENVIRONMENT_PROFILE_ID:-}" == "${expected_profile_id}" && \
    "${ImageVersion:-}" == "${expected_image_version}" ]] || \
    die "build-renderer.sh must run through reproduce-renderer-in-profile.sh"
[[ "${CARGO_HOME:-}" == "${expected_cargo_home}" && \
    "${RUSTUP_HOME:-}" == "${expected_rustup_home}" ]] || \
    die "renderer build requires the locked profile Cargo and Rustup homes"
[[ "$(rustc --version)" == "${expected_rustc_version}" ]] || die "unexpected rustc version"
[[ "$(cargo --version)" == "${expected_cargo_version}" ]] || die "unexpected Cargo version"
[[ "$(node --version)" == "${expected_node_version}" ]] || die "unexpected Node.js version"
[[ "$(npm --version)" == "${expected_npm_version}" ]] || die "unexpected npm version"
[[ "$(wasm-rquickjs --version)" == "${expected_wasm_rquickjs_version}" ]] || \
    die "unexpected wasm-rquickjs version"
[[ -x "${expected_wasi_sdk}/bin/clang" && -r "${expected_libclang}" ]] || \
    die "locked WASI SDK or libclang is unavailable"

for command in awk cargo cmp cp diff find install mktemp mv node npm python3 rm sha256sum sort; do
    command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done

mkdir -p -- "${repository_root}/target/task-tmp/ui-renderer"
export TMPDIR="${repository_root}/target/task-tmp/ui-renderer"
temporary_directory="$(mktemp -d "${TMPDIR}/build.XXXXXXXX")"
cleanup() {
    rm -rf -- "${temporary_directory}"
}
trap cleanup EXIT

npm --prefix "${ui_directory}" ci --no-audit --prefer-offline
npm --prefix "${ui_directory}" run build

wrapper_candidate="${temporary_directory}/wrapper-source"
wasm-rquickjs generate-wrapper-crate \
    --js "${ui_directory}/dist/ssr/renderer.mjs" \
    --wit "${renderer_crate}/wit" \
    --world renderer \
    --target wasi-p2 \
    --output "${wrapper_candidate}"
install -m 0644 -- "${renderer_source}/wrapper.Cargo.toml" "${wrapper_candidate}/Cargo.toml"
install -m 0644 -- "${renderer_source}/wrapper.Cargo.lock" "${wrapper_candidate}/Cargo.lock"
install -d -m 0755 -- "${wrapper_candidate}/vendor"
cp -a -- \
    "${renderer_source}/vendor/rquickjs-macro-0.10.0" \
    "${wrapper_candidate}/vendor/rquickjs-macro-0.10.0"

mkdir -p -- "${wrapper_root}"
if [[ ! -d "${wrapper_directory}" ]] || \
    ! diff -qr -- "${wrapper_directory}" "${wrapper_candidate}" >/dev/null; then
    rm -rf -- "${wrapper_directory}"
    mv -- "${wrapper_candidate}" "${wrapper_directory}"
fi

wrapper_metadata="${temporary_directory}/cargo-metadata.json"
cargo metadata \
    --manifest-path "${wrapper_directory}/Cargo.toml" \
    --locked \
    --format-version 1 \
    > "${wrapper_metadata}"
python3 "${script_directory}/verify-wrapper-path-sources.py" \
    "${wrapper_directory}" \
    "${wrapper_metadata}"

rust_path_remaps="--remap-path-prefix=${repository_root}=/automata --remap-path-prefix=${CARGO_HOME}=/cargo --remap-path-prefix=${RUSTUP_HOME}=/rustup --remap-path-prefix=${expected_wasi_sdk}=/wasi-sdk"
c_path_remaps="-ffile-prefix-map=${repository_root}=/automata -fdebug-prefix-map=${repository_root}=/automata -ffile-prefix-map=${CARGO_HOME}=/cargo -fdebug-prefix-map=${CARGO_HOME}=/cargo -ffile-prefix-map=${RUSTUP_HOME}=/rustup -fdebug-prefix-map=${RUSTUP_HOME}=/rustup -ffile-prefix-map=${expected_wasi_sdk}=/wasi-sdk -fdebug-prefix-map=${expected_wasi_sdk}=/wasi-sdk"

SOURCE_DATE_EPOCH=0 \
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
CFLAGS_wasm32_wasip2="${c_path_remaps}" \
RUSTFLAGS="${rust_path_remaps}" \
CARGO_TARGET_DIR="${wrapper_target}" \
RUSTC="${expected_cargo_home}/bin/rustc" \
LIBCLANG_PATH="${expected_libclang}" \
CLANG_PATH="/usr/bin/clang-18" \
WASI_SDK="${expected_wasi_sdk}" \
cargo build \
    --manifest-path "${wrapper_directory}/Cargo.toml" \
    --locked \
    --release \
    --target wasm32-wasip2 \
    --no-default-features \
    --features p2,encoding

mapfile -t scripts < <(
    find "${ui_directory}/dist/client/assets" -maxdepth 1 -type f \
        -name 'entry-client-*.js' -print | sort
)
mapfile -t styles < <(
    find "${ui_directory}/dist/client/assets" -maxdepth 1 -type f \
        -name 'entry-client-*.css' -print | sort
)
[[ "${#scripts[@]}" -eq 1 && "${#styles[@]}" -eq 1 ]] || \
    die "expected exactly one Vite client script and stylesheet"

component_source="${wrapper_target}/wasm32-wasip2/release/renderer.wasm"
[[ -f "${component_source}" && ! -L "${component_source}" ]] || \
    die "wasm-rquickjs did not produce renderer.wasm"

wit_hash="$(sha256sum "${renderer_crate}/wit/renderer.wit" | awk '{print $1}')"
stamped_component="${temporary_directory}/renderer.wasm"
python3 "${script_directory}/component-wit-provenance.py" stamp \
    "${component_source}" \
    "${stamped_component}" \
    "${wit_hash}"

component_hash="$(sha256sum "${stamped_component}" | awk '{print $1}')"
script_hash="$(sha256sum "${scripts[0]}" | awk '{print $1}')"
style_hash="$(sha256sum "${styles[0]}" | awk '{print $1}')"
component_name="renderer-${component_hash}.wasm"
script_name="client-${script_hash}.js"
style_name="styles-${style_hash}.css"
script_public_path="/assets/${scripts[0]##*/}"
style_public_path="/assets/${styles[0]##*/}"

candidate="${temporary_directory}/ui-renderer"
candidate_assets="${candidate}/assets"
install -d -m 0755 -- "${candidate_assets}"
install -m 0644 -- "${stamped_component}" "${candidate_assets}/${component_name}"
install -m 0644 -- "${scripts[0]}" "${candidate_assets}/${script_name}"
install -m 0644 -- "${styles[0]}" "${candidate_assets}/${style_name}"

python3 - \
    "${candidate}/manifest.json" \
    "${component_name}" \
    "${script_name}" \
    "${script_public_path}" \
    "${style_name}" \
    "${style_public_path}" <<'PY'
import json
import pathlib
import sys

path, component, script, script_path, stylesheet, stylesheet_path = sys.argv[1:]
document = {
    "schemaVersion": 1,
    "component": component,
    "script": {"file": script, "publicPath": script_path},
    "stylesheet": {"file": stylesheet, "publicPath": stylesheet_path},
}
pathlib.Path(path).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

package_lock_hash="$(sha256sum "${ui_directory}/package-lock.json" | awk '{print $1}')"
wrapper_lock_hash="$(sha256sum "${renderer_source}/wrapper.Cargo.lock" | awk '{print $1}')"
wrapper_manifest_hash="$(sha256sum "${renderer_source}/wrapper.Cargo.toml" | awk '{print $1}')"
ssr_hash="$(sha256sum "${ui_directory}/dist/ssr/renderer.mjs" | awk '{print $1}')"
printf '%s\n' \
    'schema = 1' \
    'profile = "automata.dev/github-hosted-ubuntu-24-04-x64-v1"' \
    'node = "24.19.0"' \
    'npm = "11.17.0"' \
    'rust = "1.97.1"' \
    'wasm_rquickjs = "0.4.1"' \
    "package_lock_sha256 = \"${package_lock_hash}\"" \
    "wrapper_lock_sha256 = \"${wrapper_lock_hash}\"" \
    "wrapper_manifest_sha256 = \"${wrapper_manifest_hash}\"" \
    "wit_sha256 = \"${wit_hash}\"" \
    "ssr_bundle_sha256 = \"${ssr_hash}\"" \
    > "${candidate}/provenance.toml"

"${script_directory}/generate-renderer-sbom.sh" \
    "${candidate}/renderer.cdx.json" \
    "${candidate_assets}/${component_name}"
"${script_directory}/verify-renderer-build.sh" "${candidate}"

rm -rf -- "${renderer_output}"
mv -- "${candidate}" "${renderer_output}"
printf 'Built renderer component and client assets in %s\n' "${renderer_output}"
