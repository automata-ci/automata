#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_node_version="v24.19.0"
readonly expected_npm_version="11.17.0"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"
# shellcheck source=scripts/ci/lib/third-party-license-input.sh
source "${script_directory}/lib/third-party-license-input.sh"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/third-party-license-prepare"
[[ "$(node --version)" == "${expected_node_version}" ]] || \
    die "Node.js 24.19.0 is required"
[[ "$(npm --version)" == "${expected_npm_version}" ]] || \
    die "npm 11.17.0 is required"
renderer_input="$(automata_third_party_license_renderer_input "${repository_root}")"
readonly renderer_input
renderer_input_lock="$(automata_third_party_license_lock_path "${repository_root}")"
readonly renderer_input_lock
install -d -m 0755 -- "$(dirname -- "${renderer_input_lock}")"
exec {renderer_input_lock_fd}>"${renderer_input_lock}"
readonly renderer_input_lock_fd
flock --exclusive "${renderer_input_lock_fd}"
# The generated input is disposable and must not retain files from an older
# reviewed wrapper shape. The exact-child check above makes this deletion
# repository-target-local even if an earlier run left nested symbolic links.
rm -rf -- "${renderer_input}"
renderer_source_input="$(
    automata_canonical_exact_target_child \
        "${renderer_input}/src" \
        "renderer license source input"
)"
readonly renderer_source_input
renderer_vendor_input="$(
    automata_canonical_exact_target_child \
        "${renderer_input}/vendor" \
        "renderer vendor input"
)"
readonly renderer_vendor_input
renderer_manifest_input="$(
    automata_canonical_exact_target_child \
        "${renderer_input}/Cargo.toml" \
        "renderer manifest input"
)"
readonly renderer_manifest_input
renderer_lock_input="$(
    automata_canonical_exact_target_child \
        "${renderer_input}/Cargo.lock" \
        "renderer lock input"
)"
readonly renderer_lock_input
renderer_license_input="$(
    automata_canonical_exact_target_child \
        "${renderer_input}/LICENSE-MIT" \
        "renderer license file input"
)"
readonly renderer_license_input
renderer_lib_input="$(
    automata_canonical_exact_target_child \
        "${renderer_source_input}/lib.rs" \
        "renderer library input"
)"
readonly renderer_lib_input
renderer_vendor_source="${repository_root}/ui/renderer/vendor"
readonly renderer_vendor_source

[[ -d "${renderer_vendor_source}" && ! -L "${renderer_vendor_source}" ]] || \
    die "reviewed renderer vendor source must be a real directory"
renderer_vendor_source_canonical="$(
    realpath --canonicalize-existing -- "${renderer_vendor_source}"
)"
renderer_vendor_source_nominal="$(
    realpath --canonicalize-missing --no-symlinks -- "${renderer_vendor_source}"
)"
readonly renderer_vendor_source_canonical renderer_vendor_source_nominal
[[ "${renderer_vendor_source_canonical}" == "${renderer_vendor_source_nominal}" ]] || \
    die "reviewed renderer vendor source path must not contain symbolic links"

renderer_vendor_file_count=0
while IFS= read -r -d '' renderer_vendor_entry; do
    die "reviewed renderer vendor source contains a non-regular entry: ${renderer_vendor_entry}"
done < <(
    find -P "${renderer_vendor_source}" -mindepth 1 \
        ! \( -type d -o -type f \) -print0
)
while IFS= read -r -d '' _renderer_vendor_file; do
    ((renderer_vendor_file_count += 1))
done < <(find -P "${renderer_vendor_source}" -type f -print0)
((renderer_vendor_file_count > 0)) || \
    die "reviewed renderer vendor source contains no regular files"

install -d -m 0755 -- "${renderer_input}" "${renderer_source_input}"
install -m 0644 -- \
    "${repository_root}/ui/renderer/wrapper.Cargo.toml" \
    "${renderer_manifest_input}"
install -m 0644 -- \
    "${repository_root}/ui/renderer/wrapper.Cargo.lock" \
    "${renderer_lock_input}"
install -m 0644 -- "${repository_root}/LICENSE" "${renderer_license_input}"
install -m 0644 -- /dev/null "${renderer_lib_input}"

# Copy into a repository-local staging directory first. Cargo must never observe
# a missing, partial, extra, or byte-different version of the reviewed patch.
renderer_vendor_stage="$(
    mktemp -d -- "${renderer_input}/.vendor-copy.XXXXXXXX"
)"
readonly renderer_vendor_stage
automata_canonical_exact_target_child \
    "${renderer_vendor_stage}" \
    "renderer vendor staging input" >/dev/null
if ! cp --archive --no-dereference -- \
    "${renderer_vendor_source}/." \
    "${renderer_vendor_stage}/"; then
    rm -rf -- "${renderer_vendor_stage}"
    die "could not copy the reviewed renderer vendor source"
fi
if ! diff --brief --recursive --no-dereference -- \
    "${renderer_vendor_source}" \
    "${renderer_vendor_stage}"; then
    rm -rf -- "${renderer_vendor_stage}"
    die "copied renderer vendor input differs from the reviewed source"
fi
rm -rf -- "${renderer_vendor_input}"
mv -- "${renderer_vendor_stage}" "${renderer_vendor_input}"
diff --brief --recursive --no-dereference -- \
    "${renderer_vendor_source}" \
    "${renderer_vendor_input}" || \
    die "installed renderer vendor input differs from the reviewed source"

# Both fetches are integrity-pinned by checked-in lockfiles. The subsequent
# notice generator itself is offline and fails if either source set is absent.
cargo fetch \
    --manifest-path "${renderer_manifest_input}" \
    --locked \
    --target wasm32-wasip2
npm --prefix "${repository_root}/ui" ci \
    --ignore-scripts

printf 'Prepared locked Cargo and npm license sources\n'
