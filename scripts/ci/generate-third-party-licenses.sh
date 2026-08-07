#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"
# shellcheck source=scripts/ci/lib/third-party-license-input.sh
source "${script_directory}/lib/third-party-license-input.sh"

automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/third-party-license-generation"
renderer_input="$(automata_third_party_license_renderer_input "${repository_root}")"
readonly renderer_input
renderer_input_lock="$(automata_third_party_license_lock_path "${repository_root}")"
readonly renderer_input_lock
install -d -m 0755 -- "$(dirname -- "${renderer_input_lock}")"
exec {renderer_input_lock_fd}>"${renderer_input_lock}"
readonly renderer_input_lock_fd
flock --shared "${renderer_input_lock_fd}"
export AUTOMATA_INTERNAL_THIRD_PARTY_LICENSE_RENDERER_INPUT="${renderer_input}"
exec node "${script_directory}/generate-third-party-licenses.mjs" "$@"
