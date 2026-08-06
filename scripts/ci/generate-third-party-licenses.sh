#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
readonly repository_root
# shellcheck source=scripts/ci/lib/target-paths.sh
source "${script_directory}/lib/target-paths.sh"

automata_init_target_root "${repository_root}"
automata_set_target_tmpdir \
    "${repository_root}" \
    "${repository_root}/target/task-tmp/third-party-license-generation"
exec node "${script_directory}/generate-third-party-licenses.mjs" "$@"
