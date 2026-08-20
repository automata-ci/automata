#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    printf 'macOS launchd wrapper contract skipped on non-macOS\n'
    exit 0
fi

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd)"
wrapper="${repository_root}/scripts/macos/launchd/automata-launchd-run"
install -d -m 0700 -- "${repository_root}/target"
scratch_directory="$(mktemp -d "${repository_root}/target/macos-launchd-test.XXXXXXXX")"
trap 'rm -rf -- "${scratch_directory}"' EXIT

env_file="${scratch_directory}/service.env"
fake_binary="${scratch_directory}/fake-service"
config_file="${scratch_directory}/runner.json"
printf '%s\n' 'AUTOMATA_TEST_VALUE=from-owner-only-env' >"${env_file}"
printf '%s\n' '{}' >"${config_file}"
chmod 0600 "${env_file}" "${config_file}"
cat >"${fake_binary}" <<'EOF'
#!/bin/sh
printf '%s\n' "${AUTOMATA_TEST_VALUE}"
printf '%s\n' "$*"
EOF
chmod 0755 "${fake_binary}"

[[ "$(${wrapper} "${env_file}" "${fake_binary}" server)" == $'from-owner-only-env\nserver' ]]
[[ "$(${wrapper} "${env_file}" "${fake_binary}" run --config "${config_file}")" == $'from-owner-only-env\nrun --config '* ]]
[[ "$(${wrapper} - "${fake_binary}" run --config "${config_file}")" == $'\nrun --config '* ]]

chmod 0644 "${env_file}"
if "${wrapper}" "${env_file}" "${fake_binary}" server >/dev/null 2>&1; then
    printf 'wrapper accepted a group-readable environment file\n' >&2
    exit 1
fi

printf 'macOS launchd wrapper contract verified\n'
