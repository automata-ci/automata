#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd)"
readonly repository_root

scratch_directory="$(mktemp -d "${repository_root}/target/install-test.XXXXXXXX")"
readonly scratch_directory
cleanup() {
  rm -rf -- "${scratch_directory}"
}
trap cleanup EXIT

release_directory="${scratch_directory}/release"
payload_directory="${scratch_directory}/payload"
install_directory="${scratch_directory}/bin"
asset="automata-x86_64-unknown-linux-musl.tar.gz"
readonly asset
archive_member_arguments=(
  LICENSE
  SHA256SUMS
  THIRD_PARTY_LICENSES.txt
  THIRD_PARTY_NOTICES.txt
  VERSION
  automata
  automata-runner
  sbom
)
readonly archive_member_arguments

write_internal_checksums() {
  local payload="$1"
  (
    cd "${payload}"
    sha256sum \
      LICENSE \
      THIRD_PARTY_LICENSES.txt \
      THIRD_PARTY_NOTICES.txt \
      VERSION \
      automata \
      automata-runner \
      sbom/*.cdx.json \
      > SHA256SUMS
  )
}

build_release_archive() {
  local payload="$1"
  local release="$2"
  install -d -m 0700 -- "${release}"
  (
    cd "${payload}"
    tar -czf "${release}/${asset}" "${archive_member_arguments[@]}"
  )
  (
    cd "${release}"
    sha256sum "${asset}" > "${asset}.sha256"
  )
}

expect_installer_failure() {
  local release="$1"
  local case_name="$2"
  local expected_message="$3"
  local log="${scratch_directory}/${case_name}.log"
  if AUTOMATA_INSTALL_DIR="${install_directory}" \
    AUTOMATA_RELEASE_BASE_URL="file://${release}" \
    AUTOMATA_VERSION=9.8.7 \
    "${repository_root}/scripts/install.sh" >"${log}" 2>&1; then
    printf 'installer accepted invalid %s fixture\n' "${case_name}" >&2
    exit 1
  fi
  grep -F -- "${expected_message}" "${log}" >/dev/null
}

fake_uname_directory="${scratch_directory}/fake-uname-bin"
install -d -m 0700 -- "${fake_uname_directory}"
cat > "${fake_uname_directory}/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "${AUTOMATA_INSTALL_TEST_UNAME_S}" ;;
  -m) printf '%s\n' "${AUTOMATA_INSTALL_TEST_UNAME_M}" ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "${fake_uname_directory}/uname"

unsupported_os_log="${scratch_directory}/unsupported-os.log"
if AUTOMATA_INSTALL_TEST_UNAME_S=Darwin \
  AUTOMATA_INSTALL_TEST_UNAME_M=arm64 \
  PATH="${fake_uname_directory}:${PATH}" \
  "${repository_root}/scripts/install.sh" >"${unsupported_os_log}" 2>&1; then
  printf 'installer accepted an unsupported operating system\n' >&2
  exit 1
fi
grep -F \
  "prebuilt releases and runner execution currently support Linux only; for a source-supported control plane use 'cargo install automata-ci --locked'" \
  "${unsupported_os_log}" >/dev/null
if grep -F 'cargo install automata-ci automata-ci-runner' "${unsupported_os_log}" >/dev/null; then
  printf 'installer recommended an unsupported runner fallback\n' >&2
  exit 1
fi

unsupported_architecture_log="${scratch_directory}/unsupported-architecture.log"
if AUTOMATA_INSTALL_TEST_UNAME_S=Linux \
  AUTOMATA_INSTALL_TEST_UNAME_M=aarch64 \
  PATH="${fake_uname_directory}:${PATH}" \
  "${repository_root}/scripts/install.sh" >"${unsupported_architecture_log}" 2>&1; then
  printf 'installer accepted an unsupported prebuilt architecture\n' >&2
  exit 1
fi
grep -F \
  "prebuilt releases currently support Linux x86_64; for a source-supported control plane use 'cargo install automata-ci --locked'; production runner installation requires a verified static distribution" \
  "${unsupported_architecture_log}" >/dev/null
if grep -F 'cargo install automata-ci automata-ci-runner' \
  "${unsupported_architecture_log}" >/dev/null; then
  printf 'installer recommended an unsupported runner fallback\n' >&2
  exit 1
fi

install -d -m 0700 -- "${release_directory}" "${payload_directory}/sbom"

printf '%s\n' '#!/bin/sh' 'printf "%s\n" "automata 9.8.7 (test)"' > "${payload_directory}/automata"
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "automata-runner 9.8.7 (test)"' > "${payload_directory}/automata-runner"
chmod 0755 "${payload_directory}/automata" "${payload_directory}/automata-runner"
printf 'test\n' > "${payload_directory}/LICENSE"
printf 'test\n' > "${payload_directory}/THIRD_PARTY_LICENSES.txt"
printf 'test\n' > "${payload_directory}/THIRD_PARTY_NOTICES.txt"
printf '9.8.7\n' > "${payload_directory}/VERSION"
printf '{}\n' > "${payload_directory}/sbom/automata.cdx.json"
printf '{}\n' > "${payload_directory}/sbom/automata-runner.cdx.json"
printf '{}\n' > "${payload_directory}/sbom/renderer.cdx.json"
printf '{}\n' > "${payload_directory}/sbom/ui-runtime.cdx.json"
write_internal_checksums "${payload_directory}"
build_release_archive "${payload_directory}" "${release_directory}"

portable_bin="${scratch_directory}/portable-bin"
sha256sum_binary="$(command -v sha256sum)"
mktemp_binary="$(command -v mktemp)"
install -d -m 0700 -- "${portable_bin}"
# The generated wrapper expands its arguments when invoked.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'for argument do' \
  '  case "$argument" in' \
  '    --check | --strict | --ignore-missing) ;;' \
  '    -*) exit 97 ;;' \
  '  esac' \
  'done' \
  "exec \"${sha256sum_binary}\" \"\$@\"" \
  > "${portable_bin}/sha256sum"
mktemp_log="${scratch_directory}/mktemp.log"
# The generated wrapper expands its arguments and log path when invoked.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'for argument do' \
  '  case "$argument" in' \
  '    /*) printf "%s\n" "$argument" >> "$AUTOMATA_INSTALL_TEST_MKTEMP_LOG" ;;' \
  '  esac' \
  'done' \
  "exec \"${mktemp_binary}\" \"\$@\"" \
  > "${portable_bin}/mktemp"
chmod 0755 "${portable_bin}/sha256sum" "${portable_bin}/mktemp"

assert_mktemp_log_is_repository_local() {
  local template
  [[ -s "${mktemp_log}" ]]
  while IFS= read -r template; do
    case "${template}" in
      "${repository_root}"/target/*) ;;
      *)
        printf 'installer used scratch outside the repository target: %s\n' "${template}" >&2
        exit 1
        ;;
    esac
  done < "${mktemp_log}"
}

test_home="${scratch_directory}/home"
default_temporary_parent="${test_home}/.cache/automata/install-tmp"
install -d -m 0700 -- "${test_home}"
export AUTOMATA_INSTALL_TEST_MKTEMP_LOG="${mktemp_log}"
export HOME="${test_home}"
export PATH="${portable_bin}:${PATH}"
unset TMPDIR XDG_RUNTIME_DIR XDG_CACHE_HOME

AUTOMATA_INSTALL_DIR="${install_directory}" \
AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
AUTOMATA_VERSION=9.8.7 \
  "${repository_root}/scripts/install.sh"

[[ "$(sed -n '1p' "${mktemp_log}")" == \
  "${default_temporary_parent}/automata-install.XXXXXXXX" ]]
[[ "$(stat -c '%a' -- "${default_temporary_parent}")" == 700 ]]
if compgen -G "${default_temporary_parent}/automata-install.*" >/dev/null; then
  printf 'installer left default scratch behind\n' >&2
  exit 1
fi
assert_mktemp_log_is_repository_local

[[ "$("${install_directory}/automata" --version)" == 'automata 9.8.7 (test)' ]]
[[ "$("${install_directory}/automata-runner" --version)" == 'automata-runner 9.8.7 (test)' ]]
[[ ! -e "${install_directory}/LICENSE" ]]

explicit_temporary_parent="${scratch_directory}/explicit-tmp"
: > "${mktemp_log}"
TMPDIR="${explicit_temporary_parent}" \
AUTOMATA_INSTALL_DIR="${install_directory}" \
AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
AUTOMATA_VERSION=9.8.7 \
  "${repository_root}/scripts/install.sh"
[[ "$(sed -n '1p' "${mktemp_log}")" == \
  "${explicit_temporary_parent}/automata-install.XXXXXXXX" ]]
[[ "$(stat -c '%a' -- "${explicit_temporary_parent}")" == 700 ]]
if compgen -G "${explicit_temporary_parent}/automata-install.*" >/dev/null; then
  printf 'installer left explicit TMPDIR scratch behind\n' >&2
  exit 1
fi
assert_mktemp_log_is_repository_local

explicit_temporary_real="${scratch_directory}/explicit-real"
explicit_temporary_link="${scratch_directory}/explicit-link"
install -d -m 0700 -- "${explicit_temporary_real}"
ln -s -- "${explicit_temporary_real}" "${explicit_temporary_link}"
symbolic_tmp_log="${scratch_directory}/symbolic-tmp.log"
if TMPDIR="${explicit_temporary_link}" \
  AUTOMATA_INSTALL_DIR="${install_directory}" \
  AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
  AUTOMATA_VERSION=9.8.7 \
  "${repository_root}/scripts/install.sh" >"${symbolic_tmp_log}" 2>&1; then
  printf 'installer accepted a symbolic-link TMPDIR\n' >&2
  exit 1
fi
grep -F \
  "temporary directory must not be a symbolic link: ${explicit_temporary_link}" \
  "${symbolic_tmp_log}" >/dev/null

cp -- "${release_directory}/${asset}.sha256" "${scratch_directory}/archive.sha256"
printf '%s\n' '0000000000000000000000000000000000000000000000000000000000000000  extra' \
  >> "${release_directory}/${asset}.sha256"
checksum_shape_log="${scratch_directory}/checksum-shape.log"
if AUTOMATA_INSTALL_DIR="${install_directory}" \
  AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
  AUTOMATA_VERSION=9.8.7 \
  "${repository_root}/scripts/install.sh" >"${checksum_shape_log}" 2>&1; then
  printf 'installer accepted a multi-line release checksum file\n' >&2
  exit 1
fi
grep -F \
  'release checksum file must contain exactly one line' \
  "${checksum_shape_log}" >/dev/null
cp -- "${scratch_directory}/archive.sha256" "${release_directory}/${asset}.sha256"
[[ "$("${install_directory}/automata" --version)" == 'automata 9.8.7 (test)' ]]
[[ "$("${install_directory}/automata-runner" --version)" == 'automata-runner 9.8.7 (test)' ]]

printf '%064d  %s\n' 0 "${asset}" > "${release_directory}/${asset}.sha256"
checksum_mismatch_log="${scratch_directory}/checksum-mismatch.log"
if AUTOMATA_INSTALL_DIR="${install_directory}" \
  AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
  AUTOMATA_VERSION=9.8.7 \
  "${repository_root}/scripts/install.sh" >"${checksum_mismatch_log}" 2>&1; then
  printf 'installer accepted an incorrect release checksum\n' >&2
  exit 1
fi
grep -F \
  'release archive checksum does not match' \
  "${checksum_mismatch_log}" >/dev/null
cp -- "${scratch_directory}/archive.sha256" "${release_directory}/${asset}.sha256"

duplicate_release="${scratch_directory}/duplicate-release"
install -d -m 0700 -- "${duplicate_release}"
(
  cd "${payload_directory}"
  tar -czf "${duplicate_release}/${asset}" \
    LICENSE SHA256SUMS THIRD_PARTY_LICENSES.txt THIRD_PARTY_NOTICES.txt VERSION \
    automata automata automata-runner sbom
)
(
  cd "${duplicate_release}"
  sha256sum "${asset}" > "${asset}.sha256"
)
expect_installer_failure \
  "${duplicate_release}" \
  duplicate-member \
  'release archive member must appear exactly once: automata'

missing_payload="${scratch_directory}/missing-payload"
missing_release="${scratch_directory}/missing-release"
cp -a -- "${payload_directory}" "${missing_payload}"
rm -f -- "${missing_payload}/sbom/renderer.cdx.json"
write_internal_checksums "${missing_payload}"
build_release_archive "${missing_payload}" "${missing_release}"
expect_installer_failure \
  "${missing_release}" \
  missing-member \
  'release archive member must appear exactly once: sbom/renderer.cdx.json'

symlink_payload="${scratch_directory}/symlink-payload"
symlink_release="${scratch_directory}/symlink-release"
cp -a -- "${payload_directory}" "${symlink_payload}"
rm -f -- "${symlink_payload}/automata"
ln -s -- /bin/true "${symlink_payload}/automata"
write_internal_checksums "${symlink_payload}"
build_release_archive "${symlink_payload}" "${symlink_release}"
expect_installer_failure \
  "${symlink_release}" \
  symlink-executable \
  'release archive member must be one regular file: automata'

hardlink_payload="${scratch_directory}/hardlink-payload"
hardlink_release="${scratch_directory}/hardlink-release"
cp -a -- "${payload_directory}" "${hardlink_payload}"
rm -f -- "${hardlink_payload}/automata-runner"
ln -- "${hardlink_payload}/automata" "${hardlink_payload}/automata-runner"
write_internal_checksums "${hardlink_payload}"
build_release_archive "${hardlink_payload}" "${hardlink_release}"
expect_installer_failure \
  "${hardlink_release}" \
  hardlink-executables \
  'release archive member must be one regular file: automata'

internal_checksum_payload="${scratch_directory}/internal-checksum-payload"
internal_checksum_release="${scratch_directory}/internal-checksum-release"
cp -a -- "${payload_directory}" "${internal_checksum_payload}"
sed -i \
  's/^[0-9a-f]\{64\}  automata$/0000000000000000000000000000000000000000000000000000000000000000  automata/' \
  "${internal_checksum_payload}/SHA256SUMS"
build_release_archive \
  "${internal_checksum_payload}" \
  "${internal_checksum_release}"
expect_installer_failure \
  "${internal_checksum_release}" \
  internal-checksum \
  'release archive internal checksums do not match'

failure_log="${scratch_directory}/version-mismatch.log"
if AUTOMATA_INSTALL_DIR="${install_directory}" \
  AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
  AUTOMATA_VERSION=9.8.6 \
  "${repository_root}/scripts/install.sh" >"${failure_log}" 2>&1; then
  printf 'installer accepted a mismatched archive version\n' >&2
  exit 1
fi
grep -F \
  'release archive version 9.8.7 does not match requested version 9.8.6' \
  "${failure_log}" >/dev/null
[[ "$("${install_directory}/automata" --version)" == 'automata 9.8.7 (test)' ]]
[[ "$("${install_directory}/automata-runner" --version)" == 'automata-runner 9.8.7 (test)' ]]

rm -f -- "${install_directory}/automata-runner"
install -d -m 0700 -- "${install_directory}/automata-runner"
invalid_target_log="${scratch_directory}/invalid-target.log"
if AUTOMATA_INSTALL_DIR="${install_directory}" \
  AUTOMATA_RELEASE_BASE_URL="file://${release_directory}" \
  AUTOMATA_VERSION=9.8.7 \
  "${repository_root}/scripts/install.sh" >"${invalid_target_log}" 2>&1; then
  printf 'installer accepted a directory as an executable target\n' >&2
  exit 1
fi
grep -F \
  "refusing to replace a non-file installation target: ${install_directory}/automata-runner" \
  "${invalid_target_log}" >/dev/null
[[ "$("${install_directory}/automata" --version)" == 'automata 9.8.7 (test)' ]]
[[ -d "${install_directory}/automata-runner" ]]
printf 'installer contract verified\n'
