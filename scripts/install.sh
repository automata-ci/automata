#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL
umask 022

repository="automata-ci/automata"
target="x86_64-unknown-linux-musl"
maximum_archive_bytes=268435456
maximum_checksum_bytes=4096

die() {
  printf 'automata installer: %s\n' "$*" >&2
  exit 1
}

for command in chmod curl grep id install mktemp mv rm sed sha256sum stat tar uname wc; do
  command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: $command"
done

case "$(uname -s)" in
  Linux) ;;
  *) die "prebuilt releases and runner execution currently support Linux only; for a source-supported control plane use 'cargo install automata-ci --locked'" ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) die "prebuilt releases currently support Linux x86_64; for a source-supported control plane use 'cargo install automata-ci --locked'; production runner installation requires a verified static distribution" ;;
esac

requested_version="${AUTOMATA_VERSION:-latest}"
requested_version="${requested_version#v}"
if [ "$requested_version" != latest ] && \
  ! printf '%s\n' "$requested_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'; then
  die "AUTOMATA_VERSION must be 'latest' or a semantic version"
fi

asset="automata-${target}.tar.gz"
if [ -n "${AUTOMATA_RELEASE_BASE_URL:-}" ]; then
  release_base="${AUTOMATA_RELEASE_BASE_URL%/}"
elif [ "$requested_version" = latest ]; then
  release_base="https://github.com/${repository}/releases/latest/download"
else
  release_base="https://github.com/${repository}/releases/download/v${requested_version}"
fi

if [ -n "${AUTOMATA_INSTALL_DIR:-}" ]; then
  install_dir="${AUTOMATA_INSTALL_DIR}"
elif [ -n "${XDG_BIN_HOME:-}" ]; then
  install_dir="${XDG_BIN_HOME}"
elif [ -n "${HOME:-}" ]; then
  install_dir="${HOME}/.local/bin"
else
  die "HOME is unset; set AUTOMATA_INSTALL_DIR explicitly"
fi

temporary_parent_is_private=false
if [ -n "${TMPDIR:-}" ]; then
  temporary_parent="$TMPDIR"
else
  if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    temporary_base="$XDG_RUNTIME_DIR"
  elif [ -n "${XDG_CACHE_HOME:-}" ]; then
    temporary_base="$XDG_CACHE_HOME"
  elif [ -n "${HOME:-}" ]; then
    temporary_base="${HOME%/}/.cache"
  else
    die "no private scratch root is available; set TMPDIR, XDG_RUNTIME_DIR, XDG_CACHE_HOME, or HOME"
  fi
  temporary_parent="${temporary_base%/}/automata/install-tmp"
  temporary_parent_is_private=true
fi
case "$temporary_parent" in
  /*) ;;
  *) die "temporary directory must be absolute: $temporary_parent" ;;
esac
temporary_parent="${temporary_parent%/}"
[ -n "$temporary_parent" ] || temporary_parent=/
if [ -L "$temporary_parent" ]; then
  die "temporary directory must not be a symbolic link: $temporary_parent"
fi
if [ ! -e "$temporary_parent" ]; then
  install -d -m 0700 -- "$temporary_parent" || \
    die "could not create temporary directory: $temporary_parent"
elif [ ! -d "$temporary_parent" ]; then
  die "temporary path is not a directory: $temporary_parent"
fi
if [ ! -w "$temporary_parent" ] || [ ! -x "$temporary_parent" ]; then
  die "temporary directory is not writable and searchable: $temporary_parent"
fi
if [ "$temporary_parent_is_private" = true ]; then
  chmod 0700 -- "$temporary_parent" || \
    die "could not secure temporary directory: $temporary_parent"
  [ "$(stat -c '%u' -- "$temporary_parent")" = "$(id -u)" ] || \
    die "private temporary directory is not owned by the current user: $temporary_parent"
  [ "$(stat -c '%a' -- "$temporary_parent")" = 700 ] || \
    die "private temporary directory must have mode 0700: $temporary_parent"
fi

temporary_directory=''
temporary_prefix="${temporary_parent%/}/automata-install."
automata_stage=''
runner_stage=''
cleanup() {
  temporary_suffix=''
  [ -z "$automata_stage" ] || rm -f -- "$automata_stage"
  [ -z "$runner_stage" ] || rm -f -- "$runner_stage"
  case "$temporary_directory" in
    "${temporary_prefix}"*)
      temporary_suffix="${temporary_directory#"${temporary_prefix}"}"
      case "$temporary_suffix" in
        '' | */*) ;;
        *) rm -rf -- "$temporary_directory" ;;
      esac
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

temporary_directory="$(mktemp -d "${temporary_prefix}XXXXXXXX")"
case "$temporary_directory" in
  "${temporary_prefix}"*)
    temporary_suffix="${temporary_directory#"${temporary_prefix}"}"
    case "$temporary_suffix" in
      '' | */*) die "mktemp returned an unexpected temporary path" ;;
    esac
    ;;
  *) die "mktemp returned an unexpected temporary path" ;;
esac
if [ -L "$temporary_directory" ] || [ ! -d "$temporary_directory" ]; then
  die "mktemp did not create a private temporary directory"
fi
[ "$(stat -c '%u' -- "$temporary_directory")" = "$(id -u)" ] || \
  die "temporary directory is not owned by the current user"
[ "$(stat -c '%a' -- "$temporary_directory")" = 700 ] || \
  die "temporary directory must have mode 0700"

archive_path="${temporary_directory}/${asset}"
checksum_path="${archive_path}.sha256"
curl --fail --location --silent --show-error --proto '=https,file' \
  --proto-redir '=https' --tlsv1.2 --retry 3 \
  --max-filesize "$maximum_archive_bytes" \
  --output "$archive_path" "${release_base}/${asset}"
curl --fail --location --silent --show-error --proto '=https,file' \
  --proto-redir '=https' --tlsv1.2 --retry 3 \
  --max-filesize "$maximum_checksum_bytes" \
  --output "$checksum_path" "${release_base}/${asset}.sha256"
if [ ! -f "$archive_path" ] || [ -L "$archive_path" ]; then
  die "release archive download is not a regular file"
fi
if [ ! -f "$checksum_path" ] || [ -L "$checksum_path" ]; then
  die "release checksum download is not a regular file"
fi
archive_bytes="$(stat -c '%s' -- "$archive_path")"
checksum_bytes="$(stat -c '%s' -- "$checksum_path")"
if ! [ "$archive_bytes" -gt 0 ] || \
  ! [ "$archive_bytes" -le "$maximum_archive_bytes" ]; then
  die "release archive size is outside the supported bound"
fi
if ! [ "$checksum_bytes" -gt 0 ] || \
  ! [ "$checksum_bytes" -le "$maximum_checksum_bytes" ]; then
  die "release checksum size is outside the supported bound"
fi

expected_line="$(sed -n '1p' "$checksum_path")"
[ "$(wc -l < "$checksum_path")" -eq 1 ] || \
  die "release checksum file must contain exactly one line"
case "$expected_line" in
  [0-9a-f][0-9a-f]*"  ${asset}" | [0-9a-f][0-9a-f]*" *${asset}") ;;
  *) die "release checksum file has an unexpected format" ;;
esac
expected_checksum="${expected_line%% *}"
printf '%s\n' "$expected_checksum" | grep -Eq '^[0-9a-f]{64}$' || \
  die "release checksum is not SHA-256"
actual_checksum_line="$(sha256sum "$archive_path")" || \
  die "could not compute the release archive checksum"
actual_checksum="${actual_checksum_line%% *}"
[ "$actual_checksum" = "$expected_checksum" ] || \
  die "release archive checksum does not match"

archive_members="${temporary_directory}/archive-members.txt"
tar -tzf "$archive_path" > "$archive_members" || \
  die "release archive could not be listed"
for required_member in \
  LICENSE \
  SHA256SUMS \
  THIRD_PARTY_LICENSES.txt \
  THIRD_PARTY_NOTICES.txt \
  VERSION \
  automata \
  automata-runner \
  sbom/ \
  sbom/automata.cdx.json \
  sbom/automata-runner.cdx.json \
  sbom/renderer.cdx.json \
  sbom/ui-runtime.cdx.json
do
  [ "$(grep -Fxc -- "$required_member" "$archive_members")" -eq 1 ] || \
    die "release archive member must appear exactly once: $required_member"
done
[ "$(wc -l < "$archive_members")" -eq 12 ] || \
  die "release archive must contain exactly the supported member set"
while IFS= read -r member; do
  case "$member" in
    LICENSE | SHA256SUMS | THIRD_PARTY_LICENSES.txt | \
      THIRD_PARTY_NOTICES.txt | VERSION | automata | automata-runner | sbom/ | \
      sbom/automata.cdx.json | sbom/automata-runner.cdx.json | \
      sbom/renderer.cdx.json | sbom/ui-runtime.cdx.json) ;;
    *) die "release archive contains an unexpected path: $member" ;;
  esac
done < "$archive_members"

extract_directory="${temporary_directory}/extract"
install -d -m 0700 -- "$extract_directory"
tar --extract --gzip --file "$archive_path" \
  --directory "$extract_directory" \
  --no-same-owner \
  --no-same-permissions \
  SHA256SUMS VERSION automata automata-runner || \
  die "release archive could not be extracted"
for extracted_member in SHA256SUMS VERSION automata automata-runner; do
  extracted_path="${extract_directory}/${extracted_member}"
  if [ ! -f "$extracted_path" ] || [ -L "$extracted_path" ] || \
    ! [ "$(stat -c '%h' -- "$extracted_path")" -eq 1 ]; then
    die "release archive member must be one regular file: $extracted_member"
  fi
done
[ "$(stat -c '%s' -- "${extract_directory}/VERSION")" -le 256 ] || \
  die "release archive VERSION is too large"
for executable in automata automata-runner; do
  executable_bytes="$(stat -c '%s' -- "${extract_directory}/${executable}")"
  if ! [ "$executable_bytes" -gt 0 ] || \
    ! [ "$executable_bytes" -le 134217728 ]; then
    die "release archive executable size is outside the supported bound: $executable"
  fi
done

checksum_members="${temporary_directory}/checksum-members.txt"
sed -n 's/^[0-9a-f]\{64\}  //p' "${extract_directory}/SHA256SUMS" \
  > "$checksum_members"
if ! [ "$(wc -l < "${extract_directory}/SHA256SUMS")" -eq 10 ] || \
  ! [ "$(wc -l < "$checksum_members")" -eq 10 ]; then
  die "release archive SHA256SUMS has an unexpected format"
fi
for checksummed_member in \
  LICENSE \
  THIRD_PARTY_LICENSES.txt \
  THIRD_PARTY_NOTICES.txt \
  VERSION \
  automata \
  automata-runner \
  sbom/automata.cdx.json \
  sbom/automata-runner.cdx.json \
  sbom/renderer.cdx.json \
  sbom/ui-runtime.cdx.json
do
  [ "$(grep -Fxc -- "$checksummed_member" "$checksum_members")" -eq 1 ] || \
    die "release archive checksum member must appear exactly once: $checksummed_member"
done
(
  cd "$extract_directory"
  sha256sum --check --strict --ignore-missing SHA256SUMS
) >/dev/null 2>&1 || die "release archive internal checksums do not match"

archive_version="$(sed -n '1p' "${extract_directory}/VERSION")"
[ "$(wc -l < "${extract_directory}/VERSION")" -eq 1 ] || \
  die "release archive contains an invalid VERSION file"
printf '%s\n' "$archive_version" | \
  grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' || \
  die "release archive contains an invalid version"
if [ "$requested_version" != latest ] && [ "$archive_version" != "$requested_version" ]; then
  die "release archive version ${archive_version} does not match requested version ${requested_version}"
fi

automata_version="$("${extract_directory}/automata" --version)" || \
  die "downloaded automata executable failed its version check"
runner_version="$("${extract_directory}/automata-runner" --version)" || \
  die "downloaded automata-runner executable failed its version check"
case "$automata_version" in
  "automata ${archive_version}" | "automata ${archive_version} "*) ;;
  *) die "downloaded control-plane executable does not match release version ${archive_version}" ;;
esac
case "$runner_version" in
  "automata-runner ${archive_version}" | "automata-runner ${archive_version} "*) ;;
  *) die "downloaded runner executable does not match release version ${archive_version}" ;;
esac

install -d -m 0755 -- "$install_dir"
for destination in \
  "${install_dir%/}/automata" \
  "${install_dir%/}/automata-runner"
do
  if [ -d "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
    die "refusing to replace a non-file installation target: $destination"
  fi
done
automata_stage="$(mktemp "${install_dir%/}/.automata.XXXXXXXX")"
runner_stage="$(mktemp "${install_dir%/}/.automata-runner.XXXXXXXX")"
install -m 0755 -- "$extract_directory/automata" "$automata_stage"
install -m 0755 -- "$extract_directory/automata-runner" "$runner_stage"
mv -f -- "$automata_stage" "${install_dir%/}/automata"
automata_stage=''
mv -f -- "$runner_stage" "${install_dir%/}/automata-runner"
runner_stage=''

printf 'Installed %s and %s in %s\n' "$automata_version" "$runner_version" "$install_dir"
case ":${PATH:-}:" in
  *:"${install_dir}":*) ;;
  *) printf 'Add %s to PATH to run Automata.\n' "$install_dir" ;;
esac
