#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: install.sh <profile-id> <guest-agent> <vsock-bridge> <job-uid> <job-gid> <process-limit>" >&2
    exit 64
fi

profile_id=$1
guest_agent=$2
vsock_bridge=$3
job_uid=$4
job_gid=$5
process_limit=$6
job_user=automata-job
install_root=/Library/Automata
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

if [ "$(id -u)" -ne 0 ] || [ "$(uname -m)" != arm64 ]; then
    echo "guest installation requires root in an ARM64 macOS VM" >&2
    exit 77
fi
case $profile_id in
    ''|*[!A-Za-z0-9._/-]*) echo "invalid profile ID" >&2; exit 64 ;;
esac
for number in "$job_uid" "$job_gid" "$process_limit"; do
    case $number in
        ''|*[!0-9]*) echo "invalid job UID/GID or process limit" >&2; exit 64 ;;
    esac
done
if [ "$job_uid" -lt 500 ] || [ "$job_gid" -lt 500 ] || \
   [ "$process_limit" -lt 1 ] || [ "$process_limit" -gt 1000000 ]; then
    echo "job UID/GID or process limit is outside the supported range" >&2
    exit 64
fi
if [ ! -x "$guest_agent" ] || [ ! -x "$vsock_bridge" ]; then
    echo "guest binaries must be executable" >&2
    exit 66
fi
if dscl . -read "/Users/$job_user" >/dev/null 2>&1 || \
   dscl . -read "/Groups/$job_user" >/dev/null 2>&1; then
    echo "the sealed-image job identity must not already exist" >&2
    exit 78
fi
if dscl . -search /Users UniqueID "$job_uid" | grep -q . || \
   dscl . -search /Groups PrimaryGroupID "$job_gid" | grep -q .; then
    echo "the requested job UID/GID is already allocated" >&2
    exit 78
fi

dscl . -create "/Groups/$job_user"
dscl . -create "/Groups/$job_user" PrimaryGroupID "$job_gid"
dscl . -create "/Users/$job_user"
dscl . -create "/Users/$job_user" UniqueID "$job_uid"
dscl . -create "/Users/$job_user" PrimaryGroupID "$job_gid"
dscl . -create "/Users/$job_user" NFSHomeDirectory "/Users/$job_user"
dscl . -create "/Users/$job_user" UserShell /bin/bash
dscl . -create "/Users/$job_user" IsHidden 1
dscl . -create "/Users/$job_user" AuthenticationAuthority ';DisabledUser;'
dscl . -create "/Users/$job_user" Password '*'

install -d -o root -g wheel -m 0755 "$install_root" "$install_root/bin"
install -d -o "$job_user" -g "$job_user" -m 0700 \
    "/Users/$job_user" \
    "/Users/$job_user/Library" \
    "/Users/$job_user/Library/Caches" \
    "/Users/$job_user/Library/Caches/Automata" \
    "/Users/$job_user/workspaces" \
    "/Users/$job_user/runner" \
    "/Users/$job_user/tmp" \
    "/Users/$job_user/tool-cache"
install -o root -g wheel -m 0555 "$guest_agent" \
    "$install_root/bin/automata-ci-sandbox-guest"
install -o root -g wheel -m 0555 "$vsock_bridge" \
    "$install_root/bin/automata-macos-vsock-bridge"

guest_sha256=$(/usr/bin/shasum -a 256 "$install_root/bin/automata-ci-sandbox-guest" | awk '{print $1}')
macos_version=$(/usr/bin/sw_vers -productVersion)
macos_build=$(/usr/bin/sw_vers -buildVersion)
identity_tmp="$install_root/.guest-identity.json.tmp"
printf '{"profile_id":"%s","guest_agent_sha256":"%s","macos_version":"%s","macos_build":"%s","architecture":"arm64","job_uid":%s,"job_gid":%s,"process_limit":%s}\n' \
    "$profile_id" "$guest_sha256" "$macos_version" "$macos_build" "$job_uid" "$job_gid" "$process_limit" \
    > "$identity_tmp"
chown root:wheel "$identity_tmp"
chmod 0444 "$identity_tmp"
mv -f "$identity_tmp" "$install_root/guest-identity.json"
cp "$install_root/guest-identity.json" "$script_dir/guest-identity.json"
chmod 0444 "$script_dir/guest-identity.json"

for label in dev.automata.guest-agent dev.automata.vsock-bridge; do
    source_plist="$script_dir/$label.plist"
    destination_plist="/Library/LaunchDaemons/$label.plist"
    plutil -lint "$source_plist" >/dev/null
    install -o root -g wheel -m 0600 "$source_plist" "$destination_plist"
    if [ "$label" = dev.automata.guest-agent ]; then
        /usr/libexec/PlistBuddy \
            -c "Set :HardResourceLimits:NumberOfProcesses $process_limit" \
            -c "Set :SoftResourceLimits:NumberOfProcesses $process_limit" \
            "$destination_plist"
    fi
    chown root:wheel "$destination_plist"
    chmod 0444 "$destination_plist"
    launchctl bootstrap system "$destination_plist"
done

echo "guest installed; shut down the VM before sealing its disk and auxiliary storage" >&2
