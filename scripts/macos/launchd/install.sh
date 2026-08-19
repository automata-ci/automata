#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
wrapper_source=$script_directory/automata-launchd-run
label_prefix=dev.automata
plist_directory=/Library/LaunchDaemons
log_directory=/Library/Logs/Automata
install_root=/Library/Automata

die() {
    printf 'automata macOS launchd installer: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf '%s\n' \
        'usage: install.sh control-plane SERVICE_USER ENV_FILE AUTOMATA_BINARY' \
        '       install.sh runner SERVICE_USER RUNNER_CONFIG RUNNER_BINARY' >&2
    exit 2
}

is_absolute_safe_path() {
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!A-Za-z0-9_./:-]*) return 1 ;;
    esac
}

require_absolute_safe_path() {
    is_absolute_safe_path "$1" || die "path is not a canonical absolute path: $1"
}

require_owner_only_file() {
    path=$1
    expected_owner=$2
    require_absolute_safe_path "$path"
    [ -f "$path" ] || die "path is not a regular file: $path"
    [ ! -L "$path" ] || die "path must not be a symbolic link: $path"
    [ "$(stat -f '%Su' -- "$path")" = "$expected_owner" ] ||
        die "path is not owned by $expected_owner: $path"
    case "$(stat -f '%Lp' -- "$path")" in
        600|400) ;;
        *) die "path must be owner-only (0600 or 0400): $path" ;;
    esac
}

require_executable() {
    path=$1
    require_absolute_safe_path "$path"
    [ -f "$path" ] || die "executable is not a regular file: $path"
    [ ! -L "$path" ] || die "executable must not be a symbolic link: $path"
    [ -x "$path" ] || die "executable is not executable: $path"
    if find "$path" -prune -perm -022 -print | grep . >/dev/null 2>&1; then
        die "executable is group- or world-writable: $path"
    fi
    return 0
}

xml_path() {
    case "$1" in
        *[\&\<\>\"\']*) die "path contains an XML metacharacter: $1" ;;
    esac
    printf '%s' "$1"
}

[ "$(id -u)" -eq 0 ] || die "run this installer with sudo"
[ "$#" -eq 4 ] || usage
role=$1
service_user=$2
input_path=$3
binary=$4

service_uid=$(id -u "$service_user" 2>/dev/null) ||
    die "service account does not exist: $service_user"
[ "$service_uid" -ne 0 ] || die "service account must not be root"
service_group=$(id -gn "$service_user") ||
    die "service group name could not be resolved: $service_user"

case "$role" in
    control-plane)
        label=$label_prefix.control-plane
        require_owner_only_file "$input_path" "$service_user"
        ;;
    runner)
        label=$label_prefix.runner
        require_owner_only_file "$input_path" "$service_user"
        ;;
    *) die "unknown service role: $role" ;;
esac
require_executable "$binary"

install -d -o root -g wheel -m 0755 "$plist_directory" "$install_root/bin"
install -d -o "$service_user" -g "$service_group" -m 0750 "$log_directory"
install -o root -g wheel -m 0555 "$wrapper_source" "$install_root/bin/automata-launchd-run"

plist=$plist_directory/$label.plist
temporary_plist=$plist_directory/.$label.plist.$$
wrapper=$install_root/bin/automata-launchd-run

input_xml=$(xml_path "$input_path")
binary_xml=$(xml_path "$binary")
wrapper_xml=$(xml_path "$wrapper")
log_xml=$(xml_path "$log_directory/$label.log")
error_xml=$(xml_path "$log_directory/$label.error.log")

if [ "$role" = control-plane ]; then
    env_xml=$input_xml
    command_xml='<string>server</string>'
    argument_xml=''
else
    env_xml='-'
    command_xml='<string>run</string>'
    argument_xml=$(printf '%s\n' \
        '        <string>--config</string>' \
        "        <string>$input_xml</string>")
fi

cat > "$temporary_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>$wrapper_xml</string>
        <string>$env_xml</string>
        <string>$binary_xml</string>
        $command_xml
$argument_xml
    </array>
    <key>UserName</key>
    <string>$service_user</string>
    <key>GroupName</key>
    <string>$service_group</string>
    <key>WorkingDirectory</key>
    <string>$install_root</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>$log_xml</string>
    <key>StandardErrorPath</key>
    <string>$error_xml</string>
</dict>
</plist>
EOF

plutil -lint "$temporary_plist" >/dev/null || {
    rm -f "$temporary_plist"
    die "generated launchd plist failed validation"
}

launchctl bootout "system/$label" >/dev/null 2>&1 || true
install -o root -g wheel -m 0600 "$temporary_plist" "$plist"
rm -f "$temporary_plist"
launchctl bootstrap system "$plist"
printf 'installed and started %s as %s\n' "$label" "$service_user"
