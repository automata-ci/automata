#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: install-node-runtime.sh <major> <node-executable> <sha256>" >&2
    exit 64
fi

major=$1
source_node=$2
expected_sha256=$3
install_root=/Library/Automata/externals

case $major in
    12|16|20|24) ;;
    *) echo "unsupported Node.js action runtime" >&2; exit 64 ;;
esac
case $expected_sha256 in
    *[!0-9a-f]*|'') echo "invalid Node.js SHA-256" >&2; exit 64 ;;
esac
if [ "${#expected_sha256}" -ne 64 ]; then
    echo "invalid Node.js SHA-256" >&2
    exit 64
fi
if [ "$(id -u)" -ne 0 ] || [ "$(uname -m)" != arm64 ]; then
    echo "Node.js runtime installation requires root in an ARM64 macOS VM" >&2
    exit 77
fi
if [ ! -f "$source_node" ] || [ ! -x "$source_node" ] || \
   [ "$(stat -f %HT "$source_node")" != "Regular File" ]; then
    echo "Node.js runtime must be an executable regular file" >&2
    exit 66
fi
if [ "$(/usr/bin/shasum -a 256 "$source_node" | /usr/bin/awk '{print $1}')" != "$expected_sha256" ]; then
    echo "Node.js runtime digest mismatch" >&2
    exit 65
fi
if [ "$(/usr/bin/lipo -archs "$source_node")" != "arm64" ]; then
    echo "Node.js runtime must contain only native ARM64 code" >&2
    exit 65
fi

probe="automata-node-runtime-$major"
if [ "$(/usr/bin/env -i PATH=/usr/bin:/bin "$source_node" --input-type=commonjs --eval \
    "if (process.versions.node.split('.')[0] !== '$major') process.exit(64); process.stdout.write('$probe')")" != "$probe" ]; then
    echo "Node.js runtime failed its exact-major execution probe" >&2
    exit 65
fi

destination="$install_root/node$major/bin/node"
/usr/bin/install -d -o root -g wheel -m 0755 \
    "$install_root" "$install_root/node$major" "$install_root/node$major/bin"
/usr/bin/install -o root -g wheel -m 0555 "$source_node" "$destination"
if [ "$(/usr/bin/shasum -a 256 "$destination" | /usr/bin/awk '{print $1}')" != "$expected_sha256" ]; then
    echo "installed Node.js runtime digest mismatch" >&2
    exit 65
fi

echo "installed Node.js $major action runtime at $destination" >&2
