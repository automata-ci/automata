# automata-ci-sandbox-macos

`automata-ci-sandbox-macos` runs every macOS job in a freshly booted Apple
Virtualization.framework VM. There is no native-process mode, compatibility
alias, host-shared resource policy, virtual NIC, or host directory share.

The Rust provider verifies a root-owned template manifest and its disk and
auxiliary-storage digests, then verifies the signed Swift helper by SHA-256 and
designated code requirement before every launch. The helper makes private APFS
clones, assigns a unique machine identifier, configures exact whole-vCPU and
memory bounds, omits network and directory-sharing devices, and owns the VM for
the lifetime of its anonymous control pipes. Losing the runner kills the helper
and therefore the VM.

The manifest, disk, auxiliary storage, and mutable state must share the exact
configured APFS volume. That roleless volume must be alone in a dedicated
non-boot container, have the exact configured quota, and retain enough capacity
for a fully dirtied clone plus headroom. Startup verifies this through bounded
`diskutil -plist` output and refuses shared or unbounded layouts.

The only job transport is a bounded, versioned Virtio socket protocol. Before
job traffic, the guest proves a fresh nonce, profile, guest-agent digest,
macOS version/build, architecture, dedicated non-admin UID/GID, and sealed
process ceiling. The root guest bridge admits only that exact configuration;
the agent applies it before executing commands as the dedicated guest identity.

Lifecycle mutations remain replay-safe and generation-fenced. A new journal
namespace deliberately rejects the deleted native provider's state instead of
migrating it. Startup reconciles every incomplete VM attempt while holding its
exclusive clone lock.

The Swift package also builds the template installer/sealer and the in-guest
Virtio socket bridge. Guest launchd definitions and the one-time provisioning
script live in [`guest/`](guest/). See
[`docs/platforms/macos.md`](../../docs/platforms/macos.md) for deployment and
physical-host validation.

Automata is pre-1.0 and not production-ready.
