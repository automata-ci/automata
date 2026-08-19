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

For jobs whose validated runtime authority contains HTTP(S) origins, the
provider starts an owner-only proxy socket inside the current attempt directory
and opens the bridge's fixed guest-loopback relay. Every command receives
`HTTP_PROXY` and `HTTPS_PROXY` (including their lowercase forms) pointing to
`127.0.0.1:18081`. HTTPS remains encrypted end to end through an exact-authority
`CONNECT` tunnel; plain HTTP is forwarded only to an exact configured origin.
The broker rejects every other host, port, protocol, and malformed request,
limits concurrent sessions, strips proxy credentials before plain-HTTP
forwarding, and stops with the VM. Jobs with no runtime-service routes retain a
closed relay. The VM still has no virtual NIC and no general network access.

macOS limits Unix socket paths to 103 bytes, so provider configuration rejects
a state root which cannot fit the fixed attempt and proxy-socket suffix. The
documented `/Volumes/AutomataVM/state` layout is within that bound.

Lifecycle mutations remain replay-safe and generation-fenced. A new journal
namespace deliberately rejects the deleted native provider's state instead of
migrating it. Startup reconciles every incomplete VM attempt while holding its
exclusive clone lock.

The Swift package also builds the template installer/sealer and the in-guest
Virtio socket bridge. Guest launchd definitions and the one-time provisioning
script live in [`guest/`](guest/). See
[`docs/platforms/macos.md`](../../docs/platforms/macos.md) for deployment and
physical-host validation.

The provider has component and product-process coverage. Its physical-host test
is opt-in and requires a sealed template on Apple Silicon. A three-repetition
physical soak of the shipped runner, recovery paths, and runtime proxy passed
on the dedicated test Mac mini on 2026-08-19; the platform guide records the
exact evidence. A continuously scheduled, protected physical lane is still a
deployment follow-up.
