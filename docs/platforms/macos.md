# Isolated macOS runners

Automata supports macOS jobs only through a disposable macOS 15-or-newer ARM64
virtual machine on an Apple Silicon macOS 15+ host. The former native provider
has been deleted. Current runner product schema v8 has no `macos_native` key,
no migration from a noncurrent schema, and no host-shared resource mode.

## Why Virtualization.framework

macOS has no public, cgroup-equivalent whole-job security boundary for hostile
processes. Process groups and `setrlimit` can help with cleanup or individual
limits, but they leave the host kernel, identity, filesystem, Keychain, and
network in the job's security domain. They are not accepted as isolation.

Apple's supported macOS-on-Apple-Silicon boundary is
[Virtualization.framework](https://developer.apple.com/documentation/virtualization/virtualize-macos-on-a-mac).
Its VM configuration exposes exact
[CPU count and guest physical-memory size](https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration),
and device arrays determine whether network interfaces, host directories, and
Virtio sockets exist. The Automata helper configures only a private disk,
graphics, entropy, and one
[Virtio socket device](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdeviceconfiguration).
Both `networkDevices` and `directorySharingDevices` are empty.

The helper carries only Apple's
[`com.apple.security.virtualization`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization)
entitlement. Apple documents that configuration validation checks this
entitlement. No networking, Hypervisor.framework, device-access, App Sandbox
escape, or private entitlement is requested.

## Boundary and trust model

Provider startup and each job use this sequence:

1. At startup, validate the full root-owned, non-writable, symlink-free trust
   path and hash the manifest, disk image, auxiliary storage, and helper.
2. Before each launch, re-hash and code-signature-verify the helper; the helper
   must have exactly the virtualization entitlement, and it revalidates the
   complete root-owned source-artifact path before opening it.
3. Verify that the manifest, template artifacts, and provider state are on the
   configured roleless APFS volume; that this is the only volume in a dedicated
   non-boot APFS container; and that its exact quota and remaining capacity can
   hold a fully dirtied clone plus 32 GiB of headroom.
4. Create an owner-only attempt directory and APFS-clone both mutable VM
   artifacts into it.
5. Configure a unique VM machine identifier, exact whole vCPUs and memory, no
   NIC, and no shared directory; then validate and cold-boot the VM.
6. Challenge the guest over Virtio socket with a fresh nonce. The guest proves
   its profile, agent digest, macOS version/build, architecture, and job UID/GID.
7. Apply the process ceiling inside the guest before accepting workflow traffic.
8. Create the attempt's private workspace and command roots inside the fresh
   guest, then forward bounded exec/copy frames. Closing the anonymous runner
   pipe is watched independently of blocked guest I/O and terminates the VM.
   Destroy removes the clone under an exclusive lock.

The host macOS kernel, Virtualization.framework, signed helper, Rust provider,
and immutable template are trusted. Workflow code is not. The dedicated
`automata-job` guest account is non-admin, has no password, and owns only guest
workspace, runner, temp, home, and tool-cache paths. Runner TLS, object-store
credentials, spool keys, host Keychain, and host files are never mounted or
sent into the VM.

Only `network: "disabled"` is implemented. Private egress is intentionally
rejected until a separate authenticated host broker exists; attaching a NAT
device would weaken the current contract.

The protocol-2 host helper and newly provisioned guest bridge contain the
closed transport primitive for that broker. The guest bridge owns only
`127.0.0.1:18081`, permits at most 16 concurrent relays, and connects to the
host only through fixed Virtio socket port 10251. The helper registers that
port only when its launch request names the owner-only Unix socket
`runtime-proxy.sock` directly inside the current attempt directory. It rejects
another path, owner, file type, link count, or group/other permission.

The current runner deliberately sends `null`, so no host listener or runtime
service route is available and no network capability is advertised. A later
slice must supply an attempt-scoped broker that authenticates and restricts
exact GitHub and Results routes before the runner may expose the guest
loopback endpoint. This transport is not a generic TCP proxy and does not
justify adding a VM network device.

## Build and sign the host tools

Use Xcode's Swift toolchain on Apple Silicon:

```console
swift build -c release \
  --package-path crates/automata-ci-sandbox-macos/swift

codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" \
  --identifier dev.automata.macos-vm-helper \
  --entitlements crates/automata-ci-sandbox-macos/swift/virtualization.entitlements \
  crates/automata-ci-sandbox-macos/swift/.build/release/automata-macos-vm-helper
```

Install the helper root-owned and non-writable at
`/Library/Automata/bin/automata-macos-vm-helper`. Record its lowercase SHA-256
and a strict designated requirement, for example
`identifier "dev.automata.macos-vm-helper" and anchor apple generic and
certificate leaf[subject.OU] = "ABCDEFGHIJ"`. Replace `ABCDEFGHIJ` with the
exact ten-character signing Team ID; this conjunctive grammar is the only
accepted Developer ID requirement.

A private fleet may instead sign with a reviewed private code-signing identity
and pin the exact leaf certificate SHA-1 used by Apple's
[requirement language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html):

```text
identifier "dev.automata.macos-vm-helper" and certificate leaf = H"0123456789ABCDEFFEDCBA98765432100A2BC5DA"
```

The hash is exactly 40 uppercase hexadecimal characters. It identifies the
certificate, not the helper bytes; `helper_sha256` independently pins the
complete executable. The private key must remain outside the runner service
identity, and rotating the certificate requires an explicit configuration
update. Apple trust-store installation is neither required nor consulted by
this exact-leaf requirement. A signer that reads the private key directly can
produce the Mach-O signature without adding that certificate to the host trust
store. For example, `rcodesign` accepts a password file rather than exposing
the PKCS#12 password in the process arguments:

```console
rcodesign sign \
  --p12-file /offline/path/helper-signing.p12 \
  --p12-password-file /offline/path/helper-signing.password \
  --binary-identifier dev.automata.macos-vm-helper \
  --code-signature-flags runtime \
  --entitlements-xml-file crates/automata-ci-sandbox-macos/swift/virtualization.entitlements \
  --timestamp-url none \
  crates/automata-ci-sandbox-macos/swift/.build/release/automata-macos-vm-helper
```

`rcodesign` is an independently distributed tool, not an Automata runtime
dependency. Pin and verify the reviewed release before using it. Developer ID
remains the distribution profile for
software delivered to third-party Macs because it supplies Apple/Gatekeeper
identity and notarization. An ad-hoc signature may be used only to inspect
build and entitlement shape and is intentionally rejected by both accepted
product grammars.

## Provision bounded host storage

Use a dedicated APFS **container (partition)** for VM storage, not another
volume in the macOS startup container. Apple documents that
[volumes in one APFS container share its free space, while a per-volume quota
limits allocation](https://support.apple.com/guide/disk-utility/add-delete-or-erase-apfs-volumes-dskua9e6a110/mac).
Automata requires both boundaries: a fixed, non-boot
container and exactly one roleless `AutomataVM` volume with an exact quota. This
keeps a hostile guest's copy-on-write disk growth out of the startup container.

Back up the host, then use Disk Utility's documented
[**Partition** operation](https://support.apple.com/guide/disk-utility/partition-a-physical-disk-dskutl14027/mac)
to create the fixed container. Do not use **Add APFS Volume** on `Macintosh HD`. Provision the
container with enough capacity for the chosen quota and APFS overhead. Make the
final volume its sole member and assign a whole-GiB quota between 64 GiB and
1 TiB. The quota must exceed the sealed virtual disk length plus auxiliary
storage plus 32 GiB of provider headroom. For example, the minimum 64 GiB
template can use a 100 GiB (`107374182400` byte) quota; a 128 GiB template needs
a larger quota. Apple's Disk Utility **Size Options** UI can set the quota. If a
bootstrap volume was created during partitioning, add the quota-bearing volume
and remove the bootstrap volume only after resolving the exact device
identifiers with `diskutil apfs list`.

Verify the mounted result and record the volume UUID:

```console
diskutil info -plist /Volumes/AutomataVM \
  | plutil -extract VolumeUUID raw -o - -
diskutil apfs list
```

The dedicated container must show only `AutomataVM`, with no APFS role and the
configured quota. Create the mutable provider root as the runner service
account, and keep the template tree root-owned after sealing:

```console
runner_account=automata-runner
template_builder="$(id -un)"
sudo chown root:wheel /Volumes/AutomataVM
sudo chmod 0755 /Volumes/AutomataVM
sudo diskutil enableOwnership /Volumes/AutomataVM
sudo install -d -o "$runner_account" -g "$(id -gn "$runner_account")" -m 0700 \
  /Volumes/AutomataVM/state
sudo install -d -o root -g wheel -m 0755 \
  /Volumes/AutomataVM/templates
sudo install -d -o "$template_builder" -g "$(id -gn "$template_builder")" -m 0700 \
  /Volumes/AutomataVM/templates/macos-15-arm64-v1
```

At startup Automata independently resolves `df` and `diskutil -plist` data. It
rejects the startup container, sibling volumes, virtual or disk-image backing
stores, disabled ownership enforcement, APFS roles, UUID/device/quota
mismatches, cross-volume template files, a read-only filesystem, a mutable or
non-root-owned state-directory ancestry, and less free space than the full
virtual disk plus auxiliary storage plus 32 GiB. A quota is not an
ephemeral-disk claim: the guest still sees its fixed template disk, so
`ephemeral_disk_bytes` remains zero.

## Build and seal a template

Obtain a pinned local macOS 15-or-newer IPSW from Apple. Apple's supported
installation flow uses
[`VZMacOSRestoreImage`](https://developer.apple.com/documentation/virtualization/vzmacosrestoreimage)
and
[`VZMacOSInstaller`](https://developer.apple.com/documentation/virtualization/vzmacosinstaller).
The template tool implements that flow and preserves the hardware model,
machine identifier, and auxiliary storage required by
[`VZMacPlatformConfiguration`](https://developer.apple.com/documentation/virtualization/vzmacplatformconfiguration).

```console
tool=crates/automata-ci-sandbox-macos/swift/.build/release/automata-macos-template-tool
codesign --force --sign - \
  --entitlements crates/automata-ci-sandbox-macos/swift/virtualization.entitlements "$tool"

template=/Volumes/AutomataVM/templates/macos-15-arm64-v1
"$tool" install /absolute/path/macOS15.ipsw "$template" 128 4 8
"$tool" boot "$template" 4 8 \
  --provisioning-directory /absolute/path/provisioning \
  --output-directory /absolute/path/empty-output
```

The same provisioning UI can be driven entirely over SSH. The control mode
keeps the `VZVirtualMachineView` inside the host user's Aqua session, writes
framebuffer captures to an owner-controlled path, and accepts input commands
on standard input. It does not require Screen Sharing, Remote Management,
Screen Recording, or Accessibility access:

```console
builder="$(id -un)"
builder_uid="$(id -u "$builder")"
control=/absolute/path/owner-only-control
install -d -m 0700 "$control"
rm -f "$control/screen.png"
sudo launchctl asuser "$builder_uid" sudo -u "$builder" \
  "$tool" boot "$template" 4 8 \
  --provisioning-directory /absolute/path/provisioning \
  --output-directory /absolute/path/empty-output \
  --control-screenshot "$control/screen.png"
```

The builder must already have an Aqua login session; `launchctl asuser` reuses
that session and does not create one from an SSH login.

The tool prints `ready`, then accepts one newline-terminated command at a
time and replies with `ok <command>` or `error <reason>`:

- `capture` atomically replaces the configured PNG.
- `click <x> <y>` moves and clicks using screenshot coordinates with a
  top-left origin.
- `key <macOS-virtual-key-code>` sends an unmodified key press.
- `type <base64-utf8>` types US-keyboard characters that do not require a
  modifier: lowercase letters, digits, space, tab, newline, and
  `` `-=[]\\;',./ ``. Upload a script through the provisioning directory for
  commands containing other characters instead of putting credentials on a
  terminal command line.
- `shutdown` requests a graceful guest shutdown. `stop` is an immediate VM
  stop and is only a recovery operation.

EOF also stops the VM so an abandoned SSH controller cannot leave an
unmanaged guest running. The tool exits automatically after a guest-initiated
shutdown. The screenshot path must not exist when control mode starts; its
parent must already be a directory.

In the provisioning window, finish Setup Assistant with a temporary admin.
Build `automata-ci-sandbox-guest` for ARM64 macOS and the release
`automata-macos-vsock-bridge`; place them and `guest/` in the read-only
provisioning directory. macOS 13+ automounts that temporary share under
`/Volumes/My Shared Files/Provisioning`; a separate initially empty output
directory is writable at `/Volumes/My Shared Files/Output`. The tool rejects
overlapping directories or a nonempty output directory. From a guest Terminal,
copy the provisioning bundle to a guest-local directory and run:

```console
sudo guest/install.sh automata.dev/macos-15-arm64-vm-v1 \
  ./automata-ci-sandbox-guest ./automata-macos-vsock-bridge 502 502 512
sudo guest/install-node-runtime.sh 20 ./node20 \
  <lowercase-sha256-of-the-native-arm64-node20-binary>
sudo guest/install-node-runtime.sh 24 ./node24 \
  <lowercase-sha256-of-the-native-arm64-node24-binary>
cp guest/guest-identity.json "/Volumes/My Shared Files/Output/guest-identity.json"
sudo shutdown -h now
```

`node20` and `node24` above are the `bin/node` regular files extracted from
version-pinned official `darwin-arm64` Node.js distributions on the trusted
builder. Verify each distribution against its published Node.js release
`SHASUMS256.txt` before copying the binary into the provisioning directory.
The installer independently pins the binary digest, rejects non-ARM64 or wrong
major-version executables, and installs it root-owned and non-writable beneath
`/Library/Automata/externals`. The checked-in runner example advertises both
runtimes. Set an unavailable generation to `null`; the runner then withholds
that exact Node capability. Node 12 and 16 use the same installer when a native
ARM64 binary is deliberately provided, but are not part of the checked-in
profile.

The script creates the disabled-password non-admin account, installs the two
launch daemons, writes the baked guest identity, and copies that identity beside
the guest-local provisioning assets. Remove all guest-local provisioning
material before the final shutdown.

Current macOS refuses to delete its last administrator or secure-token user. If
the temporary Setup Assistant account is the last one, do not leave its known
bootstrap credential active. Run the following cleanup script with `sudo`; it
disables and hides the account, removes it from the admin group, assigns a
non-login shell, and shuts down from the same already-authorized root process:

```sh
#!/bin/sh
set -eu
bootstrap_user=replace-with-short-account-name
pwpolicy -u "$bootstrap_user" -disableuser
dseditgroup -o edit -d "$bootstrap_user" -t user admin
dscl . -create "/Users/$bootstrap_user" IsHidden 1
dscl . -create "/Users/$bootstrap_user" UserShell /usr/bin/false
dscl . -read /Groups/admin GroupMembership
dscl . -read "/Users/$bootstrap_user" AuthenticationAuthority IsHidden UserShell
shutdown -h now
```

If managed provisioning supplies a different administrator, delete the
temporary account instead. Boot once more without either directory option to
verify that no shared directory, usable interactive login, File Sharing,
Remote Login, Screen Sharing, or other remote service is enabled, then shut
down cleanly. Use the identity copied into the dedicated host output directory
for sealing.

Seal only on an offline trusted builder:

```console
"$tool" seal "$template" \
  /absolute/path/guest/guest-identity.json \
  /absolute/path/automata-ci-sandbox-guest \
  "$template/manifest.json"

sudo chown -R root:wheel "$template"
sudo chmod 0555 "$template"
sudo chmod 0444 "$template"/{Disk.img,AuxiliaryStorage,manifest.json}
shasum -a 256 "$template/manifest.json"
```

The sealer hashes the complete disk and auxiliary storage, embeds the serialized
hardware model, and copies the attested OS/agent/identity values into a strict
manifest. Build and seal at the final path: the strict manifest records absolute
artifact paths. Moving it later is rejected. The manifest, disk, auxiliary
storage, and provider state must remain on the dedicated quota volume;
otherwise startup fails before a job can be leased.

## Configure and run

Copy
[`runner.macos.example.json`](../../crates/automata-ci-runner/config/runner.macos.example.json)
to an ignored host-local file. Replace the helper and manifest digests, strict
code requirement, runner identity, endpoints, and credential sources. The
environment profile manifest digest must exactly equal
`macos_virtualization.template_manifest_sha256`.

Provision the three configured TLS paths as owner-only regular files beneath
`~/Library/Application Support/Automata/tls`. The long-lived runner renews and
atomically reconciles that file-backed identity before expiry; Keychain remains
the custody boundary for stable spool and object-store secrets. A
Keychain-backed TLS identity is not a current alternate mode.

The linked checked-in example is the sole complete current boundary: runner
product schema 8. It selects the `macos_virtualization` provider, a writable
unprivileged executor with networking disabled, and the mandatory closed
`object_store.tls_trust` policy. Do not reconstruct a product document from a
partial provider-only excerpt; noncurrent schemas are rejected rather than
migrated or defaulted.

Run one runner process and one slot per provider root:

```console
cargo build --release --bin automata-runner
./target/release/automata-runner capabilities --config /absolute/path/runner.macos.json
./target/release/automata-runner run --config /absolute/path/runner.macos.json
```

Startup refuses Intel, macOS before 15, fractional CPU allocations, multiple
slots or profiles, services, containers, GPUs, claimed ephemeral-disk capacity,
private/host networking, host identity/filesystem policies, mutable or
wrong-owner artifacts, mismatched hashes/profile, untrusted helper signatures,
an unbounded/shared/boot-container APFS layout, insufficient clone capacity, or
overlapping host state roots. It admits Bash, `sh`, action materialization
utilities, and every configured Node runtime by executing them inside a
disposable VM before connecting to the control plane. Missing or wrong-major
Node runtimes therefore cannot be advertised. Old schema/native configuration
is an error.

## Validation

Repository CI intentionally does not schedule paid GitHub-hosted macOS jobs.
When repository-scoped Apple Silicon capacity is provisioned, it must compile
and lint the Rust and Swift components, inspect the helper entitlement, and
exercise protocol/configuration failure paths. Before deployment, that physical
runner must also execute the ignored
`macos_vm_runner_process_e2e::shipped_runner_process_executes_a_claimed_isolated_shell_job`
test with the eight `AUTOMATA_MACOS_VM_*` artifact and storage
variables. That test verifies no Ethernet device, no host helper path,
memory/vCPU sizing, the sealed process ceiling, shell/output behavior, and
clone cleanup. Deployment qualification must additionally inject
process-ceiling exhaustion, pipe loss, and helper crashes, reopen the journal,
and run repeated clean jobs.

Create `/Volumes/AutomataVM/e2e-state` as an empty `0700` directory owned by
the physical runner service account before running the command below.

```console
AUTOMATA_MACOS_VM_HELPER=/Library/Automata/bin/automata-macos-vm-helper \
AUTOMATA_MACOS_VM_HELPER_SHA256=<helper-sha256> \
AUTOMATA_MACOS_VM_HELPER_REQUIREMENT='<strict-designated-requirement>' \
AUTOMATA_MACOS_VM_TEMPLATE_MANIFEST=/Volumes/AutomataVM/templates/macos-15-arm64-v1/manifest.json \
AUTOMATA_MACOS_VM_TEMPLATE_SHA256=<manifest-sha256> \
AUTOMATA_MACOS_VM_STORAGE_ROOT=/Volumes/AutomataVM/e2e-state \
AUTOMATA_MACOS_VM_STORAGE_VOLUME_UUID=<uppercase-volume-uuid> \
AUTOMATA_MACOS_VM_STORAGE_QUOTA_BYTES=107374182400 \
cargo test --locked -p automata-ci-runner --test runner -- \
  macos_vm_runner_process_e2e::shipped_runner_process_executes_a_claimed_isolated_shell_job \
  --ignored --nocapture --test-threads=1
```
