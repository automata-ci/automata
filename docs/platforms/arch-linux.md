# Arch Linux runner hosts

Arch Linux is Automata's initial runner-host distribution. A host is admitted
only when it can enforce the isolation capabilities it advertises. Package
presence alone is not sufficient.

## Required host packages

```console
sudo pacman -S --needed podman crun netavark aardvark-dns \
  fuse-overlayfs passt slirp4netns nftables
```

Keep the normal Arch `firewall_driver = "nftables"` default. `none` removes
Netavark's firewall/NAT enforcement and is not an acceptable runner setting.
Netavark 2 no longer accepts the legacy `iptables` backend on this platform.

## Kernel/module invariant

The running kernel release must have its complete matching module tree:

```console
running_kernel="$(uname -r)"
test -s "/usr/lib/modules/${running_kernel}/modules.dep"
modinfo -k "$running_kernel" nf_tables >/dev/null
modinfo -k "$running_kernel" nft_ct >/dev/null
modinfo -k "$running_kernel" nft_masq >/dev/null
modinfo -k "$running_kernel" nft_fib_inet >/dev/null
modinfo -k "$running_kernel" nft_nat >/dev/null
modinfo -k "$running_kernel" nft_reject_inet >/dev/null
```

Arch replaces the old kernel's module tree when the `linux` package is
upgraded. Until reboot, `uname -r` still identifies the old kernel. Already
loaded modules continue to work, which makes the host look healthy, but a new
rootless network cannot autoload missing nftables modules. Netavark then emits
misleading errors similar to:

```text
nftables error: internal:0:0-0: Could not process rule: No such file or directory
```

Do not work around this with `firewall_driver = "none"`. Drain the runner,
reboot into the installed kernel, and run the admission probe before
registering it again.

The host should preload the modules needed by rootless Netavark, because the
runner service account must not receive general module-loading privileges:

```text
# /etc/modules-load.d/automata-netavark.conf
nf_tables
nft_ct
nft_masq
nft_fib_inet
nft_nat
nft_reject_inet
nft_numgen
```

After creating that file, reboot. A one-time development-host check may load
them with `sudo modprobe`, but production runners must reach the ready state
through their normal boot configuration.

## Rootless identity and cgroups

Give the dedicated runner account non-overlapping subordinate ID ranges and
verify unified cgroup v2:

```console
getsubids "${USER}"
test -r /sys/fs/cgroup/cgroup.controllers
podman info --format '{{.Host.Security.Rootless}} {{.Host.CgroupsVersion}}'
```

The runner's service manager must delegate the controllers used for job limits.
Merely seeing `/sys/fs/cgroup` is not proof that the account can create and
manage a child cgroup.

## Active admission probe

Before advertising Podman job isolation, create an isolated network, attach a
throwaway container with a loopback-only published port, and remove both. The
probe must use the same account, environment, storage, network backend, and
systemd unit configuration as the runner daemon. A successful `podman info`
alone does not exercise Netavark or nftables.

Automata's runner doctor performs this idempotently with its own statically
linked executable as the scratch payload and reports structured capability
failures:

```console
automata-runner doctor --active --json
```

The service must have a private scratch root. Set an absolute
`AUTOMATA_RUNNER_SCRATCH_DIR`, or provide `XDG_RUNTIME_DIR`/`XDG_STATE_HOME` to
the service account; the runner appends its own private subdirectory for XDG
roots. A root path, relative path, and every path beneath `/tmp` are rejected.
For a systemd user unit, a typical explicit setting is:

```systemd
Environment=AUTOMATA_RUNNER_SCRATCH_DIR=%S/automata-runner/scratch
```

Create persistent state with owner-only permissions. Probe contexts are
mode 0700 and removed after success, failure, or bounded cancellation.

The active probe requires a statically linked runner because the scratch image
contains no userspace libraries. It uses a unique, ownership-labeled network,
image, container, and mode-0700 build context; publishes only to a random
loopback port; never pulls an image; and cleans every owned resource before it
advertises the networking capability. The equivalent manual shape is:

```console
podman network create automata-admission-probe
podman run --rm \
  --network automata-admission-probe \
  --publish 127.0.0.1::8080 \
  --pull never \
  YOUR_LOCALLY_PINNED_PROBE_IMAGE
podman network rm automata-admission-probe
```

Never allow a failed probe to fall back to a weaker isolation provider while
retaining the stronger capability advertisement. The runner remains
unregistered or advertises only the providers whose active probes succeeded.

## Upgrade procedure

1. Mark the runner draining and wait for active leases to finish.
2. Upgrade the complete Arch system with `pacman -Syu`; do not perform partial
   upgrades.
3. Reboot whenever the kernel or low-level container stack changes.
4. Run the module and active Podman admission checks.
5. Register the new capability snapshot and return the runner to service.

Automata will reject registrations whose running-kernel module tree is missing,
even when an older Podman process happens to keep working with already-loaded
modules.
