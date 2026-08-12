# Arch Linux runner hosts

This guide prepares an Arch Linux host for Automata's current rootless Podman
runner. Before opening a control-plane session, the runner checks its nftables
modules and performs a create/inspect/destroy lifecycle with the configured
Podman inputs. Installing the packages alone is not enough.

The lifecycle proves local network and provider admission. Resource limits,
profile conformance, service containers, and end-to-end workflow compatibility
have separate checks.

## Required host packages

```console
sudo pacman -S --needed podman crun netavark aardvark-dns \
  fuse-overlayfs passt slirp4netns nftables
```

Keep the normal Arch `firewall_driver = "nftables"` default. `none` removes
Netavark's firewall/NAT enforcement and is not an acceptable runner setting.
Netavark 2 no longer accepts the legacy `iptables` backend on this platform.

## Kernel/module invariant

Every required nftables module must either already be loaded or be loadable
from the running kernel release's matching dependency index. Keep the complete
matching module tree installed so a missing prerequisite can be loaded:

```console
running_kernel="$(uname -r)"
test -s "/usr/lib/modules/${running_kernel}/modules.dep"
modinfo -k "$running_kernel" nf_tables >/dev/null
modinfo -k "$running_kernel" nft_ct >/dev/null
modinfo -k "$running_kernel" nft_masq >/dev/null
modinfo -k "$running_kernel" nft_fib_inet >/dev/null
modinfo -k "$running_kernel" nft_nat >/dev/null
modinfo -k "$running_kernel" nft_reject_inet >/dev/null
modinfo -k "$running_kernel" nft_numgen >/dev/null
```

Arch replaces the old kernel's module tree when the `linux` package is
upgraded. Until reboot, `uname -r` still identifies the old kernel. Modules
that are already loaded can continue to work, but a new rootless network cannot
autoload any missing nftables prerequisite. Netavark then emits
misleading errors similar to:

```text
nftables error: internal:0:0-0: Could not process rule: No such file or directory
```

Do not work around this with `firewall_driver = "none"`. Stop the runner,
reboot into the installed kernel, and rerun admission before starting it again.
At startup, a missing tree is fatal when any required module is not already
loaded; the active lifecycle remains mandatory even when all modules are loaded.

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

Give the three dedicated runner accounts mutually non-overlapping subordinate
ID ranges and verify unified cgroup v2. Run the `podman info` diagnostic once
as each service account; production admission does not invoke it:

```console
test -r /sys/fs/cgroup/cgroup.controllers
for instance in 1 2 3; do
  getsubids "automata-runner-${instance}"
  sudo -u "automata-runner-${instance}" \
    podman info --format '{{.Host.Security.Rootless}} {{.Host.CgroupsVersion}}'
done
```

Run each of the three production processes in its own delegated systemd
service with this cgroup shape:

```systemd
[Service]
Delegate=yes
DelegateSubgroup=supervisor
MemorySwapMax=0
```

`DelegateSubgroup=supervisor` keeps each service's delegated root empty while
placing the runner process in a child. The sandbox provider validates the empty
root, enables and re-reads the CPU, memory, and process controllers, forces
rootless Podman's cgroupfs manager beneath that root, and verifies each started
workload is a descendant. Both `memory.swap.max` and `memory.swap.current` must
be zero at the effective boundary on every create, replay, and attach. A normal
login shell, a unit without the supervisor subgroup, or systemd-managed Podman
scopes outside the delegation fail closed at that provider boundary. The
[checked-in host units](../../deploy/runner-host/README.md) provide three
service instances plus per-process and aggregate CPU, memory, swap, and task
limits. The active network probe does not inspect or certify this cgroup/resource
contract.

## Dedicated Podman runtime mount

Production requires Linux 6.4 or newer, where tmpfs supports the exact
`noswap` mount option. Provision one dedicated tmpfs per runner process whose
mountpoint is that process's configured `podman.runtime_directory`. A directory
that merely resides on the shared `/run` or `/run/user/<uid>` tmpfs is not
sufficient, and the three processes must not share one mount. Give every mount
exact mode 0700 and the dedicated runner UID/GID, and choose finite `size=` and
`nr_inodes=` bounds appropriate to one job. For the checked-in UID/GID
1001-through-1003 shape:

```console
for instance in 1 2 3; do
  runner_account="automata-runner-${instance}"
  runner_uid="$((1000 + instance))"
  sudo install -d -m 0700 -o "$runner_account" -g "$runner_account" \
    "/run/automata_runner_${instance}"
  sudo mount -t tmpfs "automata-runner-runtime-${instance}" \
    "/run/automata_runner_${instance}" \
    -o "nodev,nosuid,noswap,size=20G,nr_inodes=349525,mode=0700,uid=${runner_uid},gid=${runner_uid}"
  findmnt -no TARGET,FSTYPE,OPTIONS \
    --target "/run/automata_runner_${instance}"
done
```

Use the checked-in boot-managed mount units ordered before the matching
`automata-runner@N` service; the command is only a development illustration.
Do not bind a tmpfs at another path and do not create any mount below it. Each
configuration requires `state.podman` to equal
`podman.runtime_directory/automata-ci-podman/state`. Journal and spool roots
remain durable and cannot overlap the transient runtime mount.

Startup opens this mount before creating the Podman subtree. It joins two
bounded `/proc/thread-self/mountinfo` reads around the open descriptor's
filesystem and mount identity, decodes kernel path escapes, and requires one
record with root `/`, the exact configured mountpoint, `tmpfs`, and one exact
`noswap` superblock option. It rejects same-device aliases and every equal or
descendant mountpoint. The exact mount ID, device, mount options, propagation
fields, source, and superblock options are retained and revalidated before
every runner-initiated Podman spawn, provider operation, and authorized job
Docker request. The first mismatch irreversibly quarantines the shared Podman
trust handle.

This is a non-swappable runtime-storage proof, not a per-job capacity proof.
Keep both `ephemeral_disk_bytes` fields at `0`; the runner advertises no
ephemeral-disk capacity.

## Active admission probe

Before advertising Podman job isolation, create an isolated network, attach a
throwaway container with a loopback-only published port, and remove all owned
resources. The production probe uses the exact configured absolute Podman
binary and base arguments. It clears the ambient process environment and sets
the configured `HOME`, `PATH`, `XDG_RUNTIME_DIR`, and `TMPDIR`, and it keeps its
one-file rootfs below the configured Podman state root. It first rejects an
effective UID of zero; it does not invoke `podman info`. The manual command
above is therefore neither part of nor equivalent to production admission.

`automata-runner run` performs this mandatory check before starting any
listener or control session. The opt-in runner doctor performs a similar
idempotent `PrivateEgress` diagnostic with its ambient binary, environment, and
diagnostic scratch settings; it is not a substitute for the production
exact-config gate. Doctor output can include raw Podman failure detail and must
remain in the operator trust domain.

The configured Podman, conmon, OCI runtime, init, seccomp, and cleanup files and
the closed seven-entry helper directory are trusted host inputs. Production
requires root-owned, non-group/world-writable lexical and canonical ancestry;
executables must be regular, executable files and the configured Podman itself
must not be a symlink. The helper directory's canonical path ends in
`usr/sbin`, contains no `systemd-run`, and is the entire process `PATH`.
Symlink helper entries retain both link and canonical-target identity.

The configured home and runtime directory, plus the state-root `TMPDIR`, probe,
generated-configuration, hooks, CDI, and engine directories, must be
non-symlink mode-0700 directories owned by the runner account beneath root- or
runner-owned non-group/world-writable ancestry. The hooks and CDI directories
must be empty. `$HOME/.config/containers` and `$HOME/.docker` must be absent or
empty private directories, and `$HOME/.dockercfg` must be absent, closing
containers/image credential fallbacks. The default
`/etc/containers/certs.d`, `/usr/share/containers/certs.d`, and
`/etc/docker/certs.d` registry-client certificate trees must be absent or
exactly empty; a nested build cannot inherit an ambient client certificate or
private key. All Podman storage is below the dedicated runtime mount and
pinned to descriptor-validated graph, run, network, temporary, and volume
paths. Startup
snapshots these filesystem identities before the probe; the same snapshot is
revalidated before every runner-initiated Podman spawn and every authorized
request to the long-lived job Docker service. Mount drift permanently
quarantines the provider even if the original record is later restored.
Podman/conmon's internal
stopped-container cleanup re-exec inherits the admitted environment but remains
inside the trusted administrator/runtime boundary rather than passing through
the runner guard. This metadata/ownership evidence is not a byte attestation.
Jobs never receive these private host paths.

Run the active doctor through the prepared admission unit that carries the
same delegation and no-swap settings as the daemon; a direct shell invocation
does not satisfy the production contract. For a local diagnostic, an
equivalent transient service shape is:

```console
systemd-run --user --wait --collect --pipe \
  -p Type=exec \
  -p Delegate=yes \
  -p DelegateSubgroup=supervisor \
  -p MemorySwapMax=0 \
  automata-runner doctor --active --json
```

The doctor must have a private scratch root. Set an absolute
`AUTOMATA_RUNNER_SCRATCH_DIR`, or provide `XDG_RUNTIME_DIR`/`XDG_STATE_HOME` to
the service account; the runner appends its own private subdirectory for XDG
roots. A root path, relative path, and every path beneath `/tmp` are rejected.
For a systemd user unit, a typical explicit setting is:

```systemd
Environment=AUTOMATA_RUNNER_SCRATCH_DIR=%S/automata-runner/scratch
```

Production does not use those ambient doctor settings. It uses the fixed
mode-0700 `active-probe` child of the configured Podman state root as the
private parent for one-file rootfs lowerdirs, and the state-root
`process-transient` child as `TMPDIR`. Create the state root with owner-only
permissions. Each rootfs child is mode 0711 beneath that private parent and
contains only a mode-0555 `automata-runner` payload.

Both active probes require a statically linked runner because this one-file
rootfs contains no userspace libraries. The lifecycle verifies the exact
payload bytes and descriptor/name binding before and after Podman starts it as
`--rootfs <path>:O`. The `:O` overlay keeps runtime-created paths in
container-owned state and leaves the lowerdir unchanged. Each probe uses a
unique, ownership-labeled network and container, publishes only to a random
loopback port, and builds or pulls no image. Production applies the exact
configured `NetworkPolicy`: `PrivateEgress` requires a non-internal network,
while `Disabled` adds `--internal` and verifies the network is internal.

Admission inspects the created network's identity and policy, requires the
probe container to be attached exclusively to that exact network, checks the
loopback readiness response, verifies resource ownership before deletion, and
confirms the exact container and network IDs are absent afterward. Only then
does it unlink the exact payload and rootfs through retained `NOFOLLOW`
descriptors. If container absence cannot be confirmed, the lowerdir remains
instead of invalidating storage that may still reference it. Successful cleanup
is part of admission, not best-effort housekeeping. The following is only an
abbreviated operator diagnostic, not equivalent admission evidence; its rootfs
path must be a mode-0711 directory beneath a private mode-0700 parent and
contain only a static mode-0555 `automata-runner`:

```console
podman network create automata-admission-probe
podman run --rm \
  --network automata-admission-probe \
  --publish 127.0.0.1::8080 \
  --read-only --cap-drop all --security-opt no-new-privileges \
  --user 65532:65532 \
  --rootfs /path/to/private/one-file-rootfs:O \
  /automata-runner __probe-http-ready \
  --port 8080 --token 0123456789abcdef0123456789abcdef
podman network rm automata-admission-probe
```

Add `--internal` to `podman network create` when diagnosing the `Disabled`
branch. This abbreviated command sequence omits the identity, policy,
attachment, source-byte binding, ownership, readiness-response, exact-ID
cleanup, and post-delete inspections that production requires.

Never allow a failed probe to fall back to a weaker isolation provider while
retaining the stronger capability advertisement. The current runner has one
production Podman provider and exits before any listener or control session
unless that configured network probe and cleanup succeed. This positive probe
does not itself prove that an environment-profile image exists or that its
manifest conforms, nor does it certify cgroup/resource enforcement, privilege
or root-filesystem policy, or the optional job-scoped Docker API. Startup
separately creates, inspects, and destroys every configured profile through the
provider before constructing advertised inventory; supply-chain and complete
hosted-image conformance remain separate operator boundaries.

## Local smart-Git bridge firewall

Local integration jobs fetch an immutable snapshot from the bounded smart-HTTP Git
bridge on the host. A rootless job reaches the host gateway, so a loopback-only
listener is insufficient. Bind the bridge to one exact RFC 1918 address
(`192.168.0.8:8088` in the development example), never `0.0.0.0`. Exact binding
prevents the process from also listening on Tailscale and any other host
address, but the private LAN address still needs an ingress guard.

[`scripts/dev/git-bridge-firewall.sh`](../../scripts/dev/git-bridge-firewall.sh)
owns the independent `inet automata_git_bridge_guard` table. Its input base
chain has an `accept` policy and exactly one terminal rule: drop packets for the
configured Git address and TCP port when their input interface is not `lo`.
It does not flush a ruleset or edit Results, `iptables-nft`, Netavark, Docker,
or Tailscale state.

Choose the host-specific values in a nonsymlink config copied from
[`deploy/dev/git-bridge-firewall.env.example`](../../deploy/dev/git-bridge-firewall.env.example).
The helper parses this strict data without sourcing it and rejects wildcard,
loopback, public, carrier-grade NAT, and non-canonical addresses; privileged or
invalid ports; duplicate or unknown keys; and every config path that traverses
a symbolic link. `audit` and `apply` additionally reject an address that is not
assigned to a non-loopback interface on the host.

Inspect the exact transaction before approving any privileged action:

```console
./scripts/dev/git-bridge-firewall.sh render \
  --listen-address 192.168.0.8 \
  --port 8088
```

For these inputs the complete proposed table is:

```nftables
table inet automata_git_bridge_guard {
	comment "automata-git-bridge-firewall:v1"
	chain git_bridge_input {
		type filter hook input priority -10; policy accept;
		ip daddr 192.168.0.8 tcp dport 8088 iifname != "lo" drop comment "automata-git-bridge-firewall:deny-non-loopback:v1"
	}
}
```

Verify that the host routes its own exact private address through loopback:

```console
ip -4 route get 192.168.0.8
# local 192.168.0.8 dev lo ...
```

After reviewing the render output, install and audit the guard before starting
the bridge. Creation is one atomic nftables transaction, exact reapplication is
a no-op, and any extra, missing, or changed table object makes `audit`, `apply`,
and `remove` refuse without changing the table.

The following development command assumes the runner bootstrap guide has
already created `target/integration/source` and
`target/runner-local/git-http-scratch`; `realpath` intentionally fails when
either reviewed input is absent.

```console
sudo ./scripts/dev/git-bridge-firewall.sh apply \
  --listen-address 192.168.0.8 \
  --port 8088
sudo ./scripts/dev/git-bridge-firewall.sh audit \
  --listen-address 192.168.0.8 \
  --port 8088
python3 scripts/dev/git-http-server.py \
  --project-root "$(realpath target/integration/source)" \
  --scratch-directory "$(realpath target/runner-local/git-http-scratch)" \
  --git-http-backend "$(realpath "$(git --exec-path)/git-http-backend")" \
  --listen-address 192.168.0.8 \
  --port 8088
```

Confirm the actual rootless Podman path after the exact listener is running.
Capture one request in one terminal (the `tcpdump` package is diagnostic-only):

```console
sudo timeout 30s tcpdump -l -nn -i any -Q in -c 1 \
  'tcp and dst host 192.168.0.8 and dst port 8088'
```

In another terminal, use the same host-gateway alias and rootless Netavark path
as a job. This probe first pulls the exact digest with an empty authentication
file, then creates and removes only its uniquely named network:

```console
(
  set -e
  git_probe_network="automata-git-path-probe-${UID}"
  git_probe_image='ghcr.io/automata-ci/automata-ubuntu-24.04-x64@sha256:db8471ae0e6b77038961029f8e8620ae35eb3cdde21978ff831c251e0ec899dd'
  git_probe_auth="$PWD/target/runner-local/git-probe-anonymous-auth.json"
  install -d -m 0700 -- "$(dirname -- "${git_probe_auth}")"
  install -m 0600 /dev/null "${git_probe_auth}"
  printf '{"auths":{}}\n' > "${git_probe_auth}"
  cleanup_git_probe() {
    rm -f -- "${git_probe_auth}"
    podman network rm "${git_probe_network}" >/dev/null 2>&1 || true
  }
  trap cleanup_git_probe EXIT
  podman pull --authfile "${git_probe_auth}" "${git_probe_image}" >/dev/null
  podman network create "${git_probe_network}" >/dev/null
  podman run --rm --pull never --network "${git_probe_network}" \
    --add-host automata-git.ghe.com:host-gateway \
    "${git_probe_image}" \
    curl --silent --show-error --output /dev/null --max-time 5 \
      --write-out 'HTTP %{http_code}\n' \
      'http://automata-git.ghe.com:8088/automata-ci/automata/info/refs?service=git-upload-pack'
)
```

The request must return HTTP 200 and the capture must identify `lo` as the
input interface. If it arrives through another interface, the guard remains
fail-closed and the request is dropped; stop the listener and investigate the
route rather than weakening the rule. From a separate LAN machine, a request
to `http://192.168.0.8:8088/` must time out. The process must have no listener
on `0.0.0.0:8088`, a Tailscale address, or any address other than the reviewed
private address.

Stop the bridge before removal. Removal requires a byte-for-byte canonical
match, captures the table's kernel handle, and deletes by that handle so a
concurrent replacement is not selected by name:

```console
sudo ./scripts/dev/git-bridge-firewall.sh remove \
  --listen-address 192.168.0.8 \
  --port 8088
```

Kernel table state does not survive boot. A persistent development setup must
run `apply` as a dedicated startup dependency before the exact-address bridge,
using root-owned nonsymlink copies of the reviewed helper and config. Never
reload a generic nftables ruleset that flushes tables owned by container
runtimes. To change address or port, stop the listener, remove the exact old
policy, apply the reviewed new policy, and only then start the new listener.

The standalone contract suite exercises strict validation, symlink rejection,
atomic idempotency, drift refusal, loopback allowance, non-loopback denial, and
exact removal inside a disposable network namespace; it does not alter the host
namespace:

```console
./scripts/dev/git-bridge-firewall.test.sh
```

## Local Results listener firewall

The local GitHub Actions Results endpoint is a deliberate exception to the
loopback-only development services. A rootless job resolves
`host.containers.internal`, but it cannot reach a process bound only to host
loopback. Bind the development listener to one exact RFC 1918 address instead
(`192.168.0.8:8081` on the current development host), and publish
`http://host.containers.internal:8081/` to the job. Never bind this HTTP-only
development endpoint to `0.0.0.0`.

That private address is also reachable from the physical LAN unless the host
filters it. [`scripts/dev/results-firewall.sh`](../../scripts/dev/results-firewall.sh)
owns one independent `inet automata_results_guard` table. Its input base chain
has an `accept` policy and only one terminal rule: packets for the configured
address and TCP port are dropped when their input interface is not `lo`.
Consequently, traffic unrelated to the Results socket continues to the
existing Docker, Podman, Tailscale, and host rules unchanged. The helper never
flushes a ruleset or edits an `iptables-nft`, Netavark, or Tailscale table.

Choose the host-specific inputs in a nonsymlink config copied from
[`deploy/dev/results-firewall.env.example`](../../deploy/dev/results-firewall.env.example).
The helper parses this as strict data rather than sourcing shell. It rejects
wildcard, loopback, public, non-canonical, and unassigned addresses; privileged
or invalid ports; unknown keys; duplicate keys; and a config path containing
any symbolic-link component.

Before applying the policy, inspect its complete transaction:

```console
./scripts/dev/results-firewall.sh render \
  --listen-address 192.168.0.8 \
  --port 8081
```

For those example inputs the exact proposed table is:

```nftables
table inet automata_results_guard {
	comment "automata-results-firewall:v1"
	chain results_input {
		type filter hook input priority -10; policy accept;
		ip daddr 192.168.0.8 tcp dport 8081 iifname != "lo" drop comment "automata-results-firewall:deny-non-loopback:v1"
	}
}
```

Confirm the route and the real rootless Podman packet path before installing
the guard. `ip route` must select host loopback for the bound address:

```console
ip -4 route get 192.168.0.8
# local 192.168.0.8 dev lo ...
```

With the Results listener already running, capture one inbound request in one
terminal (the `tcpdump` package is needed only for this diagnostic):

```console
sudo timeout 30s tcpdump -l -nn -i any -Q in -c 1 \
  'tcp and dst host 192.168.0.8 and dst port 8081'
```

In another terminal, make the request through the same rootless Netavark path
used by a job. This probe first pulls the exact digest with an empty
authentication file, then creates and removes only its uniquely named Podman
network:

```console
(
  set -e
  results_probe_network="automata-results-path-probe-${UID}"
  results_probe_image='ghcr.io/automata-ci/automata-ubuntu-24.04-x64@sha256:db8471ae0e6b77038961029f8e8620ae35eb3cdde21978ff831c251e0ec899dd'
  results_probe_auth="$PWD/target/runner-local/results-probe-anonymous-auth.json"
  install -d -m 0700 -- "$(dirname -- "${results_probe_auth}")"
  install -m 0600 /dev/null "${results_probe_auth}"
  printf '{"auths":{}}\n' > "${results_probe_auth}"
  cleanup_results_probe() {
    rm -f -- "${results_probe_auth}"
    podman network rm "${results_probe_network}" >/dev/null 2>&1 || true
  }
  trap cleanup_results_probe EXIT
  podman pull --authfile "${results_probe_auth}" "${results_probe_image}" >/dev/null
  podman network create "${results_probe_network}" >/dev/null
  podman run --rm --pull never --network "${results_probe_network}" \
    "${results_probe_image}" \
    curl --silent --show-error --output /dev/null --max-time 5 \
      --write-out 'HTTP %{http_code}\n' \
      http://host.containers.internal:8081/
)
```

The capture must identify `lo` as the input interface. Do not apply this
policy if the packet arrives through any other interface: the guard is
intentionally fail-closed and would make Results unreachable to jobs.

Once the rendered rules and packet path have been reviewed, apply and audit
the policy. Each creation is one atomic nftables transaction. Reapplying an
exact policy is a no-op; a present table with any extra, missing, or changed
object makes both `audit` and `apply` fail without modifying it.

```console
sudo ./scripts/dev/results-firewall.sh apply \
  --listen-address 192.168.0.8 \
  --port 8081
sudo ./scripts/dev/results-firewall.sh audit \
  --listen-address 192.168.0.8 \
  --port 8081
```

Test denial from a separate LAN machine, not from the host itself. A request
to `http://192.168.0.8:8081/` must time out while the Podman request above must
still receive an HTTP response.

Removal is equally narrow. It requires a byte-for-byte canonical match of the
entire expected table, captures that table's kernel handle, and deletes by
handle. Drift causes refusal, and a concurrent replacement is not selected by
name:

```console
sudo ./scripts/dev/results-firewall.sh remove \
  --listen-address 192.168.0.8 \
  --port 8081
```

The table is kernel state and must be applied again after boot. Keep this as a
dedicated startup dependency that runs `apply` before the Results listener;
do not enable or reload a generic nftables ruleset that flushes tables owned by
container runtimes. Install any startup copy of the helper and its config as
root-owned regular files, reject existing symlink targets, and use the same
reviewed arguments for startup audit and removal. When changing the address or
port, first stop the listener, remove the exact old policy, apply the new
policy, and only then restart the listener. This avoids a period in which an
unprotected socket is listening.

The standalone contract suite exercises validation, config symlink rejection,
atomic idempotency, drift refusal, and exact removal inside a disposable
network namespace; it never changes the host namespace:

```console
./scripts/dev/results-firewall.test.sh
```

## Upgrade status

The current product does not expose runner draining or mutable capability
registration, so it does not support an in-place runner upgrade procedure. Do
not treat the unimplemented administration commands as an operational drain or
rotation mechanism.

For an offline development host, upgrade the complete Arch system with
`pacman -Syu`, reboot after kernel or container-stack changes, and rerun the
module and active Podman checks before starting a runner. If the capability
snapshot changes, the current static bootstrap refuses registration drift;
provision a fresh runner identity and reviewed bootstrap record instead of
editing durable registration state by hand.

`automata-runner run` fails before starting any listener or opening a control
session when a required networking module is neither loaded nor available from
the running kernel's dependency index, or when exact configured active
rootless-network admission and cleanup fail.
