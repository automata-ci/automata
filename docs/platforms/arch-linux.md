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

## Local smart-Git bridge firewall

Local dogfood jobs fetch an immutable snapshot from the bounded smart-HTTP Git
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

```console
sudo ./scripts/dev/git-bridge-firewall.sh apply \
  --listen-address 192.168.0.8 \
  --port 8088
sudo ./scripts/dev/git-bridge-firewall.sh audit \
  --listen-address 192.168.0.8 \
  --port 8088
python3 scripts/dev/git-http-server.py \
  --project-root "$(realpath target/dogfood/source)" \
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
as a job. This probe creates and removes only its uniquely named network:

```console
(
  set -e
  git_probe_network="automata-git-path-probe-${UID}"
  git_probe_image='localhost/automata/ubuntu-24.04-x64@sha256:40c952578a042ce6333c3965420068dad0a08ec8acd6514de03807dbe5cf3de8'
  trap 'podman network rm "${git_probe_network}" >/dev/null 2>&1 || true' EXIT
  podman network create "${git_probe_network}" >/dev/null
  podman run --rm --pull never --network "${git_probe_network}" \
    --add-host automata-git.ghe.com:host-gateway \
    "${git_probe_image}" \
    curl --silent --show-error --output /dev/null --max-time 5 \
      --write-out 'HTTP %{http_code}\n' \
      'http://automata-git.ghe.com:8088/GoNeuralAI/automata/info/refs?service=git-upload-pack'
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
used by a job. This probe creates and then removes only its uniquely named
Podman network:

```console
(
  set -e
  results_probe_network="automata-results-path-probe-${UID}"
  results_probe_image='localhost/automata/ubuntu-24.04-x64@sha256:40c952578a042ce6333c3965420068dad0a08ec8acd6514de03807dbe5cf3de8'
  trap 'podman network rm "${results_probe_network}" >/dev/null 2>&1 || true' EXIT
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
