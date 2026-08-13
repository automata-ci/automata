# `automata-runner`

The supported provisioned `automata-runner` command targets Linux and macOS execution
hosts. Windows native execution remains source-only experimental code without a
production enrollment path or release gate. On supported hosts the command validates
the host, opens an mTLS session to
the control plane, accepts fenced leases, runs jobs through the configured
sandbox provider, streams logs, and removes interrupted work.

`automata-runner run` selects exactly one host-compatible provider from its
configuration: rootless Podman or Kubernetes on Linux, the experimental
trusted-native provider on Windows, or disposable Virtualization.framework
VMs on Apple Silicon macOS 15+. The checked-in
Linux host examples
([one](config/runner.local-1.example.json),
[two](config/runner.local-2.example.json), and
[three](config/runner.local-3.example.json)) select three independent
single-slot Podman processes; the
[Windows](config/runner.windows.example.json) and
[macOS](config/runner.macos.example.json) examples each remain one process and
one slot. The [configuration guide](config/README.md) documents Kubernetes,
Windows native containment, and the macOS VM trust boundary.

No crates.io package or public runner archive has been published. Install a
reviewed source build for configuration work and diagnostics:

```console
cargo install --path crates/automata-ci-runner --locked
automata-runner --version
automata-runner doctor --json
```

That Cargo build is suitable for configuration inspection, host diagnostics,
and development of the trusted native Windows path. On Linux, an ordinary
dynamically linked build is not a valid production probe payload, which must
be a static executable that can run from a one-file root filesystem. Do not
start a production Linux runner until an exact reviewed static archive is
available.

## Startup admission

`automata-runner run` contacts no control plane until the configured host and
provider pass admission. The current Linux path checks:

- a non-root service account and the required nftables modules;
- the configured Podman, conmon, OCI runtime, init, cleanup, seccomp, and helper
  inputs under administrator-controlled ancestry;
- private runner-owned home, runtime, temporary, state, hooks, CDI, graph, and
  engine directories, with ambient Docker and registry credential paths absent
  or empty;
- a dedicated `tmpfs,noswap` mount on Linux 6.4 or newer for Podman runtime
  state; and
- a create, inspect, readiness, and destroy lifecycle using the configured
  network policy and a cleared host-process environment.

The lifecycle copies the running static executable into a private one-file
root filesystem and starts it with Podman's overlay-on-rootfs mode. It verifies
the source bytes, network identity, exclusive attachment, loopback readiness,
ownership, cleanup, and post-delete absence. The runner rechecks the admitted
filesystem and mount snapshot before later Podman operations.

This proves that the configured provider can complete its local lifecycle. It
does not attest image supply chain, prove resource enforcement, or establish
GitHub Actions compatibility.

`automata-runner doctor --active` performs a similar ambient Linux diagnostic
using the caller's `PATH` and scratch settings. Its success does not replace
startup admission, and its raw Podman output should stay inside the operator
trust domain. The active Podman diagnostic is unavailable on Windows; Windows
provider admission happens on `automata-runner run`.

## Environment profiles

Before advertising capacity, startup creates, inspects, and destroys a sandbox
for each configured environment profile. The observed provider, profile,
generation, and running state must match the configuration, and cleanup must
finish. Scheduling sees the intersection of this live inventory and the exact
capabilities admitted during one-time enrollment.

Service containers are opt-in on Linux. `podman.service_proxy_image` must
contain one registry-qualified immutable reference of the form
`repository@sha256:<64 lowercase hex>` that is already in the runner's local
Podman store. Configuration requests the feature for enrollment; successful
image inspection adds it to the live inventory. A missing value
disables the feature, and an invalid or unavailable configured image stops
startup. Mutable tags are rejected.

The Windows profile supports PowerShell and `cmd.exe` `run:` steps, plus an
optional explicitly configured standalone Python interpreter. Startup probes
each configured interpreter through a copied script before advertising the
profile. Every `uses:` action, including JavaScript, composite, local,
repository, and container actions, fails closed. Job containers, service
containers, administrator profiles, and parallel native jobs are unsupported.

Hosted Windows CI is currently disabled because Automata does not yet operate
Windows runners. The native-provider tests remain in the repository, but they
are not a release gate; there is deliberately no Windows enrollment or static
registration path. Do not deploy it until secure Windows credential publication
and the Windows end-to-end CI gate are implemented together.

The macOS profile supports Bash and `sh` `run:` steps, plus optional explicitly
configured Python and PowerShell Core interpreters. Startup probes every
configured interpreter inside a cold-booted, digest-attested macOS 15-or-newer
ARM64 VM.
The provider is single-slot; Virtualization.framework fixes whole-vCPU and
memory size, and the guest applies the process ceiling before workflow traffic.
The VM has no virtual NIC or host directory share. It does not advertise
actions, containers, services, GPUs, or ephemeral-disk capacity.
Template artifacts and mutable clones must live on one pinned, quota-bounded
APFS volume that is alone in a dedicated non-boot container.

## Job boundary

On Linux, workload environment values are sent to Podman through a bounded
anonymous standard-input document. They never enter the Podman host process
environment. Jobs do not receive runner state paths, the host Podman socket,
control-plane credentials, or provider-control credentials.

The Windows native provider is for trusted workflows only. It creates fresh
workspace and scratch directories and uses a Windows Job Object for process,
memory, and CPU limits and whole-tree termination. It retains host filesystem
and network access and the runner service account's unchanged token; it is not
a container, VM, or restricted-token boundary. Run it only as a dedicated
non-administrative service account with administrator-provisioned restrictive
ACLs. The safe state adapter rejects reparse traversal but cannot currently
attest DACL ownership or hard-link counts. Those ACLs protect state from other
host users, not from a trusted job running as the same account, so workflows
must not access runner state paths. See the
[Windows source-build boundary](../../docs/getting-started.md#windows-source-build-and-native-runner-boundary)
before supplying environment-backed credentials.

Rootless Podman is a shared-kernel Linux boundary and Windows native execution
is a trusted-host boundary. macOS uses a disposable Apple VM per job. Stronger
Linux and Windows providers remain planned and are listed in the
[implementation plan](https://github.com/automata-ci/automata/blob/main/docs/implementation-plan.md#provider-scope).

## Configure a host

The complete configuration, certificate, spool, object-storage, network, and
startup procedure is in the
[runner bootstrap guide](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md).
Arch-specific kernel, cgroup, mount, and firewall requirements are in the
[Arch Linux host guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md).
