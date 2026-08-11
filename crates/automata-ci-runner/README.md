# `automata-runner`

The `automata-ci-runner` package builds the `automata-runner` command for Linux
and Windows execution hosts. It validates the host, opens an mTLS session to
the control plane, accepts fenced leases, runs jobs through the configured
sandbox provider, streams logs, and removes interrupted work.

`automata-runner run` selects exactly one host-compatible provider from its
configuration: rootless Podman on Linux or the experimental native provider
on Windows. The checked-in [Linux](config/runner.local.example.json) and
[Windows](config/runner.windows.example.json) examples show each selection.

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
finish. Scheduling sees the intersection of this live inventory and the
server's static registration ceiling.

Service containers are opt-in on Linux. `podman.service_proxy_image` must
contain one registry-qualified immutable reference of the form
`repository@sha256:<64 lowercase hex>` that is already in the runner's local
Podman store. Configuration adds the feature to the registration ceiling;
successful image inspection adds it to the live inventory. A missing value
disables the feature, and an invalid or unavailable configured image stops
startup. Mutable tags are rejected.

The Windows profile supports PowerShell and `cmd.exe` `run:` steps, plus an
optional explicitly configured standalone Python interpreter. Startup probes
each configured interpreter through a copied script before advertising the
profile. Every `uses:` action, including JavaScript, composite, local,
repository, and container actions, fails closed. Job containers, service
containers, administrator profiles, and parallel native jobs are unsupported.

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

Rootless Podman is a shared-kernel Linux boundary, and Windows native execution
is a trusted-host boundary. Neither is hostile multi-tenant isolation. Stronger
providers remain planned and are listed in the
[implementation plan](https://github.com/automata-ci/automata/blob/main/docs/implementation-plan.md#provider-scope).

## Configure a host

The complete configuration, certificate, spool, object-storage, network, and
startup procedure is in the
[runner bootstrap guide](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md).
Arch-specific kernel, cgroup, mount, and firewall requirements are in the
[Arch Linux host guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md).
