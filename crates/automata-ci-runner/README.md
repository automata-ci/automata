# `automata-runner`

The `automata-ci-runner` package builds the `automata-runner` command for Linux
execution hosts. It validates the host, opens an mTLS session to the control
plane, accepts fenced leases, runs jobs through the configured sandbox
provider, streams logs, and removes interrupted work.

No crates.io package or public runner archive has been published. Install a
reviewed source build for configuration work and diagnostics:

```console
cargo install --path crates/automata-ci-runner --locked
automata-runner --version
automata-runner doctor --json
```

An ordinary Cargo build may be dynamically linked. It is not a valid
production probe payload, which must be a static executable that can run from a
one-file root filesystem. Do not start a production runner until an exact
reviewed static archive is available.

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

`automata-runner doctor --active` performs a similar ambient diagnostic using
the caller's `PATH` and scratch settings. Its success does not replace startup
admission, and its raw Podman output should stay inside the operator trust
domain.

## Environment profiles

Before advertising capacity, startup creates, inspects, and destroys a sandbox
for each configured environment profile. The observed provider, profile,
generation, and running state must match the configuration, and cleanup must
finish. Scheduling sees the intersection of this live inventory and the
server's static registration ceiling.

Service containers are opt-in. `podman.service_proxy_image` must contain one
registry-qualified immutable reference of the form
`repository@sha256:<64 lowercase hex>` that is already in the runner's local
Podman store. Configuration adds the feature to the registration ceiling;
successful image inspection adds it to the live inventory. A missing value
disables the feature, and an invalid or unavailable configured image stops
startup. Mutable tags are rejected.

## Job boundary

Workload environment values are sent to Podman through a bounded anonymous
standard-input document. They never enter the Podman host process environment.
Jobs do not receive runner state paths, the host Podman socket, control-plane
credentials, or provider-control credentials.

The current isolation provider is rootless Podman with a shared Linux kernel.
It is not a hostile multi-tenant boundary. Stronger providers remain planned
and are listed in the
[implementation plan](https://github.com/automata-ci/automata/blob/main/docs/implementation-plan.md#planned-provider-scope).

## Configure a host

The complete configuration, certificate, spool, object-storage, network, and
startup procedure is in the
[runner bootstrap guide](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md).
Arch-specific kernel, cgroup, mount, and firewall requirements are in the
[Arch Linux host guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md).
