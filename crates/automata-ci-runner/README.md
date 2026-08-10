# Automata Runner

`automata-ci-runner` installs the `automata-runner` executable for Automata
execution hosts.

`automata-runner run` fails before starting any listener or control-plane
session unless its passive nftables-module check and active local Podman
lifecycle both succeed. Production rejects an effective UID of zero and then
uses the exact configured Podman binary; a cleared process environment
containing the configured `HOME`, `PATH`, `XDG_RUNTIME_DIR`, and `TMPDIR`; a
private probe root below the configured Podman state root; and the configured
network policy. It does not invoke `podman info`. `private_egress` requires a
non-internal network, while `disabled` requires Podman's `--internal` policy.
Workload environment values never enter the Podman host process environment;
they cross only a bounded anonymous `/dev/stdin` environment document.

The initial lifecycle checks that the running executable is a static ELF and
copies its exact bytes as the only file in a private one-file rootfs. Podman
runs that lowerdir as `--rootfs <path>:O`, so runtime-created paths remain in
container-owned overlay state rather than changing the source. Admission
verifies the source binding and bytes before and after start, the created
network's identity and policy, exclusive container attachment, loopback HTTP
readiness, exact resource ownership, and exact-ID absence after deletion. It
removes the source rootfs only after container absence is confirmed.

Before building its advertised inventory, startup separately creates,
inspects, and destroys a sandbox for every configured environment profile
through the exact provider policy. It requires matching
provider/profile/generation/running evidence and complete cleanup. This proves
that the configured digest-pinned image launches through that provider path;
it is not supply-chain attestation or a complete hosted-image conformance
suite.

`automata-runner doctor` is an ambient `PrivateEgress` diagnostic: its Podman
binary, environment, and scratch settings are not the production configuration
gate, and its output can include raw Podman diagnostics. Production accepts
only exact root-owned, non-symlink Podman, conmon, runtime, init, cleanup, and
seccomp inputs plus a closed helper directory and root-controlled,
non-group/world-writable ancestry. Podman process and state
directories must be non-symlink, mode-0700 directories owned by the runner
account beneath root- or runner-controlled ancestry. Ambient containers/Docker
credential fallback paths under the dedicated runner home must be absent or
exactly empty, as must Podman 6's root-controlled ambient registry-client
certificate trees. Startup snapshots this metadata before the probe; the
active probe, every runner-initiated Podman spawn, and every job Docker-service
request revalidate that same snapshot before use. Podman/conmon's internally
delegated stopped-container cleanup re-exec inherits the admitted environment
but remains inside the trusted administrator/runtime boundary rather than
passing through the runner's guard. This is filesystem identity and ownership
evidence, not a byte attestation. The hooks and CDI directories must remain
empty, and runner jobs never receive these private host paths.

Production requires Linux 6.4 or newer and one dedicated `tmpfs,noswap` mount
whose exact mountpoint is the configured `XDG_RUNTIME_DIR`. The Podman state
root is fixed at `XDG_RUNTIME_DIR/automata-ci-podman/state`, so graph,
workspace, generated configuration, shared run/tmp, and dynamic job-engine
run/tmp state all remain on that one mount. Startup rejects shared ancestors,
bind aliases, and every child mount, captures the exact mount record, and
irreversibly quarantines Podman use after any later drift. This proof does not
advertise ephemeral-disk capacity; both configured capacities remain zero.

Service-container port publication is opt-in through
`podman.service_proxy_image`. The value must be one registry-qualified
`repository@sha256:<64 lowercase hex>` reference that is already present in the
runner's rootless Podman store. The `capabilities` command includes the feature
in the durable registration ceiling only when that immutable pin is configured.
Startup then configures the provider with that exact value and requires local
image inspection to succeed before the live session observes the feature. The
control plane intersects registered and observed abilities, so an unverified
feature cannot become schedulable. An absent value omits the registered and
observed feature; an unavailable or mismatched configured image aborts startup.
There is no mutable tag fallback.

After admission, the runner accepts fenced leases, executes jobs through the
configured isolation provider, streams logs, and reconciles interrupted work.

No crates.io release is published yet. From the root of a reviewed source
checkout, install and inspect the runner with:

```console
cargo install --path crates/automata-ci-runner --locked
automata-runner --version
automata-runner doctor --json
```

That Cargo build is suitable for configuration inspection and host diagnostics.
An ordinary dynamically linked build cannot serve as the production command's
one-file rootfs payload. No current public artifact satisfies that production
boundary. After an exact reviewed release is published, use its statically
linked archive before expecting `automata-runner run` to open a control-plane
session.

Automata remains in bootstrap development and is not production-ready.
Start with the
[installation guide](https://github.com/automata-ci/automata/blob/main/docs/getting-started.md)
and read the
[runner bootstrap guide](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md)
before connecting a host.
