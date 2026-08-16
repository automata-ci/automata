# `automata-runner`

The provisioned `automata-runner` command targets Linux and macOS execution
hosts. Its only Windows execution provider uses Hyper-V-isolated containers;
the component is implemented, but it
remains a source-build path without a production enrollment flow, promoted
runner image, or physical-host release gate. On supported hosts the command
validates the host and opens an mTLS session to
the control plane, accepts fenced leases, runs jobs through the configured
sandbox provider, streams logs, and removes interrupted work.

For Unix file-backed TLS custody, the long-lived command also renews its runner
certificate before expiry through the dedicated mTLS authority. It recovers
partial file rotation durably, drains every old-identity task and connection,
then rebuilds the composition with the replacement identity. The macOS
Keychain and Windows environment-backed examples intentionally fail closed at
this boundary until native atomic custody adapters and physical-host
qualification exist; there is no manual or static-identity fallback.

`automata-runner run` selects exactly one host-compatible provider from its
configuration: rootless Podman or Kubernetes on Linux, fresh
Hyper-V-isolated Windows containers on Windows, or disposable
Virtualization.framework VMs on Apple Silicon macOS 15+. The checked-in
Linux host examples
([one](config/runner.local-1.example.json),
[two](config/runner.local-2.example.json), and
[three](config/runner.local-3.example.json)) select three independent
single-slot Podman processes; the
[Windows](config/runner.windows.example.json) and
[macOS](config/runner.macos.example.json) examples each remain one process and
one slot. The [configuration guide](config/README.md) documents Kubernetes,
Windows Hyper-V container isolation, and the macOS VM trust boundary.

No crates.io package or public runner archive has been published. Install a
reviewed source build for configuration work and diagnostics:

```console
cargo install --path crates/automata-ci-runner --locked
automata-runner --version
automata-runner doctor --json
```

That Cargo build is suitable for configuration inspection, host diagnostics,
and development of the Windows Hyper-V container path. On Linux, an ordinary
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
containers, administrator profiles, and host-network or host-filesystem policy
are unsupported.

Hosted Windows CI is currently disabled because Automata does not yet operate
Windows runners. Unit and injected-runtime provider tests do not constitute a
release gate; there is deliberately no Windows enrollment or static-registration
fallback. Do not deploy it until secure Windows credential publication, a
promoted digest-pinned Windows image, and the physical Windows end-to-end gate
are implemented together.

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

The Windows provider creates a fresh digest-pinned Windows container per job
with runtime isolation fixed to `hyperv`, networking fixed to `none`, no host
mounts, a writable disposable container root, and `ContainerUser` identity.
The absolute container-runtime executable is SHA-256 pinned before use; create
and attach inspect the realized isolation, image, labels, resources, entrypoint,
network mode, privilege, and mount set before accepting evidence. Arguments,
environment values, and file bytes cross a versioned framed guest protocol on
anonymous standard input rather than the runtime command line. Runner state,
control credentials, and object-store credentials remain on the host and are
never mounted into the job container. Memory and CPU limits are verified from
runtime inspection, and each workflow command is placed in a nested Job Object
for bounded process count and whole-tree termination.

This is an implemented fail-closed boundary, not yet a production claim: the
repository does not publish the required Windows image and does not run the
physical-host Hyper-V acceptance suite. See the
[Windows isolation plan](../../docs/platforms/windows.md) before preparing a
candidate host or image.

Rootless Podman is a shared-kernel Linux boundary, Windows uses a fresh Hyper-V
utility-VM-backed container per job, and macOS uses a disposable Apple VM per
job.
Additional provider work remains listed in the
[implementation plan](https://github.com/automata-ci/automata/blob/main/docs/implementation-plan.md#provider-scope).

## Repository action cache

Linux runners resolve credential-free repository actions pinned to one
canonical lowercase 40-character Git commit without consuming the GitHub REST
API quota. The first resolution downloads the immutable GitHub archive,
performs the normal bounded archive inspection, and publishes the verified
content-addressed bytes to the configured shared object store. Each runner also
retains a verified local copy through its built-in product action cache under
the private journal state root. A warm job
therefore reads local disk first and falls back to the shared object store; it
does not contact GitHub again.

Runner product schema 4 requires an explicit object-store trust policy.
`web_pki` uses platform roots; `private_ca` loads exactly one bounded CA through
an existing secure-input descriptor and installs it into an otherwise empty
root store. The PEM bytes must use canonical RFC 7468 64-column/LF encoding
with one terminal LF and no surrounding data; a present KeyUsage must include
`keyCertSign`. Private trust is HTTPS-only and never retries with Web PKI. The
runner, server, and image initializer must select the same endpoint trust,
bucket, and prefix for one installation.

The local archive cache is bounded to 256 entries, 512 MiB total, and 16 MiB per
compressed archive. Its sibling reference index is crash-durable and retains at
most 4,096 exact references. Both are recreated automatically and require no
separate operator configuration or migration. Removing either cache directory
only discards acceleration data; the next exact public resolution repopulates
it from shared storage or GitHub.

This fast path is deliberately narrower than general repository action
resolution. Tags, branches, noncanonical commit spellings, and every request
carrying a repository credential bypass both reference reuse and the public
archive cache. Private and internal actions therefore cannot inherit authority
from an older cache entry.

## Configure a host

The complete configuration, certificate, spool, object-storage, network, and
startup procedure is in the
[runner bootstrap guide](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md).
