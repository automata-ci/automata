# `automata-runner`

`automata-runner` executes Automata jobs on isolated worker hosts. The available
deployment path is a dedicated Linux host with rootless Podman; Automata's own
[public CI Checks](https://github.com/automata-ci/automata/commit/280cd4f9e685ac022c65a920ba24f4f019b0fd25/checks)
run on that path. The command validates the host, opens an mTLS session to
the control plane, accepts fenced leases, runs jobs through the configured
sandbox provider, streams logs, and removes interrupted work.

Other provider implementations have narrower status:

| Provider | Status |
| --- | --- |
| Rootless Podman on Linux | Available |
| Kubernetes on Linux | Experimental; cluster isolation must be attested by the operator |
| Fixed-relay Docker on Linux | Experimental local-installation foundation; no public stack lifecycle |
| Virtualization.framework on Apple Silicon | Component complete; physical-host production qualification remains |
| Hyper-V containers on Windows Server 2025 | Component complete; broker, image publication, and physical-host qualification remain |

For Unix file-backed TLS custody, the long-lived command also renews its runner
certificate before expiry through the dedicated mTLS authority. It recovers
partial file rotation durably, drains every old-identity task and connection,
then rebuilds the composition with the replacement identity. The checked-in
macOS configuration therefore keeps its renewable TLS identity in owner-only
files while retaining Keychain custody for stable secrets. Windows has no
deployment configuration until native atomic TLS custody and physical-host
qualification exist; there is no manual or static-identity fallback.

The sealed local installation additionally keeps an installation-authority-
bound chain of one-use recovery tokens. If that single Linux runner remains
down beyond its current leaf lifetime, `enroll` accepts only the exact expired
config/CA/chain/key/completion-receipt tuple and the control plane replaces the
certificate only after that exact leaf is expired in durable state and while
the same runner is offline with no live session. A distinct still-live leaf
left by an ambiguous renewal is revoked atomically. This does not broaden
ordinary enrollment or mTLS renewal, and it is unavailable to Windows broker
enrollment. The hidden local readiness probe observes the same completed tuple
through two stable no-follow snapshots without taking the runner-held TLS
writer flock.

`automata-runner run` selects exactly one host-compatible provider from its
configuration: rootless Podman, Kubernetes, or the evaluation-only fixed-relay
Docker provider on Linux; fresh Hyper-V-isolated Windows containers on Windows;
or disposable Virtualization.framework VMs on Apple Silicon macOS 15+. The checked-in
Linux host examples
([one](config/runner.local-1.example.json),
[two](config/runner.local-2.example.json), and
[three](config/runner.local-3.example.json)) select three independent
single-slot Podman processes. The
[macOS](config/runner.macos.example.json) example remains one process and
one slot. The [configuration guide](config/README.md) documents Kubernetes,
the unprovisioned Windows Hyper-V component boundary, and the macOS VM trust
boundary.

No public runner archive is published. Install a reviewed source build for
configuration inspection and host diagnostics:

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
has no supported `automata-runner run` or provider-admission path.

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

The Windows profile supports exact configured PowerShell and `cmd.exe` `run:`
steps, plus an optional standalone Python interpreter. Its image contract also
binds a Windows Server 2025 Server Core manifest and lock to provenance, SPDX
SBOM, patch, revocation, archive-tool, hash-helper, and Node-path evidence.
Those action artifacts are inputs to a future broker-owned materializer, not
runtime authority: JavaScript, composite, repository, local, and Node action
features remain absent from both enrollment and live inventories, even for an
externally promoted image. The executor rejects every Windows action step
before provider mutation and repeats the guard at direct execution.

Restricted-broker custody, Windows credential publication, and a
retained-file-identity materializer remain separate integration gates. Until
they are implemented together, Windows enrollment stays unavailable rather
than registering an action-ready runner. Missing, stale, tampered, revoked, or
mismatched image, tool, or runtime evidence fails closed. Docker actions, job
containers, service containers, administrator profiles, and host-network or
host-filesystem policy remain unsupported.

Hosted Windows CI is currently disabled because Automata does not yet operate
Windows runners. Unit and injected-runtime provider tests do not constitute a
release gate; there is deliberately no static-registration or unsigned-receipt
fallback. The source contract requires broker-owned enrollment-secret and
admission-receipt custody and writes neither secret to runner-local staging.
Do not deploy it until that broker is installed under its restricted service
identity, secure Windows credential publication is qualified, a
real externally promoted digest-pinned Windows image, and the physical Windows
end-to-end gate are implemented together. The checked-in candidate image
contract is deliberately unsigned and is not evidence of a built or tested
image.

The macOS profile supports Bash and `sh` `run:` steps, composite, repository,
and admitted local actions, plus explicitly configured Node action generations
and optional Python and PowerShell Core interpreters. Startup probes every
configured interpreter and Node runtime inside a cold-booted, digest-attested
macOS 15-or-newer ARM64 VM. Credential-free HTTP(S) routes for repository,
Results, and OIDC authorities cross only the exact allowlisted Virtio-socket
runtime proxy; the VM still has no general network device.
The provider is single-slot; Virtualization.framework fixes whole-vCPU and
memory size, and the guest applies the process ceiling before workflow traffic.
The VM has no virtual NIC or host directory share. It does not advertise
Docker actions, job containers, service containers, GPUs, or ephemeral-disk
capacity.
Template artifacts and mutable clones must live on one pinned, quota-bounded
APFS volume that is alone in a dedicated non-boot container.

## Job boundary

On Linux, workload environment values are sent to Podman through a bounded
anonymous standard-input document. They never enter the Podman host process
environment. Jobs do not receive runner state paths, the host Podman socket,
control-plane credentials, or provider-control credentials.

The evaluation-only local Docker provider similarly exposes no host socket,
bind, or per-job volume. Each job joins one deterministic internal front
network with a credential-free fixed-port proxy; only the proxy joins the exact
pre-provisioned Results transit, so jobs have no external DNS or public egress.
The provider uses one fixed private relay, an already-present immutable guest,
and the exact classic/config-ID or containerd/manifest-ID representation of the
daemon-local imported Results proxy. It verifies the exact daemon,
installation anchor, desired-plan-bound transit, running numeric Results target,
and peer proxies on every operation that consumes the shared route.
The rootful relay daemon must attest daemon-default user-namespace remapping
plus built-in seccomp and private cgroup namespaces, expose every required
memory/CPU/PID controller, have AppArmor and SELinux disabled, and exactly match
the architecture already advertised by the runner inventory. The trusted fixed
relay service uses `userns_mode: host` only for bounded root-owned-socket
bootstrap; untrusted job containers omit that override and inherit daemon
remapping. Its trusted relay must run Docker Engine 28 or newer with API 1.48 or
newer. Its trusted configuration must leave daemon-wide `log-opts`, bridge
`default-network-opts`, and `default-ulimits` empty because the bounded Engine
facts do not fully expose those settings. Realized drift fails closed after
create. Rootless Docker is not qualified, and each sandbox separately proves one
nonzero host UID/GID mapping that covers its fixed identities. The guest's
protected client lives in tmpfs. Its administrator contract is an attenuated
UID 0 inside that remapped namespace with every Linux capability set empty; it
does not promise `chown`, identity switching, or other POSIX capabilities.
Durable host state owns execution replay; an ambiguous committed invocation
causes the exact sandbox to be destroyed rather than restarted.

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

Credential-free repository actions pinned to one canonical lowercase
40-character Git commit are cached without consuming the GitHub REST API quota.
The first resolution downloads the immutable GitHub archive, performs the
normal bounded archive inspection, and publishes two write-once records to the
configured shared object store: the content-addressed archive and a small
reference manifest keyed by provider, repository, commit, and action subpath.
Both control-plane activation and every runner consult that installation-wide
manifest before GitHub. Once both records exist, any replica and any runner can
prepare and execute the action while GitHub's API, web, and codeload origins are
unavailable.

Unix runners additionally retain a verified local copy and reference index
under the private journal state root. A warm runner reads local disk first and
falls back to the shared manifest and archive. This local tier can keep that
runner warm during a simultaneous object-store interruption; another runner
requires the shared store.

Runner product schema 8 requires an explicit object-store trust policy.
`web_pki` uses platform roots; `private_ca` loads exactly one bounded CA through
an existing secure-input descriptor and installs it into an otherwise empty
root store. The PEM bytes must use canonical RFC 7468 64-column/LF encoding
with one terminal LF and no surrounding data; a present KeyUsage must include
`keyCertSign`. Private trust is HTTPS-only and never retries with Web PKI. The
runner, server, and image initializer must select the same endpoint trust,
bucket, and prefix for one installation.

The shared reference manifests and action archives are persistent installation
state and are not subject to the runner-local eviction policy. The local archive
cache is bounded to 256 entries, 512 MiB total, and 16 MiB per compressed
archive. Its sibling reference index is crash-durable and retains at most 4,096
exact references. Both local directories are recreated automatically and
require no separate operator configuration. Removing either local directory
only discards acceleration data; the next exact public resolution repopulates
it from shared storage without GitHub when the shared manifest is warm.

An archive object left by a release older than the shared-manifest schema is not
by itself a warm entry because its reference cannot be discovered from a
content digest. During rollout, run the pinned action set successfully once on
the new version before relying on GitHub-outage operation. A warm-entry check
must preserve both `actions/references/v1/sha256/*.json` and the referenced
`actions/v1/sha256/*.tar.gz` objects. Uncached actions fail closed during an
outage; Automata never substitutes a stale tag or branch.

This fast path is deliberately narrower than general repository action
resolution. Tags, branches, noncanonical commit spellings, and every request
carrying a repository credential bypass both reference reuse and the public
archive cache. Private and internal actions therefore cannot inherit authority
from an older cache entry.

## Configure a host

The complete configuration, certificate, spool, object-storage, network, and
startup procedure is in the
[runner bootstrap guide](https://github.com/automata-ci/automata/blob/main/crates/automata-ci-runner/config/README.md).
