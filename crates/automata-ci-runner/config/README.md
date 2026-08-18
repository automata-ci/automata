# Local runner bootstrap

This directory contains three checked-in Linux Podman instance configurations
and one isolated macOS VM configuration for `automata-runner`.
[`runner.local-1.example.json`](runner.local-1.example.json),
[`runner.local-2.example.json`](runner.local-2.example.json), and
[`runner.local-3.example.json`](runner.local-3.example.json) select the same
locked Ubuntu 24.04 profile while keeping every host-local identity, state
path, credential path, runtime mount, and metrics port distinct.
[`runner.macos.example.json`](runner.macos.example.json)
selects the Virtualization.framework provider on Apple Silicon macOS 15+.
Exactly one of the `podman`, `local_docker`, `kubernetes`, `windows_hyperv`,
and `macos_virtualization` provider objects may be configured.

The Linux examples' local bootstrap digest is not an official promoted profile;
follow the
[profile publication guide](https://github.com/automata-ci/automata/blob/main/images/github-hosted-ubuntu-24.04-x64/README.md)
before trusting a protected-main candidate.

Product schema v7 accepts exactly one sandbox provider. Host runners use the
top-level `podman` object and require `state.podman`. Kubernetes and local
Docker runners omit every provider-specific state root and use a top-level
`kubernetes` or `local_docker` object. Windows and macOS runners use their
matching provider name in both locations. All non-v7 schemas,
`windows_native`, and the removed macOS native key are rejected, not migrated.
The Kubernetes runner loads credentials through standard in-cluster or ambient
kubeconfig discovery; the JSON remains secret-free.

`object_store.tls_trust` is mandatory and has exactly one of two current
shapes: `{ "mode": "web_pki" }`, or `{ "mode": "private_ca",
"certificate_source": { ... } }`. The private-CA source uses the same bounded
file, environment, or macOS Keychain descriptor contract as other runner
secure inputs and must contain exactly one canonically encoded RFC 7468 X.509
CA certificate: 64-column Base64, LF line endings, one terminal LF, no
preamble/trailing bytes, and `keyCertSign` when KeyUsage is present.
Private mode installs that certificate into an otherwise empty root store; it
never merges or retries with platform roots. `loopback_development: true` is
valid only for a literal-loopback HTTP endpoint with `web_pki` selected; HTTPS
requires it to be false, and private-CA trust always requires HTTPS.

The Podman BuildKit surface is a separate, default-off opt-in. Configure it
only with the attempt-scoped Docker API and one locally preloaded, untagged
digest pin:

```json
{
  "podman": {
    "job_container_engine": "attempt_scoped_docker_api",
    "buildkit_runtime_image": "registry.example.invalid/buildkit/runtime@sha256:7777777777777777777777777777777777777777777777777777777777777777"
  }
}
```

Omit the field or set it to `null` to keep BuildKit disabled. Startup refuses
a tag, a tagged digest, a missing local image, a mismatched inspected digest,
or a failed no-network `buildkitd --version` probe. Only after the provider has
passed that immutable-image gate does the runner register
`automata.core/buildkit@v1`; configured inventory alone is not sufficient.
Server-side runtime-policy mappings used by Buildx jobs must request that
container feature explicitly so those jobs cannot be leased to a runner where
the opt-in is absent. Action names are not inferred as scheduling requirements.

The admitted surface targets unchanged default `docker/setup-buildx-action`
`docker-container` operation and `docker/build-push-action`, including
CacheService v2 traffic carried through the BuildKit session. It does not
expose a host Podman/Docker socket or registry credentials. Custom images,
driver resource/network options, host mounts/devices, additional privileged
containers, custom BuildKit configuration, and cross-attempt objects are
rejected. Because Buildx and Podman request shapes evolve, validate the exact
deployed versions with the opt-in live rootless fixture before enabling this
field; an unreviewed future Docker create field fails closed.

The evaluation-only local Docker selection has this closed shape:

```json
{
  "local_docker": {
    "installation_name": "evaluation",
    "installation_id": "6e561f8b-9098-418d-b573-d82f5c73006e",
    "guest_image": "registry.example/automata/sandbox-guest@sha256:<64 hex digits>",
    "results_transport": {
      "proxy_image": {
        "reference": "automata.local/automata-ci-service-proxy:manifest-<64 lowercase hex digits>",
        "config_image_id": "sha256:<64 lowercase hex digits>",
        "manifest_image_id": "sha256:<64 lowercase hex digits>"
      },
      "plan_sha256": "<64 lowercase hex digits>",
      "transit_network_id": "<64 lowercase hex digits>",
      "results_container_id": "<64 lowercase hex digits>",
      "results_address": "10.91.0.2"
    }
  }
}
```

It is available only on Linux and selects no configurable Docker endpoint. The
runner connects through the fixed private relay, verifies the exact daemon and
installation anchor, and requires the immutable guest and imported
Results-proxy images to be already present. The supplied proxy tag must be the
one derived from its manifest ID. Classic Docker must expose that sole tag with
the config ID and no repository digest; the containerd image store must expose
the manifest ID with that sole tag and the sole canonical
repository-at-manifest digest. The Results object also binds the desired-plan
digest, exact Engine IDs, and one canonical private numeric address; ports and
topology are not configurable. The executor must use `private_egress`, a writable container root,
administrator identity, at least 256 MiB of memory, one whole CPU, and three
processes. `max_parallel_jobs` is bounded to 256 and maps directly to durable
one-based slot custody. Every environment must launch a container and use POSIX
runner and workspace paths outside `/automata` and `/automata-control`. Jobs
receive no host bind, engine socket, or per-job volume. Their only network path
is the fixed Results proxy, with no external DNS or public egress. Exited
containers are never restarted. Durable host state owns invocation replay;
ambiguity after an invocation commit fails closed until the exact sandbox is
destroyed and proven absent.

The relay daemon must be rootful Docker configured with daemon-default
user-namespace remapping. `/info.SecurityOptions` must contain exactly
`name=userns`, `name=seccomp,profile=builtin`, and `name=cgroupns`, with
`name=no-new-privileges` optionally present. Rootless, AppArmor, SELinux, and
unknown security options are rejected. `/info` must report memory, swap, CPU
CFS period/quota, and PID-limit enforcement. Every job also proves that PID 1 has one
canonical UID range and one canonical GID range, each starting at container ID
0, mapping to a nonzero host ID, and covering container IDs through 65533.
The relay architecture must exactly equal the architecture in the already
validated runner inventory. Rootless Docker's usual multi-range map is
intentionally unsupported. The
administrator identity is UID 0 only inside that boundary with every Linux
capability set empty under `no_new_privileges` and built-in seccomp; it does not
provide `chown`, identity switching, or other POSIX capabilities.
The relay must run Docker Engine 28 or newer with API 1.48 and have no daemon
`default-ulimits`; that setting is a trusted relay prerequisite. Any
daemon-injected ulimit still fails exact post-create inspection and can be
removed through the separate custody-only cleanup path when the front-network
custody remains exact. Container-runtime/image or shared-transit damage does not
by itself block that container cleanup; exact front-network drift blocks destroy,
and a foreign endpoint can leave the emptied front network for operator recovery.
Guest, job, and Results-proxy images must not declare volumes, exposed ports, or
a healthcheck. The externally provisioned transit must be an internal isolated
private IPv4 bridge with a first-host gateway and a `/23`-or-wider prefix. Its
exact Results-transport-schema-2 labels bind the installation ID, selector key,
Compose project, resource kind, and configured desired-plan digest. A future
lifecycle may create that network and declare it external to Compose; the
runner neither creates nor deletes it.

A Kubernetes selection has this provider-specific shape:

```json
{
  "kubernetes": {
    "namespace": "automata-runners",
    "guest_image": "registry.example/automata/sandbox-guest@sha256:<64 hex digits>",
    "network_isolation_verified": true,
    "ephemeral_storage_enforcement_verified": true,
    "process_limit_enforcement": 4096,
    "gpu_resource_name": "nvidia.com/gpu",
    "node_selector": { "automata.dev/pool": "jobs" },
    "runtime_class_name": "kata"
  }
}
```

`executor.network` must be `disabled`, `executor.privilege` must be
`unprivileged`, and `process_limit_enforcement` must equal the executor PID
limit. A dedicated non-empty node selector is mandatory. Nonzero ephemeral
storage or GPU inventory is admitted only with its corresponding verified
enforcement field or resource mapping. The runner creates the authenticated
client, exercises every configured environment through create, inspect,
attach, configured-tool execution, and destroy, and registers only after that
evidence succeeds. These assertions do not
replace cluster-side CNI, node-local traffic, admission-policy, RuntimeClass,
or kubelet verification.

> [!WARNING]
> Initial enrollment and automatic certificate renewal are qualified only for
> Unix file-backed TLS custody. `automata-runner run` renews that identity
> before expiry, durably recovers an interrupted rotation, drains the old
> runner generation, and reloads the new files itself. The macOS example uses
> that exact file-backed TLS contract. The Windows source path requires the
> restricted broker for active profile admission, opaque receipt and
> enrollment-secret custody, and final credential publication. Windows has no
> deployment example until native atomic renewal custody, external image
> promotion, authenticated placement, and the physical-host gate are qualified.
> There is no local-secret, manual-registration, or alternate-protocol fallback.

Configure the control plane with the
[`automata` reference](https://github.com/automata-ci/automata/blob/main/crates/automata-ci/README.md),
then provision the runner host according to the requirements below.

## Windows Hyper-V-isolated component boundary

The internal Windows product fixture is an unprovisionable source-build path for the implemented
Hyper-V container provider. It requires one absolute SHA-256-pinned container
runtime executable, one immutable Windows image reference, and the exact guest
agent path baked into that image. Every job receives a fresh container with
`--isolation hyperv`, no network, no host mounts, a writable disposable root,
and `ContainerUser` identity. Configuration rejects every host-network,
host-filesystem, administrator, native-process, process-isolated-container, or
mutable-image alternative.

`windows_hyperv.image_contract` also names bounded, no-follow files for the
exact Windows Server 2025 Server Core manifest, image lock, and typed reference
records for provenance, SPDX SBOM, patch-report, and revocation artifacts. Each
reference record has the Automata reference-record media type and binds the
native artifact's exact media type and digest; the verifier never treats a
reference record as an in-toto or SPDX document. The manifest and lock digests
are pinned in runner configuration. All evidence must bind the configured profile,
base image, output image, guest path, workspace, and exact x86-64 Hyper-V,
offline, unprivileged policy. The manifest's tool entries must exactly match
the configured `pwsh.exe`, `powershell.exe`, `cmd.exe`, `tar.exe`,
`automata-sha256.exe`, and each configured Node 12/16/20/24 executable. Missing,
malformed, revoked, substituted, or digest-mismatched material stops startup.

The resulting inventory advertises
`automata.core/windows-hyperv-container@v1` only for `windows_hyperv`. GitHub
Windows projection requires that exact launch capability together with
`IsolationLevel::VirtualMachine`; a generic VM advertisement, including the
macOS VM provider, cannot match. Registered and live-observed capabilities are
intersected before scheduler matching, and the match is repeated before a
placement can become a lease.

Without an external promotion envelope the verified candidate's durable
inventory contains only
PowerShell and `cmd.exe` shell steps plus command files, with optional support
for one absolute standalone Python interpreter. A production image may enable
JavaScript, composite, repository, and local-action capabilities only after a
canonical Ed25519-signed promotion payload accepts all evidence digests and
revocation generation. Startup exercises every configured shell, archive,
hash, Node, and optional Python executable through a copied probe in one fresh
container. The required Windows enrollment adapter must run the same exact
profile/tool contract and retain a short-lived authenticated receipt under an
opaque broker-custody handle. The request binds the shared probe-contract schema
and digest, and the supplied helper executes the same lifecycle, argv, and
output checks as startup. This component supplies that request/receipt port;
the restricted-broker caller and credential-publication integration remain a
separate deployment gate. Once composed, the enrollment request must use the
broker-attested ordered host-input set (configuration, executable, manifest,
lock, evidence records, and promotion envelope), including protected DACL,
owner, non-reparse, stable file/volume identity, and exact digest proof, and the
receipt's exact capability set and a staged retry must resolve the identical
receipt digest and binding. Missing, stale, expired, or tampered custody fails
closed. The
`capabilities` command remains a passive shell-only diagnostic and cannot mint
action authority. Startup independently repeats the probes before opening a
runtime session, and action/Node features remain schedulable only when the
registered and live-observed sets agree. There is no `PATH` or Node-generation
fallback. Docker actions, job
containers, service containers, and active Podman doctor checks remain
unsupported. The host state root contains provider ownership and recovery
metadata only; no runner state or credential path is mounted into a job
container.

The checked-in runtime digest and the files under
[`images/windows-server-2025-hyperv-candidate`](../../../images/windows-server-2025-hyperv-candidate/README.md)
are explicit candidate fixtures, not promoted artifacts. They exercise the
contract and verifier interfaces but do not claim that an image was built,
signed, scanned, patched, or run on physical Windows hardware. No promotion
envelope is checked in. Unit and injected-runtime tests do not prove HCS/HCN
behavior, patch compatibility, or nested Job Object enforcement. Keep this
runner out of production until the external image pipeline supplies real
evidence and signature and the physical-host acceptance gate is published. The
exact launch requirement also does not by itself satisfy every AUTH-02 and
broker acceptance requirement.

The internal
[`runner.windows.product.json`](../tests/fixtures/runner.windows.product.json)
exists only for schema and component testing. It is not a deployment example
and must not be copied into production. Follow the
[Windows isolation plan](../../../docs/platforms/windows.md); no supported
`automata-runner run` Windows path is published yet.

## macOS virtual-machine example

The macOS example accepts only a disposable Virtualization.framework VM on
Apple Silicon macOS 15 or newer. A digest- and signature-pinned helper APFS
clones a sealed macOS template for each job, configures exact whole vCPUs and
memory, omits the virtual NIC and every host-directory share, and communicates
through a versioned Virtio socket protocol. A dedicated non-admin guest account
receives the process ceiling. Every action, job or service container, parallel
slot, GPU claim, fractional CPU, nonzero ephemeral-disk capacity, and policy
other than disabled-network/writable-guest-root/unprivileged fails closed.
`storage_volume_uuid` and `storage_quota_bytes` pin the exact roleless APFS
volume used for both immutable template artifacts and mutable clones. It must be
the sole volume in a dedicated non-boot container; startup rejects a shared
startup container, a missing/different quota, or insufficient clone headroom.

The `macos_keychain` secret source selects one exact generic-password item by
`service` and `account` in the account's default Keychain. Reads are serialized,
bounded, and performed with authentication UI disabled; missing, duplicate,
locked, interactive-only, or malformed values stop startup without exposing
secret bytes. Pre-provision item access for the exact reviewed
`automata-runner` binary and verify it while logged in as the service account.
Do not pass secret values on a command line or store them in the JSON.

The renewable TLS roots, certificate chain, and private key use the example's
three owner-only regular files under `~/Library/Application Support/Automata/tls`.
Provision that directory and those files for the dedicated service account;
certificate renewal durably rotates only this file-backed identity. Keychain
continues to hold the stable spool and object-store secrets.

Copy [`runner.macos.example.json`](runner.macos.example.json) to an ignored
host-specific path, replace every helper/template pin plus the identity and
endpoints, provision its owner-only state roots, TLS files, and Keychain items, then start
`automata-runner run --config /absolute/path/to/runner.macos.json`. Template
construction, signing, isolation details, and the physical-host acceptance gate
are documented in the [macOS guide](../../../docs/platforms/macos.md).

The remainder of this guide describes the three-process rootless-Podman Linux
host. macOS uses one runner process with one slot; Windows has no supported
deployment or `automata-runner run` path.

## What the Linux example assumes

The three `runner.local-N.example.json` files assume:

- three dedicated runner accounts with UID/GID pairs 1001 through 1003 and
  non-overlapping subordinate ID ranges;
- durable journal and spool state below `/var/lib/automata-runner`;
- Linux 6.4 or newer with three dedicated, bounded `tmpfs,noswap` mounts at
  `/run/automata_runner_1` through `/run/automata_runner_3`;
- dynamically enrolled TLS leaves/keys and operator-provisioned spool keys below
  each `/etc/automata-runner/instances/N` boundary;
- a control-plane runner listener reachable at the configured HTTPS URL;
- the same RustFS bucket and prefix used by the server;
- the pinned Ubuntu 24.04 OCI image is available by its exact digest; and
- the isolated GitHub emulator is started by the integration harness on the
  exact mapped origin configured below.

Copy all three examples to ignored, host-specific paths. Update, at minimum,
the three `runner_id` values, `control_endpoint`, account paths, runtime UID,
resources, and GitHub context origins. Keep the server, API, and GraphQL
origins identical and change their port together with the emulator mapping.
Do not edit the checked-in examples with machine credentials and never reuse
an ID, client key, or spool key between instances.

`control_endpoint` is also the only managed-secret delivery origin. Values are
fetched after lease acceptance through its direct mTLS connection, retained
only in bounded execution-local zeroizing custody, registered with the output
masker, and acknowledged separately before user work. No runner-wide secret
cache or durable secret spool is configured.

The checked-in dogfood host starts exactly three `automata-runner` processes,
each with a distinct identity and `max_parallel_jobs: 1`. Each process can
consume its complete `resources_per_job` ceiling, so full occupancy requires
at least 12,000 CPU millicores, 48 GiB of job memory, and 12,288 job PIDs, plus
runner, Podman, and operating-system overhead. Do not increase a runner's slot
count. Review the aggregate bounds before adapting the examples to a smaller
host and change all three configurations plus the systemd cgroup limits
together.

Both `ephemeral_disk_bytes` fields must remain `0`. The current Podman adapter
does not provide a proven per-job storage quota, so the runner deliberately
advertises no ephemeral-disk capacity and rejects a nonzero configured value.
Jobs that require nonzero ephemeral disk will not match this runner.

Each configured `podman.runtime_directory` is its process's exact mountpoint,
not a directory on a shared `/run` or `/run/user/<uid>` tmpfs. Each checked-in
layout requires `state.podman` to be exactly
`podman.runtime_directory/automata-ci-podman/state`; separate `/var/lib`
Podman state, sibling state, bind mounts, and child mounts fail closed. Mount
each runtime before starting its runner, give it exact mode 0700 and the runner
UID/GID, include finite `size=` and `nr_inodes=` operator bounds, and use the
kernel's exact `noswap` option. An equivalent instance-one mount is:

```console
sudo install -d -m 0700 -o automata-runner-1 -g automata-runner-1 \
  /run/automata_runner_1
sudo mount -t tmpfs automata-runner-runtime-1 /run/automata_runner_1 \
  -o nodev,nosuid,noswap,size=20G,nr_inodes=349525,mode=0700,uid=1001,gid=1001
```

The service manager must create and order each mount before its runner starts;
the manual command is only a development illustration. Do not bind any runtime
tmpfs elsewhere, share it between processes, or mount anything below it. Linux
before 6.4 cannot provide this contract because tmpfs did not support `noswap`.

## 1. Check the host

The passive doctor is safe to run first:

```console
automata-runner doctor --server http://127.0.0.1:8080 --json
```

On a prepared Linux host, the active probe creates uniquely named temporary
rootless Podman resources, checks networking and cleanup, then removes them:

```console
automata-runner doctor --active --server http://127.0.0.1:8080 --json
```

Do not use `--active` until the host guide's kernel, cgroup, subuid/subgid, and
Netavark/nftables prerequisites are satisfied.

The doctor is an ambient operator diagnostic: it resolves `podman` from its own
`PATH`, inherits its diagnostic process context, uses its diagnostic scratch
settings, and exercises a diagnostic `PrivateEgress` policy rather than the
JSON configuration. Its structured output can include raw Podman failure
detail, so keep it in the operator trust domain. It is useful for host
preparation, but it is not a substitute for the production configuration gate.

The production `run` command independently repeats passive and active admission
before it starts any listener or opens a control-plane session. It runs the
exact absolute Podman binary from the JSON configuration after clearing the
ambient environment and installing one fixed Podman environment. That includes
the configured `HOME`, one approved helper directory as the entire `PATH`, the
required `XDG_RUNTIME_DIR`, private `TMPDIR`, exact generated containers,
storage, registries, signature-policy, mounts, and auth files, disabled systemd
health wrappers, and an unreachable private session-bus address. It requires a
nonzero effective UID and does not invoke `podman info`. Its mode-0700
`active-probe` parent is beneath the configured Podman state root; each
lifecycle places the exact static runner bytes in one mode-0711 rootfs child as
its sole mode-0555 payload. Podman runs that source as `--rootfs <path>:O`,
keeping runtime changes in container-owned overlay state. Podman
process-temporary files use the same state boundary.

Admission applies the exact `executor.network` policy. `private_egress` creates
a non-internal Podman network; `disabled` adds `--internal`. The probe inspects
the created network's identity and internal-policy flag, requires the container
to be attached exclusively to that exact network, verifies the loopback
readiness endpoint, checks the rootfs name, inode, mode, length, and full bytes
before and after start, verifies ownership before cleanup, and confirms that
the exact owned container and network IDs are absent after deletion. No probe
image is built or pulled. The source rootfs is unlinked through retained
`NOFOLLOW` descriptors only after container absence is confirmed; an
unconfirmed container keeps its lowerdir rather than invalidating storage that
may still reference it. Workload variables never extend the Podman host
environment: exec and service-container values use only a bounded anonymous
`--env-file /dev/stdin` document, and provider-control namespaces fail closed.

Treat the configured Podman, conmon, OCI runtime, catatonit, seccomp profile,
the fixed `/usr/bin/rm` user-namespace cleanup program, and approved helper
directory as administrator-provisioned host inputs. Rootless pause handling
also admits the exact `/usr/bin/catatonit` binary and requires Podman's earlier
compiled `/usr/libexec/podman/catatonit` location to remain absent.
Executable paths must resolve to root-owned, executable, non-symlink regular
files with no group/world write permission; the seccomp profile has the same
ownership and immutability policy without the executable-bit requirement.
Every lexical and canonical ancestor is checked. Symlink directory components
such as `/bin` are resolved, and both the link and target ancestry must satisfy
the trust policy.

`approved_helper_directory` must be one real, canonical, root-owned,
group/world-non-writable, runner-traversable directory whose literal path ends
in `/usr/sbin`. It is the entire Podman `PATH`; the suffix prevents
containers/common from appending the host `/usr/sbin`. It must contain exactly
the seven names `newuidmap`, `newgidmap`, `nft`, `netavark`, `aardvark-dns`,
`pasta`, and `rootlessport`. Each may be a root-owned symlink to, or a direct
root-owned copy of, the reviewed executable. No other entry is accepted. In
particular, do not include `systemd-run`: Netavark then starts the pinned
`aardvark-dns` directly and retains DNS without depending on a mutable user
D-Bus service.

The configured home and required runtime directory, plus the derived `TMPDIR`,
`active-probe`, generated-system-config, `empty-hooks`, and `empty-cdi`
directories, must be normalized non-symlink directories owned by the effective
runner UID with exact mode 0700. Their ancestry may contain only root- or
runner-owned directories without group/world write permission. The transient
state-root `podman-graph` and the per-boot
`XDG_RUNTIME_DIR/automata-ci-podman/shared-run` roots are private,
descriptor-validated engine roots. Generated configuration files are exact
mode-0600, single-link files and are compared byte-for-byte before every
runner-initiated Podman spawn; hooks and CDI directories must remain exactly
empty. Every runner-initiated launch also requires
`/etc/containers/podman_preexec_hooks.txt` to be absent and accepts
`/proc/sys/crypto/fips_enabled` only when absent or exactly `0` followed by a
newline. A FIPS-enabled host is outside this current provider contract because
Podman would add implicit host mounts.

The configured `HOME` belongs only to the dedicated runner UID. To prevent
containers/image authentication fallback, `$HOME/.config/containers` and
`$HOME/.docker` must each be absent or an exactly empty mode-0700 directory,
and `$HOME/.dockercfg` must be absent. The generated empty `REGISTRY_AUTH_FILE`
does not replace these gates. Podman 6's ambient registry-certificate trees
under `/etc/containers`, `/usr/share/containers`, and `/etc/docker` must also
be absent or exactly empty and root-controlled, including the rootless-UID
variants. This prevents Docker-compatible builds from inheriting host client
keys or registry-specific extra CAs while retaining the standard system CA
roots.

Startup captures filesystem identities and metadata before probing and
embeds that exact immutable snapshot in the production Podman launch boundary.
It also captures the configured runtime mount's exact Linux mount ID, device,
decoded root and mountpoint, mount options, propagation fields, filesystem,
source, and superblock options from bounded `/proc/thread-self/mountinfo`
snapshots. The mount record must have root `/`, the configured runtime path as
its exact mountpoint, `tmpfs` as its filesystem, and one exact `noswap` option.
Any same-device alias or mount at/below the runtime path is rejected, including
dynamic job-engine run/tmp children.
The active probe, every provider/endpoint process, the job Docker service
spawn, and every later authorized Docker-service request revalidate it before
Podman use. The first drift permanently quarantines the shared provider trust
handle even if the host later restores the original mount. Mutable private
roots must retain their device, inode, mode, UID,
and GID; immutable administrator inputs also retain size and
modification/change times. Generated configuration bytes are validated
separately. This contract assumes a
dedicated runner account whose host UID is not shared with hostile processes:
Podman necessarily reopens euid-owned configuration and mutable graph paths by
name after the guard, so the guard detects stale or tampered state but does not
claim resistance to a malicious same-UID process racing that reopen. Job
sandboxes never mount these private host roots. `env_clear` prevents ambient
variable inheritance; it does not replace the filesystem checks.

Podman may ask conmon to run Podman's own stopped-container cleanup command
after a container exits. That Podman-internal re-exec inherits the admitted
fixed environment and engine identity, but it does not pass back through the
runner's pre-spawn guard. It is part of the trusted administrator/runtime
boundary, not a runner-initiated launch. Intercepting it would require a
reviewed Podman wrapper or patched runtime. The runner still revalidates every
launch and Docker API request that it initiates directly.

Only a fully static runner distribution can serve as the one-file rootfs
payload; a normal dynamically linked development build may diagnose the host
but intentionally cannot start a production runner session.

### Optional service-container helper

The optional `podman.service_proxy_image` field enables namespace-local TCP and
UDP service port mappings. It accepts only a registry-qualified immutable
reference in the form `registry/repository@sha256:` followed by exactly 64
lowercase hexadecimal characters. Tags, tag-plus-digest ambiguity, uppercase
digests, whitespace, and unqualified names fail configuration validation with
a sanitized error.

Leave the field absent unless an operator has published or mirrored a reviewed
candidate and preloaded that exact digest into this runner account's Podman
store. Configuration authorizes the feature only in the durable registration
ceiling emitted by `automata-runner capabilities`; it is not live proof. After
the normal active network probe, provider construction inspects the exact local
image, and only that successfully verified provider includes the feature in the
session advertisement. The control plane intersects both values before
scheduling. A missing or different image therefore fails startup instead of
turning configured authority into an observed ability, and the runner never
retries a mutable tag. The checked-in local example intentionally omits the
field because the repository does not hardcode an unpublished or machine-local
candidate digest.

## 2. Provision runner inputs and enroll identity

Before enrollment, each instance `N` expects:

- its reviewed JSON configuration installed at
  `/etc/automata-runner/instances/N/runner.json`, root-owned with mode `0640`,
  grouped to that runner's service group, and containing the final identity
  and paths;
- an empty `/etc/automata-runner/instances/N/tls` directory with mode `0700`,
  owned by the exact `automata-runner-N` account that will run the daemon;
- `/etc/automata-runner/instances/N/secrets/spool-key-v1.hex` — that instance's
  unique 64-hexadecimal-character key, owned by the runner account with mode
  `0600`;
- `AUTOMATA_S3_ACCESS_KEY_ID` and `AUTOMATA_S3_SECRET_ACCESS_KEY` — credentials
  for the configured RustFS bucket;
- the exact owner-only private-CA file selected by
  `object_store.tls_trust.certificate_source`, when private trust is enabled;
- instance-specific durable journal and spool directories owned by the runner
  account;
- transient Podman state and runtime directories beneath the dedicated tmpfs
  mount, plus home and scratch directories owned by the runner account;
- absolute trusted toolchain paths including `sha256sum`, which the GitHub
  executor invokes inside the job sandbox for declared artifact files;
- the root-owned approved helper directory described above, containing only
  the seven reviewed helper names and no `systemd-run`; and
- exact root-owned Podman, conmon, crun, catatonit, and seccomp-profile paths
  matching the JSON configuration.

The TLS files are enrollment outputs, not inputs to issue or install manually.
Run each enrollment as that instance's exact service account, using the same
installed configuration, stable runner name, and account that systemd will use.
Enrollment creates its private key and private recovery state inside the TLS
directory, submits its canonical capability document, and installs
`server-ca.pem`, `runner.pem`, and `runner-key.pem` there. Keep the parent
instance path on trusted, non-group-writable ancestors, but do not make the TLS
directory root-owned or group-writable. Never enroll as root or as an operator
account and then copy the private key into place.

Mint a separate one-use token and run `automata-runner enroll` as the exact
service account for each configuration, selecting exactly one explicit
`--token-source file:PATH`, `--token-source env:NAME`, or
`--token-source stdin`. Start the services only after every enrollment succeeds.
If an enrollment is interrupted, repeat the exact command as the same account
with the same server, configuration, runner name, and source selector. The
private stage retains the original token and key and is loaded before the source;
an explicit stdin retry may therefore use `/dev/null`. Do not mint a replacement
token or delete the stage.

The long-lived runner owns certificate renewal after enrollment. It requests a
replacement only inside the fixed server due window, keeps the existing leaf
usable for exact replay until that leaf expires, and stores request, key, and
response recovery state beside `runner-key.pem` under the same owner-only
custody lock. Do not delete `.automata-renewal-*` state or replace either TLS
file independently. After an accepted response, the process publishes each
file with an atomic replacement and crash-reconciles the pair, drains every
task and control connection using the old identity, and rebuilds the full
runner composition from disk. Normal service shutdown remains authoritative
during this sequence.

Use owner-only file sources or the process supervisor's private credential
facility. Do not place secret values in the JSON file, shell history, service
arguments, or job environment.

### Rotate the spool key

The top-level spool `protection_id` and `key_hex` identify the one active key.
Every new object is protected with that ID. The optional `decrypt_only` array
contains old `{ "protection_id", "key_hex" }` entries used only when a durable
journal reference names that exact ID. The runner accepts at most eight old
keys and rejects duplicate IDs, including an active ID repeated as old.

To rotate without losing crash recovery, install the new and old key files
first, change the active fields to the new ID/key, and move the previous active
entry into `decrypt_only` in the same restart. Keep the old entry until every
journal reference bearing its ID has completed or been reconciled. Removing it
early fails closed with an unavailable-key error; the runner never tries other
keys or falls back to plaintext. Once the old ID is no longer referenced,
remove its decrypt-only entry and securely retire the external key file.

## 3. Start the isolated GitHub emulator

The checked Linux examples are integration-test configurations. Their three
GitHub context URLs use the same reserved authority,
`http://automata-git.invalid:8088`, and explicitly enable
`map_github_server_to_host_gateway`. They therefore require the isolated
GitHub emulator from
[`automata-integration-tests`](https://github.com/automata-ci/automata-integration-tests),
not the standalone development Git bridge.

The emulator binds port 8088 on host loopback and serves the closed fixture
catalog's GitHub API, archives, and read-only smart Git transport. The runner
adds only `automata-git.invalid` to each job's hosts file and configures Pasta
with `--tcp-ns 8088`, forwarding that one namespace port to the matching host
loopback listener. It does not expose any other host-loopback port. The
reserved `.invalid` name fails DNS closed when either the typed runner opt-in
or the generated network configuration is absent.

Run these examples through the integration harness, which reserves the port,
starts the emulator, and verifies its fixture and binary provenance. If the
emulator port changes, update the server, API, and GraphQL URLs together; the
runner rejects mixed authorities. Normal production configurations use HTTPS
GitHub origins and must leave `map_github_server_to_host_gateway` disabled.

## 4. Start the runner

After all three identities are enrolled, configure the host service manager to
run `automata-runner run` once per configuration. Each process must use the
exact service account and installed configuration that owned enrollment. The
checked-in JSON uses conventional service paths; do not start it under a
different account or before all of its host-path and mount assumptions are
true.

Public source repositories and actions use anonymous access. When the exact
GitHub provider registry is configured, a materialized Standard job may instead
receive short-lived, lease-bound repository authority for its registered
private repository. CredentialFree jobs receive none. General private
marketplace-action compatibility is not claimed.

Before starting any listener or opening its mTLS session, the runner requires
every networking module to be loaded or available from the running kernel's
dependency index, plus the exact configured Podman lifecycle described above.
Failure exits without advertising the runner. After the network gate, startup
also creates, inspects, and destroys one sandbox for every configured
environment profile through the exact provider policy. It requires matching
provider/profile/generation/running evidence and complete cleanup before it
constructs the advertised inventory. Linux admission attaches to that same
sandbox and proves the configured Bash, `sh`, optional Python/PowerShell,
install, tar, SHA-256, and Node-major executables. Host network, host
filesystem, and host identity are never valid tool-probe boundaries; an
administrator profile additionally requires administrator and user-namespace
provider evidence. This verifies that the configured digest-pinned image
launches and exposes the configured runtime through that provider path; it is not
supply-chain attestation or the complete hosted-image conformance suite.

The runner schema rejects static repository, workflow, and Results token
sources. Opaque JobIR secret references also fail closed until the control
protocol supplies a job-scoped secret or credential authority. Never place an
SCM credential in the runner JSON, process environment inherited by jobs, or
sandbox mounts.

## Troubleshooting order

1. Run the passive doctor and confirm server health.
2. Run the active Podman probe and resolve every unavailable or degraded
   capability.
3. Verify the runner-control certificate SAN, trust chain, and configured URL.
4. Verify the certificate-to-runner database mapping.
5. Confirm the runner and server use the same S3 endpoint, trust policy,
   bucket, and prefix.
6. Audit the Git and Results firewall tables and packet path.
7. Inspect the runner journal and spool paths under the service account.

The
[architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
explains why runner identity,
job credentials, storage credentials, and human sessions remain separate trust
domains.
