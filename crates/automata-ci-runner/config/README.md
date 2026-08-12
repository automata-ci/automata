# Local runner bootstrap

This directory contains three checked-in Linux Podman instance configurations
plus Windows and macOS native configurations for `automata-runner`.
[`runner.local-1.example.json`](runner.local-1.example.json),
[`runner.local-2.example.json`](runner.local-2.example.json), and
[`runner.local-3.example.json`](runner.local-3.example.json) select the same
locked Ubuntu 24.04 profile while keeping every host-local identity, state
path, credential path, runtime mount, and metrics port distinct.
[`runner.windows.example.json`](runner.windows.example.json) selects the
trusted native provider on Windows. [`runner.macos.example.json`](runner.macos.example.json)
selects the trusted native provider on Apple Silicon macOS 15+. Exactly one of
the `podman`, `kubernetes`, `windows_native`, and `macos_native` provider
objects may be configured.

The Linux examples' local bootstrap digest is not an official promoted profile;
follow the
[profile publication guide](https://github.com/automata-ci/automata/blob/main/images/github-hosted-ubuntu-24.04-x64/README.md)
before trusting a protected-main candidate.

Product schema v2 accepts exactly one sandbox provider. Host runners use the
top-level `podman` object and require `state.podman`. Kubernetes runners omit
`state.podman`, `state.windows_native`, and `state.macos_native` and use a
top-level `kubernetes` object. Native Windows and macOS runners use their
matching provider name in both locations. The runner loads
credentials through Kubernetes' standard in-cluster or ambient kubeconfig
discovery; the JSON remains secret-free.

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
client, exercises every configured environment through create/inspect/destroy,
and registers only after that lifecycle succeeds. These assertions do not
replace cluster-side CNI, node-local traffic, admission-policy, RuntimeClass,
or kubelet verification.

> [!WARNING]
> Runner enrollment and certificate lifecycle are not yet a turnkey user flow.
> This guide is for contributors integrating the G1 end-to-end path, not for a
> production runner installation.

Start with the
[control-plane setup](https://github.com/automata-ci/automata/blob/main/docs/deployment.md),
then provision a Linux runner host with the
[Arch Linux guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md).

## Windows native example

The Windows example is an experimental source-build path for trusted workflows.
It advertises PowerShell and `cmd.exe` shell steps, with optional support for an
absolute standalone Python interpreter, and uses fresh job directories plus Job
Object process containment; it is not container or VM isolation. Run
it under a dedicated non-administrative service account: children retain that
account's token because restricted-token launch is not implemented. The Job
Object controls process lifetime and resource use, not privilege. The example's
`host` privilege policy explicitly acknowledges that unchanged identity; it is
not an unprivileged sandbox policy. Pre-provision restrictive ACLs on every
configured state and execution root, and supply its
private key, spool key, and object-store credentials only through the service
supervisor's private environment. Only workflow `run:` steps are supported;
every `uses:` action, including JavaScript, composite, local, repository, and
container actions, fails closed. Job containers, service containers,
administrator profiles, and active Podman doctor checks remain unsupported.
Every configured interpreter is exercised through a copied script during
startup admission before the runner advertises the profile.

The current safe Windows adapter rejects reparse traversal but cannot attest
DACL ownership or hard-link counts. ACLs protect these roots from other host
users; they do not isolate runner state from a trusted job that inherits the
same account and host-filesystem access. Such workflows must not touch the
configured runner state paths.

Copy [`runner.windows.example.json`](runner.windows.example.json) to an ignored
host-specific path and follow the
[Windows source-build boundary](../../../docs/getting-started.md#windows-source-build-and-native-runner-boundary)
before starting `automata-runner run --config C:\path\to\runner.windows.json`.

## macOS native example

The macOS example is an experimental trusted-workflow path for Apple Silicon
running macOS 15 or newer. It executes Bash and `sh` scripts through a hidden
same-binary supervisor which owns a POSIX process group and terminates that
group on timeout, cancellation, output overflow, or runner disconnect.
Optional absolute Python and PowerShell Core paths are accepted and probed at
startup. Every `uses:` action, job or service container, parallel native slot,
GPU claim, and nonzero ephemeral-disk capacity fails closed.

This provider deliberately uses the dedicated runner account's unchanged host
identity, filesystem, and network. Its configured CPU, memory, and PID values
are one-slot scheduling capacity, not hard resource limits. Run only trusted
workflows under a dedicated non-administrative account. Provision the provider
root and every existing descendant as that account with mode 0700; the adapter
opens paths descriptor-relatively, rejects symlink traversal and hard-linked
copy targets, and keeps a checksummed, exclusively locked lifecycle journal.

The `macos_keychain` secret source selects one exact generic-password item by
`service` and `account` in the account's default Keychain. Reads are serialized,
bounded, and performed with authentication UI disabled; missing, duplicate,
locked, interactive-only, or malformed values stop startup without exposing
secret bytes. Pre-provision item access for the exact reviewed
`automata-runner` binary and verify it while logged in as the service account.
Do not pass secret values on a command line or store them in the JSON.

Copy [`runner.macos.example.json`](runner.macos.example.json) to an ignored
host-specific path, replace the identity and endpoints, provision its roots and
Keychain items, then start `automata-runner run --config /absolute/path/to/runner.macos.json`.
The implementation and remaining VM-isolation work are tracked in the
[macOS plan](../../../docs/platforms/macos.md).

The remainder of this guide describes the three-process rootless-Podman Linux
host. Windows and macOS each remain one process with one slot.

## What the Linux example assumes

The three `runner.local-N.example.json` files assume:

- three dedicated runner accounts with UID/GID pairs 1001 through 1003 and
  non-overlapping subordinate ID ranges;
- durable journal and spool state below `/var/lib/automata-runner`;
- Linux 6.4 or newer with three dedicated, bounded `tmpfs,noswap` mounts at
  `/run/automata_runner_1` through `/run/automata_runner_3`;
- distinct TLS leaves/keys and spool keys below each
  `/etc/automata-runner/instances/N` boundary;
- a control-plane runner listener reachable at the configured HTTPS URL;
- the same RustFS bucket and prefix used by the server;
- the pinned Ubuntu 24.04 OCI image is available by its exact digest; and
- a firewall-protected smart-Git bridge is available for the local repository
  snapshot.

Copy all three examples to ignored, host-specific paths. Update, at minimum,
the three `runner_id` values, `control_endpoint`, account paths, runtime UID,
resources, and Git bridge URLs. Do not edit the checked-in examples with
machine credentials and never reuse an ID, client key, or spool key between
instances.

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
kernel's exact `noswap` option. The checked-in systemd host shape provisions
three separate 20 GiB mounts; the equivalent instance-one mount is:

```console
sudo install -d -m 0700 -o automata-runner-1 -g automata-runner-1 \
  /run/automata_runner_1
sudo mount -t tmpfs automata-runner-runtime-1 /run/automata_runner_1 \
  -o nodev,nosuid,noswap,size=20G,nr_inodes=349525,mode=0700,uid=1001,gid=1001
```

Use the checked-in [three-process systemd units](../../../deploy/runner-host/README.md)
so all mounts and services are boot-managed and correctly ordered; the manual
command is only a development illustration. Do not bind any runtime tmpfs
elsewhere, share it between processes, or mount anything below it. Linux before
6.4 cannot provide this contract because tmpfs did not support `noswap`.

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

## 2. Provision runner inputs

Each instance `N` expects:

- `/etc/automata-runner/instances/N/tls/server-ca.pem` — server trust roots;
- `/etc/automata-runner/instances/N/tls/runner.pem` — that instance's unique
  runner certificate chain;
- `/etc/automata-runner/instances/N/tls/runner-key.pem` — that instance's
  unique private key, owned by the runner account with mode `0600`;
- `/etc/automata-runner/instances/N/secrets/spool-key-v1.hex` — that instance's
  unique 64-hexadecimal-character key, owned by the runner account with mode
  `0600`;
- `AUTOMATA_S3_ACCESS_KEY_ID` and `AUTOMATA_S3_SECRET_ACCESS_KEY` — credentials
  for the configured RustFS bucket;
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

Before starting the host, follow the control-plane guide's
[static runner bootstrap](https://github.com/automata-ci/automata/blob/main/docs/deployment.md#bootstrap-three-static-local-runners)
for all three configurations: render three canonical capability documents,
issue three client-only leaves, and bind each digest to its exact distinct
runner identity. Automated enrollment remains unavailable.

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

## 3. Prepare the local repository bridge

The integration configuration points GitHub context URLs at a read-only smart HTTP
server on `automata-git.ghe.com:8088`. A static file server is insufficient
because Git's dumb HTTP transport cannot honor the workflow's shallow checkout.

Review the exact repository paths needed by the integration run and stage them
in the default Git index before creating the immutable snapshot. The snapshot
script uses that index as-is; it rejects `GIT_INDEX_FILE`, unstaged tracked
changes, and every nonignored untracked path before it creates an object or
publishes the bare repository. Never stage credentials just to make the check
pass. A failed snapshot leaves its requested output path absent.

Create the snapshot and a separate bridge scratch directory:

```console
git status --short
git add -- PATHS_REVIEWED_FOR_THE_INTEGRATION_RUN
git diff --cached --check
git diff --cached
./scripts/dev/create-integration-snapshot.sh target/integration/source
install -d -m 0700 target/runner-local/git-http-scratch
```

The bridge binds one exact RFC 1918 host address. Render, review, apply, and
audit its independent firewall policy before starting the listener:

```console
./scripts/dev/git-bridge-firewall.sh render \
  --config deploy/dev/git-bridge-firewall.env.example
sudo ./scripts/dev/git-bridge-firewall.sh apply \
  --config deploy/dev/git-bridge-firewall.env.example
sudo ./scripts/dev/git-bridge-firewall.sh audit \
  --config deploy/dev/git-bridge-firewall.env.example
```

Then start the bounded read-only CGI bridge:

```console
python3 scripts/dev/git-http-server.py \
  --project-root "$(realpath target/integration/source)" \
  --scratch-directory "$(realpath target/runner-local/git-http-scratch)" \
  --git-http-backend "$(realpath "$(git --exec-path)/git-http-backend")" \
  --listen-address 192.168.0.8 \
  --port 8088
```

The URL format is `http://HOST:PORT/OWNER/REPOSITORY`. The server accepts only
smart read endpoints for `git-upload-pack`; it cannot push or invoke arbitrary
CGI paths.

The `.ghe.com` suffix is intentional: the official artifact client recognizes
it, while `.localhost` is forced to container loopback by the resolver. The
typed Podman option maps exactly the configured GitHub hostname to the host
gateway; production configurations add no such mapping by default.

## 4. Start the runner

Run the installed binary as the dedicated account:

```console
automata-runner run \
  --config /path/to/runner.local.json
```

The checked-in JSON uses conventional service paths and may be run directly
only when those exact assumptions are true.

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
constructs the advertised inventory. This verifies that the configured
digest-pinned image launches through that provider path; it is not
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
5. Confirm the runner and server use the same S3 bucket and prefix.
6. Audit the Git and Results firewall tables and packet path.
7. Inspect the runner journal and spool paths under the service account.

The
[architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
explains why runner identity,
job credentials, storage credentials, and human sessions remain separate trust
domains.
