# Local runner bootstrap

This directory contains the checked-in Linux integration configuration for
`automata-runner`. It selects the locked bootstrap Ubuntu 24.04 profile and a
rootless Podman sandbox provider. That local bootstrap digest is not an
official promoted profile; follow the
[profile publication guide](https://github.com/automata-ci/automata/blob/main/images/github-hosted-ubuntu-24.04-x64/README.md)
before trusting a protected-main candidate.

> [!WARNING]
> Runner enrollment and certificate lifecycle are not yet a turnkey user flow.
> This guide is for contributors integrating the G1 end-to-end path, not for a
> production runner installation.

Start with the
[control-plane setup](https://github.com/automata-ci/automata/blob/main/docs/deployment.md),
then provision the runner host with the
[Arch Linux guide](https://github.com/automata-ci/automata/blob/main/docs/platforms/arch-linux.md).

## What the example assumes

`runner.local.example.json` assumes:

- a dedicated runner account with UID 1000;
- durable journal and spool state below `/var/lib/automata-runner`;
- Linux 6.4 or newer with a dedicated, bounded `tmpfs,noswap` mount at
  `/run/automata-runner` for all Podman state;
- TLS material below `/etc/automata-runner/tls`;
- a control-plane runner listener reachable at the configured HTTPS URL;
- the same RustFS bucket and prefix used by the server;
- the pinned Ubuntu 24.04 OCI image is available by its exact digest; and
- a firewall-protected smart-Git bridge is available for the local repository
  snapshot.

Copy the example to an ignored, host-specific path. Update, at minimum,
`runner_id`, `control_endpoint`, account paths, runtime UID, resources, and the
Git bridge URLs. Do not edit the checked-in example with machine credentials.

Both `ephemeral_disk_bytes` fields must remain `0`. The current Podman adapter
does not provide a proven per-job storage quota, so the runner deliberately
advertises no ephemeral-disk capacity and rejects a nonzero configured value.
Jobs that require nonzero ephemeral disk will not match this runner.

The configured `podman.runtime_directory` is the exact mountpoint, not a
directory on a shared `/run` or `/run/user/<uid>` tmpfs. The checked-in layout
requires `state.podman` to be exactly
`podman.runtime_directory/automata-ci-podman/state`; separate `/var/lib`
Podman state, sibling state, bind mounts, and child mounts fail closed. Mount
the runtime before starting the runner, give it exact mode 0700 and the runner
UID/GID, include finite `size=` and `nr_inodes=` operator bounds, and use the
kernel's exact `noswap` option. For example:

```console
sudo install -d -m 0700 -o automata-runner -g automata-runner /run/automata-runner
sudo mount -t tmpfs automata-runner-runtime /run/automata-runner \
  -o nodev,nosuid,noswap,size=64G,nr_inodes=1048576,mode=0700,uid=1000,gid=1000
```

Make this a boot-managed mount ordered before the runner service; a manual
mount is only a development example. Do not bind the same tmpfs elsewhere or
mount anything below it. Linux before 6.4 cannot provide this contract because
tmpfs did not support `noswap`.

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

The example expects:

- `/etc/automata-runner/tls/server-ca.pem` — server trust roots;
- `/etc/automata-runner/tls/runner.pem` — the runner certificate chain;
- `/etc/automata-runner/tls/runner-key.pem` — the runner private key, owned by
  the runner account with mode `0600`;
- `/etc/automata-runner/secrets/spool-key-v1.hex` — exactly 64 hexadecimal
  characters, owned by the runner account with mode `0600`;
- `AUTOMATA_S3_ACCESS_KEY_ID` and `AUTOMATA_S3_SECRET_ACCESS_KEY` — credentials
  for the configured RustFS bucket; and
- durable journal and spool directories owned by the runner account;
- transient Podman state and runtime directories beneath the dedicated tmpfs
  mount, plus home and scratch directories owned by the runner account;
- the root-owned approved helper directory described above, containing only
  the seven reviewed helper names and no `systemd-run`; and
- exact root-owned Podman, conmon, crun, catatonit, and seccomp-profile paths
  matching the JSON configuration.

Before starting the runner, follow the control-plane guide's
[static runner bootstrap](https://github.com/automata-ci/automata/blob/main/docs/deployment.md#bootstrap-one-static-local-runner)
to render the canonical capabilities, issue the client-only leaf, and bind its
digest to this exact runner identity. Automated enrollment remains unavailable.

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

Public source repositories and public repository actions remain supported
through anonymous access. Private repositories and private actions are
intentionally unsupported until the server can broker a short-lived GitHub App
credential bound to the exact job and repository.

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
