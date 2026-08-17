# Automata local installation

`automata-ci-local` owns the cross-platform, disposable local-installation
boundary used by `automata local`. It validates the initial x86-64 Linux, Apple
Silicon macOS, or x86-64 Windows host tuple; a local Linux Docker Engine 28.0.0
or newer with API 1.48 or newer; and Compose plugin version 2.20.0 or newer. It
will supervise the local Compose project without adding container-engine
behavior to the control-plane crate.

The user-visible slice provides read-only host preflight and snapshot-backed
workflow checking on the qualified platforms. On x86-64 Linux it also provides
`automata local init`, a mutating init-only operation for a Docker Engine at
exactly `unix:///var/run/docker.sock`. During `local doctor`, context
discovery is completed first, subsequent daemon probes are pinned to that exact
local Unix-socket or Windows-named-pipe endpoint, and JSON schema 3 reports the
bounded context name. Init accepts only the fixed Unix socket so the verified
daemon, imported images, sealed topology, and future relay all name the same
authority.

The private local-snapshot foundation uses live bytes for staged additions
and tracked modifications, omits tracked deletions and ignored files, and seals
each leaf through descriptor- or handle-relative, no-follow ancestor traversal.
It pins the requested directory before Git runs, resolves Git's reported prefix
back to that same directory identity, and pins the worktree, Git directory,
common directory, and no-follow `.git` locator. A regular `.git` file is admitted
only for a linked worktree and its exact bytes are retained. Every later Git
query is explicitly bound to those pinned authorities and their identities are
verified before and after the process. Caller-path or `.git` locator links,
nested-repository confusion, locator retargeting, and `core.worktree`
redirection therefore cannot select a separate tree.
Git mode deterministically represents tracked executable files and symlinks,
including symlink placeholders. Contained Unix symlinks are preserved in the
archive; shared archive policy rejects escaping links, cycles, and aliases
before analysis. Sparse-checkout and assume-unchanged index flags are rejected
because they can hide live state. Ignored-path classification is one bounded
NUL-safe batch per scan. Index conflicts, submodules, path-prefix type
conflicts, Unicode-normalization or full-case-fold aliases, nonportable device
names, non-Unicode paths, bounded component-trie or ustar exhaustion, special
files, and concurrent mutation fail closed. The current source checkpoint is
available on Unix and fails closed on Windows until exact native mutation
evidence has been qualified.

`local check` consumes that archive through one high-level analysis boundary.
Only direct `.github/workflows/*.{yml,yaml}` members are eligible, and an
optional selector must be the exact canonical member path. It accepts only an
explicit local `workflow_dispatch`, recompiles reachable same-archive reusable
workflows, rejects remote or dynamic calls, and validates typed call contracts,
cycles, propagation, and bounds through the shared traversal. Reports retain
only discovered source metadata and value-free external secret/variable names
plus closed built-in requirements. `github.token` and `secrets.GITHUB_TOKEN`
are reported as the non-promptable `github_token` built-in; this checkpoint
does not supply it for execution. Local source and event provenance is distinct
from GitHub delivery evidence. The command is independent of `local doctor`,
Docker, network access, and GitHub tokens, and performs no admission, scheduling,
execution, or Check publication.

`local init` requires an explicit absolute `--state-directory` and an explicit
`--catalog-source file:ABS`; neither has an environment fallback. The state
directory, its trusted ancestry, operation lock, and fixed records are opened
without following links and with exact invoking-user ownership and modes. The
immutable epoch binds a domain-separated digest of the stable state-root
identity and the identity of the held operation-lock file. This custody assumes
a trusted stable local filesystem: copying, restoring, remounting, or replacing
the lock changes authority and requires a future reset or migration. The
operator-selected catalog is canonical, bounded, and digest verified, but init
does not claim that the file was independently OIDC-authenticated. The sole OCI
candidate must be the catalog-declared regular no-follow sibling of that exact
catalog file. Registry roles are pulled only by their catalog-bound digests;
the candidate is structurally verified, converted to the bounded portable
Docker-load form, and qualified under its exact daemon-local tag and mutually
exclusive classic/config-ID or containerd/manifest-ID representation.

The init adapter creates or exactly adopts the immutable external identity
volume, elects the immutable Desired volume as a guard before image
qualification or any other role mutation, and then creates or adopts the other
eleven owner-specific persistent volumes. Persistent labels bind
installation identity, material schema/generation, and immutable epoch
fingerprint, never a mutable plan digest. A fixed one-shot materializer runs
with no network, a read-only root, UID 0, all capabilities dropped except
`CHOWN` and `DAC_OVERRIDE`, and only the exact image, command, and twelve
mounts. It receives one bounded canonical request over attached stdin and
publishes static role manifests last after validating content,
metadata, links, and cross-file certificate/key equality. Host custody retains
the exact one-time certificate bytes. Partial fresh volume creation and matching
fixed write temporaries resume exactly, and an uncommitted malformed temporary
is discarded and rebuilt. Loss or conflicting final/static custody after
established materialization requires reset rather than silent repair. The
material root is KDF root derivation input only and is never copied verbatim
into a credential.

Init seals only the canonical desired specification together with the immutable
epoch and material. The desired record includes the local service-proxy tag and
both acceptable OCI IDs so later convergence can reattest the same daemon
representation. This slice has no renderer and generates no Compose document.
Init invokes no Compose operation and starts no service, relay, bootstrap,
database, object store, or runner. No public `up`, `down`, `status`, `reset`,
relay, or bootstrap lifecycle command exists; `ResetRequired` is detectable,
but there is no reset command. The adapter exposes no generic delete, prune, or
arbitrary helper API.

On Linux, the runner also consumes one evaluation-only sandbox-provider
factory. The concrete Docker provider and engine API stay private. They connect
only through the fixed `/run/automata-engine/docker.sock` relay, bind every
operation to the exact daemon and installation anchor, and accept only
already-present immutable guest, job, and Results-proxy images. The mandatory
`LocalDockerResultsTransport` pins one externally provisioned transit-network
ID, one running Results-container ID and private IPv4 address, and the proxy
image; the per-sandbox provider never creates, replaces, or deletes the shared
transport.
The fixed relay daemon must be rootful
and report daemon-default user-namespace remapping, the built-in seccomp
profile, and private cgroup namespaces. Rootless mode and daemons with AppArmor
or SELinux enabled are deliberately not qualified because this provider does
not model those daemon-added labels. `/info` must also report memory, swap, CPU
CFS period/quota, and PID-limit enforcement. PID 1 then
requires each kernel `uid_map` and `gid_map` to contain one nonzero host range
covering container identities 0 through 65533. Daemon security-option drift is
part of the pinned identity and invalidates the provider. The relay architecture
must exactly match the architecture already recorded in the runner inventory;
the immutable guest, job, and proxy images must match that same relay
architecture and must not declare volumes, exposed ports, or a healthcheck. The
proxy additionally has an exact credential-free runtime shape and must carry
`io.automata.service-proxy.protocol-version=2`.

The bounded Engine facts do not expose the daemon's `default-ulimits`
configuration. An empty `default-ulimits` policy is therefore a trusted
fixed-relay prerequisite, not a preflight attestation. The provider still
requires the realized container ulimit list to be empty; a violation fails
closed after create, and custody-only destroy can still remove the container
when its immutable custody and exact front network remain valid.

A job receives no host bind, host engine socket, or per-job volume. It joins one
deterministic internal `/29` front network shared only with a credential-free
proxy. That proxy joins the front network and the separate internal transit;
the job never joins transit, control, or dependency networks. Its only route is
`results.automata.invalid:8081` through the exact proxy to the configured
numeric Results address, with no external DNS or public egress. Installation
custody deterministically maps profile admission plus job slots 1 through 256
to disjoint front networks and transit addresses; collisions, overlap, or
insufficient transit capacity fail without an alternate allocation scan.

Create, attach, inspect, and endpoint operations re-attest the complete shared
transit and all attached peer proxies under one cancellation-aware 30-second
budget. Destroy skips shared-transit and container-runtime/image re-attestation,
so damage there does not by itself block removal of containers whose immutable
custody remains exact. Exact front-network drift blocks destroy before mutation;
a foreign endpoint prevents deletion of the front network after owned containers
are removed. Its workspace and protected control client live in container tmpfs
mounts. The
protected guest broker replaces the profile keepalive as PID 1; the keepalive
is bound into the sandbox identity but is not run as initialization. Raw
provider endpoints are attempt-once. The production runner places them behind
its durable exact-request replay boundary, while profile admission calls each
raw operation once and destroys the sandbox after ambiguous evidence. The
advertised administrator is deliberately attenuated: workflow processes have
UID 0 only inside the proven remapped namespace, while inheritable, permitted,
effective, bounding, and ambient Linux capability sets are all empty under
`no_new_privileges` and the built-in seccomp profile. It does not promise
`chown`, identity switching, or any other POSIX capability. Existing running
containers are adopted only after exact identity inspection; an exited
container is never restarted.
Durable execution replay remains host-owned, and an ambiguous committed
invocation fails closed until the exact sandbox is destroyed and proven absent.

This transport foundation does not itself provision the shared transit or
listener, inject Results/cache URLs, or issue a token. Local snapshot admission
and repository-scoped Results/cache authority remain separate reviewed work;
there is no ambient installation credential or GitHub-authority fallback.

An installation is one reusable control-plane and runner-capacity domain, not
one repository. Repositories sharing an installation are one trusted set and
retain their own admission, authorization, secret, cache, and history scope in
the existing control plane. A separate `--installation` name is the explicit
way to request another deployment/capacity domain.

`automata local init` is the sole product mutation command: it imports or pulls
the verified image set, creates/adopts exact installation volumes, and seals
host material plus desired topology without converging it. The runner-only
provider boundary above still does not add a local lifecycle command. The
snapshot boundary is consumed separately by `automata local check`, which
compiles an explicit local manual-dispatch event and all reachable same-snapshot
reusable workflows through the shared compiler and credential analysis. It
does not admit or run work, mint GitHub evidence, request a token, or publish a
Check Run. There is no mirrored live-resource inventory or public lifecycle
state machine, and secret values never enter the desired document. This slice
does not generate a Compose document.

This crate has no command-line parser. The `automata` product maps its public
CLI into the high-level local-check and x86-64 Linux init requests; filesystem,
catalog, materializer, snapshot, and archive authority stay private.
