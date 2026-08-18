# Local installation and deployment roadmap

- Roadmap status: Active
- Available slice: read-only `automata local doctor`, source-only
  `automata local check`, x86-64 Linux-only sealed `automata local init`,
  recorded-metadata `status`, exact confirmed `reset`, and explicit
  runner-schema-8 evaluation through the fixed-relay `LocalDocker` provider;
  init starts no services and there is no `automata local run`, `up`, or `down`
  yet
- Current implementation checkpoints: 2B.1 pinned Docker context and immutable
  identity anchor; 2B.2 verified catalog/image/material/epoch/desired sealing;
  2B.3 read-only custody status and exact established reset; the evaluation-only
  3A provider and closed Results gateway foundation; plus the read-only
  source-validation portion of 3B
- Date: 2026-08-17

This roadmap owns the work required to make Automata easy to evaluate on one
machine, run repository-scoped work through a repository-agnostic local
installation, optionally connect that installation to GitHub, and then grow the
tested deployment choices. Capability claims remain in
[Compatibility](../../compatibility.md); this page records product decisions,
reuse boundaries, merge checkpoints, and the evidence required to change those
claims.

The local product is an adapter around Automata's existing control plane and
runner, not a second CI implementation. New local code may supply a source
authority, a Docker sandbox provider, composition, and native credential-store
adapters. It must not replace the existing workflow compiler, admission,
scheduler, runner protocol, enrollment, result history, or secret-delivery
model.

## Product outcome

The first supported experience starts the complete control plane and enough
local execution capacity for `N` concurrent Linux jobs on Arch Linux, Apple
Silicon macOS, or Windows x86-64. macOS and Windows use their Docker Desktop
Linux engine. Native macOS and native Windows jobs remain separate advanced
execution profiles.

From an existing Git checkout containing a compatible workflow, the onboarding
contract is:

```console
cd my-repository
automata local run
```

The optional workflow selector and concurrency flag are predictable:

```console
automata local run .github/workflows/ci.yml
automata local run .github/workflows/ci.yml --workers 3
```

For the first topology, `--workers N` means `N` concurrent job slots on one
ordinary runner identity. It maps to the runner's existing
`max_parallel_jobs=N` capability instead of generating and enrolling `N`
separate runners. A future advanced fleet-testing option may create several
runner identities, but that is not part of first-run onboarding.

On a new installation, omitting `--workers` selects one slot. On an existing
installation, omitting it reuses the stored desired value. Supplying a different
value is an explicit, validated desired-spec update and survives `down -> up`.

`local run` will:

1. discover the repository and build a bounded immutable snapshot of the
   current worktree, including tracked modifications and non-ignored untracked
   files, without changing the checkout;
2. discover eligible workflows in that sealed snapshot, resolve the workflow
   selector and event, then use the existing GitHub
   Actions frontend and compiler to validate syntax, inputs, actions, reusable
   workflows, runner selectors, and statically discoverable credential names
   from those exact bytes;
3. reconcile a deterministic Compose project containing the existing Automata
   control plane, its dependencies, and one ordinary runner configured with the
   requested parallelism;
4. query the existing managed-secret provider for the compiler-discovered names
   and prompt with echo disabled for missing supported user secrets;
5. admit that same sealed snapshot through an explicit local source authority
   into the existing admission, scheduling, runner, logging, and result path;
6. stream progress and finish with the workflow's result status.

Snapshot construction, compilation, credential discovery, and admission are
one evidence chain: after the snapshot is sealed, no later step rereads workflow
or reusable-workflow bytes from the live checkout.

The first worktree run needs no GitHub App, browser, webhook, public hostname,
or push. Optional GitHub connection comes later for authenticated remote refs,
webhook-driven runs, Check Runs, and GitHub API authority.

The workflow positional argument is optional. An exact eligible
repository-relative path resolves directly. A filename, stem, or workflow
display name is accepted only when it is unique. Interactive ambiguity opens a
picker; non-interactive and JSON modes report the sorted choices and fail.

Only direct `.github/workflows/*.yml|yaml` files are eligible; nested files and
`.ci/workflows` aliases are not. This explicit local source policy does not
change the autonomous GitHub provider's production discovery policy. Local
compatibility also does not imply full GitHub Actions parity: unsupported
syntax, actions, events, dynamic secret references, and runner selectors fail
during read-only inspection.

The available read-only check accepts only declared `workflow_dispatch`. A
later executable slice may add a separately typed, truthful local `push`
context, but a local event is never represented as a signed GitHub delivery and
never produces a GitHub Check. `actions/checkout` will resolve to the admitted
snapshot; it must not silently fetch another revision. `github.token` and
`secrets.GITHUB_TOKEN` are closed built-in requirements, never promptable user
secrets; the current check reports that requirement but does not claim to
supply it for execution.

The initial selector registry accepts `automata-local`, `ubuntu-24.04`, and a
release-pinned `ubuntu-latest` alias. It records the exact local image, OS, and
architecture. On Apple Silicon, substituting the ARM64 companion profile for an
Ubuntu AMD64 alias requires explicit interactive confirmation or
`--allow-architecture-substitution`; `automata-local` directly selects the
host-native profile.

## Command structure

The currently available command surface is deliberately small:

```console
automata local doctor [--json]
automata local check [WORKFLOW] [--input NAME=VALUE]... [--json]
automata local init --state-directory ABS --catalog-source file:ABS
  [--installation NAME] [--workers N]
automata local status --state-directory ABS [--json]
automata local reset --state-directory ABS --yes
```

Init is x86-64 Linux-only and stops after sealed material and canonical desired
intent. It generates no Compose document. The target surface below remains
planned and is not accepted by the current CLI; it keeps lifecycle, runs,
secrets, and optional integrations in distinct namespaces:

```console
automata local run [WORKFLOW] [--workers N] [--event EVENT]
  [--input NAME=VALUE]... [--allow-architecture-substitution]
  [--non-interactive] [--allow-missing-secrets] [--json]

automata local up
automata local down
automata local services logs [SERVICE] [--follow]

automata local runs list
automata local runs view RUN
automata local runs watch RUN
automata local runs logs RUN [--job JOB]
automata local runs cancel RUN

automata local secret set NAME [--from-file PATH | --stdin]
automata local secret list [--json]
automata local secret delete NAME [--yes]

automata local variable set NAME [--from-file PATH | --stdin]
automata local variable list [--json]
automata local variable delete NAME [--yes]

automata local github connect [OWNER/REPOSITORY]
automata local github status
automata local github disconnect
```

`local run` is the primary onboarding path and implicitly initializes and starts
the stack when necessary. The explicit lifecycle commands are for inspection,
recovery, and repeated use; their existence must not turn the quickstart into a
manual assembly guide. `up` never prompts for a workflow, secret, browser, or
GitHub connection.

The future converged lifecycle commands that select an installation accept the
same `--installation NAME` selector. Current sealed init accepts that selector;
current status and reset instead derive the immutable name and ID from the
explicit `--state-directory` custody and deliberately accept no separate
selector. Host-only `doctor` and source-only `check` do not invent or select an
installation. Any native cache location is an internal platform choice, not
installation identity or a public lifecycle selector.
An installation is a repository-agnostic deployment and runner-capacity domain:
the same selected installation may admit snapshots from different repositories,
and repository identity never enters its selector key, engine labels, Compose
project, or desired specification. The read-only check deliberately derives or
reports no repository identity; a durable repository identity contract is
deferred until local admission actually consumes and qualifies it. Repositories
sharing one installation form one trusted set and share its runner capacity;
separate installation names are useful for distinct trust sets or destructive
test environments, but names on the same administrator-controlled daemon are
not a hostile-code isolation boundary.
JSON reserves stdout for one stable document and never prompts.
Non-interactive execution never reads values from implicit environment
variables or command arguments. Secret setters use hidden TTY input when no
explicit input source is supplied; variables use ordinary TTY input.

`down` removes the running, replaceable Compose topology without `--volumes` and
preserves installation identity, desired spec, persistent service data, run
history, and OS credentials. `reset` requires confirmation and removes those
exact persistent resources as well. Neither command performs a global Docker
prune or uninstalls an external GitHub App.

## Current baseline

The source tree has useful production components, but not yet the complete
onboarding path:

| Existing path | Reusable capability | Remaining local gap |
| --- | --- | --- |
| `automata local doctor` | Cross-platform host, Docker, Compose, and architecture preflight | It is deliberately read-only; checkpoint 2A retired checkpoint 1's proposed native state-root input, and checkpoint 2B.1 makes installation identity engine-owned |
| `automata local check` | Deterministic bounded live-worktree archive, exact `.github/workflows` selection, local-only manual event compilation, reachable same-snapshot reusable workflows with typed call-graph and root-secret propagation, and value-free external/built-in credential discovery | It is deliberately read-only and fails closed on Windows; repository identity, local admission, scheduling, execution, and GitHub Checks remain absent |
| `automata local init`, `status`, and `reset` | x86-64 Linux-only exact-socket identity/image/volume adoption, host material and one-time certificate custody, fixed materialization, sealed canonical desired intent, read-only recorded-custody inspection, and exact confirmed teardown | Status does not live-attest volume contents; reset requires an authority-bound epoch plus complete post-guard Engine custody and retains images; convergence, bootstrap, `up`, and `down` remain absent |
| `automata-ci-local` Docker boundary | Exact-endpoint anchor and sealed-init management plus a private fixed-relay provider with deterministic closed Results topology | Convergent lifecycle must provision and reattest the lifecycle-created, Compose-external shared transit and rendered Results listener |
| Control-plane configuration and container build | Complete server configuration and product images | Configuration and bootstrap are manual and Unix-oriented |
| GitHub workflow crates | Frontend, compiler, typed workflow contracts, reusable-workflow handling | They need a separately authorized local snapshot source |
| Workflow service | Credential requirement discovery, admission, and orchestration boundaries | It needs local provenance as an additional source authority |
| Runner and runner journal | Enrollment/redeem, mTLS protocol, durable slots, result delivery, bounded `max_parallel_jobs`, and explicit evaluation-only `local_docker` composition | Local snapshot admission and repository-scoped Results/cache authority remain absent |
| Secret and key-management crates | Secret domain, versioned providers, envelope encryption, delivery, and masking | CLI credential custody is Linux-only and local prompting is absent |
| Rootless Podman, macOS VM, and native Windows providers | Hardened production or advanced execution profiles | None is the portable Linux-container evaluation provider |
| Release automation | Guarded Linux x86-64 release flow | Native CLI artifacts and multi-architecture images are not public |

## Reuse decisions

The following decisions are constraints, not implementation suggestions. A PR
that cannot reuse one of these paths must document the missing contract and
improve the shared abstraction instead of creating a local duplicate.

| Concern | Required reuse | Permitted local addition |
| --- | --- | --- |
| Operation identity | `automata_ci_core::OperationId` | Local provenance fields around the shared ID |
| Service lifecycle | Docker Compose convergence, health, project labels, and engine inspection | A deterministic project specification and CLI supervisor |
| Installation identity | A deterministic external Docker volume with immutable identity labels | Exact create/adopt inspection and engine-scoped serialization |
| Desired specification | Canonical credential-free product intent | One minimal immutable v1 document in an engine-managed config volume; future rendering remains a convergence concern |
| Workflow syntax | `GithubWorkflowFrontend`, the existing compiler, typed input and reusable-workflow contracts | A source-policy adapter that admits local workflow locations |
| Admission and orchestration | Existing workflow service, transaction boundary, scheduler, cancellation, and run history | An explicit `LocalSnapshot` authority and provenance |
| Runner | Existing runner process, mTLS protocol, journal/spool, and `max_parallel_jobs` | Local runner configuration and a Docker sandbox provider |
| Enrollment | Existing issuance and one-use redeem semantics | A private local bootstrap transport into the existing application service if one is missing |
| Sandbox contract | Existing provider/executor interfaces, custody, output bounds, and results path | Evaluation-only `LocalDocker` implementation |
| Secrets | Existing `SecretName`, `SecretValue`, `SecretProvider`, key-management, managed provider, delivery, and masking | Native OS credential adapters and guided CLI collection |
| CLI credentials | Existing exact-schema Linux Secret Service custody | One portable port plus Keychain and Credential Manager adapters |
| Logs and results | Existing stored run identities, log stream, conclusions, cancellation, and history | Local CLI presentation only |

The following designs are explicitly rejected:

- a local-specific operation ID type;
- a second workflow parser, compiler, scheduler, result store, or cancellation
  model;
- a host manifest that mirrors every container, network, volume, Compose phase,
  or Docker version;
- an authoritative host installation manifest or host lifecycle journal;
- using live containers as the only copy of desired parallelism or render
  inputs needed after `down`;
- an independent local lifecycle state machine layered over Compose;
- a new `automata-runner run-local` protocol or local-only enrollment token;
- one runner identity per requested job slot in the default topology;
- a second durable workflow-secret provider or a second permanent encrypted
  vault containing the same values; and
- generated Compose topology persisted as repository infrastructure instead of
  being owned by the product lifecycle adapter.

## Accepted local architecture

### Topology

Every long-running service runs in one deterministic Compose project generated
and reconciled by the typed product lifecycle adapter. The source repository
does not ship a standalone Compose stack. Runtime rendering is limited to a
small, value-free environment/configuration surface and is covered through the
adapter contract rather than a second operator-owned topology.

```text
local Git worktree
        |
        v
bounded immutable snapshot ---- future local admission authority
                                      |
                                      v
                             existing workflow service
                                      |
                         existing scheduler and history
                                      |
        +-----------------------------+---------------------------+
        | deterministic Compose project                           |
        |                                                         |
        | control plane ---- PostgreSQL ---- object storage       |
        |       |                                                 |
        |       +---- ordinary runner (max_parallel_jobs = N)     |
        |                         |                               |
        +-------------------------|-------------------------------+
                                  v
                         LocalDocker provider
                                  |
                         sibling job containers

optional GitHub App/tunnel ---> existing signed-GitHub provider boundary
```

The control plane and runner continue to use their production protocols. Local
composition does not bypass admission or call an executor directly from the
CLI.

### Compose identity, desired spec, and realized topology

The supervisor separates three kinds of state. An immutable external volume
anchors installation identity. A persistent engine-managed config volume holds
minimal desired intent. Compose and fresh Engine inspection are the live source
of truth for realized resources and health. No host lifecycle journal mirrors
any of them.

#### Immutable identity anchor

A deterministic external named Docker volume is created once as the
installation anchor. Its exact Automata-managed label allowlist contains the
managed marker, identity schema, installation UUID, installation selector key,
deterministic Compose project, and the anchor resource-kind discriminator. The
selector key is derived only from the canonical installation selector under an
exact versioned byte preimage; it is an identifier, not cryptographic key
material. No repository, checkout, worktree, or source identity participates in
that preimage. Changing an identity field requires confirmed reset or an
explicit migration; it is never an in-place update.

Create and adoption require `Driver=local`, `Scope=local`, empty driver options,
no host-bind option, and no container attachment. The supervisor always
re-inspects after `volume create`, because that API may return a pre-existing
name. It validates driver, scope, options, mount attachments, and managed labels
before adopting the returned volume or creating any attached topology. The
identity anchor itself is never mounted.

Label comparison is exact only within Automata's reserved managed namespace.
Every role has a required-and-allowed key set, and an unknown managed key fails
closed. Engine- and Compose-owned labels outside that namespace are not mistaken
for Automata ownership and do not cause whole-map equality checks. Standard
Compose labels used for independent project discovery are validated separately.

#### Persistent desired specification

A separate engine-managed config volume persists one schema-versioned,
credential-value-free desired-spec document. Current immutable v1 contains the
installation binding, requested `max_parallel_jobs`, human port, exact local
profile and architecture decision, exact image inputs, stable Results transit
addressing, and its canonical plan digest. The imported service proxy retains
its deterministic daemon-local tag plus both acceptable OCI IDs for later
reattestation. It contains no renderer field, rendered Compose bytes,
credential value, live resource ID, live phase, daemon version, or resource
inventory.

The digest is computed from the canonical document with its digest field
excluded and is read back and recomputed after the fixed materializer commits
it. Current desired v1 is deliberately immutable within an epoch; a future
mutable desired contract requires an explicit schema migration rather than an
in-place reinterpretation. An interruption leaves either no established final
record or the complete canonical document, never an accepted partial spec.

Every persistent service volume carries only immutable Automata
contract/identity/role labels: managed marker, contract and resource kind,
installation UUID, selector key, project, and exact role. The identity anchor
has the additional immutable identity-schema label described above. Persistent
volume labels never carry a plan digest, so a plan update cannot make durable
PostgreSQL, object, runner, or desired-spec data look foreign.

#### Replaceable topology and `down`

Future convergence renders the canonical desired spec into a product-owned
Compose configuration. Its
containers, networks, initialization helpers, and generated-config volumes are
replaceable and carry the exact plan digest plus their role in the managed
namespace. Reconciliation refuses a mixed-digest or unknown-role topology,
replaces only resources whose ownership was proven, and inspects the result.
Mutable parallelism, profile selection, image identity, and render inputs are
therefore bound both to the durable desired document and to every replaceable
resource that realizes that plan.

`down` holds the engine lock, validates the identity, desired document, and
discovered resource union, then runs exact-project Compose teardown without
`--volumes`. It removes any separately managed replaceable generated-config
volume after proving its digest and lack of foreign attachment. It preserves the
identity anchor, desired-spec volume, PostgreSQL/object/runner persistent
volumes, and OS-held key material. `up` later reads and verifies the stored
desired document, renders its digest-bound topology, and reconciles it. Thus
`down -> up` retains `N`, profile, render inputs, data, and run history without a
host manifest.

#### Engine-scoped mutation lock

Every initialize, desired-spec update, up, down, reset, and ordinary
reconciliation mutation holds one deterministic engine lock container. The
lock uses an exact inert
configuration: digest-pinned helper image and fixed lock-holder command,
non-root user, read-only root, `network=none`, all capabilities dropped,
no-new-privileges, `restart=no`, auto-remove disabled, and no mount, device,
port, secret, credential, or user-supplied environment. Before starting it, the
manager attaches the helper's sole stdin stream. The fixed helper command reads
until EOF and then exits; it has no wall-clock or heartbeat lease that could
expire while an old Compose request is still mutating the daemon. A paused or
hung manager therefore retains a live lock and reports busy rather than
creating a second writer. Its managed labels contain only the lock role,
installation key, installation UUID, Compose project, and core operation ID
allowed for that role. The retained immutable container ID is the holder token;
there is no second local operation-identity type.

Successful creation is followed by exact inspection and retention of the
returned container ID. On graceful release, the manager first waits for every
mutation and child process to settle, closes stdin, waits for the helper to
stop, re-inspects the same ID, and removes it by ID, never by name. Unexpected
holder-stream loss makes the manager cancel its child process and stop issuing
requests, but it does not assert that an already accepted daemon operation was
retracted. The stopped exact-ID container remains as sticky
interrupted-operation evidence and automatic acquisition never deletes it. A
colliding live holder reports busy; a stopped holder reports recovery required.
The exceptional lock-recovery path must establish positive engine/process
quiescence and receive explicit operator authorization before removing that
exact ID. Unknown configuration or indeterminate liveness fails closed; elapsed
time alone never authorizes lock deletion.

#### Exact reset

This subsection specifies the future converged lifecycle reset after checkpoint
2C. It includes repositories, service topology, OS credentials, and the
Engine-held lifecycle lock; it does not describe checkpoint 2B.3's noninteractive
sealed-custody reset, whose narrower implemented contract is recorded below.
The converged reset runs under that lock and uses this ordered transaction:

Before confirmation, the command lists the installation-wide repositories,
history, repository-scoped secrets, and GitHub connections that will be lost;
reset is never presented as a checkout-local operation.

1. discover the union of deterministic names, exact Compose-project resources,
   all resources with the installation's managed labels, volume/network
   attachments, the desired-spec and identity volumes, and the lock ID;
2. prevalidate every candidate's role-specific managed-label allowlist,
   identity, digest where replaceable, driver/options where a volume, realized
   configuration, and attachment graph, plus the exact OS credential selectors
   and credential-store availability; any unknown, foreign, or indeterminate
   candidate stops before the first mutation;
3. tear down the exact replaceable topology, then exact persistent service and
   desired-spec volumes, re-inspecting after each bounded phase while preserving
   the identity anchor and lock;
4. delete the installation's exact OS credential/key entries; an indeterminate
   result preserves the identity anchor and lock for explicit recovery;
5. rediscover, require that only the validated identity anchor and lock remain,
   then remove the re-inspected identity anchor last among installation data;
6. re-inspect and release the exact retained lock ID last; and
7. immediately rediscover by deterministic names, Compose project, and managed
   labels and requery the exact credential selectors, reporting any residue or
   concurrently created installation rather than claiming success.

Ordinary resources are rediscovered by deterministic name and immutable labels;
the sole host-recorded resource ID is the authority-bound reset intent's
prevalidated helper ID, which is live-reinspected before exact-ID removal. No
reset path deletes by broad label query, removes a caller-supplied directory, or
uses a global prune.

### Workers and job sandboxes

The local stack starts one normal Automata runner with
`max_parallel_jobs=--workers`. The runner uses its existing stable slot journal,
spool, enrollment, mTLS, scheduling, cancellation, and result paths. Existing
issuance and redeem semantics create its identity; local setup may add a private
bootstrap transport, but not a second enrollment authority.

`LocalDocker` is a genuinely new, evaluation-only implementation of the
existing sandbox/provider interfaces. It creates sibling Linux job and service
containers through the host engine. The runner container is therefore
engine-admin-equivalent, which is acceptable only for an explicitly local,
trusted-repository evaluation mode.

The provider must:

- validate a Linux Docker Engine, negotiated API, engine identity, and
  architecture;
- use digest-pinned images for released profiles;
- label each job resource with installation, runner, operation, slot, profile,
  and specification identity;
- inspect the realized configuration before attach, mutation, or destroy;
- reject foreign name or label collisions without adoption or deletion;
- prohibit privileged jobs, host namespaces, devices, arbitrary host binds,
  and the Docker socket inside jobs;
- keep jobs off the control-plane dependency network; and
- clean exact owned resources without a global prune.

The initial truthful profiles are
`automata.local/ubuntu-24-04-amd64-container-v1` and
`automata.local/ubuntu-24-04-arm64-container-v1`. The local selector registry
maps aliases to those exact profiles and records the mapping as run provenance.

### Local worktree source

The new source boundary builds a deterministic, bounded archive from Git's
tracked and non-ignored worktree inventory. It rejects unsafe file types,
escaping symlinks, submodule ambiguity, sparse or assume-unchanged index state,
Unicode-normalization and full-case-fold collisions, and concurrent mutation.
The archive digest—not a possibly dirty HEAD—is the execution source identity.
The current check uses that digest only as its exact local revision and does not
derive or report repository identity. Durable local admission will require a
separately reviewed repository identity contract; its exact versioned byte
preimage and native mutation evidence must be qualified before it exists.
HEAD, dirty state, the selected workflow, inputs, and architecture decisions
remain explicit run provenance; none becomes local installation identity.

The planned sealed local-snapshot admission authority is accepted only in the
local deployment context. It will parameterize source location and archive
policy around the existing workflow frontend/compiler and then enter the
existing workflow service. It cannot create signed-GitHub evidence, publish a
Check Run, or enter the autonomous provider inbox. The available check stops
before this authority boundary.

Jobs receive a copy of the admitted immutable snapshot, never a writable host
bind. Workflows that require GitHub API authority fail with an actionable
instruction to connect GitHub or configure a separately supported credential.

### Required custody and optional native caches

The explicit state directory introduced by sealed init is durable authority,
not a cache: its stable directory and operation-lock identities bind the epoch,
and it retains one-time certificate custody. Copying, replacing, or deleting it
cannot silently adopt or recover an installation. A future platform port may
add a separate discardable inspection cache or redacted diagnostic evidence,
but that cache must not contain or select custody and must remain distinct from
the required state directory. Installation identity is also anchored in the
immutable external volume, while current status derives bounded live metadata
directly from the Engine rather than trusting a mirrored inventory.

If a later implementation genuinely needs a crash-safe host document, that
cross-cutting contract is designed separately after auditing the runner
journal, spool, CLI receipts, and provider persistence; none is treated as a
safe drop-in abstraction for another domain. Service data, certificates, and
server key material remain in exact engine volumes. Native filesystem code does
not recursively manage a parallel copy of the stack.

The existing managed-secret provider is the single durable runtime source of
truth for workflow secrets. Existing secret types, envelope encryption,
versioning, runner delivery, and masking remain unchanged. Local work adds:

- value-free comparison of compiler-discovered names with provider metadata;
- hidden, bounded, zeroizing interactive collection after workflow validation;
- an authenticated local-manager call to create or replace the existing
  provider version;
- a portable OS credential-store port based on the current Linux Secret Service
  implementation, with macOS Keychain and Windows Credential Manager adapters;
  and
- exact OS records for the local-manager credential and any small installation
  root required to unlock server bootstrap material.

Workflow values are not duplicated permanently in the OS credential manager or
a second local vault. This avoids Windows item-size limits and competing sources
of truth. The OS store protects bounded bootstrap/session material; PostgreSQL's
existing encrypted provider protects workflow values.

Before prompting, `local run` completes value-free workflow validation. For an
existing stack it queries provider metadata and prompts only for absent supported
names in sorted order. For a new stack it may collect statically referenced
values into bounded zeroizing memory, then creates the installation and writes
them directly into the provider before admission. Cancellation drops those
buffers. If reconciliation fails, no plaintext recovery file is created.

Built-in credentials such as `GITHUB_TOKEN` are classified separately and are
never prompted as ordinary repository secrets. Non-interactive and JSON modes
fail with missing names and exact `automata local secret set NAME --stdin`
recovery commands unless `--allow-missing-secrets` is explicit. Generated
Compose YAML, argv, status, debug output, and evidence contain references or
redacted values only.

### Network boundary

The human UI and local-manager API bind to loopback. PostgreSQL, object storage,
runner mTLS, Results, and the Docker socket are private to exact Compose
networks or mounts. Job containers use a separate network and reach Results
through an exact gateway/proxy; they cannot join the dependency network.

The rendered PostgreSQL certificate uses one deterministic reserved `.invalid`
DNS identity. The control plane selects the explicit
Web-PKI-plus-private-CA verify-full policy: SQLx's compiled public roots remain
in the declared trust union, while the reserved name prevents a public CA from
issuing a competing certificate. Database URLs contain explicit TCP fields and
no query parameters; ambient `PG*`, passfile, socket, and search-path authority
is rejected.

An optional public HTTPS origin is added only for GitHub connection. Its
gateway exposes the minimum human callback, setup, and webhook routes. A tunnel
provider must preserve webhook bytes and headers, persist its origin across
restart, and keep local-manager and dependency routes private.

### Engine and Docker Desktop trust

For doctor, init, and the future portable lifecycle, the active Docker context
and daemon are part of installation scope: those operations report the selected
context and verified engine identity, and do not silently adopt an installation
from another context. Checkpoint 2B.3 status/reset are the deliberate recovery
exception: they address only the fixed Linux Docker socket and ignore the
current CLI context. Future context migration remains a separate export/restore
operation rather than name reuse.

Anyone authorized to control that daemon is trusted as an installation
administrator. Docker access can mount or delete volumes, alter labels, inspect
containers, and bypass CLI ownership checks; labels and the engine lock prevent
accidents and cross-installation cleanup, not a malicious engine-authorized
user. Repositories run locally must also be trusted because the runner itself
has engine-administrator authority even though job containers do not.

On Docker Desktop, named volumes live inside the Desktop Linux VM. Qualification
must prove persistence across `down`, ordinary Desktop restart, host sleep, and
host reboot on the tested version. It cannot promise survival across factory
reset, uninstall, destructive Docker cleanup, VM-disk loss, or manual daemon
mutation; those operations can destroy installation identity, desired spec,
database, object, and runner volumes. The local stack is not a backup, and docs
must identify export/backup needs before those operations.

macOS and Windows commands require Docker Desktop's Linux engine. Windows
preflight additionally verifies Linux-container/WSL2 mode and fails before
anchor or lock creation when the daemon reports Windows containers. The current
context, volume driver/scope behavior, Desktop persistence boundary, and
factory-reset limitation are clean-host qualification evidence, not assumptions.

## Platform qualification matrix

The first host tuples are Arch Linux x86-64, Apple Silicon macOS ARM64, and
Windows x86-64. Intel macOS and Windows ARM are unsupported until native
artifacts and clean-host evidence exist.

| Gate | Arch Linux | Apple Silicon macOS | Windows x86-64 |
| --- | --- | --- | --- |
| Engine | Docker Engine | Docker Desktop Linux engine | Docker Desktop/WSL2 Linux engine |
| Job architecture | `linux/amd64` | `linux/arm64` | `linux/amd64` |
| CLI | Native `automata` | Native ARM64 `automata` | Native `automata.exe` from PowerShell |
| Workflow secret storage | Existing encrypted managed provider | Existing encrypted managed provider | Existing encrypted managed provider |
| CLI credential custody | Secret Service | Keychain | Credential Manager |
| Host-specific evidence | socket ownership, restart, exact teardown | paths with spaces, sleep/reboot, host gateway | Linux-container mode, path/drive handling, CRLF, shutdown/reboot |
| Job claim | Linux containers | Linux containers, not native macOS | Linux containers, not native Windows |

Docker Desktop is third-party software whose terms vary by organization and
use. macOS and Windows documentation must verify and disclose the current
prerequisites and must not imply universal free eligibility. Another engine may
join the quickstart only after the same lifecycle, provider, networking, and
clean-host gates pass.

A platform is qualified only when a clean host can:

- complete a first workflow with `automata local run` and no manual JSON,
  certificate, UUID, numeric ID, browser, or public ingress steps;
- run a common `.github/workflows` workflow through the existing compiler,
  scheduler, runner, and result store without editing or copying it;
- prompt once for an absent referenced secret, keep it masked, and reuse the
  existing managed-provider version without prompting on the next run;
- overlap three matrix jobs with `--workers 3` and show the runner's three
  existing execution slots;
- stream logs, expose durable history, and distinguish infrastructure failure
  from workflow conclusion;
- recover from a runner crash and complete stack restart;
- preserve desired `N`, profile, render inputs, and data across `down`, Desktop
  restart where applicable, and host reboot;
- expose the active context and documented factory-reset/data-loss boundary; and
- remove only exact owned state on confirmed `reset`.

## Merge checkpoints

Each checkpoint uses a sibling worktree from the latest merged `origin/main`.
Dependent work starts only after its predecessor merges. Every PR states its
contract, reused production surfaces, new trust boundary, non-goals, tests, and
live evidence. GitHub issues are not planning authority for this roadmap.

The order intentionally reaches an Arch end-to-end workflow early. Platform
polish, optional GitHub connection, and production deployment guides follow a
working local vertical slice.

### 1. Host preflight and accepted direction

Checkpoint 1 originally added `automata local doctor`, host/engine/Compose
discovery, a proposed platform state-root policy, stable read-only JSON, and
cross-target contract tests.

Gate at merge time: live Arch preflight passes; Apple and Windows targets
cross-check with warnings denied; proposed unsafe state roots and incompatible
engines fail actionably; and preflight creates no file, credential, or engine
resource.

Status: available. Host, Docker, Compose, and architecture behavior remains
useful and is retained. Checkpoint 2A removed public state-root resolution and
its readiness gate because checkpoint 2B.1 makes installation identity
engine-owned. Checkpoint 2B.2 later introduced an explicit operator-selected
private custody directory for epoch material and one-time certificates. That
directory is authority-bound durable state, not an optional or discardable
cache.

### 2A. Retire host lifecycle state and freeze the reuse boundary

Remove checkpoint 1's unused public state-root option and JSON field before any
mutating local command depends on them. Record the reuse-first architecture and
delete the draft host installation manifest, mirrored resource inventory,
local-specific operation ID, broad lifecycle state machine, and duplicated
platform filesystem framework. Do not publish an engine label schema until a
real engine adapter consumes and integration-tests it. Do not publish a
repository-identity algorithm until the `LocalSnapshot` admission adapter
consumes and integration-tests it. Do not extract the runner journal into a
premature generic state library: journal, spool, CLI receipt, provider, and
installation identity have different custody and recovery contracts.

This checkpoint changes only the read-only preflight and the accepted design
direction. It does not create, inspect, adopt, or delete engine resources and
does not claim that `local up` is available.

Gate for the checkpoint 2A diff: `local doctor` rejects the removed
`--state-dir` option, JSON schema 2 has no state path or state-path issue codes,
preflight creates no host or engine state, all reader-facing docs agree, and the
focused native and package-scoped cross-target checks pass. The diff contains
no unconsumed engine identity API, host lifecycle journal, or new platform
filesystem substrate.

### 2B. Engine identity and desired-spec adapter

Land the first Docker Engine adapter and the engine-owned identity and desired
intent contracts in two independently reviewable, strictly ordered slices.
Installation identity is a repository-agnostic deployment/capacity boundary;
repository and snapshot identity remain questions for later local admission.
Compose and fresh engine inspection are resource truth throughout, and no host
manifest mirrors them.

#### 2B.1. Pinned Docker context and immutable identity anchor

Snapshot the selected Docker context before daemon probes, retain its exact
validated local Unix-socket or Windows-named-pipe endpoint, pin subsequent
daemon probes with that exact `--host` value, and connect the direct Engine API
adapter only to that endpoint. Reverify the expected engine identity before
mutation. Define the
exact versioned byte preimage from the canonical installation selector to the
full selector key, deterministic Compose project, and deterministic anchor
name. Create only the external immutable identity-anchor volume in this slice;
do not create, label, mount, or otherwise anticipate the desired-spec volume or
any realized topology.

The anchor's exact managed-label allowlist contains only its managed marker,
identity schema, installation UUID, full selector key, Compose project, and
anchor resource kind. The selector preimage contains no repository, checkout,
worktree, or source input. The adapter exposes only the high-level inspection
and create-or-adopt operations consumed here; generic volume mutation, pull,
remove, reset, and lifecycle APIs do not land speculatively.

Gate: create and adoption always re-inspect the deterministic anchor name after
`volume create` and require local driver/scope, empty options, no bind, the
exact anchor managed-label allowlist, and no container attachment. Foreign
name, full-key, project, resource-kind, or truncated-name collisions fail
without a second mutation. Changing the active context cannot redirect an
already pinned adapter; a changed engine identity at the retained endpoint
fails closed.
Stateful fake-daemon and ignored live-Docker tests exercise the public adapter,
including a create response that cannot be trusted, rather than testing value
objects in isolation. The slice creates no desired-spec volume, helper
container, Compose topology, host manifest, or repository binding.
Doctor JSON schema 3 reports the bounded selected context name without exposing
the retained endpoint URI, and CLI process tests prove daemon probes receive the
exact validated `--host` value.

#### 2B.2. Verified sealed init and fixed materializer

The x86-64 Linux-only `automata local init` consumer requires an explicit
absolute private state directory and an explicit `file:ABS` release catalog. It
accepts only the exact Docker authority at
`unix:///var/run/docker.sock`. The catalog is operator-selected release
evidence: init verifies its canonical structure, source-contract digest, closed
profile/image set, and exact no-follow sibling candidate, but does not invent an
OIDC-authentication claim for the selected file. Registry roles retain the
catalog's top-level provenance while Docker qualification uses the exact
linux/amd64 platform reference. The service-proxy candidate retains its fixed
GHCR provenance name, is deeply verified before mutation, and is converted to a
bounded hybrid Docker-load archive. Its daemon-local tag is accepted only with
the mutually exclusive classic config-ID/no-RepoDigest or containerd
manifest-ID/exact-RepoDigest representation.

State custody uses trusted-ancestry, no-follow opens, exact invoking-user
ownership/modes, one held process lock, one 32-byte material root, canonical
epoch and selection records, and exact one-time certificate bytes. A
domain-separated state-authority digest binds the stable state-root identity
and the verified held lock-file identity into the epoch. This assumes trusted
stable local-filesystem custody: copying, restoring, remounting, or replacing
the lock changes authority and requires a future reset or migration. The
material root is KDF root derivation input and is never copied verbatim into a
credential.

After epoch validation and before image qualification, helper recovery, or any
other role mutation, init creates or exactly adopts Desired as the atomic guard
among the twelve owner-specific persistent volumes. Labels bind installation
identity, material schema/generation, role, and immutable epoch fingerprint,
never the desired plan digest. A fixed-purpose materializer uses the exact
qualified Automata image, no network, a read-only root, UID 0,
`CapDrop=ALL`, only `CHOWN` and `DAC_OVERRIDE`, and exactly the twelve volume
mounts. It receives one bounded canonical request over attached stdin; no
secret request is stored in a writable image layer or temporary request mount.
Static role manifests publish last after content, metadata, link, certificate,
and key validation; dynamic owner roots remain empty until future convergence.
Missing or conflicting established custody is reset required, while
uncommitted fixed crash temporaries are safely rebuilt.

The slice persists canonical credential-free desired intent, including the
imported service-proxy tag plus both acceptable OCI IDs for later reattestation.
It has no renderer, produces no Compose document, and then stops. Init invokes
no Compose operation and starts no control plane, relay, bootstrap, database,
object store, or runner. `local status` is existing-only and nonrepairing: it
reports `recorded_sealed` only after canonical host custody and exact bounded
Engine metadata agree, while explicitly leaving volume contents uninspected.
`local reset` requires an absolute state directory and `--yes`, authorizes an
authority-bound canonical epoch only after exact complete post-Desired Engine
custody agrees, completes a durable reconciling deletion transaction, and
retains images plus the custody root and operation lock. Safe missing or
malformed non-authority host records do not strand cleanup. Retained image
absence or retagging does not block custody deletion. `up` and `down` remain
absent. Stateful
recovery, adversarial parser and filesystem tests, strict helper-inspection
tests, and live Docker portable-load qualification cover the sealed boundary.
This completes checkpoint 2B's material/desired-intent handoff without claiming
convergence.

#### 2B.3. Read-only recorded status and exact established reset

Status acquires an existing-only shared operation lock and performs no state
repair, helper creation, or volume-content inspection. Its stable human and JSON
reports distinguish incomplete custody, recorded sealed metadata, and durable
reset progress without exposing secret values. Reset requires explicit `--yes`
and a full all-before-any preflight: an authority-bound canonical epoch,
positive complete post-Desired ownership, the sealed-epoch-derived contract for
any present init helper, the identity anchor and twelve roles, no foreign
attachments, and no unexpected related volumes, containers, or networks.
Material-root and certificate bytes never authorize deletion; missing or safely
malformed non-authority records remain removable evidence, while a canonically
valid conflicting selection or materialization record blocks before mutation.
That conflict check covers both final records and readable fixed crash
temporaries; a second different valid authority epoch also blocks, and a
temp-only epoch must first be published by exact init replay.
Both commands connect directly to the fixed Docker Unix socket with pinned API
1.48 and validate/reverify daemon identity, Linux/amd64, Engine 28+, and API
range. Docker CLI availability, its current context, `DOCKER_API_VERSION`, and
the Compose plugin are deliberately irrelevant to inspection and teardown;
init and public doctor retain their full CLI/context/Compose preflight.
The reset-only reader pins fixed names with no-follow path descriptors and
accepts only invoking-user-owned regular single-link files with owner-only,
non-special permissions; unreadable non-authority files are opaque, while epoch
and reset intent must remain owner-readable. Status retains the exact `0600`
health contract. Pre-guard and copied custody never authorize Engine mutation.

The authority- and closed-topology-bound reset intent is durable before the
first deletion and is self-contained for replay even when other host records
are later lost or corrupted. Replay removes an exact stale init helper first,
the eleven non-Desired roles, Desired, and the identity anchor, reconciling
ambiguous outcomes to inspected absence. Cancellation after intent is latched
while the complete transaction finishes; operation errors still dominate. Only
after Engine absence is rediscovered are whatever safe fixed host records
remain removed with epoch and reset intent last. Imported images, the state
directory, and the original verified operation lock remain.

### 2C. Convergent Compose lifecycle

Build on the completed 2B.2 sealed desired-intent/material handoff. Introduce
the renderer and its complete executable command surface together, then add
convergence, digest-labeled replaceable topology, the inert ID-held engine lock,
union discovery, `up`, converged live status, and `down`. The command layer
remains private until these operations are convergent and their destructive
boundary is proven.

The renderer may reuse the current hidden image boundary
`automata internal object-store ensure-bucket`, but it must not emit references
to absent readiness, bootstrap, or relay commands. Those fixed hidden
operations and the renderer that invokes them land and qualify together; the
renderer does not invent a shell client, test helper, compatibility alias, or
placeholder service-init command.
The initializer and server share the production S3 connection parser and the
sole validated-config-to-store AWS SDK construction boundary. Runner product
schema 8 independently requires the same closed
trust choice for every runner-side S3 client. Local HTTPS rendering selects
exact private-CA trust and mounted bounded `SecretSource` file references for
the CA and credentials on all three surfaces; the private root is never merged
with Web PKI roots. Initialization may create the exact bucket only after
`HeadBucket` reports not found, and creation conflicts require a successful
final `HeadBucket` under the same total deadline.
Every non-`us-east-1` bucket creation carries the exact validated region as its
S3 `LocationConstraint`; `us-east-1` alone omits it.

Gate: persistent volumes never carry a mutable plan digest; every replaceable
resource carries the current digest; unknown managed keys, unexpected roles,
and mixed digests fail closed. Concurrent mutation tests prove graceful
ID-based release only after child quiescence, busy-live behavior,
manager-crash/EOF retention as a stopped recovery-required record, cancellation
on holder-stream loss, and no automatic or age-based stale deletion. Reset tests
prove all-before-any validation, ordered topology and OS-credential deletion,
anchor-last, lock-last, and immediate reinspection. Deleting an optional host
cache cannot affect installation identity or recovery. `down -> up` preserves
the desired `N`, profile, render inputs, data, and run history.

### 3A. `LocalDocker` provider

Status: evaluation provider and its closed Results gateway foundation are
implemented behind the existing sandbox/provider interfaces. Runner product
schema 8 binds the sealed desired-plan digest and the exact classic/config-ID
or containerd/manifest-ID representation of the imported proxy. The provider
requires Docker Engine 28/API 1.48 and consumes one externally provisioned
plan-labeled transit network, running numeric Results target, and protocol-2
proxy image. It
deterministically maps profile admission plus job slots 1 through 256 to
disjoint `/29` front networks and transit addresses. Jobs join only their front
network; the proxy alone bridges that front to the internal transit at fixed
port 8081, with no public egress or external DNS.

Create, attach, inspect, and endpoint operations re-attest the imported-image
representation, shared transport, and every attached peer under one bounded
cancellation-aware budget. Destroy
skips shared-transit and container-runtime/image re-attestation, so damage there
does not by itself block removal of containers with exact immutable custody.
Exact front-network drift blocks destroy before mutation; a foreign endpoint
prevents deletion of the front network after owned containers are removed. The
provider does not own or delete the shared transit or Results listener.

Gate: shell and JavaScript-action sandboxes execute; restart attach and exact
cancellation work; realized configuration is inspected; foreign collisions
fail without mutation; prohibited privilege, namespace, bind, device, socket,
and network requests fail closed; output/copy bounds hold; and destroy leaves no
owned job resources. The future lifecycle-created, Compose-external
transit/listener, local repository authority, Results/cache URL and token
injection, and `automata local run` composition remain separate gates.

### 3B. `LocalSnapshot` source adapter

Add bounded Git worktree snapshotting and a provider-distinct local source
authority. Parameterize source location/archive loading around the existing
GitHub Actions frontend and compiler. Feed compiled requests into the existing
workflow service, admission transaction, scheduler, cancellation, logs, and
history. Define a durable repository identity only when admission consumes and
qualifies it, never as an engine installation binding. `automata local check`
is the read-only source-analysis precursor and intentionally exposes neither
repository identity nor admission authority.

Status: read-only source validation available, admission gate incomplete. The
library seals Git's tracked plus non-ignored live-worktree inventory through
pinned no-follow ancestor handles, normalizes tracked symlinks from Git mode,
detects mutation, and hashes the exact deterministic gzip bytes consumed by
shared repository archive discovery. Portable component-trie bounds and
aliases, link cycles, sparse or assume-unchanged index flags, and workflow
namespace aliases fail closed. Ignored paths are classified through one
bounded NUL-safe batch per worktree scan. Source capture currently fails closed
on Windows until exact native mutation evidence is qualified.

Only direct `.github/workflows` members are eligible, with an exact canonical
selector required when discovery is ambiguous; `.ci`, filename, stem, and
display-name fallbacks do not exist. `automata local check` composes local event
compilation, reachable same-snapshot reusable-workflow loading, the shared typed
call-graph traversal, root-secret propagation, snapshot revision, and local
source provenance without entering admission. Remote and dynamic reusable calls
fail explicitly. Its only current event is an explicit local
`workflow_dispatch`; it cannot synthesize GitHub delivery evidence. Reports
contain value-free external names and closed built-in requirements, never
credential or input values, absolute paths, archive bytes, environment values,
or repository identity.

Gate: clean and dirty worktrees produce deterministic digests; ignored files,
`.git`, sockets, devices, escaping symlinks, submodule ambiguity, concurrent
mutation, oversized archives, and case collisions fail closed; direct
`.github/workflows` files and same-snapshot reusable workflows use the existing
compiler and canonical call-contract traversal; hostile Git environment,
cancellation, bounds, redaction, and dirty-worktree fixtures pass; no source
operation mutates Git; and no local subject can enter signed-GitHub admission or
create a GitHub Check. Durable repository identity and Windows source capture
remain separate future qualification gates rather than weak checkpoint claims.

### 3C. Arch secretless vertical slice

Have the product lifecycle adapter compose the external dependencies, control
plane, initialization service, and one ordinary runner. Use existing enrollment
issuance/redeem and configure `max_parallel_jobs=N`. Wire `LocalDocker` and
`LocalSnapshot` through the production pipeline. Expose the smallest complete
`automata local run`, `status`, `down`, reset, infrastructure logs, and run
history needed to operate the slice. Start with workflows requiring no user
secrets.

Gate: from a clean Arch state, `cd fixture && automata local run` completes a
common `ubuntu-latest` shell and JavaScript-action workflow without GitHub, a
browser, or public ingress; `--workers 3` overlaps a three-entry matrix on the
existing runner's three slots; the engine config volume retains the canonical
desired digest while Compose is realized-resource truth; repeated run/up is
convergent; down removes replaceable topology and up restores the same
three-slot/profile plan; Ctrl-C, explicit cancellation, runner restart, exact
reset, and the positively fenced interrupted-lock recovery path work; and the
CLI never bypasses admission or invokes the provider directly.

This is the first checkpoint allowed to describe local execution as available
to contributors.

### 4A. Portable CLI credential custody

Extract the existing Linux Secret Service implementation behind one bounded
credential-store port and add native macOS Keychain and Windows Credential
Manager adapters. Define exact-match schemas for local-manager credentials and
small installation bootstrap roots only.

Gate: native tests or faithful platform fixtures prove exact create, load,
replace, and delete; ambiguous entries and locked/unavailable stores fail
closed; bytes never enter argv, implicit environment variables, debug output,
or evidence; helper cancellation is bounded; and a missing root never causes
silent regeneration.

### 4B. Existing-provider secret onboarding

Add value-free comparison of compiler-discovered credential requirements with
the existing managed-provider metadata, hidden first-run collection, direct
create/replace through the existing provider API, and the local secret/variable
commands. Reuse existing envelope encryption, versioning, runner delivery,
masking, and deletion. Do not add a second durable vault or local provider
protocol.

Gate: a first referenced user secret prompts once after workflow validation,
remains in bounded zeroizing memory, reaches the existing provider, and is
masked through all log/output variants; the second run does not prompt;
canceled collection creates no plaintext recovery state; non-interactive and
JSON modes fail with names and exact stdin recovery commands; list/status are
value-free; variables remain separate; replacement, deletion, restart, and
reset use existing provider semantics.

### 4C. Conditional cross-domain host-state consolidation

After the Arch vertical slice, audit runner journal, runner spool, CLI credential
receipts, provider persistence, and any residual local host files as separate
security domains. Only if at least two have the same durability, confidentiality,
locking, descriptor, and recovery contract should a dedicated foundational PR
extract a shared primitive. This work is separate from the local supervisor and
must not block it merely to create an abstraction.

Gate, when the checkpoint is needed: the audit states which contracts are
identical and which must remain separate; callers retain their domain schemas
and fault semantics; native Linux, macOS, and Windows tests exercise the shared
lowest-level behavior; migration is explicit; and no secret-bearing spool or
journal becomes readable through a weaker local-installation API. If the audit
finds no honest common contract, record that decision and do not add a library.

### 5. Arch local-first qualification

Confirm or create the designated dummy repository under `AlexanderDzhoganov`,
then test its local checkout without installing a GitHub App. Commit a redacted,
executable smoke harness and evidence format covering `.github/workflows`,
exact canonical selectors, typed inputs, a user secret, a variable, dispatch,
truthful local push once that event exists, cancellation, restart, persistence,
and cleanup.

Gate: the one-command run works from clean state; the second secret-bearing run
does not prompt; `--workers 3` overlaps three jobs; history and logs are useful;
`down -> up` preserves identity, desired digest, `N`, profile, and data; and the
ordered reset deletes only the prevalidated topology, credentials, anchor, and
fixed custody records, retaining the state directory and original operation
lock with no Engine residue on immediate reinspection.

### 6. Apple Silicon macOS qualification

Build and privately stage native ARM64 CLI plus native ARM64 product, runner,
job, and JavaScript-action images. Qualify Docker Desktop, Keychain, paths with
spaces, hidden prompting, host gateway behavior, sleep, restart, and reboot on
the Mac mini. Keep public artifacts and GitHub connection disabled.

Gate: the same Arch smoke contract passes with `--workers 1` and `3`, without
x86 emulation or Linux Secret Service assumptions. Native tests cover locked
Keychain behavior, private discardable cache/lock creation, immutable external
identity-volume labels, atomic desired-spec updates, interruption, and exact
reset. The selected context and local driver/scope are reported; identity,
desired spec, and persistent data survive down/up, Desktop restart, sleep, and
host reboot. Deleting a separate optional inspection cache leaves discovery
correct, while missing or moved durable custody fails closed until an explicit
migration or reset path authorizes recovery. The guide records current Docker
Desktop prerequisites and terms, engine-authorized-user trust, and the
factory-reset/uninstall data-loss boundary.

### 7. Windows x86-64 qualification

Build the native Windows CLI and qualify it from PowerShell with Docker
Desktop/WSL2 Linux-container mode, Credential Manager, hidden prompting, drive
and space-containing paths, CRLF, process shutdown, restart, and reboot. Runner
and jobs remain Linux containers.

Gate: the same smoke contract passes with `--workers 1` and `3`; native tests
cover locked Credential Manager, private discardable cache/lock creation,
junction and reparse-point refusal where a cache path is used, long paths,
immutable external identity-volume labels, interruption, and exact reset.
The selected context, Linux daemon mode, and local driver/scope are reported;
identity, desired spec, and persistent data survive down/up, Desktop restart,
and host reboot. Deleting a separate optional inspection cache leaves discovery
correct, while missing or moved durable custody fails closed until an explicit
migration or reset path authorizes recovery; no native Windows execution
provider is involved. Docker Desktop prerequisites, terms,
engine-authorized-user trust, and the factory-reset/uninstall data-loss boundary
are current.

### 8A. Frozen signed release candidate

Build checksummed native CLIs and digest-pinned multi-architecture Linux images,
SBOMs, and provenance. Apply Developer ID signing/notarization/stapling and
Authenticode before qualification. Freeze every artifact and image identity;
keep publication disabled.

Gate: build inputs and signing custody are reviewed, installer tests consume the
private candidates, every identity is recorded, and no documentation claims an
unpublished URL exists.

### 8B. Exact-final-byte qualification

Install the frozen candidates on clean Arch, Apple Silicon macOS, and Windows
x86-64 hosts and repeat the complete local matrix. Any rebuild, resign,
renotarization, or repackaging returns to 8A.

Gate: the exact final bytes pass signature, checksum, SBOM, provenance,
no-Rust-toolchain install, one-command run, secret prompt/reuse, three-slot
parallelism, cancellation, crash/restart, down/up, and exact reset on all three
hosts.

### 9. Public artifacts and onboarding documentation

Stage the root README and documentation information architecture against the
frozen candidates, rehearse publication/rollback, publish the exact qualified
artifacts, verify them publicly, and then activate the documentation. The first
README procedure becomes the tested local flow.

Gate: public download and installer smoke tests pass on all three hosts; the
README commands are exercised by the same smoke harness; links and anchors
pass; no Rust toolchain is required; and contributor assembly, native execution
hosts, and production deployment remain clearly distinguished.

### 10. Optional public-origin boundary

Add a restricted public HTTP gateway, persisted public-origin state,
user-supplied origins, a fake tunnel, and one evaluated default tunnel after its
privacy, licensing, and cross-platform behavior are accepted.

Gate: only intended routes are forwarded; webhook headers and body remain
byte-exact; local-manager, Results, runner mTLS, dependencies, and Docker remain
private; the hostname resumes across down/up, sleep, and reboot; credentials are
redacted; and an unstable origin fails before App creation.

### 11. Optional GitHub repository connection

Implement `automata local github connect [OWNER/REPOSITORY]` with the GitHub App
Manifest flow, exact personal/organization routing, callback state,
HMAC-verified installation capture, API verification, exact repository
selection, staged provider/human-auth configuration, one-use `/setup`, portable
local-manager session custody, reconnect, status, and disconnect. Reuse the
existing signed GitHub provider and do not reenroll local runners.

Gate: emulator and live tests cover forged IDs, expired/replayed state, partial
retry, permissions/events, authority failure, public/private and
multi-repository installations, redaction, wrong setup identity, restart, and
disconnect. No manual App fields, numeric IDs, registry JSON, or certificate
steps are required. The original local worktree flow still works disconnected.

### 12. Connected-GitHub qualification

Install the App only on the designated `AlexanderDzhoganov` dummy repository
and exercise authenticated remote-ref and webhook paths on the three qualified
hosts.

Gate: signed deliveries are durably admitted through the existing provider; a
completed Check has the exact Details link; queued/running/completed state
agrees; fork heads follow the explicit local evaluation policy; public origin
and connection resume; and event support is claimed only when backed by live
evidence.

### 13. Production Docker Compose deployment

Build a production-oriented Compose topology separate from the engine-admin
local evaluation stack: TLS reverse proxy, external or explicitly development
PostgreSQL/S3 choices, secret files, persistence, probes, backup/restore,
upgrade/rollback, and supported hardened runner choices. Reuse the same product
containers and configuration decoders, not the local Docker provider.

Gate: real TLS/webhooks, configuration validation, restart persistence, backup
restoration, dependency failure, non-root containers, and exact digest pins
pass. The guide states the topology's threat model and non-goals.

### 14. Linux systemd deployment

Add control-plane units, credential and tmpfiles packaging, runner lifecycle
operations, and a generalized hardened rootless-Podman runner-host guide. The
local engine-admin provider is forbidden.

Gate: clean-VM install, `systemd-analyze verify`, reboot, key/certificate
rotation, runner drain/recovery, backup restoration, and documented upgrade and
rollback pass.

### 15. Helm/Kubernetes deployment

Deployment assets belong in an independently owned infrastructure repository,
not this product source tree. That repository can start with one control-plane
replica, external PostgreSQL and object storage,
existing secret references, ingress, runner mTLS, probes, metrics,
NetworkPolicy, and explicit migration behavior. Kubernetes runners retain an
independent experimental gate; the chart never mounts the local engine socket.

Gate: chart lint/schema/template, kind or k3d integration, upgrade/rollback,
dependency outages, secret non-disclosure, and documented network exceptions
pass.

### 16. Cloud references

Publish these from an independently owned infrastructure repository: one
provider-neutral validated topology, then one infrastructure change per cloud.
Start with AWS because PostgreSQL and S3 match existing storage
boundaries. GCP and Azure require a proven S3-compatible store or a separately
implemented native object-store adapter. Terraform/OpenTofu follows a real
manual deployment.

Each cloud gate names a separately qualified hardened runner provider and
includes DNS/TLS, webhook delivery, parallel execution, backup/restore,
upgrade, teardown, security review, and an explicit cost inventory. The local
engine-admin provider is never accepted as the production runner.

## Documentation migration

User documentation moves only as tested product paths become available. Stable
high-traffic files remain landing pages so existing links do not break. Target
ownership is:

```text
docs/local/                    quickstart, lifecycle, worktree source, secrets
docs/integrations/             optional GitHub connection and provider guides
docs/platforms/                advanced native execution-host guides
docs/reference/                configuration and command reference
docs/maintainers/roadmaps/     plans, audits, and conformance work
```

| Current source | Disposition |
| --- | --- |
| Root `README.md` | Make the tested local flow its first procedure only after checkpoint 9 publishes qualified artifacts |
| `docs/README.md` | Keep as the stable index and update categories when destinations exist |
| `docs/getting-started.md` | Keep as a short chooser; move exact local steps to `docs/local/` |
| `docs/development.md` | Retain contributor build/test material; remove duplicated reader onboarding after publication |
| Authentication and provider guides | Retain operator detail; move local credential custody to `docs/local/` and App setup to `docs/integrations/` |
| Observability | Retain the product metrics contract; collector configuration and runbooks belong to infrastructure owners |
| Compatibility and conformance docs | Update only from executable gates, never from roadmap intent |
| Architecture, ADR, security, governance, and release docs | Preserve as reference/maintainer material and repair links during migration |
| Parity plans and dated audits | Move under maintainer ownership when touched; archive only after remaining decisions live elsewhere |

Cleanup will remove stale CLI examples and contradictory quickstarts, not
useful operational history. The provider example and runner profiles must be
reconciled against executable configuration. Publication guards remain until
the exact signed final-byte matrix passes.

The final README quickstart is generated from or tested by the same Arch,
macOS, and Windows smoke harness. Documentation records availability; it is not
the evidence that creates it.
