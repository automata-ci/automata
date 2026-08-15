# Local installation and deployment roadmap

- Roadmap status: Active
- Available slice: read-only `automata local doctor` and source-only
  `automata local check` from a reviewed source checkout
- Current implementation checkpoints: 2B.2a shared sandbox-guest protocol v4
  file primitives, plus the read-only source-validation portion of 3B
- Last completed engine-adapter checkpoint: 2B.1, pinned Docker context and
  immutable identity anchor
- Date: 2026-08-15

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
automata local run ci --workers 3
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

The workflow positional argument is optional only when exactly one direct
workflow exists. Otherwise callers supply its exact canonical
repository-relative path. Filename, stem, and display-name aliases are not a
second selector grammar.

Direct `.github/workflows/*.yml|yaml` and `.ci/workflows/*.yml|yaml` files are
eligible; nested files are not initially. Supporting `.github/workflows` in the
explicit local source adapter does not change the autonomous GitHub provider's
discovery policy. Local compatibility also does not imply full GitHub Actions
parity: unsupported syntax, actions, events, dynamic secret references, and
runner selectors fail during read-only inspection.

The first event set contains declared `workflow_dispatch` and a truthful local
`push` context. A local event is never represented as a signed GitHub delivery,
and it never produces a GitHub Check. `actions/checkout` resolves to the admitted
snapshot; it does not silently fetch another revision or invent a
`GITHUB_TOKEN`.

The initial selector registry accepts `automata-local`, `ubuntu-24.04`, and a
release-pinned `ubuntu-latest` alias. It records the exact local image, OS, and
architecture. On Apple Silicon, substituting the ARM64 companion profile for an
Ubuntu AMD64 alias requires explicit interactive confirmation or
`--allow-architecture-substitution`; `automata-local` directly selects the
host-native profile.

## Command structure

The target command surface keeps local lifecycle, runs, secrets, and optional
integrations in distinct namespaces:

```console
automata local doctor [--json]
automata local check [WORKFLOW] [--input NAME=VALUE]... [--json]
automata local run [WORKFLOW] [--workers N] [--event EVENT]
  [--input NAME=VALUE]... [--allow-architecture-substitution]
  [--non-interactive] [--allow-missing-secrets] [--json]

automata local init [--workers N]
automata local up
automata local status [--json]
automata local down
automata local reset [--yes]
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

Every command that addresses an installation accepts the same
`--installation NAME` selector. Host-only `doctor` and source-only `check` do
not invent or select an installation. Any native cache location is an internal
platform choice, not installation identity or a public lifecycle selector.
An installation is a repository-agnostic deployment and runner-capacity domain:
the same selected installation may admit snapshots from different repositories,
and repository identity never enters its selector key, engine labels, Compose
project, or desired specification. Repository identity is derived and retained
with `LocalSnapshot` admission instead. Repositories sharing one installation
form one trusted set and share its runner capacity; separate installation names
are useful for distinct trust sets or destructive test environments, but names
on the same administrator-controlled daemon are not a hostile-code isolation
boundary.
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
| `automata local check` | Deterministic bounded live-worktree archive, physical common-Git-directory identity, explicit workflow-location policy, local-only manual event compilation, reachable same-snapshot reusable workflows with typed call-graph and root-secret propagation, and value-free credential discovery | It is deliberately read-only; local admission, scheduling, execution, and GitHub Checks remain absent |
| `automata-ci-local` Engine adapter | Exact-endpoint Docker connection plus strict identity-anchor inspect/create/adopt with fake and opt-in live tests | No product command calls the mutation API until desired intent and convergent lifecycle contracts land |
| `automata-ci-sandbox-guest` | Protocol 4 bounded optional read and Unix durable compare-and-swap atomic commit, plus a non-root helper-image data mountpoint | No local adapter yet mounts a desired-spec volume or invokes these primitives |
| Control-plane configuration and container build | Complete server configuration and product images | Configuration and bootstrap are manual and Unix-oriented |
| GitHub workflow crates | Frontend, compiler, typed workflow contracts, reusable-workflow handling | They need a separately authorized local snapshot source |
| Workflow service | Credential requirement discovery, admission, and orchestration boundaries | It needs local provenance as an additional source authority |
| Runner and runner journal | Enrollment/redeem, mTLS protocol, durable slots, result delivery, `max_parallel_jobs` | There is no evaluation-only Docker Engine job provider |
| Secret and key-management crates | Secret domain, versioned providers, envelope encryption, delivery, and masking | CLI credential custody is Linux-only and local prompting is absent |
| Rootless Podman, macOS VM, and native Windows providers | Hardened production or advanced execution profiles | None is the portable Linux-container evaluation provider |
| Release automation | Guarded Linux x86-64 release flow | Native CLI artifacts and multi-architecture images are not public |

`automata preview` remains a dependency-free SSR and health preview. It is not a
local CI stack and must remain clearly separate from `automata local run`.

## Reuse decisions

The following decisions are constraints, not implementation suggestions. A PR
that cannot reuse one of these paths must document the missing contract and
improve the shared abstraction instead of creating a local duplicate.

| Concern | Required reuse | Permitted local addition |
| --- | --- | --- |
| Operation identity | `automata_ci_core::OperationId` | Local provenance fields around the shared ID |
| Service lifecycle | Docker Compose convergence, health, project labels, and engine inspection | A deterministic project specification and CLI supervisor |
| Installation identity | A deterministic external Docker volume with immutable identity labels | Exact create/adopt inspection and engine-scoped serialization |
| Desired specification | Canonical product configuration and Compose rendering contracts | One minimal value-free document in an engine-managed config volume |
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
bounded immutable snapshot ---- LocalSnapshot authority
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

A separate engine-managed config volume will persist one schema-versioned,
credential-value-free desired-spec document. The exact version-one field set is
deliberately not frozen before renderer version one has a closed input contract.
Installation binding, requested capacity, local profile and architecture
selection, immutable image identities, and rendering decisions are examples of
the concerns that contract is expected to settle, not a final schema. The
frozen document must contain every input needed to reconstruct the same stack
after `down`, reject unknown or unbounded extension data, and contain no
repository identity, credential value, container or network ID, live phase,
daemon version, or resource inventory.

The frozen schema will define its canonical encoding and plan digest together.
The shared sandbox guest protocol supplies bounded optional reads and a durable,
compare-and-swap atomic file commit. The supervisor will run only an already
present, digest-pinned helper image, inspect each exact helper container ID, and
mount only the config volume at the image's `65532:65532`-owned data mountpoint. A
desired-spec update will hold the engine lock, compare the expected prior
state, commit, then read through a fresh helper and verify canonical decode,
installation binding, and recomputed digest. An interruption therefore leaves
either the prior complete document or the next complete document, never a
partial desired spec; an ambiguous or stale comparison never becomes an
unconditional overwrite. Matching readback after an ambiguous commit is not
durability proof by itself: the supervisor issues a fresh compare-and-swap
commit and requires its synchronization-closing `AlreadyCurrent` or
`Committed` acknowledgement before reporting success.

Every persistent service volume carries only immutable Automata
contract/identity/role labels: managed marker, contract and resource kind,
installation UUID, selector key, project, and exact role. The identity anchor
has the additional immutable identity-schema label described above. Persistent
volume labels never carry a plan digest, so a plan update cannot make durable
PostgreSQL, object, runner, or desired-spec data look foreign.

#### Replaceable topology and `down`

The canonical desired spec renders a product-owned Compose configuration. Its
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

Every desired-spec update, up, down, reset, and ordinary reconciliation
mutation after the immutable installation anchor exists holds one deterministic
engine lock container. Deterministic, post-inspected create-or-adopt of the
anchor and empty desired-spec volume remain separately race-safe primitives.
The lock uses an exact inert configuration: digest-pinned helper image and
fixed lock-holder command,
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

Reset runs under that lock and uses this ordered transaction:

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

No reset path trusts resource IDs from a host file, deletes by broad label
query, removes a caller-supplied directory, or uses a global prune.

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
The source adapter also derives the canonical repository identity
used by local admission. Before assigning that provenance contract version 1,
its exact versioned byte preimage must define Git worktrees, symlinks,
non-Unicode paths, case behavior, checkout moves, and clones on Linux, macOS,
and Windows. HEAD, dirty state, repository identity, selected workflow, inputs,
and architecture decisions remain explicit run provenance; none becomes local
installation identity.

`LocalSnapshot` is a distinct admission authority accepted only in the local
deployment context. It parameterizes source location and archive policy around
the existing workflow frontend/compiler and then enters the existing workflow
service. It cannot create signed-GitHub evidence, publish a Check Run, or enter
the autonomous provider inbox.

Jobs receive a copy of the admitted immutable snapshot, never a writable host
bind. Workflows that require GitHub API authority fail with an actionable
instruction to connect GitHub or configure a separately supported credential.

### Internal native cache and secrets

The implementation may use a platform-standard native directory for a
process-local coordinator lock, discardable inspection cache, or redacted
diagnostic evidence. That path is internal and is not accepted as a public
installation selector. Deleting it cannot create, adopt, lose, rebind, or reset
an installation. Installation identity comes from the immutable external volume
labels, desired intent comes from the digest-bound config-volume document, and
live state comes from inspected Compose topology.

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

An optional public HTTPS origin is added only for GitHub connection. Its
gateway exposes the minimum human callback, setup, and webhook routes. A tunnel
provider must preserve webhook bytes and headers, persist its origin across
restart, and keep local-manager and dependency routes private.

### Engine and Docker Desktop trust

The active Docker context and daemon are part of installation scope. Doctor,
status, and every mutation report the selected context and verified engine
identity; an installation on another context is not silently adopted. A new
installation plan names the active context before creating its anchor. Context
switching can therefore make an installation appear absent until the operator
returns to its daemon, and the documentation treats context migration as a
separate export/restore operation rather than name reuse.

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
engine-owned and any optional native cache remains internal and discardable.

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
intent contracts in independently reviewable, strictly ordered slices. The
shared guest primitive lands before a desired-spec schema; the schema lands only
after renderer version one's complete input set is known; read-only volume I/O
lands before locked mutation.

Installation identity is a repository-agnostic deployment/capacity boundary;
repository and snapshot identity remain owned by later `LocalSnapshot`
admission. Compose and fresh engine inspection are resource truth throughout,
and no host manifest mirrors them.

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

#### 2B.2a. Shared sandbox-guest protocol v4 durable file primitives

Advance the existing shared sandbox guest and every in-tree consumer, template,
and fixture to protocol version 4. Add `ReadOptionalFile`, whose closed response
distinguishes bounded present bytes from `NotFound`; every other I/O failure is
a rejection, never a string-parsed absence signal. Add `AtomicCommitFile` with
an expected state of either `Absent` or an exact SHA-256 of the prior file bytes
and a closed `Committed`, `AlreadyCurrent`, or `Conflict` outcome. The same
desired bytes are idempotently `AlreadyCurrent`; a mismatched expectation is a
non-mutating `Conflict`.

On Unix, atomic commit requires an existing parent, bounds and validates the
target, creates an exclusive temporary file in that same directory, writes and
synchronizes the complete file, renames it atomically, and synchronizes the
parent directory. A caught failure before rename cleans only that operation's
exact temporary file. The one-shot helper consumes EOF before dispatching an
atomic commit so trailing input cannot arrive after mutation begins. Native
Windows guests reject this operation with `OperationFailed`; the local
config-volume helper always runs in a Linux container on all three initial host
platforms.
Existing ordinary sandbox file-transfer operations keep their established
semantics.

Seed `/var/lib/automata-local` in the scratch helper image with mode `0700` and
UID/GID `65532`, retain final `USER 65532:65532`, and do not declare a Dockerfile
`VOLUME`. This lets Docker initialize a fresh named volume for the non-root
helper without a root fallback or an anonymous volume. Engine users must supply
an already present, registry-qualified digest reference and use pull-never
semantics; this slice adds no pull path.

Gate: protocol 4 rejects every prior wire version. Guest wire tests cover
request/response framing, replay, redaction, bounds, paths, expectations, typed
missing, idempotence, conflict, pre-rename cleanup, post-rename ambiguity, and
committed bytes. Windows-targeted tests require the closed unsupported atomic
response; downstream Rust exhaustive-match checks and a Swift-source coupling
test prevent an in-tree consumer from silently retaining an older protocol.
An opt-in live Linux-container test uses an explicit Docker endpoint and an
already loaded digest-pinned helper with pull disabled, non-root UID/GID,
read-only root filesystem, `network=none`, all capabilities dropped,
no-new-privileges, and only a fresh named local volume mounted at the dedicated
data path. It performs atomic commit and optional read through unnamed
auto-removed helpers, then revalidates the volume's cryptographic ownership
label and empty attachment set before non-force removal. This
shared-prerequisite slice creates no installation volume, freezes no
desired-spec schema, extends no local Engine adapter, and exposes no lifecycle
command; checkpoint 2B.2 is not complete.

#### 2B.2b. Renderer-v1 inputs and canonical desired-spec schema

First enumerate and test renderer version one's closed, value-free input
contract without invoking Compose or mutating the Engine. Only after every
render-affecting input is explicit may this slice freeze the exact bounded
desired-spec schema, canonical byte encoding, digest rule, validation, and
version/migration policy. The concerns described in the architecture section
are review prompts rather than a field list; the implemented renderer contract
is the authority for the final schema.

The document binds to the repository-agnostic installation identity and never
contains repository or snapshot identity, credential values, live resource
IDs, observed daemon state, or arbitrary extension maps. No ambient current
directory, environment variable, clock, active context, or live topology may
change rendering outside the canonical document and immutable checked-in
renderer.

Gate: exact-schema and golden-vector tests prove that canonical bytes and the
plan digest are stable across host OSes, unknown or non-canonical input fails,
every renderer-v1 input participates according to the frozen rule, and equal
documents render byte-identical value-free Compose configuration. This slice
creates no Engine resource and exposes no lifecycle command.

#### 2B.2c. Desired-spec volume and read adapter

Extend the pinned Engine adapter with the separate persistent desired-spec
config volume and the exact `desired-spec` persistent-volume role. Its immutable
labels bind only the installation UUID, full selector key, Compose project,
persistent-volume contract/resource kind, and exact role; they contain neither
repository identity nor a mutable plan digest. Create and adoption use fresh
post-inspection and require the local driver/scope, empty options, no bind, the
exact managed-label allowlist, and no attachment before any helper starts.

Add only bounded desired-spec inspection in this slice. A fresh, exactly
inspected helper container uses the already present digest-pinned image with
pull disabled, its hardened non-root configuration, and the config volume as
its sole read-only mount. `ReadOptionalFile` maps an empty new volume to a typed
uninitialized result and present bytes to canonical schema validation; helper
failure, malformed bytes, wrong installation binding, or indeterminate
attachment state fails closed. The adapter removes and reinspects the exact
helper by container ID.

Gate: foreign config-volume name, key, project, role, label, driver, option, or
attachment evidence fails before a helper starts. Stateful fake-daemon and
ignored live-Docker tests cover create/adopt, typed missing and present reads,
exact helper configuration and post-inspection, cleanup, restart, and zero
realized topology. There is no desired-spec write API and no user lifecycle
command in this slice.

#### 2B.3. Engine lock and compare-and-swap desired-spec commit

Implement the deterministic exact-ID engine lock before exposing desired-spec
mutation. Under that lock, a commit freshly reads the current optional document,
requires the caller's expected absent state or exact prior canonical-byte
SHA-256, invokes protocol 4 `AtomicCommitFile`, and then reads through a new
helper. Success requires the expected closed commit outcome plus canonical
decode, installation binding, and recomputed plan digest. A stale expectation
is a typed conflict with no mutation; an ambiguous daemon or helper result is
inspected through a fresh read and then resolved by a fresh
synchronization-closing commit. Inspection alone never proves durability; an
unprovable outcome retains interrupted lock evidence for explicit recovery.

Every later Compose mutation consumes this locked high-level operation. The
adapter still exposes no generic container, volume-write, pull, or remove API;
the helper is already present by immutable digest, runs non-root with only the
exact config mount, and is checked and removed by exact container ID.

Gate: concurrent managers cannot lose an update; absent-first-create,
same-document retry, stale-prior conflict, interruption before and after rename,
fresh readback, wrong binding/digest, busy-live lock, stopped recovery-required
lock, and positively authorized exact-ID recovery are covered by stateful fake
daemon and opt-in live-Docker tests. No plan digest enters persistent-volume
labels, no realized topology exists, and no user lifecycle command is exposed.

### 2C. Compose realization, convergent lifecycle, and exact reset

Build on the completed 2B.3 locked adapter. Realize the checked-in renderer-v1
configuration as persistent identity-only volumes and digest-labeled
replaceable topology, then add union discovery, `up`, `status`, `down`, and exact
reset. The command layer remains private until these operations are convergent
and their destructive boundary is proven.

The renderer consumes the current hidden image boundary
`automata internal object-store ensure-bucket`; it does not invent a shell
client, test helper, compatibility alias, or placeholder service-init command.
The initializer and server share the production S3 connection parser and the
sole validated-config-to-store AWS SDK construction boundary. Runner product
schema 4 independently requires the same closed
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

Implement the evaluation-only Docker Engine provider behind the existing
sandbox/provider interfaces. Reuse executor requests, operation identity,
runner custody, copy/exec/attach/output bounds, cancellation, and result
delivery. Add fake-daemon conformance and an ignored live Docker suite.

Foundation status: the shared sandbox contract now carries mandatory exact
runner custody and durable slot identity. `LocalDocker` product exposure stays
closed until a host-owned, bounded, non-evicting operation journal can preserve
accepted/committed/result/cancellation linearization for the sandbox lifetime.

Gate: shell and JavaScript-action sandboxes execute; restart attach and exact
cancellation work; realized configuration is inspected; foreign collisions
fail without mutation; prohibited privilege, namespace, bind, device, socket,
and network requests fail closed; output/copy bounds hold; and destroy leaves no
owned job resources.

### 3B. `LocalSnapshot` source adapter

Add bounded Git worktree snapshotting and a provider-distinct local source
authority. Parameterize source location/archive loading around the existing
GitHub Actions frontend and compiler. Feed compiled requests into the existing
workflow service, admission transaction, scheduler, cancellation, logs, and
history. Define and retain the exact canonical repository identity as admitted
source provenance here, not as an engine installation binding. Add
`automata local check` as a read-only view of that path.

Status: read-only source validation available, admission gate incomplete. The library
seals Git's tracked plus non-ignored live-worktree inventory through pinned
no-follow ancestor handles, normalizes tracked symlinks from Git mode, detects
mutation, and hashes the exact deterministic gzip bytes consumed by shared
repository archive discovery. Windows reparse points and junctions, portable
component-trie bounds and aliases, link cycles, sparse or assume-unchanged
index flags, and workflow-namespace aliases fail closed. Ignored paths are
classified through one bounded NUL-safe batch per worktree scan.
`.github/workflows` and `.ci/workflows` are explicit first-class policies; if
both namespaces are present the source fails as ambiguous. `automata local
check` composes event compilation, same-tree reusable-workflow loading,
typed call-graph validation and root-secret propagation, physical
common-Git-directory identity, snapshot revision, and local source provenance
without entering admission. Its only current event is an explicit local
`workflow_dispatch`; it cannot synthesize GitHub delivery evidence.

Gate: clean and dirty worktrees produce deterministic digests; ignored files,
`.git`, sockets, devices, escaping symlinks, submodule ambiguity, concurrent
mutation, oversized archives, and case collisions fail closed; direct
`.github/workflows` and `.ci/workflows` files and admitted same-tree reusable
workflows use the existing compiler; the versioned repository-identity preimage
has cross-platform worktree, symlink, non-Unicode, case, move, and clone
fixtures; no source operation mutates Git; and no local subject can enter
signed-GitHub admission or create a GitHub Check.

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
`.ci/workflows`, typed inputs, a user secret, a variable, dispatch, truthful
local push, cancellation, restart, persistence, and cleanup.

Gate: the one-command run works from clean state; the second secret-bearing run
does not prompt; `--workers 3` overlaps three jobs; history and logs are useful;
`down -> up` preserves identity, desired digest, `N`, profile, and data; and the
ordered reset deletes only the prevalidated topology, credentials, anchor, and
lock, with no residue on immediate reinspection.

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
host reboot. Deleting the host cache leaves Compose discovery and recovery
correct. The guide records current Docker Desktop prerequisites and terms,
engine-authorized-user trust, and the factory-reset/uninstall data-loss boundary.

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
and host reboot. Deleting the host cache leaves Compose discovery and recovery
correct; no native Windows execution provider is involved. Docker Desktop
prerequisites, terms, engine-authorized-user trust, and the
factory-reset/uninstall data-loss boundary are current.

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
pass; no Rust toolchain is required; and preview, contributor assembly, native
execution hosts, and production deployment remain clearly distinguished.

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
