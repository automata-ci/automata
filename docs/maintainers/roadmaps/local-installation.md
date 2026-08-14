# Local installation and deployment roadmap

- Roadmap status: Planned
- Available slice: read-only host preflight from a reviewed source checkout
- Date: 2026-08-14

This roadmap owns the work required to turn Automata into a product that a new
user can run locally, connect to one GitHub repository, and later deploy using
a production topology. Capability claims stay in
[Compatibility](../../compatibility.md); this page records decisions, dependencies,
merge checkpoints, and acceptance evidence.

## Product outcome

The first supported experience will run the complete control plane and `N`
Linux workers on one machine. The host may be Arch Linux, Apple Silicon macOS,
or Windows, but the quickstart jobs are Linux container jobs on every host.
Native macOS and native Windows jobs remain separate, advanced execution
profiles.

The final quickstart contract is:

```console
automata local doctor
automata local up --workers 3 --github OWNER/REPOSITORY
```

`up` is a resumable operation. It may pause for browser confirmation while the
user creates a private GitHub App, limits its installation to the requested
repository, and signs in. It must never ask the user to edit JSON, copy numeric
GitHub IDs, generate UUIDs, or create certificates by hand.

The same flow also has an explicit split form:

```console
automata local up --workers 3
automata local github connect OWNER/REPOSITORY
```

The lifecycle surface will be:

```console
automata local status [--json]
automata local logs [SERVICE] [--follow]
automata local down
automata local reset
```

`down` preserves the installation and durable data. `reset` is destructive,
requires confirmation, and removes only resources owned by the exact local
installation.

## Current baseline

The source tree does not yet provide that experience. The existing paths have
different purposes and cannot be combined into a cross-platform quickstart by
changing documentation alone.

| Existing path | Evidence in the source tree | Why it is not the quickstart |
| --- | --- | --- |
| `automata preview` | Starts the SSR interface and health endpoints without dependencies | It does not accept webhooks, schedule jobs, or run workers |
| `deploy/dev/compose.yaml` | Starts PostgreSQL and RustFS | It does not start the control plane, initialize the bucket, or start workers |
| Manual control-plane guide | Starts the complete server with hand-created keys and certificates | It is long, Unix-oriented, and contains values that must be reconciled manually |
| Rootless Podman runner | Hardened Linux provider and three example identities | It needs dedicated users, delegated cgroups, subordinate IDs, exact tmpfs mounts, helpers, and host networking policy |
| Native Windows runner | Trusted host-process provider | Durable enrollment rejects non-Unix hosts and `uses:` actions are unsupported |
| macOS runner | Disposable macOS VM provider | It requires Apple Silicon, signed helpers, a sealed image, and dedicated quota-managed APFS storage |
| GitHub provider | Strict provider registry accepted by the server | No App creation, installation discovery, or repository-connect command exists |
| Distribution | Linux x86-64 release automation with publication guards | No public product release or cross-platform installer exists |

The first implemented slice is deliberately smaller: `automata local doctor`
validates the initial host tuple, a local Linux Docker Engine, negotiated API
and architecture agreement, Compose plugin version 2.20.0 or newer, a dedicated
root strictly below the platform's user-state directories, and the Unix
non-root process requirement. It is read-only and does not imply that `up` or
workers are already available.

## Accepted local architecture

### One Linux container model on all hosts

Every long-running local component runs in a generated Compose project:

```text
GitHub and browser
        |
 public HTTPS origin
        |
 loopback-published local gateway
        |
   control plane -------- PostgreSQL
        |                     |
        +--------------- object storage
        |
  runner mTLS and private Results route
        |
 worker-01 ... worker-N
        |
 Docker Engine API
        |
 sibling Linux job and service containers
```

Docker Engine is the initial supported engine on all three platforms. Arch
uses Docker Engine directly; macOS and Windows use Docker Desktop's Linux
engine. Podman may be added only after it passes the same provider and
lifecycle conformance suite; it is not an automatic fallback in the supported
quickstart.

Docker Desktop is third-party software with terms that vary by organization
and use. The macOS and Windows gates must verify and disclose the then-current
prerequisites and must not imply universal free-use eligibility. A future
alternative engine enters the quickstart only through the same conformance and
support gate.

The existing rootless Podman, Kubernetes, native Windows, and macOS VM
providers retain their production or advanced contracts. The local path uses a
separate evaluation-only container-engine provider instead of weakening any of
those providers.

Before public artifacts exist, the contributor lane builds a dedicated
multi-stage local image from the reviewed checkout and records the source
revision and image identity in state. The final reader quickstart replaces that
development override with digest-pinned multi-architecture product images; it
does not present an unpublished image name as downloadable.

### Workers and jobs

`--workers N` generates `N` explicit, one-slot runner services. Each worker
has a stable runner ID, certificate, journal, encrypted spool, configuration,
and engine-managed state volume. Compose scaling is not used because replica
ordinals are not a durable identity contract.

The first successful `up --workers N` fixes the worker count for that named
installation. Repeating the same value is idempotent; requesting another value
fails with reset/recreate instructions until runner drain, disable, and delete
operations exist. This avoids inventing scale-down semantics that the current
control plane cannot enforce safely.

Worker containers use the host Docker Engine API to create sibling job and
service containers. The worker is therefore engine-admin-equivalent. This is
acceptable only for an explicitly local, trusted-repository evaluation mode.
Job containers never receive the engine socket, control-plane credentials, or
access to the Compose dependency network.

The local provider must:

- require an explicit runner `run-local` boundary that production `run` does
  not accept;
- accept only a local Unix socket from inside the Linux worker container;
- verify a Linux engine, API version, engine identity, and architecture;
- use digest-pinned, preloaded images and pull-never execution;
- label every resource with installation, runner, operation, generation,
  profile, and specification identities;
- verify labels and the realized resource policy before every mutation;
- reject foreign name collisions without deleting or adopting them;
- prohibit privileged jobs, host namespaces, host binds, devices, and the
  engine socket inside jobs; and
- clean exact owned resources without a global prune or broad label delete.

Initial profiles are truthful local container profiles rather than aliases for
the existing hardened rootless profile:

- `automata.local/ubuntu-24-04-amd64-container-v1`
- `automata.local/ubuntu-24-04-arm64-container-v1`

The ARM64 profile requires native ARM64 product, worker, job, and JavaScript
action toolchain artifacts. Silent x86 emulation is not the supported macOS
path.

### Network boundary

Only the human UI, OAuth callbacks, setup callbacks, and GitHub webhook route
are reachable through the public HTTPS origin. PostgreSQL, object storage,
Results, runner mTLS, and the Docker socket are never tunneled.

The control plane and dependencies use a generated private Compose network.
Current server validation accepts plaintext database and object-store endpoints
only at literal loopback, while a containerized server sees those dependencies
at private addresses. A single hidden local-container deployment context will
allow only a complete, generated RFC1918 tuple and will leave standard server
validation unchanged. Independent `allow private` flags are not part of the
design.

Job containers use a separate job network. They reach Results through an exact
local gateway alias or a narrowly scoped private proxy; they do not join the
control-plane network. This route must pass live tests independently on Docker
Engine, Docker Desktop for macOS, and Docker Desktop for Windows.

The tunnel is a pluggable boundary with a managed evaluation default and an
escape hatch for a user-supplied HTTPS origin. The chosen default must preserve
webhook method, headers, and bytes; redact credentials; and resume the exact
persisted hostname across `down -> up`, sleep, and reboot on all three hosts.
App creation is blocked unless that stability contract is available. Ephemeral
origins are not a supported recovery mode because callback/setup URLs and old
Check Details links cannot all be repaired through the webhook API; replacing
an origin requires a separately tested complete App and configuration migration.

### State and secrets

The local supervisor owns a named installation below the native platform state
root:

| Host | Default state root |
| --- | --- |
| Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/automata/local` |
| macOS | `$HOME/Library/Application Support/Automata/local` |
| Windows | `%LOCALAPPDATA%\Automata\local` |

The state manifest is schema-versioned and records only non-secret identities:
installation UUID, project name, engine identity, architecture, ports,
network, image digests, desired worker count, public origin, GitHub connection
revision, and lifecycle state. Every mutation takes a cross-platform advisory
lock and writes state atomically.

Secrets and Linux permission-sensitive runner material live in
engine-managed volumes. Generated Compose YAML, process arguments, status JSON,
logs, debug representations, and evidence bundles contain references or
redacted values, never plaintext credentials. `reset` validates an exact
installation marker and resource inventory before removing volumes. It does
not uninstall or delete the external GitHub App silently.

The caller-supplied state root must be a strict descendant of the current
platform home, profile, or user-state directory. It is a container for named
installations and is never itself recursively removed. Before host-file
deletion, the manager rejects
filesystem, drive, and share roots; home/profile roots and their ancestors;
lexical parent traversal; Unix symlink components; and Windows junction or
reparse components. It performs handle-anchored deletion only beneath the exact
marked installation child and revalidates containment at each traversal step.

Visible lifecycle states include `services_ready`, `awaiting_github`,
`app_installed`, `authenticated`, `enrolling_workers`, `ready`, and `degraded`.
An interrupted operation resumes from durable evidence instead of starting a
second installation.

## GitHub repository connection

The GitHub App Manifest flow is the target setup path. The implementation will
verify its exact permission and callback contract against GitHub's current
official documentation when that checkpoint begins. The provisional minimum is
`push`, `pull_request`, `merge_group`, and `repository_dispatch` events with
Checks write, Contents read, Pull requests read, and Merge queues read. A
webhook-only relay is insufficient because the dashboard and GitHub Check
Details URL need the same public HTTPS origin.

The resumable connect operation will:

1. start or attach the public HTTPS origin;
2. resolve `OWNER` through a bounded GitHub account lookup, retain its numeric
   identity and `User`/`Organization` type, and choose the corresponding personal
   or organization App Manifest endpoint without attempting to infer private
   repository visibility;
3. open the App Manifest flow with single-use, time-bounded local state and fail
   actionably if the browser identity lacks App-manager authority;
4. exchange the temporary manifest code and store the returned App key, App and
   client IDs, webhook secret, and OAuth client secret in private state;
5. open the new App's installation URL with `request_oauth_on_install=false`
   and ask the user to select the exact repository;
6. capture the exact HMAC-verified `installation` event, bind its sender as the
   installer identity, and fail actionably when repository-install authority is
   absent;
7. verify the completed installation with an App JWT and a short-lived token
   rather than trusting an `installation_id` query parameter, then discard that
   token;
8. list accessible repositories and select only the requested owner/name;
9. discover canonical owner, repository, installation, visibility, and default
   branch data;
10. cross-check the signed event sender's stable numeric ID and login through a
    bounded GitHub account lookup without asking the user to copy either value;
11. generate connection UUIDs, authority revisions, the one-use installation
   bootstrap tuple, human-auth configuration, and the strict provider registry;
12. validate generated configuration through the production decoders before an
    atomic install and control-plane reload or restart;
13. open the anonymous `/setup` bootstrap, have the configured identity finish
    its one permitted setup, and verify the first administrator browser session;
14. use a new browser-approved, local-only handoff to authorize `N` one-use
    runner enrollment credentials without depending on Linux Secret Service or
    persisting a CLI bearer on macOS or Windows; and
15. enroll/start the requested workers and report the dashboard and readiness
    URLs.

The current runner-token API accepts only CLI-audience sessions, and the
operator CLI has no Windows credential-custody implementation. The local
browser-to-manager handoff is therefore product work with its own single-use
state, origin binding, CSRF protection, expiry, replay rejection, and secret
redaction tests; ordinary browser login cannot be substituted for it.

Reconnect is idempotent. Stable semantics reuse identities; changed policy or
credentials increment the relevant revision. A multi-repository App
installation never widens the local repository registry beyond the exact
repository requested by the user.

The quickstart warns that this local engine-admin mode is for repositories the
operator trusts. The connect checkpoint adds an exact local admission rule that
rejects a pull request whose head repository differs from its base repository;
restricting fork credentials alone does not disable fork execution.

The smoke repository contract is intentionally small and observable:

- workflows are direct lowercase `.yml` or `.yaml` files under
  `.ci/workflows/`;
- no `.github/workflows/` copy exists that would also run on native GitHub
  Actions;
- `runs-on: automata-local` selects the host-native local profile without
  redefining GitHub's `ubuntu-24.04` architecture semantics;
- a three-entry matrix demonstrates three workers concurrently; and
- `push`, `pull_request`, `merge_group`, and `repository_dispatch` live evidence
  is added only when each event has an asserted product test.

## Platform qualification matrix

The initial qualified host tuples are Arch Linux x86-64, Apple Silicon macOS
ARM64, and Windows x86-64. Preflight rejects Intel macOS and Windows on ARM for
the supported quickstart; adding either requires native artifacts and its own
clean-host evidence rather than merely passing Docker API inspection.

| Gate | Arch Linux | Apple Silicon macOS | Windows |
| --- | --- | --- | --- |
| Host engine | Docker Engine | Docker Desktop Linux engine | Docker Desktop/WSL2 Linux engine |
| Worker/job architecture | `linux/amd64` | `linux/arm64` | `linux/amd64` |
| Orchestrator | Native `automata` | Native `automata` | Native `automata.exe` from PowerShell |
| Durable sensitive state | Engine-managed volumes | Engine-managed volumes | Engine-managed volumes |
| Host-specific proof | engine/socket ownership, restart, cleanup | paths with spaces, host gateway, sleep/reboot, native ARM64 | Linux-container mode, drive/path handling, CRLF, shutdown/reboot |
| Job claim | Linux containers | Linux containers, not native macOS jobs | Linux containers, not native Windows jobs |

A platform is qualified only after a clean host can:

- run the documented command without hand-editing JSON, certificates, UUIDs,
  revisions, or numeric GitHub IDs;
- complete only the expected browser confirmations for App creation,
  repository installation, and login;
- produce a useful and redacted `status --json` document;
- run three matrix jobs concurrently on three distinct runner identities;
- show live logs, final results, and the exact GitHub Check Details page;
- recover from one worker crash and a complete stack restart;
- preserve data across `down` and remove only exact owned state on confirmed
  `reset`; and
- keep App keys, source credentials, webhook secrets, and enrollment tokens out
  of command lines, logs, non-secret configuration, and test evidence.

## Merge checkpoints

Each checkpoint uses a sibling worktree created from the latest merged
`origin/main`. A dependent checkpoint starts only after its predecessor merges.
Every PR states its contract, security impact, non-goals, tests, and live
evidence; it does not depend on issue linkage.

### 1. Local host foundation and accepted design

Add the dedicated local lifecycle crate, the `automata local doctor`
command, platform state-root policy, Docker/Compose discovery, stable JSON
preflight output, this roadmap, and CLI contract tests.

Gate: Linux tests and a live Arch preflight pass; Windows x86-64 and Apple
Silicon targets cross-check; Docker Desktop fixtures cover both endpoint forms;
unsafe broad state roots are rejected; preflight makes no state or container
changes; and the normal operator CLI cannot route `local` as a remote command.

### 2. Durable lifecycle and state kernel

Add the versioned installation manifest, transition state machine, advisory
locking, atomic writes, exact resource inventory, backend trait, and anchored
filesystem ownership/deletion primitives. Keep this internal and exercise it
with a fake backend; do not advertise `up` before a real stack exists.

Gate: interruption and concurrent-manager tests preserve one installation;
filesystem roots, drive or share roots, home/profile roots, ancestors, and
caller-supplied state roots themselves are never deletion targets; Unix
symlinks and Windows junctions/reparse points fail closed; all recursive work is
handle-anchored beneath the exact marked installation child; and adversarial
Linux, macOS, and Windows fixtures prove that `reset` cannot escape it.

### 3. Durable zero-worker service composition

Add `up`, `status`, `logs`, `down`, and `reset`; generated configuration; random
keys and certificates; Compose rendering; the scoped local-container server
policy; a multi-stage source-checkout image; health waits; idempotent RustFS
bucket creation; and interruption recovery. Stop in `awaiting_github` with zero
workers.

Gate: repeated `up` is idempotent, `down` preserves data, confirmed `reset`
revalidates exact state and resource ownership, no secret reaches arguments or
generated YAML, dependency failures become actionable degraded states, and
`up -> down -> up -> reset` passes live on Arch.

### 4. Local container-engine sandbox provider

Add a separate Docker Engine API provider, fake-daemon contract tests, exact
resource ownership, exec/copy/attach/cancel/destroy behavior, resource
inspection, the truthful AMD64 local profile, and an ignored live Docker suite.

Gate: restart attach works, cancellation kills exact owned containers,
foreign collisions fail without mutation, copy and output bounds fail closed,
and destroy leaves no owned job resources.

### 5. Stable public-origin boundary

Add the local HTTP gateway, persisted public-origin state, user-supplied origin
support, a fake tunnel for tests, and one evaluated default tunnel after its
privacy, licensing, and cross-platform behavior are accepted.

Gate: only intended HTTP routes are forwarded; signed webhook headers and body
remain byte-exact; the default hostname survives `down -> up`, sleep, and reboot
for the installation lifetime; tunnel credentials are redacted. An origin that
cannot be resumed fails before App creation. Ephemeral-hostname replacement is
not the quickstart recovery path and would require a separately tested complete
App/configuration migration.

### 6. GitHub App creation and verified repository connection

Resolve the owner type and numeric owner through a bounded GitHub account lookup,
route App Manifest creation to the personal or organization settings endpoint,
then add Manifest generation/conversion, callback state, HMAC-verified
installation-event capture, installation/API verification, exact repository
discovery, and generated provider/human-auth configuration. Stop at
`app_installed`; do not start workers or claim a connected installation yet.

Gate: protocol-emulator tests cover forged IDs, expired/replayed state,
partial retries, public/private repositories, multi-repository installations,
exact permissions/events, atomic writes, configuration decoding, and secret
redaction. Personal and organization routing is exact; lack of App-manager or
repository-install authority fails with an actionable browser recovery path;
the signed `installation` event's sender identity is retained as the installer
evidence and cross-checked by bounded API lookup. No manual App field, numeric
ID, or registry JSON is required.

### 7. Installation bootstrap and enrollment authorization

Bind the one-use bootstrap tuple to the verified installer identity, complete
the anonymous `/setup` flow, add exact local fork rejection, and add the
browser-approved, local-manager enrollment-authorization handoff. Ordinary
browser sessions remain unable to call the CLI-audience runner-token API.

Gate: wrong GitHub identity, origin/CSRF mismatch, expiry, replay, restart, and
partial-completion tests fail closed; setup creates exactly one first
administrator; the local handoff authorizes only the recorded bounded worker
count and never persists a CLI bearer. Provider configuration reload is atomic
and rollback-safe.

### 8. Runner local-only composition

Add `automata-runner run-local`, the Linux worker image, engine-socket adapter,
private Results route, `automata-local` selector, stable one-slot worker
identities and volumes, automatic use of the approved enrollment handoff, and
generated `N`-worker Compose services. Do not expose workers through ordinary
production `run`.

Gate: `N=1` and `N=3` start; shell and JavaScript-action jobs execute; three
jobs overlap on three identities; worker restart reconciles exact sandboxes;
job code cannot access the engine socket or dependency network. The first
successful `up --workers N` makes `N` immutable until confirmed `reset`;
repeating the same value is idempotent and a different value fails with exact
reset/recreate guidance, avoiding stale runners before drain/delete exists.

### 9. Arch end-to-end qualification

Create the designated repository under `AlexanderDzhoganov` after confirming
its exact name, install the App on only that repository, add the three-job
fixture, and commit an executable redacted smoke harness/evidence format.

Gate: a clean local state reaches its first completed GitHub Check; webhook
delivery is durably accepted; queued/running/completed Check states and Details
link work; three workers overlap; cancellation cleans owned resources; and
`down -> up` preserves the installation.

### 10. Native ARM64 artifacts and macOS qualification

Build and privately stage native ARM64 control-plane, worker, job, and action
toolchain candidates; qualify Docker Desktop, gateway/tunnel behavior, browser
launch, paths with spaces, sleep, restart, and reboot on the Mac mini. Public
publication remains disabled until checkpoint 13.

Gate: the same command and GitHub fixture pass with `N=3` without x86
emulation or Unix-host secret-file assumptions. The guide records Docker
Desktop's current terms and licensing prerequisites and does not imply that its
use is free for every organization.

### 11. Windows orchestration and qualification

Add the native Windows local-manager artifact and PowerShell UX; qualify Docker
Desktop/WSL2 Linux-container mode, Windows state paths, CRLF, process shutdown,
restart, and reset. The worker and jobs remain Linux containers.

Gate: the same command and GitHub fixture pass with `N=3` from clean
PowerShell, and no native Windows enrollment path is involved. The same Docker
Desktop terms/licensing disclosure is verified for this host lane.

### 12. Cross-platform release candidates and installers

Build checksummed native local-manager artifacts and multi-architecture Linux
images, SBOMs, provenance, and installer contract tests. Apply Developer ID
signing, notarization, and stapling to the macOS candidate and Authenticode to
the Windows candidate before qualification so the tested bytes are the bytes
eventually published. Keep public publication disabled while candidates are
qualified.

Gate: clean-host installer tests consume exact final signed CI-produced
candidates on all three operating systems, verify platform signatures,
notarization where applicable, checksums, and provenance, and require no Rust
toolchain.

### 13. Publication authority and first public artifacts

Resolve the release-authority design in a focused review, publish the exact
qualified artifacts, and only then change release-status text and installer
URLs. Do not remove the existing publication guard as a shortcut.

Gate: exact registry/archive identities, signatures, checksums, SBOMs,
provenance, rollback procedure, and public download smoke tests pass.

### 14. README and documentation information architecture

Make the now-public tested local flow the first root README procedure, split
operator and maintainer material, and make the deployment chooser own topology
selection.

Gate: every quickstart command is exercised by the smoke harness; clean-reader
tests consume the public artifacts on all three hosts; links and anchors pass;
installation does not require a Rust toolchain; preview remains clearly
dependency-free and separate.

### 15. Durable Docker Compose deployment

Build a production-oriented composition separate from the privileged local
evaluation stack: TLS reverse proxy, external or explicitly development
PostgreSQL/S3 choices, secret files, persistence, probes, backup/restore,
upgrade/rollback, and optional hardened runner profiles. This topology must not
reuse the engine-admin local evaluation provider.

Gate: configuration validation, restart persistence, real TLS/webhooks,
backup restoration, dependency failure recovery, non-root images, and exact
version/digest pins pass.

### 16. Linux systemd deployment

Add control-plane units and credential/tmpfiles packaging; implement or require
runner disable, drain, and delete lifecycle operations; generalize runner units
beyond exactly three instances; and retain the hardened rootless Podman guide
as an advanced host deployment. The local engine-admin provider is forbidden.

Gate: clean-VM installation, `systemd-analyze verify`, reboot, key/certificate
rotation, drain/recovery, and backup restoration pass. Unimplemented automatic
runner certificate rotation remains an explicit production blocker.

### 17. Helm/Kubernetes deployment

Start with one control-plane replica, external PostgreSQL and object storage,
existing secret references, ingress, a runner mTLS service, probes, metrics,
NetworkPolicy, and explicit migration behavior. Kubernetes runners remain
experimental until their independent live gate passes; the chart never mounts
the local evaluation engine socket into a production runner.

Gate: chart lint/schema/template validation, kind or k3d integration,
upgrade/rollback, dependency outages, secret non-disclosure, and documented
node-traffic exceptions pass.

### 18. Cloud reference deployments

Publish one provider-neutral validated topology, then one infrastructure PR per
cloud. Start with AWS because PostgreSQL and S3 align with the existing storage
boundaries. GCP and Azure require a proven S3-compatible store or a separately
implemented native object-store adapter. Terraform or OpenTofu follows a real
manual deployment rather than preceding it.

Each cloud gate names a separately qualified hardened runner provider; the
local engine-admin provider is not accepted. The gate includes DNS/TLS, webhook
delivery, an `N`-worker run, backup/restore, upgrade, teardown, security review,
and an explicit cost inventory.

## Documentation migration

User guides will be reorganized only as their product paths become real. Keep
the stable high-traffic files as landing pages so existing links do not break.
The target ownership is:

```text
docs/local/                    local quickstart, lifecycle, GitHub connect
docs/deploy/                   chooser, Compose, systemd, Kubernetes, cloud
docs/operations/               backup, restore, upgrade, observability
docs/platforms/                advanced native execution-host guides
docs/reference/                configuration and command reference
docs/maintainers/roadmaps/     plans, audits, and conformance work
```

The current documentation has an explicit disposition so cleanup does not
silently erase useful operational detail:

| Current source | Disposition | Checkpoint |
| --- | --- | --- |
| Root `README.md` | Replace the opening procedure only after the three-host local smoke gate and public artifacts; retain project and security context | 14 |
| `docs/getting-started.md` | Keep as a stable chooser; move the tested local procedure to `docs/local/` | 14 |
| `docs/deployment.md` | Keep the manual development assembly truthful now; later convert it into the deployment chooser | 1, then 14 |
| `deploy/dev/README.md` | Retain as contributor-only PostgreSQL/RustFS support, not a product deployment | 14 |
| Runner configuration guide | Retain as the hardened Linux rootless-Podman host reference | 14 and 16 |
| Arch and macOS platform guides | Retain as advanced execution-host references; do not use them as the portable local quickstart | 9, 10, and 16 |
| Native Windows material in `docs/getting-started.md` | Move into a dedicated advanced Windows platform guide while keeping the chooser short | 11 and 14 |
| Provider example and workflow claims | Reconcile against executable configuration, workflow discovery, and event tests | 1 and 6 |
| Parity plans and dated audits | Move under maintainer ownership when touched; archive only after their remaining decisions are represented elsewhere | 14 |
| Release documentation | Preserve publication authority and safeguards until qualified artifacts exist | 12 and 13 |

The cleanup checkpoints will:

- replace the preview-first root README only after the real local flow passes
  all three host gates;
- keep `docs/getting-started.md` as a short chooser instead of mixing preview,
  source installation, and native execution experiments;
- turn `docs/deployment.md` into a deployment chooser and move exact procedures
  to topology-specific guides;
- keep `deploy/dev` explicitly contributor-only;
- retitle the runner configuration guide as the hardened Linux runner-host
  reference rather than a local bootstrap;
- reconcile the provider example and runner profiles from one generated source
  of truth;
- correct stale CLI examples and workflow-selection claims against executable
  help and product tests;
- move parity plans and dated audits out of the operator path;
- delete or archive branch-status plans that no longer own a decision; and
- preserve publication safeguards in release documentation and workflows.

The final README quickstart is generated from or tested by the same commands as
the Arch, macOS, and Windows smoke harness. Documentation is not the evidence
that makes a platform available; the clean-host acceptance record is.
