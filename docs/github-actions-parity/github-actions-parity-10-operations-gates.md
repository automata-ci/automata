# GitHub Actions parity: Operations, limits, runner fleet, and acceptance gates

Add retention and repair, dynamic fleet management, bounded limits, and the Linux, Windows, security, event, chaos, and unchanged-repository acceptance gates.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lanes X, S, and P with security review.

**Package IDs:** OPS-01, FLT-01, FLT-02, FLT-03, FLT-04, LIM-01, GATE-01, GATE-02, GATE-03, GATE-04, GATE-05, GATE-06.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
- [Matrices, scheduling, dependencies, and reusable workflows](github-actions-parity-03-scheduling-reuse.md)
- [Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
- [Services, job containers, Docker, Podman, Kubernetes, and BuildKit](github-actions-parity-05-containers-docker.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)
- [Triggers, dispatch, schedules, and event families](github-actions-parity-07-events.md)
- [Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)
- [Windows, Linux and macOS profiles, architectures, and cross-OS cache](github-actions-parity-09-platforms.md)
- [Cross-repository integration tests](github-actions-parity-11-integration-tests.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### OPS-01 — Retention, notifications, observability, and repair

**Owner:** X with S and C reviewing operations. **Size:** XL.
**Dependencies:** RES-02, ART-02, CACHE-01, LIM-01.

Current `upstream/main` already ships bounded Prometheus/OpenMetrics endpoints,
RED/USE families across the control plane, Results, storage, and runners, a
logical-workflow cardinality manifest, checked recording/alert rules, dashboards, and
runbooks. Latest main also records sanitized runner lease-request failure stages
in logs. This package extends that base; it does not rebuild observability from
zero, and the closed lease-stage signal still needs a bounded metric family.

Tasks:

- [ ] Define retention for workflow runs, logs, summaries, annotations,
  artifacts, cache metadata, approvals, audit records, and source snapshots.
- [ ] Add durable retention workers with tenant fairness, dry-run reporting,
  tombstones, and repair.
- [ ] Define notification events and deliver webhook/email adapters through an
  outbox with bounded retry and no secret-bearing bodies.
- [x] Maintain the existing bounded scrape contract, RED/USE families,
  cardinality manifest, recording/alert rules, dashboards, and runbooks.
- [ ] Complete remaining RED/USE coverage for ingress, compilation, scheduling,
  leases, execution, Results, stores, object storage, and provider APIs.
- [ ] Add a closed, bounded lease-request-stage-by-failure metric family for the
  sanitized stages already logged; update the cardinality manifest, rules,
  dashboards, and exact exposition tests together.
- [ ] Extend existing cardinality budgets as families are added and continue to
  prohibit unbounded IDs or user-controlled values in metric labels.
- [ ] Extend operator views for stuck leases, blocked concurrency, approval
  waits, failed projections, publication backlog, and GC backlog.
- [ ] Add audited repair commands for replay, reconciliation, release, and
  deletion.
- [ ] Extend current runbooks with backup/restore, credential rotation, outage,
  and corruption procedures.

Acceptance:

- [ ] Every durable queue and asynchronous projector has lag, retry, failure,
  and age metrics.
- [ ] Retention and repair survive restart and competing replicas.
- [ ] Operator tooling is bounded, dry-run capable where applicable, and
  produces an immutable audit record.

### FLT-01 — Dynamic runner registration and credential lifecycle

**Owner:** P with C reviewing identity. **Size:** XL. **Dependencies:** SEC-02,
GATE-06.

The current control plane issues one-use enrollment tokens and signs a
runner-generated CSR while atomically binding exact identity, group,
capabilities, labels, slots, and leaf digest. The checked-in Linux host remains
exactly three independent, single-slot runner processes, each with a separate
OS account, runner ID, client leaf/key, spool key, journal, spool, Podman state,
delegated cgroup, and metrics listener on ports 9464, 9465, and 9466. At the
checked-in per-job ceiling the trio advertises 12,000 CPU millicores, 48 GiB
memory, and 12,288 PIDs; the aggregate systemd slice is capped at 13.5 CPU
cores, 54 GiB, and 13,824 tasks. Inventory schema 3 admits a host only with
slots 1, 2, and 3.

Authenticated Handshake/Sync already negotiates the exact current runner
protocol v1 and JobIR v1 contract before lease traffic; the supported protocol
range is currently min=max v1. Rotation and lifecycle update channels remain
separate work; version skew is unsupported.

Tasks:

- [x] Design an authenticated enrollment protocol separate from normal runner
  Handshake/Sync.
- [x] Issue one-time, narrowly scoped registration credentials with expiry and
  replay protection.
- [x] Bind registered runner ID, tenant, group, labels, capabilities, slot
  count, certificate, platform, and environment profile.
- [ ] Add certificate issuance/rotation/revocation and server-root rotation.
- [x] Remove the privileged static fleet path without a compatibility mode and
  document enrollment for the exact three-process reference deployment.
- [ ] Add disable, drain, replace, delete, and audit operations.
- [x] Negotiate the exact protocol v1 and JobIR v1 range during authenticated
  Handshake/Sync before accepting lease traffic.
- [ ] Keep enrollment and updates pinned to the exact current protocol and
  block mixed-version automatic replacement.
- [ ] Reject capability or identity changes that were not authorized by the
  registration operation.
- [ ] Add CLI/API/UI flows without returning private keys after creation.

Acceptance:

- [ ] A new runner enrolls without editing a server-side fleet file.
- [ ] A stolen/expired registration token cannot enroll or replace a runner.
- [ ] Rotation and revocation take effect across replicas without interrupting
  unrelated runners.

### FLT-02 — Runner groups, labels, routing, and administrative policy

**Owner:** P with S owning scheduler selection. **Size:** L.
**Dependencies:** FLT-01, FND-01.

Tasks:

- [ ] Model multiple runner groups per tenant with repository allowlists.
- [ ] Separate administrator labels from attested platform/capability fields.
- [ ] Normalize labels case-insensitively and reject ambiguous duplicates.
- [ ] Define exact `runs-on` matching, group selection, fallback, and no-match
  diagnostics.
- [ ] Bind routing to environment profile digest and isolation capabilities.
- [ ] Add desired-state drain/disable and safe slot-count changes.
- [ ] Define the assignment pickup window, offline/stale heartbeat threshold,
  lease withdrawal, and late-runner policy.
- [ ] Keep queued jobs pending or fail them with a stable reason when every
  matching runner is offline, disabled, stale, incompatible, or at capacity.
- [ ] Add audited CLI/API/UI management and pagination.
- [ ] Test concurrent edits, deleted repositories/groups, stale sessions, and
  label spoof attempts.

Acceptance:

- [ ] A job is offered only to an eligible, admitted runner in an authorized
  group.
- [ ] Runner self-report cannot escalate routing privileges.
- [ ] Routing decisions are explainable from durable evidence.

### FLT-03 — Ephemeral, just-in-time, and autoscaled runners

**Owner:** P with S and C review. **Size:** XL. **Dependencies:** FLT-01,
FLT-02, LIM-01, OPS-01.

Tasks:

- [ ] Specify one-job runner and just-in-time registration semantics.
- [ ] Define autoscaler demand signals that account for labels, groups,
  profiles, concurrency blocks, and quota rather than raw queue length.
- [ ] Add launch, readiness, admission, claim, drain, shutdown, and deletion
  state machines.
- [ ] Publish a `workflow_job`-style queued/in-progress/completed lifecycle
  feed for autoscalers without exposing job credentials or mutable payloads.
- [ ] Prevent double assignment during scaler/controller failover.
- [ ] Bound cold-start retries and clean failed instances and credentials.
- [ ] Add cloud/provider-neutral interfaces before concrete adapters.
- [ ] Test scale-to-zero, burst, partial provider outage, quota exhaustion,
  orphaned instances, late runner arrival, and control-plane restart.
- [ ] Publish cost and capacity metrics without promising billing features.

Acceptance:

- [ ] An ephemeral runner accepts at most one attempt and cannot reconnect for
  another after terminal state.
- [ ] Duplicate controllers converge on one desired fleet.
- [ ] Failed launches do not leak instances, certificates, or registration
  authority.

### FLT-04 — Kubernetes deployment, packaging, signing, and updates

**Owner:** P. **Size:** XL. **Dependencies:** FLT-03, PROV-03, OIDC-02, OPS-01.

The workspace contains a Kubernetes sandbox adapter, in-sandbox guest
transport, and runner product-configuration variant. `PROV-03` owns the missing
production composition and cluster evidence; these components alone are not a
fleet controller or deployable operator.

Tasks:

- [ ] Provide reviewed Kubernetes manifests or an operator for control plane,
  workers, object storage dependencies, and autoscaled runners.
- [ ] Define network policies, pod security, volumes, disruption budgets,
  anti-affinity, probes, and upgrade ordering.
- [ ] Produce signed Linux and Windows artifacts with checksums and provenance.
- [ ] Add update channels and define the supported current-version replacement
  and rollback policy before the first release.
- [ ] Verify supply-chain inputs and pin build images/actions by digest or SHA.
- [ ] Add air-gapped installation and trust-root rotation procedures if kept in
  scope.
- [ ] Run upgrade, rollback, lost-node, and certificate-rotation drills.

Acceptance:

- [ ] A documented install reaches readiness without mutable or unsigned
  runtime downloads.
- [ ] The documented deployment path installs only the current protocol and
  schema without hidden version-skew behavior.
- [ ] Rollback behavior is explicit when database migrations are irreversible.

### LIM-01 — Limits, quotas, rate limiting, and overload behavior

**Owner:** S with X and C review. **Size:** XL. **Dependencies:** FND-04.

Current new work is pinned to JobIR v1 and runner-requirements schema v1.
Schema v1 requires a resolved `resource_allocation` derived from an immutable,
run-pinned default/minimum/maximum policy. The Automata-only workflow extension
covers CPU, memory, ephemeral storage, and GPU request/limit values; the
runner/provider contract separately carries a PIDs ceiling. Current cache
finalization enforces a concurrent-safe 10 GiB per-repository LRU quota, and
rerun admission allows 50 reruns within the current 30-day source horizon.
These implemented slices do not complete the cross-product limit registry,
rate limits, fairness, or SaaS policy-management surface.

Tasks:

- [ ] Inventory every current hard-coded limit and compare it to documented
  GitHub limits or an explicit Automata safety boundary.
- [ ] Cover workflow bytes, YAML aliases, expression depth, jobs, matrix rows,
  reusable depth/count, steps, outputs, environment values, log bytes,
  annotations, summaries, artifacts, cache, API bodies, webhook rate, queue
  depth, runner slots, concurrent jobs, per-job CPU/memory/ephemeral-storage/GPU
  allocation, runner PIDs, and immutable resource-policy bounds.
- [x] Require runner-requirements schema v1 and a run-pinned resolved resource
  allocation for every new runnable/materialized job.
- [ ] Enforce or explicitly diverge from the 35-day workflow-run lifetime, the
  24-hour self-hosted queue timeout, and the five-day self-hosted job maximum.
- [ ] Decide whether hosted-compatible labels use GitHub's six-hour job limit
  or the self-hosted limit, then expose that policy before scheduling.
- [ ] Enforce the 50,000-Check-runs-per-suite boundary with deterministic
  matrix/retry failure behavior.
- [ ] Implement and boundary-test trigger, workflow-queue,
  runner-registration, management API, artifact, and cache-operation rate
  limits.
- [x] Enforce the 10 GiB per-repository cache quota with concurrent-finalize
  accounting and LRU behavior.
- [x] Enforce the current 50-rerun limit and 30-day rerun-admission horizon.
- [ ] Add audited SaaS management and bounded overrides for resource and
  remaining tenant/repository policies; preserve immutable run-pinned policy.
- [ ] Reject over-limit input at the earliest authoritative layer with stable
  diagnostics.
- [ ] Add token-bucket or equivalent limits for ingress and management APIs.
- [ ] Add scheduler and worker backpressure, tenant fairness, admission shedding,
  and retry-after semantics.
- [ ] Prevent retry storms and unbounded dead-letter/error payloads.
- [ ] Add overload, quota-race, restart, and multi-replica tests.

Acceptance:

- [ ] No supported request can allocate an unbounded collection or payload.
- [ ] One noisy tenant cannot starve control, scheduling, Results, or storage
  for another.
- [ ] Operators can explain each rejection from policy and observed usage.

## External integration-suite gate policy

The
[cross-repository integration-test workstream](github-actions-parity-11-integration-tests.md)
provides shared deployment, provider, evidence, comparison, and graduation
machinery. It does not redefine the gates below.

| Gate | Required companion evidence |
| --- | --- |
| GATE-01 | IT-01/IT-02 intake and admission, IT-03 differential machinery, the first IT-04 live graduation, and feature-owned Linux scenarios |
| GATE-02 | IT-09 Windows adapter plus Windows feature scenarios; hosted Windows evidence remains independent of Linux GATE-06 |
| GATE-03 | IT-03 protected live target, IT-06-style credential/effect controls, and feature-owned authority canaries |
| GATE-04 | IT-02 admission coverage, IT-03 provider observation, and event-owner positive/negative scenarios |
| GATE-05 | IT-12 multi-replica/fault adapter plus FND-02 restart controls and feature-owned fault/overload scenarios |
| GATE-06 | IT-01 exact bundle, IT-02 coverage, IT-03 live comparison, IT-08 continuous operation, and the exact unchanged Automata workflow |

An emulator result can satisfy deterministic protocol coverage but cannot
satisfy a live GitHub requirement. A candidate, quarantined, skipped, expired,
or incompletely observed scenario cannot satisfy any gate.

### GATE-01 — Unchanged mainstream Linux conformance workflow

**Owner:** X as integration owner; all lanes fix their failures. **Size:** XL.
**Dependencies:** FND-01, FND-02, WF-03, WF-05, WF-06, MAT-01, MAT-02,
MAT-03, DEP-01, SCH-01, RUN-01, RUN-02, RUN-03, ACT-01, LOG-03, LOG-04,
CAN-01, CAN-02, AUTH-03, RES-01, RES-02, ART-01, CHECK-01, PROV-01,
CACHE-02, PLAT-01, IT-04.

This is the first compatibility gate. The workflow fixture must remain normal
GitHub Actions YAML rather than an Automata-specific test protocol.

This gate uses a public Linux conformance workflow that is identical on GitHub
and Automata. A later gate executes Automata's complete repository CI workflow
unchanged.

Tasks:

- [ ] Freeze a public repository and commit containing one ordinary Linux
  workflow; send the same signed push to GitHub and Automata without changing
  workflow YAML.
- [ ] Include multiple dependent jobs, a matrix, expressions, outputs,
  `continue-on-error`, timeouts, working directories, environment files,
  masks, summaries, annotations, a public JavaScript action, checkout, a local
  composite action, cache restore/save, and artifact upload/download.
- [ ] Include PostgreSQL only after `PROV-01` proves the production helper
  path.
- [ ] Run the same commit on GitHub-hosted Ubuntu and Automata's immutable Linux
  profile.
- [ ] Capture normalized job graph, contexts, step order/outcomes/conclusions,
  outputs, logs, command effects, Checks, artifacts, cache behavior, and cleanup.
- [ ] Classify every difference as bug, approved divergence, environmental
  input, nondeterminism, or fixture error.
- [ ] Run success, user failure, timeout, explicit cancellation, rerun, and
  control-plane restart variants.
- [ ] Make the Automata run exercise real ingress, Postgres, object storage,
  runner process, provider, Results, and Check publication.
- [ ] Use the loopback provider emulator only for deterministic protocol
  coverage; separately prove GitHub.com networking, App installation,
  credential issuance, webhook delivery, and Check publication against the
  live provider boundary.

Acceptance:

- [ ] No product path is substituted by an in-memory fake.
- [ ] All unapproved semantic differences are closed or capability-rejected.
- [ ] The fixture passes repeatedly and produces a checked-in comparison
  report tied to exact versions and digests.
- [ ] Passing this diagnostic gate unblocks, but does not substitute for,
  full-repository `GATE-06`.

### GATE-02 — Unchanged Windows run-and-actions workflow

**Owner:** X with R, P, and C. **Size:** XL. **Dependencies:** WIN-ISO-11,
WIN-03, CACHE-03, ART-01, CAN-02, GATE-01, IT-09.

Hosted Windows CI is intentionally absent from the audited main branch because
Automata does not currently operate a Windows runner. This gate independently
restores that hosted release evidence; it is not a dependency of the current
Linux-only repository-CI `GATE-06`.

Tasks:

- [ ] Restore a controlled Windows Hyper-V release job that builds the shipped
  control plane, runner, broker, and guest artifacts and exercises
  `automata-runner run` through the Hyper-V-container product path.
- [ ] Freeze a Windows workflow using default `pwsh`, explicit PowerShell,
  `cmd`, optional Python, checkout, local composite, one repository JavaScript
  action, cache, artifact upload/download, summaries, outputs, and cancellation.
- [ ] Compare against GitHub-hosted Windows with normalized paths, case,
  line endings, and environment ordering.
- [ ] Run through the shipped runner, restricted broker, Hyper-V-container
  provider, and bounded guest executable, not the executor or an injected
  runtime alone.
- [ ] Prove trust-to-isolation placement, no host share, outer network policy,
  workload process containment, timeout, cancellation, durable cleanup,
  runner/broker/engine/host restart reconciliation, and no
  container/writable-layer/endpoint/generation reuse.
- [ ] Run the IT-09 hostile and crash-at-every-transition matrix on dedicated
  Hyper-V hosts with no production credentials.
- [ ] Assert exact signed image/tool manifests and standalone PowerShell
  packaging; reject Store/MSIX-only, stale-patch, or security-drifted hosts.
- [ ] Publish exact Hyper-V-container, image, guest-authority, egress, action,
  cache, and unsupported service/reboot/nested-container/device limitations
  next to the feature matrix.

Acceptance:

- [ ] All supported `run:` and `uses:` phases in the fixture match expected
  semantics.
- [ ] The gate claims only the exact Hyper-V-isolated Windows container profile
  and never implies process isolation, nested containers, devices, interactive
  desktop, reboot semantics, or native execution.
- [ ] CI builds and runs the control-plane, runner, broker, and guest product
  path on controlled Windows Hyper-V hardware.

### GATE-03 — Credentials, trust, environments, and OIDC

**Owner:** X with C. **Size:** XL. **Dependencies:** AUTH-03, CFG-02, ENV-02,
OIDC-02, SEC-01, SEC-02, REU-04, EVT-02, EVT-03, EVT-05, EVT-08,
IT-03.

Tasks:

- [ ] Build public/private, same-repository/fork, Dependabot, protected/unprotected
  branch, environment, reusable, dispatch, schedule, rerun, and pull-request-
  target scenarios.
- [ ] Record the effective permission set, token scopes, secret/variable
  availability, environment approval state, OIDC claims, and runner isolation
  requirements for each scenario.
- [ ] Prove denied credentials are never created, stored, transported, logged,
  or masked as though present.
- [ ] Exercise approval, rejection, timeout, cancellation, rule changes, and
  reviewer races.
- [ ] Restart every control-plane process between authority preparation,
  issuance, delivery, use, and finalization.
- [ ] Attempt cross-run, cross-job, cross-attempt, cross-fence, cross-session,
  and cross-tenant replay.
- [ ] Scan Postgres, blobs, journals, spool, logs, metrics, traces, UI payloads,
  and crash diagnostics for canary values.

Acceptance:

- [ ] Every authority is least privilege and bound to authenticated durable
  evidence.
- [ ] Fork and Dependabot scenarios cannot obtain stronger authority through a
  later layer.
- [ ] The gate is runnable in CI with local provider fixtures plus separately
  controlled live cloud federation probes.

### GATE-04 — Broader event and trigger differential suite

**Owner:** X with C and W. **Size:** XL. **Dependencies:** EVT-02, EVT-03,
EVT-04, EVT-05, EVT-06, EVT-07, EVT-08, WF-01, WF-02, IT-02, IT-03.

Tasks:

- [ ] Build signed, replayable fixtures for every supported event/activity type.
- [ ] Cover positive, negative, empty, missing, renamed, deleted, transferred,
  forked, archived, and malformed payload cases where applicable.
- [ ] Compare trigger filters, context values, default ref/SHA, changed-file
  resolution, permissions, and deduplication with GitHub.
- [ ] Exercise manual input validation, schedule default-branch behavior,
  disabled workflows, chained workflow depth, and stateful events.
- [ ] Run redelivery, out-of-order delivery, duplicate delivery, repository
  policy changes, and provider API outage.
- [ ] Ensure unsupported activities reject before materialization with stable
  diagnostics.
- [ ] Classify emulator fixtures as hermetic protocol evidence and run a
  controlled live-provider acceptance case for every advertised ingress family
  that depends on GitHub App installation, API authority, or networking.

Acceptance:

- [ ] Each advertised trigger has at least one positive and one negative
  product-composition fixture.
- [ ] Replay and redelivery cannot duplicate logical runs.
- [ ] Event status is derived from the machine-readable registry used by code.

### GATE-05 — Multi-replica, restart, overload, and chaos gate

**Owner:** X with S, P, and C. **Size:** XL. **Dependencies:** MAT-02, MAT-03,
SCH-02, CAN-02, ENV-02, LIM-01, OPS-01, FLT-03, FLT-04, ART-02,
CACHE-01, IT-12.

Tasks:

- [ ] Run multiple control, materialization, scheduler, projector, GC, and fleet
  controller replicas.
- [ ] Kill processes at every durable transition for ingress, compilation,
  matrix expansion, concurrency, lease, result, artifact, cache, approval,
  notification, and runner lifecycle.
- [ ] Partition Postgres, object storage, provider APIs, runners, and GitHub API
  independently.
- [ ] Inject duplicate, delayed, reordered, truncated, corrupt, and
  uncertain-outcome operations, including sandbox-create failure before and
  after durable handle custody; prove exact returned custody is destroyed
  before slot release and missing custody remains fenced until a bounded runner
  drain and provider-side reconciliation prove absence or cleanup.
- [ ] Saturate each configured quota and queue while measuring tenant fairness,
  bounded memory, recovery lag, and retry traffic.
- [ ] Exercise current-version replacement, certificate/key rotation,
  backup/restore, and rollback within the declared current schema boundary.
- [ ] Verify repair tools converge state without bypassing authority or
  idempotency.

Acceptance:

- [ ] There is no duplicate execution, lost terminal result, credential reuse,
  unbounded retry loop, or permanent capacity leak.
- [ ] Recovery meets documented objectives and leaves actionable telemetry.
- [ ] The test report records topology, versions, injected faults, invariants,
  and residual limitations.

### GATE-06 — Automata repository CI unchanged

**Owner:** X as integration owner; all lanes fix their failures. **Size:** XL.
**Dependencies:** GATE-01, DCK-01, IT-01, IT-02, IT-03, IT-08.

This is the backlog's full unchanged-CI requirement. It follows rather than
replaces the smaller Linux and container/daemon diagnostic gates. `GATE-02`
restores hosted Windows independently because the checked-in repository CI no
longer declares a Windows job.

At the audited `4aa42c00e2651b5dd17f7a81931f57f5bb36a44a` baseline, the
checked-in `.github/workflows/ci.yml` Git blob is
`285b6f2ae0bf54b7a0f8766b892514c1c3928061`: 19,197 canonical bytes with
SHA-256 `afc1d3ac6ce075c163c8820f9f97ee490ce907160f3ca361c02cabd0e94a677a`.
It declares ten Ubuntu jobs (`verify`, `rust_tests`, `rust_coverage`,
`renderer_tests`, `postgres_store`, `postgres_integrations`, `frontend`,
`renderer`, `dist_build`, and `dist`), uses `actions/checkout` v7.0.1 and
`actions/setup-node` v7.0.0, and has no Windows job. This is audit evidence, not
the future frozen gate fixture; the gate must still pin its chosen source and
workflow bytes explicitly.

Tasks:

- [ ] Pin one Automata commit and the exact bytes of its checked-in
  `.ci/workflows/ci.yml`.
- [ ] Deliver the normal signed provider event and execute every job through
  product ingress, compilation, scheduling, shipped runners, Results, and
  Checks.
- [ ] Do not remove jobs, alter `runs-on`, replace `uses:`, change conditions,
  rewrite scripts, or substitute services for the Automata run.
- [ ] Supply only external installation, repository, secret, variable, runner,
  object-store, and certificate configuration that the unchanged workflow
  legitimately expects.
- [ ] Run PostgreSQL service jobs through the production service path and
  ordinary Docker and rootless Podman commands through the isolated `DCK-01`
  endpoint/store.
- [ ] Execute artifact upload, `hashFiles`, checkout, setup actions, matrix
  shards, concurrency, frontend/browser work, static builds, and coverage
  exactly as declared.
- [ ] Compare GitHub and Automata job graphs, conditions, outcomes,
  conclusions, outputs, summaries, annotations, artifacts, Checks, and cleanup
  using normalized environmental inputs.
- [ ] Repeat success, selected failure, cancellation, runner loss, and
  control-plane restart cases without editing the workflow.
- [ ] Make CI fail when the repository workflow changes without refreshing the
  pinned conformance record and compatibility review.
- [ ] Require a real GitHub App installation and live GitHub.com provider path;
  the loopback emulator may debug protocol behavior but cannot satisfy this
  unchanged-repository acceptance gate.

Acceptance:

- [ ] The complete workflow succeeds repeatedly on GitHub Actions and Automata
  with no product-path fake or YAML variant.
- [ ] Every remaining observable difference is an approved, documented
  divergence with an early rejection or normalization rule.
- [ ] The report records exact source, workflow digest, runner/profile/action
  versions, helper image digests, and infrastructure topology.


## Explicit decisions that unblock implementation

These are product choices, not coding leftovers. Assign one decision owner and
record the result before the dependent package reaches implementation. An
approved divergence must name its early rejection boundary and test.

- [ ] **Service image mutability:** continue requiring immutable digests, or
  support tags with resolver-captured provenance (`PROV-02`).
- [ ] **Absolute working directories:** keep workspace confinement, or define
  additional safe roots and provider contracts (`RUN-02`).
- [ ] **Custom shell templates:** support GitHub's one-`{0}` command templates
  on each platform, or publish a strict supported grammar (`RUN-02`).
- [ ] **Insecure legacy workflow commands:** honor
  `ACTIONS_ALLOW_UNSECURE_COMMANDS`, or retain a deliberate secure divergence
  with an admission diagnostic (`LOG-01`).
- [ ] **Legacy Results/cache protocols:** implement v1 compatibility and legacy
  environment variables, or require pinned modern clients (`CACHE-02`).
- [ ] **GitHub REST compatibility:** decide which action-required REST calls go
  directly to GitHub and which, if any, require an Automata proxy (`ACT-02`).
- [ ] **Container CLI/daemon compatibility:** keep a narrow BuildKit proxy,
  expose the reviewed per-job Docker/Podman subset, or explicitly reject
  workflows needing a general socket (`BLD-01`, `DCK-01`).
- [x] **Windows trust:** use one fresh Hyper-V-isolated Windows container per
  job and reject native, process-isolated, or full-VM fallbacks (`PLAT-03`).
- [ ] **macOS execution:** commit to a provider and signing/test capacity, or
  keep source portability without advertising execution (`PLAT-02`).
- [ ] **Hosted-image parity:** publish selected immutable profiles or pursue
  broad preinstalled-tool parity (`PLAT-01`).
- [ ] **Cross-OS cache archives:** implement exact metadata semantics or reject
  the option (`CACHE-03`).
- [ ] **Artifact management scope:** same-run only, cross-run within a
  repository, or cross-repository with explicit authority (`ART-02`).
- [ ] **Native GitHub records:** state permanently that Automata publishes
  Checks and its own Results/UI rather than native Actions run/artifact/cache
  records (`CHECK-01`, `UI-01`).
- [ ] **Automata-specific resources:** keep extensions out of compatibility
  workflows or give them a namespaced capability/diagnostic model (`FND-01`).
- [ ] **Limits that differ from GitHub:** document each as compatibility limit,
  safety boundary, or configurable policy rather than copying values silently
  (`LIM-01`).

## Pull-request and handoff protocol

Use this sequence for large packages so four to six developers can work without
holding one integration branch for weeks:

1. [ ] **Decision/contract PR:** types, invariants, reason codes, limits, public
   traits, serialization version, and executable contract tests; no product
   claim.
2. [ ] **Storage/protocol PR:** migrations, exact replay, restart, mixed-version
   readers, and multi-replica tests.
3. [ ] **Adapter PRs:** one provider/store/OS at a time, based on the merged
   contract.
4. [ ] **Composition PR:** configuration, startup admission, capability
   publication, metrics, and fail-closed behavior.
5. [ ] **Companion integration PR:** add or graduate the corresponding scenario
   in `automata-integration-tests`, pin the merged Automata revision, and retain
   the required evidence classes.
6. [ ] **Acceptance PR:** real process/adapters, frozen fixtures, retained
   cross-repository evidence, documentation, and compatibility-state
   transition.

Handoff checklist:

- [ ] Contract owner posts the exact trait/schema commit and, only after the
  governance mode enables durable upgrades, its reserved migration number.
- [ ] Downstream owner rebases after that commit rather than copying types.
- [ ] Operation-ID and fingerprint material is documented and fixture-tested.
- [ ] Secret classification and durable-data rules are reviewed by lane C.
- [ ] Provider capability changes are reviewed by lanes R and P.
- [ ] Scheduler policy remains outside runner JobIR unless it is required for
  execution semantics.
- [ ] Final integrator runs merge-base tests plus affected OS/provider gates.
- [ ] Companion suite PR cites the same product and IT package IDs and pins one
  verified release bundle rather than a mutable branch.
- [ ] Evidence handoff records suite/product commits, executable and image
  digests, source/workflow/action locks, schemas, topology, native records,
  canonical diff, attempts, and cleanup.
- [ ] Lane C approves protected live-provider or side-effect execution; lane P
  approves disposable runner/provider infrastructure.

## Initial issue-creation checklist

Before implementation starts, create issues in this order:

- [ ] Create one epic for each section and one issue for each work-package ID.
- [ ] Add dependency links exactly as listed in each package.
- [ ] Mark the six lane starters and `FND-04` ready; leave later packages
  blocked.
- [ ] Reserve one rotating integration owner per wave.
- [ ] Assign canonical-schema ownership and reserve serialized-format versions
  for Wave 0 and Wave 1; reserve migration numbers only after the governance
  mode enables durable upgrades.
- [ ] Attach the relevant backlog section and current code evidence to every
  issue instead of copying a stale support claim.
- [ ] Record explicit non-goals, especially hosted-image parity, Docker socket
  compatibility, Windows isolation, and native GitHub records.
- [ ] Create a dashboard with columns for contract, storage, adapter,
  composition, acceptance, and documentation rather than only “in progress”.
- [ ] Limit each developer to one hotspot-owning package plus one review/helper
  package at a time.
- [ ] Review the critical path every week: `FND-01` → authority and scheduling;
  `FND-03` → logs/cancellation/actions; `RES-02` → Checks/UI; `GATE-01` →
  `DCK-01` → `GATE-06` → fleet and broader platform claims. `GATE-02`
  independently restores hosted Windows evidence after its own dependencies.

The plan is complete only when accepted work updates
[compatibility.md](../compatibility.md), the relevant gate in
[implementation-plan.md](../implementation-plan.md), and the dated evidence in
the underlying issue. Checking a box in this document alone never changes
product support.


---

[Previous: Windows, Linux and macOS profiles, architectures, and cross-OS cache](github-actions-parity-09-platforms.md) · [Next: Cross-repository integration tests](github-actions-parity-11-integration-tests.md) · [Parent execution plan](../github-actions-parity-execution-plan.md)
