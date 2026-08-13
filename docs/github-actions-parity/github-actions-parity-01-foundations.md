# GitHub Actions parity: Foundations, conformance, and governance

Build the capability registry, reusable product fixture, executor seams, and shared schema/limit governance that unblock parallel implementation.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Integration owner with lanes W, R, and X.

**Package IDs:** FND-01, FND-02, FND-03, FND-04.

## Related workstreams

- Start with this document after reading the parent plan.

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### FND-01 — Capability registry and early rejection

**Owner:** W. **Size:** L. **Dependencies:** none.

**Primary scope:** workflow decoder/compiler, workflow service projection,
runner capability model, compatibility tests, and `docs/compatibility.md`.

Tasks:

- [x] Define a machine-readable entry for every workflow, job, step, action,
  trigger, and runtime feature.
- [x] Record decode, compile, projection, admission, scheduler, Linux, Windows,
  Kubernetes, Results, and differential status independently.
- [x] Record the evaluation phase and required runtime/provider capabilities.
- [x] Record the stable unsupported diagnostic and source span policy.
- [x] Inventory every currently accepted decoder field, trigger, and action
  runtime value directly from source.
- [x] Inventory every current logical projection rejection and classify the
  executor's bounded admission/error categories.
- [x] Move known incompatibilities to publication or admission. Job-level
  concurrency, deployment environments, and direct container actions now fail
  in compilation with exact source spans; projection guards remain for plans
  constructed by other frontends.
- [x] Generate tests that fail when a field is added to any governed current
  decoder surface without a downstream entry; adding a new decoder surface
  requires extending the closed inventory in the same change.
- [x] Generate tests that fail when a compatibility claim has no acceptance
  fixture.
- [x] Validate the compatibility table from the registry.
- [x] Add a reviewed-delta mechanism for new GitHub syntax, permissions,
  variables, limits, and action runtimes.
- [x] Run a scheduled, source-pinned detector against the reviewed GitHub
  Actions reference catalog and open a bounded diff issue when syntax,
  contexts, permissions, events, limits, or default variables change.
- [x] Track the pinned `actions/runner` baseline and automatically require
  compatibility review when a newer approved release is selected.
- [x] Store reference snapshots with retrieval date, source URL, content
  digest, parser version, and a human-approved replacement workflow.

Acceptance:

- [x] Every accepted field is either mapped to its independently stated product
  stage or rejected before a run is created.
- [x] Adding a field to a governed decoder surface without a registry entry
  fails CI.
- [x] “Component complete” cannot be inferred from parsing alone.
- [x] Existing unsupported diagnostics remain stable or have an explicit
  migration note.

Handoff: feature owners add registry entries in their contract pull request;
only the acceptance pull request may mark a product stage available.

### FND-02 — Product conformance fixture and immutable fixture catalog

**Owner:** X. **Size:** XL. **Dependencies:** none.

**Primary scope:** product integration-test support, GitHub HTTP stubs,
PostgreSQL and object-store fixtures, conformance snapshots, and CI sharding.

Current foundation on `main`: the private conformance read API exports a
bounded `schemaVersion: 1` document with delivery/run identities, expanded
JobIR, matrix and strategy context, latest attempt/result evidence, and
artifact metadata. It intentionally omits raw logs, secret-bearing runtime
inputs, artifact bytes, and per-step outputs. The loopback provider emulator is
protocol evidence only; it cannot prove GitHub.com networking, App
installation, or live credential behavior.

This package adds an opt-in, media-type-negotiated `schemaVersion: 2` export.
It returns verified masked log frames and gives fields modeled as optional by
the export an explicit `present` or `unavailable` state; missing per-step
outputs are never synthesized as an empty map. Legitimate semantic `null`
values inside typed GitHub data remain representable. The product-owned
`automata-ci-conformance` crate now defines exact
  catalog, provenance, evidence-class, fake-clock, failure-script, restart,
  webhook, GitHub-stub, live-prerequisite, and shard contracts. The product now
  also publishes an explicit composition behind the
`automata-ci/conformance-test-support` Cargo feature and one
`ProductConformanceShard` provisioning adapter that consumes all four identities
from a selected plan entry; default production builds do not expose or select
that composition, and companion process wiring remains pending.

The companion
[`automata-integration-tests`](https://github.com/automata-ci/automata-integration-tests)
repository was audited at `af7e2ca`. It already supplies immutable fixture
schema v3 locks, complete top-level workflow byte auditing, digest-addressed
source/action packs, a strict loopback provider emulator, real local Automata
process composition, a schema-v1 canonical evidence model, and a fail-closed
comparator. That harness is manual, its default lane is provider-emulated, its
CI does not launch Automata, and all seven scenarios remain candidates. The
[integration-test workstream](github-actions-parity-11-integration-tests.md)
owns the cross-repository harness and graduation work; this package continues
to own the product export and composition contracts intended for that harness.

Tasks:

- [x] Establish an external immutable fixture catalog with exact source,
  workflow, and action locks and reject unreviewed workflow inventory drift.
- [x] Establish a fail-closed loopback GitHub protocol emulator and keep its
  evidence distinct from live GitHub proof.
- [x] Establish canonical evidence types and a strict structural comparator;
  the evidence schema and comparator reject incomplete records, while concrete
  target adapters remain incomplete.
- [x] Preserve the companion repository's manual reusable fixture composing signed webhook ingress,
  immutable source storage, workflow admission, PostgreSQL scheduling,
  Results, Checks, and real control-plane and runner processes.
- [x] Publish a deterministic monotonic fixture-control clock and an explicit
  product composition that injects it into workflow admission, Results, and
  the real GitHub provider runtime builder without changing production defaults.
- [ ] Make the companion process launcher select that opt-in composition for
  every launched control-plane and runner process rather than using wall time.
- [x] Send validated byte-exact raw webhook fixtures through the production
  Axum ingress. The fixture type locks the body and signature at construction
  or decoding, and the route test proves invalid signatures write nothing,
  exact replays are idempotent, and changed bytes under one delivery identity
  conflict.
- [x] Serve paginated GitHub APIs, rate limits, indeterminate mutations, and
  credential failures through a bounded exact-order loopback server; compose
  the real hardened GitHub HTTP client against its held shard listener.
- [x] Provide a shell-free bounded child-process restart probe and require the
  exact scheduled service restart before each durable fixture transition.
- [ ] Apply that restart probe to the real control-plane, runner, PostgreSQL,
  and object-store processes and retain their restart evidence in the companion
  run.
- [ ] Snapshot selected workflows, expanded jobs, dependencies, step results,
  outputs, annotations, summaries, logs, services, artifacts, caches, effective
  authority, and cleanup.
- [ ] Catalog every fixture by upstream version, immutable commit/digest,
  operating system, provider, external prerequisites, and expected digest.
- [ ] Convert current checkout, upload/download-artifact, cache, service, and
  Windows fixtures into catalog entries.
- [x] Define mutually exclusive contract, hermetic-product, provider-emulator,
  and live-provider evidence classes so one class cannot satisfy another.
- [ ] Make CI and deployment adapters select and enforce those evidence
  classes rather than relying on convention.
- [x] Make catalog-bound `ScenarioAdmission` return an explicit non-passing
  `Skipped` outcome for missing live prerequisites.
- [ ] Enforce that outcome in the companion CI/live adapter rather than merely
  publishing the contract.
- [ ] Allow the same source/event fixture to consume GitHub-derived expected
  snapshots.
- [x] Evolve the existing schema-v1 export with a versioned per-step-output
  boundary; never synthesize missing output maps as empty evidence.
- [x] Keep emulator, hermetic GitHub stub, and live-provider evidence as
  distinct catalog classes so one cannot satisfy another's acceptance gate.
- [x] Derive isolated shard identities without shared PostgreSQL schemas,
  port-reservation keys, credential scopes, or object prefixes.
- [x] Make the product-owned conformance provisioning adapter consume the
  selected shard's PostgreSQL schema, object prefix, credential scope, and
  port-reservation key together. It marker-owns a real PostgreSQL schema,
  gates real immutable-blob operations, scopes the hermetic GitHub credential
  adapter, and holds real loopback listeners through handoff.
- [ ] Make the companion real-process adapter consume that product provisioning
  boundary for every control-plane/runner process and external S3 resource;
  existing standalone tests that bind port `0` or invent local fixture names
  are not evidence for this task.
- [x] Publish strict evidence, scenario-admission, and source/build/profile
  metadata contracts for `IT-01`/`IT-02`/`IT-03` consumption.
- [ ] Add the companion-repository JSON/CLI adapter that consumes those
  contracts; the companion's existing schema-v3 fixture model remains a
  distinct external contract.

Acceptance:

- [ ] A signed push reaches a terminal run, Results, and Check through real
  product composition without network access.
- [x] Production ingress and its durable repository contract replay an exact
  delivery while changed bytes under the same identity conflict.
- [x] Typed product-port adapters can fail source, token, Results, the Checks
  credential boundary, runner, or object storage independently; mutating ports
  can apply an operation and then return an indeterminate outcome.
- [ ] Process-composed tests exercise those failures through the full workflow
  lifecycle, including Checks publication after credential acquisition.
- [x] Canonical catalog and evidence-envelope provenance is auditable offline.
- [ ] Real process adapters emit and retain that bound envelope for every run.
- [ ] Restart snapshots from real service processes remain deterministic; the
  ordering and restart-record contract is complete, while retained process
  evidence belongs to the pending adapter run.

### FND-03 — Extract executor integration seams

**Owner:** R. **Size:** M. **Dependencies:** none.

**Primary scope:** `automata-ci-job-executor-github` only; no behavior change.

Tasks:

- [x] Extract shell selection, script extension/fixup, and argv construction
  from `executor.rs` into `shell.rs`.
- [x] Extract repository-action archive materialization into
  `action_content.rs`.
- [x] Extract job/service container request construction into
  `container_runtime.rs`.
- [x] Keep action lifecycle, post registration, orchestration, and operation
  identity in `executor.rs`.
- [x] Preserve output parsing in `output.rs` until the streaming contract
  lands.
- [x] Preserve every operation-ID input exactly.
- [x] Add source-level tests preventing extracted modules from bypassing
  cancellation, bounds, or secret classification.

Acceptance:

- [x] No public API or observable behavior changes.
- [x] Existing golden executor tests remain byte-for-byte identical.
- [x] Lanes R, P, and action-focused contributors can subsequently edit
  separate files.

### FND-04 — Contract, migration, and limit governance

**Owner:** rotating integration owner. **Size:** S. **Dependencies:** none.

Current baseline: runner protocol v1, message schema v1, JobIR schema v1,
runner-requirements schema v1, and one canonical greenfield
`0001_initial_schema.sql`. The checked-in
[foundation governance registry](../governance/foundation-governance-v1.json)
is an active exact-current inventory; it does not imply upgrade compatibility.

Tasks:

- [x] Record the canonical greenfield migration inventory and fail CI if a
  parallel branch adds or reserves a numbered migration while that mode is
  active.
- [x] Record owners, exact version/evidence bindings, and named tests for the
  current JobIR, protobuf, core envelopes, workflow plan, workflow runtime
  policy/workspace/derivation, protocol, message, and runner requirements;
  record the canonical store migration policy separately.
- [x] Complete the registry for every named/versioned internal durable and wire
  format declaration in the governed Rust and TypeScript roots, including
  event evidence, provider-owned persistence, and the separately mapped
  canonical Store migration. Ordinary unversioned public JSON APIs are
  explicitly outside this inventory.
- [x] Require a source-bound, non-ignored compatibility-reader test for every
  prior version whenever a named/versioned durable or wire format advances
  beyond v1; `exact-current-only` cannot advance to v2.
- [x] Discover every named/versioned derived contract token (digest and identity
  domains, cryptographic contexts, wire discriminators, credential keys, and
  storage namespaces) across crate sources; require a source-local owner/kind
  registration or an exact-source exclusion under a separate evolution policy.
- [x] Expand the machine-readable inventory to every GitHub and stricter
  Automata limit, enforcement phase, and reason code.
- [x] Require every registered limit to bind distinct boundary-minus-one,
  boundary, and boundary-plus-one fragments inside an attributed Rust test.
- [x] Define who updates root manifests, lockfiles, shared CI, and generated
  protobuf fixtures during each wave.

Acceptance:

- [x] Migration inventory drift fails before parallel branches can claim a
  nonexistent next sequence.
- [x] No governed named/versioned internal durable or wire format changes
  without a version and compatibility test, with complete reader coverage for
  all prior versions after v1.
- [x] Limits have one owner and one enforcing phase.

---

[Parent execution plan](../github-actions-parity-execution-plan.md) · [Next: Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
