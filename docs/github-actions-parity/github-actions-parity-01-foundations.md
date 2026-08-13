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

- [ ] Define a machine-readable entry for every workflow, job, step, action,
  trigger, and runtime feature.
- [ ] Record decode, compile, projection, admission, scheduler, Linux, Windows,
  Kubernetes, Results, and differential status independently.
- [ ] Record the evaluation phase and required runtime/provider capabilities.
- [ ] Record the stable unsupported diagnostic and source span policy.
- [ ] Inventory every currently accepted decoder field.
- [ ] Inventory every current late projection or executor rejection.
- [ ] Move known incompatibilities to publication or admission.
- [ ] Generate tests that fail when a decoded field has no downstream entry.
- [ ] Generate tests that fail when a compatibility claim has no acceptance
  fixture.
- [ ] Validate or generate the compatibility table from the registry.
- [ ] Add a reviewed-delta mechanism for new GitHub syntax, permissions,
  variables, limits, and action runtimes.
- [ ] Run a scheduled, source-pinned detector against the reviewed GitHub
  Actions reference catalog and open a bounded diff issue when syntax,
  contexts, permissions, events, limits, or default variables change.
- [ ] Track the pinned `actions/runner` baseline and automatically require
  compatibility review when a newer approved release is selected.
- [ ] Store reference snapshots with retrieval date, source URL, content
  digest, parser version, and a human-approved replacement workflow.

Acceptance:

- [ ] Every accepted field is either product-runnable or rejected before a run
  is created.
- [ ] Adding a decoder field without a registry entry fails CI.
- [ ] “Component complete” cannot be inferred from parsing alone.
- [ ] Existing unsupported diagnostics remain stable or have an explicit
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
to own the product export and composition contracts it consumes.

Tasks:

- [x] Establish an external immutable fixture catalog with exact source,
  workflow, and action locks and reject unreviewed workflow inventory drift.
- [x] Establish a fail-closed loopback GitHub protocol emulator and keep its
  evidence distinct from live GitHub proof.
- [x] Establish canonical evidence types and a strict structural comparator;
  the evidence schema and comparator reject incomplete records, while concrete
  target adapters remain incomplete.
- [x] Establish a manual reusable fixture composing signed webhook ingress,
  immutable source storage, workflow admission, PostgreSQL scheduling,
  Results, Checks, and real control-plane and runner processes.
- [ ] Add deterministic fake-clock control.
- [ ] Inject exact raw webhook bodies and signatures.
- [ ] Stub paginated GitHub APIs, rate limits, indeterminate mutations, and
  credential failures.
- [ ] Restart individual services between every durable transition.
- [ ] Snapshot selected workflows, expanded jobs, dependencies, step results,
  outputs, annotations, summaries, logs, services, artifacts, caches, effective
  authority, and cleanup.
- [ ] Catalog every fixture by upstream version, immutable commit/digest,
  operating system, provider, external prerequisites, and expected digest.
- [ ] Convert current checkout, upload/download-artifact, cache, service, and
  Windows fixtures into catalog entries.
- [ ] Separate hermetic CI fixtures from deployment-owned live tests.
- [ ] Make missing live prerequisites skip explicitly rather than report a
  false pass.
- [ ] Allow the same source/event fixture to consume GitHub-derived expected
  snapshots.
- [ ] Evolve the existing schema-v1 export with a versioned per-step-output
  boundary; never synthesize missing output maps as empty evidence.
- [ ] Keep emulator, hermetic GitHub stub, and live-provider evidence as
  distinct catalog classes so one cannot satisfy another's acceptance gate.
- [ ] Shard without shared rows, ports, credentials, or object prefixes.
- [ ] Publish the evidence and scenario-admission contracts consumed by
  `IT-02`/`IT-03`, and provide exact source/build/profile metadata to the
  `IT-01` release-bundle contract.

Acceptance:

- [ ] A signed push reaches a terminal run, Results, and Check through real
  product composition without network access.
- [ ] Duplicate delivery replays, while changed bytes under the same identity
  conflict.
- [ ] A test can fail source, token, Results, Checks, runner, or object storage
  independently.
- [ ] Fixture provenance is auditable offline.
- [ ] Restart snapshots remain deterministic.

### FND-03 — Extract executor integration seams

**Owner:** R. **Size:** M. **Dependencies:** none.

**Primary scope:** `automata-ci-job-executor-github` only; no behavior change.

Tasks:

- [ ] Extract shell selection, script extension/fixup, and argv construction
  from `executor.rs` into `shell.rs`.
- [ ] Extract repository-action archive materialization into
  `action_content.rs`.
- [ ] Extract job/service container request construction into
  `container_runtime.rs`.
- [ ] Keep action lifecycle, post registration, orchestration, and operation
  identity in `executor.rs`.
- [ ] Preserve output parsing in `output.rs` until the streaming contract
  lands.
- [ ] Preserve every operation-ID input exactly.
- [ ] Add source-level tests preventing extracted modules from bypassing
  cancellation, bounds, or secret classification.

Acceptance:

- [ ] No public API or observable behavior changes.
- [ ] Existing golden executor tests remain byte-for-byte identical.
- [ ] Lanes R, P, and action-focused contributors can subsequently edit
  separate files.

### FND-04 — Contract, migration, and limit governance

**Owner:** rotating integration owner. **Size:** S. **Dependencies:** none.

Current baseline: runner protocol v1, message schema v1, JobIR schema v1,
runner-requirements schema v1, and one canonical greenfield
`0001_initial_schema.sql`. The checked-in
[foundation governance registry](../governance/foundation-governance-v1.json)
is a bootstrap inventory and does not imply upgrade compatibility.

Tasks:

- [x] Record the canonical greenfield migration inventory and fail CI if a
  parallel branch adds or reserves a numbered migration while that mode is
  active.
- [ ] Keep schema changes in the canonical greenfield migration and its
  inventory test until the first released schema creates supported durable
  upgrade state.
- [x] Record owners and exact source evidence for the current JobIR, protobuf,
  core envelopes, workflow-plan, workflow-runtime-policy, protocol, message,
  runner-requirements, and canonical store contracts.
- [ ] Complete the registry for every durable and wire format, including event
  evidence and provider-owned persistence.
- [ ] Require compatibility readers for every durable or wire-format change.
- [ ] Expand the seeded machine-readable inventory to every GitHub and stricter
  Automata limit, enforcement phase, and reason code.
- [x] Require boundary-minus-one, boundary, and boundary-plus-one tests for
  every registered limit.
- [x] Define who updates root manifests, lockfiles, shared CI, and generated
  protobuf fixtures during each wave.

Acceptance:

- [x] Migration inventory drift fails before parallel branches can claim a
  nonexistent next sequence.
- [ ] Parallel schema branches coordinate changes to the canonical baseline.
- [ ] No durable format changes without a version and compatibility test.
- [ ] Limits have one owner and one enforcing phase.

---

[Parent execution plan](../github-actions-parity-execution-plan.md) · [Next: Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
