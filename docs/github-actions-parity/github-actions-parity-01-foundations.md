# GitHub Actions parity: Foundations, conformance, and governance

Build typed capability requirements, reusable product fixtures, executor seams,
and shared schema and limit contracts that unblock parallel implementation.

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

### FND-01 — Typed capability requirements and early rejection

**Owner:** W. **Size:** L. **Dependencies:** none.

**Primary scope:** workflow decoder/compiler, workflow service projection,
runner capability model, compatibility tests, and `docs/compatibility.md`.

Tasks:

- [x] Define stable typed identifiers for runner and provider capabilities used
  by scheduling and admission.
- [x] Carry evaluation phase and required runtime or provider capabilities in
  the compiled product contracts that consume them.
- [x] Keep stable unsupported diagnostics and exact source spans in focused
  decoder, compiler, projection, and admission tests.
- [x] Move known incompatibilities to publication or admission. Job-level
  concurrency, deployment environments, and direct container actions now fail
  in compilation with exact source spans; projection guards remain for plans
  constructed by other frontends.
- [x] Preserve projection guards for logical plans constructed by non-GitHub
  frontends rather than assuming the source compiler was the only ingress.
- [x] Maintain explicit support stages in `docs/compatibility.md`; parsing a
  field alone never advances its product status.
- [x] Pin the reviewed `actions/runner` baseline in the compatibility document
  and require conformance evidence when that baseline changes.

Acceptance:

- [x] Known parsed-but-unrunnable surfaces have focused tests proving rejection
  before a run is created.
- [x] Scheduler and runner admission require the exact capabilities carried by
  the product contract rather than inferring missing capabilities.
- [x] “Component complete” cannot be inferred from parsing alone.
- [x] Existing unsupported diagnostics remain covered by owning behavior tests
  or have an explicit migration note.

Handoff: feature owners update the typed contract, owning behavior tests, and
compatibility entry together; only the acceptance pull request may mark a
product stage available.

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
`0001_initial_schema.sql`. There is no released schema or supported database
upgrade source. Version, reader, rejection, and limit tests remain with their
owning product crates.

Tasks:

- [x] Keep schema changes in the canonical greenfield migration while there is
  no released schema to upgrade.
- [x] Keep version declarations and focused reader or forward-version rejection
  tests in the crate that owns each durable or wire contract.
- [x] Retain existing boundary tests beside the product limits they exercise
  rather than treating a documentation entry as runtime evidence.
- [x] Define who updates root manifests, lockfiles, shared CI, and generated
  protobuf fixtures during each wave.

Acceptance:

- [x] Parallel schema branches coordinate changes through one owner of the
  canonical baseline.
- [x] Owning readers retain their existing focused compatibility or
  unsupported-version tests.
- [x] Existing enforced product limits retain owner-local boundary tests.

---

[Parent execution plan](../github-actions-parity-execution-plan.md) · [Next: Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
