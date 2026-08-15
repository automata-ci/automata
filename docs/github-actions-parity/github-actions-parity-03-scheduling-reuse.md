# GitHub Actions parity: Matrices, scheduling, dependencies, and reusable workflows

Implement durable matrix policy, dependency semantics, concurrency, reruns, and local or remote reusable workflows.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane S, with workflow and control-plane reviewers.

**Package IDs:** MAT-01, MAT-02, MAT-03, DEP-01, SCH-01, SCH-02, REU-01, REU-02, REU-03, REU-04.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
- [Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### MAT-01 — Matrix expansion differential closure

**Owner:** S. **Size:** L. **Dependencies:** WF-03.

Tasks:

- [ ] Verify static axes, expression axes, whole-matrix `fromJSON`, include
  merging, include-only matrices, exclude matching, duplicates, and empty
  axes.
- [ ] Verify deterministic ordering, identities, numbering, and matrix context.
- [ ] Enforce the 256-instance limit before partial publication.
- [ ] Verify matrix values in names, conditions, environment, concurrency,
  `continue-on-error`, and reusable calls.
- [ ] Resolve nested array/object expression behavior through differential
  fixtures before broadening support.

Acceptance:

- [ ] Repeated activation produces identical identities and ordering.
- [ ] Equivalent static and dynamic matrices produce equivalent contexts.
- [ ] Limit failure is atomic.

### MAT-02 — Durable `strategy.max-parallel`

**Owner:** S and sole scheduling-store owner. **Size:** XL.
**Dependencies:** MAT-01.

Tasks:

- [ ] Persist resolved matrix identity and `max-parallel` relationally rather
  than only in plan blobs.
- [ ] Add positive and bounded constraints.
- [ ] Gate materialization or selection by nonterminal sibling count.
- [ ] Promote waiting cells transactionally on terminal transitions.
- [ ] Recover capacity after success, cancellation, executor loss, retry, and
  service restart.
- [ ] Preserve independent capacity for separate matrix jobs and runs.
- [ ] Stress multiple selectors and database failover.

Acceptance:

- [ ] No race exceeds the configured cap.
- [ ] Capacity is never permanently leaked.
- [ ] Workflows without the option retain existing behavior.

### MAT-03 — Durable `strategy.fail-fast`

**Owner:** S. **Size:** XL. **Dependencies:** MAT-02, CAN-01 cancellation
contract.

Tasks:

- [ ] Persist one lineage-scoped fail-fast decision after a non-tolerated
  failure.
- [ ] Respect per-cell `continue-on-error`.
- [ ] Cancel unmaterialized, queued, leased, and running siblings through their
  correct mechanisms.
- [ ] Synthesize terminal state for cells that never ran.
- [ ] Make duplicate terminal callbacks and cancellation races idempotent.
- [ ] Preserve `fail-fast: false` behavior.

Acceptance:

- [ ] Restart cannot revive cancelled cells or strand the parent job.
- [ ] Final workflow and `needs` results are correct for mixed outcomes.

### DEP-01 — Dependencies, outputs, selected reruns, and limits

**Owner:** S. **Size:** L. **Dependencies:** MAT-01; final acceptance after
MAT-02 and MAT-03.

Tasks:

- [ ] Match implicit success and explicit status functions across chains,
  fans, diamonds, skips, cancellations, and tolerated failures.
- [ ] Match `needs.<job>.result`, missing outputs, dynamic indexing, and
  `toJSON(needs)`.
- [ ] Implement currently rejected output-merge semantics.
- [ ] Verify matrix-output merge ordering and duplicate names.
- [ ] Preserve secret-derived output suppression.
- [ ] Define selected reruns using completed dependency results and stable
  matrix identities.
- [x] Preserve rerun-all, rerun-failed-jobs, and rerun-specific-job as
  distinct idempotent operations with exact dependency expansion for the
  currently accepted graph shapes.
- [ ] Define which skipped, cancelled, continued, matrix, and reusable
  children belong to each rerun selection.
- [ ] Reject reruns of deleted or expired source and changed authority rather
  than compiling new evidence under the old run.
- [x] Preserve the current 50-rerun limit.
- [x] Preserve runner-requirements schema v1 when cloning rerun jobs and fail
  closed when source requirements use a different schema.

Acceptance:

- [ ] Reruns neither repeat unintended dependencies nor lose required prior
  outputs.
- [ ] Results are independent of which service replica receives callbacks.

### SCH-01 — Workflow concurrency parity correction

**Owner:** S. **Size:** M. **Dependencies:** none.

Tasks:

- [x] Reclassify `queue: max` as current GitHub syntax.
- [x] Change compatible pending capacity from 4,096 to 100.
- [x] Reject `queue: max` with `cancel-in-progress: true` before admission.
- [x] Verify repository scope, case-insensitive group normalization, FIFO by
  wait start, and one replacement pending run under standard mode.
- [x] Test expression-valued cancellation, reruns, duplicate admission,
  restart, and multi-replica races.

Acceptance:

- [x] Invalid combinations create no run.
- [x] Concurrent admission cannot exceed capacity or reorder durable FIFO.
- [x] Compatibility documentation is corrected.

### SCH-02 — Job-level concurrency

**Owner:** S. **Size:** XL. **Dependencies:** SCH-01, MAT-01, CAN-01.

Tasks:

- [ ] Evaluate group and cancellation for each concrete job or matrix cell at
  activation.
- [ ] Generalize durable occupancy to workflow runs and job instances in the
  correct repository-scoped namespace.
- [ ] Gate before JobIR publication and leasing.
- [ ] Persist running and pending occupants with fenced transitions.
- [ ] Release and promote occupants on every terminal path.
- [ ] Route replacement cancellation through normal cleanup machinery.
- [ ] Test skipped and zero-instance jobs, matrix-derived groups,
  workflow/job collisions, reruns, and multi-replica races.

Acceptance:

- [ ] At most one running and one replacement pending occupant exists in
  standard mode.
- [ ] Restart cannot leak occupancy or publish blocked work.
- [ ] No coordination policy is added to runner JobIR.

### REU-01 — Prove local reusable workflows through product composition

**Owner:** S. **Size:** L. **Dependencies:** FND-02, DEP-01 contract.

Tasks:

- [x] Preserve the durable repository-local reusable-call coordinator runtime
  for child-graph publication and completion, public-output mapping,
  secret-derived output suppression, and exact replay.
- [x] Preserve coordinator records as control-plane state distinct from
  concrete reusable child jobs.
- [ ] Drive webhook or dispatch through exact source, catalog compilation,
  recursive expansion, child jobs, outputs, caller `needs`, and final Check.
- [ ] Restart at publication, child completion, output aggregation, and caller
  finalization.
- [ ] Test duplicate delivery, skips, cancellation, zero-child workflows, and
  permission ceilings.
- [ ] Prove coordinators never project as runner jobs.

Acceptance:

- [ ] A real repository-local called workflow runs without mocks.
- [ ] Every coordinator operation is idempotent and restart-safe.

### REU-02 — Remote reusable-workflow source and provenance

**Owner:** W; C supplies the authenticated-source contract and S reviews
integration. **Size:** XL. **Dependencies:** REU-01, AUTH-02.

Tasks:

- [ ] Parse `owner/repo/.github/workflows/file@ref`.
- [ ] Resolve branch, tag, and SHA to one immutable commit.
- [ ] Fetch public, private, internal, and configured-GHES source with exact
  repository authority.
- [ ] Reject redirects and cross-host credential-scope changes.
- [ ] Persist requested ref, resolved commit, workflow path, source digest, and
  authority evidence.
- [ ] Cache only by immutable identity.
- [ ] Extend cycle/depth detection across repositories.
- [ ] Test moved tags, deleted refs, missing access, and fork provenance.

Acceptance:

- [ ] Execution never depends on a mutable ref after admission.
- [ ] Audit records identify exact called source.
- [ ] Unauthorized source never leaks existence or credentials.

### REU-03 — Reusable workflows with matrices and concurrency

**Owner:** S. **Size:** XL. **Dependencies:** REU-01, MAT-02, MAT-03, SCH-02.

Tasks:

- [ ] Create one deterministic durable call coordinator per matrix cell.
- [ ] Apply max-parallel, fail-fast, per-cell continuation, and job
  concurrency.
- [ ] Aggregate per-cell outputs with verified completion semantics.
- [ ] Propagate caller, matrix, concurrency, and called-workflow cancellation.
- [ ] Test static and dynamic matrices, nested calls, retries, and restart.

Acceptance:

- [ ] Call cells behave like ordinary matrix jobs to the caller graph.
- [ ] Coordinators remain control-plane objects, never fake runner jobs.

### REU-04 — Reusable inputs, secrets, permissions, outputs, and reruns

**Owner:** S with C security review. **Size:** XL. **Dependencies:** REU-01,
AUTH-01, CFG-02; remote-ref cases also depend on REU-02.

Tasks:

- [ ] Match required, default, unknown, boolean, number, and string inputs.
- [x] Preserve value-free environment, secret-name, and variable-name
  requirements on every expanded reusable child job, and require exact
  evidence before atomically sealing its child graph.
- [ ] Implement explicit secret remapping and full `secrets: inherit`.
- [ ] Verify every secret hop and detect case collisions.
- [ ] Enforce permission ceilings at every depth.
- [ ] Match output behavior for skip, failure, cancellation, and secret
  suppression.
- [ ] Enforce ten levels and 50 unique workflows.
- [ ] Use mutable refs for full reruns and the original resolved commit for
  selected or failed-job reruns.
- [ ] Verify caller/callee `env`, defaults, context, runner access,
  concurrency, and cancellation boundaries.

Acceptance:

- [ ] A callee cannot gain a secret or permission absent from its caller.
- [ ] Limit failures are atomic and identify the call chain.
- [ ] Reruns use the correct immutable source.

---

[Previous: Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md) · [Next: Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
