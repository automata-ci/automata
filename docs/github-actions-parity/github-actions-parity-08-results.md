# GitHub Actions parity: Results, Checks, artifacts, cache, and product UI

Complete durable results, per-job Checks, artifact and cache lifecycle, exact clients, and the run-management UI.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane X, with runner, provider, and control-plane reviewers.

**Package IDs:** RES-01, RES-02, CHECK-01, ART-01, ART-02, ART-03, CACHE-01, CACHE-02, UI-01.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)
- [Windows, Linux and macOS profiles, architectures, and cross-OS cache](github-actions-parity-09-platforms.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### RES-01 — Exact artifact and cache client harness

**Owner:** X. **Size:** M. **Dependencies:** FND-02.

This package turns the existing protocol slices into reproducible client
compatibility tests. It does not add new protocol operations.

Current `upstream/main` documents the upload-artifact v7.0.1 protocol slice at
commit `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` with
`@actions/artifact` 6.2.0, plus `@actions/cache` 5.0.5 over CacheService v2.
Ignored offline tests import explicitly supplied local client modules and never
download packages. They are focused client-library and protocol evidence, not
ordinary-CI acceptance of every exact action wrapper or the production stores.
Runner protocol v1 carries a required, per-attempt Results authority bundle;
there is no runner- or fleet-wide Results credential.

Tasks:

- [x] Record the current upload-artifact, embedded artifact-client, and
  CacheService v2 client versions with immutable release or commit identity.
- [x] Require explicit local module paths for the current ignored exact-client
  tests; never download mutable dependencies in those tests.
- [ ] Pin and verify exact `actions/download-artifact` and complete action
  wrappers, including each embedded client version, from one immutable fixture.
- [ ] Build one reusable harness that supplies Results URLs, scoped runtime
  tokens, repository/ref/run identity, PostgreSQL, production object storage,
  and deterministic time.
- [x] Exercise CreateArtifact, block upload, block-list commit, finalize, list,
  signed download, cache reserve/finalize/restore, exact keys, restore-key
  precedence, and single-range responses in focused adapter tests.
- [ ] Carry that matrix through the reusable real-store harness and complete
  malformed-route, expired-token, wrong-scope, replay, size-mismatch,
  duplicate-finalize, truncated-body, and range-request coverage.
- [ ] Record request/response transcripts with credentials redacted.
- [ ] Publish the supported client/version matrix from one machine-readable
  fixture used by documentation and tests.

Acceptance:

- [ ] Exact action wrappers run against the real Results HTTP adapter,
  PostgreSQL repository, and production blob store.
- [ ] The suite is deterministic and network independent.
- [ ] Unsupported operations fail with stable protocol responses rather than
  connection resets or generic internal errors.

### RES-02 — Complete job, step, log, and result contract

**Owner:** X with R supplying executor records. **Size:** L.
**Dependencies:** FND-04, RUN-01, LOG-02.

The current fenced, schema-versioned `JobResult` retains the attempt, terminal
job outputs and conclusion, step outcome/conclusion/timestamps, summaries, and
annotations. Validation currently bounds public job outputs to 1 MiB under the
provider-compatible UTF-16 accounting rule, retained attachments to 8 MiB, and
annotations to 4,096. It does not retain per-step outputs, step/action phase
identity, log archives, or the complete downstream failure taxonomy.

Tasks:

- [x] Preserve the current schema-versioned, fenced job result and its retained
  job outputs, step results, summaries, annotations, and validation bounds.
- [ ] Inventory every conclusion, outcome, skipped/cancelled state, timing,
  attempt, output, summary, annotation, and log field required downstream.
- [ ] Define compatibility readers and a migration contract for the next
  durable result-schema revision.
- [ ] Preserve step number, action identity, nested composite path, pre/main/post
  phase, retry attempt, and runner identity without exposing credentials.
- [ ] Distinguish infrastructure failure, policy rejection, user failure,
  cancellation, timeout, neutral, skipped, and continued failure.
- [ ] Define ordered, bounded streaming log chunks and finalization semantics.
- [x] Enforce explicit byte and count limits for current summaries and
  annotations.
- [ ] Add deterministic truncation indicators and complete downstream
  summary/annotation retention semantics.
- [ ] Define bounded log-archive generation/download plus authorized log
  deletion without changing the immutable terminal conclusion.
- [ ] Define run deletion as a durable, idempotent tombstone/reclamation
  workflow that preserves the minimum required audit record.
- [ ] Make result finalization idempotent under duplicate runner frames,
  reconnect, and control-plane failover.
- [ ] Add mixed-version reader, migration, replay, and corruption tests for the
  next schema revision.

Acceptance:

- [ ] A complete workflow result can be projected without re-reading JobIR or
  raw provider payloads.
- [ ] Duplicate or reordered terminal frames cannot change a finalized result.
- [ ] Logs, summaries, annotations, and outputs retain masking classification.

### CHECK-01 — Per-job GitHub Check projection

**Owner:** X with C reviewing provider authority. **Size:** L.
**Dependencies:** RES-02, AUTH-03.

Automata retains a fenced workflow subject as the admission and diagnostic
authority, then creates one child Check subject for every concrete job attempt.
The child copies the exact provider identity and commit from its workflow
authority, advances from queued through in-progress to its terminal conclusion,
and links directly to that job in the Automata dashboard. Initial attempts and
later retries use the same transactional insertion path. Automata does not
pretend these are native GitHub Actions run records.

The Wave 1 contract slice is component-complete: claims freeze exact identity,
lifecycle timestamps, authority, presentation evidence, and annotation
progress; provider mutations use bounded reconciliation and durable issue
cutoffs; and requested actions map to the existing reauthorized, idempotent
rerun selections. This does not complete `CHECK-01` product acceptance. The
remaining package work still depends on the complete `RES-02` result surface,
the final `AUTH-03` credential path, broader workflow fixtures, and retained
live-GitHub evidence.

Tasks:

- [x] Preserve one fenced aggregate Check subject and durable outbox lifecycle
  for each delivery/schedule workflow subject and physical rerun.
- [x] Define stable per-job-attempt external IDs while preserving the existing
  distinct workflow subject for each physical rerun.
- [x] Project queued, in-progress, completed, skipped, cancelled, failed, and
  timed-out states and conclusions from the durable attempt lifecycle.
- [x] Publish accurate start and completion timestamps.
- [x] Publish a bounded job name and an exact HTTPS dashboard `details_url`.
- [x] Publish bounded title, summary, text, and annotations.
- [x] Batch annotations within GitHub API limits and preserve deterministic
  ordering.
- [x] Add requested-action support only after its authority and idempotency
  model is explicit; otherwise omit the field.
- [ ] Publish status badges from durable workflow/ref state with bounded cache
  behavior and no credential-bearing redirect.
- [x] Decide whether optional commit-status projection is needed alongside
  Checks; implement an idempotent projector or record an explicit divergence.
- [ ] Extend reconciliation across delivery retries, out-of-order updates,
  force-push replacement, per-job attempts, and deleted refs without collapsing
  the existing rerun-specific workflow subjects.
- [x] Bound API retries and handle rate limiting without blocking scheduler
  progress.
- [ ] Add product fixtures for multi-job, matrix, reusable, cancelled, and
  partially failed workflows.

Acceptance:

- [x] Each visible job has one coherent Check lifecycle per attempt.
- [ ] Check publication is idempotent and resumes after process restart.
- [ ] Provider failures are observable and retryable without losing Automata's
  authoritative result.

### ART-01 — Same-run artifact behavior

**Owner:** X. **Size:** L. **Dependencies:** RES-01, RES-02.

The current server slice creates, stages, commits, and finalizes artifacts. An
authorized job can list finalized artifacts from its workflow run by exact name
or numeric ID and receive a short-lived, artifact-ID-and-digest-bound download
URL. Focused and ignored client-library tests cover upload/list/get/download
with digest verification, but do not prove the exact action wrappers running in
separate jobs or the complete download-selection surface.

Tasks:

- [x] Preserve same-run lookup by exact artifact name or numeric ID and
  digest-bound signed download.
- [ ] Run exact upload and download actions from separate jobs in one workflow.
- [ ] Match download-all, glob-pattern, and `merge-multiple` behavior, including
  duplicate path conflicts, through the exact download action.
- [ ] Verify name uniqueness, hidden-file policy, include/exclude behavior,
  compression, digest verification, empty matches, and path traversal safety.
- [ ] Define and implement `overwrite` behavior, including atomic replacement
  and authority checks, or reject it before client upload if intentionally
  unsupported.
- [ ] Apply configured retention within the supported maximum and expose the
  effective expiration.
- [x] Bind create/finalize authority to tenant, repository, run, job, attempt,
  and fence, and bind each signed download to artifact ID and content digest.
- [ ] Make finalize and list behavior deterministic under duplicate requests
  and concurrent same-name uploads.
- [ ] Scan zip entries, declared provenance subjects, sizes, and object keys for
  canonicalization and archive-bomb limits.
- [ ] Add cancellation and partial-upload cleanup behavior.

Acceptance:

- [ ] One unchanged Linux fixture uploads in one job and downloads in another.
- [ ] The downloaded tree and reported digest match the producer exactly.
- [ ] Cross-run/repository access is denied unless explicitly implemented by
  `ART-02`.

### ART-02 — Artifact management, retention, and garbage collection

**Owner:** X. **Size:** XL. **Dependencies:** ART-01, FND-04 limit ownership.

Current artifact metadata may expose an effective expiry and is available to
the authorized run UI, but cross-run management, deletion, retention workers,
and physical object garbage collection are not implemented.

Tasks:

- [ ] Specify list, lookup, download, delete, and overwrite scopes for current
  run, other runs, repositories, and tenants.
- [ ] Add durable artifact tombstones and idempotent deletion operations.
- [ ] Separate metadata deletion from physical object reclamation.
- [ ] Implement expiration scheduling, retryable object GC, orphan scanning,
  and bounded repair.
- [ ] Enforce per-artifact, per-run, per-repository, and tenant quotas before
  accepting bytes.
- [ ] Reconcile finalize/delete races and signed URL expiry.
- [ ] Add admin visibility without exposing object-store credentials or raw
  signed URLs.
- [ ] Test millions-of-record pagination, expiry backlog, partial object-store
  outage, and restore from database backup.

Acceptance:

- [ ] Deleted or expired artifacts become inaccessible immediately at the
  authority layer and are eventually removed physically.
- [ ] GC is restartable, rate limited, tenant fair, and safe under duplicate
  workers.
- [ ] Usage accounting converges after failures and repair.

### ART-03 — Artifact attestations and provenance

**Owner:** X with C reviewing signing authority. **Size:** L.
**Dependencies:** ART-01, OIDC-01, SEC-02.

Tasks:

- [ ] Decide the supported attestation formats and compatibility boundary.
- [ ] Bind each subject digest to the exact completed job, attempt, source,
  workflow digest, environment profile, runner, and declared artifact path.
- [ ] Define signer/key custody, rotation, verification, and revocation.
- [ ] Reject subjects not produced or sandbox-hashed by the job.
- [ ] Add upload, lookup, verification, and retention behavior.
- [ ] Integrate provenance into Results and UI without treating unsigned data
  as verified.
- [ ] Test tampered subjects, replay across runs, key rotation, cancellation,
  and deleted artifacts.

Acceptance:

- [ ] A verifier can reconstruct and validate the complete authority chain.
- [ ] No runner-supplied statement becomes trusted without server-side binding.

### CACHE-01 — Cache management and physical garbage collection

**Owner:** X. **Size:** L. **Dependencies:** RES-01, FND-04 limit ownership.

The current CacheService v2 slice implements create, finalize, and signed
download. Restore checks the current ref and then the server-owned default
branch, uses exact-key and ordered-prefix precedence, and keeps entries
immutable. PostgreSQL enforces seven-day inactivity eligibility and a 10 GiB
per-repository LRU quota, including concurrent-finalize accounting. Eviction
makes metadata ineligible immediately but leaves immutable objects for a future
collector; there is no management or delete API.

Tasks:

- [ ] Add list and delete operations with exact repository/ref authority.
- [ ] Support deletion by cache ID, exact key, key+ref, and bounded bulk cleanup
  with dry-run and deterministic pagination.
- [x] Preserve immutable cache entries and deterministic exact/prefix restore
  precedence across current-ref and default-branch scope.
- [x] Enforce current seven-day inactivity eligibility and 10 GiB repository
  LRU accounting, including concurrent finalization.
- [ ] Move expiration and repository LRU enforcement into durable jobs rather
  than request-side processing.
- [ ] Separate metadata eviction from retryable object deletion.
- [ ] Reconcile abandoned reservations and incomplete uploads.
- [ ] Add pagination, usage accounting, quotas, metrics, and operator repair.
- [ ] Test concurrent reservations for the same key/version, duplicate finalize,
  default-branch fallback, expired signed URLs, and object-store outage.

Acceptance:

- [x] Eviction makes an entry immediately ineligible for restore.
- [ ] Object GC is idempotent and eventually reconciles physical usage.
- [ ] Cache pressure cannot starve unrelated repositories or tenants.

### CACHE-02 — Exact cache client compatibility on Linux

**Owner:** X with P supplying the Linux profile. **Size:** M.
**Dependencies:** CACHE-01, PLAT-01.

An ignored offline fixture currently imports an explicitly supplied exact
`@actions/cache` 5.0.5 module and completes save, exact restore, and ordered
restore-prefix recovery without downloading packages. This is not yet an
ordinary-CI run of the complete pinned action wrappers.

Tasks:

- [x] Run the exact `@actions/cache` 5.0.5 client-library fixture offline when
  its immutable local module path is supplied.
- [ ] Run pinned cache, restore, and save action wrappers on Linux in ordinary
  CI with exact embedded client versions.
- [x] Preserve current exact-key, ordered restore-prefix, current-ref, and
  default-branch lookup behavior.
- [ ] Test action-level version calculation, pull-request/fork scopes,
  lookup-only, fail-on-cache-miss, and save-always behavior.
- [ ] Decide whether legacy v1 endpoints and environment variables are needed;
  implement them or publish an explicit rejected boundary.
- [ ] Reject `enableCrossOsArchive` until `CACHE-03` proves its archive and
  metadata contract.
- [ ] Test executable bits, symlinks, Unicode, long paths, and case-sensitive
  collisions.
- [x] Support `HEAD`, full `GET`, and one byte range with stable `206` and `416`
  behavior.
- [ ] Add a large-cache action acceptance fixture.

Acceptance:

- [ ] The supported Linux/action/version matrix is executable from ordinary
  CI.
- [ ] Unsupported legacy or cross-OS modes fail before upload with a stable
  reason.

### UI-01 — Workflow run graph, job detail, and control UI

**Owner:** X. **Size:** L. **Dependencies:** RES-02, CHECK-01, EVT-01,
DEP-01, ART-02, CACHE-01.

This extends the existing run lists, filters, detail pages, job pages, log
search, and artifact surfaces; it is not a greenfield UI rewrite.

The current authenticated UI has deterministic run/job/log pagination,
server-side log search, and authorized read-only artifact presentation with
name, size, SHA-256 digest, expiry, and an Automata download route. The backend
and Unix CLI already expose durable rerun-all, rerun-failed, and
rerun-specific-job operations for supported source graphs; browser controls do
not exist yet.

Tasks:

- [ ] Render dependency and reusable-workflow graphs with matrix expansion and
  attempt identity.
- [ ] Show live/terminal step state, pre/main/post phases, summaries,
  annotations, grouped logs, outputs, environments, artifacts, and cache use.
- [x] Preserve deterministic run, job, and log pagination plus current
  server-side log search.
- [ ] Add cancel and rerun controls with CSRF, authorization, audit, idempotency,
  and stale-attempt protection.
- [ ] Expose separate rerun-all, rerun-failed, and rerun-specific-job controls
  using the durable `DEP-01` operations.
- [ ] Add workflow enable/disable controls backed by the durable event-source
  state, with repository authorization and audit.
- [ ] Add run deletion, log archive download, and log deletion controls with
  explicit retention/audit consequences.
- [x] Preserve authorized read-only artifact browse/download with name, size,
  digest, and expiration state.
- [ ] Add artifact deletion, name/ID filtering, and provenance presentation.
- [ ] Add cache list/filter/delete-by-ID/key/ref and bounded bulk-cleanup views.
- [ ] Distinguish compile rejection, policy rejection, waiting approval,
  queued, runner unavailable, infrastructure failure, and user failure.
- [ ] Add accessible keyboard navigation, focus management, screen-reader
  labels, and high-contrast states.
- [ ] Add responsive and high-volume visual fixtures with stable screenshot
  baselines.
- [x] Keep secret values, raw signed object URLs, and raw provider payloads out
  of rendered page models.

Acceptance:

- [ ] A user can diagnose and control a multi-job matrix/reusable run without
  database or log access.
- [ ] Controls operate on the intended attempt exactly once.
- [ ] UI state agrees with Checks and durable Results after refresh/restart.

---

[Previous: Triggers, dispatch, schedules, and event families](github-actions-parity-07-events.md) · [Next: Windows, Linux and macOS profiles, architectures, and cross-OS cache](github-actions-parity-09-platforms.md)
