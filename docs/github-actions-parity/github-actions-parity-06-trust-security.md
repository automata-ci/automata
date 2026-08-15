# GitHub Actions parity: Event ingress, identity, secrets, environments, OIDC, and security

Create the generalized ingress and least-authority chain for permissions, tokens, variables, secrets, environments, OIDC, and untrusted data.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane C, with scheduler, runner, provider, and Results reviewers.

**Package IDs:** EVT-01, AUTH-01, AUTH-02, AUTH-03, CFG-01, CFG-02, CFG-03, ENV-01, ENV-02, OIDC-01, OIDC-02, SEC-01, SEC-02.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
- [Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### EVT-01 — Versioned event registry and generalized ingress

**Owner:** C. **Size:** L. **Dependencies:** FND-01.

Tasks:

- [x] Split the central event model, decoder, trigger compiler, and webhook
  normalizer into per-event modules.
- [x] Define a versioned normalized envelope containing only authenticated,
  bounded facts.
- [x] Give every event a canonical name, activities/defaults, typed trigger,
  ref/SHA rule, source rule, changed-file strategy, trust inputs, and recursion
  policy.
- [x] Preserve exact raw JSON in immutable storage but exclude it from queue
  descriptors and diagnostics.
- [x] Move existing push, pull request, merge group, and repository dispatch to
  the generalized path without behavior change.
- [x] Preserve configured GitHub `all_direct` fanout from one immutable
  repository revision, with a sorted digest-bound workflow inventory and
  durable per-workflow progress and Check subjects.
- [x] Generalize immutable-revision workflow selection and independently
  replayable progress and Check projection across the current provider,
  manual, and schedule admission paths; reserve the closed `workflow_run`
  origin contract for EVT-08 chained admission.
- [x] Add a durable enabled/disabled workflow state used by webhook, manual,
  and schedule admission, and required by the EVT-08 chained-event entry point.
- [x] Version GitHub App installation replacement as contiguous immutable
  binding generations, preserve historical authenticated identity, and allow
  central admission to finish after promotion when the old delivery was
  already authenticated, claimed, source-materialized, and given its exact
  per-workflow Check under the prior binding.
- [ ] Retain generation-scoped historical credential routes across a process
  restart so a delivery not yet source-materialized under the old installation
  can still fetch private source and publish its old Check after replacement.
- [x] Reject configured-but-unimplemented events at publication.
- [x] Add a leaf registration pattern so event families can be implemented in
  parallel after this package merges.

Acceptance:

- [x] Existing events pass signature, inbox, source, admission, redelivery,
  and restart tests.
- [x] Duplicate keys, oversized bodies, wrong identity, and changed
  redeliveries fail closed.
- [x] Debug output contains no body or credential.

Implementation note: the v1 registry is closed and digest-pinned; ingress seals
facts-only envelopes against immutable raw-blob identity. Provider delivery,
schedule, and manual origins share deterministic selection, progress, and
control subjects, while GitHub Check projection remains a separate optional
binding. The closed `workflow_run` origin and repository port are ready for
EVT-08; this package does not claim that chained admission exists. Workflow
enable-state and installation-binding history are versioned, immutable, and
replay checked. Installation history does not imply credential availability:
post-restart private-source and Check routing for a prior installation remains
explicitly unchecked above.

### AUTH-01 — Permission catalog and effective defaults

**Owner:** C. **Size:** L. **Dependencies:** none.

Tasks:

- [ ] Create a versioned GitHub permission catalog with current names and
  allowed levels.
- [ ] Reject unknown names and invalid levels at publication.
- [ ] Preserve explicit empty mapping as deny-all.
- [ ] Resolve omitted enterprise, organization, and repository defaults.
- [ ] Apply workflow then job permissions.
- [ ] Expand read-all/write-all from the pinned catalog.
- [ ] Keep `id-token` out of read-all and reject `id-token: read`.
- [ ] Apply reusable-workflow ceilings.
- [ ] Pin catalog/default-policy revision and digest to the run.
- [ ] Put only exact resolved permissions into executable JobIR.
- [ ] Add `artifact-metadata` with its documented levels and enforce it on
  provenance/attestation reads and writes independently from artifact content
  authority.

Acceptance:

- [ ] `{}`, omitted, read-all, write-all, mappings, and reusable ceilings have
  golden results.
- [ ] Unknown future permission names fail early.
- [ ] No runtime adapter guesses defaults.

### AUTH-02 — Authenticated event trust and authority reduction

**Owner:** C; S integrates the sealed snapshot. **Size:** XL.
**Dependencies:** EVT-01, AUTH-01.

Tasks:

- [ ] Build a versioned trust snapshot from authenticated facts, not JSON
  pointer guesses.
- [x] Preserve authenticated repository-owner ID through provider-manifest
  persistence and rehydration, and treat owner-ID changes as policy-evidence
  changes.
- [ ] Retain event/activity, actors, source/target repository, source ref/SHA,
  fork, Dependabot/automation, privileged transition, upstream-run evidence,
  and token recursion separately.
- [ ] Apply fork write downgrade and only an explicit fork-write policy.
- [ ] Remove normal secrets from fork and Dependabot jobs.
- [ ] Handle target, merge-group, workflow-run, dispatch, schedule, and rerun
  independently.
- [ ] Preserve original actor authority on rerun while exposing triggering
  actor.
- [ ] Feed one result to token, secret, cache, environment, OIDC, and output
  policies.
- [ ] Pin policy revision and digest.

Acceptance:

- [ ] A truth-table covers all supported events and ambiguous combinations.
- [ ] Every consumer observes the same classification.
- [ ] Missing or changed evidence fails closed.

### AUTH-03 — Runtime `GITHUB_TOKEN` issuance and lifecycle

**Owner:** C. **Size:** XL. **Dependencies:** AUTH-01, AUTH-02.

Tasks:

- [ ] Accept every exact safe mapping, not only nonempty mappings.
- [ ] Implement deny-all safely without falling back to provider defaults.
- [ ] Support OIDC-only jobs.
- [ ] Validate returned App permissions do not exceed the request.
- [ ] Populate and mask both token aliases before user code.
- [ ] Bind issue/refresh/revoke to tenant, repository, run, job, attempt,
  lease, fence, session, policy, and JobIR digest.
- [ ] Preserve indeterminate-mint handling.
- [ ] Revoke or retain for safe revocation after cancellation, completion,
  fence loss, or failed finalization.
- [ ] Add real allow/deny API probes by scope.

Acceptance:

- [ ] Deny-all, OIDC-only, read, write, fork, Dependabot, and reusable cases
  pass.
- [ ] Values never enter logs, JobIR, offers, or diagnostics.
- [ ] Expired or fenced authority cannot refresh.

### CFG-01 — Scoped secret and variable domain/storage

**Owner:** C. **Size:** XL. **Dependencies:** none.

Tasks:

- [ ] Extend the existing secret model rather than creating a competing one.
- [ ] Complete tenant/organization, repository, and environment secret
  management and selected-repository policies.
- [x] Preserve the versioned repository and environment variable ledger with
  canonical names, immutable versions, and value-free job bindings.
- [ ] Add organization variable storage and complete management and delivery
  across all supported scopes.
- [ ] Canonicalize names case-insensitively and reject `GITHUB_` variables.
- [ ] Enforce 48 KB per value, 500 repository, 1,000 organization, 100
  environment, and 256 KB delivered aggregate limits.
- [ ] Define exact precedence and snapshot timing.
- [ ] Version variable mutations and preserve encrypted, value-free secret
  store interfaces.
- [ ] Audit all mutations.
- [ ] Document that GitHub secret values cannot be imported.

Acceptance:

- [ ] Scope, precedence, collision, policy, and boundary tests pass.
- [ ] Database and debug output contain no plaintext secret.
- [ ] Mutation replay is revision-fenced and idempotent.

### CFG-02 — Runtime variables and complete secret delivery

**Owner:** C; R integrates contexts/masks. **Size:** XL.
**Dependencies:** CFG-01, AUTH-02.

Tasks:

- [ ] Replace variable-reference ineligibility with an exact value snapshot.
- [ ] Resolve organization/repository variables at the documented phase and
  environment variables only after approval.
- [ ] Inject canonical `vars` with version evidence.
- [ ] Complete all secret scopes and trust/reusable policies.
- [ ] Resolve unset values as GitHub does.
- [ ] Support reusable rename and inherit with hop-by-hop proof.
- [ ] Reject dynamic whole-secret access unless fully authorized.
- [x] Register every installed managed-secret value with the runner masker
  before acknowledging custody or starting user or provider work.
- [ ] Register masks before custody acknowledgement for every remaining secret
  delivery path.
- [ ] Zeroize values after every terminal, cancellation, disconnect, and
  restart path.
- [ ] Keep durable offers value-free.

Acceptance:

- [ ] Variable-bearing jobs run only with exact custody evidence.
- [ ] Environment values are absent before approval.
- [ ] Forks and incomplete reusable chains get no unauthorized value.
- [ ] Secret-oracle scans cover logs, outputs, artifacts, stores, and errors.

### CFG-03 — Secret/variable management API, CLI, and UI

**Owner:** C; X implements the UI against the merged backend contract.
**Size:** L. **Dependencies:** CFG-01.

Tasks:

- [ ] Add all supported scopes and selected-repository policies to APIs.
- [ ] Add variable CRUD and secret create/replace/delete/list metadata.
- [ ] Add safe noninteractive CLI commands.
- [ ] Add browser forms and lists.
- [ ] Preserve RBAC, CSRF, revision, operation ID, and audit evidence.
- [ ] Never return secret values after creation.
- [ ] Handle case collisions and ambiguous retries.

Acceptance:

- [ ] API, CLI, and browser produce the same durable operations.
- [ ] Secret values appear in no response, redirect, HTML, log, or snapshot.

### ENV-01 — Environment configuration and protection rules

**Owner:** C. **Size:** XL. **Dependencies:** CFG-01, AUTH-02.

Tasks:

- [ ] Add environment CRUD and immutable revision identity.
- [ ] Support individual and team reviewers, thresholds, and self-review
  prevention.
- [ ] Add wait timers, protected-branch-only policy, and branch/tag patterns.
- [ ] Add audited admin bypass and decide auto-creation/custom protection
  scope.
- [ ] Handle policy changes, rejection, expiry, cancellation, disabled
  environment, stale authority, and reviewer ABA.
- [ ] Enforce the 30-day wait limit.
- [ ] Add administration and review API/CLI/UI.

Acceptance:

- [ ] Every rule has current-authority and multi-replica PostgreSQL tests.
- [ ] Stale approval never releases credentials.
- [ ] Waiting jobs reach correct terminal states under rejection/expiry.

### ENV-02 — Runnable environment jobs and deployment lifecycle

**Owner:** C with S projection and X result integration. **Size:** XL.
**Dependencies:** ENV-01, CFG-02, RES-02.

Tasks:

- [ ] Remove the logical environment/deployment rejection.
- [ ] Evaluate and bind environment name and URL at the correct phase.
- [ ] Wait before leasing and release environment values only after readiness.
- [x] Preserve the PostgreSQL queued-to-leased current-authority check for the
  resolved environment revision and status, approval and reviewer authority,
  secret and variable versions and precedence, reusable secret permission,
  and trust classification.
- [ ] Create Automata deployment records and status transitions.
- [ ] Handle cancellation, reruns, and concurrency.
- [ ] Add deployment history and run/job links.
- [ ] Decide reviewed GitHub Deployment API projection explicitly.

Acceptance:

- [ ] Protected and unprotected jobs run through product composition.
- [x] PostgreSQL blocks the lease when sealed protected-environment or selected
  credential authority changes after resolution.
- [ ] Restart does not leak credentials or duplicate deployment state.

### OIDC-01 — Claims and subject-policy parity

**Owner:** C. **Size:** L. **Dependencies:** AUTH-01, AUTH-02, ENV-01.

Tasks:

- [ ] Preserve existing claims and add actor, repository/owner IDs, run ID,
  ref type, head/base refs, environment, visibility, enterprise, and reusable
  workflow identity where applicable.
- [ ] Match branch, tag, pull-request, and environment subject forms.
- [ ] Percent-encode subject components correctly.
- [ ] Add configurable subject templates if approved.
- [ ] Preserve caller-selected audience and require `id-token: write`.
- [ ] Match the reviewed token lifetime and define one-time request/replay
  behavior for the runner request bearer.
- [ ] Bind claims only to authenticated durable evidence.
- [ ] Version subject policy and update discovery metadata.

Acceptance:

- [ ] Golden JWTs cover push, PR, environment, reusable, dispatch, schedule,
  and rerun.
- [ ] Missing/conflicting evidence fails issuance.
- [ ] OIDC-only jobs require no repository token.

### OIDC-02 — Production keys and cloud federation

**Owner:** C with X acceptance support. **Size:** L. **Dependencies:** OIDC-01,
AUTH-03.

Tasks:

- [ ] Prove external HTTPS issuer configuration and homogeneous replica key
  sets.
- [ ] Automate two-phase rotation and bound all retained histories.
- [ ] Test replica replacement during rotation.
- [ ] Test AWS, Azure, GCP, and one generic verifier as available.
- [ ] Gate runner OIDC advertisement on readiness.
- [ ] Add metrics and rotation/rollback/compromise runbooks.

Acceptance:

- [ ] Multiple replicas issue and replay valid tokens throughout rotation.
- [ ] Misconfigured TLS, claims, keys, or history keeps OIDC unavailable.

### SEC-01 — Untrusted-data and action-policy hardening

**Owner:** C with all lanes reviewing their sinks. **Size:** XL.
**Dependencies:** EVT-01, AUTH-02.

Tasks:

- [ ] Mark authenticated provenance and trust on event/context values.
- [ ] Prevent accidental flow into argv, environment keys, command paths,
  annotations, headers, or database queries.
- [ ] Add optional hardened warnings/rejection for high-risk interpolation
  without silently changing compatibility mode.
- [ ] Add immutable-action-SHA enforcement and repository/organization
  allowlists.
- [ ] Reject redirects.
- [ ] Secure target and workflow-run events, fork caches, and privileged use of
  artifacts.
- [ ] Add injection fixtures for branches, PRs, issues, comments, annotations,
  logs, and forms.

Acceptance:

- [ ] Adversarial strings cannot alter control structures.
- [ ] Action policy is enforced during both admission and resolution.
- [ ] Diagnostics contain neither payload bodies nor credentials.

### SEC-02 — Cross-system credential-boundary proof

**Owner:** X drives acceptance; C, R, and P review. **Size:** L.
**Dependencies:** AUTH-03, CFG-02, OIDC-01, FND-04.

Tasks:

- [ ] Prove every token, secret, Results credential, and OIDC bearer is bound
  to exact run/job/attempt/lease/fence/session.
- [ ] Test lease theft, replay, cancellation, rerun, session replacement, and
  control-plane restart at every authority phase.
- [ ] Scan database, blobs, journals, logs, errors, metrics, and diagnostics
  for values.
- [ ] Verify masks precede user code and zeroization follows every terminal
  path.
- [ ] Gate stronger credentials on provider isolation capabilities.

Acceptance:

- [ ] Cross-attempt, fence, or session replay always fails.
- [ ] A weaker runner cannot receive stronger authority.
- [ ] Tests restart real processes rather than only in-memory fakes.
- [ ] This package proves the one-use enrollment and durable leaf-digest runner
  identity boundary; `FLT-01` reruns the suite before any enrollment expansion.

---

[Previous: Services, job containers, Docker, Podman, Kubernetes, and BuildKit](github-actions-parity-05-containers-docker.md) · [Next: Triggers, dispatch, schedules, and event families](github-actions-parity-07-events.md)
