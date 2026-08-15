# GitHub Actions parity: Triggers, dispatch, schedules, and event families

Implement pull-request filters, manual dispatch, schedules, lifecycle events, collaboration events, and privileged or chained events.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane C, with delegated workflow and UI contributors.

**Package IDs:** EVT-02, EVT-03, EVT-04, EVT-05, EVT-06, EVT-07, EVT-08.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)
- [Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### EVT-02 — Pull-request changed files and filter parity

**Owner:** C. **Size:** XL. **Dependencies:** EVT-01, AUTH-02 trust contract.

Tasks:

- [x] Add authenticated, paginated pull-request file retrieval.
- [x] Select least authority for public, private, same-repository, and fork
  pull requests.
- [ ] Match two-dot, three-dot, new-branch, forced/diverged, rename, deletion,
  300-file, and 1,000-commit behavior.
- [x] Separate complete file evidence, provider-proven run-all behavior,
  retryable unavailability, and invalid evidence.
- [x] Never turn transport failure into match or skip.
- [x] Match positive/negative path order and branch/tag/path interaction.
- [x] Complete pull-request activity defaults.
- [ ] Implement supported commit-message skip directives and intentional
  skipped-check projection.
- [x] Bind evidence digest to the exact event and workflow selection.

Acceptance:

- [ ] Differential fixtures cover all documented diff shapes and boundaries.
- [x] Pagination cannot reorder, duplicate, or omit files undetected.
- [x] Missing evidence never silently skips a workflow.
- [x] Restart after any page is deterministic.

Current implementation boundary:

- Public same-repository and fork pull requests use anonymous, paginated
  `pulls/{number}/files` reads. Exact pre/post pull-request snapshots bind the
  base repository, head repository, pull-request number, base SHA, head SHA,
  state, and provider-reported file count. The github.com Actions product
  target consumes exactly the first 300 provider file records in at most three
  exact 100-file pages; a reported 301st file is neither fetched nor matched.
- Each page is order-digested; the aggregate evidence digest also binds the
  canonical path set. A well-formed rename contributes both its previous and
  current path while retaining one provider-record count. Duplicate primary
  filenames, malformed rename pairs, omitted pages, or snapshot-drifting
  evidence is invalid. Transport, rate-limit, and server failures are retryable
  and never become run-all.
- A retry deliberately starts again at page one; partial pages are not cached.
  Exact snapshot binding and canonical page digests make the replay
  deterministic. Once a workflow is admitted, the selection digest is part of
  immutable workflow-plan provenance and therefore its plan/admission digest;
  a terminal path miss is retained by durable per-workflow delivery progress.
- Private pull-request delivery evidence pins a distinct
  `private_pull_request_files_read` selector whose exact policy is only
  `pull requests: read`. The selector, App/config/policy revisions, delivery
  claim fence, action, and provider-use horizon are revalidated before a
  credential handoff. Acquisition happens only after the compiler demands
  path evidence, and the existing `contents: read` source selector cannot be
  substituted at the typed, adapter, or database boundary.
- Existing-push Compare evidence accepts its documented first 300 file records;
  rename records likewise contribute both old and new paths. Exact 299/300/301
  fixtures pin the boundary and prove a 301st PR file cannot affect selection.
- GitHub's [generic troubleshooting guidance](https://docs.github.com/en/actions/how-tos/troubleshoot-workflows#filtering-and-diff-limits)
  currently says 300 files, while its [Enterprise Cloud trigger guidance](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#using-filters-to-target-specific-paths-for-pull-request-or-push-events)
  says 3,000. Automata pins github.com generic's 300-file behavior. This
  documentation observation is not live differential evidence; a protected
  provider run must resolve the contradiction before a broader compatibility
  claim.
- New-branch and forced/diverged push comparisons remain fail-closed.
  Commit-message skip directives and live GitHub differential evidence also
  remain open; this component coverage is not a production compatibility claim.

### EVT-03 — Manual dispatch core parity

**Owner:** C. **Size:** L. **Dependencies:** EVT-01, AUTH-02, CFG-02.

Tasks:

- [ ] Preserve existing boolean, choice, string, 25-input, and 65,535-character
  behavior.
- [ ] Add number and environment input types.
- [ ] Preserve typed `inputs` and string `github.event.inputs`.
- [ ] Match required/default/choice validation.
- [ ] Resolve branch and tag refs to immutable commits.
- [ ] Handle branch/tag name collisions correctly.
- [x] Preserve admission-time pinning of the exact current sealed runtime
  policy to the authenticated human `workflow_dispatch` audit, and fail closed
  when no exact policy is available.
- [ ] Populate actor and triggering actor.
- [ ] Hydrate organization/repository variables and eligible secrets while
  deferring environment values.
- [ ] Preserve exact replay and changed-input/ref conflict behavior.
- [ ] Match GitHub's dispatch REST API request shape and response semantics, or
  record an explicit namespaced Automata API divergence before UI/CLI work.

Acceptance:

- [ ] All five input types have boundary and invalid fixtures.
- [ ] Mutable ref movement after admission cannot alter a run.
- [ ] Environment selection cannot bypass protection.

### EVT-04 — Dispatch CLI and browser UI

**Owner:** X after C freezes the API. **Size:** M. **Dependencies:** EVT-03,
CFG-03, ENV-01.

Tasks:

- [ ] Add `automata workflow dispatch` with workflow, ref, operation ID,
  typed inputs, and JSON output.
- [ ] Retry only with the same operation ID.
- [ ] Build a browser form from the immutable workflow contract.
- [ ] Render string, boolean, choice, number, and environment controls.
- [ ] Verify refs server-side rather than accepting a browser-supplied SHA.
- [ ] Apply RBAC, CSRF, limits, and audit events.
- [ ] Link dispatch from workflow pages.

Acceptance:

- [ ] CLI and browser generate the same canonical request digest.
- [ ] Stale contract, duplicate field, permission loss, CSRF, and retry cases
  are tested.

### EVT-05 — Schedule behavior parity

**Owner:** C. **Size:** L. **Dependencies:** EVT-01, AUTH-02, CFG-02.

Tasks:

- [x] Preserve authenticated private-repository schedule-source groundwork:
  re-resolve the exact current private-source authority before source access
  and reject provider-manifest or authority drift.
- [ ] Preserve durable discovery and fire claims.
- [ ] Populate `github.event.schedule`.
- [ ] Match default-branch/latest-workflow source selection.
- [ ] Enforce the documented five-minute minimum schedule interval before
  durable discovery.
- [ ] Track the responsible actor when cron or default branch changes.
- [ ] Handle deletion, disablement, re-enablement, workflow moves, and branch
  changes.
- [ ] Implement inactivity behavior if in scope and document delay/drop policy.
- [ ] Hydrate variables and eligible secrets.
- [ ] Add multi-replica, restart, overload, lateness, and retry metrics/tests.
- [ ] Correct stale documentation.

Acceptance:

- [ ] One occurrence creates one run under duplicate workers and restarts.
- [ ] Source, actor, ref, SHA, and schedule value match expected snapshots.

### EVT-06 — Repository lifecycle and publication events

**Owner:** C; W may implement a delegated event module after `EVT-01`.
**Size:** XL. **Dependencies:** EVT-01, AUTH-02.

Events:

- [ ] `branch_protection_rule`
- [ ] `create`
- [ ] `delete`
- [ ] `fork`
- [ ] `gollum`
- [ ] `page_build`
- [ ] `public`
- [ ] `registry_package`
- [ ] `release`
- [ ] `watch`

For each event:

- [ ] add typed activities and defaults;
- [ ] add bounded duplicate-safe payload decoding;
- [ ] normalize repository, installation, actor, ref, SHA, and activity;
- [ ] select the documented workflow source;
- [ ] add immutable subject/trust evidence;
- [ ] implement redelivery and public/private tests;
- [ ] add positive, wrong-activity, malformed, oversized, and identity-negative
  fixtures.

Acceptance:

- [ ] Each event's ref/SHA and activity selection matches reviewed snapshots.
- [ ] No event gains secrets or writes solely from being in this batch.

### EVT-07 — Collaboration and review events

**Owner:** C; W may implement a delegated event module after `EVT-01`.
**Size:** XL. **Dependencies:** EVT-01, EVT-02, AUTH-02.

Events:

- [ ] `issues`
- [ ] `issue_comment`
- [ ] `label`
- [ ] `milestone`
- [ ] `discussion`
- [ ] `discussion_comment`
- [ ] `pull_request_review`
- [ ] `pull_request_review_comment`

Tasks:

- [ ] Implement documented activities/defaults.
- [ ] Distinguish issue comments on issues from pull requests.
- [ ] Bind review/comment events to exact PR source/base evidence.
- [ ] Preserve actor ID, login, and type separately.
- [ ] Never let a trusted commenter upgrade an untrusted PR source.
- [ ] Add recursion and rate controls for comment-driven automation.

Acceptance:

- [ ] Same-repository, fork, and Dependabot cases retain original source trust.
- [ ] Incomplete transitive evidence keeps secret-bearing jobs ineligible.

### EVT-08 — Privileged, stateful, and chained events

**Owner:** C with security and X Checks review. **Size:** XL.
**Dependencies:** EVT-01, AUTH-02, CHECK-01, ENV-02.

Events:

- [ ] `pull_request_target`
- [ ] `check_run`
- [ ] `check_suite`
- [ ] `status`
- [ ] `deployment`
- [ ] `deployment_status`
- [ ] `workflow_run`

Tasks:

- [ ] Give pull-request-target explicit base-source and privileged policy.
- [ ] Authenticate Check, status, deployment, and App ownership.
- [ ] Suppress recursive triggers caused by Automata credentials where GitHub
  does.
- [ ] Implement workflow-run requested, in-progress, and completed.
- [ ] Enforce the three-level chain limit.
- [ ] Bind upstream workflow/run/source/trust/conclusion transitively.
- [ ] Preserve fork and Dependabot provenance.
- [ ] Gate downstream secrets and writes on complete evidence.
- [ ] Deduplicate Automata-originated Check echoes.

Acceptance:

- [ ] Forks cannot gain secrets through target or chained workflows.
- [ ] Fourth-level chains are rejected correctly.
- [ ] Check/deployment feedback cannot form an unbounded loop.

---

[Previous: Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md) · [Next: Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)
