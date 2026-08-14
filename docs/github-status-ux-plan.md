# GitHub status and run UX plan

Status: core implementation complete. This document records the researched
GitHub platform boundary, the implemented architecture, and future native UX
work that adds a distinct capability rather than a second projection path.

Implemented to date:

- stable exact-job Details pages with dashboard/log authorization split;
- generic non-enumerating sign-in handoff back to the exact deep link;
- bounded same-origin live snapshots with ETag revalidation, visibility pause,
  terminal stop, request cancellation, and exponential failure backoff;
- native queued/running/terminal Check output with exact Automata links;
- durable execution start/completion timestamps projected as RFC 3339 UTC;
- verified immutable `JobResult` evidence carried by terminal job claims;
- deterministic bounded terminal Markdown with conclusion counts, step
  timelines, retained masked summaries, and UTF-8-safe truncation;
- deterministic source-annotation conversion with repository-relative path
  confinement, explicit omission counts, and 50-item GitHub batches;
- a durable presentation digest, monotonic annotation cursor, and exact
  paginated reconciliation for possibly accepted annotation updates;
- idempotent terminal recovery that does not reload result evidence once GitHub
  already reports the exact desired conclusion.
- same-origin browser rerun-all and rerun-failed controls backed by the existing
  CSRF-protected, idempotent workflow-rerun transaction;
- signed `check_run`/`check_suite` normalization, exact provider identity
  resolution, current Automata authorization, and native rerun controls;
- lifecycle-specific requested-action buttons on completed Check Runs.

GitHub Checks are the sole commit/PR result projection. Automata does not carry
an unused Commit Status API path or publish duplicate status rows. GitHub
deployments remain a separate future environment feature and will
be added only with a complete durable product path and independent authority.

## Outcome

An Automata run should feel native from a pull request or commit:

1. A job appears promptly as queued, changes to running when execution starts,
   and shows an accurate terminal result and duration.
2. GitHub's Checks view contains useful Markdown output and source annotations,
   rather than only a state and conclusion.
3. **Details** always targets the exact Automata job. A signed-in or public
   viewer sees it immediately; an unauthenticated viewer gets a non-leaking
   sign-in handoff that returns to that exact job.
4. The Automata page updates while the job is running and shows live logs when
   the viewer has log access.
5. GitHub-native rerun controls call Automata's durable rerun machinery.
6. Checks remain the single source of commit/PR status. Environment deployments
   may be added later only as a distinct environment-history feature.

Target service objectives after rollout:

- p95 durable lifecycle-to-GitHub state lag below 5 seconds when GitHub is
  healthy;
- 100% of created Check Runs have a canonical HTTPS `details_url`;
- no Check Run remains nonterminal after its durable Automata subject is
  terminal, excluding visible retry/rate-limit backlog;
- clicking **Details** never returns a raw-log authorization 404 for an
  otherwise dashboard-readable job;
- duplicate webhook delivery and publisher restart do not duplicate a Check
  Run or a source annotation.

## Platform boundary

### What GitHub permits

The Checks API is the primary third-party CI integration surface. A GitHub App
with `checks:write` can publish Check Runs with:

- `queued`, `in_progress`, and `completed` states (the additional `waiting`,
  `pending`, and `requested` states are reserved to GitHub Actions);
- `started_at`, `completed_at`, `details_url`, and `external_id`;
- Markdown `output.title`, `output.summary`, and `output.text`;
- source annotations, with at most 50 appended by one request;
- up to three requested-action buttons;
- `rerequested` and `requested_action` webhook-driven controls.

Annotations appear in the pull request Checks UI and, when they refer to a
line, in Files changed. GitHub automatically associates a Check Run with the
App's suite for the repository and SHA. Current documented limits include
50,000 Check Runs per suite and 1,000 Check Runs with the same name in a suite.

The Commit Status API is a smaller, separate surface: one context can be
`pending`, `success`, `failure`, or `error`, with a short description and
`target_url`. It does not populate the pull request Checks tab. Automata does
not use it because doing so would create a second, less capable representation
of the same result.

Deployments are also separate. For jobs that genuinely target a declared
environment, a deployment and its evolving status can provide repository
environment/deployment history, `log_url`, and `environment_url`. Build and
test jobs should not be mislabeled as deployments.

References:

- [Check Run endpoints](https://docs.github.com/en/rest/checks/runs)
- [Using the Checks API](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks)
- [Status checks](https://docs.github.com/en/pull-requests/reference/status-checks)
- [Commit status endpoints](https://docs.github.com/en/rest/commits/statuses)
- [Check webhook payloads](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_run)
- [Deployment endpoints](https://docs.github.com/en/rest/deployments/deployments)
- [Deployment status endpoints](https://docs.github.com/en/rest/deployments/statuses)
- [Actions limits](https://docs.github.com/en/actions/reference/limits)

### What GitHub does not permit

There is no GitHub App registration or Checks API field that embeds an
arbitrary application iframe in a repository, pull request, or Checks page.
GitHub App registration exposes external homepage, setup, callback, and webhook
URLs; it does not expose a repository UI iframe slot. Automata also cannot
create native GitHub Actions workflow-run, job, log, or artifact records.

Therefore the closest supported UX is:

- render as much diagnosis as possible in GitHub's native Check output;
- use native annotations and requested-action buttons;
- deep-link to an excellent external job page for live logs and full detail.

Automata should continue to send `frame-ancestors 'none'`. Weakening its CSP
would not create a GitHub embedding surface and would make the dashboard
clickjacking-prone.

## Current Automata implementation

The existing foundation is strong:

- `crates/automata-ci-store/src/github_checks.rs` and
  `crates/automata-ci-postgres/src/store/github_checks.rs` persist fenced Check subjects and a durable,
  restart-safe projection outbox.
- `crates/automata-ci-github/src/checks.rs` creates/reconciles an exact Check
  Suite and Check Run, validates App/suite/SHA/name/external ID/details URL, and
  updates lifecycle state.
- `crates/automata-ci-github-delivery/src/checks_publisher.rs` derives canonical
  repository, run, and job URLs and handles bounded retries, rate limits,
  mutation uncertainty, and credential fencing.
- one child Check subject is inserted for each concrete job attempt; lifecycle
  changes advance it from queued through in-progress to a terminal conclusion.
- terminal `JobResult` already retains masked step summaries, step timelines,
  and up to 4,096 structured annotations.
- the dashboard already has run detail and paginated/searchable job log pages.
- the durable rerun backend already supports whole-workflow, failed-job, and
  selected-job reruns.

This implementation closes the prior user-visible gaps:

1. create/start/complete payloads now include bounded native output, durable
   timestamps, annotations, lifecycle-valid actions, and strict validation;
2. Check subjects retain distinct start/completion time and deterministic
   presentation/annotation progress;
3. exact job URLs now render metadata independently from log authorization;
4. anonymous private deep links use a non-enumerating sign-in return flow;
5. visible nonterminal pages update through bounded same-origin polling; and
6. signed `check_run`/`check_suite` controls resolve to the durable rerun path.

Environment deployment history and status badges are separate future product
features. No partial provider client or runtime scaffolding is retained for
them.

## Design decisions

### Checks remain authoritative

Automata will continue to create one Check Run per concrete job attempt. The
existing aggregate workflow Check remains the pre-admission/compile diagnostic
until job expansion is known. We should evaluate hiding or neutralizing the
aggregate after successful expansion in a GitHub.com fixture, but must not
remove the only diagnostic for workflows that fail before jobs exist.

Provider-facing job names remain the evaluated job display name to match
GitHub's required-check convention. Installation documentation will warn that
job names must be unique across workflows when used as required checks; GitHub
itself applies that constraint without workflow, matrix, or trigger scope.

### Job detail and logs become separate capabilities

The canonical `/OWNER/REPO/actions/runs/RUN/jobs/JOB` route becomes a job-detail
page authorized by dashboard metadata visibility. Log content inside that page
has an independent `full`, `restricted`, or `unavailable` collection state.
This makes the Check deep link stable without broadening access to logs.

For an anonymous request to a syntactically valid run/job URL when human login
is enabled, the server may render the same generic sign-in handoff for missing
and unauthorized records. It must not query or reveal the resource name,
status, existence, or repository privacy. The existing POST-based, login-bound
flow remains intact and returns to the exact bounded local path. An authorized
viewer still receives the normal indistinguishable 404 for a missing or denied
resource after login.

### Live UI uses bounded incremental polling first

Add a same-origin, authorization-enforcing job snapshot/log-tail endpoint with
an opaque cursor and `ETag`. While visible and nonterminal, the client polls
every two seconds, stops on terminal state, aborts on navigation, pauses while
the tab is hidden, and exponentially backs off to 30 seconds on transient
failure. This fits the current HTTP deployment model and is easier to operate
than immediately adding long-lived WebSocket/SSE connections. The protocol can
later be transported over SSE without changing the snapshot model.

### Presentation is deterministic durable data

Provider Markdown and annotations must not be regenerated differently on each
retry. A terminal result projector will load the verified immutable JobResult,
convert it to a bounded provider presentation, store it as a content-addressed
blob, and atomically attach its key/digest/revision to the Check subject before
waking the outbox.

The provider presentation contains:

- exact start/completion timestamps;
- bounded title, summary, and text plus explicit truncation counts;
- deterministic annotations in step/result order;
- a total annotation count and SHA-256 digest;
- the exact requested actions permitted for that lifecycle;
- no raw log text, secret-derived output value, credential, or signed URL.

Queued and in-progress summaries are small server-owned templates. Terminal
text includes masked step summaries and a compact step result table. Annotation
paths must normalize to repository-relative slash paths; invalid/absolute/
escaping paths are omitted and included in an omission count. Lines and columns
must be positive and internally ordered. Levels map error→failure,
warning→warning, and notice→notice.

### Annotation publication has its own idempotent cursor

GitHub appends annotations on every update, so retrying a successful but
unobserved batch would create duplicates. The outbox therefore records a
presentation revision, next batch index, and provider annotation count. Each
batch is at most 50 annotations. After an uncertain PATCH, the publisher lists
and fully paginates GitHub annotations and compares the exact deterministic
prefix:

- exact next prefix: commit the cursor without resending;
- unchanged exact prefix: safely retry the batch;
- any other content/count: block the projection with observable provider
  mismatch instead of guessing.

The final batch may be included with the terminal state transition. A Check is
marked delivered only when lifecycle, timestamps, output digest, actions, and
annotation cursor all match the desired presentation.

### Requested actions are narrow and audited

Use GitHub's native `rerequested` event and, where the desired distinct choices
fit the three-button limit, requested actions with stable identifiers such as
`rerun_all` and `rerun_failed`. A job Check rerequest maps to selected job and
dependents. A workflow Check rerequest maps to the entire workflow.

Webhook input is not sufficient authority by itself. The adapter must verify
the webhook signature, installation/repository/App, external ID, Check Run ID,
suite/SHA, sender identity, source terminality, retention, and current rerun
authorization. It then calls the existing durable rerun service with an
idempotency operation ID derived from the GitHub delivery ID plus action and
Check identity. A successful rerun creates a fresh Automata physical run and
fresh per-attempt Check Runs; it does not rewrite immutable old results.

### Checks are the only commit-result projection

Automata publishes no Commit Status API rows. Checks already provide lifecycle,
Markdown, annotations, actions, timestamps, and exact Details links; a second
status representation would be less capable and create ambiguous required-check
configuration.

GitHub deployments are not another result projection. A future deployment
feature may represent only jobs with a resolved workflow environment, after the
environment product model is complete. It must arrive as one complete vertical
slice: durable identity/outbox state, exact SHA, environment-only admission,
queued/running/terminal status, job `log_url`, validated `environment_url`,
independent `deployments:write` authority, and webhook loop prevention. Until
then there is no partial deployment API scaffolding in the runtime or provider
library.

## Delivery phases

### Phase 1 — Make every Details link useful

Primary files:

- `crates/automata-ci/src/app/web/data.rs`
- `crates/automata-ci/src/app/web/live.rs`
- `crates/automata-ci/src/app/web/model.rs`
- `crates/automata-ci/src/app/web/routes.rs`
- `ui/src/pages/JobLogPage.tsx` (rename/evolve to job detail)
- `ui/src/models.ts`, `ui/src/validation/*`, and UI fixtures/tests

Work:

- introduce `JobDetailPage`/`JobDetailData` whose metadata authorization uses
  the dashboard policy and whose log collection is independently authorized;
- keep the current canonical job path so all already-published Details links
  improve without a redirect or migration;
- render status, run/job attempt, start/duration, runner, steps/summary when
  available, and a precise log-access placeholder when not;
- render a generic deep-link sign-in page for anonymous syntactically valid
  routes without existence disclosure and preserve the exact return path;
- add a bounded JSON snapshot/log-tail endpoint and client polling lifecycle;
- keep ordinary HTML navigation and manual Refresh as a no-JavaScript fallback;
- add `Cache-Control: no-store` to private/live documents and API snapshots;
- retain `frame-ancestors 'none'` and all existing same-origin/CSP constraints.

Acceptance:

- dashboard public/log private, dashboard authenticated/log private, fully
  private, public, missing, wrong repository, and stale-session cases all have
  explicit tests;
- a GitHub Details URL opens the exact job for an authorized viewer;
- login returns to the exact job and query without an open redirect;
- a running job updates state and appends new log lines without full-page
  navigation, duplicate lines, or losing search/scroll state;
- terminal polling stops.

### Phase 2 — Accurate lifecycle and native Check output

Primary files:

- `crates/automata-ci-core/src/job/result.rs`
- `crates/automata-ci-store/src/github_checks.rs`
- `crates/automata-ci-postgres/src/store/github_checks.rs`
- `crates/automata-ci-postgres/migrations/0001_initial_schema.sql`
- `crates/automata-ci-github/src/checks.rs`
- `crates/automata-ci-github-delivery/src/checks_publisher.rs`
- their focused integration tests

Work:

- persist `started_at_ms` and `completed_at_ms` independently on every Check
  subject and include them in the claimed outbox snapshot/guards;
- use the durable job attempt start and JobResult completion times, not publisher
  wall-clock time;
- define bounded `GithubCheckOutput` request models with redacted Debug output
  and strict UTF-8 limits;
- extend create/start/update payloads and response validation for timestamps
  and output;
- create queued output (`Waiting for a runner`) and in-progress output with an
  exact Details Markdown link;
- project terminal masked step summaries and compact result counts;
- keep only third-party-permitted states; do not attempt Actions-reserved
  waiting/pending/requested values;
- preserve current state-before-mutation reconciliation and rate-limit policy.

Acceptance:

- captured GitHub requests prove exact ISO-8601 UTC timestamps and payloads for
  every state/conclusion;
- delayed publisher execution does not alter start/completion time;
- malformed/oversized provider responses fail closed without exposing output;
- process restart between durable transition and GitHub PATCH resumes exactly;
- GitHub.com smoke evidence shows queued, running, duration, terminal title,
  summary, and Details in the expected PR/commit UI.

### Phase 3 — Full annotations and summaries

Work:

- implement the content-addressed presentation artifact and digest validation;
- convert retained annotation properties (`file`, `line`, `endLine`, `col`,
  `endColumn`, `title`) to GitHub's model with repository-path confinement;
- publish 50-item batches in deterministic order with a durable batch cursor;
- implement exact paginated annotation reconciliation after ambiguous updates;
- expose truncation/omission counts in both GitHub summary and Automata job UI;
- cap published Markdown below provider limits and truncate only on UTF-8 scalar
  boundaries with a stable marker;
- never publish annotations lacking a valid repository path and line; retain
  them in Automata's step result display as non-source diagnostics.

Acceptance:

- 0, 1, 50, 51, and 4,096 annotation fixtures;
- failures injected before send, after send/before response, after response/
  before cursor commit, and during reconciliation;
- no duplicate annotations after restart or rate limiting;
- source annotations appear in both Checks and Files changed on GitHub.com;
- secret masking and path traversal adversarial tests remain green.

### Phase 4 — GitHub-native and browser controls

Primary files:

- `crates/automata-ci-github/src/webhook.rs`
- `crates/automata-ci/src/server/github_webhook.rs`
- `crates/automata-ci-github-delivery/src/*`
- `crates/automata-ci/src/app/workflow_rerun_api.rs` and rerun composition
- run/job UI models and pages

Work:

- normalize the minimum `check_run.rerequested`,
  `check_run.requested_action`, and `check_suite.rerequested` payloads;
- add immutable mapping from external Check identity to source run/logical job;
- reauthorize sender and repository at durable rerun admission;
- call existing whole/failed/specific-job rerun operations idempotently;
- expose browser rerun-all/rerun-failed/rerun-job controls with CSRF, audit, and
  stale-attempt guards so GitHub and Automata controls share one backend;
- advertise only actions valid for the current lifecycle and authority;
- return fast 2xx webhook acknowledgement after durable enqueue, not after the
  rerun completes.

Acceptance:

- duplicate deliveries and repeated button clicks produce one physical rerun;
- cross-App, cross-repository, stale Check, nonterminal source, unauthorized
  sender, and expired-retention cases fail closed;
- GitHub rerequest produces a fresh run and new exact Details links;
- old Check output remains immutable and auditable.

### Phase 5 — Environment deployments and badges

Work:

- add environment-only deployment/deployment-status projection and independently
  pinned `deployments:write` authority;
- add repository/workflow badge endpoints derived from durable latest ref state,
  with bounded caching and no credential-bearing redirects;
- document required-check naming and App-source selection for branch protection
  and rulesets;
- add provider configuration migration and permission-upgrade guidance.

Acceptance:

- commit/PR results continue to have exactly one Checks-based representation;
- environment jobs appear in GitHub deployment history with correct log and
  environment URLs; non-environment jobs never do;
- badge responses are deterministic, cache bounded, and do not reveal private
  repository state without authorization.

## Schema and protocol changes

The exact schema should be finalized during Phase 2, but it must preserve these
invariants:

- `github_check_subjects` owns immutable identity plus explicit desired start,
  completion, and presentation reference/revision;
- `github_check_projection_outbox` freezes all of those values in a claim so a
  worker cannot publish a mixed revision;
- a presentation reference is content-addressed and digest-verified before use;
- annotation batch progress is durable and monotonic for one external Check Run
  and presentation revision;
- advancing lifecycle or presentation wakes a delivered/retry outbox row;
- old lifecycle revisions cannot overwrite a terminal provider state;
- existing Check Run IDs and already-published Details URLs remain valid.

Because this repository currently uses a consolidated initial PostgreSQL
migration, update that migration and its schema/trigger tests together. If
released installations already consume it before implementation starts, first
introduce a numbered forward migration rather than rewriting deployed history.

## Observability and operations

Add low-cardinality metrics:

- projection queue depth/oldest age by action and state;
- lifecycle-to-provider lag histogram;
- GitHub requests by operation/status class;
- rate-limit and retry delay counters;
- presentation conversion omissions/truncations;
- annotation batches published/reconciled/blocked;
- Details route outcomes split into page, generic sign-in handoff, and 404 (no
  owner/repository/run labels);
- live polling active requests, unchanged responses, and backoff;
- rerequest action accepted/rejected/replayed by reason class.

Add a runbook for stuck queued/in-progress Checks, credential rejection,
rate-limit exhaustion, ambiguous annotation batches, permission upgrades, and
the suite/name limits. Structured logs must use internal IDs or hashes and must
not include provider tokens, user Markdown, annotation messages, raw webhook
payloads, or private URLs.

## Test and rollout strategy

Testing layers:

1. pure model tests for limits, time formatting, Markdown truncation, path and
   annotation conversion, conclusion mappings, and Debug redaction;
2. HTTP capture tests in `automata-ci-github` for exact request/response and
   pagination contracts;
3. PostgreSQL transition/trigger/restart tests for every outbox phase;
4. delivery publisher fault-injection tests around every mutation cutoff;
5. SSR/unit/Playwright tests for deep links, access matrices, live updates,
   responsive layout, keyboard focus, and reduced motion;
6. isolated GitHub emulator acceptance for deterministic CI;
7. a manual or gated GitHub.com App smoke repository for UI facts that an
   emulator cannot prove: Checks rendering, Details behavior, annotations in
   Files changed, and rerun buttons.

Roll out behind independently reversible flags:

1. job-detail route/access split;
2. live polling;
3. timestamps and output, initially without annotations/actions;
4. annotation batching;
5. rerequest/actions;
6. environment deployments, once the complete environment product path exists.

During each provider phase, shadow-build and validate the desired presentation
before enabling mutation. Compare Automata durable state with GitHub readback
for canary installations. Stop rollout on duplicate Check/annotation evidence,
increased Details 404s, projection age SLO breach, or unexpected rate-limit
pressure.

## Definition of done

- A multi-job, matrix, failed, cancelled, skipped, timed-out, and rerun fixture
  has coherent Check lifecycles and exact job links.
- A reviewer can see state, duration, result summary, and line annotations in
  GitHub without leaving the pull request.
- **Details** reliably opens the exact live/terminal Automata job with correct
  dashboard/log authorization behavior.
- GitHub and Automata rerun controls use the same durable, audited operation.
- every mutation is restart-safe and rate-limit aware; annotation append
  ambiguity is reconciled rather than blindly retried.
- commit/PR results have one Checks-based projection; any future environment
  deployment path is separately authorized and does not duplicate it.
- documentation clearly states the remaining unavoidable divergence: Automata
  is a GitHub App using Checks and its own run UI, not a producer of native
  GitHub Actions run records or an iframe inside GitHub.
