# GitHub Checks

Status: **Experimental**. This living reference documents Automata's current GitHub
Checks contract and records behavior rather than delivery scheduling or future promises.
The GitHub integration owns provider projection; the web app owns Details/snapshots,
and the rerun service owns admission. Only Check Runs project results: no production Commit Status, Deployment, or badge.

## User-visible lifecycle

- The configured Check name is the one delivery-wide aggregate (`Automata` in
  production). In `all_direct` mode it remains nonterminal while any admitted
  workflow is running and derives its terminal conclusion from every admitted
  workflow. Workflow discovery and lifecycle subjects are internal and never
  become Check Runs. Each concrete job attempt has its own Check named from the
  evaluated job display name, and a physical rerun gets fresh job Checks.
- Required-name ownership is event-isolated. Only the configured default-branch
  push, `pull_request` `opened`/`reopened`/`synchronize`, and `merge_group`
  `checks_requested` deliveries may publish it. Other deliveries publish only
  the concrete jobs they run; webhook bookkeeping never becomes a Check Run.
  A required aggregate never
  concludes `skipped`; zero selected workflows or an all-skipped result fails.
- Delivery, schedule, and rerun origins share the same fenced projection contract.
- Identity is immutable: tenant, repository, connection, installation, App, head SHA,
  Check name, `automata-check:<UUID>` external ID, and exact Details target.
- Provider reads are accepted only after every returned identity field matches exactly.
- Lifecycle states are `queued`, `in_progress`, and `completed`; work that never starts may go directly
  from queued to completed. Conclusions are `action_required`, `cancelled`, `failure`, `success`, `skipped`, or `timed_out`, never `neutral` or `stale`.
- A job Check's Details is exactly `/OWNER/REPO/actions/runs/RUN/jobs/JOB`; aggregate
  Checks target the repository or workflow run. Metadata and log authorization stay independent.
- Anonymous syntactically valid private links get a generic sign-in handoff without
  existence disclosure; signed-in missing or denied resources get the same generic 404.
- The snapshot reuses the page model and scope and sends `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff`; its SHA-256 ETag yields `304` when unchanged.
  It yields `404` after current authority no longer permits that exact page.
- A visible nonterminal page polls its same-origin snapshot every two seconds, pauses
  while hidden, stops when terminal, and backs off to 30 seconds with manual refresh.
- `frame-ancestors 'none'` and `X-Frame-Options: DENY` are Automata invariants.
- Job Check names are bounded projections of evaluated display names. The exact
  aggregate name is reserved and rejected as a job name so no job, schedule, or
  rerun can satisfy the merge gate. Other required job names must be unique
  after projection across workflows.

## GitHub platform boundary

Automata uses the Checks API fields and webhooks exposed to GitHub Apps. It does not
infer an embedding or native-Actions-record prohibition beyond those documented APIs.
Commit Statuses are a separate, smaller result surface and are intentionally unused.
Deployments and deployment statuses are a different product boundary and are unused.
The limits cited below are GitHub's; local byte and retention bounds are identified here.
GitHub guidance requires unique required-check job names; use its troubleshooting guide for stale checks or an unexpected source.
Runtime startup attests every effective installation before enabling ingress:
the configured App and installation IDs must match GitHub, `merge_group` must
be subscribed, and `merge_queues: read` must be effective.

- [Check Run endpoints](https://docs.github.com/en/rest/checks/runs)
- [Check Suite endpoints](https://docs.github.com/en/rest/checks/suites)
- [Checks API guide](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks)
- [`check_run` webhook](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_run)
- [`check_suite` webhook](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_suite)
- [Webhook signature validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [Status checks](https://docs.github.com/en/pull-requests/reference/status-checks)
- [Commit status endpoints](https://docs.github.com/en/rest/commits/statuses)
- [Deployment endpoints](https://docs.github.com/en/rest/deployments/deployments)
- [Deployment status endpoints](https://docs.github.com/en/rest/deployments/statuses)
- [GitHub Actions limits](https://docs.github.com/en/actions/reference/limits)
- [Protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) and [required-check troubleshooting](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

## Deterministic presentation and durability

Terminal job presentation is regenerated from immutable `JobResult` only after its digest,
size, and media type are verified; no separate presentation blob is persisted.
Conclusion and completion time must agree with the frozen attempt/result join.
Automata adds no raw logs, output values, webhook bodies, credentials, or signed URLs;
retained summaries and annotations are masked before storage.
The SHA-256 presentation digest covers bounded output, ordered converted annotations,
and the omission count; Check lifecycle timestamps and requested actions are outside that digest.
Annotation conversion recognizes validated property keys, confines repository-relative
paths, and validates ordered positive line/column coordinates and the provider level.
Retention permits at most 4,096 annotations; GitHub accepts 50 per update, returns up to 100
per annotation page, and accepts at most three requested-action buttons.
The 4,096 retention, 16 MiB result object, and 60 KiB rendered presentation-text caps are Automata limits.

The durable Check projection contract is exactly three tables:

- `github_check_subjects` owns immutable identity and origin, desired state and revision,
  workflow/job topology, and durable creation/update times.
- `github_check_projection_outbox` owns provider bindings, claim/create fences, retry
  state, provider observations, and terminal block reason.
- `github_check_annotation_progress` owns presentation digest, total, next cursor, and
  the size of a possibly accepted batch.

Attempt and result joins freeze exact start, completion, and result evidence per revision.
Check credentials are move-only, connection-specific capabilities; App, installation,
repository, service revisions, identity digests, and expiry are fully validated; schema constraints reject mixed origins or authorities.

## Fenced publishing and recovery

Before a Check Run create POST, the publisher persists an owner/fence and issue window.
It never blindly repeats a create after the request may have reached GitHub.
Recovery fully paginates suite/name candidates and accepts only the exact immutable
identity within same-origin, pagination-cycle, and total-result bounds.
Zero matches retry reconciliation, one exact match binds, and more than one blocks as
`ambiguous_create`; no candidate is selected heuristically.
Before an update mutation, the publisher reads the exact Check and refuses to overwrite a terminal
provider result that differs from the frozen desired result.
The completion PATCH carries terminal output and requested actions; annotations follow.
Before each annotation PATCH, progress persists the uncertain batch size. Recovery reads
fully paginated provider annotations and compares the entire deterministic prefix.
An unchanged prefix resends, an exact advanced prefix commits, and any mismatch blocks
as `annotation_mismatch`; append ambiguity is never guessed.
A projection completes only after lifecycle is recorded and its annotation cursor is
complete. Result reload may be skipped only for the exact terminal result plus complete
annotations, never from conclusion alone.
Limits are 64 attempts per revision, 15-minute claims, a 24-hour maximum retry delay,
and a seven-minute post-issue reconciliation grace window.
Terminal blocks are `ambiguous_create`, `annotation_mismatch`, `attempt_limit`, and
`credential_rejected`; operators must resolve the identity, evidence, authority, or retry-exhaustion problem.
There is no Check-specific metrics contract, operations runbook, or latency/stuck SLO.
Publisher logs and errors use bounded internal identity, not result content or secrets.
Rate limits retain fences; credential rejection blocks instead of retrying stale authority.

## Reruns

Browser UI exposes rerun-all and rerun-failed only; selected-job rerun is a backend/CLI
operation and a GitHub job requested action.
Browser POST admission requires exact `Origin`, current session, and double-submit CSRF;
present cross-site Fetch Metadata is rejected. The closed JSON body is capped at 8 KiB and needs `runs:rerun`.
Webhook processing verifies HMAC over the raw body before parsing configured provider
identity, then reauthorizes the sender against current Automata repository authority.
Check admission matches exact App, suite, run, head SHA, external ID, terminal state,
and durable binding; suite admission matches its App, suite, SHA, and terminal job
Checks, then deduplicates their workflow runs.
On a job Check, `rerequested` or `rerun_job` selects that job and its dependents,
`rerun_all` selects the workflow, and `rerun_failed` selects failed jobs and dependents.
A suite rerequest selects the workflows represented by its terminal job Checks.
Completed job Checks offer `rerun_job`, `rerun_failed`, and `rerun_all`; the merge
aggregate offers no rerun action because it represents multiple workflows.
The durable operation identity combines GitHub delivery ID, SHA-256 of the raw body, and
source run. Exact delivery replay is idempotent; a distinct click/delivery may create a run.
Rerun success means durable admission succeeded, not that the new execution completed.
A newly admitted rerun creates a fresh physical run and fresh Checks; exact replay returns it, and old results stay immutable.
The request retains the exact source selection, actor, repository, and provider evidence.
Current retention and attempt limits are evaluated inside durable rerun admission.
Authorization or binding drift fails closed; a valid GitHub signature never grants `runs:rerun`.
Browser and webhook paths converge on the same durable rerun transaction.
See [Workflow reruns](workflow-reruns.md) for the CLI/API contract and selection rules.

## Maintainer map

- Provider models/client: [`checks.rs`](../crates/automata-ci-provider-github/src/checks.rs).
- Presentation: [`checks_presentation.rs`](../crates/automata-ci-github-delivery/src/checks_presentation.rs).
- Publisher/recovery: [`checks_publisher.rs`](../crates/automata-ci-github-delivery/src/checks_publisher.rs).
- Durable API: [store `github_checks.rs`](../crates/automata-ci-store/src/github_checks.rs).
- Adapter/schema: [PostgreSQL `github_checks.rs`](../crates/automata-ci-store-postgres/src/github_checks.rs) and [migrations](../crates/automata-ci-store-postgres/migrations/).
- Web model/authorization: [`live.rs`](../crates/automata-ci/src/app/web/live.rs).
- Routes/security: [`routes.rs`](../crates/automata-ci/src/app/web/routes.rs).
- Browser polling: [`JobLogPage.tsx`](../ui/src/pages/JobLogPage.tsx).
- Webhook normalization: [`webhook_event.rs`](../crates/automata-ci-provider-github/src/webhook_event.rs).
- Delivery/rerun admission: [delivery `lib.rs`](../crates/automata-ci-github-delivery/src/lib.rs).
- Browser rerun: [server](../crates/automata-ci/src/server/workflow_rerun.rs) and [API](../crates/automata-ci/src/app/workflow_rerun_api.rs).

Focused contract evidence lives in:

- [store API tests](../crates/automata-ci-store/tests/github_checks_api.rs);
- [publisher tests](../crates/automata-ci-github-delivery/tests/checks_publisher.rs); and
- the focused tests colocated with the provider, web, webhook, and rerun sources above.
Behavioral changes must update code, focused tests, and this reference together.
