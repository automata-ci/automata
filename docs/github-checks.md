# GitHub Checks

Automata projects provider-neutral workflow results to GitHub Check Suites and
Check Runs. GitHub-specific code translates the common result contract and
owns GitHub API recovery; workflow state, durable claims, retry policy, and
worker supervision remain provider-neutral.

Automata does not publish Commit Statuses, Deployments, or badges.

## Result lifecycle

- A result subject has immutable provider, repository, revision, name, Details
  URL, and workflow or job identity.
- Desired phases are `queued`, `running`, and `completed`. Terminal conclusions
  are `action_required`, `cancelled`, `failure`, `success`, `skipped`, and
  `timed_out`.
- GitHub bindings are durable and provider observations are validated against
  the immutable result subject before Automata advances publication state.
- Result workers claim a subject with an owner, fence, and renewable expiry.
  Completion, retry, continuation, and failure mutations require the current
  fence.
- Provider continuation state is bounded and versioned. The GitHub adapter uses
  it to recover a possibly applied Check Run creation and append annotations in
  deterministic batches.
- Credential handoffs are move-only capabilities bound to the current provider
  connection, repository, claim fence, operation, and conservative lifetime.

The common durable model is implemented by `provider_result_subjects`,
`provider_result_outbox`, `provider_result_annotations`, and bounded provider
continuation/history state. GitHub-specific Check projection tables are not on
the runtime path.

## GitHub projection

The GitHub adapter performs these operations behind the common
`ProviderResultAdapter` boundary:

1. Create or resolve the App's Check Suite.
2. Create a deterministically identified Check Run, or reconcile an uncertain
   create by its immutable identity.
3. Read and validate the bound Check Run before applying lifecycle changes.
4. Start or complete the Check Run.
5. Read and append bounded annotation batches.

Check Run identity includes the App, installation, repository, head revision,
external ID, name, and Details URL. Recovery never chooses among ambiguous
candidates heuristically. Provider rate limits and transient failures preserve
the durable claim through a bounded retry; rejected or inconsistent authority
fails closed.

GitHub accepts at most 50 annotations per update, so the adapter persists a
continuation cursor and reconciles the observed prefix before appending more.
Presentation input is bounded by the common result model and provider limits;
credentials and raw webhook bodies are never included.

## Rerequests and reruns

GitHub `check_run.rerequested`, `check_suite.rerequested`, and supported
requested actions normalize to provider-neutral workflow controls. The common
runtime validates the referenced result subject and hands the request to the
durable rerun service. A successful webhook response means rerun admission was
persisted, not that the new execution completed.

The original run and its results remain immutable. A newly admitted rerun owns
new workflow/job result subjects and therefore new Check Runs. Delivery replay
is idempotent; a distinct GitHub delivery can represent a distinct user action.
See [Workflow reruns](workflow-reruns.md) for selection and authorization rules.

## Platform references

- [Check Run endpoints](https://docs.github.com/en/rest/checks/runs)
- [Check Suite endpoints](https://docs.github.com/en/rest/checks/suites)
- [`check_run` webhook](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_run)
- [`check_suite` webhook](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_suite)
- [Webhook signature validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [Status checks](https://docs.github.com/en/pull-requests/reference/status-checks)

## Maintainer map

- Common result model and repository port:
  [`automata-ci-provider`](../crates/automata-ci-provider/src/).
- Common worker and provider adapter boundary:
  [`automata-ci-provider-delivery`](../crates/automata-ci-provider-delivery/src/).
- PostgreSQL common result repository:
  [`result.rs`](../crates/automata-ci-provider-postgres/src/result.rs).
- GitHub result adapter:
  [`result_adapter.rs`](../crates/automata-ci-github-delivery/src/result_adapter.rs).
- GitHub Checks client and models:
  [`checks.rs`](../crates/automata-ci-provider-github/src/checks.rs).
- GitHub webhook normalization:
  [`webhook_event.rs`](../crates/automata-ci-provider-github/src/webhook_event.rs).
- Runtime composition and credential authority:
  [`automata-ci`](../crates/automata-ci/src/server/).

Changes to result semantics must keep the common contracts, PostgreSQL adapter,
GitHub adapter, focused tests, and this reference aligned.
