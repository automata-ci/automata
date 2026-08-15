# GitHub Actions parity backlog

This document records the implementation gaps found by comparing Automata
`upstream/main` at commit
[`1885c2a`](https://github.com/automata-ci/automata/commit/1885c2a2c8b3bc49334272c1a782ca115dd5f999)
with the public GitHub Actions documentation, refreshed on 2026-08-13.

The [compatibility page](compatibility.md) remains the source of truth for
current support claims. The [implementation plan](implementation-plan.md)
owns release gates and sequencing. This page is a dated engineering backlog:
it records missing behavior, acceptance evidence, and product decisions without
claiming that unchecked work is available.

Automata has a substantial parser, durable orchestration model, Linux execution
substrate, Windows `run:` execution, and partial Results/cache support. Broad
GitHub Actions parity remains incomplete because many features either parse but
fail during logical projection, compile without scheduler enforcement, work
only in focused component tests, work only on Linux, lack production ingress or
credentials, or deliberately diverge from GitHub.

The 2026-08-12 refresh includes the runtime restoration merged in PR #29:
runner protocol v1, message schema v1, JobIR schema v1, runner-requirements
schema v1, one canonical greenfield `0001_initial_schema.sql`, three isolated
single-slot Linux runner processes, the Kubernetes product configuration path,
durable rerun and protected-environment authority,
value-safe managed-secret delivery, and immutable multi-workflow fanout. The
baseline has no supported database or mixed-version upgrade source. These are
component or experimental foundations unless a later item records product
acceptance. Hosted Windows CI was removed from `main`; the replacement
Hyper-V-container component is source-tested but is not a release gate until
the dedicated-host acceptance suite returns.

The final baseline retains exact cleanup custody when sandbox creation has an
uncertain outcome and the provider returns a recovery handle. Missing custody
is an executor-contract failure and remains fenced; the runtime never guesses
or reconstructs a provider identity. Operators must drain that runner, use
provider-owned evidence to prove absence or destroy any external resource, and
then recreate its empty local state; deleting the journal alone must never
release capacity.

The companion
[`automata-integration-tests`](https://github.com/automata-ci/automata-integration-tests)
repository was audited at `af7e2ca`. It contains a manual real-Automata E2E
harness with immutable source/action locks, a strict loopback GitHub emulator,
real control-plane and runner processes, canonical evidence types, and a
fail-closed comparator. Its current CI runs contract tests and fixture audit,
not the real E2E; all seven scenarios remain `candidate`; and no live
GitHub-versus-Automata differential path exists. The detailed parallel work is
tracked in the
[cross-repository integration-test plan](github-actions-parity/github-actions-parity-11-integration-tests.md).

`concurrency.queue: max` is documented by GitHub, including a 100-entry queue
and FIFO behavior, and is implemented as a compatibility feature rather than
an Automata-only extension. See
[GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## Legend

- **P0** — correctness or security blocker.
- **P1** — needed for ordinary GitHub Actions workflows.
- **P2** — broader compatibility or product surface.
- **E2E** — implemented components that still need production acceptance.
- **Decision** — intentional divergence that must be explicitly decided and
  documented.

## 1. P0: make compatibility claims mechanically truthful

- [ ] Add a machine-readable capability matrix for every feature:
  - [ ] decoded;
  - [ ] compiled;
  - [ ] logically projected;
  - [ ] admitted;
  - [ ] scheduled;
  - [ ] executable on Linux;
  - [ ] executable on Windows;
  - [ ] executable on Kubernetes;
  - [ ] projected into Results/Checks;
  - [ ] differentially tested against GitHub.
- [ ] Generate `docs/compatibility.md` from that matrix, or validate the
  document against it.
- [ ] Prevent a decoded field from being advertised as supported when later
  stages reject it.
- [ ] Move unsupported-feature errors to publication or admission, before jobs
  are queued.
- [ ] Include source spans and stable machine-readable reason codes in every
  unsupported diagnostic.
- [ ] Add a schema-to-runtime coverage test proving every recognized field is
  runnable or rejected early.
- [ ] Add a test that fails when a new decoder field has no projection/runtime
  classification.
- [ ] Add a test that fails when a compatibility-table entry has no associated
  acceptance fixture.
- [x] Expose a private, bounded `schemaVersion: 1` conformance snapshot for
  deliveries, runs, expanded JobIR, matrix/strategy context, terminal attempt
  evidence, and artifact metadata.
- [ ] Add versioned per-step outputs to that conformance schema; do not invent
  empty output maps for evidence the runner does not retain.
- [ ] Keep loopback provider-emulator evidence distinct from proof of live
  GitHub.com networking, App installation, and credentials.
- [ ] Separate statuses into `decode`, `plan`, `runtime`, `product`, and
  `differential`, rather than the broad `Component complete` label.
- [ ] Update the comparison baseline whenever the pinned `actions/runner`
  version changes.
- [ ] Add a scheduled job that detects changes in GitHub's public Actions
  reference.
- [ ] Track post-baseline GitHub deltas such as:
  - [ ] `GITHUB_ARTIFACTS`;
  - [ ] `GITHUB_ARTIFACTS_LIST`;
  - [ ] `concurrency.queue`;
  - [ ] new permission scopes;
  - [ ] new variables;
  - [ ] Node runtime changes;
  - [ ] input and workflow limits.
- [ ] Pass Automata's unchanged `.ci/workflows/ci.yml` through the real
  product composition.
- [ ] Compare the exact same workflow bytes, commit, and event on GitHub and
  Automata.
- [ ] Compare:
  - [ ] selected workflows;
  - [ ] expanded jobs;
  - [ ] matrix instances;
  - [ ] job ordering;
  - [ ] conditions;
  - [ ] step outcomes and conclusions;
  - [ ] outputs;
  - [ ] annotations;
  - [ ] summaries;
  - [ ] masked logs;
  - [ ] artifacts;
  - [ ] caches;
  - [ ] services;
  - [ ] cancellation;
  - [ ] reruns;
  - [ ] cleanup.
- [ ] Run that differential gate before claiming workflow parity.
- [ ] Verify one coherent cross-repository release bundle before starting an
  E2E deployment; bind the Automata commit, binary hashes, profile manifest and
  image, helpers, schema versions, and topology.
- [ ] Enforce scenario capability requirements, side effects, runner count,
  graduation state, and quarantine expiry instead of treating them as catalog
  annotations.
- [ ] Add concrete live GitHub and complete Automata evidence adapters, a
  protected event driver, and an atomic retained differential report.
- [ ] Graduate Chalk push/PR first, then p-limit push/PR, Testify push/PR, and
  the controlled Testify tag/release lane; keep each scenario independent.
- [ ] Add required secret-free isolated smoke, scheduled protected live corpus,
  flake evidence, quarantine enforcement, fixture refresh review, and phase
  budgets.

## 2. P0: current parse-or-compile false positives

These items can be accepted by an early stage and then fail later in the
product path.

- [ ] Implement `jobs.<id>.container` end to end; it currently decodes but
  compilation rejects it.
- [ ] Implement `docker://...` container actions; they parse but execution
  rejects them.
- [ ] Implement job-level `concurrency`; it compiles but logical projection
  rejects it.
- [ ] Implement `jobs.<id>.environment`; it compiles but logical projection
  rejects deployment semantics.
- [ ] Prove repository-local reusable calls and output propagation through
  production provider/runner composition. Their coordinator is intentionally a
  control-plane object and must not be projected as runner JobIR.
- [ ] Extend the existing reusable coordinator runtime to remote sources,
  matrices, complete secret forwarding, cancellation, and edge-case outputs.
- [ ] Implement production `hashFiles()`; production currently installs no
  expression extension provider.
- [ ] Enforce `strategy.fail-fast`; it is evaluated but not consumed by
  scheduling.
- [ ] Enforce `strategy.max-parallel`; it is evaluated but does not throttle
  leases.
- [ ] Resolve status-function parser/evaluator inconsistencies:
  - [ ] accept only GitHub-supported arities;
  - [ ] or implement any intentionally accepted extension;
  - [ ] never defer a known-invalid call into a missing extension provider.
- [ ] Reject service-container secret expressions during compilation until
  secure runtime transport exists.
- [ ] Reject untyped event configuration before publication until the event has
  real product ingress.
- [ ] Add focused tests for every decode-to-projection rejection currently
  present.

## 3. P0: `GITHUB_TOKEN`, permissions, and event trust

GitHub calculates token permissions from enterprise, organization, and
repository defaults, then workflow permissions, then job permissions, and
finally downgrades fork and Dependabot pull requests. Automata does not yet
reproduce this securely. See
[GitHub permission semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

- [ ] Make token issuance support omitted permissions and `ProviderDefault`.
- [ ] Support `permissions: read-all`.
- [ ] Support `permissions: write-all`.
- [ ] Support `permissions: {}` as valid deny-all.
- [ ] Support an OIDC-only mapping such as
  `permissions: { id-token: write }`.
- [ ] Maintain a reviewed allowlist for current permission keys:
  - [ ] `actions`;
  - [ ] `artifact-metadata`;
  - [ ] `attestations`;
  - [ ] `checks`;
  - [ ] `code-quality`;
  - [ ] `contents`;
  - [ ] `deployments`;
  - [ ] `discussions`;
  - [ ] `id-token`;
  - [ ] `issues`;
  - [ ] `packages`;
  - [ ] `pages`;
  - [ ] `pull-requests`;
  - [ ] `security-events`;
  - [ ] `statuses`;
  - [ ] `vulnerability-alerts`.
- [ ] Enforce scope-specific levels; for example, `vulnerability-alerts` is
  read-or-none, not write.
- [ ] Reject unknown permission keys at publication.
- [ ] Import or configure repository and organization default permission
  policies.
- [ ] Apply workflow-level permissions.
- [ ] Apply job-level reductions and overrides.
- [ ] Apply reusable-workflow permission ceilings at every call hop.
- [ ] Downgrade write permissions for fork pull requests unless the explicit
  administrator policy permits them.
- [ ] Treat Dependabot pull requests as fork-equivalent.
- [ ] Remove normal secrets from Dependabot-triggered jobs.
- [ ] Give `pull_request_target` a separate trust policy from `pull_request`.
- [ ] Bind effective permission calculation to authenticated event provenance.
- [ ] Test `github.token` and `secrets.GITHUB_TOKEN` aliases for every
  permission mode.
- [ ] Test masking of issued tokens.
- [ ] Test token expiry, refresh, revocation, and retry.
- [ ] Test that a rerun uses the original actor's authority, not the triggering
  rerun actor's greater authority.
- [ ] Test real permitted and denied GitHub API operations for every supported
  scope.
- [ ] Document that Automata issues GitHub App installation credentials, not
  native GitHub Actions job tokens.
- [ ] Add individual reviewed API compatibility surfaces where common actions
  require them.
- [ ] Keep arbitrary transparent REST proxying fail-closed unless that product
  decision changes.

## 4. Workflow events and ingress

Automata's verified webhook surface is presently `push`, `pull_request`,
`merge_group`, and `repository_dispatch`. Manual dispatch and schedules use
Automata-specific product paths. GitHub's event reference is much broader. See
[GitHub event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

For every event below, implement typed configuration, activity filters,
authenticated ingress, exact payload/context construction, correct
`GITHUB_REF` and `GITHUB_SHA`, source selection, deduplication, redelivery, and
differential tests.

- [ ] `branch_protection_rule`
- [ ] `check_run`
- [ ] `check_suite`
- [ ] `create`
- [ ] `delete`
- [ ] `deployment`
- [ ] `deployment_status`
- [ ] `discussion`
- [ ] `discussion_comment`
- [ ] `fork`
- [ ] `gollum`
- [ ] `issue_comment`
- [ ] `issues`
- [ ] `label`
- [ ] `milestone`
- [ ] `page_build`
- [ ] `public`
- [ ] `pull_request_review`
- [ ] `pull_request_review_comment`
- [ ] `pull_request_target`
- [ ] `registry_package`
- [ ] `release`
- [ ] `status`
- [ ] `watch`
- [ ] `workflow_run`

Additional event work:

- [ ] Implement the complete documented activity-type set for `pull_request`.
- [ ] Implement pull-request changed-file retrieval for `paths` and
  `paths-ignore`.
- [ ] Handle fork pull-request changed-file retrieval with least privilege.
- [ ] Handle renamed and deleted pull-request files correctly.
- [ ] Match GitHub's two-dot and three-dot diff rules.
- [ ] Match new-branch push diff behavior.
- [ ] Handle pushes with more than 1,000 commits.
- [ ] Handle changed-file truncation and diff timeouts.
- [ ] Define fail-closed behavior when complete changed-file evidence cannot be
  obtained.
- [ ] Differential-test the current 300-file filtering boundary.
- [ ] Implement branch, tag, and path filter ordering exactly.
- [ ] Match behavior when both positive and negative patterns are present.
- [ ] Match required-check behavior when path or branch filtering skips a
  workflow.
- [ ] Implement workflow skip directives such as `[skip ci]` where applicable.
- [ ] Prevent unintended recursive workflow triggering from job-issued
  credentials.
- [ ] Add `workflow_run`'s three-level chaining limit.
- [ ] Secure `workflow_run` privilege transitions; downstream runs can receive
  secrets or write authority even when upstream work was untrusted.
- [ ] Add chaining across Checks, statuses, deployments, and releases.
- [x] Select every configured direct workflow at one immutable repository
  revision, retain path-local progress, and authorize a separate Check subject
  for each selected workflow.
- [ ] Test webhook reordering, redelivery, and installation replacement.

### `workflow_dispatch`

GitHub supports typed inputs, API, CLI, and UI invocation, up to 25 top-level
inputs, and a 65,535-character input payload. See
[GitHub dispatch reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

- [ ] Add input type `number`.
- [ ] Add input type `environment`.
- [ ] Preserve booleans as booleans in `inputs`.
- [ ] Expose the corresponding string representation in
  `github.event.inputs`.
- [ ] Enforce required inputs.
- [ ] Enforce defaults.
- [ ] Validate choice options.
- [ ] Enforce 25 top-level inputs.
- [ ] Enforce the 65,535-character payload limit.
- [ ] Add first-party CLI dispatch.
- [ ] Add a browser dispatch form.
- [ ] Add ref selection.
- [ ] Resolve branches and tags to an immutable commit.
- [ ] Support the GitHub-compatible API shape, or explicitly publish the
  Automata difference.
- [ ] Hydrate repository variables and secrets.
- [ ] Validate environment inputs against configured environments.
- [ ] Populate actor and triggering actor correctly.
- [x] Pin the exact current sealed runtime policy in authenticated dispatch
  admission and prove changed-input conflicts plus exact-replay idempotency.

### `schedule`

- [ ] Match the five-minute minimum schedule interval.
- [ ] Populate `github.event.schedule`.
- [ ] Match default-branch and latest-workflow selection.
- [ ] Match actor semantics when the default branch or cron is changed.
- [ ] Handle deleted or disabled workflows.
- [ ] Handle default-branch changes.
- [ ] Implement public-repository inactivity disable/reactivation semantics.
- [ ] Test delayed and dropped runs under high load.
- [ ] Test duplicate fire and retry behavior.
- [ ] Test scheduler restart and multi-replica claims.
- [ ] Hydrate variables and eligible secrets.
- [x] Re-resolve the exact durable source authority before matching a private
  scheduled workflow; preserve this fail-closed boundary as schedule semantics
  expand.
- [ ] Correct stale docs that still describe schedule synthesis as unsupported.

## 5. YAML and workflow schema

GitHub explicitly supports YAML anchors and aliases. Automata currently rejects
all anchors and aliases. See
[reusable configurations and YAML anchors](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).

- [ ] Support YAML anchors on mappings.
- [ ] Support YAML anchors on sequences.
- [ ] Support YAML anchors on scalars.
- [ ] Support aliases for environment maps.
- [ ] Support aliases for complete step lists.
- [ ] Support aliases for complete job definitions.
- [ ] Support aliases for service definitions.
- [ ] Match GitHub's handling of duplicate anchors.
- [ ] Continue rejecting YAML merge keys if matching current GitHub behavior.
- [ ] Distinguish aliases from unsupported merge-key syntax in diagnostics.
- [ ] Differential-test YAML 1.2 boolean behavior.
- [ ] Test `.yml` and `.yaml`.
- [ ] Test BOM and newline variants.
- [ ] Test quoted and unquoted `on`.
- [ ] Test null, empty, and duplicate values.
- [ ] Test unknown keys at every workflow level.
- [ ] Reject unsupported keys rather than preserving them as apparent support.
- [ ] Enforce the current 500 KB workflow-file limit.
- [ ] Document Automata's depth, scalar, collection, and expansion limits when
  stricter than GitHub.
- [ ] Preserve accurate source spans through anchor expansion.
- [ ] Test `run-name` evaluation and display.
- [ ] Test workflow, job, and step `env` precedence.
- [ ] Test workflow and job `defaults.run` precedence.
- [ ] Test every accepted job field through runtime, not merely
  deserialization.
- [ ] Test every accepted step field through runtime.
- [ ] Maintain a generated schema-versus-docs inventory.

## 6. Expressions and context availability

GitHub documents context availability by workflow key and supports `contains`,
`startsWith`, `endsWith`, `format`, `join`, `toJSON`, `fromJSON`, `hashFiles`,
status functions, wildcard filters, and loose coercion. See
[expressions](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions)
and
[contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts).

- [ ] Implement production `hashFiles()`.
- [ ] Match glob negation ordering.
- [ ] Match path normalization per operating system.
- [ ] Match case sensitivity per operating system.
- [ ] Match symlink handling.
- [ ] Match behavior for missing files and empty matches.
- [ ] Match directory rejection or handling.
- [ ] Hash file contents in the same deterministic order.
- [ ] Prevent `hashFiles` from escaping the workspace.
- [ ] Generate the context-availability table from current GitHub
  documentation.
- [ ] Validate every expression-bearing workflow key against that table.
- [ ] Match null and empty-string behavior for missing properties.
- [ ] Match boolean and numeric coercion.
- [ ] Match NaN behavior.
- [ ] Match hexadecimal and exponent parsing.
- [ ] Match negative-zero comparison.
- [ ] Match case-insensitive string comparison, including non-ASCII cases.
- [ ] Match identity equality for arrays and objects.
- [ ] Match wildcard filtering over arrays and objects.
- [ ] Match short-circuit evaluation.
- [ ] Test unevaluated invalid properties and functions in short-circuited
  branches.
- [ ] Test every built-in function's arity.
- [ ] Match `format` brace escaping.
- [ ] Match `join` for scalar, null, and array inputs.
- [ ] Match `fromJSON` failures and limits.
- [ ] Prevent `toJSON` from exposing secret material.
- [ ] Remove or clearly classify Automata-only expression helpers such as
  `case`.
- [ ] Match implicit `success()` insertion for job and step conditions.
- [ ] Match explicit `always()`, `cancelled()`, `failure()`, and `success()`.
- [ ] Test status functions across transitive dependency graphs.
- [ ] Test expression templates containing multiple `${{ }}` segments.
- [ ] Test malformed delimiters, quotes, and escapes.
- [ ] Fail unsupported expressions at compile time instead of silently
  yielding null.

## 7. Context objects, default variables, and environment semantics

GitHub's variable reference includes the complete `GITHUB_*` and `RUNNER_*`
surface, configuration-variable precedence, and limits. See
[variables reference](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).

Missing or incomplete values include:

- [ ] `github.actor_id`
- [ ] `github.triggering_actor`
- [ ] `github.ref_protected`
- [ ] `github.repository_id`
- [ ] `github.repository_owner_id`
- [ ] `github.retention_days`
- [ ] `github.secret_source`
- [ ] action-specific `github.action`
- [ ] action-specific `github.action_path`
- [ ] action-specific `github.action_ref`
- [ ] action-specific `github.action_repository`
- [ ] `GITHUB_ACTOR_ID`
- [ ] `GITHUB_ACTION_REF`
- [ ] `GITHUB_REPOSITORY_ID`
- [ ] `GITHUB_REPOSITORY_OWNER_ID`
- [ ] `GITHUB_REF_PROTECTED`
- [ ] `GITHUB_RETENTION_DAYS`
- [ ] correct pull-request `GITHUB_REF_NAME`
- [ ] correct pull-request `GITHUB_REF_TYPE`
- [ ] `RUNNER_DEBUG`
- [ ] correct `runner.environment`
- [ ] x86 and ARM architecture mappings.

Broader context work:

The current runtime already constructs phase-correct environments in
base → job → prior command-file → step order, including case-insensitive
Windows keys, and re-evaluates top-level and nested action-post environments.
The authenticated source manifest also retains the immutable repository owner
ID, but the corresponding runtime context/default variables remain missing.

- [ ] Populate every documented `github` property for the correct event and
  phase.
- [ ] Rotate command-file paths for every step.
- [ ] Populate action-only properties only during action phases.
- [ ] Populate the complete `runner` context on Linux, Windows, macOS, and in
  containers.
- [ ] Populate `job.container` after job containers exist.
- [ ] Populate `job.services` ports and absence semantics exactly.
- [ ] Verify `steps.<id>.outcome` versus `conclusion` under
  `continue-on-error`.
- [ ] Complete the `jobs` context for reusable-workflow finalization.
- [ ] Preserve typed booleans and numbers in `inputs`.
- [ ] Complete repository, organization, and environment `vars`.
- [ ] Apply variable precedence correctly.
- [ ] Enforce current variable limits:
  - [ ] 48 KB per variable;
  - [ ] 500 repository variables;
  - [ ] 1,000 organization variables;
  - [ ] 100 environment variables;
  - [ ] 256 KB combined repository/organization delivery.
- [ ] Treat configuration-variable names case-insensitively.
- [ ] Prevent configuration variables from using the `GITHUB_` prefix.
- [x] Prevent jobs from overwriting documented default variables in the
  `GITHUB_*` and `RUNNER_*` namespaces without reserving custom names such as
  `GITHUB_TOKEN` or `RUNNER_DIGEST`.
- [x] Continue allowing `CI` only as the documented exception.
- [x] Prevent `GITHUB_ENV` from setting `NODE_OPTIONS`.
- [ ] Add a generated field-by-field context conformance suite.

## 8. Matrices, dependencies, and job graph execution

- [ ] Enforce `strategy.fail-fast`.
- [ ] Enforce `strategy.max-parallel`.
- [ ] Cancel remaining matrix siblings after a non-tolerated failure.
- [ ] Respect per-cell `continue-on-error` during fail-fast decisions.
- [ ] Persist throttling state across orchestrator restarts.
- [ ] Persist fail-fast cancellation state.
- [ ] Test queued, leased, running, and completed cells.
- [ ] Test fail-fast while a sibling lease is being accepted.
- [ ] Test fail-fast during runner loss.
- [ ] Test dynamic matrices from previous job outputs.
- [ ] Test invalid `fromJSON`.
- [ ] Test empty matrices.
- [ ] Test include-only matrices.
- [ ] Test duplicate matrix combinations.
- [ ] Test `include` object merging.
- [ ] Test combinations introduced solely by `include`.
- [ ] Test `exclude` matching.
- [ ] Support expressions nested inside matrix array or object values if GitHub
  accepts them.
- [ ] Enforce the 256-job matrix limit exactly.
- [ ] Match matrix numbering and strategy context.
- [ ] Support matrices on reusable-workflow call jobs.
- [ ] Implement exact matrix-output merge behavior.
- [ ] Test completion-order effects on matrix outputs.
- [ ] Test outputs from failed, skipped, and continued cells.
- [ ] Match implicit dependency-success behavior.
- [ ] Match skipped propagation through chains and diamonds.
- [ ] Match cancellation propagation through `needs`.
- [ ] Match `needs.<job>.result` values and casing.
- [ ] Match absent and empty outputs.
- [ ] Match `toJSON(needs)` and dynamic indexing.
- [ ] Implement currently rejected output-merge logical semantics.
- [ ] Test reruns of only failed matrix jobs.
- [ ] Ensure selected reruns retain correct dependencies and carried results.

## 9. Concurrency, cancellation, and reruns

GitHub documents `queue: single`, `queue: max`, a maximum of 100 waiting items,
case-insensitive groups, and FIFO-by-wait-start behavior. See
[concurrency syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency).

- [x] Reclassify `queue: max` as current GitHub syntax, not an Automata-only
  extension.
- [x] Match the 100-item queue.
- [x] Reject `queue: max` with `cancel-in-progress: true`.
- [x] Match FIFO based on when a job or run begins waiting.
- [ ] Implement job-level concurrency.
- [ ] Evaluate job-level groups with the correct contexts.
- [x] Support expression-valued `cancel-in-progress`.
- [x] Match case-insensitive group names.
- [x] Keep groups repository-scoped.
- [x] Match replacement of the existing pending run under `queue: single`.
- [ ] Propagate cancellation to queued jobs.
- [ ] Propagate cancellation to active leases.
- [ ] Propagate cancellation to complete process trees.
- [ ] Propagate cancellation to services.
- [ ] Propagate cancellation to result projection.
- [ ] Run subsequent `if: always()` cleanup steps after cancellation.
- [ ] Run subsequent `if: cancelled()` steps after cancellation.
- [ ] Run registered JavaScript-action posts after cancellation when GitHub
  does.
- [ ] Run nested-composite posts after cancellation.
- [ ] Preserve checkout cleanup after cancellation.
- [ ] Determine whether command files written before cancellation must be
  collected.
- [ ] Match GitHub's graceful cancellation signal and escalation sequence.
- [ ] Test workflow- and job-concurrency interaction.
- [ ] Test concurrency during reruns.
- [ ] Test duplicate event delivery.
- [ ] Test coordinator failover.
- [ ] Test cancellation while a post action is running.
- [ ] Test job and workflow timeouts during cleanup.
- [x] When uncertain sandbox creation returns an exact recovery handle, journal
  it as cleanup custody and fence any missing-custody state without identity
  reconstruction.
- [ ] For every shipped provider, prove returned sandbox custody is destroyed
  before slot release; document the bounded drain and provider-side
  reconciliation required when custody is missing.
- [x] Enforce the current 50-rerun limit (51 physical attempts including the
  original run).
- [x] Implement authenticated, durable, idempotent rerun-all,
  failed-and-dependents, and selected-job-and-dependents operations for the
  currently supported graph shapes.
- [ ] Extend rerun selection to matrix, workflow-concurrency, mutable-ref, and
  complete GitHub actor/ref semantics.
- [ ] Match rerun actor and triggering-actor behavior.
- [ ] Match reusable-workflow ref behavior for full reruns versus selected-job
  reruns.

## 10. Reusable workflows

GitHub supports local and cross-repository reusable workflows, ten levels, 50
unique workflows, matrices on call jobs, permission reduction, and defined
rerun/ref behavior. See
[reusable workflow reference](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).

Current component foundation: repository-local reusable calls execute through
a sealed control-plane coordinator. Focused PostgreSQL tests cover child
activation/materialization, terminal result propagation, autonomous call
completion, public output mapping, secret-derived output suppression, and
value-free environment/secret/variable requirements sealed against drift.
Production provider/runner acceptance and the broader cases below remain open.

- [ ] Prove the existing repository-local reusable coordinator through full
  production provider/runner composition without projecting the coordinator as
  a runner job.
- [ ] Support `owner/repo/path@ref`.
- [ ] Resolve SHA references.
- [ ] Resolve branch references.
- [ ] Resolve tag references.
- [ ] Refuse redirects.
- [ ] Support public cross-repository calls.
- [ ] Support approved private and internal cross-repository calls.
- [ ] Enforce caller/callee repository visibility rules.
- [ ] Bind resolved source to immutable provenance.
- [ ] Support matrices on call jobs.
- [ ] Support all documented call-job keywords.
- [ ] Preserve caller `github` context.
- [ ] Apply the caller's runner access.
- [ ] Enforce ten-level nesting.
- [ ] Enforce 50 unique reusable workflows.
- [ ] Match full-rerun mutable-ref behavior.
- [ ] Pin the original callee commit for selected-job and failed-job reruns.
- [ ] Complete typed input coercion.
- [ ] Verify required-plus-default behavior.
- [ ] Support documented input expression contexts.
- [ ] Support complete output propagation.
- [ ] Support nested outputs.
- [ ] Support outputs from skipped or failed callees.
- [ ] Support output behavior for matrix callees.
- [ ] Implement full `secrets: inherit`.
- [ ] Permit safe secret renaming.
- [ ] Handle omitted secret hops.
- [ ] Detect case-insensitive secret collisions.
- [ ] Preserve permission monotonicity through every hop.
- [ ] Support environment-bearing callee jobs.
- [ ] Match caller/callee environment-secret behavior.
- [ ] Test cancellation and concurrency across caller/callee boundaries.
- [ ] Test source changes between attempts.
- [ ] Test inaccessible nested workflows.
- [ ] Test cycles, depth, and catalog limits end to end.

## 11. JavaScript, composite, and repository actions

GitHub action metadata supports JavaScript, composite, and Docker actions, with
inputs, outputs, pre, main, and post hooks, and Node 20 or 24. See
[action metadata syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax).

Current component tests already prove repository pre-before-main ordering,
ordinary-failure posts, reverse nested post order, occurrence-scoped state,
bounded cleanup deadlines, and post-time re-evaluation of inputs, environment,
defaults, timeout, and continuation policy. Checked-out local action `pre` and
all cancellation-time post behavior remain gaps.

- [ ] Execute JavaScript actions on Windows.
- [ ] Execute local JavaScript actions on Windows.
- [ ] Execute composite actions on Windows.
- [ ] Execute nested composites on Windows.
- [ ] Enable `actions/checkout` on Windows.
- [ ] Enable setup actions on Windows.
- [ ] Enable artifact and cache actions on Windows.
- [ ] Configure Node 24 in the Windows profile.
- [ ] Decide whether Node 20 compatibility is required.
- [ ] Either configure node12, node16, and node20 or reject those action
  runtimes during admission.
- [ ] Keep the runner/runtime pin aligned with GitHub's Node patch version.
- [ ] Implement local-action `pre`.
- [ ] Match `pre-if`.
- [ ] Match `post-if`.
- [x] Preserve occurrence-scoped state through prepared repository action
  pre/main/post phases.
- [x] Match reverse nested post ordering in focused component tests.
- [x] Run registered posts after ordinary main failure.
- [ ] Match post behavior after cancellation.
- [x] Enforce bounded post cleanup timeouts.
- [x] Re-evaluate post `continue-on-error` at post time.
- [ ] Match action default inputs.
- [ ] Match required-input behavior; metadata `required: true` does not itself
  force runner failure.
- [ ] Match `INPUT_*` normalization exactly.
- [ ] Match invocation-specific `GITHUB_ACTION`.
- [ ] Match `GITHUB_ACTION_PATH`.
- [ ] Match `GITHUB_ACTION_REPOSITORY`.
- [ ] Add authenticated private action downloads.
- [ ] Add internal action downloads.
- [ ] Replace production `NoRepositoryCredentials` action fetching with exact
  lease/job-scoped repository authority for private and internal actions.
- [ ] Complete configured GitHub Enterprise Server support, including an
  explicitly reviewed alternate archive origin where required. The base HTTP
  endpoint is already configurable and redirect rejection must remain.
- [ ] Add source-integrity verification for repository action archives.
- [ ] Enforce action allow and deny policy.
- [ ] Support immutable-SHA policy.
- [ ] Implement redirect rejection.
- [ ] Test repository renames and missing refs.
- [ ] Run real `actions/checkout` acceptance:
  - [ ] normal clone;
  - [ ] detached SHA;
  - [ ] fetch depth;
  - [ ] submodules;
  - [ ] LFS;
  - [ ] sparse checkout;
  - [ ] persisted credentials;
  - [ ] cleanup.
- [ ] Run exact setup-action fixtures against the advertised tool cache.
- [ ] Test action toolkit calls against Automata Results, cache, and OIDC.
- [ ] Decide whether unsupported `runs.plugin` remains a documented rejection.

## 12. Shell and script semantics

- [ ] Implement arbitrary valid custom shell templates with exactly one `{0}`
  placeholder.
- [ ] Implement template parsing without invoking an extra shell unexpectedly.
- [ ] Match default Linux and macOS fallback from missing `bash` to `sh`.
- [ ] Match explicit `bash` fallback behavior.
- [ ] Match Windows default fallback from PowerShell Core to Windows
  PowerShell.
- [ ] Support Git Bash for `shell: bash` on Windows.
- [ ] Support `sh` on Windows where GitHub does.
- [ ] Enable and configure PowerShell on the Linux compatibility profile.
- [ ] Match script-file extensions.
- [ ] Match script encoding and line endings.
- [ ] Match GitHub's `cmd` invocation and quoting semantics, or document the
  hardened divergence.
- [ ] Test shell paths containing spaces and metacharacters.
- [ ] Test exit-code propagation.
- [ ] Test PowerShell `$LASTEXITCODE`.
- [ ] Test signals and Ctrl-C or Ctrl-Break.
- [ ] Test job and step `working-directory` precedence.
- [ ] Decide whether absolute working directories outside the workspace are
  supported.
- [ ] Match container shell defaults once job containers exist.
- [ ] Add macOS shell behavior.
- [ ] Add advertised Python runtime acceptance.
- [ ] Add shell-not-found diagnostics matching the correct lifecycle phase.

## 13. Docker actions, job containers, and service containers

- [ ] Implement `jobs.<job>.container`.
- [ ] Implement `container.image`.
- [ ] Implement container registry credentials.
- [ ] Implement container environment.
- [ ] Implement container ports.
- [ ] Implement container volumes.
- [ ] Implement documented container options.
- [ ] Implement container working-directory mapping.
- [ ] Implement container command-file paths.
- [ ] Implement `/github/home`.
- [ ] Implement `/github/workspace`.
- [ ] Implement `/github/workflow`.
- [ ] Populate `job.container`.
- [ ] Implement Docker actions using Dockerfiles.
- [ ] Implement `docker://image`.
- [ ] Implement Docker action `entrypoint`.
- [ ] Implement Docker action `args`.
- [ ] Implement Docker action environment.
- [ ] Implement Docker action filesystem mounts.
- [ ] Match Dockerfile restrictions and default-user behavior.
- [ ] Permit tag-based service images where GitHub permits them, or document
  the immutable-digest-only divergence.
- [ ] Implement service registry credentials.
- [ ] Implement service volumes.
- [ ] Implement expression-derived service ports.
- [ ] Implement secret service environment through non-durable transport.
- [ ] Support the documented service `options` surface.
- [ ] Match service health and readiness behavior.
- [ ] Match service failure diagnostics.
- [ ] Match service DNS and network naming.
- [ ] Match host port publication.
- [ ] Publish and pin the reviewed service-proxy helper image.
- [ ] Run a real service-container workflow through production.
- [ ] Run multiple services with TCP and UDP ports.
- [ ] Test cancellation and cleanup of services.
- [ ] Test restart recovery without leaked containers or networks.
- [ ] Decide whether general Docker socket behavior is a goal.
- [ ] Keep the narrow BuildKit proxy clearly separate from a general Docker
  daemon.
- [ ] Run live `setup-buildx-action` acceptance.
- [ ] Run live `build-push-action` acceptance.
- [ ] Run live CacheService v2 BuildKit sessions.
- [ ] Add Windows container support if Windows parity is a goal.
- [ ] Add Hyper-V or disposable Windows isolation before hostile Windows
  workflows.

## 14. Workflow commands, command files, and log semantics

GitHub documents annotations, groups, masks, command stopping, state, and the
`GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_PATH`, `GITHUB_STATE`, and
`GITHUB_STEP_SUMMARY` files. See
[workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).

- [ ] Implement problem matchers rather than discarding matcher events.
- [ ] Load matcher JSON safely.
- [ ] Convert matched log lines into annotations.
- [ ] Support matcher removal.
- [ ] Implement structured nested log groups.
- [ ] Preserve group start and end in Results and UI.
- [ ] Implement `::debug::`.
- [ ] Implement `ACTIONS_STEP_DEBUG`.
- [ ] Set `RUNNER_DEBUG=1` when debug logging is enabled.
- [ ] Implement command echo changes.
- [ ] Preserve stop and resume command behavior across stdout and stderr.
- [ ] Verify command parsing across fragmented output records.
- [ ] Enforce annotation metadata fields and path, line, and column validation.
- [x] Enforce immutability for the documented default `GITHUB_*` and
  `RUNNER_*` variables.
- [x] Keep `NODE_OPTIONS` blocked through `GITHUB_ENV`.
- [ ] Decide whether to support `ACTIONS_ALLOW_UNSECURE_COMMANDS`.
- [ ] Match multiline environment/output delimiter parsing.
- [ ] Match UTF-8 BOM behavior.
- [ ] Match CRLF behavior.
- [ ] Match duplicate environment, path, and output semantics.
- [ ] Match summary aggregation and ordering.
- [ ] Match deletion and empty-summary behavior.
- [ ] Match command-file effects after failed steps.
- [ ] Differential-test command-file effects after cancellation.
- [ ] Change masking from retroactive whole-phase masking to GitHub's
  observable registration-forward behavior.
- [ ] Add runner-equivalent transformed masks where required:
  - [ ] URI-escaped;
  - [ ] JSON-escaped;
  - [ ] shell-escaped;
  - [ ] line-fragment forms.
- [ ] Test multiline secrets.
- [ ] Test overlapping masks.
- [ ] Test masks introduced by actions.
- [ ] Stream logs live rather than only after process completion.
- [ ] Keep command parsing correct under live streaming.
- [ ] Define output and log size limits with compatible failure behavior.
- [ ] Ensure truncation cannot silently discard successful command files.

## 15. Artifacts, provenance, and attestations

Automata has a reviewed slice of the modern Results API, but not the full
artifact lifecycle. GitHub artifacts support cross-job and cross-run storage,
download, deletion, retention, and attestations. See
[workflow artifacts](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts).

The current offline client-library fixtures pin `actions/upload-artifact`
7.0.1 (embedded artifact client 6.2.0) and `actions/cache` 5.0.5 without network
downloads. They are ignored, memory-backed compatibility probes rather than
ordinary action-wrapper or production PostgreSQL/object-store acceptance.

- [ ] Run exact current `actions/upload-artifact` client acceptance.
- [ ] Run exact current `actions/download-artifact` client acceptance.
- [x] Support selecting an artifact by name in the current Results boundary.
- [x] Support selecting an artifact by ID in the current Results boundary.
- [ ] Support downloading all artifacts.
- [ ] Support pattern selection.
- [ ] Support merge-multiple behavior.
- [x] Verify downloaded artifact digests in the exact client-library fixture.
- [x] Support run-scoped same-run cross-job listing and downloads.
- [ ] Support cross-run downloads.
- [ ] Support cross-repository downloads with reviewed authority.
- [ ] Implement overwrite semantics.
- [ ] Implement artifact deletion.
- [ ] Implement list and management APIs.
- [ ] Implement retention-days semantics.
- [ ] Implement repository and workflow retention policy.
- [ ] Implement expiry processing.
- [ ] Implement physical object garbage collection.
- [ ] Implement name-collision behavior.
- [ ] Implement hidden-file behavior.
- [ ] Match glob and symlink behavior.
- [ ] Match compression-level behavior.
- [ ] Match empty-file and no-files behavior.
- [x] Add read-only artifact browse/download UI with digest, size, and expiry.
- [ ] Add artifact deletion and provenance-management UI.
- [ ] Link artifacts from Check Runs.
- [ ] Implement artifact-metadata permission handling.
- [ ] Implement general artifact attestations.
- [ ] Implement attestation signing and verification.
- [ ] Implement provenance subject association.
- [ ] Implement attestation management and revocation where required.
- [ ] Accept that artifacts cannot be inserted as native GitHub Actions
  artifacts.
- [ ] Clearly label Automata-owned artifacts in the UI and Checks.

## 16. Dependency cache

GitHub's cache behavior includes immutable entries, exact and prefix restore,
branch scoping, rate limits, quotas, and eviction. See
[dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).

- [ ] Run exact current `actions/cache` client acceptance.
- [ ] Run `actions/cache/restore`.
- [ ] Run `actions/cache/save`.
- [ ] Test `cache-hit`.
- [ ] Match key and version calculation.
- [x] Match ordered restore keys.
- [x] Match current-ref then canonical default-branch visibility.
- [x] Match pull-request merge-ref scope.
- [ ] Match fork write restrictions.
- [ ] Match cross-OS archive behavior.
- [x] Match concurrent save and finalize races.
- [x] Match immutable-entry conflict behavior.
- [ ] Add cache listing.
- [ ] Add cache usage reporting.
- [ ] Add deletion by key.
- [ ] Add deletion by ID.
- [ ] Add deletion by ref.
- [ ] Add bulk cleanup.
- [ ] Add physical object collection after eviction.
- [ ] Make quota and retention configurable where appropriate.
- [x] Match seven-day inactivity semantics.
- [x] Match the documented 10 GiB repository LRU quota.
- [ ] Enforce cache upload, download, and delete rate limits, or document
  Automata alternatives.
- [ ] Run production object-store acceptance.
- [ ] Run BuildKit `cache-to` and `cache-from` acceptance.
- [ ] Enable cache actions on Windows.
- [ ] Decide whether CacheService v1 compatibility is needed.
- [ ] Keep native GitHub cache inventory explicitly out of scope.

## 17. Secrets and configuration variables

GitHub has repository, organization, and environment secrets and variables,
visibility policies, precedence, limits, and delayed environment availability.
See [secrets reference](https://docs.github.com/en/actions/reference/security/secrets)
and
[variables reference](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).

- [ ] Add organization secrets.
- [ ] Add enterprise secrets if in product scope.
- [x] Store versioned repository and environment secret bindings with current
  policy/version evidence at the PostgreSQL authority boundary.
- [ ] Add selected-repository policies.
- [ ] Add organization variables.
- [x] Store versioned repository and environment variables with precedence and
  currentness checks.
- [ ] Expose repository/environment values through complete product APIs and
  runtime delivery; add the missing organization scope.
- [ ] Add management API, CLI, and UI for all supported scopes.
- [ ] Apply native precedence.
- [ ] Apply case-insensitive names.
- [ ] Detect collisions.
- [ ] Return an empty string for unset secret or context values where GitHub
  does.
- [ ] Match secret availability for fork pull requests.
- [ ] Match Dependabot restrictions.
- [ ] Match environment-secret release only after approval.
- [ ] Match queue-time versus runner-start secret reads.
- [ ] Support dynamic secret references where GitHub allows them.
- [ ] Otherwise reject dynamic references during publication.
- [ ] Support reusable-workflow secret renames.
- [ ] Support complete `secrets: inherit`.
- [ ] Support safe multi-hop forwarding.
- [ ] Preserve exact secret authority and version evidence.
- [x] Register every built-in managed-secret value for masking before custody
  acknowledgement, provider work, or user code starts.
- [ ] Add secret redaction variants.
- [ ] Test empty secrets and common substrings.
- [ ] Test secret-derived output suppression and warning behavior.
- [ ] Add external and dynamic secret providers if required.
- [ ] Document that GitHub's stored secret values cannot be imported.

## 18. Environments, deployments, and approvals

GitHub environments provide reviewers, wait timers, deployment branch rules,
custom protection rules, secrets, and variables. See
[deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

- [ ] Remove the current logical projection rejection for environment jobs.
- [ ] Carry environment names into JobIR.
- [ ] Evaluate environment names at the correct lifecycle point.
- [ ] Evaluate `environment.url`.
- [ ] Create deployment records or an explicit Automata equivalent.
- [ ] Publish deployment-status transitions.
- [ ] Add environment CRUD API.
- [ ] Add environment CLI.
- [ ] Add environment administration UI.
- [ ] Implement environment auto-creation if GitHub parity requires it.
- [ ] Implement required reviewers.
- [ ] Implement team reviewers.
- [ ] Implement approval thresholds.
- [ ] Complete `prevent_self_review`.
- [ ] Implement wait timers.
- [ ] Implement protected-branch-only rules.
- [ ] Implement branch and tag pattern rules.
- [ ] Implement administrator bypass settings.
- [ ] Record bypass audits.
- [ ] Implement custom GitHub App protection rules if in scope.
- [ ] Release environment secrets only after approval.
- [ ] Release environment variables at the correct phase.
- [ ] Handle rejection.
- [ ] Handle approval timeout.
- [ ] Handle cancellation while awaiting approval.
- [x] Revalidate environment revision/status/approval, event/source/reusable
  trust, secret versions/policies, variable precedence, and completeness under
  the lease authority lock before exposure.
- [ ] Handle reruns through protected environments.
- [x] Reject lease after stale reviewer, policy, disablement, or expiry changes
  at the PostgreSQL authority boundary.
- [ ] Enforce the current 30-day approval waiting limit.
- [ ] Add deployment history.
- [ ] Link deployment state from run and job pages.
- [ ] Test concurrency groups around deployment jobs.
- [ ] Pass existing approval storage and state machines through production
  acceptance.

## 19. OIDC

Automata has its own issuer and cannot be GitHub's issuer. It still needs
GitHub-compatible request semantics and a broader claim surface. See
[GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc).

- [ ] Support OIDC-only jobs without requiring unrelated repository
  permissions.
- [ ] Add actor and actor ID claims.
- [ ] Add repository ID and owner ID.
- [ ] Add run ID.
- [ ] Add ref type.
- [ ] Add head and base refs.
- [ ] Add environment identity.
- [ ] Add repository visibility and enterprise metadata where applicable.
- [ ] Add reusable-workflow identity claims.
- [ ] Match environment subject forms.
- [ ] Match pull-request subject forms.
- [ ] Support configurable subject templates if in target scope.
- [ ] Support audience selection.
- [ ] Validate permission gating through `id-token: write`.
- [ ] Match token lifetime and one-time request behavior.
- [ ] Prove discovery and JWKS endpoints.
- [ ] Prove key rotation.
- [ ] Bound retained signing-key history.
- [ ] Prove homogeneous multi-replica keys.
- [ ] Prove external TLS configuration.
- [ ] Test AWS federation.
- [ ] Test Azure federation.
- [ ] Test GCP federation.
- [ ] Test Vault or another generic OIDC consumer.
- [ ] Update stale OIDC documentation.
- [ ] Clearly require cloud policies to trust Automata's issuer.

## 20. Checks, logs, run UI, and control APIs

GitHub presents workflow runs through Check Suites, per-job Check Runs,
searchable and downloadable logs, rerun and cancel controls, and artifacts. See
[workflow run logs](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs).

Current aggregate Check subjects are fenced and cover provider deliveries,
scheduled fires, each `all_direct` workflow, and each physical rerun. They do
not contain a job identity or the richer presentation fields below.

- [ ] Publish one Check Run per job, or explicitly document the alternate
  projection.
- [ ] Populate `details_url`.
- [ ] Publish Check title, summary, and text.
- [ ] Publish step annotations.
- [ ] Batch annotations within API limits.
- [ ] Publish accurate started and completed timestamps.
- [ ] Publish accurate job conclusions.
- [ ] Link Automata logs.
- [ ] Link Automata artifacts.
- [ ] Link summaries.
- [ ] Support requested actions and rerun buttons where appropriate.
- [ ] Add commit-status projection where repositories require status contexts.
- [ ] Support `check_run`, `check_suite`, and `status` triggers.
- [ ] Add run list, filter, and search.
- [ ] Add workflow graph visualization.
- [ ] Add per-step timing.
- [x] Add log search.
- [ ] Add log archive download.
- [ ] Add log deletion.
- [ ] Add configurable retention.
- [ ] Add cancel controls.
- [ ] Add rerun-all.
- [ ] Add rerun-failed.
- [ ] Add rerun-specific-job.
- [ ] Add workflow enable and disable.
- [ ] Add run deletion.
- [ ] Add status badges.
- [ ] Add workflow notifications.
- [ ] Add Actions metrics.
- [ ] Add queue and runner utilization metrics.
- [ ] Add artifact and cache usage metrics.
- [ ] Add audit events for administrative actions.
- [ ] Expose selected reviewed REST or API equivalents needed by clients.
- [ ] Do not claim native GitHub Actions run records: GitHub does not permit
  third parties to insert them.

## 21. Runner registration, groups, labels, and fleet management

GitHub self-hosted runners include label and group routing, registration,
ephemeral or JIT operation, autoscaling, and ARC or scale-set patterns. See
[self-hosted runner reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners).

Current registration uses short-lived, one-use, tenant/group-scoped enrollment
tokens. Each runner generates its own key and submits its exact configured
capability ceiling in a CSR-based enrollment. The shipped Linux host still uses
three independent one-slot runner processes with distinct identities,
credentials, state, and metrics ports `9464`–`9466`; it is not one three-slot
runner.

- [x] Add authenticated token issuance and unauthenticated one-use redemption.
- [x] Remove privileged static fleet bootstrap rather than retaining a
  migration or break-glass compatibility path.
- [x] Negotiate the runner protocol and JobIR ranges before a session or lease;
  the current baseline admits protocol v1 only.
- [x] Add a runner enrollment and registration API.
- [ ] Add credential rotation.
- [ ] Add disable and enable.
- [ ] Add drain.
- [ ] Add delete and replace.
- [ ] Add runner inspection.
- [ ] Add label management.
- [ ] Add group management.
- [ ] Add repository access policy for groups.
- [ ] Add organization and enterprise access policy.
- [ ] Add selected-workflow access policy if required.
- [ ] Match group-plus-label routing.
- [ ] Match array-label routing.
- [ ] Match expression-derived `runs-on`.
- [ ] Match offline and stale runner behavior.
- [ ] Match queue-timeout behavior.
- [ ] Match the assignment pickup window.
- [ ] Add ephemeral one-job runners.
- [ ] Add JIT runner credentials.
- [ ] Add queue-aware autoscaling.
- [ ] Add scale-to-zero.
- [ ] Add capacity reporting.
- [ ] Add rolling upgrades.
- [ ] Add graceful drain during upgrades.
- [ ] Add orphan detection.
- [ ] Add multi-replica scheduler failover.
- [ ] Prove no double lease or commit.
- [ ] Add fleet reconciliation.
- [ ] Add Kubernetes operator assertions.
- [ ] Add production-cluster acceptance.
- [ ] Add a `workflow_job`-style lifecycle event for autoscalers.
- [ ] Publish a supported labels and profiles manifest.
- [ ] Make clear that `ubuntu-latest` is a selected Automata image, not
  automatically GitHub-hosted image parity.
- [ ] Publish the exact image digest and tool manifest.
- [ ] Sign runner distributions and image manifests.
- [ ] Add automatic runner protocol and version compatibility checks.

## 22. Platform and hosted-image compatibility

GitHub runners span Linux, Windows, and macOS, x64 and ARM64, with documented
tools, filesystem conventions, and privileges. See
[GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

### Linux

- [ ] Run the full unchanged CI gate under rootless Podman.
- [ ] Add `pwsh` where workflows expect it.
- [ ] Add advertised Node runtime versions.
- [ ] Add exact tool-cache semantics.
- [ ] Test common setup actions.
- [ ] Test Docker and build tools.
- [ ] Test browser workloads.
- [ ] Test GitHub filesystem layout.
- [ ] Publish an installed-software inventory.
- [ ] Differential-test against the selected GitHub image rather than merely
  reusing its label.

### Windows

The Windows implementation is a source-only, unprovisionable trusted-host
`run:` experiment for single-slot PowerShell, `cmd`, and optional Python. Every
`uses:` action and all job/service containers are rejected; Job Objects bound
process lifetime and resource use without changing the inherited account, host
filesystem, or network. It has no enrollment path or hosted release gate on the
current baseline.

- [ ] Support all `uses:` actions.
- [ ] Support Node 24 actions.
- [ ] Support checkout.
- [ ] Support artifact and cache actions.
- [ ] Support composites.
- [ ] Support service and job containers if target scope requires them.
- [ ] Support multiple parallel jobs safely.
- [ ] Add Git Bash.
- [ ] Add isolated Windows providers.
- [ ] Add restricted-token launch or stronger VM isolation.
- [ ] Add Hyper-V disposable runners for hostile jobs.
- [ ] Add service installation and recovery.
- [ ] Add a signed Windows distribution.
- [ ] Publish a Windows tool and image manifest.
- [ ] Preserve the trusted-host boundary until stronger isolation exists.
- [ ] Restore a hosted `windows-2025` build and real-runner release gate.

### macOS

- [x] Select and document the staged macOS direction: Apple Silicon macOS 15+
  trusted-native Bash/sh first, then repository-scoped self-hosted validation,
  followed by Virtualization.framework isolation.

- [ ] Add a macOS provider.
- [ ] Report `runner.os=macOS`, not Linux.
- [ ] Add macOS shell behavior.
- [ ] Add the initial Apple Silicon/ARM64 provider and acceptance path.
- [ ] Decide whether Intel/x64 is a later supported profile.
- [ ] Add process-tree containment.
- [ ] Add keychain and signing support.
- [ ] Add Xcode and toolchain profiles.
- [ ] Add macOS acceptance jobs.
- [ ] Add cleanup and recovery tests.

### Architecture and image breadth

- [ ] Add x86 if supported.
- [ ] Add ARM32 if supported.
- [ ] Add Linux ARM64.
- [ ] Add Windows ARM64.
- [ ] Prove runner-requirements-schema-v1 CPU, memory, ephemeral-storage, GPU,
  and per-runner PID-cap enforcement through production providers. These are
  structured `JobResourceAllocation` fields, not labels.
- [ ] Add custom images.
- [ ] Add image lifecycle and version pinning.
- [ ] Add an image-deprecation policy.
- [ ] Add proxy and custom-CA support.
- [ ] Add private-networking options.
- [ ] Add static egress or IP options if a hosted product is intended.

## 23. Limits, quotas, and overload behavior

GitHub's reference includes a 500 KB workflow file, 35-day workflow limit,
30-day approval wait, 256 matrix jobs, 50 reruns, 100 concurrency waiters,
24-hour self-hosted queue time, and five-day self-hosted job time. See
[Actions limits](https://docs.github.com/en/actions/reference/limits).

- [ ] Enforce or document the 500 KB workflow-file limit.
- [ ] Enforce or document the 35-day workflow limit.
- [ ] Enforce or document the 30-day approval limit.
- [ ] Enforce the 256-job matrix limit.
- [x] Enforce the 50-rerun limit.
- [x] Enforce the 100-entry `queue: max` limit.
- [ ] Implement the 24-hour self-hosted queue timeout.
- [ ] Decide whether to match the five-day self-hosted job maximum.
- [ ] Decide whether GitHub-hosted six-hour semantics apply to mapped hosted
  labels.
- [ ] Enforce or check the 50,000 Check Runs per suite boundary if applicable.
- [ ] Add trigger-event rate limiting.
- [ ] Add workflow-queue rate limiting.
- [ ] Add runner-registration rate limiting.
- [ ] Add cache-upload rate limiting.
- [ ] Add cache-download rate limiting.
- [ ] Add cache-delete rate limiting.
- [ ] Add GitHub App and API budget monitoring.
- [ ] Add object-store quota monitoring.
- [ ] Add backpressure instead of uncontrolled queue growth.
- [ ] Add overload-admission diagnostics.
- [ ] Test scheduler recovery at every durable transition.
- [ ] Test runner disconnect during each job phase.
- [ ] Test object-store timeout and retry.
- [ ] Test GitHub API throttling.
- [ ] Test webhook floods.
- [ ] Test large logs, summaries, outputs, and annotations.
- [ ] Document every deliberate Automata limit that is stricter than GitHub.

## 24. Security hardening

GitHub treats many event and context values as attacker-controlled and
recommends immutable action pins and careful handling of privileged triggers.
See
[script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections).

- [ ] Mark untrusted context properties in internal metadata.
- [ ] Prevent interpolation from implicitly turning untrusted fields into
  executable code.
- [ ] Add script-injection differential and security fixtures.
- [ ] Add branch-name injection fixtures.
- [ ] Add pull-request title and body injection fixtures.
- [ ] Add annotation and log injection fixtures.
- [ ] Enforce or recommend immutable action SHA pinning.
- [ ] Add repository action allowlists.
- [ ] Add organization action policies.
- [ ] Reject action and reusable-workflow redirects.
- [ ] Secure `pull_request_target`.
- [ ] Secure `workflow_run` privilege transitions.
- [ ] Prevent fork cache poisoning.
- [ ] Prevent untrusted artifacts from becoming privileged inputs without
  provenance checks.
- [ ] Isolate hostile jobs from runner credentials.
- [ ] Ensure secrets are registered for masking before process launch.
- [ ] Zeroize all ephemeral credentials.
- [ ] Bind credentials to runner, attempt, and lease.
- [ ] Test lease theft and replay.
- [ ] Test credential use after cancellation.
- [ ] Test credential use after rerun.
- [ ] Test service-container secret leakage.
- [ ] Test action-archive traversal and symlink attacks.
- [ ] Test workspace and command-file reparse or symlink attacks.
- [ ] Add artifact attestations and policy enforcement.
- [ ] Add audit logs for approvals, reruns, bypasses, and secret changes.
- [ ] Publish the accepted Hyper-V-container host, image, broker, isolation,
  recovery, and compatibility evidence for Windows workflows.

## 25. Explicit divergence decisions

These need deliberate product decisions. Silently drifting is worse than
stating that a behavior is unsupported.

- [ ] Decide whether immutable digest-only service images remain stricter than
  GitHub.
- [ ] Decide whether absolute working directories outside the workspace remain
  forbidden.
- [ ] Decide whether exact GitHub `cmd` quoting is too risky and should remain a
  hardened divergence.
- [ ] Decide whether deprecated insecure workflow commands will ever be
  opt-in.
- [ ] Decide whether legacy CacheService and artifact clients are supported.
- [ ] Decide whether arbitrary GitHub REST proxying remains out of scope.
- [ ] Decide whether native GitHub Deployment records will be created through
  reviewed APIs.
- [ ] Decide whether general Docker socket semantics are supported.
- [ ] Decide whether GitHub-hosted image parity is a goal or labels merely map
  to Automata profiles.
- [ ] Decide whether macOS is part of the compatibility promise.
- [x] Require hostile Windows workflows to wait for the Hyper-V-container
  acceptance gate; no weaker Windows fallback is permitted.
- [ ] Decide which GitHub UI, administration, and billing surfaces Automata
  will reproduce.
- [ ] Document that Automata's per-job `resources` syntax is not portable
  GitHub syntax.
- [x] Remove the stale claim that `queue: max` is Automata-only.
- [ ] Keep Automata-owned run, artifact, and cache records clearly distinct
  from native GitHub Actions records.

## Recommended implementation order

### Milestone 0: close security and false-positive gaps

- [ ] Correct `GITHUB_TOKEN` defaults, deny-all, OIDC-only, fork, and
  Dependabot behavior.
- [ ] Make pull-request path filters runnable.
- [x] Enforce reserved runner-owned default environment variables.
- [ ] Implement cancellation-aware cleanup and action posts.
- [ ] Reject every parsed-but-unrunnable feature before scheduling.
- [ ] Add the layered capability matrix.

### Milestone 1: pass one unchanged real Linux workflow

- [ ] Production checkout.
- [ ] Linux run, JavaScript, and composite actions.
- [ ] Matrices with fail-fast and max-parallel.
- [ ] Services.
- [ ] Artifact upload and download.
- [ ] Cache restore and save.
- [ ] Concurrency and cancellation.
- [ ] Results, logs, summaries, annotations, and Checks.
- [ ] Compare against GitHub at the same commit and event.

### Milestone 2: complete mainstream workflow language

- [ ] YAML anchors and aliases.
- [ ] Production `hashFiles`.
- [ ] Job-level concurrency.
- [ ] Reusable workflows.
- [ ] Environment jobs.
- [ ] Complete contexts and default variables.
- [ ] Complete dispatch and schedule behavior.

### Milestone 3: containers and broader actions

- [ ] Job containers.
- [ ] Docker actions.
- [ ] Complete services.
- [ ] Private, internal, and GitHub Enterprise Server actions.
- [ ] Real Buildx, BuildKit, and cache acceptance.

### Milestone 4: control-plane parity

- [ ] Broader webhook events.
- [ ] Variable and secret scopes.
- [ ] Protected environments.
- [ ] Deployments.
- [ ] Rerun, cancel, delete, and disable APIs.
- [ ] Check, log, artifact, and cache management.
- [ ] OIDC claim and subject parity.

### Milestone 5: platform and fleet breadth

- [ ] Windows actions and isolated providers.
- [ ] macOS execution.
- [ ] ARM64.
- [ ] Registration, groups, and autoscaling.
- [ ] Kubernetes production acceptance.
- [ ] Signed distributions and image manifests.

Milestone 0 should be implemented first. It closes security differences and
prevents Automata from accepting workflows it cannot run. After that, the most
valuable compatibility gate is unchanged production Linux CI rather than more
parser-only coverage.
