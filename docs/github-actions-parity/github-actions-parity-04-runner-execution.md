# GitHub Actions parity: Runner execution, actions, logs, and cancellation

Complete shells, action lifecycle, streaming output, workflow commands, masking, matchers, cancellation, and process termination.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane R, with provider and Results reviewers.

**Package IDs:** RUN-01, RUN-02, RUN-03, ACT-01, ACT-02, LOG-01, LOG-02, LOG-03, LOG-04, CAN-01, CAN-02.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Workflow language, expressions, and runtime contexts](github-actions-parity-02-workflow-language.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### RUN-01 — Action metadata, inputs, and runtime availability

**Owner:** R. **Size:** M. **Dependencies:** FND-03.

Tasks:

- [ ] Differential-test action default inputs and scalar coercion against a
  live pinned runner.
  - [x] Component fixtures cover missing, null, boolean, numeric-looking,
    literal, template, and expression defaults through metadata preparation
    and executor resolution.
- [x] Match `INPUT_*` normalization, declaration order, and
  case-insensitive lookup.
- [x] Preserve safe deprecation messages.
- [x] Match metadata `required: true` behavior without inventing validation.
- [x] Verify output expressions and absent outputs.
- [x] Populate invocation-specific action, path, ref, and repository context.
- [ ] Approve supported Node generations and reject unavailable runtimes at
  admission.
  - [x] The closed metadata set is `node12`, `node16`, `node20`, and `node24`;
    execution requires an exact same-generation toolchain entry and never
    falls back. The current Ubuntu profile provides only Node 24.
  - [x] Recursively preflight repository action runtimes after runtime-context
    masking but before custody acknowledgement, provider create/attach,
    archive extraction, or user code. Nested containers, cycles, and missing
    runtimes fail closed with zero provider operations.
  - [x] Reject checkout-created local action references during activation,
    before Job IR publication or runner lease, because preceding workflow code
    can create or replace metadata that does not exist at activation time. Keep
    the bounded JIT compiler and exact runtime/shell checks in the executor as
    defense in depth; that path is not advertised as runnable source support.
  - [x] Carry prepared repository runtime requirements across the scheduling
    boundary for exact-commit public actions. Activation anonymously and
    recursively resolves their metadata and records JavaScript/composite, exact
    Node generation, literal composite shells, repository-action, command-file,
    and summary capabilities in Job IR. Repository-composite `$/...` children
    bind to the same exact repository revision and are prepared recursively
    from that immutable archive. Their `./...` children remain workspace-local
    and fail closed before scheduling. Activation-known top-level shells are
    concretized. Capability matching rejects runners missing any requirement
    before lease acquisition; the runner repeats repository preflight before
    custody or provider work as defense in depth.
  - [x] Bind a schema-versioned supported `RunnerFeature` set to every immutable
    runtime-profile mapping. Activation requires one selected policy profile and
    rejects a source-required feature outside that exact set before runtime or
    Job IR blob publication. Unknown feature identifiers, duplicate or excessive
    sets, historical mappings without the feature-policy section, and Windows
    profiles that claim action or Node execution fail closed. The current Linux
    example claims only its configured Bash, `sh`, Python, Node 24, action, and
    command-file/summary toolchain features; Windows claims no action or Node
    runtime.
  - [x] Keep temporary placement absence distinct from terminal semantic
    admission. A job that passed its immutable profile ceiling but has no
    currently eligible runner remains durable `NoWork`; admission never derives
    global support from connected runner inventory.
  - [ ] Complete ACT-02 binding for mutable tag/branch resolution and private
    repository action credentials. Until then those references, along with
    repository composite shell expressions, fail closed before scheduling.
- [x] Pin Node patch versions in profile manifests. The current Ubuntu profile
  records Node 24.19.0; no legacy runtime is advertised by that profile.
- [x] Decide whether `runs.plugin` is supported; retain an explicit
  source-spanned publication rejection and document it as unsupported.

Acceptance:

- [x] Checkout, setup, and artifact metadata fixtures pass the complete
  decoder-to-prepared-action contract against the reviewed pinned metadata.
- [ ] Missing, default, boolean, and numeric-looking inputs pass live
  differential tests.
  - [x] The executor component suite covers all four shapes, declaration order,
    case-insensitive overlays, empty missing values, deprecations, and ignored
    `required: true` markers.

### RUN-02 — Shell and script dispatch parity

**Owner:** R. **Size:** L. **Dependencies:** FND-03.

Tasks:

- [x] Support custom shell templates with exactly one `{0}` placeholder under
  the published closed grammar in the executor README.
- [x] Reject zero or multiple placeholders without an unintended outer shell.
- [x] Implement default bash-to-sh fallback on POSIX.
- [x] Match explicit bash behavior.
- [x] Implement Windows PowerShell Core fallback to Windows PowerShell.
- [ ] Support configured Git Bash and `sh` on Windows.
  The isolated Windows profile currently exposes neither executable; both
  contracts reject during admission rather than probing the host. Add them only
  with a pinned image/toolchain update and corresponding isolation evidence.
- [x] Add Linux PowerShell profile support.
- [x] Match extensions, encoding, CRLF/LF, exit codes, and
  `$LASTEXITCODE`.
- [x] Test executable and script paths containing spaces and metacharacters.
- [x] Verify workflow/job/step working-directory precedence. Workflow and job
  defaults arrive as the frontend-resolved job default; step-local values
  override it, then the executor falls back to the workspace.
- [x] Record the exact hardened `cmd` quoting decision. Automata passes the
  script as a bounded argv value under `/D /E:ON /V:OFF /C`, omits the pinned
  runner's nested `/S /C CALL` string, and rejects active `cmd` path syntax.
- [x] Produce lifecycle-correct shell-not-found diagnostics. Static literals
  fail admission before provider work (`CapabilityChanged` for a missing
  configured tool, `InvalidJob` for an invalid contract); expression-derived
  shells fail before script copy or user execution.

Acceptance:

- [x] A table-driven suite covers every advertised shell and operating system.
- [x] Workflow-controlled values cannot escape the selected template contract.

### RUN-03 — Reserved environment variables and phase files

**Owner:** R. **Size:** M. **Dependencies:** FND-03.

Tasks:

- [x] Reject writes to documented default variables in the `GITHUB_*` and
  `RUNNER_*` namespaces from workflow and command-file environments,
  case-insensitively on Windows, without reserving custom names that merely
  share those prefixes.
- [x] Preserve the documented `CI` exception.
- [x] Continue blocking `NODE_OPTIONS` through `GITHUB_ENV`.
- [x] Rotate environment, output, path, state, summary, and artifact files for
  every phase.
- [x] Match BOM, CRLF, multiline delimiter, duplicate-key, and invalid-name
  behavior.
- [x] Test command-file collection after success, failure, timeout, and
  cancellation.
- [ ] Aggregate step summaries in completed-step order, define deletion and
  empty-file behavior, and preserve a deterministic truncation indicator.
  - [x] Completed-step ordering plus missing, deleted, and empty summaries are
    defined and covered.
  - [ ] Match the pinned runner's diagnostic-and-skip behavior for a summary
    larger than 1 MiB across the bounded copy interface. The pinned runner does
    not truncate the file, so no truncation policy is inferred.
- [x] Verify summary isolation across pre, main, post, composite, and repeated
  action occurrences.

Acceptance:

- [x] A step cannot shadow runner identity or command-file paths.
- [x] Phase files never leak between steps or action occurrences.

### ACT-01 — Checked-out local action `pre`

**Owner:** R. **Size:** L. **Dependencies:** RUN-01, CAN-01.

Current component foundation:

- [x] Repository actions run source-ordered `pre` phases before the matching
  main job step.
- [x] Registered top-level posts re-evaluate their environment, inputs,
  defaults, timeout, and continuation policy at post time.
- [x] Nested posts unwind in reverse source order with occurrence-scoped state,
  and ordinary user-code failure still enters the bounded post deadline.

Remaining tasks:

- [ ] Define when local metadata becomes available after checkout.
- [ ] Execute checked-out local JavaScript `pre` instead of emitting the
  current sanitized intentional-skip diagnostic, then keep pre, main, and post
  under one invocation identity.
- [ ] Apply the existing source ordering, occurrence state, `pre-if`, `post-if`,
  timeout, continuation, and registration semantics to checked-out local and
  nested-local actions.
- [ ] Start eligible top-level and nested JavaScript posts after execution
  cancellation under the distinct bounded cleanup budget defined by `CAN-01`.

Acceptance:

- [ ] Local and nested fixtures execute pre/main/post correctly.
- [ ] Cancellation retains bounded eligible cleanup.
- [ ] Repeated action occurrences do not share state.

### ACT-02 — Private, internal, and GHES action source resolution

**Owner:** R with C credential review. **Size:** XL. **Dependencies:** RUN-01,
AUTH-03.

Current component foundation:

- [x] Runner composition derives action archive requests from the configured
  GitHub HTTP endpoint instead of fixing the product path to GitHub.com.
- [x] The endpoint disables redirects and ambient proxy discovery, so an
  archive request cannot silently follow a cross-host redirect.

Remaining tasks:

- [ ] Replace the runner's `NoRepositoryCredentials` authority with a reviewed,
  lease- and job-scoped repository credential resolver; keep anonymous access
  only for sources that are actually public.
- [ ] Thread an explicitly reviewed archive origin through runner product
  configuration for GHES installations whose archive host differs from the
  configured server/API origin; never infer it from a redirect.
- [ ] Support public, approved private/internal, and configured GHES action
  sources.
- [ ] Resolve branch, tag, and SHA to immutable source evidence.
- [ ] Enforce repository and organization action allowlists and immutable-SHA
  policy.
- [ ] Verify archive digests, paths, links, and subpath containment.
- [ ] Cache only immutable action content.
- [ ] Keep credentials out of logs and durable action metadata.

Acceptance:

- [ ] Public and private repository actions execute under exact least
  authority.
- [ ] Unauthorized sources fail without leaking repository existence.
- [ ] Renames, missing refs, archive traversal, and symlink attacks are tested.

### LOG-01 — Pure workflow-command differential closure

**Owner:** R. **Size:** M. **Dependencies:** FND-02.

Tasks:

- [ ] Expand pure runtime fixtures for fragmented stdout/stderr, CRLF, BOM,
  heredocs, duplicates, annotations, groups, debug, echo, stop/resume,
  matchers, summaries, and failure/cancellation.
- [ ] Clearly classify recognized commands separately from executor-projected
  commands.
- [ ] Fix only demonstrated parser or phase-applicator differences.
- [ ] Preserve no-I/O boundaries and resource ceilings.

Acceptance:

- [ ] Parser fixtures are pinned to reviewed runner behavior.
- [ ] Recognized-but-discarded events remain visible to LOG-02 work.

### LOG-02 — Structured and incremental execution output

**Owner:** R owns the contract; P implements provider portions; X reviews
result storage. **Size:** XL. **Dependencies:** FND-03.

Tasks:

- [ ] Add ordered event types for ordinary bytes, begin/end group, debug,
  echo state, and system diagnostics.
- [ ] Preserve stdout/stderr identity and cross-pipe observation order.
- [ ] Add an object-safe, bounded execution output sink/session.
- [ ] Retain buffered fallback for providers without streaming capability.
- [ ] Advertise streaming explicitly.
- [ ] Define sink failure, cancellation, truncation, and exact replay behavior.
- [ ] Implement streaming in Podman and Windows providers.
- [ ] Gate Kubernetes or retain explicit buffered behavior.
- [ ] Publish frames while a process is still running.
- [ ] Persist and replay acknowledged frames without duplication.

Acceptance:

- [ ] A long-running command's first line reaches the control plane before
  exit.
- [ ] Sink failure or cancellation leaves no running process.
- [ ] Runner reconnect cannot duplicate acknowledged log events.
- [ ] Old byte-log readers remain compatible.

### LOG-03 — Live workflow commands and registration-forward masking

**Owner:** R. **Size:** L. **Dependencies:** LOG-01, LOG-02.

Tasks:

- [ ] Parse partial lines independently per stream while honoring observed
  order.
- [ ] Apply commands as output arrives.
- [ ] Register dynamic masks only for subsequent output.
- [ ] Keep static secrets masked before launch.
- [ ] Add required encoded and multiline mask forms.
- [ ] Apply stop/resume commands live.
- [ ] Project groups, debug, and echo state.
- [ ] Define which command-file effects survive cancellation.
- [ ] Ensure truncated output cannot silently apply incomplete mutations.

Acceptance:

- [ ] Dynamic masking is registration-forward, not retroactive.
- [ ] Existing secret-oracle tests remain green.
- [ ] Structured command effects appear in durable order.

### LOG-04 — Problem matchers, annotations, and debug controls

**Owner:** R. **Size:** L. **Dependencies:** LOG-03.

Tasks:

- [ ] Resolve matcher files beneath the workspace only.
- [ ] Reject traversal, links, reparse escapes, and oversized files.
- [ ] Parse a bounded matcher schema and bounded regular expressions.
- [ ] Register and remove by owner and source.
- [ ] Apply matchers only to subsequent lines.
- [ ] Bound multiline matcher state.
- [ ] Normalize annotation paths and locations.
- [ ] Mask captures before persistence.
- [ ] Implement `ACTIONS_STEP_DEBUG`, `RUNNER_DEBUG`, and command echo
  projection.

Acceptance:

- [ ] Representative compiler/setup matchers produce expected annotations.
- [ ] Malicious matcher data cannot exhaust the runner.

### CAN-01 — Cancellation-aware cleanup and action posts

**Owner:** R. **Size:** XL. **Dependencies:** FND-03; LOG-02 preferred.

Current component foundation:

- [x] When provider create reports an uncertain outcome with an exact recovery
  handle, journal that handle as sandbox cleanup custody and fence any
  missing-custody state without reconstructing a provider identity.
- [ ] Document and exercise the bounded operator path for missing custody:
  drain the runner, prove absence or cleanup from provider-owned evidence, then
  recreate empty local state without treating journal deletion as cleanup.

Tasks:

- [ ] Separate user-code cancellation from bounded cleanup cancellation.
- [ ] Re-evaluate remaining conditions after cancellation.
- [ ] Run eligible `always()` and `cancelled()` steps.
- [ ] Run registered JavaScript and nested-composite posts in correct order.
- [ ] Preserve checkout credential cleanup and action state.
- [ ] Distinguish cancellation, job timeout, and cleanup timeout.
- [ ] Collect only the command-file effects GitHub preserves.
- [ ] Always destroy services, networks, and sandbox state.
- [ ] Test cancellation during run, action pre/main/post, composite child,
  service startup, command-file read, and artifact hashing.

Acceptance:

- [ ] Differential fixtures match cleanup ordering and final conclusions.
- [ ] Cleanup cannot gain credentials not present before cancellation.
- [ ] No service or process survives.

### CAN-02 — Graceful signal escalation

**Owner:** R defines semantics; P implements providers. **Size:** L.
**Dependencies:** LOG-02, CAN-01.

Tasks:

- [ ] Model per-command process identity.
- [ ] Send the documented interrupt signal and wait the first grace period.
- [ ] Escalate to terminate and wait the second grace period.
- [ ] Kill the complete process tree by the force deadline.
- [ ] Implement Podman process-group behavior.
- [ ] Implement supported Windows Ctrl-C or Ctrl-Break behavior and Job Object
  fallback.
- [ ] Finish with service and sandbox cleanup.

Acceptance:

- [ ] Child and grandchild processes do not survive on Linux or Windows.
- [ ] Signal-observing fixtures see the expected sequence where supported.

---

[Previous: Matrices, scheduling, dependencies, and reusable workflows](github-actions-parity-03-scheduling-reuse.md) · [Next: Services, job containers, Docker, Podman, Kubernetes, and BuildKit](github-actions-parity-05-containers-docker.md)
