# Integration tests: Harness, evidence, and continuous operation

Build the shared cross-repository intake, admission, live-target, comparison,
and continuous-test machinery. Read the
[integration-test hub](github-actions-parity-11-integration-tests.md) first for
the evidence model, ownership boundary, security rules, and team schedule.

**Package IDs:** IT-01, IT-02, IT-03, IT-08.

## Work packages

### IT-01 — Cross-repository release-bundle and pin intake

**Owner:** X with P review. **Size:** M. **Dependencies:** FND-04.

**Primary scope:** a single verified descriptor that binds Automata source,
binaries, profiles, images, helpers, schemas, and deployment topology before
the suite launches any service.

The audited example configurations currently disagree on the profile-manifest
digest:

- the integration repository uses
  `60a170562937ab00b8772c088781620e38b8f5dbf3783f20a49197218d8cb6d4`;
- this repository's current profile lock uses
  `aeedd8086b362a929ab7be40913a148cb6236f5d98a2c1b590bc298fda7bcd76`;
- both reference image digest
  `db8471ae0e6b77038961029f8e8620ae35eb3cdde21978ff831c251e0ec899dd`.

Do not repair that by copying the newer manifest hash into the example. Produce
or select one coherent released bundle and verify every member of it.

Tasks:

- [ ] Define a versioned release-bundle descriptor and canonical encoding.
- [ ] Bind the Automata commit to independently hashed `automata` and
  `automata-runner` executables.
- [ ] Bind profile manifest, profile image, service proxy, database,
  object-store, and other helper images by digest.
- [ ] Bind protocol, JobIR, runner-requirements, export, fixture, and evidence
  schema versions.
- [ ] Bind provider, runner count, resource allocation, network policy,
  filesystem policy, and platform topology.
- [ ] Inventory package-manager, toolchain, and external-service dependencies;
  either hydrate a digest-addressed snapshot or record the exact reviewed
  egress prerequisite. Locked Git repositories alone do not make `npm install`
  or Go tool downloads hermetic.
- [ ] Verify the source worktree is clean and the selected commit contains the
  expected profile and workflow locks.
- [ ] Reject a zero hash, mutable tag, missing member, mixed bundle, or source
  and executable mismatch before starting PostgreSQL or a control process.
- [ ] Persist the accepted descriptor and verifier version with every report.
- [ ] Represent unavailable live prerequisites as an explicit non-passing
  skip, never a success.
- [ ] Document the reviewed promotion path when a new profile source manifest
  exists but its corresponding image has not been rebuilt and published.

Acceptance:

- [ ] Changing any source, binary, image, profile, schema, or topology member
  without issuing a new descriptor fails intake.
- [ ] The suite cannot start a gating run from placeholder values or a mutable
  reference.
- [ ] A report can be traced offline to one internally consistent release
  bundle.

### IT-02 — Admission lane, capability coverage, and graduation ledger

**Owner:** X with W review. **Size:** M. **Dependencies:** FND-01, FND-02,
FND-04.

**Primary scope:** prove what the product would select or reject before paying
for full execution, and mechanically connect scenario coverage to stable
product capability identifiers and admission behavior.

Tasks:

- [ ] Add an admission-only target that accepts the exact locked source and
  event and records selected workflows, expanded jobs, runner requirements,
  and stable rejections.
- [ ] Map scenario metadata to the stable capability identifiers exercised by
  product admission and to the owning work-package IDs without leaking
  planning IDs into runtime labels.
- [ ] Enforce that every locked top-level workflow in a fixture/project has a
  positive, negative, or intentionally unsupported scenario.
- [ ] Enforce `requiredCapabilities`, runner labels, runner-pool count,
  side-effect declarations, and scenario state at execution time; they are
  currently mostly descriptive metadata.
- [ ] Generate coverage by capability, event, workflow, platform, provider,
  primary evidence lane, evidence property, and scenario state.
- [ ] Record unsupported capability combinations as early rejection evidence.
- [ ] Require candidate-to-gating changes to cite the product acceptance PR,
  exact evidence bundle, and compatibility update.
- [ ] Require quarantine owner, issue, reason, expiry, and retained attempts.
- [ ] Fail when a new accepted capability or locked workflow has no scenario.
- [ ] Run admission over all four current workflows and seven current
  scenarios in ordinary secret-free CI.

Acceptance:

- [ ] The current corpus produces deterministic selected or rejected admission
  records without starting runners.
- [ ] No candidate, skipped, expired, or quarantined scenario contributes to a
  passing capability count.
- [ ] Coverage reports name missing product and test prerequisites separately.

### IT-03 — Live GitHub target and differential evidence

**Owner:** X with C review. **Size:** XL. **Dependencies:** FND-02.

**Staged prerequisites:** begin target and report contracts after `FND-02`;
accept the live path only after `EVT-01`, `AUTH-02`, `AUTH-03`, `RES-02`, and
`CHECK-01`. `SEC-02` consumes this machinery and is not a hard predecessor.

**Primary scope:** paired private fixture mirrors, least-privilege live
provider authority, concrete GitHub and Automata evidence adapters, and an
atomic differential report.

Tasks:

- [ ] Store private mirror mappings in protected deployment configuration, not
  public fixture manifests.
- [ ] Provision a narrowly scoped GitHub App and a separate read-only evidence
  observer; document and test each permission.
- [ ] Create source branches, same-repository pull requests, and tags from an
  exact fixture lock without rewriting workflow bytes.
- [ ] Resolve every `uses:` reference immediately before live execution and
  require it to match the fixture's locked action commit. The unchanged Chalk
  and p-limit workflows contain version tags, so a manifest lock alone cannot
  prevent the live target from resolving a moved tag.
- [ ] After execution, prove each action's resolved commit from trusted
  target-native evidence or diagnostics. Fail gating if the commit is missing
  or differs. If a target cannot expose trustworthy resolution evidence,
  classify the limitation and use a SHA-pinned workflow for exact-pin gates.
- [ ] Extend pull-request fixtures from one source SHA to an exact base/head
  commit graph. Record each provider-generated merge commit separately and
  compare its admitted tree/workflow content rather than pretending GitHub and
  the emulator share one merge SHA.
- [ ] Deliver one logical event to GitHub and Automata and bind both native run
  identities to it.
- [ ] Implement the concrete GitHub Actions evidence adapter.
- [ ] Complete the canonical Automata adapter after `RES-02` exposes required
  per-step outputs and other missing evidence.
- [ ] Poll with bounded deadlines and handle provider rate limits,
  indeterminate mutation results, delayed Checks, and duplicate delivery.
- [ ] Persist target-native records, schema-validated canonical records, and
  the fail-closed structural diff atomically.
- [ ] Verify Check names and external identities map to expected workflow
  paths, rather than checking only a successful count.
- [ ] Normalize only reviewed volatile fields and attach an approved-divergence
  ID to every allowed difference.
- [ ] Redact credentials, authorization headers, webhook bodies containing
  secrets, and signed URLs before evidence retention.
- [ ] Close temporary pull requests; delete temporary refs, tags, tokens, App
  resources, and provider-side test records where the API permits it; verify
  cleanup.
- [ ] Expose a non-interactive CLI command for protected CI orchestration.

Acceptance:

- [ ] One designated credential-free smoke event, initially Chalk push,
  executes repeatedly on GitHub and Automata from the same logical source/event
  inputs and produces both native and schema-valid canonical records. This
  proves the machinery but does not graduate the scenario.
- [ ] An unknown semantic difference, missing workflow, missing matrix row,
  action-resolution ambiguity, or incomplete observation fails the run.
- [ ] The report binds every input required by the hub's cross-repository
  evidence record and contains no credential.
- [ ] A failed or cancelled comparison still completes bounded cleanup and
  retains diagnostic evidence.

### IT-08 — Continuous compatibility operations

**Owner:** X as rotating integration owner. **Size:** L. **Dependencies:**
IT-03, IT-04.

**Staged prerequisites:** start secret-free PR and scheduled infrastructure
after the first Chalk gate. Run the full corpus and Automata dogfood only after
`GATE-01` establishes the Linux product baseline.

**Primary scope:** required smoke, scheduled live corpus, flake and quarantine
policy, reviewed fixture refreshes, performance budgets, and retained reports.

Tasks:

- [ ] Keep ordinary integration-repository pull-request CI secret-free and run
  contract tests, fixture audit, admission, and the approved isolated smoke.
- [ ] Configure checkout with `persist-credentials: false`; do not pass
  `${{ github.token }}` or `GITHUB_TOKEN` to harness steps; launch child
  processes from an explicit environment allowlist.
- [ ] Run root/privileged isolated smoke only on an ephemeral dedicated worker
  with no cloud metadata, persistent container socket, developer state, or
  reusable credential.
- [ ] Add a protected default-branch or manual live-provider workflow using
  exact suite and Automata commits.
- [ ] Reject arbitrary `workflow_dispatch` revisions for credentialed lanes.
  Require the executing suite workflow and code to be an exact trusted commit
  reachable from the protected default branch, and never consume PR-built
  artifacts.
- [ ] Run every scenario marked `gating` in the selected suite commit on a
  schedule and before a release candidate. Candidate or quarantined scenarios
  remain visible but do not block completion of this operations package.
- [ ] Add Automata's unchanged repository CI as a locked dogfood fixture only
  when `GATE-06` selects the exact source/workflow revision.
- [ ] Retain every retry attempt, classify flakes, and prohibit silent retry.
- [ ] Enforce quarantine owner, issue, reason, expiry, and automatic failure
  when an exception expires.
- [ ] Discover upstream fixture/action candidates without rewriting locks;
  open a reviewed update with byte and behavior diffs.
- [ ] Budget queue, provisioning, checkout, setup, execution, evidence,
  comparison, and cleanup phases separately.
- [ ] Publish a capability-coverage report generated from gating scenarios.
- [ ] Set bounded evidence retention and scrub reports before upload.
- [ ] Alert on a missing scheduled run, stale last-pass evidence, cleanup leak,
  or growing flake rate.

Acceptance:

- [ ] Required checks cannot pass from unit tests alone when their package
  requires isolated, live, differential, platform, or fault evidence.
- [ ] No untrusted pull-request code or artifact runs with live-provider,
  release, host-root, or production-like credentials.
- [ ] A regression produces one immutable report containing exact pins,
  attempts, differences, and cleanup status.

---

[Integration-test hub](github-actions-parity-11-integration-tests.md) · [Next: Corpus qualification](github-actions-parity-11b-integration-corpus.md) · [Parent execution plan](../github-actions-parity-execution-plan.md)
