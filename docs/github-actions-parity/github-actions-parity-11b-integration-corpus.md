# Integration tests: Corpus qualification and graduation

Graduate the existing Chalk, p-limit, and Testify scenarios without editing
their locked upstream workflows or claiming semantics they do not exercise.
Read the
[integration-test hub](github-actions-parity-11-integration-tests.md) first for
the evidence model, ownership boundary, security rules, and team schedule.

**Package IDs:** IT-04, IT-05, IT-06.

## Current corpus

| Fixture | Scenarios | Purpose | Current state |
| --- | --- | --- | --- |
| Chalk | branch push, opened PR | Node 22/26 matrix using public Node 24 actions | 2 candidate |
| p-limit | branch push, opened PR | Node 20 action runtime and Node 20/22/24 toolchains | 2 candidate |
| Testify | branch push, opened PR, release tag | Eleven-job Go matrix and one controlled `contents: write` release | 3 candidate |

Every scenario graduates independently. A successful push does not graduate a
pull request or tag, and isolated emulator success does not satisfy live or
differential requirements.

## Work packages

### IT-04 — Chalk canonical graduation

**Owner:** X with W, S, R, and P review. **Size:** L. **Dependencies:** IT-01,
IT-02, IT-03, IT-07, MAT-01, RUN-01, AUTH-03, PLAT-01, RES-02, CHECK-01.

**Primary scope:** make the smallest existing Node matrix the first complete
isolated and live differential gate.

Tasks:

- [ ] Run admission, isolated Automata, live GitHub, live Automata, and
  differential comparison for Chalk branch push and opened same-repository
  pull request.
- [ ] Assert selected workflow identity, both Node 22/26 matrix cells, checkout
  and setup-node action identities, step order, outcomes, conclusions, Checks,
  and cleanup.
- [ ] Prove the configured Node 24 action runtime and Node 22/26 toolchain
  behavior rather than inferring them from successful jobs.
- [ ] Require the preflight and post-run action-resolution evidence from
  `IT-03`; fail if a mutable action tag cannot be bound to the expected commit.
- [ ] Exercise duplicate delivery and repeated clean execution without changing
  locked workflow bytes.
- [ ] Keep generic outputs, annotations, summaries, masking, conditional skips,
  job dependencies, timeout, cancellation, and rerun semantics in
  feature-owned synthetic fixtures. Do not edit Chalk or claim behavior its
  upstream workflow does not exercise.
- [ ] Repeat from fresh infrastructure enough times to detect nondeterministic
  ordering or cleanup leaks.
- [ ] Promote each scenario separately and retain each pre-promotion failure.

Acceptance:

- [ ] Both Chalk scenarios are `gating` with zero unknown differences.
- [ ] Every accepted comparison points to exact isolated and live records.
- [ ] A missing per-step output or other unobservable field fails closed; the
  adapter never manufactures an empty value.

### IT-05 — Legacy Node runtime and Go-matrix corpus

**Owner:** X with R, P, and S review. **Size:** L. **Dependencies:** IT-04,
RUN-01, WF-06, MAT-01, PLAT-01, EVT-01, AUTH-03, RES-02.

**Primary scope:** qualify p-limit's Node 20 action runtime and Testify's large
Go matrix without weakening the Chalk baseline.

Tasks:

- [ ] Run p-limit push and pull-request scenarios through admission, isolated,
  live, and differential lanes.
- [ ] Assert the Node 20 action runtime and Node 20/22/24 toolchains use their
  declared versions with no fallback to Node 24.
- [ ] Run Testify push and pull-request scenarios through the same stages.
- [ ] Assert all eleven Testify jobs, matrix values, action identities,
  contexts, step order, outcomes, conclusions, Checks, and cleanup.
- [ ] Require preflight and post-run proof for every mutable action reference.
- [ ] Add negative evidence for one unavailable runtime and one missing matrix
  expansion.
- [ ] Keep job-dependency and conditional-skip parity in feature-owned
  synthetic fixtures; the unchanged Testify workflows do not exercise those
  semantics.
- [ ] Keep release-tag authority and effects out of these credential-free
  scenarios; `IT-06` owns that lane.
- [ ] Promote scenarios independently and retain each pre-promotion failure.

Acceptance:

- [ ] p-limit push/PR and Testify push/PR are `gating` with no missing workflow,
  action-runtime fallback, matrix row, or unknown difference.
- [ ] The larger corpus runs without shared runner, port, credential, database,
  or object-prefix state.

### IT-06 — Controlled Testify tag and release-effect lane

**Owner:** X with C review. **Size:** L. **Dependencies:** IT-01, IT-02, IT-03.

**Staged prerequisites:** contract and paired-mirror work may run in parallel
with `IT-05`. Acceptance requires `IT-05`, `EVT-01`, `AUTH-01`, `AUTH-02`,
`AUTH-03`, `SEC-02`, and `CHECK-01`.

**Primary scope:** qualify a permissioned tag-triggered release in paired
disposable mirrors with exact effect and cleanup assertions.

The current isolated push trigger accepts only `refs/heads/*`; it cannot drive
the existing Testify tag scenario. This package adds an explicit tag path
rather than coercing a tag into a branch event.

Tasks:

- [ ] Add exact tag creation and signed tag-push support to the live driver and
  bounded emulator route.
- [ ] Create paired disposable mirrors with byte-identical source/workflow
  trees: a baseline repository for native GitHub Actions and a candidate
  repository for Automata. Prevent native Actions in the candidate from racing
  Automata for the same release effect.
- [ ] Give each mirror a separate narrowly scoped installation/token and
  repository identity; normalize only those intentional identity differences.
- [ ] Provision short-lived authority limited to `contents: write` within its
  one disposable mirror.
- [ ] Assert a branch push selects only the main workflow while the release tag
  selects the expected main and release workflows on both targets.
- [ ] Verify one release per target, then compare normalized release identity,
  tag, body, assets, Checks, and corresponding Automata-native result.
- [ ] Attempt replay, duplicate delivery, wrong tag, changed permission,
  cancellation, and indeterminate release creation independently per target.
- [ ] Revoke each credential and delete each release, assets, tag, branch, and
  temporary installation state on success and every failure path.
- [ ] Scan retained native/canonical evidence and logs for credential canaries.

Acceptance:

- [ ] Exactly the expected two workflows run on each target and exactly one
  reviewed release effect is created per target, with no cross-target race.
- [ ] Both mirror cleanups are verified after success, failure, cancellation,
  and retry.
- [ ] The scenario cannot run from an untrusted pull request or with broader
  repository/organization authority.

---

[Previous: Harness and evidence](github-actions-parity-11a-integration-harness.md) · [Integration-test hub](github-actions-parity-11-integration-tests.md) · [Next: Platform adapters](github-actions-parity-11c-integration-platforms.md)
