# GitHub Actions parity: Cross-repository integration tests

Turn the product work packages into repeatable evidence in the private
[`automata-integration-tests`](https://github.com/automata-ci/automata-integration-tests)
repository. This workstream owns test-harness machinery, corpus qualification,
and cross-repository evidence handoff. Product behavior stays in workstreams
01–10, and final compatibility acceptance stays in `GATE-01` through
`GATE-06`.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in these integration-test pages are planned
work.

**Accountable lane:** X, with P for deployment adapters and C for every
credentialed or live-provider lane.

**Package IDs:** IT-01, IT-02, IT-03, IT-04, IT-05, IT-06, IT-07, IT-08,
IT-09, IT-10, IT-11, IT-12.

## Audited starting point

This plan was prepared from these exact revisions:

- Automata
  [`4aa42c00e2651b5dd17f7a81931f57f5bb36a44a`](https://github.com/automata-ci/automata/commit/4aa42c00e2651b5dd17f7a81931f57f5bb36a44a);
- `automata-integration-tests`
  [`af7e2ca07247aea1855fe4300f218a4db33a4050`](https://github.com/automata-ci/automata-integration-tests/commit/af7e2ca07247aea1855fe4300f218a4db33a4050).

The integration repository contains a useful manual product-path E2E harness.
It can start real Automata control-plane and runner binaries with PostgreSQL,
S3-compatible storage, pre-enrollment statically provisioned mTLS runners, and
rootless Podman; send a signed webhook through real product ingress; execute
locked workflow bytes; and
require terminal GitHub-compatible Checks plus Automata-native run/job
evidence. Its default provider is a strict loopback GitHub emulator, not
GitHub.com. That harness must migrate to the enrollment API before it can gate
this clean-break control-plane contract.

| Existing evidence | Audited status |
| --- | --- |
| Immutable corpus | 3 projects, 4 workflows, and 7 scenarios; all 7 are `candidate`, none is `gating` |
| Catalog events | Branch push, opened same-repository pull request, and a Testify release-tag push |
| Executable isolated events | Branch push and opened same-repository pull request; the current driver rejects the cataloged tag scenario |
| Product E2E | Implemented as a manual `deployment local execute` path |
| GitHub oracle | Loopback protocol emulator only |
| Differential comparison | Schema and comparator exist; concrete live GitHub and complete Automata adapters do not |
| Continuous CI | Formatting, lint, types, 60 fast tests, build, and fixture audit; no real Automata E2E |
| Canonical evidence | Workflow/run/job/matrix evidence; per-step outputs and broader semantic evidence remain incomplete |

Do not convert any row in this table into a product-support claim. The suite's
checked roadmap records implementation state, not retained proof that the
manual E2E ran successfully at the audited revision.

## Read only the package group you own

Each integration package is defined exactly once in one smaller document:

| Document | Packages | Primary owner |
| --- | --- | --- |
| [Harness, evidence, and continuous operation](github-actions-parity-11a-integration-harness.md) | IT-01, IT-02, IT-03, IT-08 | X with P/C review |
| [Corpus qualification and graduation](github-actions-parity-11b-integration-corpus.md) | IT-04, IT-05, IT-06 | X plus the feature owners |
| [Platform, provider, and topology adapters](github-actions-parity-11c-integration-platforms.md) | IT-07, IT-09, IT-10, IT-11, IT-12 | P with X review |

## Ownership boundary

These rules keep the integration work from duplicating the 90 product and gate
packages already defined elsewhere:

- `FND-02` owns Automata's export contract, product-composition seams, local
  restart controls, and the general fixture/evidence contract.
- Feature owners add scenario assets and assertions for their existing package
  IDs. For example, artifact scenarios belong to `ART-01`/`ART-02`, service
  scenarios to `PROV-01`/`PROV-02`, and cancellation scenarios to
  `CAN-01`/`CAN-02`.
- `IT-01` through `IT-12` own only cross-repository intake, harness, corpus,
  live-oracle, platform-adapter, and continuous-test machinery.
- `GATE-01` through `GATE-06` decide whether evidence satisfies a compatibility
  gate. A passing emulator scenario cannot replace a required live GitHub or
  full-product gate.
- Fixture `requiredCapabilities` values describe runtime capabilities. Do not
  put planning IDs such as `ACT-01` or `IT-04` into that field. Record package
  IDs in test metadata, pull requests, and evidence manifests instead.

The feature owner writes expected behavior. Lane X owns harness code and
comparison policy. Lane C approves live-provider, secret, environment, OIDC,
or side-effect lanes. Lane P approves rootful host setup, runner isolation,
provider, and cleanup changes. The rotating integration owner makes the final
gate decision.

## Evidence model and graduation

An execution record has exactly one primary lane:

| Primary lane | Purpose | May satisfy |
| --- | --- | --- |
| Contract | Parser, schema, adapter, and comparator behavior using bounded fakes | A package's local tests only |
| Isolated Automata | Real Automata processes with the loopback provider emulator | Product composition and deterministic protocol evidence |
| Live GitHub | GitHub-hosted execution and provider-native observation | GitHub baseline evidence |
| Live Automata | Real GitHub ingress/provider authority driving Automata | Automata live-provider evidence |

A differential record references one exact GitHub record and one exact
Automata record. It is not another execution lane. Each execution may also
carry zero or more orthogonal properties such as `restart`, `fault`, `scale`,
or `side-effect`. Gate requirements name both the required lanes and required
properties, so fault evidence cannot accidentally replace a live-provider
comparison.

A scenario graduates from `candidate` to `gating` only when:

- [ ] every locked workflow in that fixture/project has an explicit scenario;
- [ ] its product package prerequisites are accepted;
- [ ] admission either selects it or returns the expected stable rejection;
- [ ] every required primary lane and property passes at exact pinned
  revisions;
- [ ] the canonical comparison has no unknown or unapproved difference;
- [ ] retry and flake attempts are retained instead of hidden;
- [ ] cleanup proves the runner, credentials, refs, side effects, storage, and
  network resources returned to the declared state;
- [ ] the evidence bundle has an owner, retention policy, and immutable ID.

`candidate`, `quarantined`, skipped, or expired evidence never counts toward a
gate. Quarantine requires an owner, issue, reason, expiry, and retained failing
attempt.

## Cross-repository evidence record

Every retained run binds all inputs needed to reproduce and audit it:

- integration-suite commit and dirty-state assertion;
- Automata commit plus control-plane and runner executable SHA-256 values;
- source repository, source commit graph, event bytes, and event digest;
- complete workflow inventory and workflow byte digests;
- action references, preflight resolutions, target-observed commits, and
  archive digests;
- fixture, deployment, evidence, JobIR, protocol, and runner-requirements
  schema versions;
- execution-profile manifest digest, image digest, helper-image digests, and
  toolchain versions;
- runner/provider/platform topology, resource policy, and network mode;
- GitHub installation/repository identities without retained credentials;
- native target records, canonical records, comparison result, retry history,
  cleanup result, and approved-divergence IDs.

Never identify acceptance with a mutable branch such as `main`, a mutable image
tag, a zero digest, or an unversioned local binary.

## Feature-package test ownership

The feature owner delivers these companion assets; the IT packages supply
shared machinery and the GATE package owns final acceptance.

| Product packages | Companion scenario assets | Final gate |
| --- | --- | --- |
| WF-01–WF-06, MAT-01–MAT-03, SCH-01–SCH-02, DEP-01, REU-01–REU-04 | YAML/expression/matrix/dependency/reusable positive and negative fixtures | GATE-01, GATE-04, GATE-06 |
| RUN-01–RUN-03, ACT-01–ACT-02, LOG-01–LOG-04, CAN-01–CAN-02 | Shell/action/command/log/mask/cancellation/restart fixtures | GATE-01, GATE-02, GATE-05, GATE-06 |
| PROV-01–PROV-03, CTR-01–CTR-03, DKR-01–DKR-02, BLD-01, DCK-01 | Service/container/Docker/BuildKit/Kubernetes workflows and cleanup probes | GATE-01, GATE-05, GATE-06 |
| EVT-01–EVT-08, AUTH-01–AUTH-03, CFG-01–CFG-03, ENV-01–ENV-02, OIDC-01–OIDC-02, SEC-01–SEC-02 | Signed events, trust matrix, credential canaries, approvals, OIDC and replay probes | GATE-03, GATE-04, GATE-05 |
| RES-01–RES-02, CHECK-01, ART-01–ART-03, CACHE-01–CACHE-03, UI-01 | Exact clients, result/Check assertions, artifact/cache contents and management evidence | GATE-01, GATE-02, GATE-03, GATE-06 |
| WIN-01–WIN-03, PLAT-01–PLAT-04, FLT-01–FLT-04, OPS-01, LIM-01 | Platform/topology/resource/overload/upgrade fixtures | GATE-02, GATE-05, GATE-06 |

Do not create duplicate IT packages for each row. Add the scenario and its
assertions to the owning feature PR, then use the shared adapter and graduation
machinery defined in this workstream.

## Parallel delivery for four to six developers

### Six developers

| Wave | W | S | R | P | C | X/integration owner |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | Review IT-02 registry mapping | Review admission graph evidence | Review runner evidence contract | IT-01 profile/topology intake | Review live-lane security contract | IT-01 descriptor + IT-02 ledger |
| 1 | Add workflow fixtures | Add matrix/dependency fixtures | Add shell/action fixtures | Prepare disposable Linux adapter | IT-03 App/mirror authority | IT-03 target/report skeleton |
| 2 | Chalk expression assertions | Chalk matrix/job assertions | Chalk step/action assertions | Finish IT-07 Linux adapter and isolated Chalk execution | Review redaction/cleanup | Finish live adapters and prepare IT-04 |
| 3 | Reusable fixtures | p-limit/Testify graph evidence | Node 20/action evidence | Start IT-09/IT-10 contracts | Live Chalk + IT-06 contract | IT-03 live path, graduate IT-04, then IT-05 |
| 4–5 | Feature-owned scenarios | Feature-owned scenarios | Cancellation/action scenarios | IT-09 through IT-12 as product prerequisites land | IT-06 acceptance and credential gates | IT-08 and GATE evidence integration |

With five developers, combine W and S as in the parent plan. Keep X focused on
IT-01 through IT-04; the combined W/S owner supplies admission and graph
expectations without editing the test orchestrator concurrently.

With four developers, use the parent plan's combined P+X owner and serialize
the external critical path:

```text
IT-01 -> IT-07 ----+-> IT-04 -> IT-05/IT-06 -> IT-08
   |                |
   +-> IT-02 -> IT-03
   |
   +-> IT-09/IT-10/IT-11/IT-12 when their product prerequisites land
```

Developer 1 owns workflow/scheduler expectations, Developer 2 runner/action
expectations, Developer 3 credentials/live-provider review, and Developer 4
harness/provider integration. Defer IT-09 through IT-12 and full IT-08
operations until `GATE-01` is stable unless an independent gate needs their
contract earlier.

## Cross-repository pull-request handoff

Use this sequence for every feature that requires integration evidence:

1. [ ] Merge the Automata contract/composition change with its local tests and
   stable package ID.
2. [ ] Open a companion `automata-integration-tests` pull request citing the
   same product package and IT package, pinned to the merged Automata commit.
3. [ ] Run admission and credential-free isolated acceptance first.
4. [ ] Run live differential or side-effect evidence only from a protected
   trusted trigger when the package requires it.
5. [ ] Retain the immutable evidence bundle, native records, canonical diff,
   attempts, and cleanup result.
6. [ ] Update compatibility claims only in the final Automata acceptance PR,
   linking both merged commits and the retained evidence ID.

## Security and CI rules

- [ ] Keep normal pull-request workflows secret-free.
- [ ] Never use `pull_request_target` or a privileged `workflow_run` to execute
  untrusted pull-request code or artifacts.
- [ ] Run third-party workflows only on disposable dedicated workers with no
  developer home, SSH agent, cloud metadata, production socket, or production
  credential.
- [ ] Scope live GitHub authority to disposable fixture repositories and the
  minimum API permissions.
- [ ] Keep release/side-effect credentials out of default and differential
  read-only lanes.
- [ ] Use fresh per-run identities, ports, database namespace, object prefix,
  certificates, and work roots.
- [ ] Verify cleanup; process exit alone is not cleanup evidence.
- [ ] Treat fixture commits and action pins as reproducibility controls, not a
  substitute for review of untrusted code.
- [ ] Keep GitHub-emulator evidence labeled as emulator evidence. It cannot
  prove GitHub.com networking, App installation, credentials, or API behavior.

## Definition of done

- [ ] Contract and schema tests pass in secret-free ordinary CI.
- [ ] All external inputs are immutable and recorded.
- [ ] Missing prerequisites produce a failing or explicit non-passing result.
- [ ] Time, retries, output, evidence, and retained artifacts are bounded.
- [ ] Every failure path attempts cleanup and records uncertain cleanup.
- [ ] Native and canonical evidence validate before comparison.
- [ ] Unknown fields or differences fail closed.
- [ ] Credentials and canary values are absent from commands, reports, logs,
  artifacts, and diagnostics.
- [ ] A companion product package and final gate are named.
- [ ] Documentation links and repository-local verification pass in both
  repositories.

---

[Previous: Operations, limits, runner fleet, and acceptance gates](github-actions-parity-10-operations-gates.md) · [Harness packages](github-actions-parity-11a-integration-harness.md) · [Parent execution plan](../github-actions-parity-execution-plan.md)
