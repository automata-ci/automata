# GitHub Actions parity parallel execution plan

This document converts the dated
[GitHub Actions parity backlog](github-actions-parity-backlog.md) into work
packages for a team of four to six developers. It is based on Automata
`upstream/main` at commit
[`1885c2a`](https://github.com/automata-ci/automata/commit/1885c2a2c8b3bc49334272c1a782ca115dd5f999)
and the refreshed audit completed on 2026-08-13.

The [compatibility page](compatibility.md) remains the source of truth for
current support. The [implementation plan](implementation-plan.md) owns release
gates. This page is an execution aid: unchecked tasks are planned work, not
availability claims.

The refreshed greenfield baseline uses runner protocol v1, message schema v1,
JobIR schema v1, runner-requirements schema v1, and one canonical
`0001_initial_schema.sql`. It has no supported database or mixed-version
upgrade source. It also contains a real Kubernetes product-composition path,
three independent
single-slot Linux runner processes, durable workflow reruns and protected
environment lease authority, and immutable multi-workflow fanout. These are
component or experimental foundations unless their package records product
acceptance. Hosted Windows CI is currently disabled, so the Windows gate is an
independent restoration task rather than a prerequisite for the repository's
current Ubuntu-only CI workflow.

The runtime preserves exact sandbox cleanup custody when an uncertain create
failure returns a recovery handle. Missing-custody state remains fenced rather
than being guessed, reconstructed, or enumerated. Recovery drains the runner
until provider-owned evidence proves absence or cleanup and only then recreates
empty local state; journal deletion alone is not reconciliation.

The companion
[`automata-integration-tests`](https://github.com/automata-ci/automata-integration-tests)
repository now has a dedicated
[cross-repository integration-test workstream](github-actions-parity/github-actions-parity-11-integration-tests.md).
At its audited `af7e2ca` revision it provides a manual real-product isolated
harness, but all seven scenarios remain candidates, live GitHub differential
execution is absent, and ordinary suite CI does not launch Automata. The IT
packages turn that harness into retained acceptance evidence without moving
product behavior out of the existing feature packages or gates.

## How to use this plan

Each work package is intended to become an issue or epic owned by one
developer. Large and extra-large packages must be split into contract, storage,
adapter, composition, and acceptance pull requests rather than one long-lived
branch.

Sizes describe merge and coordination scope rather than elapsed time:

| Size | Expected shape |
| --- | --- |
| S | One focused pull request with local tests. |
| M | Two or three pull requests, normally contract then integration. |
| L | Three to five pull requests, including product acceptance. |
| XL | A program epic with an interface-first sequence and multiple owners reviewing boundaries. |

Every issue created from this plan should contain:

- [ ] work-package ID and title;
- [ ] one accountable owner and named reviewers;
- [ ] prerequisite package IDs;
- [ ] scope and explicit non-goals;
- [ ] files or contracts the branch owns;
- [ ] contract, storage, adapter, composition, and acceptance pull requests;
- [ ] failure, cancellation, restart, and replay cases;
- [ ] exact commands and environments used for validation;
- [ ] the compatibility status that may change after acceptance;
- [ ] links to resulting tests and operational evidence.

## Team topology

Use stable ownership lanes. Moving developers between lanes every pull request
creates conflicts in the compiler, scheduler, executor, and store contracts.

| Lane | Six-person owner | Primary ownership |
| --- | --- | --- |
| W — Workflow language | Developer 1 | YAML, workflow decoder/compiler, expressions, context availability, reusable source compilation |
| S — Durable scheduling | Developer 2 | activation, matrices, concurrency, reusable coordinators, workflow-service store contracts |
| R — Runner/executor | Developer 3 | GitHub executor state machine, actions, shells, commands, cancellation, runtime contexts |
| P — Providers/platforms | Developer 4 | Podman, Windows, containers, services, images, later macOS and architectures |
| C — Control/security | Developer 5 | events, permissions, credentials, variables, environments, OIDC, security policy |
| X — Results/conformance | Developer 6 | Results, artifacts, cache, Checks, UI integration, the external integration harness, conformance, and product gates |

### Five developers

Combine lanes W and S under one owner. That developer serializes changes to
the workflow compiler, logical projection, activation, and scheduling store.
Keep R, P, C, and X separate.

### Four developers

Use these assignments:

| Developer | Combined lane |
| --- | --- |
| 1 | Workflow language and durable scheduling |
| 2 | Runner and executor |
| 3 | Control plane, credentials, and security |
| 4 | Providers, platforms, Results, and conformance |

With four developers, defer dynamic fleet management, macOS, additional
architectures, artifact attestations, and lower-priority event families until
the P0 security path and unchanged Linux workflow gate are green. Do not run
all work packages at once.

## Shared ownership locks

These files and contracts are merge hotspots. Assign one owner at a time.

- `crates/automata-ci-workflow-github/src/compiler/logical.rs`: lane W.
- `crates/automata-ci-workflow-service/src/logical_projection.rs`: lane S,
  except for an interface PR explicitly handed to another lane.
- `crates/automata-ci-workflow-service/src/orchestration.rs`: lane S while
  scheduling work is active; lane C supplies reviewed contracts instead of
  editing it concurrently.
- `crates/automata-ci-job-executor-github/src/executor.rs`: lane R until the
  executor seam extraction lands.
- `crates/automata-ci-sandbox-podman/src/provider.rs`: lane P.
- `crates/automata-ci-sandbox-windows/**` and the Windows Hyper-V-container
  broker/platform integration: lane P, with a security reviewer for every
  privileged boundary.
- `crates/automata-ci-runner/src/product/context.rs`: lane R. Lanes C and P
  provide input contracts and fixtures.
- `crates/automata-ci-results-github/**`: lane X.
- central GitHub event model and trigger compiler files: lane C until the
  event registry split lands.
- GitHub Check store and publisher: lane X.
- UI shared models and renderer contract: lane X.
- runner routing, enrollment, and lifecycle files: lane P after the
  unchanged workflow gate.
- root `Cargo.toml`, `Cargo.lock`, compatibility docs, and shared CI workflow:
  the wave's integration owner.
- cross-repository fixture schemas, adapters, comparator policy, graduation
  ledger, and protected live-test workflows in `automata-integration-tests`:
  lane X; feature lanes contribute expected behavior through companion pull
  requests instead of editing the harness concurrently.

Additional coordination rules:

- [x] Check the machine-readable foundation governance registry before changing
  a registered format, limit, migration, or shared surface.
- [x] Keep the unreleased greenfield store as one canonical
  `0001_initial_schema.sql`; fold schema changes into that baseline and its
  inventory test, and do not create or reserve `0002` while the registry's
  bootstrap mode remains active.
- [ ] Introduce ordered upgrade migrations only after a released schema creates
  durable state that the project commits to preserve. Before supporting those
  upgrades, change the governance mode and define reservation, immutability,
  forward-reader, rollback, and live-skew rules in one reviewed contract.
- [ ] Merge provider-neutral core, JobIR, protocol, or protobuf changes before
  provider implementations begin.
- [ ] Give serialized-format changes one owner for the version bump,
  compatibility reader, fixtures, and migration.
- [ ] Do not put scheduler coordination policy into runner JobIR.
- [ ] Do not let two branches independently change operation-ID material.
- [ ] Rebase provider branches after shared execution contracts merge.
- [ ] Update compatibility status only in the final product-acceptance pull
  request.

## Dependency overview

```text
Foundation registry + conformance fixtures
        |
        +--> workflow semantics --> matrices/reusable workflows
        |                              |
        |                              +--> scheduler controls
        |
        +--> executor seams --> streaming/logs --> cancellation/actions
        |                         |                  |
        |                         |                  +--> Windows actions
        |                         +--> providers ----+--> containers
        |
        +--> event registry --> trust --> tokens/secrets/environments/OIDC
        |
        +--> result contract --> Checks/UI/artifacts/cache
                                      |
                                      +--> unchanged Linux workflow gate
                                               |
                                               +--> broader events/platforms/fleet
```

## Wave staffing

### Wave 0: establish parallel seams

Six developers can start these packages concurrently with little file overlap:

| Developer | First package |
| --- | --- |
| W | `FND-01` capability registry and early rejection |
| S | `SCH-01` workflow-concurrency parity correction |
| R | `FND-03` executor seam extraction |
| P | `PROV-01` existing service-container production proof |
| C | `AUTH-01` permission catalog and effective defaults |
| X | `FND-02` conformance fixture and exact-client catalog |

The rotating integration owner lands the `FND-04` bootstrap before Wave 1
branches change the canonical schema, reserve format versions, or add limits.
The package remains open until its full format/limit catalog and compatibility
reader policy land. Migration-number reservation begins only after an explicit
governance-mode transition enables durable upgrades.

Exit criteria:

- [ ] every accepted feature has a downstream classification;
- [ ] the executor hotspot is split into owned modules;
- [ ] permission defaults are represented exactly;
- [ ] existing services have a real product fixture;
- [ ] the differential fixture can drive a complete push workflow;
- [ ] concurrency documentation and limits reflect current GitHub syntax.

### Wave 1: close P0 correctness and security gaps

Run in parallel:

- W: `WF-01`, `WF-02`, and `WF-03` as separate pull requests.
- S: `MAT-01`, followed by the contract portion of `MAT-02`.
- R: `RUN-01`, `RUN-02`, and `RUN-03` where file ownership permits.
- P: land the component-foundation portions of `WIN-ISO-00`, `WIN-ISO-02`,
  `WIN-ISO-04`, `WIN-ISO-05`, and `WIN-ISO-06` without advertising
  Windows support. Complete `WIN-ISO-01` only after C lands `EVT-01` and
  `AUTH-02`, then continue `PLAT-01`. Windows toolchain capability work
  waits for the offline Hyper-V-container gate.
- C: `EVT-01`, `AUTH-02`, `AUTH-03`, and then `EVT-02` as a
  contract-first sequence.
- X: `RES-01` and `CHECK-01` contract work.

Exit criteria:

- [ ] fork and Dependabot authority is reduced correctly;
- [ ] pull-request path filters are runnable;
- [ ] reserved runner environment names cannot be overwritten;
- [ ] matrix and expression behavior has differential fixtures;
- [ ] official artifact/cache clients run against real product adapters;
- [ ] unsupported jobs fail before a lease.

### Wave 2: durable runtime interfaces

- W: `WF-04` and `WF-05`, then support the reusable-workflow fixture.
- S: `MAT-02`, `MAT-03`, the contract portion of `DEP-01`, `SCH-02`, and then
  local reusable workflow proof `REU-01` under one store owner.
- R: `LOG-01`, `LOG-02`, and `CAN-01`.
- P: `WIN-ISO-02`, `WIN-ISO-03`, and `WIN-ISO-04` on separate owned paths,
  followed by `WIN-ISO-05` and `WIN-ISO-06`. Defer `CTR-01`/`CTR-02` unless
  additional provider capacity exists.
- C: `CFG-01`, `CFG-02`, `CFG-03`, and `EVT-03`; defer `EVT-04` until
  `ENV-01` is complete.
- X: `ART-01`, `CACHE-01`, and the storage side of `RES-02`.

Exit criteria:

- [ ] max-parallel and fail-fast survive restart;
- [ ] job concurrency has a durable contract;
- [ ] output can be processed while a command runs;
- [ ] variable and secret custody is exact and value-safe;
- [ ] job-container and Windows action interfaces are frozen;
- [ ] same-run artifact/cache behavior passes exact clients.

### Wave 3: mainstream workflow parity

- W/S: finish `DEP-01`, then `REU-02`, `REU-03`, and `REU-04`.
- W/R/C: complete `WF-06` after `WF-04`, `AUTH-02`, and `CFG-02` merge.
- R: `LOG-03`, `LOG-04`, `CAN-02`, `ACT-01`, and `ACT-02`; land `ACT-01`
  before the provider lane begins `WIN-02`.
- P with C/X support: start `WIN-ISO-07`/`WIN-ISO-09` and `WIN-01` on
  separate paths after the offline Hyper-V-container gate; land
  `WIN-ISO-08` after the network/data boundary is ready, then `WIN-02` and
  the `WIN-ISO-10` integration gate.
  Continue `PROV-02`, `CTR-03`, and `DKR-01` only where ownership and staffing
  do not delay the isolation critical path.
- C: `ENV-01`, then `EVT-04`; continue with `ENV-02`, `OIDC-01`, and
  `EVT-05`.
- X: `ART-02`, Linux client acceptance in `CACHE-02`, `CHECK-01`, and
  `UI-01`; run `CACHE-03` after `WIN-02`.

Exit criteria:

- [ ] local and remote reusable workflows have immutable provenance;
- [ ] job containers execute, and Windows JavaScript/composite actions execute
  inside the fresh Hyper-V-isolated container boundary;
- [ ] cancellation runs eligible cleanup and posts;
- [ ] protected environments release values only after approval;
- [ ] detailed per-job Results and Checks exist;
- [ ] the unchanged Linux workflow is ready to enter `GATE-01`.

### Wave 4: broader product surface

- [ ] Run `GATE-01` and fix failures by owning lane.
- [ ] Build `IT-09` and begin `WIN-ISO-11`; do not close the security package
  in this wave. Integration wave 5 must run the full hostile/fault matrix,
  close `WIN-ISO-11`, then complete `WIN-03` → `GATE-02` → `WIN-ISO-12`.
- [ ] Implement `DKR-02`, `BLD-01`, and `DCK-01`.
- [ ] Run `GATE-06` after `GATE-01` and `DCK-01`; execute the independent
  hosted-Windows restoration gate `GATE-02` when its Windows dependencies are
  ready.
- [ ] Complete `PROV-03` production-cluster acceptance for the already
  composed Kubernetes provider before fleet packaging work.
- [ ] Complete lower-priority event families `EVT-06`, `EVT-07`, and
  `EVT-08`.
- [ ] Complete `OIDC-02`, `ART-03`, and management UI.
- [ ] Complete `SEC-01` and `SEC-02` before the credential gate.
- [ ] Complete `LIM-01`, then finish `OPS-01` against its overload contract.
- [ ] Start dynamic fleet packages only after the execution path is stable.

### Wave 5: platform, fleet, and scale breadth

- [ ] `FLT-01` through `FLT-04`.
- [ ] `PLAT-02` through `PLAT-04`; `PLAT-01` completed before `GATE-01`.
- [ ] `GATE-03` security/credential gate.
- [ ] `GATE-04` broader-event gate.
- [ ] `GATE-05` chaos and multi-replica gate.

### Integration-test companion waves

These run beside the product waves. They do not replace package-local tests or
permit a product feature to advertise support early.

| Product wave | External integration-test work |
| --- | --- |
| 0 | `IT-01` release-bundle intake and `IT-02` admission/graduation contracts |
| 1 | Exercise admission over the locked corpus; build the `IT-03` mirror, authority, target, and report skeleton |
| 2 | Complete canonical Automata observation, finish the `IT-07` Linux adapter, and prepare isolated `IT-04` Chalk evidence |
| 3 | Finish live `IT-03`; graduate `IT-04`; begin `IT-05`; start other adapter contracts |
| 4 | Complete `IT-05`/`IT-06`, feed `GATE-01`/`GATE-06`, and build `IT-09` against the shipped Windows Hyper-V-container trust, lifecycle, and guest path; run ready `IT-10` Kubernetes adapters |
| 5 | Run and graduate the full `IT-09` hostile, crash-transition, network, and cleanup matrix; close `WIN-ISO-11`, then `WIN-03` → `GATE-02` → `WIN-ISO-12`; run `IT-08` continuously and add `IT-11` macOS and `IT-12` fault topology when prerequisites land |

### Reduced-team serialization

The dependency graph does not change with fewer developers. Combined owners
must serialize hotspot work in this order instead of attempting the six-lane
schedule concurrently.

| Wave | Five developers: combined W+S owner | Four developers: combined P+X owner |
| --- | --- | --- |
| 0 | `FND-01` → `SCH-01` | `FND-02` → `PROV-01` |
| 1 | `WF-01` → `WF-02`; `WF-03` → `MAT-01` → `MAT-02` contract | `RES-01` → `WIN-ISO-00` and component provider foundation; after C completes `EVT-01` → `AUTH-02`, finish `WIN-ISO-01` → `PLAT-01` |
| 2 | `WF-04`/`WF-05` → `MAT-02` → `MAT-03` → `DEP-01` contract → `SCH-02` → `REU-01` | `RES-02` → `WIN-ISO-02`/`WIN-ISO-03`/`WIN-ISO-04` → `WIN-ISO-05` → `WIN-ISO-06` |
| 3 | finish `DEP-01` → `REU-02` → `REU-03` → `REU-04`; review `WF-06` between store changes | `WIN-ISO-07` → `WIN-ISO-08`/`WIN-ISO-09` → `WIN-01` → `WIN-02` → `WIN-ISO-10` |
| 4 | close `GATE-01` failures before broader syntax or scheduling work | build `IT-09`, then in integration wave 5 run it and serialize `WIN-ISO-11` → `WIN-03` → `GATE-02` → `WIN-ISO-12`; defer other fleet/platform breadth |

For four developers, Developer 3 owns C packages and serializes authority work
as `EVT-01` → `AUTH-02` → `AUTH-03` → `CFG-01` → `CFG-02` → `ENV-01`
→ `OIDC-01`. Delegate UI-only parts of `CFG-03` and `EVT-04` to the
combined P+X owner only after their backend contracts merge.

## Common definition of done

Every package must satisfy the applicable items:

- [ ] domain and unit tests;
- [ ] adversarial tests for paths, archives, input size, credentials, and
  untrusted event data;
- [ ] PostgreSQL contract and migration-upgrade tests where state changes;
- [ ] retry, replay, cancellation, and restart tests;
- [ ] multi-replica tests for durable scheduling or mutation races;
- [ ] provider integration tests where external state is involved;
- [ ] one product-composition test through real adapters;
- [ ] stable source-spanned diagnostics or reason codes;
- [ ] bounded logs, output, metadata, archives, and collections;
- [ ] no secrets or raw provider payloads in durable errors or debug output;
- [ ] exact pinned upstream action, client, image, or runner version;
- [ ] no ordinary test that downloads mutable network content;
- [ ] a companion `automata-integration-tests` scenario and immutable evidence
  handoff when the package requires product, provider, differential, platform,
  or fault acceptance;
- [ ] explicit evidence classification so emulator, isolated, live-provider,
  differential, and fault results cannot substitute for one another;
- [ ] package tests and strict Clippy for affected targets;
- [ ] documentation links and structure verification;
- [ ] capability advertisement only after product acceptance.

## Workstream documents

Open only the workstream owned by your lane, plus the documents that its
dependencies reference. Each package appears exactly once; package IDs remain
stable across files so issues and pull requests can link to them.

| Order | Workstream | Packages |
| --- | --- | --- |
| 1 | [Foundations, conformance, and governance](github-actions-parity/github-actions-parity-01-foundations.md) | FND-01, FND-02, FND-03, FND-04 |
| 2 | [Workflow language, expressions, and runtime contexts](github-actions-parity/github-actions-parity-02-workflow-language.md) | WF-01, WF-02, WF-03, WF-04, WF-05, WF-06 |
| 3 | [Matrices, scheduling, dependencies, and reusable workflows](github-actions-parity/github-actions-parity-03-scheduling-reuse.md) | MAT-01, MAT-02, MAT-03, DEP-01, SCH-01, SCH-02, REU-01, REU-02, REU-03, REU-04 |
| 4 | [Runner execution, actions, logs, and cancellation](github-actions-parity/github-actions-parity-04-runner-execution.md) | RUN-01, RUN-02, RUN-03, ACT-01, ACT-02, LOG-01, LOG-02, LOG-03, LOG-04, CAN-01, CAN-02 |
| 5 | [Services, job containers, Docker, Podman, Kubernetes, and BuildKit](github-actions-parity/github-actions-parity-05-containers-docker.md) | PROV-01, PROV-02, PROV-03, CTR-01, CTR-02, CTR-03, DKR-01, DKR-02, BLD-01, DCK-01 |
| 6 | [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity/github-actions-parity-06-trust-security.md) | EVT-01, AUTH-01, AUTH-02, AUTH-03, CFG-01, CFG-02, CFG-03, ENV-01, ENV-02, OIDC-01, OIDC-02, SEC-01, SEC-02 |
| 7 | [Triggers, dispatch, schedules, and event families](github-actions-parity/github-actions-parity-07-events.md) | EVT-02, EVT-03, EVT-04, EVT-05, EVT-06, EVT-07, EVT-08 |
| 8 | [Results, Checks, artifacts, cache, and product UI](github-actions-parity/github-actions-parity-08-results.md) | RES-01, RES-02, CHECK-01, ART-01, ART-02, ART-03, CACHE-01, CACHE-02, UI-01 |
| 9 | [Windows, Linux and macOS profiles, architectures, and cross-OS cache](github-actions-parity/github-actions-parity-09-platforms.md) | WIN-ISO-00 through WIN-ISO-12, WIN-01, WIN-02, WIN-03, PLAT-01, PLAT-02, PLAT-03, PLAT-04, CACHE-03 |
| 10 | [Operations, limits, runner fleet, and acceptance gates](github-actions-parity/github-actions-parity-10-operations-gates.md) | OPS-01, FLT-01, FLT-02, FLT-03, FLT-04, LIM-01, GATE-01, GATE-02, GATE-03, GATE-04, GATE-05, GATE-06 |
| 11 | [Cross-repository integration tests](github-actions-parity/github-actions-parity-11-integration-tests.md) | IT-01, IT-02, IT-03, IT-04, IT-05, IT-06, IT-07, IT-08, IT-09, IT-10, IT-11, IT-12 |

Recommended reading order is this hub, foundations, the assigned lane
document, the integration-test workstream for companion evidence, and then the
operations and gates document. Implementation order is still determined by the
package dependency graph.

## Package lookup

Use the workstream table above as the package index. Search for a package ID
within its linked document; do not duplicate a package into another page.

## Delivery guidance

The explicit product decisions, pull-request protocol, handoff checklist, and
initial issue-creation checklist live with the acceptance gates:

- [Operations, limits, runner fleet, and acceptance gates](github-actions-parity/github-actions-parity-10-operations-gates.md)
- [Cross-repository integration tests](github-actions-parity/github-actions-parity-11-integration-tests.md)
