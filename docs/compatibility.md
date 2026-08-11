# GitHub Actions compatibility

Automata reads standard GitHub workflow and action files, and standard
workflows do not need expressions that detect the orchestrator. An
Automata-specific `concurrency.queue` extension is under development; it is
outside GitHub compatibility and is not part of the supported product surface.

A feature is compatible only when the same repository revision has equivalent
observable behavior on GitHub Actions and Automata. Parsing a field, storing it,
or testing one component is not enough.

## Reference implementation

The current comparison baseline is
[`actions/runner` v2.336.0](https://github.com/actions/runner/releases/tag/v2.336.0)
at commit
[`98aabcd429c4e8402406c56ce2d26387fed3b9ce`](https://github.com/actions/runner/commit/98aabcd429c4e8402406c56ce2d26387fed3b9ce),
reviewed on 2026-08-07. Its JavaScript-action runtime is Node.js 24.18.0.

Automata uses the open runner's parser, schema, expression behavior, fixtures,
and protocol documentation as research material. The upstream runner is not a
dependency of either Automata binary. Changing the pin requires a reviewed
delta and a new conformance run.

One post-baseline delta has been reviewed without moving that pin:
[`GITHUB_ARTIFACTS` and `GITHUB_ARTIFACTS_LIST`](https://github.com/actions/runner/pull/4527)
at merge commit
[`35e45850b519df66a669e2c91e0917804a33d0c7`](https://github.com/actions/runner/commit/35e45850b519df66a669e2c91e0917804a33d0c7).
The runtime crate records the exact reviewed source and test files.

The initial Ubuntu execution profile contains Node.js 24.19.0. That patch-level
difference is recorded in the image manifest and remains subject to the
v2.336.0 differential tests.

## What a conformance run compares

A conformance record contains the source and event digests; expanded jobs and
matrices; dependencies and conditions; step order and results; outputs;
registered post actions; command files; annotations; masked logs; services;
artifacts and caches; cancellation and rerun behavior; and the runner capability
fingerprint.

The comparison may normalize opaque IDs, timestamps, temporary paths, signed
URLs, and credentials. It may not normalize a semantic difference. Unsupported
syntax or runtime requirements must fail before scheduling with a source span
and a machine-readable reason.

## v0.1 implementation status

No v0.1 release has been published. The table describes the source tree as of
2026-08-11. “Component complete” means the boundary has focused tests but the
repository's full workflow has not passed through the production composition.
See [Documentation style](documentation-style.md#state-capability-precisely) for
the other status labels.

| Area | Status | Implemented boundary | Remaining work |
| --- | --- | --- | --- |
| Workflow parsing and planning | Component complete | The strict subset is parsed into logical plans. Unsupported syntax produces diagnostics. | Pass the complete workflow through admission, execution, and result comparison. |
| Matrices, dependencies, conditions, and outputs | Component complete | Deterministic expansion and activation are tested. Public job outputs, summaries, and annotations cross the executor boundary; registered credential values are redacted. | Prove the behavior in the end-to-end fixture. |
| `workflow_dispatch` inputs and base context | Component complete | Typed dispatch inputs and the base runtime context have component coverage. | Compose and verify the complete external dispatch path and repository variable/secret hydration. |
| Workflow-level concurrency | Component complete for the standard source model | Group and `cancel-in-progress` parsing, admission-time evaluation, and durable coordination have component paths. | Pass the production composition. Job-level concurrency and the Automata-only `queue: max` extension remain unsupported. |
| JavaScript and local composite actions | Component complete | Bounded runtime and executor subsets have focused conformance tests. | Complete pre/main/post and marketplace compatibility. |
| Job and service containers | Experimental | Digest-pinned service configuration reaches the logical plan, JobIR, executor, and rootless Podman backend. Provider lifecycle and service boundaries have component tests. | Publish and configure the reviewed immutable service-proxy helper, then pass the full composition. |
| Scheduling and runner execution | Experimental | PostgreSQL coordination, leases, fencing, mTLS runner transport, host probes, and rootless Podman execution are composed. | Pass the normal CI workflow from admission through runner cleanup. |
| Runtime identity and result projection | Component complete | Runs receive immutable positive numeric aliases. Logs, public outputs, summaries, annotations, and finalized results have focused tests. | Complete production retention and end-to-end comparison. |
| Artifacts and Results API | Component complete | The implemented GitHub Actions Results boundary supports durable block and manifest admission, verified reads, and signed downloads. The executor also processes the separately reviewed `GITHUB_ARTIFACTS` declaration file, hashes workspace files in the sandbox, and publishes a fresh deterministic read-only `GITHUB_ARTIFACTS_LIST` snapshot to later phases. | Add the unsupported cross-run management, deletion, retention, remaining client behavior, and end-to-end conformance evidence for the environment-file delta. |
| CacheService v2 | Component complete | Eligible jobs receive runtime URLs and a JWT. Lookup checks the current ref, then the server-owned default branch read-only. Entries expire after seven inactive days; a repository has a 10 GiB LRU quota. Signed downloads support `HEAD`, full `GET`, and one byte range. | Add the management API, physical object collection, and any separately claimed BuildKit behavior. |
| GitHub provider | Experimental | Configured deployments include browser and device login, encrypted provider state, push webhook ingress, public/private source delivery, fenced Check Runs, scoped App credentials, and lease-bound repository authority. Authenticated `pull_request` and `merge_group` normalization has component tests only. | Compose the broader event path, then pass provider, runner, and service-image acceptance together. |
| Authentication, permissions, and UI | Component complete | Tenant-scoped RBAC, management APIs, browser forms, repository publication settings, SSR run pages, and Linux Secret Service-backed CLI sessions are composed. | Complete the production acceptance and operating evidence. |
| Managed secrets | Component complete for management; unsupported for jobs | PostgreSQL-backed create, replace, delete, activation, readiness, and metadata paths fail closed around key custody. | Deliver managed values to eligible runners and add external providers. Jobs do not receive managed secret values today. |
| Workload OIDC | Unsupported end to end | The issuer, storage, authority checks, and `/oidc/token` endpoint exist. | Prove external TLS and homogeneous multi-replica key operation, bound authority history, and advertise the runner capability. |
| Reusable workflows, environments, schedules, reruns, job-level concurrency, the `queue: max` extension, and complete permissions semantics | Unsupported end to end | Some fields are retained for diagnostics or active implementation. | Implement, compose, and compare their runtime semantics. |
| Arbitrary GitHub REST fallback | Unsupported | Unknown compatibility routes fail closed. | No transparent job-token proxy is planned. Add individual reviewed surfaces if required. |

Hosted runner labels map to immutable environment profiles, not generic machine
aliases. A runner advertises a configured profile only after a create, inspect,
and destroy probe succeeds through that provider. This proves that the local
provider can start the pinned image and clean it up; it is not supply-chain
attestation or hosted-image conformance.

## GitHub-owned records

GitHub does not let third parties insert arbitrary native Actions workflow-run,
job, log, or artifact records. Automata reports through fenced Check Runs, an
Actions-compatible Results service, and its own run UI. It does not pretend
that these are native GitHub Actions records.

GitHub also does not expose stored secret values. Secrets used by Automata jobs
must be configured in Automata after runner delivery is implemented. The
workload OIDC issuer uses Automata keys, so a cloud policy must trust it
explicitly; it is not GitHub's issuer.

## End-to-end acceptance gate

The acceptance fixture is this repository's normal
`.github/workflows/ci.yml`, not a reduced smoke workflow. GitHub Actions builds
generation zero from a reviewed commit. Automata must run the same workflow
bytes and repository revision to produce generation one. The results are
compared before promotion, and a generation never replaces the control plane
that is executing it.

The fixture grows as runtime features land. It covers static distribution,
artifacts, caches, matrices, reusable workflows, concurrency cancellation,
services, Podman-backed Docker behavior, and React/Vite SSR. Until it passes,
the table above is component evidence rather than a claim of workflow parity.
