# GitHub Actions compatibility

Automata reads standard GitHub workflow and action files, and standard
workflows do not need expressions that detect the orchestrator. Automata also
implements the explicit `concurrency.queue: max` and per-job `resources`
extensions at component boundaries. These extensions are Automata syntax, not
GitHub Actions compatibility claims.

A feature is compatible only when the same repository revision has equivalent
observable behavior on GitHub Actions and Automata. Parsing a field, storing it,
or testing one component is not enough.

The status table and its attributed acceptance fixtures are validated against
the machine-readable
[GitHub Actions capability registry](governance/github-actions-capabilities.md).
Each feature records stages independently, so `Component complete` cannot be
inferred from decoder or compiler acceptance alone.

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
2026-08-12. “Component complete” means the boundary has focused tests but the
repository's full workflow has not passed through the production composition.
See [Documentation style](documentation-style.md#state-capability-precisely) for
the other status labels.

| Area | Status | Implemented boundary | Remaining work |
| --- | --- | --- | --- |
| Workflow parsing and planning | Component complete | The strict subset is parsed into logical plans. Unsupported syntax produces diagnostics. | Pass the complete workflow through admission, execution, and result comparison. |
| Per-job resource requests and limits | Component complete | The Automata-only `jobs.<id>.resources` extension is compiled, matrix-activated, resolved against an immutable run-pinned default/minimum/maximum policy, carried in runner requirements, checked during placement, and passed through explicit provider enforcement capabilities. Podman enforces CPU/memory; the Kubernetes runner variant additionally supports attested ephemeral storage and mapped devices. | Add the SaaS policy-management surface and production cluster acceptance evidence. Standard GitHub Actions does not accept this extension, so portable workflows must generate or maintain an Automata-specific workflow. |
| Matrices, dependencies, conditions, and outputs | Component complete | Deterministic expansion and activation are tested, including bounded `fromJSON(needs.*.outputs.*)` arrays/objects and fail-closed secret-derived inputs. Public job outputs, summaries, and annotations cross the executor boundary; registered credential values are redacted. | Prove the behavior in the end-to-end fixture. |
| `workflow_dispatch` inputs and base context | Experimental | The authenticated CLI control-plane API admits typed inputs against an exact repository, workflow, branch/tag ref, commit, and prior signed-GitHub source snapshot. Canonical immutable evidence and an authority-bound request digest make exact replay idempotent and changed-input replay fail closed. GitHub webhook ingress does not synthesize `workflow_dispatch`. | Add a first-party CLI command and browser form, repository variable/secret hydration, and production acceptance. The API currently requires an exact commit that already has durable signed-source evidence; it does not resolve a mutable branch or tag. |
| `repository_dispatch` trigger and event context | Experimental | GitHub App webhook ingress strictly authenticates and retains the repository, installation, custom event type, bounded client payload, default-branch ref, and exact raw body used for `github.event`. Workflow `types` filters are selected exactly. Before creating a Check or admitting a run, a claimed worker resolves the configured default branch once, persists the immutable commit and resolution authority, and uses that commit on every replay. Public resolution is anonymous; private resolution uses only the manifest-pinned exact-repository `contents:read` authority. | Pass production acceptance and differential comparison. Provider changed-file synthesis is unsupported for this trigger and fails closed rather than broadening authority. |
| Workflow-level concurrency | Component complete | Group and `cancel-in-progress` are evaluated from admission-safe context. Standard single-pending coordination has durable preemption, idempotent replay, and admission/claim race coverage. The Automata-only ordered `queue: max` extension has PostgreSQL coverage for FIFO promotion and stale-running-slot recovery. | Pass the production composition. Job-level concurrency remains unsupported; `queue: max` is not a GitHub compatibility feature. |
| JavaScript and local composite actions | Component complete | Repository action trees are prepared before user code. Repository JavaScript and nested composite actions have source-ordered pre execution, occurrence-scoped state, hierarchical post registration and cleanup ordering, post-time input/environment/timeout/continuation re-evaluation, cancellation, and command-file tests. Checked-out local composites remain JIT-prepared; local action `pre` entrypoints are intentionally skipped with a sanitized diagnostic. | Complete broader marketplace behavior and the end-to-end differential fixture. |
| Job and service containers | Experimental | Digest-pinned service configuration reaches the logical plan, JobIR, executor, and rootless Podman backend. Provider lifecycle and service boundaries have component tests. | Publish and configure the reviewed immutable service-proxy helper, then pass the full composition. |
| Scheduling and runner execution | Experimental | PostgreSQL coordination, leases, fencing, mTLS runner transport, host probes, and rootless Podman execution are composed. | Pass the normal CI workflow from admission through runner cleanup. |
| Kubernetes sandbox provider | Experimental | The Rust adapter renders exact requests/limits, a hardened non-root Pod, deny-by-default network policy, generation- and UID-fenced lifecycle operations, and a framed in-sandbox exec/copy guest with bounded replay protection. The runner has a mutually exclusive Kubernetes product-config variant, ambient client construction, capability gating, and startup profile lifecycle admission. | Prove the operator assertions against a production cluster and add SaaS fleet reconciliation. Cluster provisioning is out of repository scope; network isolation must include the standard NetworkPolicy node-traffic exception. |
| Runtime identity and result projection | Component complete | Runs receive immutable positive numeric aliases. Logs, public outputs, summaries, annotations, and finalized results have focused tests. | Complete production retention and end-to-end comparison. |
| Artifacts and Results API | Component complete | The implemented GitHub Actions Results boundary supports durable block and manifest admission, verified reads, and signed downloads. The executor also processes the separately reviewed `GITHUB_ARTIFACTS` declaration file, hashes workspace files in the sandbox, and publishes a fresh deterministic read-only `GITHUB_ARTIFACTS_LIST` snapshot to later phases. | Add the unsupported cross-run management, deletion, retention, remaining client behavior, and end-to-end conformance evidence for the environment-file delta. |
| CacheService v2 | Component complete | Eligible jobs receive runtime URLs and a JWT. Lookup checks the current ref, then the server-owned default branch read-only. Entries expire after seven inactive days; a repository has a 10 GiB LRU quota. Signed downloads support `HEAD`, full `GET`, and one byte range. | Add the management API, physical object collection, and production BuildKit/cache acceptance evidence. |
| Buildx and BuildKit | Experimental | The rootless-Podman runner can opt into one locally verified, digest-pinned BuildKit runtime. Its attempt-scoped Docker proxy covers the current default `setup-buildx-action` `docker-container` lifecycle, `build-push-action` session streaming, and the bounded GitHub Actions provenance archive used with CacheService v2. The default BuildKit tag is a synthetic local alias; host sockets, custom images/driver resources, host mounts/devices, arbitrary privileged containers, and cross-attempt helper state are not exposed. Registration is withheld until exact image inspection and a no-network executable probe pass. | Run the opt-in live rootless Buildx fixture against the production image and pinned tool versions, then add separate live CacheService v2 session evidence. New Docker or Buildx request fields require explicit policy review. |
| GitHub provider | Experimental | Configured deployments include browser and device login, encrypted provider state, authenticated push, `pull_request`, `merge_group`, and `repository_dispatch` webhook ingress, durable event replay, public/private source delivery, fenced Check Runs, scoped App credentials, and lease-bound repository authority. The canonical configured default-branch ref is manifest-revisioned and digest-bound. An explicit `all_direct` policy evaluates each canonical direct workflow at one authenticated revision from a sorted, digest-bound inventory; path-local progress makes partial retry idempotent. Legacy exact-path configuration remains precise. | Add the remaining reviewed event types and pass multi-workflow provider, runner, and service-image acceptance together. |
| Authentication, permissions, and UI | Component complete | Tenant-scoped RBAC, management APIs, browser forms, repository publication settings, SSR run pages, and Linux Secret Service-backed CLI sessions are composed. | Complete the production acceptance and operating evidence. |
| Managed secrets | Experimental | PostgreSQL-backed create, replace, delete, activation, readiness, and metadata paths fail closed around key custody. Eligible Standard jobs can receive exact pinned versions from the built-in provider over the direct mTLS ephemeral route. Durable lease offers carry only a value-free binding overlay; the runner uses bounded zeroizing custody and masks every value before acknowledgement. | Pass full workflow eligibility and protected-environment acceptance. External and dynamically leased providers and variable-value delivery remain unsupported. |
| Workload OIDC | Experimental | The issuer, storage, authority checks, `/oidc/token` endpoint, runner context, and capability admission are composed. A replica advertises OIDC only after strict HTTPS configuration, exact key loading, and durable key readiness succeed. | Prove external TLS, homogeneous multi-replica key operation, bounded authority history, and cloud-provider acceptance. |
| Reusable workflows, environments, schedules, reruns, job-level concurrency, and complete permissions semantics | Partial | [Authenticated workflow reruns](workflow-reruns.md) create a fresh physical attempt under the stable public run identity, reauthorize the current actor, seal exact selected/carried graph provenance, preserve nested effective results, and create a distinct Check subject through the existing fenced projection outbox. The bounded CLI can record an exact, revision-pinned protected-environment approval or rejection. Reusable-call values support name mapping, but Automata-managed secret authority is deliberately narrower: a referenced managed-secret name must be forwarded under the same case-insensitive name through every call hop; rename, omitted-hop, and case-collision evidence fails closed. Secret-bearing `workflow_run` and `merge_group` jobs also fail closed until their transitive source provenance is durably bound. Reusable workflows and the other listed surfaces remain incomplete. | Pass production provider/runner acceptance for reruns and protected environments, then add provenance-preserving managed-secret rename and composite-event support before widening those reusable/event boundaries. |
| Arbitrary GitHub REST fallback | Unsupported | Unknown compatibility routes fail closed. | No transparent job-token proxy is planned. Add individual reviewed surfaces if required. |

[GitHub defines](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#repository_dispatch)
`repository_dispatch`'s `GITHUB_REF` as the default branch and `GITHUB_SHA` as
the last commit on that branch, while the
[App webhook payload](https://docs.github.com/en/webhooks/webhook-events-and-payloads#repository_dispatch)
provides the branch name but no immutable commit. Automata therefore has an
unavoidable event-time/resolver-time boundary: it authenticates and stores the
webhook first, then resolves the branch under the live delivery claim. The
branch can move between those operations, so the chosen commit reflects the
resolver-time branch state, not a claimed event-time snapshot. After that one
resolution the SHA, ref, and authority evidence are immutable. This is an
Automata delivery and Check identity; it is not a native GitHub Actions
workflow-run identity.

Hosted runner labels map to immutable environment profiles, not generic machine
aliases. A runner advertises a configured profile only after a create, inspect,
and destroy probe succeeds through that provider. This proves that the local
provider can start the pinned image and clean it up; it is not supply-chain
attestation or hosted-image conformance.

## Automata per-job resources extension

Step-based jobs can declare Kubernetes-style placement requests and enforceable
limits:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    resources:
      requests:
        cpu: 500m
        memory: 512Mi
        ephemeral-storage: 1Gi
        gpu: 1
      limits:
        cpu: "2"
        memory: 2Gi
        ephemeral-storage: 4Gi
        gpu: 1
    steps:
      - run: make test
```

CPU accepts positive millicores (`500m`) or positive cores with at most three
decimal places (`1`, `1.25`). Memory and ephemeral storage accept positive
whole-byte quantities with Kubernetes binary suffixes `Ki` through `Ei`,
decimal suffixes `K` through `E`, or no suffix. Fractional storage quantities
and exponent notation are deliberately excluded from the stable dialect. GPU
values are positive whole counts; when present, request and limit must match.

Each scalar can be an activation-time expression using the same matrix and
needs-safe contexts as other job activation fields. Every run pins a repository
resource policy. A job with no `resources` block receives that policy's full
default allocation; a partial block replaces only the supplied dimensions and
uses the corresponding request or limit defaults for the rest. The resolved
allocation must remain within the pinned minimum-request and maximum-limit
bounds, every request must be less than or equal to its limit, and GPU requests
and limits must match exactly.

The runtime policy's default allocation and minimum-request/maximum-limit
bounds are part of the immutable policy bytes and semantic digest pinned to the
run, so a retry cannot observe changed SaaS settings. Requests become placement
evidence; limits are separately checked against the runner's per-job capacity
and passed to the sandbox provider for enforcement.

## GitHub-owned records

GitHub does not let third parties insert arbitrary native Actions workflow-run,
job, log, or artifact records. Automata reports through fenced Check Runs, an
Actions-compatible Results service, and its own run UI. It does not pretend
that these are native GitHub Actions records.

GitHub also does not expose stored secret values. Secrets used by eligible
Automata Standard jobs must be configured in Automata and bound to exact
built-in-provider versions; they cannot be imported from GitHub. The workload
OIDC issuer uses Automata keys, so a cloud policy must trust it explicitly; it
is not GitHub's issuer.

## Repository workflow boundary

Automata repositories keep every workflow directly under `.ci/workflows`.
The repository must not contain `.github/workflows`: GitHub supplies source,
webhooks, and Check Run APIs, but GitHub Actions is not an execution fallback.
Automata parses the GitHub Actions workflow language, schedules every job on an
Automata runner, and reports each job through an Automata-owned Check Run.

Actions and provider features that are not yet supported are compatibility
gaps. They fail closed until Automata implements the matching behavior; they
must never be routed to a GitHub-hosted runner or projected through a native
GitHub Actions bridge.

## End-to-end acceptance gate

The acceptance fixture is this repository's normal
`.ci/workflows/ci.yml`, not a reduced smoke workflow. Automata must run the
reviewed workflow bytes and repository revision directly. Differential
conformance against GitHub Actions belongs in the isolated integration suite;
the product repository never uses GitHub Actions as its CI runtime. A
generation never replaces the control plane that is executing it.

The fixture grows as runtime features land. It covers static distribution,
artifacts, caches, matrices, reusable workflows, concurrency cancellation,
services, Podman-backed Docker behavior, and React/Vite SSR. Until it passes,
the table above is component evidence rather than a claim of workflow parity.
