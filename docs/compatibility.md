# GitHub Actions compatibility contract

Automata compatibility mode accepts standard GitHub workflow and action files.
It does not add YAML keywords or require expressions that branch on the
orchestrator. A repository is compatible only when the same immutable source
revision runs with equivalent observable semantics on GitHub Actions and
Automata.

## Reference and evidence

Each release records the upstream `actions/runner` revision against which it was
developed. The open runner's parser, schema, expression behavior, fixtures, and
protocol documentation are treated as a reference implementation. Automata
ports behavior into safe Rust and keeps provenance for imported MIT fixtures.

The initial G1 baseline, reviewed on 2026-08-07, is
[`actions/runner` v2.336.0](https://github.com/actions/runner/releases/tag/v2.336.0)
at commit
[`98aabcd429c4e8402406c56ce2d26387fed3b9ce`](https://github.com/actions/runner/commit/98aabcd429c4e8402406c56ce2d26387fed3b9ce).
Its bundled JavaScript-action runtime is Node.js 24.18.0. This pin is a
semantic research and differential-test baseline, not a dependency in either
Automata binary. Advancing it requires a reviewed compatibility-delta record
and rerunning the conformance suite; a floating upstream branch is never used
as evidence.

The initial immutable Ubuntu profile carries Node.js 24.19.0. That reviewed
patch-level delta is shared with the renderer build toolchain and is recorded in
the profile manifest; JavaScript-action conformance remains measured against
the v2.336.0/Node.js 24.18.0 reference above.

The v2.336.0 delta also makes background-step control, the
`GITHUB_ARTIFACTS` file command, `$self` repository-action references, and the
effective cache-mode environment part of the tracked compatibility surface.
They are not claimed by G1 until their differential fixtures pass.

A conformance run records:

- source workflow/action digests and event payload digest;
- expanded jobs, matrices, dependencies, conditions, and concurrency groups;
- step order, outcome, conclusion, outputs, and registered post actions;
- command files, annotations, masked logs, services, and dynamic ports;
- attempt, rerun, cancellation, timeout, and artifact/cache behavior; and
- environment and negotiated runner capability fingerprints.

Differential comparison may normalize only inherently volatile data such as
opaque IDs, timestamps, temporary paths, signed URLs, and credentials. Any
semantic difference is a compatibility failure. Unsupported syntax or runtime
requirements fail before scheduling with a source span and machine-readable
reason; Automata never silently ignores an option.

## Compatibility surface

The required surface includes triggers and filters, reusable workflows,
expressions and coercions, matrices, DAGs, defaults, permissions, environments,
secrets, outputs, status functions, implicit success guards, concurrency,
reruns, file commands, shell selection, JavaScript/composite/container actions,
pre/main/post lifecycle, job and service containers, labels, runner groups,
artifacts, cache APIs, results APIs, OIDC, and the relevant GitHub REST surface.

Hosted labels map to immutable, fingerprinted environment profiles. They are
not generic aliases. The acceptance rule is that a provider may advertise a
profile only after its image and behavior probes pass the corresponding
conformance suite. Current runner startup exercises an exact
create/inspect/destroy lifecycle for every configured profile before it builds
the advertised inventory, including profile/generation/running evidence and
mandatory cleanup. That gate proves the configured provider can launch the
digest-pinned image through its declared policy path; it is not supply-chain
attestation or the complete hosted-image conformance suite.

## v0.1 implementation status

Automata 0.1 is a bootstrap release, not a claim of end-to-end GitHub Actions
parity. The statuses below describe the composed product, not merely a parser,
model, or adapter that exists elsewhere in the workspace. Capability-gated or
unsupported behavior fails closed; it is never silently ignored.

| Area | v0.1 status | Current boundary |
| --- | --- | --- |
| Workflow YAML, expressions, and planning | Partial | The implemented strict subset is parsed and compiled into current logical plans; unsupported syntax and semantics produce diagnostics. |
| Matrices, needs, conditions, and outputs | Partial | Current models and deterministic activation components exist, but the complete durable orchestration path is still being integrated. |
| JavaScript and local composite actions | Partial | Bounded runtime and executor components have focused conformance coverage; full pre/main/post and marketplace compatibility is not claimed. |
| Job containers and service containers | Partial | Digest-pinned service configuration reaches the current logical plan, JobIR, execution boundary, and Podman backend. An exact immutable service-proxy pin adds the service-container feature only to the durable registration ceiling. The live runner strips it and restores it only after provider verification; scheduling intersects registered and observed capabilities, so an unverified feature is never eligible. The checked-in bootstrap configuration intentionally omits the unpublished helper image, so the repository CI has not passed this path end to end. |
| Scheduling and runner execution | Partial | Durable leases, fencing, runner transport, and configured fail-closed rootless-Podman network admission are composed. The complete workflow-to-runner acceptance path has not passed end to end. |
| Logs, Results, and artifacts | Partial | Durable storage, the implemented Results facade, verified reads, and the SSR UI exist. For artifacts and logs, cross-run REST APIs, deletion, retention policy, byte-range reads, and full client compatibility remain unsupported. |
| GitHub provider integration | Partial | GitHub browser login and device-flow HTTP endpoints, envelope-encrypted login/provider state, hashed session credentials, fresh numeric membership authority, and the RBAC management HTTP API are composed. On Linux with an available Secret Service, `automata auth login`, `auth status`, and `auth logout` are operational. Exact provider configuration additionally composes signed webhook ingress, public/private source delivery, fenced Check Runs, scoped App service credentials, and exact lease-bound repository authority for materialized Standard jobs. A mandatory autonomous worker supervises asynchronous logical preparation, activation, and materialization after admission; end-to-end runner, provider, and service-image acceptance remains open. |
| CacheService v2 | Partial | The product composes the current-reference CacheService-v2 upload/download path and gives eligible jobs its runtime JWT and URLs. Cache entries have seven-day inactivity retention, and signed downloads support `HEAD`, full `GET`, and one byte range. Base/default-branch fallback, the REST management surface, BuildKit compatibility, and physical object garbage collection remain unsupported. |
| Workload OIDC | Unsupported end to end | The product composes the issuer, durable storage, fail-closed optional control issuer, and `/oidc/token` on the non-human Results listener. Migration 0037 completes signed ingress with immutable positive numeric-owner evidence, and migration 0039 revalidates its receipt and current authority at reservation and every mint. The supported runner and static-registration inventories intentionally leave OIDC unadvertised pending external TLS and homogeneous multi-replica/key-fleet readiness, so entitled jobs remain ineligible. Unbounded authority and issuance-slot ledgers also prevent production retention claims until a safe bounded archive or erasure path exists. |
| Reusable workflows, permissions, environments, schedules, reruns, and generalized concurrency | Unsupported end to end | Some source fields may be modeled for loss-aware diagnostics, but the product does not claim their runtime semantics. |
| Arbitrary GitHub REST fallback proxy | Unsupported | Unknown or unavailable compatibility routes fail closed; Automata does not forward them with a job-scoped GitHub token. |

The repository's own CI workflow is the target end-to-end acceptance fixture.
Until that gate passes through the production composition, users should treat
the entries above as component-level coverage rather than workflow parity.

## GitHub-owned boundary

GitHub's public APIs do not allow a third party to insert arbitrary native
Actions workflow-run, job, log, or artifact records. The long-term reporting
boundary therefore uses GitHub Check Runs, an Actions-compatible Results facade,
and Automata's own SSR run UI. In v0.1, the optional exact provider runtime can
create fenced Check Runs for its configured delivery identities, but the product
still does not insert native Actions records or proxy arbitrary GitHub API
requests with a job-scoped token.

Secrets must be configured in Automata because GitHub does not expose their
values. GitHub-compatible workload OIDC is product-composed, including the
token endpoint on the non-human Results listener, but remains disabled end to
end until the runner and registration paths advertise the capability after the
remaining operational proofs. Its issuer uses Automata signing keys, so cloud
trust policies must trust it explicitly rather than treating it as GitHub's
issuer.

## End-to-end acceptance gate

The first end-to-end workflow is Automata's normal
`.github/workflows/ci.yml`, not a special smoke workflow. Generation zero is
built by GitHub Actions from a reviewed commit. It runs the exact same workflow
bytes and repository SHA through Automata to produce generation one. Results
are compared before a canary promotion; a workflow can never replace the
control plane currently executing it.

New runtime features enter that workflow as they land: static distribution,
artifacts, caches, matrices, reusable workflows, concurrency cancellation,
services, Podman-backed Docker compatibility, and React/Vite SSR. GitHub remains
the differential oracle until the full suite is stable, and continues to run
periodically afterward to detect upstream semantic drift.
