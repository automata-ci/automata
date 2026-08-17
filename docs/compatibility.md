# GitHub Actions compatibility

Automata reads standard GitHub workflow and action files, and standard
workflows do not need expressions that detect the orchestrator. Automata also
implements the explicit `concurrency.queue: max` and per-job `resources`
extensions at component boundaries. These extensions are Automata syntax, not
GitHub Actions compatibility claims.

A feature is compatible only when the same repository revision has equivalent
observable behavior on GitHub Actions and Automata. Parsing a field, storing it,
or testing one component is not enough.

The status table records product stages independently and is maintained with
the owning behavior tests and acceptance evidence. `Component complete` cannot
be inferred from decoder or compiler acceptance alone.

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
2026-08-17. “Component complete” means the boundary has focused tests but the
repository's full workflow has not passed through the production composition.
See [Documentation style](documentation-style.md#state-capability-precisely) for
the other status labels.

| Area | Status | Implemented boundary | Remaining work |
| --- | --- | --- | --- |
| Workflow parsing and planning | Component complete | The strict subset is parsed into logical plans. Bounded scalar, sequence, mapping, environment, step-list, service, and whole-job alias expansion runs before decode while retaining original source evidence and definition provenance. Duplicate names use YAML's most-recent-anchor rule and aliases without preceding definitions fail. Unsupported syntax produces diagnostics. | Pass the complete workflow through admission, execution, live differential coverage, and result comparison. |
| Expression compiler and evaluator | Component complete | The pinned-runner built-in set has phase-specific closed signatures; job-condition `success`/`failure` lazily ignore admitted nonzero arguments while step status calls remain zero-argument. Focused fixtures cover loose numeric coercion, .NET ordinal-ignore-case edges, identity, missing properties, wildcards, lazy evaluation, JSON limits, and the pinned runner's undocumented `case` built-in. Sensitive `github.token`, `secrets`, and executor values propagate opaque taint; `toJSON` rejects every sensitive subtree and diagnostics remain payload-free. | Implement production `hashFiles()` and pass the isolated live GitHub differential corpus before claiming product parity. |
| Per-job resource requests and limits | Component complete | The Automata-only `jobs.<id>.resources` extension is compiled, matrix-activated, resolved against an immutable run-pinned default/minimum/maximum policy, carried in runner requirements, checked during placement, and passed through explicit provider enforcement capabilities. Podman enforces CPU/memory; the Kubernetes runner variant additionally supports attested ephemeral storage and mapped devices. | Add the SaaS policy-management surface and production cluster acceptance evidence. Standard GitHub Actions does not accept this extension, so portable workflows must generate or maintain an Automata-specific workflow. |
| Matrices, dependencies, conditions, and outputs | Component complete | Exact candidate fixtures pass through the production compiler and GitHub expression adapter for static axes, expression axes, whole-matrix `fromJSON`, include/exclude ordering, include-only and duplicate rows, empty-axis rejection, and equivalent matrix identities/value digests. The 256-cell product boundary is enforced before activation returns, and a real-PostgreSQL fault test covers atomic maximum-size publication and exact replay. The resolved requested/effective `max-parallel` policy is typed, digest-bound, persisted once with exact relational constraints, replay-checked, and exposed through a tenant-scoped read seam. Matrix-bound names, step conditions, job environment templates, and `continue-on-error` are retained; deployment environments, job concurrency, reusable-call matrices, and unobserved nested array/object expressions remain explicitly fail closed. | Run the exact candidate bytes on live GitHub and attach immutable observations before calling the fixture differential evidence. Then enforce `max-parallel` transactionally during selection and complete fail-fast, dependency, and output-merge packages. |
| `workflow_dispatch` inputs and base context | Experimental | The authenticated CLI and hosted delegated APIs admit typed inputs against an exact repository, workflow, and canonical branch/tag ref. Core resolves that potentially mutable ref once under a durable fenced operation, pins the immutable commit and workflow source, and rejects reuse of the operation ID with any changed target. Canonical evidence and an authority-bound request digest make exact replay idempotent and changed-input replay fail closed. GitHub webhook ingress does not synthesize `workflow_dispatch`. | Add a first-party CLI command and browser form, repository variable/secret hydration, production provider acceptance, and end-to-end hosted acceptance. |
| `repository_dispatch` trigger and event context | Experimental | GitHub App webhook ingress strictly authenticates and retains the repository, installation, custom event type, bounded client payload, default-branch ref, and exact raw body used for `github.event`. Workflow `types` filters are selected exactly. Before creating a Check or admitting a run, a claimed worker resolves the configured default branch once, persists the immutable commit and resolution authority, and uses that commit on every replay. Public resolution is anonymous; private resolution uses only the manifest-pinned exact-repository `contents:read` authority. | Pass production acceptance and differential comparison. Provider changed-file synthesis is unsupported for this trigger and fails closed rather than broadening authority. |
| Push and pull-request path filters | Experimental | Ordered positive/negative path filters, branch/tag interaction, pull-request activity defaults, the push commit run-all ceiling, and complete public and private pull-request pagination have focused coverage. Same-repository and fork PRs bind exact pre/post PR snapshots and GitHub Actions' documented first 3,000 pull-request file records across at most 30 pages; a rename contributes both its previous and current path without increasing the provider-record count. Private reads acquire only the manifest-pinned `pull requests: read` selector; the `contents: read` source selector is structurally disjoint. Complete, provider-run-all, retryable-unavailable, and invalid dispositions are disjoint; selection evidence is digest-bound to the authenticated event, workflow path, workflow source, and immutable admitted plan. | New-branch and forced/diverged push diff parity, commit-message skip directives, and live GitHub differential evidence remain open. Existing-push Compare evidence retains its separate 300-record response boundary. A retry refetches PR files from page one rather than checkpointing partial pages. |
| Workflow-level concurrency | Component complete | Group and `cancel-in-progress` are evaluated from admission-safe context. Standard single-pending coordination has durable preemption, idempotent replay, and admission/claim race coverage. GitHub's ordered `queue: max` policy retains at most 100 repository-scoped, case-insensitive waiters in durable FIFO order; invalid max-plus-cancel policies fail before persistence, including after expression evaluation. Reruns re-enter the same durable policy. | Pass the production composition. Job-level concurrency remains unsupported. |
| Container actions | Unsupported | Direct `docker://` action references fail compilation with their exact source span. Container-action metadata is decoded so fetched action bundles can also fail closed before user code; no container-action execution capability is advertised. | Add a separately reviewed container-action execution contract before changing this status. |
| JavaScript and composite actions | Component complete | For exact 40-character lowercase commit references to public repositories, activation anonymously prepares action trees before Job IR publication and retains JavaScript/composite, exact Node-generation, literal-shell, repository-action, command-file, and summary requirements in runner capability requirements. Verified archives and deterministic write-once reference manifests share the installation object store; after one successful fill, activation on another replica and execution on another runner do not contact GitHub. Unix runners add a bounded local read-through tier. A repository composite's `$/...` child binds to the same exact repository revision and is prepared recursively from that immutable archive, while its `./...` child remains rooted in the workflow workspace and fails closed before scheduling. Activation-resolved top-level shells are also concretized. Every runnable job selects an immutable runtime profile with a versioned, digest-bound supported-feature ceiling; an unsupported source requirement terminates before runtime/Job IR publication, while temporary absence of an eligible runner remains `NoWork`. Mutable references, repository composite shell expressions, cycles, nested containers, unavailable runtimes, and checkout-created local action references fail closed. Local metadata can be created or replaced by preceding workflow code, so those source references terminate before Job IR publication or runner lease; the executor's bounded JIT preparation and runtime checks remain defense in depth, not advertised source support. The runner repeats exact matching and repository preflight before custody or provider work. Inputs preserve metadata order, case-insensitive overlay, empty missing values, scalar spelling, ignored `required` markers, and bounded static deprecations. Invocation-specific action/path/ref/repository context, source-ordered pre execution, occurrence-scoped state, hierarchical post registration and cleanup ordering, post-time re-evaluation, cancellation, and command files have focused coverage. | ACT-02 must bind tag/branch resolution and private repository credentials. Immutable source evidence for checkout-created local metadata is required before enabling those references. Run the live pinned-runner input differential, then complete broader marketplace and end-to-end fixtures. |
| Job containers | Unsupported | `jobs.<id>.container` is decoded but fails compilation with the exact container-value span because no production job-container execution contract exists. | Define and review the execution, isolation, capability, and recovery contract before enabling this syntax. |
| Service containers | Experimental | Digest-pinned service configuration reaches the logical plan, JobIR, executor, and rootless Podman backend. Provider lifecycle and service boundaries have component tests. | Publish and configure the reviewed immutable service-proxy helper, then pass the full composition. |
| Scheduling and runner execution | Experimental | PostgreSQL coordination, leases, fencing, mTLS runner transport, host probes, and rootless Podman execution are composed. | Pass the normal CI workflow from admission through runner cleanup. |
| Kubernetes sandbox provider | Experimental | The Rust adapter renders exact requests/limits, a hardened non-root Pod, deny-by-default network policy, generation- and UID-fenced lifecycle operations, and a framed in-sandbox exec/copy guest with bounded replay protection. The runner has a mutually exclusive Kubernetes product-config variant, ambient client construction, capability gating, and startup profile lifecycle admission. | Prove the operator assertions against a production cluster and add SaaS fleet reconciliation. Cluster provisioning is out of repository scope; network isolation must include the standard NetworkPolicy node-traffic exception. |
| Local Docker sandbox provider | Experimental | Current runner schema 6 binds the mutually exclusive `local_docker` variant to one installation UUID, digest-pinned guest and Results-proxy images, and one mandatory externally provisioned Results transport. The private provider requires Docker Engine 28/API 1.48, uses only the fixed installation relay, and rechecks exact daemon, anchor, image, shared transit, running Results target, and peer-proxy identity. Each zero-volume job gets a deterministic internal front network shared only with its fixed-port proxy; the job has no external DNS or public egress. Custody-only destruction tolerates container-runtime/image and shared-transit damage, but exact front-network drift blocks destroy and a foreign endpoint can leave the emptied front network for operator recovery. | Complete the renderer-owned shared transit/listener, desired-spec, Compose, local repository authority, credential, and `automata local run` slices. No local CLI invokes this provider, and this foundation does not inject Results/cache URLs or issue tokens. |
| Runtime identity and result projection | Component complete | Runs receive immutable positive numeric aliases. Logs, public outputs, summaries, annotations, and finalized results have focused tests. | Complete production retention and end-to-end comparison. |
| Artifacts and Results API | Component complete | The implemented GitHub Actions Results boundary supports durable block and manifest admission, verified reads, and signed downloads. The executor also processes the separately reviewed `GITHUB_ARTIFACTS` declaration file, hashes workspace files in the sandbox, and publishes a fresh deterministic read-only `GITHUB_ARTIFACTS_LIST` snapshot to later phases. | Add the unsupported cross-run management, deletion, retention, remaining client behavior, and end-to-end conformance evidence for the environment-file delta. |
| CacheService v2 | Component complete | Eligible jobs receive runtime URLs and a JWT. Lookup checks the current ref, then the server-owned default branch read-only. Entries expire after seven inactive days; a repository has a 10 GiB LRU quota. Signed downloads support `HEAD`, full `GET`, and one byte range. | Add the management API, physical object collection, and production BuildKit/cache acceptance evidence. |
| Buildx and BuildKit | Experimental | The rootless-Podman runner can opt into one locally verified, digest-pinned BuildKit runtime. Its attempt-scoped Docker proxy covers the current default `setup-buildx-action` `docker-container` lifecycle, `build-push-action` session streaming, and the bounded GitHub Actions provenance archive used with CacheService v2. The default BuildKit tag is a synthetic local alias; host sockets, custom images/driver resources, host mounts/devices, arbitrary privileged containers, and cross-attempt helper state are not exposed. Registration is withheld until exact image inspection and a no-network executable probe pass. | Run the opt-in live rootless Buildx fixture against the production image and pinned tool versions, then add separate live CacheService v2 session evidence. New Docker or Buildx request fields require explicit policy review. |
| Decoder-only GitHub provider events | Unsupported | The decoder recognizes the pinned GitHub event-name grammar, but events outside push, `pull_request`, `merge_group`, `repository_dispatch`, `workflow_dispatch`, `schedule`, and `workflow_call` fail compilation with their exact event-name span. Provider webhook ingress does not normalize them. | Add event-specific authenticated normalization, immutable evidence, selection, and acceptance before enabling each event. |
| GitHub provider | Experimental | Configured deployments include browser and device login, encrypted provider state, authenticated push, `pull_request`, `merge_group`, and `repository_dispatch` webhook ingress, durable event replay, public/private source delivery, fenced Check Runs, scoped App credentials, and lease-bound repository authority. The canonical configured default-branch ref is manifest-revisioned and digest-bound. An explicit `all_direct` policy evaluates each canonical direct workflow at one authenticated revision from a sorted, digest-bound inventory; path-local progress makes partial retry idempotent. Legacy exact-path configuration remains precise. | Add the remaining reviewed event types and pass multi-workflow provider, runner, and service-image acceptance together. |
| Authentication and UI | Component complete | Tenant-scoped RBAC, management APIs, browser forms, repository publication settings, SSR run pages, and Linux Secret Service-backed CLI sessions are composed. | Complete the production acceptance and operating evidence. |
| Permissions semantics | Partial | Workflow and job permission shorthands, precedence, policy intersection, and OIDC capability gating have component coverage. | Complete GitHub permission-default and event-specific differential coverage before claiming the full semantics. |
| Managed secrets | Experimental | PostgreSQL-backed create, replace, delete, activation, readiness, and metadata paths fail closed around key custody. The create/activate/read/delete and replacement scenarios run in the PostgreSQL CI lane. Eligible Standard jobs can receive exact pinned versions from the built-in provider over the direct mTLS ephemeral route; normal runner tests bind pre-execution acknowledgement, masking, and durable value-free overlays. | Pass full workflow eligibility and protected-environment acceptance. External and dynamically leased providers and variable-value delivery remain unsupported; the attributed component fixtures do not substitute for that product acceptance. |
| Workload OIDC | Experimental | The issuer, storage, authority checks, `/oidc/token` endpoint, runner context, and capability admission are composed. A replica advertises OIDC only after strict HTTPS configuration, exact key loading, and durable key readiness succeed. | Prove external TLS, homogeneous multi-replica key operation, bounded authority history, and cloud-provider acceptance. |
| Deployment environments | Unsupported | GitHub workflow `environment` syntax is decoded but rejected during compilation with the exact environment-name or value span. Lower-level protected-environment review contracts do not make the source feature runnable. | Compose the source feature through approval, authority, scheduling, and runner execution before enabling it. |
| Job-level concurrency | Unsupported | Job-level `concurrency` is decoded but rejected during compilation with the exact concurrency-value span. Workflow-level concurrency is tracked separately above. | Add durable per-job coordination and differential acceptance before enabling it. |
| Reusable workflows | Partial | Reusable invocations, typed inputs, output references, and the bounded same-name managed-secret forwarding chain are retained across logical planning and projection. | Complete production expansion, nested authority, provider/runner acceptance, and the remaining GitHub-compatible secret forwarding behavior. |
| Scheduled workflows | Experimental | Schedule syntax, canonical schedule evidence, durable claims, and the provider service have focused component coverage. | Pass production provider, source-authority, scheduling, runner, Check, and differential acceptance. |
| Workflow reruns | Experimental | [Authenticated workflow reruns](workflow-reruns.md) create a fresh physical attempt under the stable public run identity, reauthorize the actor, seal selected/carried graph provenance, preserve nested effective results, and create a distinct Check subject. | Pass production provider/runner acceptance and differential comparison for every rerun selection mode. |
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
