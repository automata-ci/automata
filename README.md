# Automata

[![License: MIT](https://img.shields.io/badge/license-MIT-2f6f68.svg)](LICENSE)

Automata is a self-hosted control plane and runner for GitHub Actions-compatible
workflows. It accepts authenticated GitHub events, plans work from
`.ci/workflows/`, schedules fenced job attempts, and executes them through an
isolated runner provider on infrastructure you control.

Public CI runs and runner-redacted logs for this repository are available on
the [Automata CI dashboard](https://ci.automata-ci.com/automata-ci/automata/actions).

> [!WARNING]
> Automata is pre-1.0 software for development and evaluation. No public
> release has been published, and the complete production composition has not
> passed its end-to-end compatibility gate. Build from a reviewed source
> checkout; do not use the documented crate or container names as if artifacts
> had been published.

## Implementation status

Automata reads GitHub Actions workflow and action syntax, but parsing a feature
does not make it compatible. The status below describes the strongest evidence
in this repository; the [compatibility contract](docs/compatibility.md) owns the
detailed feature matrix and acceptance criteria.

| Product area | Status | Implemented boundary |
| --- | --- | --- |
| Workflow parsing and planning | Component complete | Strict YAML diagnostics, expressions, matrices, dependencies, conditions, outputs, workflow concurrency, reusable-workflow foundations, and per-job resource requests compile into immutable logical plans and JobIR. |
| GitHub integration | Experimental | Signed `push`, `pull_request`, `merge_group`, and `repository_dispatch` ingress; public and private source delivery; scheduled-workflow foundations; scoped GitHub App credentials; and fenced Check Runs are composed. |
| Scheduling and runner control | Experimental | PostgreSQL-backed orchestration, leases, fencing, cancellation, log replay, restart recovery, one-use runner enrollment, and direct HTTP/2 over mutual TLS are composed. |
| Actions, artifacts, and cache | Component complete | JavaScript and nested composite action execution, exact-commit public action resolution with verified shared and runner-local caches, job summaries, annotations, the Results artifact protocol used by `actions/upload-artifact` v7.0.1, and CacheService v2 used by `actions/cache` 5.0.5 have focused coverage. |
| Authentication and UI | Component complete | GitHub browser and device login, tenant RBAC, CLI sessions, repository visibility, management APIs, and server-rendered repository, run, job, and administration pages are composed. |
| Secrets and workload identity | Experimental | Versioned managed-secret custody and delivery, protected-environment review contracts, and GitHub-compatible workload OIDC are implemented behind eligibility and capability gates. |
| Operations | Component complete | Dependency-aware health and readiness, bounded Prometheus/OpenMetrics schemas, PostgreSQL migrations, immutable S3-compatible storage, optional private shard-management gRPC, workspace provisioning, and entitlement application have boundary or PostgreSQL coverage. |

The primary Linux execution path creates rootless Podman sandboxes without
giving jobs the host Podman socket or control-plane credentials. The workspace
also contains an experimental Kubernetes provider, disposable
Virtualization.framework macOS VMs, and Hyper-V-isolated Windows containers.
Those platform paths still require the acceptance evidence described in their
operator guides. The Windows path admits only `run:` steps and is not approved
for hostile or production workloads.

Notable unsupported workflow features include container actions, job
containers, job-level concurrency, and deployment-environment syntax. Service
containers, workflow reruns, scheduled workflows, reusable workflows, managed
secrets, OIDC, and Buildx/BuildKit have narrower experimental or component-only
boundaries. Check [Compatibility](docs/compatibility.md) before evaluating a
workflow.

## Check a local host and workflow

Automata includes a read-only preflight for the planned disposable local
installation. It checks the supported host tuple, Docker Engine, Docker Compose
2.20.0 or newer without creating host state or any containers:

```console
cargo run --locked -p automata-ci -- local doctor
cargo run --locked -p automata-ci -- local doctor --json
```

From a Git worktree, the source-only check seals tracked and non-ignored live
bytes once, selects an explicit local `workflow_dispatch`, compiles reachable
same-snapshot reusable workflows, validates their typed call contracts and call
graph, propagates mapped or inherited root secret requirements, and reports
static secret and variable names without admitting or running anything:

```console
cargo run --locked -p automata-ci -- local check
cargo run --locked -p automata-ci -- local check .github/workflows/ci.yml \
  --input target=staging --json
```

Omit the canonical repository-relative workflow path only when the repository
contains exactly one direct workflow. Input values are used only in the
bounded in-process compiler and are excluded from reports and debug output.

`automata local run` and `automata local up` are planned and are not present in
the command. The durable development assembly remains the supported way to
exercise the complete control plane from a source checkout.

## How it works

```text
 GitHub webhooks and source                 Browser / operator CLI
              |                                      |
              +-------------- automata --------------+
                              |   |   |
                       PostgreSQL | S3-compatible storage
                                  |
                  fenced JobIR leases over direct mTLS
                                  |
                         automata-runner
                                  |
                    configured sandbox provider
                    /            |             \
          rootless Podman   Kubernetes Pod   macOS VM / Windows
```

`automata` owns event admission, workflow planning, durable orchestration,
Results and management APIs, GitHub publication, and the web interface.
`automata-runner` proves its live capabilities, accepts fenced leases, executes
steps through one configured sandbox provider, streams redacted logs, and
reconciles interrupted work.

PostgreSQL coordinates mutable state. S3-compatible storage holds immutable
workflow and action bundles, log segments, artifacts, cache objects, and final
manifests. The React interface renders on the server inside a resource-limited
WASI component; Node.js is a build dependency, not a server dependency.

Read [Architecture](docs/architecture.md) for the workflow, storage, protocol,
and trust boundaries.

## Documentation

| Goal | Guide |
| --- | --- |
| Build from source and inspect the interface | [Getting started](docs/getting-started.md) |
| Check support for a workflow feature | [Compatibility](docs/compatibility.md) |
| Configure the control-plane command | [`automata` configuration](crates/automata-ci/README.md) |
| Enroll and configure an execution host | [Runner bootstrap](crates/automata-ci-runner/config/README.md) |
| Configure login, authorization, secrets, and repository visibility | [Authentication and authorization](docs/authentication.md) |
| Monitor the control plane and runners | [Prometheus and OpenMetrics](docs/observability.md) |
| Rerun a completed workflow | [Workflow reruns](docs/workflow-reruns.md) |
| Understand the system design | [Architecture](docs/architecture.md) |
| Build, test, or change the code | [Development](docs/development.md) |
| Find every document | [Documentation index](docs/README.md) |

Platform-specific guides document the current implementation contracts for
[macOS VMs](docs/platforms/macos.md) and
[Windows Hyper-V containers](docs/platforms/windows.md).

## Contributing

Bug reports, compatibility fixtures, design feedback, and focused code changes
are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing the code
and [SECURITY.md](SECURITY.md) to report a vulnerability privately. Larger
changes should start with the open gates in the
[implementation plan](docs/implementation-plan.md).

## License

[MIT](LICENSE) © 2026 Alexander Dzhoganov.
