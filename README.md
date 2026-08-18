# Automata

Automata runs GitHub Actions workflows on infrastructure you control. It
accepts repository events, compiles workflow YAML into an immutable execution
plan, schedules jobs, runs them in isolated sandboxes, streams logs, stores
artifacts and caches, and reports results through its web interface and GitHub
Checks.

The end-to-end workflow path works from source. Automata has not published a
release and has not completed its production-acceptance or full GitHub Actions
conformance gates. Expect interfaces and deployment requirements to change,
and check [GitHub Actions compatibility](docs/compatibility.md) before relying
on a workflow feature.

Automata runs this repository's own CI. The
[public dashboard](https://ci.automata-ci.com/automata-ci/automata/actions)
shows push and pull-request runs, jobs, runner-redacted logs, and artifacts.

## Run workflows

You need Git, [rustup](https://rustup.rs/), and a native C/C++ build toolchain.
The repository pins its Rust toolchain in `rust-toolchain.toml`. No public
package or image has been published, so build both commands from a reviewed
source checkout:

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo install --path crates/automata-ci --locked
cargo install --path crates/automata-ci-runner --locked
automata --version
automata-runner --version
```

Then bring up the complete path:

1. Configure PostgreSQL, S3-compatible object storage, the Results service,
   runner mutual TLS, and the GitHub App integration. The
   [`automata` configuration reference](crates/automata-ci/README.md) owns the
   required server options, secret references, listener boundaries, and
   startup checks. Start `automata server` only after those inputs are in
   place.
2. Prepare a Linux execution host with rootless Podman, enroll its identity,
   and start `automata-runner run --config /ABSOLUTE/PATH/runner.json` under
   the same dedicated account that owns the configuration. Follow the
   [runner bootstrap guide](crates/automata-ci-runner/config/README.md); the
   runner performs mandatory host and sandbox admission before it accepts a
   job.
3. Put Automata workflows in `.ci/workflows`, register the repository through
   the configured GitHub provider, and push or dispatch a supported event.
   Automata admits the workflow, leases its jobs to eligible runners, and
   publishes the results through its UI and GitHub Checks.

After the server starts, verify process and dependency readiness on the human
listener:

```console
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

`/readyz` reports database, object-store, and autonomous-worker readiness. The
server fails closed when a required dependency or credential is missing; it
does not fall back to a preview process.

## What works

Automata's complete path connects these components:

```text
GitHub events                 Browser and operator CLI
      |                                 |
      +------------ automata -----------+
                         |
                  PostgreSQL and S3
                         |
               fenced leases over mTLS
                         |
                 automata-runner
                         |
             configured sandbox provider
```

The mainline source includes:

- authenticated GitHub App webhooks, source delivery, scheduled and manually
  dispatched workflows, fenced Check Runs, and scoped repository credentials;
- a loss-aware GitHub Actions workflow frontend with expressions, matrices,
  dependencies, reusable-workflow foundations, JavaScript actions, composite
  actions, workflow-level concurrency, outputs, and command files;
- PostgreSQL-backed admission, scheduling, leases, reruns, runner enrollment,
  authentication, authorization, managed-secret metadata, and result state;
- S3-compatible immutable storage for workflow and action bundles, logs,
  artifacts, and CacheService v2 data;
- mutually authenticated runner sessions with fencing, certificate renewal,
  cancellation, restart recovery, secret masking, and resumable live logs;
- rootless Podman execution on Linux, plus experimental Kubernetes, local
  Docker, macOS Virtualization.framework, and Windows Hyper-V-container
  provider work at different qualification stages; and
- a React interface rendered on the server inside a resource-limited WASI
  component, with browser-side filtering and reconnecting live-log streams.

These are not all at the same release stage. In particular:

| Area | Status | Boundary |
| --- | --- | --- |
| Local host and workflow checks | Available | Read-only source-build inspection; no admission or execution |
| GitHub-to-runner workflow execution | Experimental | Runs real workflows; operating requirements and supported syntax may change |
| GitHub provider and Checks | Experimental | Authenticated ingress and result projection are composed; production acceptance remains open |
| Workflow parsing and planning | Component complete | The supported subset feeds real execution; broader GitHub Actions parity remains open |
| JavaScript and composite actions | Component complete | Exact-commit public actions and supported local composites have focused coverage |
| Artifacts and CacheService v2 | Component complete | Durable upload, verified reads, signed downloads, and current/default-branch cache lookup have focused coverage |
| Authentication and UI | Component complete | Tenant RBAC, management APIs, browser forms, repository visibility, and server-rendered run pages are composed |
| Managed secrets and workload OIDC | Experimental | Implemented behind workflow-eligibility, deployment, and runner-capability gates |
| Public packages and images | Not published | Build from a reviewed source checkout |

The [compatibility table](docs/compatibility.md) is the source of truth for
supported events, syntax, actions, services, artifacts, caches, secrets, OIDC,
and sandbox providers. Notable gaps include container actions, job containers,
deployment-environment syntax, and job-level concurrency; Automata rejects
unsupported behavior instead of silently sending work to GitHub-hosted
runners.

Connected repositories keep Automata workflows under `.ci/workflows`.
Automata does not use `.github/workflows` as an execution fallback, so a job is
never routed to GitHub-hosted runners when Automata lacks a feature.

## Commands

The workspace builds two product commands:

| Command | Purpose |
| --- | --- |
| `automata` | Run the control plane and perform local installation inspection and management, authentication, secret, environment-review, rerun, runner-management, and administration operations |
| `automata-runner` | Enroll an execution host, inspect its capabilities, and execute leased jobs through one configured sandbox provider |

### Inspect a local repository

`automata local doctor` checks the supported host tuple, Docker Engine, and
Compose plugin without creating containers or local state:

```console
automata local doctor
automata local doctor --json
```

From a Git worktree, `automata local check` analyzes an exact snapshot without
network access, a GitHub token, workflow admission, or execution:

```console
automata local check .github/workflows/ci.yml
```

The selected workflow must be a direct `.github/workflows/*.yml` or `.yaml`
file with `workflow_dispatch`. The command validates reachable local reusable
workflows and reports required credentials without exposing values. See the
[local installation boundary](crates/automata-ci-local/README.md) for the
snapshot and platform limits.

### Manage sealed local Docker custody

On x86-64 Linux, `local init` seals an immutable installation into an explicit
private state directory and twelve owner-specific Docker volumes:

```console
automata local init \
  --state-directory /var/lib/automata-local/default \
  --catalog-source file:/srv/automata-release/local-installation-catalog.json
automata local status \
  --state-directory /var/lib/automata-local/default --json
automata local reset \
  --state-directory /var/lib/automata-local/default --yes
```

Init accepts only the fixed local Docker socket and an operator-selected local
release catalog with its exact catalog-declared sibling candidate. It verifies
their canonical structure and digests, but does not independently authenticate
their release provenance. Exact replay reattests the same state and Engine
custody. Init generates no Compose document, invokes no Compose operation, and
starts no service. The epoch binds the stable local-filesystem identity of the
private state root and its held operation lock; copied, restored, or remounted
custody is rejected.

Status opens only an existing state directory under a shared, nonrepairing lock
and reports `recorded_sealed` only when canonical host custody and the exact
Engine identity, image representations, twelve volume labels, attachments, and
managed-resource union agree. It never starts a helper or inspects bytes inside
the volumes. Status and reset connect directly to the fixed Docker socket and do
not depend on the Docker CLI, current context, `DOCKER_API_VERSION`, or Compose
plugin; init and doctor retain their complete preflight. Reset never prompts and
requires `--yes`. Before mutation it requires an authority-bound canonical
epoch plus complete exact Engine custody. Once its topology-bound intent is
durable, reset reconciles deletion even if cancellation arrives, removes safe
fixed host records, and retains imported images, the state directory, and its
original operation lock. Missing or retagged retained images do not prevent
custody deletion. `automata local run`, `up`, and `down` are not present. See the
[local installation boundary](crates/automata-ci-local/README.md) for the full
custody and platform contract.

## Architecture

`automata` owns the human API, GitHub ingress, scheduler, Results gateway,
runner control plane, and web interface. PostgreSQL is the authority for
mutable state and coordination. S3-compatible storage holds immutable payloads;
it is never used as a lock or queue.

`automata-runner` accepts a job only after its configured provider passes host
admission. Each attempt carries a lease ID, an increasing fencing token, and a
negotiated capability snapshot. A delayed or restarted runner can replay an
acknowledged operation, but it cannot commit through an expired lease.

Local Docker is an explicit schema-7 runner evaluation path through the fixed
installation relay; `automata local run` is not implemented yet.

Workflow-specific behavior stops before scheduling. The GitHub frontend
produces a logical plan, activation resolves run-dependent values and bounded
matrix expansion, and the scheduler leases provider-neutral Job IR. Runners do
not parse workflow YAML or evaluate provider syntax.

Read the [architecture overview](docs/architecture.md) for the data flow,
storage model, recovery behavior, protocol boundaries, and trust domains.

## Develop Automata

Automata is a Rust 2024 workspace. The embedded React interface uses Node.js
only at build time.

```console
cargo build --workspace --locked
cargo test -p automata-ci-core --locked
```

The full repository checks include Rust formatting, Clippy, unit and
integration tests, documentation, workflow security checks, frontend tests,
and production builds. Some suites require PostgreSQL, S3-compatible storage,
Podman, platform-specific hosts, or extra build tools.

- [Development guide](docs/development.md)
- [Contributing guide](CONTRIBUTING.md)
- [Documentation index](docs/README.md)
- [Implementation and acceptance gates](docs/implementation-plan.md)
- [Security policy](SECURITY.md)

Report vulnerabilities through the private route in the security policy, not
a public issue. Other contributions and compatibility reports are welcome
under the [code of conduct](CODE_OF_CONDUCT.md).

Automata is licensed under the [MIT License](LICENSE).
