# Automata

Automata is a self-hosted CI system that runs GitHub Actions workflows on your
own infrastructure. Its working Linux path receives GitHub events, compiles
workflow YAML into immutable execution plans, schedules jobs, runs them in
rootless Podman sandboxes, and publishes results to GitHub Checks and the
Automata web interface.

[Get started](docs/getting-started.md) ·
[Compatibility](docs/compatibility.md) ·
[Deploy](crates/automata-ci/README.md) ·
[Configure runners](crates/automata-ci-runner/config/README.md) ·
[Documentation](docs/README.md)

Automata runs this repository's CI. The
[current Automata dashboard run](https://ci.automata-ci.com/automata-ci/automata/actions/runs/99ab4504-ef90-8aa1-ad24-34d1811b1c00)
is the run interface; its repository, log, and artifact visibility follows the
installation's publication policy. The public
[Checks for main commit `280cd4f9`](https://github.com/automata-ci/automata/commit/280cd4f9e685ac022c65a920ba24f4f019b0fd25/checks)
record the aggregate Automata result and its Rust, PostgreSQL, and frontend
jobs.

## What Automata does

```text
GitHub event                    Browser and operator CLI
     │                                    │
     └────────────── automata ────────────┘
                            │
                     PostgreSQL and S3
                            │
                  fenced leases over mTLS
                            │
                    automata-runner
                            │
                   isolated job sandbox
```

- Uses a documented subset of GitHub Actions workflow syntax and rejects
  unsupported behavior before scheduling.
- Keeps mutable coordination in PostgreSQL and immutable workflow, action, log,
  artifact, and cache data in S3-compatible storage.
- Runs jobs through capability-aware, fenced leases. A delayed runner cannot
  commit through an expired lease.
- Authenticates runners with mutual TLS and keeps runner, provider, human, and
  workload credentials in separate trust domains.
- Records structured execution output with checkpointed replay and renders
  repository, workflow, run, and job views without a Node.js production server.
- Provides authenticated CLI operations for login, secrets, protected
  environments, reruns, runner enrollment, and control-plane status.

Automata workflow files live in `.ci/workflows`. Automata does not fall back to
`.github/workflows` or send unsupported jobs to GitHub-hosted runners.

## Product status

The project is working software, but not every implemented component has the
same operational evidence.

| Status | Scope |
| --- | --- |
| Available | GitHub `push` and `pull_request` ingress; workflow admission; expressions and workflow concurrency used by this repository; per-job CPU and memory limits; exact-commit `actions/checkout`; `run:` steps; rootless Podman execution; service containers; fenced GitHub Checks; and server-rendered run and job pages. The [successful Checks on main commit `280cd4f9`](https://github.com/automata-ci/automata/commit/280cd4f9e685ac022c65a920ba24f4f019b0fd25/checks) exercise this path with Rust, PostgreSQL, and frontend jobs. |
| Available locally | `automata local doctor`, `automata local check`, and the Linux-only sealed `local init`, read-only `local status`, and confirmed `local reset` custody commands. These commands inspect or prepare state; they do not run a local workflow. |
| Work in progress | Broader dispatch and schedule paths, reusable workflows, artifact/cache client coverage, managed-secret delivery, workload OIDC, reruns, Buildx, Kubernetes, local Docker execution, and macOS VM execution have implemented boundaries with narrower evidence or missing deployment gates. |
| Planned or unavailable | Public versioned distribution, standalone GitHub-provider onboarding, `automata local run`/`up`, production Windows runner deployment, container actions, job containers, deployment-environment syntax, and job-level concurrency. |

The [compatibility reference](docs/compatibility.md) owns the detailed status,
limits, and evidence for each feature. A parser, schema, or component test does
not make a feature available through the complete product.

## Try it from source

Install Automata from a reviewed source checkout. You need Git,
[rustup](https://rustup.rs/), and a native C/C++ toolchain.

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo install --path crates/automata-ci --locked
cargo install --path crates/automata-ci-runner --locked
automata --version
automata-runner --version
```

The [getting-started guide](docs/getting-started.md) continues with read-only
host and workflow checks. The web interface is part of the complete
`automata server` process and requires its production dependencies.

## Write a workflow

Connected repositories use the same job-and-step model as GitHub Actions. Save
this as `.ci/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    resources:
      limits:
        cpu: "2"
        memory: 4Gi
    steps:
      - name: Check out source
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false

      - name: Run tests
        run: cargo test --locked
```

`resources` is an Automata extension. Pin remote actions to full commit SHAs;
Automata resolves them into verified, content-addressed bundles. Check the
[compatibility reference](docs/compatibility.md) before moving an existing
workflow, because unsupported syntax fails closed.

## Deploy the complete system

A working installation has three external boundaries:

1. The `automata` control plane, configured with PostgreSQL, S3-compatible
   object storage, Results signing, runner TLS, and a GitHub App.
2. One or more `automata-runner` processes, each enrolled once and configured
   with one sandbox provider.
3. A connected GitHub repository with workflows under `.ci/workflows`.

The repository does not yet ship a standalone provider-onboarding command or a
turnkey deployment bundle. The complete running path uses the private,
mutually-authenticated shard-management API to install GitHub App and repository
desired state. Do not write those records directly in PostgreSQL. This means a
source checkout is useful for evaluation and controlled integration work, but
first-user self-host onboarding is not complete.

Start with the [`automata` deployment and configuration
reference](crates/automata-ci/README.md), then follow the [runner bootstrap
guide](crates/automata-ci-runner/config/README.md). The runner guide also
explains why a normal dynamically linked Cargo build is not a valid Linux
production probe payload. After the server starts, these endpoints distinguish
a running process from a ready installation:

```console
curl --fail https://ci.example.com/healthz
curl --fail https://ci.example.com/readyz
```

`/readyz` checks the database, object store, and autonomous workers. The server
exits or reports not-ready when a required dependency or credential is missing;
it does not start a partial composition.

## Execution providers

Rootless Podman on x86-64 Linux is the primary deployment path. The same runner
also contains provider boundaries for Kubernetes Pods, fixed-relay local
Docker, macOS Virtualization.framework VMs, and Hyper-V-isolated Windows
containers. Those providers have different host, image, networking, and
qualification requirements; do not infer support from a compiled module alone.

Use the [compatibility reference](docs/compatibility.md) for the supported
workflow and provider matrix, and the platform guides for
[macOS](docs/platforms/macos.md) and [Windows](docs/platforms/windows.md).

## Documentation

| If you want to… | Read |
| --- | --- |
| Evaluate Automata from a checkout | [Getting started](docs/getting-started.md) |
| Check whether a workflow feature is supported | [GitHub Actions compatibility](docs/compatibility.md) |
| Install and configure the control plane | [`automata` reference](crates/automata-ci/README.md) |
| Enroll and run an execution host | [Runner bootstrap](crates/automata-ci-runner/config/README.md) |
| Understand components and trust boundaries | [Architecture](docs/architecture.md) |
| Operate authentication, secrets, and access | [Authentication and authorization](docs/authentication.md) |
| Scrape metrics and diagnose failures | [Observability](docs/observability.md) |
| Build or contribute to Automata | [Development](docs/development.md) and [Contributing](CONTRIBUTING.md) |

The [documentation index](docs/README.md) separates user guides, operator
references, design explanations, and maintainer plans.

## Contributing and security

Focused bug fixes, compatibility fixtures, tests, documentation, and design
feedback are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
pull request.

Report vulnerabilities through the private route in [SECURITY.md](SECURITY.md),
not a public issue. Automata is available under the [MIT License](LICENSE).
