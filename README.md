# Automata

[![CI](https://github.com/automata-ci/automata/actions/workflows/ci.yml/badge.svg)](https://github.com/automata-ci/automata/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-2f6f68.svg)](LICENSE)

Automata is a self-hosted control plane and runner for GitHub Actions
workflows. It reads standard workflow files and is being built to schedule and
run them on infrastructure you control.

> [!WARNING]
> Automata is early software. No public release has been published, and the
> full end-to-end compatibility gate has not passed. Use a reviewed source
> checkout for development and evaluation.

## Try the interface

You need [Git](https://git-scm.com/) and [rustup](https://rustup.rs/). The
repository selects the required Rust toolchain.

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo run --locked --bin automata -- preview
```

Open <http://127.0.0.1:8080>, or check the process from another terminal:

```console
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Preview mode needs no database or object store. It serves the web interface and
health endpoints, but it does not schedule or run workflows.

The [hosted UI demo](https://automata-ci.github.io/automata/) shows the same
interface with sample data. It is a static demonstration and cannot execute
workflows or connect to your repositories.

See [Getting started](docs/getting-started.md) to install both commands from
source. Use [Control-plane setup](docs/deployment.md) when you are ready to run
the durable local composition.

## Current status

The repository contains the control plane, PostgreSQL schema, S3-compatible
storage boundary, GitHub integration, Results and cache services,
server-rendered web interface, mTLS runner transport, and a rootless Podman
execution path for Linux.

These components have unit and boundary coverage, but the repository's normal
CI workflow has not yet passed through the complete production composition.
Automata therefore does not claim general GitHub Actions compatibility. The
[compatibility contract](docs/compatibility.md) records the supported subsets
and the remaining acceptance gates.

No public archive, crates.io package, or product container image is available.
Their names and release process are documented so the publication pipeline can
be reviewed before the first release; a documented name is not evidence that
an artifact exists.

## How it works

```text
GitHub events                                  Browser / CLI
     |                                               |
     +------------------- automata ------------------+
                              |       |
                        PostgreSQL   object storage
                              |
                         fenced lease
                              |
                       automata-runner
                              |
                    isolated job environment
```

`automata` ingests and plans workflows, schedules jobs, serves the Results and
management APIs, and renders the web interface. `automata-runner` accepts
fenced leases, validates the execution host, runs jobs through a configured
sandbox provider, streams logs, and reconciles interrupted work.

Jobs do not receive the host Podman socket or control-plane credentials. Read
the [architecture overview](docs/architecture.md) for the trust and storage
boundaries.

## Documentation

| Goal | Guide |
| --- | --- |
| Build from source and run the preview | [Getting started](docs/getting-started.md) |
| Check whether a workflow feature is supported | [Compatibility](docs/compatibility.md) |
| Configure login, permissions, and repository visibility | [Authentication and authorization](docs/authentication.md) |
| Start the durable control plane | [Control-plane setup](docs/deployment.md) |
| Configure a Linux execution host | [Runner bootstrap](crates/automata-ci-runner/config/README.md) |
| Understand the system design | [Architecture](docs/architecture.md) |
| Build, test, or change the code | [Development](docs/development.md) |
| Find every document | [Documentation index](docs/README.md) |

## Contributing

Bug reports, design feedback, compatibility fixtures, and focused code changes
are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[implementation plan](docs/implementation-plan.md) before starting a larger
change. See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

[MIT](LICENSE) © 2026 Alexander Dzhoganov.
