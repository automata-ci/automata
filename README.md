# Automata

[![CI](https://github.com/automata-ci/automata/actions/workflows/ci.yml/badge.svg)](https://github.com/automata-ci/automata/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-2f6f68.svg)](LICENSE)

Own the control plane behind your GitHub Actions workflows.

Automata is a self-hostable execution platform being built to run existing
`.github/workflows` files on infrastructure you control. It combines workflow
planning, scheduling, results, a web interface, and an isolated runner in two
Rust executables: `automata` and `automata-runner`. Future release archives will
contain statically linked Linux builds; ordinary Cargo/source builds may be
dynamically linked.

> [!WARNING]
> Automata 0.1 is bootstrap software. It is not production-ready, and the full
> end-to-end compatibility gate has not passed.
> No public release has been published yet, and the hosted UI preview is not
> deployed. Use only a reviewed source checkout for evaluation and development.

## Quick start

### Run from source

You need [Git](https://git-scm.com/) and [rustup](https://rustup.rs/). The
repository selects its Rust toolchain automatically.

```console
git clone https://github.com/automata-ci/automata.git
cd automata
cargo run --locked --bin automata -- preview
```

Open <http://127.0.0.1:8080>, or verify it from another terminal:

```console
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Preview mode is dependency-free. It renders the embedded web interface and
health endpoints, but does not start PostgreSQL, scheduling, runner control, or
workflow execution. Continue with the [getting-started guide](docs/getting-started.md)
for the complete source-build path and future release-channel policy, or the
[control-plane setup](docs/deployment.md) for the durable local composition.

### Future release channels

After the first public version appears under
[GitHub Releases](https://github.com/automata-ci/automata/releases), its exact
tag will carry the checksum-verifying Linux installer and static archive. The
planned matching distribution names are the crates.io packages `automata-ci`
and `automata-ci-runner` and the GHCR repositories
`ghcr.io/automata-ci/automata` and `ghcr.io/automata-ci/automata-runner`.
Do not guess a version or use any of those channels until the same exact version
is visibly published by its registry.

## Why Automata?

- **Keep your workflows.** Compatibility mode is designed for standard GitHub
  workflow and action files, without Automata-specific YAML.
- **Control where jobs run.** Route work by labels, runner groups, typed
  capabilities, resources, and isolation requirements.
- **Scale the control plane.** PostgreSQL owns durable coordination and
  S3-compatible storage owns immutable workflow, log, result, and artifact data.
- **Fail safely.** Leases, fencing tokens, crash journals, and idempotent cleanup
  are part of the correctness model rather than optional deployment tuning.
- **Keep jobs contained.** A job never receives the host Podman socket or
  control-plane credentials.

Automata is more than a replacement self-hosted runner. A normal self-hosted
runner still relies on GitHub's Actions control plane; Automata is building both
the control plane and the runner.

## What works today?

| Area | Bootstrap status |
| --- | --- |
| GitHub workflow parsing and planning | The repository CI bytes are mirrored and parser-tested. Its PostgreSQL service declaration reaches parsing, selection, logical lowering, projection, executor translation, and the rootless Podman runtime. The end-to-end gate remains open until a reviewed immutable service-proxy image is published and configured and the complete production composition passes. |
| Durable control plane | PostgreSQL migrations, workflow admission, scheduling records, leases, fencing, maintenance, result projection, run finalization, and S3-compatible immutable blobs are implemented. A mandatory autonomous worker discovers admitted logical work and supervises exact preparation, activation, and materialization into runnable jobs. End-to-end execution still requires the configured runner and provider boundaries described below. |
| Runner | mTLS transport, configured fail-closed network and process admission, exact provider lifecycle admission for every configured environment profile, lease handling, encrypted spool/journal foundations, and the rootless Podman path are implemented and under integration. |
| Results and artifacts | The GitHub Actions Results-compatible boundary, durable block/manifest admission, verified reads, and signed downloads are implemented. Production retention and object garbage collection remain open. |
| Web UI and CLI | The tenant-scoped SSR dashboard loads runs, summaries, verified logs, finalized artifacts, repository publication and secret settings, and authenticated user, role, permission, and direct-binding management from durable storage. GitHub browser login and session middleware are composed when authentication is configured. On Linux, `automata auth login`, `auth status`, and `auth logout` use the OS Secret Service for one server-scoped CLI session. |
| Access control and publication | Explicit tenant/resource-scoped RBAC, the authenticated management JSON API, and its bounded browser management forms are composed. Dashboard metadata, logs, and artifacts have independent private, authenticated, or public repository settings; public access is read-only. A run snapshots those settings at admission, while readable-secret logs and artifacts are always narrowed to private and raw user output is suppressed. |
| Secrets | The provider-neutral SPI requires an encrypted-at-rest boundary. Authenticated repository pages and HTTP routes expose value-free metadata plus capability-gated create, replace, delete, and built-in PostgreSQL provider activation. Fenced stale-intent recovery, cryptographic erasure, authenticated key-custody readiness, bounded cleanup metrics, and a Linux operator CLI for create/list/delete and provider status/activation are composed. Missing or wrong required key material fails startup, readiness, and every write boundary. CLI replacement, runner delivery, and external providers remain unsupported, so jobs do not receive managed secret values. |
| GitHub integration | GitHub is the current human provider. Browser and device login, envelope-encrypted login/provider state, hashed audience-specific session credentials, fresh numeric membership authority, and RBAC browser/API management are composed. When the exact provider registry is configured, the product also composes signed webhook ingress, public/private source delivery, fenced Check Runs publication, scoped GitHub App service credentials, and exact lease-bound repository authority for materialized Standard jobs; CredentialFree jobs receive none. Admission-to-materialization is supervised, while end-to-end workflow compatibility remains gated by the configured runner, provider, and service-image path. |
| Distribution | No public archive, package, or product image has been published. CI gates the future release workflow, which verifies crates.io packages, deterministic static Linux archives, checksums, SBOMs, license notices, GHCR images, and attestations before a GitHub Release becomes public. |

Unsupported behavior is rejected explicitly. Automata does not silently ignore
workflow options and call the result compatible. See the
[compatibility contract](docs/compatibility.md) for the exact standard.

## How it fits together

```text
Configured GitHub events                           Browser / CLI
              |                                         |
              +--------------- automata ----------------+
                              |       |
                        PostgreSQL   S3-compatible storage
                              |
                         fenced lease
                              |
                       automata-runner
                              |
                    isolated job environment
```

`automata` contains workflow ingestion, planning, scheduling, Results APIs,
fleet control, the server-rendered interface, and administration commands.
`automata-runner` validates configured host/network capability evidence, accepts
fenced leases, executes jobs through a sandbox provider, streams logs, and
reconciles interrupted work.

The planned crates.io package names are `automata-ci` and `automata-ci-runner`;
their installed command names will deliberately match the product roles above. Read the
[architecture overview](docs/architecture.md) for the component and trust
boundaries.

## Documentation

| I want to… | Start here |
| --- | --- |
| Build Automata from source and run the preview | [Getting started](docs/getting-started.md) |
| Understand what is and is not supported | [Compatibility](docs/compatibility.md) |
| Configure login, RBAC, and repository visibility | [Authentication and authorization](docs/authentication.md) |
| Run the bootstrap control plane | [Control-plane setup](docs/deployment.md) |
| Configure a local Linux runner | [Runner bootstrap](crates/automata-ci-runner/config/README.md) |
| Understand the system design | [Architecture](docs/architecture.md) |
| Work on the codebase | [Development guide](docs/development.md) |
| Publish a release | [Release guide](docs/releasing.md) |
| Review release history | [Changelog](CHANGELOG.md) |
| Report a vulnerability privately | [Security policy](SECURITY.md) |
| Find every document | [Documentation index](docs/README.md) |

## Contributing

Automata is currently shaped around its first end-to-end compatibility
milestone. Bug reports, design feedback, compatibility fixtures, and focused
code changes are welcome.
Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the
[implementation plan](docs/implementation-plan.md). Participation is governed
by the [code of conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © 2026 Alexander Dzhoganov.
