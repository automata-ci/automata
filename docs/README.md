# Automata documentation

Start with the shortest guide for your goal. Automata is in bootstrap
development, and the setup guides distinguish working behavior from planned or
unsupported capabilities.

## Start here

| Goal | Guide |
| --- | --- |
| Install Automata and preview the web interface | [Getting started](getting-started.md) |
| Start PostgreSQL, RustFS, and the bootstrap server | [Control-plane setup](deployment.md) |
| Configure a Linux execution host | [Runner bootstrap](../crates/automata-ci-runner/config/README.md) |
| Build, test, or change Automata | [Development](development.md) |
| Contribute a change | [Contributing](../CONTRIBUTING.md) |
| Report a vulnerability privately | [Security policy](../SECURITY.md) |
| Review release history | [Changelog](../CHANGELOG.md) |
| Publish crates, images, and a GitHub Release | [Releasing](releasing.md) |

## Product and design

- [Architecture](architecture.md) — components, data flow, correctness, and
  isolation boundaries.
- [Compatibility contract](compatibility.md) — what “GitHub Actions compatible”
  means and how claims are verified.
- [Authentication and authorization](authentication.md) — current implementation
  status and the intended trust-domain separation.
- [Implementation plan](implementation-plan.md) — ordered milestones and their
  acceptance gates.

## Operations and internals

- [Prometheus and OpenMetrics](observability.md) — scrape topology, metric
  schema, privacy/cardinality policy, recording rules, alerts, and verification.
- [Release operations](releasing.md) — one-time repository setup, version and
  tag flow, publication order, first-push GHCR visibility, and retry behavior.
- [Local durable services](../deploy/dev/README.md) — PostgreSQL and RustFS for
  development and integration tests.
- [Arch Linux runner hosts](platforms/arch-linux.md) — host prerequisites,
  rootless Podman admission, and local firewall policy.
- [`automata` control plane](../crates/automata-ci/README.md) — listener and secret
  reference details.
- [Ubuntu 24.04 execution profile](../images/github-hosted-ubuntu-24.04-x64/README.md)
  — immutable image contents and publication policy.
- [React SSR UI](../ui/README.md) — build-time frontend and embedded runtime
  boundaries.

## Distribution names

| Kind | Control plane | Runner |
| --- | --- | --- |
| Command | `automata` | `automata-runner` |
| crates.io package | `automata-ci` | `automata-ci-runner` |
| GHCR image | `ghcr.io/automata-ci/automata` | `ghcr.io/automata-ci/automata-runner` |

The wider Rust workspace uses the `automata-ci-*` package namespace and
`automata_ci_*` crate identifiers. User commands keep the shorter product
names.

## Documentation conventions

The [documentation style guide](documentation-style.md) records the reader-first
structure, terminology, command conventions, and public README references used
throughout this documentation.
