# Documentation

Automata is under active development. Each guide states what works now, what
has only component-level coverage, and what remains planned.

The quickest ways in are:

| Goal | Start here |
| --- | --- |
| Build from source and inspect the interface | [Getting started](getting-started.md) |
| Check support for a workflow feature | [Compatibility](compatibility.md) |
| Check Linux, Windows, and macOS support | [Platform support](platform-support.md) |
| Track the durable Windows release | [Windows release roadmap](windows-release-roadmap.md) |
| Start the durable local composition | [Control-plane setup](deployment.md) |
| Prepare an execution host | [Runner bootstrap](../crates/automata-ci-runner/config/README.md) |
| Build, test, or change Automata | [Development](development.md) |
| Contribute a change | [Contributing](../CONTRIBUTING.md) |
| Publish crates, images, and a GitHub Release | [Releasing](releasing.md) |

The [hosted UI demo](https://automata-ci.github.io/automata/) uses sample data.
It does not connect to repositories or execute workflows.

## Operate Automata

- [Authentication and authorization](authentication.md) covers login, roles,
  permissions, sessions, secrets, and repository visibility.
- [Prometheus and OpenMetrics](observability.md) defines the scrape endpoints,
  metrics, recording rules, alerts, and cardinality limits.
- [Arch Linux runner host](platforms/arch-linux.md) prepares a host for the
  current rootless Podman execution profile.
- [Local durable services](../deploy/dev/README.md) starts PostgreSQL and RustFS
  for development and integration tests.
- [`automata` control plane](../crates/automata-ci/README.md) documents listener
  configuration and secret references.

## Understand the system

- [Architecture](architecture.md) explains the components, data flow, storage,
  and trust boundaries.
- [Compatibility](compatibility.md) lists the supported GitHub Actions subsets
  and the evidence required for broader claims.
- [Implementation plan](implementation-plan.md) tracks completed foundations
  and the acceptance gates that still block a release.
- [Durable Windows release roadmap](windows-release-roadmap.md) tracks the
  Windows control-plane, service, packaging, and release milestones.
- [Ubuntu 24.04 execution profile](../images/github-hosted-ubuntu-24.04-x64/README.md)
  describes the immutable runner image and its publication policy.
- [React SSR UI](../ui/README.md) explains the build-time frontend and embedded
  runtime boundary.

## Work on the project

- [Development](development.md) covers builds, tests, fixtures, frontend work,
  and local services.
- [Contributing](../CONTRIBUTING.md) explains the change and review workflow.
- [Documentation style](documentation-style.md) defines status labels,
  terminology, and review checks for these pages.
- [Releasing](releasing.md) describes repository setup, versioning,
  publication, and retry behavior.
- [Changelog](../CHANGELOG.md) records release history.
- [Security policy](../SECURITY.md) gives the private reporting route.

## Names used for distribution

| Kind | Control plane | Runner |
| --- | --- | --- |
| Command | `automata` | `automata-runner` |
| Planned crates.io package | `automata-ci` | `automata-ci-runner` |
| Planned GHCR image | `ghcr.io/automata-ci/automata` | `ghcr.io/automata-ci/automata-runner` |

The wider Rust workspace uses `automata-ci-*` package names and
`automata_ci_*` crate identifiers. The shorter names are the commands users
run. None of the planned distribution names is public until its registry shows
an exact released version.
