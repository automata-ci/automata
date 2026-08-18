# Automata documentation

Automata runs GitHub Actions workflows on self-hosted infrastructure. Choose a
page by the task you need to complete; compatibility claims and exact
configuration values live in their owning references rather than being copied
across guides.

## Start here

| Goal | Page |
| --- | --- |
| Build Automata, inspect the UI, and check a workflow | [Getting started](getting-started.md) |
| Find supported GitHub Actions syntax and runtime behavior | [Compatibility](compatibility.md) |
| Configure the control plane | [`automata` deployment reference](../crates/automata-ci/README.md) |
| Enroll and configure a runner | [Runner bootstrap](../crates/automata-ci-runner/config/README.md) |
| See the system running | [Current Automata CI dashboard run](https://ci.automata-ci.com/automata-ci/automata/actions/runs/99ab4504-ef90-8aa1-ad24-34d1811b1c00) |

## Operate Automata

- [Authentication and authorization](authentication.md): browser and CLI
  login, roles, sessions, repository visibility, secrets, and protected
  environment reviews.
- [GitHub Checks](github-checks.md): Check Run identity, status projection,
  annotations, links, retries, and recovery.
- [Workflow reruns](workflow-reruns.md): whole-run, failed-job, and selected-job
  reruns through the authenticated CLI.
- [Runner enrollment and control-plane security](runner-control-plane-security-and-enrollment.md):
  one-time tokens, certificate issuance, renewal, revocation, and audit state.
- [Runtime authority delivery](runtime-authority-delivery.md): lease-bound
  workload credentials and value-free durable state.
- [Observability](observability.md): Prometheus/OpenMetrics endpoints, metrics,
  cardinality limits, and failure diagnosis.
- [macOS runners](platforms/macos.md) and [Windows runners](platforms/windows.md):
  platform-specific isolation, host preparation, and qualification limits.

## Understand the system

- [Architecture](architecture.md) explains the request path, workflow compiler,
  storage model, leases, recovery, capabilities, and trust boundaries.
- [Compatibility](compatibility.md) is the source of truth for supported events,
  syntax, actions, services, artifacts, caches, credentials, and providers.
- [Conformance testing](conformance-testing.md) defines how compatibility claims
  are tested against GitHub Actions behavior.
- [Architecture decisions](architecture-decisions/) record decisions that must
  remain stable across implementations.
- [Ubuntu 24.04 runner profile](../images/github-hosted-ubuntu-24.04-x64/README.md)
  records the immutable image contract behind the Linux execution label.
- [React SSR UI](../ui/README.md) explains the Rust HTTP and isolated React
  rendering boundary.

## Work on Automata

- [Development](development.md): repository layout, builds, tests, fixtures,
  PostgreSQL and object-storage lanes, frontend work, and distribution checks.
- [Contributing](../CONTRIBUTING.md): issue selection, change requirements,
  verification, and pull-request expectations.
- [Documentation style](documentation-style.md): page types, terminology,
  capability evidence, copy rules, and review checks.
- [Releasing](releasing.md): release authority, versioning, artifacts,
  attestations, publication order, and recovery.
- [Security policy](../SECURITY.md): private vulnerability reporting and the
  supported security-fix target.

## Maintainer plans

These pages track incomplete work. They are not user documentation and do not
change the support status recorded in [Compatibility](compatibility.md).

- [Implementation plan](implementation-plan.md)
- [GitHub Actions parity backlog](github-actions-parity-backlog.md)
- [GitHub Actions parity execution plan](github-actions-parity-execution-plan.md)
- [Parity work packages](github-actions-parity/)
- [Local installation roadmap](maintainers/roadmaps/local-installation.md)
- [Provider platform and Forgejo roadmap](maintainers/roadmaps/provider-platform-and-forgejo.md)

## Product names

| Kind | Control plane | Runner |
| --- | --- | --- |
| Command | `automata` | `automata-runner` |
| Workspace package | `automata-ci` | `automata-ci-runner` |
| Planned container image | `ghcr.io/automata-ci/automata` | `ghcr.io/automata-ci/automata-runner` |

The commands are available from a reviewed source checkout. Do not treat a
package or image name in the release workflow as published until the matching
version exists in its public registry.
