# Architecture

`automata` turns repository events and workflow files into scheduled work.
`automata-runner` executes that work inside a configured isolation provider.
PostgreSQL coordinates mutable state; S3-compatible storage holds immutable
payloads.

This page describes the source tree as of 2026-08-11 and separates the current
composition from the provider roadmap. See [Compatibility](compatibility.md)
for supported behavior and the [implementation plan](implementation-plan.md)
for open gates.

## Current composition

```text
GitHub events          Browser / CLI
      |                     |
      +------ automata -----+
                 |     |
           PostgreSQL object storage
                 |
            fenced JobIR lease over mTLS
                 |
          automata-runner on Linux
                 |
        rootless Podman job sandbox
```

The workspace builds many libraries but distributes two product commands:

- `automata` starts the complete control plane and provides administration
  commands. It has no per-role server selector yet.
- `automata-runner` supervises rootless Linux execution, host admission, lease
  renewal, logging, cancellation, and cleanup.

The browser preview is a smaller mode of `automata`; it does not start the
durable services or runner listener. Production dependencies never fall back
to preview behavior.

## Workflow boundary

GitHub-specific code stops before scheduling:

```text
workflow YAML + event
        |
 WorkflowFrontend
        |
  source plan
        |
 WorkflowCompiler
        |
 immutable logical WorkflowPlan
        |
 fenced activation and matrix expansion
        |
       JobIR
```

`WorkflowFrontend` parses and validates the GitHub dialect. The compiler lowers
it with event provenance into logical state. Activation evaluates the
run-dependent parts, expands bounded strategies, and projects executable
JobIR. The scheduler and runner do not parse YAML or evaluate provider syntax.

Automata-only `concurrency.queue` and per-job `resources` fields are extensions,
not GitHub Actions compatibility features. Resource templates cross activation
into a resolved request/limit contract; the pinned repository runtime policy
supplies defaults and bounds before scheduling.

The remaining internal boundaries have narrower jobs:

- `SchedulerPolicy` matches routing, typed requirements, and eligible capacity.
- `FleetController` reconciles runner supply outside scheduling transactions.
- `SandboxProvider` owns a job sandbox from creation through idempotent
  destruction.
- `ContainerEngine` runs job containers, services, and sequential container
  actions inside that sandbox.
- Storage, source-control, secret, authentication, and credential-broker ports
  keep backend data out of JobIR.

Rust traits are private to one release and process. Remote runners and helpers
use versioned protocols. The runner wire format is the typed
`automata.runner.v1` protobuf package over mutually authenticated TLS 1.3 and
HTTP/2; it has no opaque JSON or Rust-layout serialization.

## State and storage

PostgreSQL owns repositories, workflow snapshots, runs, numeric compatibility
aliases, jobs, attempts, leases, runner registration, admission, concurrency,
publication settings, and result metadata. Server replicas coordinate with
transactions and fencing rather than process-local locks.

S3-compatible storage owns immutable workflow and action bundles, log segments,
artifacts, cache objects, and final manifests. It is not used for coordination.

Scheduled GitHub workflows use a separate durable path from webhooks. A
manifest-pinned discovery claim binds an owner-bound provider revision, exact
default-branch commit, source archive, and sorted schedule inventory before a
registry revision becomes current. Due occurrences are fenced database-time
claims; retries retain the same occurrence, while a terminal result advances
only to its next calendar instant. A scheduled Check and workflow admission
carry the exact fire identity, so no synthetic delivery or generic GitHub
credential proxy is introduced.

The Results listener serves job-scoped log, artifact, result, cache, and OIDC
boundaries. Cache lookup checks the current ref first, then the server-owned
default branch read-only. Current policy expires entries after seven inactive
days and applies a 10 GiB LRU quota per repository. Physical object collection
and the cache management API remain planned.

## Leases, retries, and cleanup

An attempt is bound to its job, attempt ID, lease ID, and increasing fencing
token. Every state change and published result compares that token. A delayed
runner may repeat a request, but it cannot commit after a newer lease takes
ownership.

The runner journals a lease and sandbox handle before acknowledging the work.
After a restart it reattaches to a live attempt or terminates and removes an
orphan. Cancellation is stored first, prevents another step from starting,
interrupts the active process, waits for the configured grace period, kills the
sandbox, and reconciles cleanup.

Logs use stream and sequence numbers. The server acknowledges the highest
contiguous sequence so a runner can reconnect and replay. The runner redacts
registered credential values before transmission and may spill a bounded,
encrypted backlog to disk. The server stores immutable compressed segments and
publishes a final manifest.

## Capabilities and routing

Labels and runner groups express user routing and authorization. Machine facts
are typed: operating system, architecture, isolation class, resource minimums,
container features, devices, and GPU requirements.

Runner registration is an upper limit. A live session reports what its current
provider probes actually support, and scheduling uses the intersection. An
unknown required capability returns a typed decline; it is not ignored. Each
attempt records the negotiated snapshot.

Service containers illustrate this rule. Registration may allow them only when
an exact immutable service-proxy image is configured. The runner still removes
the feature until its provider probe succeeds. The checked-in configuration
omits the unpublished helper image, so the end-to-end service path remains
open.

Workload OIDC is implemented at the issuer and Results boundary but is absent
from supported runner inventories. External TLS, consistent keys across
replicas, and bounded authority retention must be proven before it can be
advertised.

## Trust boundaries

Human sessions, tenant authorization, runner mTLS identity, GitHub provider
credentials, repository workload credentials, managed secrets, and workload
tokens are separate trust domains. GitHub membership can grant a mapped role;
it never grants Automata administrator access by itself.

Jobs do not receive the host Podman socket, provider-control credentials, or
control-plane credentials. CredentialFree jobs receive no repository
credential. Managed-secret administration is implemented, but managed values
are not delivered to jobs yet. See [Authentication and authorization](authentication.md)
for the current interfaces and limits.

## Web interface

Rust owns routing, authorization, data loading, response codes, and mutations.
It sends a typed page model to an embedded React renderer built by Vite. The
renderer runs as a resource-limited WASI component without filesystem, network,
environment, or subprocess access. Node.js is a build dependency, not a server
dependency.

Every route returns complete HTML. Browser JavaScript adds small conveniences
such as theme preference, log filtering, and form state; it does not own page
data or live log transport.

## Planned providers and topology

Later gates add independent control-plane roles, multiple replicas,
Kubernetes-based fleet reconciliation, Firecracker and KVM isolation, Kata,
KubeVirt, Windows native and Hyper-V execution, and macOS native and
Virtualization.framework execution. The workspace contains the Rust Kubernetes
sandbox adapter, its in-sandbox guest transport, and a runner product-config
variant that uses ambient Kubernetes client authentication and the shared
environment-profile startup admission. Fleet reconciliation and cluster
provisioning remain deployment responsibilities.

Those providers share the scheduler, JobIR, and sandbox contracts. They are not
available merely because their interfaces or roadmap entries exist. Their
acceptance gates are listed in the [implementation plan](implementation-plan.md#planned-provider-scope).
