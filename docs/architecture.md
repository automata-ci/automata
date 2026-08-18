# Architecture

`automata` turns repository events and workflow files into scheduled work.
`automata-runner` executes that work inside a configured isolation provider.
PostgreSQL coordinates mutable state; S3-compatible storage holds immutable
payloads.

This page describes the running Linux composition and the implemented provider
boundaries. See [Compatibility](compatibility.md) for feature status and the
[implementation plan](implementation-plan.md) for open gates.

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
 automata-runner on Linux, Windows, or macOS
                 |
          configured SandboxProvider
       |             |             |                |                |
 rootless Podman  Local Docker*  Kubernetes Pod  Windows Hyper-V container  macOS VM
```

`Local Docker*` is the evaluation-only fixed-relay runner provider, not a
user-facing local-run command.

The workspace builds many libraries but distributes two product commands:

- `automata` starts the complete control plane and provides administration
  commands. It has no per-role server selector yet.
- `automata-runner` supervises rootless Podman, fixed-relay local Docker
  evaluation, or Kubernetes Pod execution on Linux; Hyper-V-isolated Windows
  container execution; or disposable macOS VM execution, along with host
  admission, lease renewal, logging, cancellation, and cleanup.

The Windows provider creates one fresh container with explicit Hyper-V
isolation, disabled networking, `ContainerUser`, a digest-qualified image,
bounded resources, and no host mounts. It verifies the effective runtime state
before exposing a provider-neutral guest execution endpoint. Native and
process-isolated Windows execution have been removed.

That Windows path is a component foundation, not an accepted hostile-workload
composition. It has a synchronized lifecycle journal and fail-closed startup
reconciliation, but currently invokes a pinned local container CLI directly
and has no independent watchdog. It also does not complete authenticated trust
routing, a restricted container-management broker, signed image production,
managed egress, or dedicated-host engine/host fault acceptance. The blocking
architecture and rollout gates are in the
[Windows isolation plan](platforms/windows.md).

The macOS provider cold-boots one Virtualization.framework VM per job with no
NIC or host directory share. It pins the signed helper and sealed template,
attests the guest over Virtio socket, and places APFS clones on a dedicated
non-boot quota volume.

## Workflow boundary

GitHub-specific code stops before scheduling:

```text
workflow YAML + event
        |
 WorkflowFrontend
        |
  source plan
        |
 GithubWorkflowCompiler
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
- `SandboxProvider` owns a job sandbox from creation through idempotent
  destruction. A provider that advertises service-container support also owns
  those resources and returns their complete healthy discovery view through
  `service_bindings`.
- `ExecutionEndpoint` is the only command, copy, signal, and wait interface
  inside an attached sandbox.
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
artifacts, cache objects, and final manifests. Exact public action bundles have
a write-once reference manifest derived from their provider, repository,
commit, and subpath, so both activation replicas and runners can discover a
previously verified content descriptor without GitHub. These immutable
identity records do not provide mutable coordination; PostgreSQL remains the
authority for transitions and publication.
Cache quota and retention eviction first records unreachable object descriptors
in a PostgreSQL outbox in the same transaction that removes their readable
metadata. Either control-plane replica may then perform idempotent deletion and
acknowledge the exact descriptor. A crash between those steps leaves durable
work for the next cache request instead of leaking storage or exposing a missing
object through live metadata.

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
days and applies a 10 GiB LRU quota per repository. Artifact deletion and
garbage collection, plus the cache management API, remain planned.

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
the feature until its provider probe succeeds. This repository's PostgreSQL CI
job exercises the complete service-container path; the example runner
configuration omits the installation-specific service-proxy image digest.

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
credential. Eligible Standard jobs may receive approved managed-secret
bindings from the built-in provider at exact pinned versions. Durable lease
state records only a value-free binding overlay; the runner fetches values over
a direct mTLS-bound ephemeral channel after leasing, holds them in zeroizing
custody, and installs every log mask before acknowledging delivery or starting
work. External or dynamic providers and variable-value delivery remain
unsupported. This path does not make every workflow eligible, and protected-
environment acceptance remains a separate boundary. See
[Authentication and authorization](authentication.md) for the current
interfaces and limits.

Workflow variables currently have durable, value-free selection metadata but
no execution-local value-custody receipt. Variable-bearing attempts therefore
remain queued: both the bounded pre-scheduling gate and PostgreSQL's direct
queued-to-leased transition reject them until a future migration introduces an
explicit custody proof.

## Web interface

Rust owns routing, authorization, data loading, response codes, and mutations.
It sends a typed page model to an embedded React renderer built by Vite. The
renderer runs as a resource-limited WASI component without filesystem, network,
environment, or subprocess access. Node.js is a build dependency, not a server
dependency.

Every initial route returns complete server-rendered HTML. Browser JavaScript
adds theme preference, form state, and in-memory filtering of replayed job
logs. The shared UI strictly decodes the structured SSE stream, applies
group-owned records, advances durable checkpoints, and reconnects through the
same replay path. Rust retains authentication, authorization, and durable
log-data authority. See
[ADR 0005](architecture-decisions/0005-structured-execution-log-groups.md).

## Provider maturity and future topology

Rootless Podman is the available Linux path used by this repository. The
workspace also contains disposable macOS Virtualization.framework execution,
the Rust Kubernetes sandbox adapter, its in-sandbox guest transport, a runner
product-config variant that uses ambient Kubernetes client authentication,
the fixed-relay local Docker provider, and the Windows Hyper-V-container
component. Their remaining qualification and deployment gates are listed in
[Compatibility](compatibility.md).

Later work adds independent control-plane roles, broader multi-replica
deployment, Kubernetes fleet reconciliation, Firecracker and KVM isolation,
Kata, KubeVirt, managed egress, and the broker and physical-host acceptance
layers required by the Windows route. Cluster provisioning remains a
deployment responsibility.

Those providers share the scheduler, JobIR, and sandbox contracts. They are not
available merely because their interfaces or roadmap entries exist. Their
acceptance gates are listed in the [implementation plan](implementation-plan.md#provider-scope).
