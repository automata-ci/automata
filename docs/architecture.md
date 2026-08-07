# Architecture

## Components and boundaries

The Cargo workspace contains libraries, but produces only two distributed
executables. `automata` can run all control-plane roles together or a
configured subset, so deployments may scale API, planner, scheduler, results,
SSR, and fleet-controller replicas independently while using one artifact.
`automata-runner` can run as a host supervisor or as the guest agent of a VM
sandbox.

```text
GitHub / API / schedules                     Browser
          |                                     |
          +------------- automata -------------+
                       |          |
                  PostgreSQL   S3 / RustFS
                       |
                 leased JobIR
                       |
                 automata-runner
                       |
             SandboxProvider boundary
                       |
        Podman | KVM | Firecracker | Kubernetes
```

The primary internal ports are:

1. `WorkflowFrontend`, which converts source workflows and events into an
   immutable, versioned workflow plan and job IR. GitHub-specific behavior is
   contained here.
2. `SchedulerPolicy`, which matches typed requirements and user routing policy
   without knowing how capacity is provisioned.
3. `FleetController`, which asynchronously reconciles desired runner capacity.
4. `SandboxProvider`, which owns the complete job lifetime: create, attach,
   inspect, execute, signal, copy, and idempotent destroy.
5. `ContainerEngine`, which implements job containers, services, and sequential
   container actions *inside* a job sandbox.
6. Storage, SCM, and workload-credential ports for PostgreSQL, S3-compatible
   object stores, secrets, and GitHub.

Human authentication, authorization, repository workload credentials,
provider-token custody, sessions, and runner machine identity are separate
ports. See the
[authentication design](authentication.md).

Rust traits are internal to one release and receive owned, versioned domain
types. Remote runners, guest agents, privileged helpers, and optional external
providers use explicitly versioned messages. The remote runner wire contract is
the typed `automata.runner.v1` protobuf package; its package version is
independent from negotiated protocol and JobIR versions. Backend-native
identifiers never leak into durable JobIR.

## Correctness model

PostgreSQL is the source of truth for runs, jobs, attempts, leases, concurrency
groups, admission, and artifact metadata. Server replicas are disposable and
coordinate through transactions and fencing rather than process-local locks.
S3/RustFS stores immutable workflow snapshots, action bundles, log segments,
artifacts, caches, and final manifests.

Attempt identity includes the job, attempt, lease, and monotonically increasing
fencing token. All state changes and published outputs compare the expected
token. Network delivery is at-least-once; externally visible commits are
fenced. Mutating provider calls carry operation IDs and generations so create,
cancel, and destroy are idempotent.

Runners journal an accepted lease and sandbox handle before acknowledging it.
After restart they either reattach to a live attempt or terminate and clean an
orphan. Cancellation is persisted first, stops new steps, interrupts the active
process, applies a grace period, kills the entire sandbox boundary, and always
reconciles teardown.

Logs are append-only frames with stream and sequence metadata. Acknowledgement
tracks the highest contiguous sequence, allowing reconnect and replay. The
runner masks secrets before transmission and spills bounded encrypted frames
to disk under backpressure. The server writes immutable compressed segments
and publishes a final S3 manifest.

## Capability and routing model

Labels and runner groups are user-facing routing and authorization. Machine
facts are structured requirements: OS, architecture, isolation class, resource
minimums, container actions, services, nested containers, devices, and GPU.
The runner handshake negotiates protocol and JobIR ranges plus namespaced
capabilities. Unknown optional capabilities are ignored; an unknown required
capability produces a typed decline reason. Every attempt records the exact
negotiated capability snapshot.

## Provider roadmap

The first local provider is one rootless Podman job pod with a private network,
workspace, limits, labels, and job-scoped container API. It is a shared-kernel
isolation tier, not a hostile multi-tenant boundary.

Linux production isolation uses an ephemeral KVM VM; Firecracker is a later
optimized provider using a guest `automata-runner`, vsock, a read-only base, and
copy-on-write job disk. Kubernetes first provisions ephemeral runner pods as a
fleet controller. Later Kubernetes, Kata, and KubeVirt implement stronger
sandbox providers behind the same contract. Windows uses disposable Hyper-V
VMs for strong isolation; macOS uses Virtualization.framework VMs, with native
execution restricted to trusted workloads.

## Frontend

Rust owns routing, authorization, data loading, response status, and mutations.
It passes a typed `PageModel` to an embedded React renderer built by Vite. The
SSR component, manifest, and hashed assets are embedded in `automata`; Node
is never a production dependency. All routes return complete HTML and use
normal links/forms. Hydration is limited to progressive enhancement such as
live log updates.

The same executable exposes a `gh`-style administration client for login,
runs, secrets, runner groups, runners, artifacts, caches, and control-plane
operations. CLI and browser authentication share provider-neutral server
sessions; machine-to-machine runner identity remains a separate mTLS trust
domain.
