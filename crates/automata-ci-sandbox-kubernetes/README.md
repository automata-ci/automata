# Kubernetes sandbox adapter

`automata-ci-sandbox-kubernetes` is the provider-neutral runner boundary backed
by one Kubernetes Pod per whole-job sandbox. It creates an ownership-labelled
Pod and a matching ingress-and-egress deny `NetworkPolicy`, waits for the
sandbox guest to become ready, supports attach/inspect/exact deletion, and
implements exec and bounded file transfer without placing job arguments,
environment values, or file contents in Pod specs or Kubernetes request URLs.

Status: **Experimental**. The runner product path and lifecycle admission are
implemented, but an operator must still prove the cluster's CNI, node, and
workload-isolation assertions before using it for untrusted jobs.

`automata-runner` can select this adapter with the mutually exclusive
top-level `kubernetes` product configuration. It discovers an authenticated
client through the standard ambient kubeconfig/in-cluster chain and runs the
same create/inspect/destroy environment-profile admission used by Podman before
opening a runner session. Cluster provisioning and policy installation
intentionally live outside this repository.

## Resource mapping

Automata stores canonical integer resources and renders the resolved job
allocation on the main workload container:

| Automata dimension | Kubernetes resource |
| --- | --- |
| CPU millicores | `cpu`, rendered as `Nm` |
| memory bytes | `memory`, rendered as bytes |
| ephemeral storage bytes | `ephemeral-storage`, rendered as bytes |
| GPU count | an operator-configured domain-qualified extended resource, such as `nvidia.com/gpu` |

Requests are placement evidence and limits are enforcement evidence. Kubernetes
uses requests when scheduling Pods and enforces CPU and memory limits through
the kubelet/runtime; local ephemeral-storage accounting works only on supported
node filesystem layouts. See Kubernetes'
[resource management contract](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).
The adapter requires the fully resolved allocation on every sandbox request and
rejects missing evidence; it never reconstructs requests from hard limits.
Automata additionally requires GPU requests and limits to be equal. The
provider advertises ephemeral-storage enforcement only when configured with
`VerifiedEphemeralStorageEnforcement`; GPU/device enforcement is advertised
only when an extended-resource mapping is configured. Kubernetes has no
per-Pod PID-limit field, so `ProcessLimits` is advertised only after
`VerifiedProcessLimitEnforcement` attests the homogeneous external Pod PID
ceiling for every eligible node. The SandboxSpec PID value must match that
attested ceiling exactly.

## Guest image contract

The adapter requires a digest-pinned, architecture-compatible image containing
the statically linked `automata-ci-sandbox-guest` executable at
`/usr/local/bin/automata-ci-sandbox-guest`. The init container copies that
executable into an `emptyDir`; the workload container starts it from the
read-only `/automata/bin` mount and listens on a Linux abstract Unix socket.
This allows the endpoint to work with job images that do not ship an Automata
agent without leaving a replaceable filesystem socket or writable guest binary
in the workload container.

Build the image from the repository root:

```console
docker build -f crates/automata-ci-sandbox-guest/Containerfile \
  -t registry.example/automata/sandbox-guest:build .
```

Publish it, resolve the registry digest, and configure only the immutable
`name@sha256:...` reference. A multi-platform publication must build each
target platform independently; the resulting guest executable must match the
Pod's node and workload architecture.

## Cluster contract

The authenticated `kube::Client` needs namespace-scoped access equivalent to:

| API resource | verbs used by the adapter |
| --- | --- |
| `pods` | `get`, `create`, `delete` |
| `pods/exec` | `create` |
| `networkpolicies.networking.k8s.io` | `get`, `create`, `delete` |

The generated Pod disables service-account token automounting, host networking,
host PID/IPC namespaces, privilege escalation, and added Linux capabilities. It
runs as a configured non-root UID/GID, drops `ALL` capabilities, and uses
`RuntimeDefault` seccomp. Kubernetes documents why
[`automountServiceAccountToken: false`](https://kubernetes.io/docs/concepts/security/service-accounts/)
and [`RuntimeDefault` seccomp](https://kubernetes.io/docs/reference/node/seccomp/)
matter, but these controls do not turn a shared-kernel container into a VM.

Construction requires `VerifiedNetworkIsolation`. That marker is an operator
attestation, not an automatic cluster probe. Before constructing it, the SaaS
composition must verify all of the following:

- the installed CNI actually enforces `NetworkPolicy`;
- no additive policy selecting Automata Pods re-allows traffic;
- supplemental CNI, host-firewall, or admission policy denies node-local and
  cloud instance-metadata paths; and
- the runner namespace cannot create or mutate policy outside the adapter's
  exact ownership boundary.

These requirements are deliberate. Kubernetes says a policy has no effect
without an enforcing network plugin, policies combine additively, and traffic
between a Pod and its node is always allowed by the standard policy model. See
the upstream [NetworkPolicy semantics and limitations](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## Current capability boundary

Supported: whole-job lifecycle, attach, inspect, literal-argv exec, ephemeral
environment injection, bounded copy-to/copy-from, disabled networking,
read-only or writable root filesystems, and CPU/memory/ephemeral-storage/GPU
requests and limits. Ephemeral storage and GPU have the explicit capability
gates described above; PID enforcement requires the separate node-pool
attestation.

Not advertised: service containers, private egress, administrator mode, user
namespaces, signals, wait, or a Docker-compatible API. Workflows
requiring those features must not be scheduled to this provider.

The remaining deployment acceptance is intentionally explicit. The product
configuration requires the network-isolation assertion, one dedicated node
selector, an exact PID ceiling, and optional storage/GPU assertions. Operators
must establish those assertions with cluster-level evidence; the adapter cannot
infer CNI enforcement or homogeneous kubelet configuration merely because the
API accepted an object.
