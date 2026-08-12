# GitHub Actions parity: Services, job containers, Docker, Podman, Kubernetes, and BuildKit

Prove services, add job containers and Docker actions, accept the Kubernetes
provider in production, and provide isolated per-job Docker, Podman, BuildKit,
and cache behavior.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane P, with runner, security, and Results reviewers.

**Package IDs:** PROV-01, PROV-02, PROV-03, CTR-01, CTR-02, CTR-03, DKR-01, DKR-02, BLD-01, DCK-01.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)
- [Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)
- [Windows, Linux and macOS profiles, architectures, and cross-OS cache](github-actions-parity-09-platforms.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### PROV-01 — Prove the existing service-container slice in production

**Owner:** P. **Size:** L. **Dependencies:** FND-02 fixture interface.

Tasks:

- [ ] Build, scan, sign, publish, and digest-pin the reviewed service helper
  image.
- [ ] Configure a production-like runner with the image already present.
- [ ] Prove startup image inspection and capability advertisement.
- [ ] Run PostgreSQL through JobIR, lease, runner process, rootless Podman,
  proxy, job context, and exact cleanup.
- [ ] Add multiple TCP/UDP services, unhealthy service, cancellation, restart,
  leaked-network, and port-context fixtures.
- [ ] Verify service-label DNS from the job, host-port publication, protocol
  mapping, collision handling, and deterministic `job.services` context.
- [ ] Preserve actionable startup, health, image, port, DNS, and proxy failure
  diagnostics without exposing registry credentials.

Acceptance:

- [ ] Existing experimental support is product-proven without broadening
  syntax.
- [ ] No container or network remains after completion or recovery.

### PROV-02 — Complete service credentials, volumes, ports, and options

**Owner:** P. **Size:** XL. **Dependencies:** PROV-01, CFG-02 secret custody.

Tasks:

- [ ] Deliver registry credentials ephemerally.
- [ ] Add named and temporary volumes.
- [ ] Add safe workspace-relative volumes and decide host-path policy.
- [ ] Evaluate dynamic ports.
- [ ] Deliver secret environment without durable plaintext.
- [ ] Parse a reviewed options allowlist.
- [ ] Preserve health checks and diagnostics.
- [ ] Resolve mutable tags to persisted immutable digests, or document a
  digest-only divergence.
- [ ] Test cleanup and recovery for every resource.

Acceptance:

- [ ] Credentials never enter JobIR, durable specs, or logs.
- [ ] Volume and option policy cannot expose arbitrary host state.
- [ ] Dynamic ports and secret environment work in a real job.

### PROV-03 — Kubernetes provider production acceptance

**Owner:** P with security and operations review. **Size:** XL.
**Dependencies:** FND-02, PLAT-01.

Current component foundation:

- [x] The shipped runner has a mutually exclusive Kubernetes product-config
  path, ambient client construction, the Rust sandbox adapter, and the framed
  in-sandbox guest transport.
- [x] Component tests render a hardened non-root Pod, deny-by-default
  NetworkPolicy, generation- and UID-fenced lifecycle state, and exact
  CPU/memory and ephemeral-storage quantities, mapped devices, and an attested
  process ceiling.
- [x] Kubernetes uncertain create/start failures return the exact sandbox
  handle, which the executor now journals as cleanup custody for new attempts.

Remaining tasks:

- [ ] Freeze a production cluster profile covering namespace ownership,
  dedicated ServiceAccount, least-privilege RBAC, admission policy, immutable
  guest images, node selection, RuntimeClass, and ambient client credentials.
- [ ] Prove the CNI enforces the rendered deny-by-default policy and document
  the standard node-traffic exception required for kubelet exec, log, and copy
  operations without creating a general workload-egress bypass.
- [ ] Assert Pod Security, seccomp, non-root identity, disabled service-account
  token mounting, host-namespace denial, and allowed RuntimeClass behavior
  against the live admission stack.
- [ ] Run create, inspect, exec, bounded copy in both directions, and destroy
  through the shipped runner product path rather than adapter-only tests.
- [ ] Verify exact CPU/memory requests and limits, ephemeral-storage enforcement,
  process ceilings, and configured GPU resource mapping whenever those
  capabilities are advertised.
- [ ] Exercise cancellation, runner loss, guest loss, ambiguous Kubernetes API
  responses, stale generations, provider restart, and idempotent recovery;
  prove cleanup before slot release and define deterministic reconstruction or
  a drain policy for legacy pre-custody intents.
- [ ] Publish bounded provider/guest diagnostics and RED/USE metrics without
  exposing Kubernetes credentials, tokens, object bodies, or user output.
- [ ] Record the operator assertions and rollback procedure; keep cluster
  provisioning a deployment responsibility rather than silently expanding the
  runner's authority.

`PROV-03` is the production prerequisite for Kubernetes-backed reconciliation,
autoscaling, and packaging in `FLT-04`; fleet acceptance cannot substitute for
this provider-path evidence.

Acceptance:

- [ ] A production-like cluster runs a leased job through create, guest
  exec/copy, result publication, cancellation, destroy, and recovery with the
  exact admitted resource allocation.
- [ ] Network and admission probes show that the job cannot reach the node,
  Kubernetes API, runner authority, or another job except through each
  explicitly reviewed control path.
- [ ] No attempt-owned Pod, policy, volume, credential material, or guest
  session survives normal completion, cancellation, crash recovery, or replay;
  the runner's ambient Kubernetes credential never enters the job Pod or guest.
- [ ] Unsupported cluster features withhold capabilities or fail startup before
  runner registration; Kubernetes remains Experimental until this package
  passes.

### CTR-01 — Freeze the job-container architecture

**Owner:** P with R and security review. **Size:** S design gate.
**Dependencies:** none.

Tasks:

- [ ] Decide whether the user container is the primary endpoint or an owned
  sibling.
- [ ] Define workspace, home, workflow-command, action-content, and tool-cache
  mounts.
- [ ] Define UID/GID, default user, network, DNS, working directory, command
  files, credentials, volumes, recovery, and generation fencing.
- [ ] Define Docker action behavior inside and outside job containers.
- [ ] Threat-model rootless nesting, options, privileged mode, devices, and
  host mounts.

Acceptance:

- [ ] Approved design maps each visible behavior to a provider-neutral
  contract and names rejected cases.

### CTR-02 — Provider-neutral job-container contract

**Owner:** P. **Size:** L. **Dependencies:** CTR-01.

Tasks:

- [ ] Carry image, nonsecret environment, ports, volumes, and reviewed options.
- [ ] Keep plaintext credentials out of JobIR and durable specs.
- [ ] Add container execution endpoint and mount declarations.
- [ ] Add network identity, lifecycle, recovery, and capability types.
- [ ] Reject unsupported host paths and privilege at admission.
- [ ] Remove unconditional executor rejection only after capability checks
  exist.

Acceptance:

- [ ] Unsupported providers reject before execution.
- [ ] Contract round trips contain no credential values.
- [ ] Podman and test providers can implement it without platform leakage.

### CTR-03 — Rootless Podman job containers

**Owner:** P. **Size:** XL. **Dependencies:** CTR-02, LOG-02.

Tasks:

- [ ] Create the selected user container and private job/service network.
- [ ] Mount workspace and command directories with correct ownership.
- [ ] Match `/github/home`, `/github/workspace`, and `/github/workflow` paths
  exactly inside the job container and keep host/provider paths private.
- [ ] Match environment, working directory, and shell behavior.
- [ ] Deliver registry credentials ephemerally.
- [ ] Support approved volumes and options.
- [ ] Populate `job.container`.
- [ ] Persist owned recovery state and destroy exact resources without global
  prune.
- [ ] Test restart and cancellation at every lifecycle phase.

Acceptance:

- [ ] Run, JavaScript, and composite steps execute inside a real job container
  and reach services by name.
- [ ] Recovery leaks no owned resource.

### DKR-01 — Prepare Docker actions

**Owner:** R for action model, P reviews execution needs. **Size:** L.
**Dependencies:** RUN-01, CTR-01.

Tasks:

- [ ] Add prepared Dockerfile and `docker://` action variants.
- [ ] Carry evaluated entrypoint, arguments, environment, and lifecycle
  metadata.
- [ ] Validate Dockerfiles and paths within immutable action content.
- [ ] Support container references nested in composites.
- [ ] Preserve expression and resource bounds.
- [ ] Continue failing early until a provider advertises execution.

Acceptance:

- [ ] Docker metadata no longer fails solely because preparation lacks a
  variant.
- [ ] Unsupported execution remains an admission failure.

### DKR-02 — Execute Docker actions without a host socket

**Owner:** P integrates with R. **Size:** XL. **Dependencies:** DKR-01,
CTR-02; reuse CTR-03 infrastructure.

Tasks:

- [ ] Build Dockerfile actions and run registry actions.
- [ ] Mount workspace, home, workflow files, and immutable action content.
- [ ] Apply entrypoint, arguments, environment, user, and working directory.
- [ ] Join the job/service network.
- [ ] Execute supported lifecycle hooks and contexts.
- [ ] Stream workflow commands and output.
- [ ] Recover and clean every action container.
- [ ] Reject privileged, device, socket, and host-mount escalation.

Acceptance:

- [ ] Repository Dockerfile, registry, and nested-composite container actions
  pass through the shipped runner.
- [ ] No general host Docker API is exposed.

### BLD-01 — Production Buildx, BuildKit, and cache acceptance

**Owner:** P; X owns the Results acceptance review. **Size:** L.
**Dependencies:** RES-01, PROV-01.

Tasks:

- [ ] Run pinned setup-buildx and build-push actions.
- [ ] Start the digest-pinned local BuildKit helper.
- [ ] Exercise `cache-to` and `cache-from` against production CacheService v2.
- [ ] Verify provenance archive handling.
- [ ] Test miss, hit, conflict, cancellation, restart, and exact cleanup.
- [ ] Review any new Docker request field explicitly.

Acceptance:

- [ ] A second build uses the first cache and produces the expected digest.
- [ ] No builder, container, volume, or socket survives cleanup.

### DCK-01 — Per-job Docker and Podman CLI compatibility

**Owner:** P with R and C review. **Size:** XL. **Dependencies:** CTR-02,
PROV-01, LOG-02.

This package is distinct from Docker actions (`DKR-*`) and the narrow BuildKit
proxy (`BLD-01`). It exists because ordinary Linux `run:` steps can invoke
Docker or Podman, including Automata's own checked-in CI workflow.

Tasks:

- [ ] Define the reviewed Docker and Podman CLI/API surface required by pinned
  conformance workflows and Automata's CI scripts.
- [ ] Provide a per-job endpoint backed by rootless Podman or another owned
  daemon without mounting a host-global socket.
- [ ] Support the required pull, build, create/run, inspect, logs, exec, wait,
  stop, remove, image, network, and volume operations incrementally.
- [ ] Support the exact rootless `podman build`, `podman save`, and
  `podman image rm` forms used by Automata's distribution and helper-image
  verification scripts.
- [ ] Give each job an isolated image/build store; never expose or mutate the
  provider's host-side image store through the job CLI.
- [ ] Bind every container, network, volume, credential, and build context to
  the exact sandbox handle and operation IDs.
- [ ] Stream stdout/stderr and exit status through the normal execution path.
- [ ] Reject privileged mode, devices, arbitrary host mounts, host networking,
  foreign namespaces, plugins, and daemon configuration changes unless a
  later reviewed contract adds them.
- [ ] Define registry credential delivery, proxy/custom-CA behavior, resource
  limits, and private/static-egress policy.
- [ ] Recover and remove all owned resources after cancellation, runner crash,
  provider restart, and ambiguous daemon responses.
- [ ] Add compatibility tests for the exact metrics and static-binary Docker
  commands in Automata's `.github/workflows/ci.yml`.

Acceptance:

- [ ] Required normal Docker and Podman CLI commands run inside one job without
  exposing runner or sibling-job state.
- [ ] Unsupported API calls fail with stable diagnostics.
- [ ] No container, image lease, volume, network, credential, or endpoint
  remains after durable cleanup.

---

[Previous: Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md) · [Next: Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)
