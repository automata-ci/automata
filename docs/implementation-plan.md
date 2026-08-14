# Implementation and conformance plan

This plan tracks the work required before Automata can claim GitHub Actions
compatibility. A feature remains unsupported until its normal product path,
failure behavior, and recovery behavior pass the gate that owns it.

The [compatibility page](compatibility.md) owns current support claims. The
[architecture page](architecture.md) owns component and trust-boundary detail.

## Current foundation

As of 2026-08-14, the source tree contains:

- workflow parsing, expression evaluation, logical planning, bounded matrix
  expansion, and JobIR projection;
- PostgreSQL admission, scheduling, leases, fencing, maintenance, result
  projection, and immutable numeric run aliases;
- mTLS runner transport, provider admission, rootless Podman, and a
  component-level Hyper-V-isolated Windows container provider with a
  checksummed lifecycle journal and fail-closed startup reconciliation; Windows
  trust routing, restricted engine management, independent recovery, and real
  host acceptance remain open;
- Results, artifact, and CacheService v2 boundaries backed by
  S3-compatible storage;
- configured GitHub provider ingress, source delivery, authentication, Check
  Runs, and scoped repository credentials;
- tenant RBAC, repository publication settings, managed-secret administration,
  the management CLI, and the server-rendered UI; and
- reproducible distribution, SBOM, notice, image, and release automation.

Focused component and boundary tests cover these paths. The production
composition has not yet run this repository's unchanged CI workflow from
admission through differential result comparison. No release artifact is
public.

## Active work order

These items are ordered by dependency. A checked item has focused evidence; it
does not by itself close the end-to-end gate.

- [x] Preserve ordinary logs and explicitly public outputs while redacting
  registered runtime and repository credential values.
- [x] Hydrate phase-correct inputs, admission-supplied variable context, and
  opaque secret references through autonomous preparation and runner
  execution. Managed repository/environment variable administration and value
  custody remain part of the open G3 gate below.
- [x] Resolve eligible runner labels and groups to one immutable environment
  profile before JobIR admission, including dynamically evaluated selections.
- [x] Expose immutable positive numeric run and attempt identities without
  replacing internal UUIDs.
- [x] Compose authenticated `pull_request` and `merge_group` event evidence
  through the product webhook route, durable replay, workflow selection, and
  admission using the exact normalized revision and ref.
- [x] Implement ordered `concurrency.queue: max` coordination with PostgreSQL
  FIFO-promotion and stale-running-slot recovery tests. Keep it explicitly
  outside GitHub compatibility as an Automata extension.
- [ ] Pass the unchanged public bootstrap workflow through admission,
  orchestration, runner execution, Results, and Check Runs.
- [ ] Pass differential fixtures for actions, command files, matrices,
  reusable workflows, artifacts, caches, services, and cancellation.
- [ ] Pass control-plane fixtures for permissions, protected environments,
  secrets and variables, OIDC, events, reruns, concurrency, and the supported
  REST surface.
- [ ] Pass heterogeneous Linux fleet fixtures for isolated Docker and BuildKit,
  large transfers, persistent-cache trust boundaries, and exclusive devices.
- [ ] Pass scale, fault-injection, strong-isolation, workflow-chaining, broader
  Windows, and macOS gates before advertising those remaining capabilities.

## Acceptance gates

### G0: reproducible bootstrap

The workspace uses safe Rust, pinned toolchains, two product executables, an
embedded resource-limited WASI renderer, PostgreSQL, and S3-compatible storage.
CI verifies distribution contents, static Linux builds, checksums, SBOMs,
license notices, and execution in `scratch`.

Runner admission must fail before connecting to the control plane when the
configured rootless Podman binary, filesystem ownership, network policy, or
create/inspect/destroy probe is invalid.

Gate: GitHub Actions builds generation-zero artifacts from a reviewed commit.
The automation exists; no public generation-zero product release has been
published.

### G1: durable single-node execution

Run this repository's unchanged `.ci/workflows/ci.yml` through the durable
control plane and one Linux runner. The run must exercise source admission,
planning, `run` and required JavaScript actions, local actions, command files,
services, artifacts, logs, results, cancellation, and cleanup.

Gate: generation zero builds and tests generation one. Promotion happens only
after the run and differential comparison finish. A special Automata-only
workflow does not satisfy the gate.

### G2: broader Actions runtime

Exercise JavaScript and composite post-time template re-evaluation in the
differential fixture, and complete job and service containers, container
actions, matrices, status functions, fail-fast, max-parallel, reusable
workflows, artifacts, cache management, cancellation, summaries, and
annotations.

Gate: Automata's CI consumes its own artifacts and caches and matches GitHub at
the same commit.

### G3: GitHub control-plane behavior

Complete the supported permissions, protected environments, approvals,
secrets and variables, concurrency, reruns, schedules, webhook events, OIDC,
and selected REST surfaces. Unknown GitHub compatibility routes continue to
fail closed; there is no general job-token proxy.

Gate: event selection and workflow validation pass first, followed by a
non-mutating maintenance workflow and an agreed staging soak.

### G4: heterogeneous Linux fleet

Add canary runner groups for services, private Podman-backed Docker and
BuildKit, large artifact handoffs, persistent-cache namespaces, dynamic
matrices, reruns, OIDC-backed external storage, and exclusive devices such as
GPUs.

Gate: unchanged Linux pull-request CI passes for trusted and untrusted sources.
No job can reach the host Podman socket, broker credentials, or another
attempt's storage or network.

### G5: scale and strong isolation

Add multiple control-plane replicas, Kubernetes fleet reconciliation,
autoscaling, drain and upgrade behavior, Firecracker, Kubernetes with Kata,
and KubeVirt behind the existing provider contracts.

Gate: fault injection proves that replica, network, runner, PostgreSQL, and
object-store failures cannot cause a double commit. Hostile fixtures cannot
escape the isolation class advertised by their runner.

### G6: Windows, macOS, and fleet migration

The native Windows provider has been removed. The selected Windows direction is
one fresh Hyper-V-isolated Windows container per job with no process-isolated,
native, or full-VM fallback. The first Wave 1 component foundation provides
closed configuration, digest-pinned image/runtime inputs, effective
Hyper-V-isolation inspection, disabled networking, no host mounts, bounded
guest execution, a checksummed lifecycle journal, and fail-closed provider
startup reconciliation.

That foundation is not a hostile-workload claim. The
[Windows runner isolation plan](platforms/windows.md) keeps authenticated
`EVT-01` -> `AUTH-02` -> `WIN-ISO-01` trust routing, a restricted
container-management broker, independent recovery and real engine/host fault
acceptance, managed egress, credential custody, dedicated host evidence,
actions, and parallel capacity behind explicit gates.

The macOS execution path is disposable Virtualization.framework VMs on ARM64;
there is no native macOS provider. Complete the physical-host qualification,
macOS shell semantics, and any separately isolated signing or GPU profiles
without weakening that VM boundary. The implementation and deployment gates
are recorded in the [macOS runner guide](platforms/macos.md). Also complete the
workflow-chaining surfaces required by larger fleets.

Gate: unchanged workflows pass per-platform differential comparison. Publish,
deploy, recovery, and release workflows enter only after read-only and staging
gates have completed their agreed soak periods.

## Provider scope

Rootless Podman on Linux and disposable macOS Virtualization.framework VMs are
current execution paths. The Hyper-V-isolated Windows container code is a
component foundation only. Planned or unaccepted profiles below must not appear
in runner capability inventory before their gates pass.

| Provider | Planned use | Isolation boundary |
| --- | --- | --- |
| Firecracker with jailer | Hostile Linux jobs | One KVM microVM per job |
| Kubernetes with Kata | VM-backed pod sandbox | One VM-backed pod per runner |
| KubeVirt | VM fleet or job sandbox | One VMI per runner or job |
| Linux native | Trusted jobs | Account, cgroup, and LSM policy |
| Windows Hyper-V container | Hostile Windows jobs after WIN-ISO acceptance | One fresh Hyper-V utility-VM-backed container per job |

Kubernetes is not treated as “one workflow job equals one fixed Pod.” Dynamic
container actions, sibling services, and a shared workspace require an
ephemeral runner with an inner engine unless a separately tested provider can
offer equivalent behavior.

## External migration evidence

Private migration targets stay outside this repository. Public conformance uses
synthetic workflows, public upstream fixtures, and generated capability
manifests without naming or copying private repositories.

An operator's external acceptance corpus should progress from read-only
authorization and validation to dry-run maintenance, services, image builds,
artifact and cache handoffs, matrices, reusable workflows, specialized runner
profiles, and non-production chaining. Production publishing and deployment
come last.

GitHub does not allow another system to create arbitrary native Actions run,
job, log, or artifact records. Workflows that query those records directly
through `api.github.com` or `gh` need a specific bridge or endpoint change; a
broad compatibility label does not remove that limitation.

## Verification rules

- Parser and planner fixtures retain source spans and upstream provenance.
- Differential tests compare the same commit and event, normalizing only the
  volatile fields listed in [Compatibility](compatibility.md).
- State-machine tests cover transitions, lease races, retries, and stale
  fencing tokens.
- Adapter suites run against in-memory fakes and the real storage or execution
  boundary where practical.
- Property and fuzz tests cover YAML and expressions, protocol envelopes,
  command files, archives, paths, redaction, and UI model validation.
- Integration tests live in each crate's `tests/` tree; implementation modules
  do not carry a second test-only architecture.
- A gate stays open until its public fixture passes through the production
  composition.
