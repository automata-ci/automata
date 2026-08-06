# Implementation and conformance plan

This plan treats GitHub Actions compatibility as a versioned product surface,
not as a YAML parsing feature. Each milestone ends in an executable gate. A
feature is unsupported until its semantics, failure behavior, and recovery
behavior have passed that gate.

## Architectural seams

GitHub Actions is the first workflow frontend. It compiles source YAML, event
data, reusable workflows, matrices, expressions, and action metadata into an
immutable, content-addressed `JobIr`. The scheduler and providers never parse
GitHub YAML or evaluate GitHub expressions.

```text
GitHub frontend -> WorkflowPlan / JobIr -> durable scheduler -> runner lease
                                                               |
                                                       SandboxProvider
                                                               |
                                      ExecutionEndpoint + ContainerEngine
```

The principal internal ports are deliberately narrower than a provider API:

- `WorkflowFrontend` owns GitHub parsing, validation, phase-correct expression
  evaluation, DAG and matrix expansion, reusable workflows, and action
  pre/main/post planning.
- `SchedulerPolicy` matches runner group and label routing separately from
  typed requirements and scores eligible capacity without provisioning it.
- `FleetController` asynchronously reconciles runner supply. Kubernetes,
  cloud VMs, and static hosts plug in here without blocking a scheduling
  transaction.
- `SandboxProvider` creates, attaches, inspects, and idempotently destroys a
  whole-job isolation boundary. It returns an `ExecutionEndpoint`; native,
  container, microVM, Kubernetes, and remote guest-agent execution share that
  contract.
- `ContainerEngine` is separate because job containers, service containers,
  and sequential container actions exist inside one job sandbox. Unsupported
  Docker options are rejected, never dropped.
- `BlobStore`, `ArtifactStore`, `CacheStore`, `SecretVault`, `ScmProvider`, and
  `AuthenticationProvider` are provider-neutral ports. Adapters use owned,
  versioned data and do not leak backend handles into durable records.

Rust traits are used only within one release and address space. Guest agents,
privileged helpers, third-party providers, and remote runners use versioned RPC
over Unix sockets, vsock, or mTLS; Rust dynamic libraries are not a plugin ABI.
The G0 protocol crate uses a strictly bounded, versioned JSON codec to harden
the message model and negotiation rules. Protobuf is the planned stable network
encoding adapter before the G1 remote-runner protocol is declared compatible;
durable records never serialize Rust layouts directly.

## Durable correctness rules

PostgreSQL is the source of truth for runs, jobs, attempts, concurrency,
environment admission, leases, and published metadata. S3/RustFS stores
immutable snapshots, action bundles, log segments, artifacts, caches, and
manifests; it is never a coordination service.

An attempt is identified by `(job_id, attempt_id, lease_id, fencing_token)`.
Delivery is at least once. Every state transition, output, artifact manifest,
and terminal result compares the current fencing token, so a late runner
cannot commit. Provider mutations also carry an operation ID and expected
generation. Create, cancel, stop, and destroy are idempotent and reconcilable
after either side crashes.

The runner journals an accepted lease and sandbox handle before acknowledging
work. It renews outbound over mTLS, kills work after lease expiry even while
disconnected, resumes acknowledged log sequences, and reconciles orphans at
startup. Log frames are redacted before transmission and spill to bounded,
encrypted local storage rather than blocking heartbeats or cancellation.

## Deployment and trust boundaries

The distribution contains exactly two product executables, both statically
linked:

- `automata` runs any control-plane role and also provides the administration
  CLI;
- `automata-runner` supervises host or guest execution.

First-party adapters are compiled in and selected by configuration. Neither
binary needs a language runtime or shared library. Podman, KVM, Kubernetes,
and platform hypervisors are provider services invoked at runtime, not linked
application dependencies. The archive also preserves third-party license,
NOTICE, and copyright texts for both binaries and their embedded renderer/UI
assets; these compliance documents are data, not additional product binaries.

Human authentication is provider-pluggable. The first adapter uses a GitHub
App: browser sessions use the web flow and the CLI defaults to device flow.
GitHub tokens are encrypted provider credentials, not general Automata bearer
tokens. Explicit organization/team mappings grant Automata roles; membership
never implies administrator. Runner mTLS identity, workload tokens, SCM
credentials, and human sessions are separate trust domains.

The React/Vite UI is entirely server rendered. Its component and hashed client
assets are embedded in `automata`; rendering runs in a resource-limited WASI
component with no filesystem, network, inherited environment, or subprocess
authority. JavaScript is optional progressive enhancement.

## Isolation provider matrix

| Provider | Initial role | Isolation claim | Container semantics |
| --- | --- | --- | --- |
| Rootless Podman | Linux local/job sandbox | shared kernel, dedicated user/network/cgroup namespaces | full target, private job-scoped engine |
| Firecracker+jailer | Linux hostile workload | one KVM microVM per job | engine behind guest agent |
| Kubernetes | fleet controller first | depends on node/runtime | inner job-scoped engine |
| Kubernetes+Kata | pod sandbox adapter | VM-backed pod | inner engine retained |
| KubeVirt | fleet or sandbox adapter | one VM/VMI per job | guest agent |
| Linux native | trusted workloads only | account+cgroup/LSM | optional local engine |
| Windows native | trusted workloads only | restricted token+Job Object | Windows engine |
| Windows Hyper-V | hostile workload | disposable VM/Hyper-V isolation | guest engine |
| macOS native | trusted workloads only | dedicated account+sandbox profile | limited |
| Virtualization.framework | strong macOS tier | disposable macOS VM | guest agent |

Kubernetes is not initially modeled as “one workflow job equals one static
Pod”: sequential dynamic container actions, sibling service networking, and a
shared workspace do not map generally to immutable Pod container specs.
Kubernetes first creates ephemeral runner Pods with a supported inner engine.

## Milestones and gates

### G0 — reproducible bootstrap

- Safe-Rust workspace, MIT license, pinned toolchains and dependencies.
- Two static-musl executables verified in `scratch`.
- Deterministic CycloneDX inventories for both binaries, the embedded WASI
  renderer, and its React runtime, with binary/component digest binding.
- React/Vite SSR build, PostgreSQL, and RustFS development stack.
- Arch runner admission diagnoses matching kernel modules and actively proves
  rootless Netavark nftables, loopback DNAT, and cleanup.
- Ordinary `.github/workflows/ci.yml` remains valid GitHub Actions syntax and
  produces consumable checksummed bootstrap artifacts.

Gate: GitHub Actions builds generation-zero artifacts from a reviewed commit.

### G1 — durable single-node dogfood

- PostgreSQL schema and migrations for repositories, workflow snapshots,
  runs, jobs, attempts, leases, concurrency groups, and runner registrations.
- Outbound runner protocol negotiation, leases, fencing, cancellation, log
  resume, and crash/orphan recovery.
- GitHub workflow parser, source spans, the phase-correct expression subset,
  `needs`, timeouts, current-workflow concurrency cancellation, `run` steps,
  command files, and local action resolution required by this repository's
  unchanged CI.
- The minimum JavaScript-action runtime needed for the exact pinned checkout,
  setup-node, and upload-artifact actions used by bootstrap CI, including
  pre/main/post behavior and action-runtime environment endpoints.
- Fenced RustFS log/result objects plus the artifact upload protocol and
  immutable manifest semantics exercised by `actions/upload-artifact`.
- Rootless Podman sandbox provider, static local fleet controller, an explicit
  `ubuntu-24.04` environment image/profile, and a private job-scoped
  Podman-backed `docker` CLI sufficient for the `scratch` smoke test. The host
  Podman socket is never exposed.
- Outbound dependency access for Cargo/npm, command-file behavior, and the SSR
  run-list/run-detail routes.

Gate: generation zero runs the repository's unchanged CI workflow through
Automata to build and test generation one. Automata never replaces the control
plane that is executing it; promotion happens only after the run finishes and
the differential report passes. This gate is not satisfied by invoking an
Automata-specific test harness or by editing the workflow for Automata.

### G2 — broader Actions runtime compatibility

- Arbitrary JavaScript and composite actions beyond the pinned G1 set, with
  complete pre/main/post ordering.
- Complete official artifact and cache runtime protocols, multipart uploads,
  retention, digest validation, and BuildKit cache endpoint.
- Job/service containers, dynamic ports, container actions, shell defaults,
  annotations, summaries, masks, timeouts, and cancellation.
- Matrix expansion, `needs`, outputs, status functions, implicit success
  guards, fail-fast, max-parallel, and reusable workflows.

Gate: Automata's CI uses its own uploaded static artifacts and caches, then
passes differential comparison against GitHub at the same commit.

### G3 — GitHub control-plane compatibility

- GitHub App installation/user authentication, Check Runs and statuses.
- Actions-compatible results, artifact, cache, OIDC, and selected REST facade;
  unsupported GitHub API calls proxy with a job-scoped token.
- Permissions, protected environments, approvals, secrets/vars, concurrency
  coalescing and cancellation, rerun attempts, schedules, and webhooks.
- Administration CLI endpoints for the complete declared command tree.

Gate: the safe read-only `world-engine` progression passes: advisory platform
selection, workflow validation, then dry-run stale-ref cleanup.

### G4 — representative `world-engine` Linux fleet

- General Linux services job with PostgreSQL and Redis.
- Docker CLI compatibility over a private Podman engine, Buildx, Compose, and
  `type=gha` cache.
- Multi-gigabyte raw artifact producer/consumer handoff with exact attempt and
  digest semantics.
- Reusable Linux engine builds, OIDC-backed external S3 cache, persistent-cache
  trust namespaces, dynamic matrices, GPU-exclusive queueing, and reruns.

Gate: unchanged Linux PR CI passes on canary runner groups, including
Dependabot-originated untrusted code. No job sees a host-wide Podman socket,
broker credentials, or another attempt's storage/network.

### G5 — scale and strong isolation

- Multiple stateless control-plane replicas under transaction/fencing tests.
- Kubernetes fleet controller, autoscaling signals, placement scoring, drain,
  and rolling protocol-skew upgrades.
- Firecracker sandbox with jailer, tap/netns, read-only base and CoW disk,
  vsock guest agent, snapshot-key validation, and secret rotation after
  restore.
- Kubernetes/Kata and KubeVirt sandbox adapters behind the same contracts.

Gate: fault injection proves no double commit during replica, network, runner,
PostgreSQL, or object-store disruptions; hostile fixtures cannot escape their
advertised isolation class.

### G6 — Windows, macOS, and full fleet migration

- PowerShell/cmd shell rules, Windows path and process semantics, services,
  Hyper-V/native providers, and signing environments.
- macOS shell/keychain semantics, native and Virtualization.framework
  providers, arm64 profiles, and GPU resource locks.
- Workflow-run chaining/API facade behavior required by `world-engine`, plus
  release/deployment canaries that cannot address production credentials.

Gate: the full existing fleet runs unchanged workflows with per-platform
differential reports. Production publish/deploy workflows enter only after
read-only and staging gates have held over an agreed soak period.

## `world-engine` compatibility ledger

The current corpus contains 29 workflows, 112 jobs, 822 workflow steps, 24
local actions (23 composite and one Node 24 action), 18 matrix jobs, four
reusable workflows, and more than 2,100 expression sites. It exercises Linux,
Windows, macOS, GPU-exclusive routing, 69 artifact uploads, 43 downloads,
caches, OIDC, environments, concurrency, service containers, GitHub
scripts/CLI/API calls, and attempt-aware workflow chaining.

The first diagnostic job is `ci-advisory-tidy.yml / setup` with Linux selected;
it tests dispatch input expressions and output command files without mutation.
It is followed by `ci.yml / Validate Workflows`, dry-run stale-ref cleanup, the
web service job, the Docker build job, artifact/matrix handoff, reusable Linux
engine builds, GPU shards, non-production workflow-run chains, then Windows and
macOS. Production, packages, Steam, recovery, and release workflows are never
used as early probes.

The hardest external boundary is explicit: GitHub does not let another system
insert arbitrary native Actions run/job/artifact records. Automata supplies its
own compatible results facade and Check Runs, but hard-coded `api.github.com`
or `gh` queries for upstream workflow-run records require either a GitHub
bridge or a targeted endpoint-routing change. This limitation is recorded per
workflow rather than hidden behind a broad “compatible” label.

## Verification disciplines

- Golden parser/planner fixtures retain source spans and upstream provenance.
- Differential tests compare the same commit/event on GitHub and Automata,
  normalizing only documented volatile fields.
- Model/state-machine tests cover every transition, lease race, retry, and
  stale fencing token.
- Adapter contract suites run unchanged against in-memory fakes, RustFS/S3,
  Podman, Firecracker, Kubernetes, and platform providers.
- Property and fuzz tests target YAML/expression parsing, protocol envelopes,
  command files, archives, path handling, redaction, and SSR model validation.
- Integration tests live in each crate's `tests/` tree; implementation modules
  contain no test-only architecture.
- Bootstrap CI checks formatting, strict Clippy, tests, dependency policy,
  frontend SSR/hydration, reproducible embedded assets, full build provenance,
  static ELF properties, `scratch` execution, checksums, SBOMs, and reproducible
  lockfile-driven third-party notices. Release promotion adds keyless signatures
  and attestations before a public release.

## Primary design references

- GitHub workflow and runner behavior: [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
  [runner groups](https://docs.github.com/en/actions/concepts/runners/runner-groups),
  and GitHub's own [container customization hook boundary](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/customize-containers).
- Container data model and rootless execution: [OCI runtime specification](https://github.com/opencontainers/runtime-spec),
  [Podman rootless operation](https://docs.podman.io/en/latest/markdown/podman.1.html),
  and [Podman system service](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html).
- MicroVM isolation: Firecracker [jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
  and [snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md).
- Kubernetes behavior: [Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/),
  [RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/),
  and [CRI](https://kubernetes.io/docs/concepts/containers/cri/); plus the
  [Kata architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md)
  and [KubeVirt architecture](https://kubevirt.io/user-guide/architecture/).
- Platform virtualization: Apple [Virtualization framework](https://developer.apple.com/documentation/virtualization)
  and Microsoft [Windows container isolation modes](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container).
