# Implementation and conformance plan

This plan treats GitHub Actions compatibility as a versioned product surface,
not as a YAML parsing feature. Each milestone ends in an executable gate. A
feature is unsupported until its semantics, failure behavior, and recovery
behavior have passed that gate.

## Architectural seams

GitHub Actions is the first workflow dialect. Its frontend parses and validates
source YAML into a dialect-owned source plan. A separate compiler lowers that
plan and event provenance into immutable WorkflowPlan v2 logical state; fenced
activation later expands bounded strategies and projects concrete JobIR v5.
The scheduler and providers never parse GitHub YAML or evaluate GitHub
expressions.

```text
GitHub frontend -> compiler -> WorkflowPlan -> fenced activation -> JobIR
                                                                  |
                                                         durable scheduler
                                                                  |
                                                            runner lease
                                                                  |
                                                       SandboxProvider
                                                                  |
                                      ExecutionEndpoint + ContainerEngine
```

The principal internal ports are deliberately narrower than a provider API:

- `WorkflowFrontend` owns bounded GitHub source parsing and dialect validation.
  `WorkflowCompiler` lowers the source plan into the logical workflow contract;
  fenced activation expands strategies and projects executable jobs. Reusable
  workflow execution and complete action pre/main/post orchestration remain
  separate, capability-gated phases.
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
- `BlobStore`, `ArtifactStore`, `CacheStore`, `SecretVault`, `ScmProvider`,
  `RepositoryCredentialBroker`, and `AuthenticationProvider` are
  provider-neutral ports. Adapters use owned, versioned data. Opaque
  secret-provider handles may be retained durably only as authenticated,
  encrypted provider-reference envelopes; plaintext handles never enter
  durable records, diagnostics, or audits.

Rust traits are used only within one release and address space. Guest agents,
privileged helpers, third-party providers, and remote runners use versioned RPC
over Unix sockets, vsock, or mTLS; Rust dynamic libraries are not a plugin ABI.
The production boundary is the checked, fully typed `automata.runner.v1`
protobuf adapter; it has no opaque JSON fields, runtime `protoc`, or Rust-layout
serialization. The adapter is wired into a bounded, mutually authenticated TLS
1.3 and HTTP/2 runner transport. The G1 product composition binds that transport
to the durable application handler, PostgreSQL-backed runner machine authority,
and the two product binaries. The end-to-end gate below remains the acceptance
boundary for compatibility claims.

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

The target distribution contains exactly two product executables, both
statically linked:

- `automata` can run any control-plane role and also provides the
  administration CLI;
- `automata-runner` can supervise host or guest execution.

The current v0.1 composition starts all control-plane roles together and has no
role selector. Its runner supports rootless Linux host execution; guest-agent
and non-Linux execution remain target-state work.

First-party adapters are compiled in and selected by configuration. Neither
binary needs a language runtime or shared library. Podman, KVM, Kubernetes,
and platform hypervisors are provider services invoked at runtime, not linked
application dependencies. The archive also preserves third-party license,
NOTICE, and copyright texts for both binaries and their embedded renderer/UI
assets; these compliance documents are data, not additional product binaries.

Human authentication is provider-pluggable. The first server adapter uses a
GitHub App and exposes browser and device-flow endpoints. On Linux with an
available Secret Service, `automata auth login`, `auth status`, and `auth
logout` are operational.
GitHub tokens are encrypted provider credentials, not general Automata bearer
tokens.
Explicit organization/team mappings grant Automata roles; membership never
implies administrator. Runner mTLS identity, workload tokens, SCM credentials,
and human sessions are separate trust domains.

Three product-composition boundaries remain explicit. The current-reference
CacheService-v2 upload/download path, digest verification, seven-day inactivity
retention, and runtime authority are composed, while base/default-branch
fallback, REST management, BuildKit compatibility, and physical object garbage
collection are not. Service-container execution is
authorized in the durable registration ceiling only by an exact immutable proxy
pin, then observed only after live provider verification; scheduling intersects
both inventories so either missing proof removes the feature. The checked-in
configuration still omits the unpublished helper image. Workload OIDC now
composes its issuer, durable storage, fail-closed optional control issuer, and
`/oidc/token` on the non-human Results listener. Migration 0037 completes
signed ingress with immutable positive numeric-owner evidence, and migration
0039 revalidates its receipt and current authority at reservation and every
mint. Workload OIDC nevertheless remains unsupported and unadvertised pending
external TLS and homogeneous multi-replica/key-fleet readiness. Its unbounded
authority and issuance-slot ledgers also prevent production retention claims
until a safe bounded archive or erasure path exists.

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
- Arch production runner admission fails before any listener or control
  session unless its nftables prerequisites are loaded or loadable from the
  running kernel's dependency index and an active rootless-Podman lifecycle
  succeeds. The lifecycle uses the exact configured binary, a cleared
  `HOME`/`PATH`/`XDG_RUNTIME_DIR`/`TMPDIR` environment, state-root scratch, and
  the exact `PrivateEgress` or `Disabled` (`--internal`) network policy.
- The lifecycle verifies created-network identity and policy, exclusive
  container attachment, loopback readiness, owned-resource cleanup, and
  post-delete absence. It is intentionally not evidence of profile-image
  existence or manifest conformance, cgroup/resource enforcement,
  privilege/root-filesystem policy, or the optional job-scoped Docker API;
  those remain operator assertions or other runtime checks. The configured
  Podman binary and helper `PATH` have root-owned, non-group/world-writable
  ancestry; private Podman process/state trees are runner-owned mode 0700 and
  never mounted into jobs. Startup revalidates its pre-probe filesystem metadata
  snapshot before provider construction. This is not a byte attestation.
- Ordinary `.github/workflows/ci.yml` remains valid GitHub Actions syntax and
  produces consumable checksummed bootstrap artifacts.

Gate: GitHub Actions builds generation-zero artifacts from a reviewed commit.

### G1 — durable single-node integration

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
- Complete official artifact and cache runtime protocols beyond the composed
  current-reference CacheService-v2 path: multipart uploads,
  base/default-branch fallback, REST management, physical object garbage
  collection, and the BuildKit cache endpoint.
- Job/service containers, dynamic ports, container actions, shell defaults,
  annotations, summaries, masks, timeouts, and cancellation.
- Matrix expansion, `needs`, outputs, status functions, implicit success
  guards, fail-fast, max-parallel, and reusable workflows.

Gate: Automata's CI uses its own uploaded static artifacts and caches, then
passes differential comparison against GitHub at the same commit.

### G3 — GitHub control-plane compatibility

- GitHub App installation/user authentication, Check Runs and statuses.
- Actions-compatible results, artifact, broader cache, OIDC, and selected REST
  facade. OIDC's product issuer and non-human Results-listener route are
  composed, but runner/registration capability support and its operational
  proof remain gated. Unsupported GitHub API calls currently fail closed; the
  product has no arbitrary job-scoped fallback proxy.
- Permissions, protected environments, approvals, secrets/vars, concurrency
  coalescing and cancellation, rerun attempts, schedules, and webhooks.
- Administration CLI endpoints for the complete declared command tree.

Gate: a safe read-only migration progression passes: event and platform
selection, workflow validation, then a dry-run maintenance workflow.

### G4 — representative heterogeneous Linux fleet

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
- Workflow-run chaining/API facade behavior required by complex repositories, plus
  release/deployment canaries that cannot address production credentials.

Gate: the full existing fleet runs unchanged workflows with per-platform
differential reports. Production publish/deploy workflows enter only after
read-only and staging gates have held over an agreed soak period.

## Migration acceptance contract

Private migration targets remain outside this public repository. Automata's
checked-in compatibility suites use synthetic workflows, public upstream action
fixtures, and generated capability manifests without copying or naming private
repositories. Operators may run an external acceptance harness against their own
workflow corpus, but its source, identifiers, counts, and rollout policy are not
part of Automata's source tree or documentation.

A migration should begin with non-mutating authorization and validation jobs,
then dry-run maintenance, service-container checks, Docker builds,
artifact/cache and matrix handoffs, reusable workflows, specialized runner
profiles, and non-production workflow chaining. Publish, deploy, recovery, and
release workflows enter only after read-only and staging gates have held for an
agreed soak period.

The hardest external boundary is explicit: GitHub does not let another system
insert arbitrary native Actions run/job/artifact records. Automata supplies its
own compatible results facade and plans to report through Check Runs, but
hard-coded `api.github.com` or `gh` queries for upstream workflow-run records
require either a GitHub bridge or a targeted endpoint-routing change. This
limitation is recorded per capability rather than hidden behind a broad
“compatible” label.

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
