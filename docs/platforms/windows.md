# Isolated Windows runners: Hyper-V container plan

This document defines the Windows execution boundary selected for Automata and
the work required to make it safe enough for hostile CI. It deliberately
separates code present in the repository from security and release claims that
still require trust routing, privileged-control isolation, crash recovery, and
evidence from real Windows hosts.

| Field | Value |
| --- | --- |
| Status | Component implementation in progress; not accepted for hostile or production workloads |
| Selected boundary | One fresh Hyper-V-isolated Windows container per job |
| Rejected Windows paths | Native host execution, process-isolated containers, and a parallel full-VM provider |
| Provider and config identity | `windows-hyperv` and `windows_hyperv` |
| Initial host | Windows Server 2025, x86-64, dedicated Hyper-V and Containers hosts |
| Initial network profile | Disabled |
| Security priority | Isolation integrity, trust routing, management-plane least privilege, destructive cleanup, then action parity |
| Work packages | WIN-ISO-00 through WIN-ISO-12; WIN-01 through WIN-03 remain capability work behind the isolation gate |
| Last reviewed | 2026-08-14 |

The words **must**, **must not**, **should**, and **may** express required,
recommended, and optional constraints. An unchecked task is planned work. It
must not be represented as an available runner capability.

## Decision

Automata has one Windows execution direction:

> Every admitted Windows job runs in a fresh Windows container whose effective
> isolation mode is Hyper-V. The product has no native-host or
> process-isolated fallback.

Microsoft distinguishes the two Windows container isolation modes. A
process-isolated container shares the host kernel. A Hyper-V-isolated
container runs inside a lightweight utility VM with its own kernel and is
treated as a robust security boundary. Automata selects only the latter. See
[Secure Windows containers](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-security),
[Hyper-V isolation for containers](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container),
and the
[Windows Security Servicing Criteria](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria).

This decision removes the earlier plan for a separate Generation 2 VM
provider. Hyper-V remains the kernel boundary, but the Windows container
runtime and Host Compute Service own the utility-VM lifecycle. This is a
narrower compatibility target than a general Windows VM: interactive desktop,
reboot-oriented workflows, arbitrary kernel drivers, nested virtualization,
and host device access are outside the first release.

The provider-neutral inventory classifies this profile as
`IsolationLevel::VirtualMachine` because Hyper-V supplies a separate kernel
and hardware boundary. That coarse security classification does not select a
full-VM backend: `SandboxLaunch::WindowsHyperVContainer`, provider
`windows-hyperv`, and the exact profile evidence distinguish the only Windows
launch shape.

## What the first Wave 1 pull request does

The first pull request is a provider and product-composition foundation. Its
implemented scope is intentionally smaller than production acceptance:

- [x] Remove the native Windows provider and its host identity, host
      filesystem, and host network capability path.
- [x] Add an explicit Hyper-V-container launch contract to provider-neutral
      execution types.
- [x] Add the `windows-hyperv` provider and `windows_hyperv` runner
      configuration.
- [x] Require a digest-qualified Windows AMD64 image already present on the
      host. Runtime pulls are disabled.
- [x] Invoke one absolute Windows container CLI executable whose bytes are
      pinned by SHA-256.
- [x] Create with explicit `--isolation hyperv`, `--network none`,
      `ContainerUser`, CPU, and memory values; bind the process ceiling in an
      immutable ownership label and enforce it with a nested guest Job Object.
- [x] Reject host binds, mounts, privileged mode, process isolation, host
      networking, and ownership-label drift when inspecting the effective
      container.
- [x] Use an in-image, bounded, versioned, one-request guest executable over
      anonymous standard input/output for probe, exec, and copy; use exact
      engine operations for wait and signal.
- [x] Make create and destroy retry-aware for a known, generation-bound handle;
      record checksummed, synchronized lifecycle events and verify absence
      after force removal.
- [x] On provider open, replay the bounded lifecycle journal, destructively
      reconcile journal-owned containers, enumerate Automata-labelled
      leftovers, and refuse registration if any unexplained resource remains.
- [x] Bind every GitHub-projected Windows requirement to VM-grade isolation and
      the exact `automata.core/windows-hyperv-container@v1` capability; advertise
      that capability only from `windows_hyperv` and enforce matching before
      placement.
- [x] Keep JavaScript/composite actions, services, nested job containers,
      egress, GPUs, ephemeral-disk claims, and parallel capacity unavailable
      unless their later packages pass.

This pull request does **not** prove or complete:

- [ ] authenticated workload trust classification;
- [ ] the AUTH-02 one-use trust decision and trust-to-provider admission grant;
- [ ] a least-privilege broker between a compromised runner and the container
      management endpoint;
- [ ] an independent watchdog and broker-mediated recovery while the runner is
      unavailable;
- [ ] externally enforced managed egress;
- [ ] a signed image factory and patch-rollout process;
- [ ] credential delivery or revocation inside the container;
- [ ] shipped-product execution on dedicated Hyper-V hardware;
- [ ] hostile cross-job, daemon-compromise, crash-transition, or cleanup soak;
- [ ] Windows Actions compatibility or a production capability claim.

The current direct CLI boundary is suitable for component development and an
offline laboratory. It is not the final hostile-workload management boundary.
A runner identity that can independently access the container-engine named pipe
could bypass fixed argument construction after runner compromise. WIN-ISO-02
must place that authority behind a narrow broker, or prove an equivalently
restricted engine service identity and API surface, before hostile jobs are
admitted.

## Non-negotiable invariants

The Windows profile is not releasable unless all of these hold:

1. **Hyper-V or no launch.** Create requests explicitly demand Hyper-V
   isolation. Effective state is inspected before workload execution. Missing,
   empty, process, default, or unknown isolation fails closed.
2. **No alternate provider.** The product contains no native Windows provider
   and cannot use a Linux, full-VM, or process-container fallback for a Windows
   assignment.
3. **One job, one container.** A container, writable layer, runtime identity,
   operation, generation, workspace, and credential are never reused for a
   second job.
4. **No host materialization.** Job commands and action hooks run only inside
   the Hyper-V-isolated container. Host directory mounts, named-pipe mounts,
   engine sockets, and general host shares are prohibited.
5. **No runner authority in the workload.** Runner mTLS keys, enrollment
   credentials, engine-management authority, object-store root credentials,
   and host service credentials never enter the container.
6. **Policy before data or secrets.** Image, isolation, ownership, resource,
   network, user, entrypoint, and generation evidence is accepted before source
   data or a job credential is delivered.
7. **Fail-closed trust routing.** Missing, stale, unknown, unauthenticated, fork,
   or Dependabot trust evidence cannot be upgraded to a secret-bearing profile.
   No capacity shortage may weaken placement.
8. **Outer network authority.** A future networked container cannot grant
   itself reachability. HCN/WFP and an upstream policy point remain
   authoritative outside the utility VM.
9. **Generation-fenced mutation.** Attach, execute, cancel, inspect, and destroy
   bind to the exact provider, operation-derived resource name, generation,
   profile digest, image digest, and spec digest.
10. **Destroy means absent.** Terminal completion, cancellation, timeout,
    runner failure, broker failure, engine failure, and host restart converge
    on verified removal or host quarantine.
11. **No global prune.** Cleanup acts only on exact resources whose ownership
    and generation are proven.
12. **Evidence before capability.** A component test, mock runtime, or
    successful container create cannot advertise production Windows support.

## Security model

### Protected assets

- the Windows host kernel, Hyper-V root partition, HCS/HCN services, container
  engine, registry, filesystem, network adapters, and management endpoints;
- runner and future broker binaries, configuration, service identities,
  journals, enrollment material, and mTLS keys;
- control-plane, source, Results, artifact, cache, and object-store authority;
- other jobs' writable layers, workspaces, processes, caches, logs, artifacts,
  network identities, and credentials;
- internal services, metadata endpoints, host management networks, and
  repository resources beyond a job's exact authority; and
- image, tool, guest executable, policy, evidence, and teardown integrity.

### Adversary

Assume workflow YAML, repository files, actions, dependencies, archives,
compilers, generated programs, and their output are malicious. They may:

- run arbitrary x86-64 user-mode code and exploit guest components;
- create processes, services supported by the container, tasks, users,
  junctions, reparse points, hard links, alternate data streams, and named
  objects inside the container;
- exhaust CPU, memory, processes, writable-layer space, logs, handles, sockets,
  and protocol frames;
- race cancellation, timeouts, attach, copy, destroy, runner restart, broker
  restart, engine restart, and host reboot;
- corrupt all writable container state and all untrusted protocol bytes;
- inspect their own environment and credentials intentionally issued to them;
  and
- attempt IPv4, IPv6, DNS, DoH, QUIC, proxy, loopback, link-local, metadata,
  and host-management bypasses if a networked profile is later enabled.

### Trusted computing base

The initial TCB includes:

- supported hardware, firmware, Microsoft hypervisor, and Windows Server host;
- the Hyper-V root partition, Host Compute Service, Host Network Service,
  selected container engine, and their configuration;
- the signed Automata runner and, before hostile admission, a restricted
  container-control broker and watchdog;
- the exact immutable Windows image, in-image guest executable, and runtime
  CLI or typed engine client;
- scheduler admission, trust classification, credential issuer, egress
  enforcement, and external evidence sink; and
- host security controls, patch state, service identities, ACLs, App Control,
  Defender, firewall, and monitoring.

The job, writable container layer, source tree, action/tool content, and every
workload observation are untrusted. Hyper-V isolation does not protect a job
from a malicious host administrator, and it does not make a broadly exposed
container-management endpoint safe.

### Required outcomes

| Threat | Required outcome |
| --- | --- |
| Container or guest-kernel compromise | Remains inside the utility VM and cannot obtain root-partition authority |
| Runner compromise | Cannot submit arbitrary engine operations or broaden the signed one-use admission decision |
| Broker compromise | Has no repository, Results, object-store root, or runner-enrollment credential; blast radius is the dedicated host |
| Job-to-job attack | Fresh container, writable layer, identity, namespace, generation, token, and cache scope; no peer routes |
| Process-isolation downgrade | Effective inspection rejects the container before copy or exec |
| Stale handle or replay | Ownership, spec digest, operation-derived name, and generation mismatch reject mutation |
| Runner/broker/engine crash | Durable reconciliation destroys the exact owned container or drains the host |
| Host restart | Startup inventory reconciles all owned resources before capacity is registered |
| Image or runtime drift | Digest, signature, OS, architecture, policy, or patch mismatch rejects registration or launch |
| Network policy failure | Container remains disconnected and receives no credential |
| Cleanup uncertainty | Assignment does not pass; the resource and, when necessary, host remain quarantined |

## Why Hyper-V-isolated containers

| Option | Kernel boundary | Compatibility | Automation | Decision |
| --- | --- | --- | --- | --- |
| Native process and Job Object | Shared host kernel and identity surface | Broad | Straightforward | Removed |
| Restricted token or AppContainer | Shared host kernel; application boundary | Too narrow for general CI | Custom | Not a runner backend |
| Process-isolated Windows container | Shared host kernel | Server/container workloads | Mature | Prohibited |
| Hyper-V-isolated Windows container | Separate utility VM and kernel | Windows container workload subset | Mature lifecycle | Selected |
| Full Generation 2 VM | Separate guest kernel and full OS | Broadest Windows compatibility | Separate VM/image/broker stack | Not planned |
| Windows Sandbox | Separate kernel, client-oriented | Interactive client workloads | Poor fleet fit | Not planned |

The selected boundary reduces custom VM lifecycle, image, boot, guest-channel,
and virtual-disk machinery. It also imposes deliberate limitations:

- container images and host builds must satisfy Windows version-compatibility
  rules;
- interactive desktop, RDP, host device access, arbitrary drivers, nested
  virtualization, and normal reboot workflows are unavailable;
- Docker actions, sibling service containers, and job containers are not
  automatically supported merely because the job itself is a Windows
  container;
- writable-layer storage and container runtime semantics differ from a full
  GitHub-hosted Windows VM; and
- runtime/daemon authority becomes a critical privileged boundary that must be
  isolated from the workload-facing runner.

## Architecture

### First-pull-request component path

```text
control plane
    |
    | runner assignment and immutable environment profile
    v
automata-runner
    |
    | fixed argv, empty environment, bounded stdio
    v
pinned container CLI ----> local engine named pipe ----> HCS / Hyper-V
                                                        |
                                                        v
                                      fresh Hyper-V-isolated container
                                                        |
                                      one-request guest executable over stdio
```

The runner verifies image metadata, creates the container, inspects effective
runtime state, starts it, probes the guest executable, and then exposes the
provider-neutral execution endpoint. This path is useful for exact component
testing. It does not yet isolate engine-management authority from a compromised
runner.

### Production target

```text
authenticated event
    |
    v
EVT-01 event registry -> AUTH-02 trust/authority reduction
    |                              |
    +------------------------------+
                   |
                   v
        WIN-ISO-01 placement decision
                   |
          one-use signed admission grant
                   |
                   v
        unprivileged automata-runner
                   |
          narrow local authenticated IPC
                   |
                   v
        restricted container broker/watchdog
          |             |              |
          |             |              +--> durable inventory/evidence
          |             +--> HCN/WFP and egress policy
          +--> typed engine/HCS lifecycle
                           |
                           v
              Hyper-V-isolated Windows container
                           |
               bounded one-request guest protocol
```

The broker accepts typed product operations, never caller-supplied command
lines or raw engine/HCS documents. It independently checks the admission grant,
operation identity, generation, profile, image, resources, network policy, and
deadline. Its service identity owns only Automata-labelled resources. The
runner owns repository-facing execution but not arbitrary container
administration.

## Exact first-provider contract

### Configuration

The provider configuration is closed:

- an absolute private state root;
- an absolute `.exe` path for the local runtime CLI;
- the SHA-256 expected for that exact CLI file;
- a normalized drive-qualified path to the guest executable inside the image;
  and
- a bounded lifecycle timeout.

Current runner product schema v4 selects exactly one provider. The Windows
provider requires one or more digest-attested environment profiles with:

- an immutable digest-qualified Windows image reference;
- a Windows keepalive executable and literal argument vector;
- an in-container Windows workspace root;
- Windows shell paths located in the image; and
- network disabled, writable container root, unprivileged execution, zero GPU,
  and zero claimed ephemeral-disk allocation.

Example values are placeholders, not deployable image or runtime attestations.
Operators must replace every placeholder digest with evidence from their own
build and host qualification.

### Runtime invocation

The current adapter:

- starts only the configured absolute executable;
- clears inherited environment variables;
- passes an argument vector instead of a shell command;
- selects the local Windows-engine named pipe explicitly;
- bounds stdin, stdout, stderr, time, and retained output;
- kills and reaps the CLI on cancellation or timeout; and
- redacts argument and payload bytes from debug output.

Runtime executable digest verification reduces accidental replacement and
path confusion. It is not code-signing validation, revocation checking, or a
complete time-of-check/time-of-use guarantee. WIN-ISO-02 must define the final
binary trust and service-update contract.

### Create and inspect

Create uses:

- no pull;
- exact operation-derived resource name;
- explicit Hyper-V isolation;
- disabled network;
- `ContainerUser`;
- requested memory and CPU values plus the immutable process-ceiling label;
- exact ownership, sandbox, generation, profile, profile-digest, spec-digest,
  image, and Hyper-V-required labels; and
- the image's configured keepalive command as entrypoint.

Before success, image inspection must report one Windows AMD64 image whose
repository digest matches the profile. Container inspection must report:

- the exact resource name and all ownership bindings;
- effective isolation equal to Hyper-V;
- network mode equal to none;
- no privileged flag, host bind, or mount;
- `ContainerUser`;
- exact image, entrypoint, command, CPU, memory, and process-ceiling label; and
- running state after start.

Any mismatch is a conflict or ownership failure. The provider never repairs
an unexpected resource in place.

### Guest endpoint

The guest executable is included in the immutable image. Each operation runs a
fresh `container exec` as `ContainerUser`, carries one length-bounded
versioned frame over anonymous stdin, and expects one bounded response on
stdout with empty stderr.

The protocol supports the provider-neutral probe, exec, file write, and file
read requirements needed by the current runner. Every exec request carries the
configured process ceiling, and the Windows guest creates the command inside a
nested Job Object before it can run. The endpoint maps signal and wait to exact
container-engine operations. Paths, environments, arguments, timeouts, output,
and file bytes remain bounded. Protocol failure is not interpreted as
successful job output.

This stdio transport does not expose a guest listener, host share, Docker pipe,
or reusable session to the workload. The engine-mediated exec operation is
still privileged management traffic and therefore belongs behind the future
broker.

### Destroy and known-handle retry

Destroy first inspects exact ownership and generation, force-removes the
container and anonymous volumes, then verifies absence. A missing resource is
idempotent success.

Create can recognize an existing exact resource for the same spec and
generation. A changed digest, label, entrypoint, limit, image, or effective
isolation is a conflict rather than a reuse opportunity.

The provider includes component-level recovery: a versioned, checksummed,
sequence-checked, synchronized append-only journal records create and destroy
intent/completion. On open it removes each journal-owned live container,
verifies absence, then enumerates Automata-labelled containers and fails if any
remain unexplained. Corrupt interior records fail closed; only an unterminated
tail is truncated.

This is not production recovery. It has not passed real engine/host crash
injection, it cannot act while the runner process is unavailable, and it does
not provide a restricted broker, independent watchdog, external quarantine
controller, evidence acknowledgement, journal compaction, or fleet
return-to-service flow. Those remain blocking WIN-ISO-05 and WIN-ISO-09 work.

## Windows API and runtime map

Automata should prefer the smallest supported surface that provides typed,
recoverable ownership. No runner-originated raw JSON, WMI query, PowerShell
script, or HCS document crosses a privilege boundary.

| Surface | What it provides | Automata use |
| --- | --- | --- |
| Container runtime CLI | Mature create, inspect, start, exec, wait, kill, remove, and image inspection | Implemented component adapter; absolute path and SHA-256 pinned |
| Container engine API | Typed container/image operations over a local service endpoint | Candidate broker-to-engine boundary; endpoint never available to job or general runner code |
| [Host Compute System](https://learn.microsoft.com/en-us/virtualization/api/hcs/overview) | Windows compute-system lifecycle beneath container runtimes | Underlying platform; direct integration only if the broker can own a smaller and more recoverable contract |
| [Host Compute Network](https://learn.microsoft.com/en-us/windows-server/networking/technologies/hcn/hcn-top) | Endpoints, namespaces, networks, policies, and inventory | Future externally enforced disabled/private/managed-egress profiles |
| [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) | Host network filtering and ALE authorization | Defense in depth and destination enforcement outside the utility VM |
| Service SID and service ACL APIs | Narrow persistent Windows service identity | Broker, watchdog, runtime endpoint, state, log, and IPC ACLs |
| DPAPI/CNG/TPM-backed custody | Host credential protection and key operations | Runner/broker enrollment and admission-verification keys; never workload data |
| Job Objects | Process-tree custody and resource accounting | Defense in depth inside the container and for broker-launched local helpers |
| Restricted tokens and process mitigations | Reduced local helper authority | Broker/relay defense in depth, not a replacement for Hyper-V |
| Win32 handle-based filesystem APIs | Open-reparse-point, final-path, volume, owner, DACL, link and file-ID checks | Private host state, executable, manifest, journal, and update validation |
| ETW, Event Log, Defender and performance counters | Host/platform evidence and detection | External operational evidence; job cannot erase accepted records |

### API questions that must be spiked

- Can the selected engine service and broker run under service SIDs without
  adding the runner account to a broad local container-administrator group?
- What exact ACL protects the engine endpoint, broker IPC, state root, logs,
  update channel, and runtime executable?
- Can the broker use a typed engine client without accepting ambient
  environment configuration, contexts, plugins, credential helpers, or
  arbitrary registry endpoints?
- Which engine/HCS events provide exact create/start/exec/kill/remove outcomes
  after timeout, service restart, or host reboot?
- How are Hyper-V isolation and network state independently measured rather
  than inferred only from requested CLI arguments?
- Which HCN policy surfaces support stable default-deny, DNS, proxy, and
  destination enforcement for Hyper-V-isolated Windows containers?
- What resource fields are genuinely host-enforced for this isolation mode on
  the selected Windows Server and engine versions?
- How are engine updates, daemon configuration, Windows patches, and image
  patches rolled out atomically without a mixed unqualified fleet?

## Host baseline

A Windows execution host is infrastructure, not a general developer machine.
Before registering capacity it must prove:

- dedicated supported hardware with virtualization enabled;
- Windows Server 2025 x86-64 at an approved build and patch floor;
- Hyper-V and Containers roles installed and healthy;
- an approved container engine configured for Windows containers;
- no interactive user workload, development daemon, mutable plugin directory,
  or unrelated container tenancy;
- Secured-core features where supported, Secure Boot, TPM, VBS/HVCI,
  Credential Guard, Defender, tamper protection, and firewall policy at the
  approved state;
- App Control policy for the runner, broker, engine client, guest image tooling,
  and reviewed maintenance tools;
- runner and broker service SIDs with no interactive or network logon beyond
  exact service needs;
- engine management endpoint inaccessible to job containers and, before
  hostile admission, inaccessible to the unprivileged runner;
- private state/log/update roots on approved local fixed volumes with expected
  owner, protected DACL, inheritance, reparse, link, and volume identity;
- sufficient non-overcommitted memory, CPU, writable-layer space, log space,
  and cleanup reserve for configured slots;
- clock, event-log forwarding, crash dumps, health probes, and drain controls;
  and
- startup reconciliation complete with no unexplained Automata-labelled or
  ambiguous resources.

Failure or uncertainty drains the host. An operator cannot override a failed
isolation, ownership, patch, engine, or recovery check by changing a runner
label.

## Image supply chain and compatibility

Windows container compatibility depends on host build, image build, and
isolation mode. Hyper-V isolation relaxes some host/image kernel coupling
because the container receives its own kernel, but it does not eliminate the
documented compatibility matrix. Exact combinations must be tested and
published. See
[Windows container version compatibility](https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility).

The image factory must:

- start from an exact Microsoft Windows Server Core digest approved for the
  host channel;
- install the exact Automata guest executable, PowerShell, Git, Node, Python
  only when supported, certificate policy, and action tool manifest;
- avoid mutable package-manager sources during job startup;
- generate an SBOM and vulnerability/patch report;
- sign the image manifest and retain base/image/tool/agent provenance;
- run offline shell, path, environment, encoding, cancellation, and guest
  protocol tests;
- run a real Hyper-V-isolated create/inspect/exec/destroy smoke on each exact
  host build;
- publish immutable digests only after security review; and
- rotate or revoke an image without permitting mutable-tag fallback.

No host directory or shared mutable tool cache is mounted into the container.
Source, action content, and outputs cross only through bounded provider-neutral
copy and result interfaces. Persistent caches and artifacts use their product
services and trust namespaces, not writable container-layer reuse.

## Network model

### Phase 1: offline only

The first profile creates with network mode none and verifies that effective
state before the guest probe. This is the only network claim made by the first
pull request.

Real-host acceptance must attempt:

- IPv4 and IPv6 external, host, peer, loopback, link-local, and metadata
  destinations;
- DNS using configured, hard-coded, multicast, and local proxy endpoints;
- DoH, QUIC, raw sockets available to the container, port forwarding, and
  engine special names; and
- race conditions during start, inspect, exec, kill, and engine restart.

### Phase 2: managed egress

A later profile may add egress only after HCN/WFP and an upstream proxy or
gateway enforce:

- default deny before container start;
- no route to host management, engine, broker, runner, peers, metadata, or
  internal control services;
- destination, port, protocol, DNS, redirect, and proxy policy bound to the
  exact attempt and profile;
- explicit handling of IPv6, DNS rebinding, signed URLs, CDNs, custom CAs,
  package managers, and OIDC;
- connection, byte, rate, and log bounds;
- externally retained allow/deny evidence; and
- synchronous policy removal during destroy and startup reconciliation.

Guest Windows Firewall and Defender add defense in depth but never constitute
the outer policy.

## Identity, filesystem, and secret handling

- The workload default is `ContainerUser`. A future administrator profile
  requires a separate capability, image, host pool, and hostile acceptance
  matrix.
- The engine daemon, broker, runner, and watchdog use distinct service
  identities. The guest never receives any of their tokens or handles.
- The writable container layer is disposable and is not a durable workspace.
  No host bind, volume, pipe, device, or engine endpoint is admitted.
- Copy operations validate normalized target-platform paths and hard size
  bounds. Archive extraction requires a separate reviewed policy before
  artifact/action features use it.
- Job credentials are minted only after trust, effective isolation, image,
  user, network, and ownership evidence is accepted.
- Credentials are attempt-scoped, minimum-authority, short-lived, auditable,
  and revoked on terminal execution, lease loss, cancellation, or cleanup
  uncertainty.
- Secrets never appear in resource names, labels, engine arguments, durable
  errors, debug output, image layers, or externally visible diagnostics.
- Success evidence must be acknowledged outside the container before destroy
  can erase local logs.

## Dependency graph

The trust chain is blocking and ordered:

```text
EVT-01 versioned authenticated event registry
    |
    v
AUTH-02 trust classification and authority reduction
    |
    v
WIN-ISO-01 fail-closed Windows placement
    |
    +--> WIN-ISO-02 restricted management boundary
    +--> WIN-ISO-03 signed image supply chain
    +--> WIN-ISO-04 exact contracts and product config
                 |
                 v
       WIN-ISO-05 lifecycle and recovery
                 |
                 v
       WIN-ISO-06 guest/data foundation
                 |
        +--------+--------+
        v                 v
 WIN-ISO-07 network   WIN-ISO-08 credentials/data
        +--------+--------+
                 v
       WIN-ISO-09 operations/reconciliation
                 |
                 v
       WIN-ISO-10 action integration
                 |
                 v
       WIN-ISO-11 hostile/fault gate
                 |
                 v
       WIN-ISO-12 production rollout
```

Provider work can build offline component seams before AUTH-02 lands, as this
pull request does. It cannot advertise, enroll, or receive hostile production
work until the complete EVT-01 -> AUTH-02 -> WIN-ISO-01 path is accepted.

## Work packages

### WIN-ISO-00 — Decision record and API spikes

Current pull-request scope:

- [x] Select Hyper-V-isolated Windows containers as the only Windows backend.
- [x] Prohibit native and process-isolated fallback.
- [x] Define provider/config identity, capability limits, trust dependencies,
      risks, milestones, and acceptance evidence.
- [x] Implement a CLI-backed laboratory provider seam and injectable component
      test boundary.
- [ ] Record a reviewed ADR for engine choice, engine version/update policy,
      broker API, endpoint ACL, ownership schema, network design, and recovery
      inventory.
- [ ] Run service-identity, real HCS/engine, effective-isolation, resource,
      host-reboot, and Windows-version compatibility spikes.

Exit: decisions are reviewed, real-host spike evidence is retained, and every
unresolved safety question becomes a blocking work item rather than an
implicit default.

### WIN-ISO-01 — Authenticated fail-closed placement

**Dependencies:** EVT-01, then AUTH-02.

- [ ] Carry authenticated event identity, repository/ref provenance, actor,
      fork/Dependabot status, policy version, requested secrets, and trust
      classification into scheduling.
- [x] Define the exact `WindowsHyperVContainer` requirement, pair it with
      `IsolationLevel::VirtualMachine`, carry it through JobIR/protobuf replay,
      and reject generic VM or alternate-provider capabilities before lease.
- [ ] Reject unknown, missing, stale, or unsigned authenticated placement
      evidence through the AUTH-02 one-use grant.
- [ ] Ensure no scheduler, rerun, recovery, administrative API, or capacity
      fallback can select an alternate Windows boundary.
- [ ] Bind a one-use admission grant to attempt, operation, generation,
      profile, image, resources, network policy, authority, and expiry.
- [ ] Retain reason codes and the trust-decision digest without raw secrets or
      provider payloads.
- [ ] Test public fork, private fork, Dependabot, deleted actor, changed ref,
      replay, stale policy, missing fields, and capacity outage.

Exit: unsupported or insufficiently trusted jobs fail before lease; no Windows
work reaches a runner through an unbound trust decision.

### WIN-ISO-02 — Restricted management boundary

The first PR implements fixed-argv CLI invocation and effective inspection but
does not complete this package.

- [x] Pin the absolute runtime executable by SHA-256 and clear its environment.
- [x] Bound command time, stdin, stdout, stderr, and debug disclosure.
- [ ] Move engine access behind a typed, authenticated local broker.
- [ ] Give runner, broker, watchdog, and engine distinct service SIDs and exact
      endpoint/filesystem rights.
- [ ] Reject raw CLI strings, engine JSON, HCS documents, image references,
      labels, names, paths, or filters supplied by the caller.
- [ ] Validate a signed one-use admission grant independently.
- [ ] Install, update, rollback, and attest broker/runtime binaries.
- [ ] Prove runner compromise cannot open the engine endpoint or manage
      non-Automata containers.

Exit: the workload-facing runner has no general container-management authority,
and the broker can mutate only exact generation-bound Automata resources.

### WIN-ISO-03 — Hermetic Windows image supply chain

- [ ] Define the exact Server Core host/image compatibility matrix.
- [ ] Build a digest-pinned image containing guest executable and reviewed
      shells/tools without job-time mutable installation.
- [ ] Produce signature, SBOM, provenance, vulnerability, patch, tool, and
      compatibility manifests.
- [ ] Verify image identity through an independent registry/signature policy,
      not only local engine metadata.
- [ ] Implement emergency revocation, staged rotation, rollback, and stale-host
      drain.
- [ ] Reject mutable tags, unexpected layers, wrong OS/architecture, absent
      repository digest, and an unapproved guest executable.

Exit: a reproducible signed image passes offline and real-host qualification
for each advertised profile.

### WIN-ISO-04 — Provider-neutral contract and product configuration

First-PR component scope:

- [x] Add the explicit Windows Hyper-V container launch variant.
- [x] Keep the current schema-v4 `windows_hyperv` configuration and remove
      `windows_native`.
- [x] Require disabled network, unprivileged workload, writable container root,
      no services, zero GPU, and no ephemeral-disk claim.
- [x] Advertise only whole-job lifecycle, exec/copy/signal/wait, environment,
      resource-limit, writable-root, and disabled-network component
      capabilities.
- [x] Probe each configured profile through create, inspect, attach, shell
      execution, and destroy before runner startup.
- [ ] Bind trust and one-use admission requirements from WIN-ISO-01.
- [ ] Add broker and host-security attestation to profile admission.
- [ ] Version exact image/tool/network/authority evidence in the capability
      registry.

Exit: invalid or ambiguous profiles fail before runner registration; product
acceptance remains gated on real Windows evidence.

### WIN-ISO-05 — Lifecycle and crash recovery

- [x] Implement exact-name create/inspect/start/kill/wait/remove for a known
      handle with ownership and generation checks.
- [x] Return uncertain outcomes with recovery custody where the provider
      contract permits.
- [x] Persist bounded create/destroy intent and completion, operation,
      generation, profile, handle, resource name, and spec fingerprint in a
      checksummed synchronized provider journal.
- [x] At provider startup, reconcile journal-owned containers, enumerate
      Automata-labelled leftovers, and fail closed without global prune.
- [ ] Extend durable state to the broker/engine identity, deadlines, external
      evidence acknowledgement, and host quarantine/return-to-service state.
- [ ] Reconcile create/start/exec/kill/remove uncertainty, engine restart,
      runner restart, broker restart, host reboot, full disk, corrupt journal,
      and missing resource.
- [ ] Quarantine label collisions, ambiguous ownership, unexpected mounts,
      isolation drift, and resources with no provable owner.
- [ ] Add an independent deadline watchdog that can remove a container when the
      runner is dead.

Exit: crash injection at every durable transition converges to exact resume,
verified removal, or drained-host quarantine with no unexplained leak.

### WIN-ISO-06 — Guest execution and offline data path

- [x] Include a bounded versioned guest executable contract.
- [x] Use one request per engine-mediated exec with anonymous stdio.
- [x] Support guest probe, exec, copy-to, and copy-from plus endpoint signal,
      wait, output records, timeouts, cancellation, and bounded file content.
- [x] Default guest execution to `ContainerUser`.
- [ ] Bind every guest request to the signed admission grant and expected
      container identity through the broker.
- [ ] Add adversarial path, reparse, hard-link, alternate-stream, Unicode,
      case-folding, reserved-name, frame, environment, and process-tree tests
      on real Windows.
- [ ] Prove timeout and cancellation remove all descendants and prevent a
      later exec in the same failed container.
- [ ] Retain external evidence before local teardown.

Exit: an offline shipped runner executes shell steps through the real provider
and destroys all owned state, but no network or action capability is implied.

### WIN-ISO-07 — Externally enforced network profiles

- [x] Initial product profile requests and inspects network disabled.
- [ ] Prove no-network behavior against the full IPv4/IPv6/DNS/host/peer/
      metadata bypass matrix.
- [ ] Define HCN/WFP ownership and a private managed-egress network profile.
- [ ] Apply default deny before start and remove policy during reconciliation.
- [ ] Bind DNS, proxy, destination, protocol, byte, connection, and time limits
      to the attempt.
- [ ] Retain network decisions externally and test engine/HCN/host crash races.

Exit: offline remains default; any advertised egress profile has authoritative
outer enforcement and cannot reach management or another job.

### WIN-ISO-08 — Credentials, source, artifacts, and cache

**Dependencies:** AUTH-03 and the applicable source/Results/artifact/cache
contracts.

- [ ] Issue credentials only after WIN-ISO-01 placement and effective provider
      evidence.
- [ ] Deliver only job-scoped, minimum-authority, short-lived values.
- [ ] Revoke on completion, cancellation, lease loss, timeout, crash, or cleanup
      uncertainty.
- [ ] Transfer source/action/artifact/cache bytes through bounded product
      interfaces with digest and archive policy.
- [ ] Keep host mounts, shared mutable tool caches, engine credentials, and
      ambient cloud credentials absent.
- [ ] Run secret canaries across labels, inspect output, logs, errors, crash
      dumps, layers, caches, artifacts, and subsequent jobs.

Exit: a networked job receives only its exact authority after isolation, and no
value survives into another attempt or host evidence.

### WIN-ISO-09 — Operations, watchdog, and reconciliation

- [ ] Install runner, broker, watchdog, engine policy, and evidence forwarding
      as reviewed services.
- [ ] Attest host build, roles, virtualization, security controls, service
      tokens, endpoint ACLs, runtime/image digests, capacity, and clean
      inventory before registration.
- [ ] Define alerts, drain, quarantine, forensic capture, credential
      revocation, destructive cleanup, host reimage, and return-to-service.
- [ ] Exercise low disk, memory pressure, engine unavailable, HCS/HCN failure,
      evidence sink failure, clock drift, update interruption, and host reboot.
- [ ] Publish SLOs for launch, cancellation, cleanup, recovery, patch age, and
      unexplained leaks.

Exit: operators can safely detect, stop, reconcile, investigate, reimage, and
return a Windows host without accepting unknown state.

### WIN-ISO-10 — Windows runtime and action integration

**Dependencies:** WIN-01, WIN-02, RUN-01 through RUN-03, ACT-01, and
WIN-ISO-06 through WIN-ISO-09 as applicable.

- [ ] Run PowerShell 7, Windows PowerShell, cmd, and optional Python with exact
      Windows argv, encoding, CRLF, environment, working-directory, and exit
      semantics.
- [ ] Run Node action pre/main/post and nested composite phases inside the same
      isolated container.
- [ ] Materialize actions without host execution or host mounts.
- [ ] Support only product artifact/cache/source interfaces accepted by their
      packages.
- [ ] Reject Docker actions, nested job/service containers, devices,
      interactive desktop, signing, reboot, and administrator requirements
      before user code unless separately accepted.

Exit: the exact action-ready profile passes through shipped product processes
without changing the isolation boundary.

### WIN-ISO-11 — Hostile and fault acceptance

- [ ] Launch the shipped control plane, runner, broker, engine integration, and
      guest executable on dedicated Windows Hyper-V hosts.
- [ ] Attempt host filesystem, registry, process, token, pipe, engine endpoint,
      network, peer, credential, cross-job, and persistence access.
- [ ] Attempt process-isolation downgrade and inspect/request mismatch.
- [ ] Crash every component at every durable transition and reboot the host.
- [ ] Exercise reparse, hard-link, alternate-stream, archive, Unicode,
      case-insensitive, reserved-name, output, frame, process, memory, CPU,
      disk, and log abuse.
- [ ] Retain independent evidence and treat any leak, downgrade, unknown
      outcome, or cleanup ambiguity as failure.

Exit: IT-09 hostile, recovery, network, cross-job, and destructive-cleanup
evidence passes for exact release artifacts. Component mocks cannot satisfy
this package.

### WIN-ISO-12 — Staged rollout and production acceptance

- [ ] Progress through offline lab, internal non-secret canary, managed-egress
      canary, trusted secret jobs, untrusted private pull requests, public/fork
      pull requests, and parallel capacity.
- [ ] Keep unavailable profiles unadvertised at every stage.
- [ ] Define immediate drain, credential revocation, container destruction,
      host quarantine, and rollback for every stage.
- [ ] Complete WIN-03, IT-09, GATE-02, operations review, and published
      compatibility limits.
- [ ] Confirm no native provider/config/schema path remains and no
      process-isolated fallback exists.

Exit: the exact Hyper-V-container profile is the production Windows route and
its compatibility, security, patch, recovery, capacity, and support contracts
are public.

## Acceptance matrix

### Component gate in this pull request

- provider-neutral types cannot express native Windows launch;
- configuration accepts exactly one Windows Hyper-V provider and rejects old,
  ambiguous, cross-platform, host-privileged, mounted, or networked shapes;
- runtime command construction is fixed, bounded, environment-cleared, and
  redacted;
- injected runtime tests cover create/inspect/start/probe/exec/copy/signal/
  wait/destroy, drift, cancellation, timeout, malformed output, and uncertain
  outcomes;
- non-Windows builds expose an explicit unsupported boundary; and
- repository tests, strict Clippy, documentation verification, and diff checks
  pass.

This gate demonstrates code shape. It does not demonstrate Hyper-V execution.

### Real-host isolation gate

- exact Windows Server, engine, CLI, image, and guest digests are retained;
- requested and effective isolation are Hyper-V;
- the container has no host mount, pipe, device, privileged flag, host/peer
  network, or engine endpoint;
- CPU and memory limits are enforced; unsupported disk/process claims are
  either proven or withheld;
- cancellation and timeout stop all workload descendants;
- force removal leaves no container, writable layer, volume, endpoint, policy,
  credential, or process;
- engine, runner, broker, guest, and host failures reconcile safely; and
- a second job cannot observe any first-job identity or state.

### Product trust gate

- EVT-01 authenticates and versions the event;
- AUTH-02 derives trust and reduces authority;
- WIN-ISO-01 binds the exact placement grant;
- the runner cannot open the management endpoint;
- credentials arrive only after effective isolation and policy evidence; and
- unsupported jobs fail before a lease or before any user-controlled command.

### Functional gate

- admitted shells match documented Windows semantics;
- checkout, one pinned JavaScript action, one local composite, artifact
  upload/download, cache, output, summary, and cancellation pass only after
  their dependencies;
- paths with spaces, Unicode, case collisions, long paths, and CRLF are tested;
- missing tools withhold exact capabilities; and
- unsupported nested containers, services, interactive, device, signing,
  reboot, and admin behavior fail early.

## Milestones

| Milestone | Packages | Meaning |
| --- | --- | --- |
| M0 — component foundation | First PR portions of WIN-ISO-00/02/04/05/06 | Container-only types, config, provider, effective-state validation, offline guest seam; no hostile claim |
| M1 — routing safety | EVT-01 -> AUTH-02 -> WIN-ISO-01 | Authenticated trust cannot downgrade or select another Windows boundary |
| M2 — restricted offline host | WIN-ISO-02/03/05/06/09 | Brokered management, signed image, real offline host, crash recovery, destructive cleanup |
| M3 — managed data and egress | WIN-ISO-07/08 | Exact outer network policy and job-scoped credentials/data |
| M4 — action-ready | WIN-01, WIN-02, WIN-ISO-10 | Shell and admitted action semantics inside the same boundary |
| M5 — security acceptance | WIN-ISO-11, IT-09 | Hostile, cross-job, downgrade, crash, reboot, and cleanup evidence |
| M6 — production | WIN-03, GATE-02, WIN-ISO-12 | Staged Windows capability and published operations contract |

## Parallel implementation lanes

Once the component contracts in this pull request settle, independent owners
can work in parallel without claiming early completion:

| Lane | Scope | Serialization points |
| --- | --- | --- |
| A — trust | EVT-01, AUTH-02, WIN-ISO-01 | event/trust schema, scheduler requirements, admission grant |
| B — host control | WIN-ISO-02, WIN-ISO-05, WIN-ISO-09 | broker protocol, service ACLs, ownership ledger, recovery |
| C — image and guest | WIN-ISO-03, WIN-ISO-06 | image/profile manifest and guest protocol |
| D — network and credentials | WIN-ISO-07, WIN-ISO-08 | network policy and credential issuance |
| E — runtime parity | WIN-01, WIN-02, WIN-ISO-10 | executor/action contracts and advertised capabilities |
| X — conformance | WIN-ISO-11, IT-09, GATE-02 | release artifacts, dedicated hosts, evidence ledger |

The root Cargo files, runner config schema, launch enum, advertised capability
model, provider ID, guest protocol, image manifest, and compatibility claims
each have one integration owner at a time.

## Risks and mitigations

| Risk | Consequence | Required mitigation |
| --- | --- | --- |
| Effective mode silently becomes process isolation | Host kernel exposed to hostile code | Explicit Hyper-V create plus independent inspect; mismatch is terminal and drains host if unexplained |
| Runner can access engine endpoint | Runner compromise becomes host container administration | Restricted broker/service identity and endpoint ACL before hostile admission |
| Runtime or image mutable tag/drift | Unreviewed code enters TCB | Absolute runtime path and digest, signed immutable image manifest, no pull, revocation and rollout policy |
| Windows host/image mismatch | Startup failure or unsupported behavior | Exact compatibility matrix and per-build real-host qualification |
| Container limitations mistaken for VM parity | Late workflow failures or unsafe workarounds | Exact capabilities; reject desktop, drivers, nested containers, services, reboot, devices, and admin until proven |
| Network none is not truly isolated | Host/internal access | Adversarial real-host matrix and outer HCN/WFP evidence |
| Writable-layer or resource exhaustion | Host denial of service | Reservation, quotas, disk headroom, deadline watchdog, drain on low capacity |
| Engine restart loses outcome | Orphans or reuse | Durable ownership ledger, startup enumeration, exact reconciliation, no global prune |
| Labels treated as authorization | Collision or attacker-selected cleanup | Operation-derived names plus signed grant, engine identity, generation, digests, and broker-owned ledger |
| Guest protocol parser compromise | Broker/runner compromise | One-request bounded frames, no listener/share, hostile parser tests, broker isolation |
| Secrets leak through engine metadata or logs | Cross-boundary disclosure | No secrets in argv/labels/errors; late issuance, redaction, canaries, external evidence |
| Shared cache reintroduces state | Cross-job contamination | Product service namespaces only; no host mount or writable-layer reuse |
| Capacity outage triggers fallback | Isolation downgrade | No alternate Windows provider; jobs remain queued or fail unsupported |

## Performance and reliability budgets

The first real-host spike must measure rather than guess numeric targets. The
release review should ratify or replace these initial constraints:

| Measure | Initial target |
| --- | --- |
| Isolation downgrade | Exactly zero |
| Native/process-container fallback | Exactly zero |
| Container or writable-layer reuse | Exactly zero |
| Unexplained owned-resource leak | Exactly zero |
| Required accepted-evidence loss | Exactly zero |
| Capacity overcommit | Exactly zero |
| Container ready p95 | Establish on exact host/image/engine before M2 |
| Cancel to workload stopped p95 | Establish before M2 |
| Terminal to verified removal p95 | Establish before M2 |
| Crash/reboot reconciliation | Bounded target with host drained until complete |
| Image and host security age | Published patch floor and emergency rotation policy |

Track p50/p95/p99 create, start, probe, exec, copy, cancel, destroy, and
recovery latency; writable-layer growth; host CPU/memory/storage pressure;
engine/HCS failure rate; evidence lag; and safe density. Never improve density
through isolation fallback, mutable reuse, hidden overcommit, or reduced
cleanup.

## Open decisions

1. Which engine and exact version are supported for the first host pool?
2. Does the final broker use a typed engine API or a stricter fixed-operation
   helper, and how is the endpoint ACL proven?
3. What minimum service rights allow create, inspect, exec, kill, enumerate,
   and remove only Automata-owned resources?
4. Which engine/HCS inventory is authoritative after crash or host reboot?
5. Which Server Core host/image combinations cover the required shell/action
   corpus while satisfying Microsoft compatibility rules?
6. Does real-host fault and adversarial testing prove the nested Job Object
   process ceiling strongly enough to advertise, and what writable-layer limit
   can be enforced without introducing a host mount or reusable volume?
7. Which HCN/WFP design provides default-deny managed egress without exposing
   host, peer, engine, or management endpoints?
8. How are DNS, redirects, CDNs, signed URLs, package managers, OIDC, and custom
   CAs governed without creating general egress?
9. Can a non-administrator `ContainerUser` profile support the accepted
   action corpus? Is any administrator profile worth its separate risk and
   host pool?
10. How are image, engine, host, runner, broker, and guest updates coordinated
    and rolled back without mixed unqualified capacity?
11. What licensing and support constraints apply to the selected Windows
    Server and container runtime fleet?
12. What host density preserves real CPU/memory/storage guarantees and recovery
    headroom?

## Rejected shortcuts

- Job Objects, restricted tokens, or AppContainer alone as the Windows runner
  security boundary.
- Process-isolated containers for repository code.
- A full-VM fallback or native emergency-capacity path.
- Treating `--isolation hyperv` request text as sufficient without inspecting
  effective state.
- Giving the job, guest executable, or general runner code the engine pipe.
- Running job commands, action hooks, archive tools, or cleanup scripts on the
  host.
- Host directory, named-pipe, engine-socket, device, or mutable-cache mounts.
- Caller-supplied raw CLI, engine, HCS, HCN, WFP, PowerShell, or WMI payloads
  through a privileged boundary.
- Relying only on guest firewall, Defender, labels, or container user identity.
- Issuing credentials before trust, image, isolation, network, and ownership
  evidence.
- Reusing containers, writable layers, anonymous volumes, identities, or
  mutable caches across jobs.
- Global engine prune during recovery.
- Advertising Windows Actions, egress, administrator, services, nested
  containers, devices, or parallel capacity before exact acceptance.

## Primary Microsoft sources

These sources should be rechecked whenever the supported Windows or container
runtime release changes.

### Containers and virtualization

- [Secure Windows containers](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-security)
- [Hyper-V isolation for Windows containers](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container)
- [Windows container version compatibility](https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility)
- [Windows container requirements](https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements)
- [Windows container base images](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images)
- [Windows container networking architecture](https://learn.microsoft.com/en-us/virtualization/windowscontainers/container-networking/architecture)
- [Hyper-V architecture](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/hyper-v-architecture)
- [Host Compute System overview](https://learn.microsoft.com/en-us/virtualization/api/hcs/overview)
- [Host Compute Network API](https://learn.microsoft.com/en-us/windows-server/networking/technologies/hcn/hcn-top)
- [Windows Security Servicing Criteria](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria)

### Process, identity, and filesystem defense in depth

- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Nested Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Process mitigation policy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [Service SID information](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Reparse points and file operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations)
- [Windows file path namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)

### Network, host hardening, and operations

- [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
- [Secured-core server](https://learn.microsoft.com/en-us/windows-server/security/secured-core-server)
- [Windows Server OSConfig](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-overview)
- [App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)
- [HVCI and memory integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Defender Antivirus on Windows Server](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows-server-configure)
- [Tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
