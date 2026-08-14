# GitHub Actions parity: Windows, Linux and macOS profiles, architectures, and cross-OS cache

Finish Windows actions, define exact Linux profiles, add macOS and architecture breadth, strengthen Windows isolation, and prove cross-OS cache behavior.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane P, with runner, security, and Results reviewers.

**Package IDs:** WIN-ISO-00 through WIN-ISO-12, WIN-01, WIN-02, WIN-03,
PLAT-01, PLAT-02, PLAT-03, PLAT-04, CACHE-03.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
- [Services, job containers, Docker, Podman, Kubernetes, and BuildKit](github-actions-parity-05-containers-docker.md)
- [Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Current Windows boundary

The Wave 1 source tree removes the native Windows provider and adds a
component-level `windows-hyperv` provider. It creates a fresh Windows
container with explicit Hyper-V isolation, disabled networking,
`ContainerUser`, no host mounts, a digest-qualified image, bounded resources,
and an in-image one-request guest executable. It inspects the effective runtime
state before returning a handle and rejects process isolation or policy drift.

That code is not yet production acceptance. It currently reaches the local
container engine through a pinned CLI. Its synchronized provider journal and
startup orphan check are component recovery, but they do not replace a
restricted management broker, independent watchdog, or real engine/host fault
evidence. Authenticated trust routing, managed egress, credential delivery, a
signed image factory, and dedicated-host acceptance also remain open. Action
steps, job and service containers, egress, devices, and parallel capacity
remain unsupported.

The detailed
[Windows runner isolation plan](../platforms/windows.md) makes one fresh
Hyper-V-isolated Windows container per job the only Windows direction. The
blocking trust order is `EVT-01` -> `AUTH-02` -> `WIN-ISO-01`; component
provider work may proceed offline but cannot advertise support before that
route and the management/recovery gates pass.

## Work packages

### WIN-ISO — Disposable Hyper-V-isolated Windows containers

**Owner:** P with runner and security reviewers. **Size:** XXL.
**Dependencies:** FND-03 provider contracts; WIN-ISO-01 specifically depends
on EVT-01 and AUTH-02.

The implementation is split into WIN-ISO-00 through WIN-ISO-12 in the
[Windows runner isolation plan](../platforms/windows.md). It covers fail-closed
trust-to-isolation placement, a least-privilege container-management broker, a
signed immutable Windows image, engine/HCS/HCN lifecycle, a bounded guest
executable, default-deny networking, credential and data boundaries, crash
recovery, and adversarial Windows CI. The first Wave 1 pull request implements
only the explicitly checked component-foundation portions of those packages.

Acceptance:

- [ ] Unknown, untrusted, public-fork, and secret-bearing Windows work can match
  only the exact Hyper-V-container profile authorized by its trust decision.
- [ ] A shipped runner executes one job in a fresh Hyper-V-isolated container
  with no host share or engine endpoint and destroys its container, writable
  layer, endpoint, identity, and credentials.
- [ ] Hostile, crash-at-every-transition, network-bypass, cross-job, secret,
  and cleanup suites pass on dedicated Windows Hyper-V hosts.

### WIN-01 — Action-ready Windows toolchain and materializer

**Owner:** P. **Size:** XL. **Dependencies:** RUN-02 contract and WIN-ISO-06
offline Hyper-V-container gate.

Tasks:

- [ ] Add and probe Node 24, Git, Git Bash, archive extraction, tar/zstd, and
  optional supported Python.
- [ ] Publish exact versions, architecture, and paths in a tool manifest.
- [ ] Withhold individual capabilities when a probe fails.
- [ ] Replace POSIX `install` and `tar` action extraction with a secure
  platform-specific materialization port.
- [ ] Preserve archive digest and subpath provenance.
- [ ] Reject traversal, links, reparse escape, and overwrite attacks.
- [ ] Support local metadata reads and idempotent cleanup.
- [ ] Honor reviewed proxy and custom-CA configuration during Git/action source
  access, Results traffic, and startup admission.

Acceptance:

- [ ] Startup proves every advertised tool inside a fresh sandbox.
- [ ] Missing Node removes action capability without removing plain run steps.
- [ ] Linux and Windows produce equivalent immutable action trees.

### WIN-02 — JavaScript and composite actions on Windows

**Owner:** P with R integration. **Size:** XL. **Dependencies:** WIN-01,
WIN-ISO-08 managed data/credential boundary, RUN-01, ACT-01.

Tasks:

- [ ] Replace blanket Windows action rejection with granular capabilities.
- [ ] Execute Node 24 pre, main, and post.
- [ ] Execute local, repository, composite, and nested-composite actions.
- [ ] Preserve Windows phase files, environment casing, and CRLF behavior.
- [ ] Populate action contexts and run cleanup after failure/cancellation.
- [ ] Keep Docker actions and containers rejected until separately available.

Acceptance:

- [ ] A shipped Windows runner executes a repository JavaScript action and a
  nested local composite.
- [ ] Unsupported action kinds fail before user code.

### WIN-03 — Official Windows action acceptance

**Owner:** P with R and X support. **Size:** L. **Dependencies:** WIN-02,
WIN-ISO-11 hosted security gate, RES-01, CACHE-03.

Tasks:

- [ ] Prove checkout detached SHA, depth, submodules, LFS, sparse checkout,
  persisted credentials, and post cleanup.
- [ ] Prove upload-artifact, download-artifact, cache restore/save, and one
  representative setup action.
- [ ] Test paths with spaces, cancellation, restart, and credential cleanup.
- [ ] Restore a hosted Windows CI job and run the shipped control-plane and
  runner binaries through the Windows product path before release acceptance.

Acceptance:

- [ ] Tests launch the shipped Windows runner process rather than only
  executor fakes.
- [ ] Hosted Windows CI exercises the feature matrix and cleanup path instead of
  relying on the currently disabled job or local-only evidence.

### PLAT-01 — Exact Linux compatibility image contract

**Owner:** P. **Size:** L. **Dependencies:** FND-02.

Current component foundation:

- [x] Requirements schema v1 carries run-pinned CPU, memory, ephemeral-disk,
  and optional GPU requests and limits through scheduler matching, executor
  admission, and `SandboxSpec`; the Kubernetes adapter renders exact resource
  quantities and mapped devices.

Remaining tasks:

- [ ] Pin Node, shells, PowerShell, Python, Git, archive tools, and build tools.
- [ ] Publish signed image digest and software inventory.
- [ ] Verify tool-cache layout and common setup actions.
- [ ] Test browser and build workloads.
- [ ] Define and attest the passwordless `sudo` contract required by unchanged
  CI, including exact `apt-get` package-install behavior.
- [ ] Ensure sudo authority exists only inside the disposable job sandbox,
  cannot reach the host/provider socket, and leaves no mutation after cleanup.
- [ ] Test package installation, maintainer scripts, cancellation, disk limits,
  network policy, and malicious sudo arguments against that boundary.
- [ ] Define update and deprecation policy.
- [ ] Support reviewed outbound proxies and custom CA bundles for source,
  action, Results, and control endpoints without weakening TLS verification.
- [ ] Define private-network and static-egress profiles with explicit
  capability evidence and route cleanup.
- [ ] Specify custom image admission, signing, vulnerability policy, lifecycle,
  and deprecation independently from the GitHub-compatible image.
- [ ] Prove each advertised allocation against its production provider; use
  `PROV-03` for Kubernetes ephemeral-disk and GPU enforcement rather than
  encoding quantitative resources as labels.
- [ ] Stop implying label equality means hosted-image parity.

Acceptance:

- [ ] The profile is reproducible, signed, and differentially tested against
  its stated target.

### PLAT-02 — macOS identity and provider

**Owner:** P. **Size:** XL. **Dependencies:** GATE-01.

The accepted staged design is maintained in the
[macOS runner implementation plan](../platforms/macos.md).

Current design foundation:

- [x] The first target is Apple Silicon on macOS 15 or newer, with Bash and
  `sh` as the required shell surface and configured Python or PowerShell Core
  optional.
- [x] macOS jobs use only disposable Virtualization.framework VMs on physical
  Apple Silicon. The earlier native-process stage and host-shared resource
  policy have been deleted. Paid GitHub-hosted macOS execution remains disabled.

Remaining tasks:

- [x] Separate POSIX path syntax from Linux operating-system identity.
- [x] Carry explicit macOS identity through sandbox and contexts.
- [x] Implement the single-slot `macos_virtualization` provider with a sealed
  guest identity, runner-only Keychain inputs, Virtio socket transport,
  descriptor-relative host state, and durable recovery.
- [ ] Add an ARM64-only, repository-scoped self-hosted macOS 15 build,
  provider, product-config, shell, cancellation, recovery, and shipped-runner
  differential lane when dedicated capacity is available.
- [x] Implement the `macos_virtualization` provider with an attested macOS 15
  ARM64 template, private guest protocol, APFS clone cleanup, resource
  enforcement, and self-hosted physical-machine acceptance.
- [ ] Keep action steps, containers, GPUs, Intel hosts, signing jobs,
  job-scoped Keychains, and broader Xcode profiles out of the initial slice;
  gate each future addition separately.

Acceptance:

- [ ] The shipped VM runner on Apple Silicon macOS 15 reports
  `runner.os=macOS` and `runner.arch=ARM64`, completes zero-resource Bash and
  `sh` jobs, and rejects actions, services, and containers before launch.
- [ ] Self-hosted macOS 15 differential fixtures cover stable environment,
  working-directory, command-file, output, timeout, cancellation, and
  conclusion behavior.
- [ ] Physical Apple Silicon acceptance proves VM template identity,
  filesystem/network separation, CPU/memory/process enforcement, helper-crash
  recovery, and repeated clean execution.

### PLAT-03 — Windows Hyper-V-container scale and expanded profiles

**Owner:** P with security review. **Size:** L. **Dependencies:** WIN-ISO-12.

The only Windows boundary is selected and delivered by WIN-ISO-00 through
WIN-ISO-12. This package does not add a native, process-isolated, or full-VM
fallback; it begins only after the Hyper-V-container path is accepted.

Tasks:

- [ ] Increase jobs per host only after cross-container identity, storage,
  network, resource-reservation, crash-recovery, and destructive-cleanup soak
  passes at the proposed density.
- [ ] Keep one fresh Hyper-V-isolated container and writable layer per job;
  parallelism never means mutable container, workspace, identity, cache,
  endpoint, or credential reuse.
- [ ] Add only separately named image, authority, and network profiles that
  retain Hyper-V isolation; prohibit silent process-isolated fallback.
- [ ] Keep Windows job containers and service containers rejected in the
  compiler or admission path because GitHub documents those features for Linux
  runners; document them as unsupported on Windows. Treat any future
  Windows-container support as an Automata-specific extension with a separate
  isolation gate.
- [ ] Add private-network/static-egress and proxy/custom-CA profiles only after
  their exact HCN/WFP and upstream policies pass the hostile network matrix.
- [ ] Publish per-profile capacity, isolation, guest authority, network, image,
  tool, and unsupported-feature evidence.

Container runtime process, CPU, and memory settings remain component evidence
until their effective enforcement passes on the exact host/image/engine tuple.

Acceptance:

- [ ] Hostile-workload tests cannot reach runner authority or another job.

### PLAT-04 — Architecture profiles

**Owner:** P. **Size:** L. **Dependencies:** PLAT-01, PLAT-02, PLAT-03.

Tasks:

- [ ] Add Linux ARM64 and Windows ARM64; macOS ARM64 belongs to the first
  `PLAT-02` provider slice.
- [ ] Add Linux/Windows x86, ARM32, or macOS Intel only if product-supported and
  separately accepted.
- [ ] Populate architecture contexts exactly.
- [ ] Publish architecture-specific tool/image manifests.
- [ ] Require native acceptance rather than cross-compile-only evidence.

Acceptance:

- [ ] Every advertised architecture completes a native runner process E2E.

### CACHE-03 — Windows and cross-OS cache semantics

**Owner:** X with P supplying Windows execution. **Size:** L.
**Dependencies:** CACHE-02, WIN-02.

Tasks:

- [ ] Run the pinned cache action through the shipped Windows runner and
  `windows-hyperv` provider.
- [ ] Match Windows cache-version calculation, lookup-only,
  fail-on-cache-miss, restore keys, save-always behavior, and branch scopes.
- [ ] Test NTFS attributes, case-insensitive collisions, Unicode, CRLF-sensitive
  content, long paths, reparse points, and archive extraction containment.
- [ ] Decide `enableCrossOsArchive` using real Linux-to-Windows and
  Windows-to-Linux fixtures.
- [ ] Preserve executable bits, symlinks, file modes, and Windows metadata only
  where the approved archive contract can represent them.
- [ ] Add large-cache, cancellation, timeout, partial-range, and cleanup tests
  on Windows.
- [ ] Publish the supported OS/action/archive-tool version matrix.

Acceptance:

- [ ] Windows save and restore work through exact production adapters.
- [ ] Cross-OS restores are byte/metadata correct or rejected before upload
  with a stable reason.
- [ ] A cache archive cannot escape the workspace or alter runner-owned paths.

---

[Previous: Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md) · [Next: Operations, limits, runner fleet, and acceptance gates](github-actions-parity-10-operations-gates.md)
