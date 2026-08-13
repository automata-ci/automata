# GitHub Actions parity: Windows, Linux and macOS profiles, architectures, and cross-OS cache

Finish Windows actions, define exact Linux profiles, add macOS and architecture breadth, strengthen Windows isolation, and prove cross-OS cache behavior.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane P, with runner, security, and Results reviewers.

**Package IDs:** WIN-01, WIN-02, WIN-03, PLAT-01, PLAT-02, PLAT-03, PLAT-04, CACHE-03.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Runner execution, actions, logs, and cancellation](github-actions-parity-04-runner-execution.md)
- [Services, job containers, Docker, Podman, Kubernetes, and BuildKit](github-actions-parity-05-containers-docker.md)
- [Results, Checks, artifacts, cache, and product UI](github-actions-parity-08-results.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Current Windows boundary

The latest shipped Windows-native path is a trusted-host, single-slot runner for
PowerShell, `cmd`, and optional Python `run:` steps. Job Objects provide process,
CPU, and memory ceilings, but the job still uses host networking, the host
filesystem, and the unchanged service identity. All action steps, job and
service containers, and parallel jobs remain unsupported. Product configuration
rejects reparse traversal of runner roots, but does not yet attest root DACL
ownership or hard-link counts. Hosted Windows CI is currently disabled, so
component tests are not release-gate evidence.

## Work packages

### WIN-01 — Action-ready Windows toolchain and materializer

**Owner:** P. **Size:** XL. **Dependencies:** RUN-02 contract.

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
RUN-01, ACT-01.

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
RES-01, CACHE-03.

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
- [x] Delivery is staged as trusted native execution, repository-scoped
  self-hosted validation, and then Virtualization.framework isolation on
  physical Apple Silicon. Paid GitHub-hosted macOS execution remains disabled.

Remaining tasks:

- [ ] Separate POSIX path syntax from Linux operating-system identity.
- [ ] Carry explicit macOS identity through sandbox and contexts.
- [ ] Implement the single-slot `macos_native` provider for trusted jobs, its
  dedicated account and runner-only Keychain inputs, owned process supervisor,
  descriptor-relative workspace access, durable recovery, and explicit
  host-shared zero-resource policy.
- [ ] Add an ARM64-only, repository-scoped self-hosted macOS 15 build,
  provider, product-config, shell, cancellation, recovery, and shipped-runner
  differential lane when dedicated capacity is available.
- [ ] Implement the `macos_virtualization` provider with an attested macOS 15
  ARM64 template, private guest protocol, APFS clone cleanup, resource
  enforcement, and self-hosted physical-machine acceptance.
- [ ] Keep action steps, containers, GPUs, Intel hosts, signing jobs,
  job-scoped Keychains, and broader Xcode profiles out of the initial slice;
  gate each future addition separately.

Acceptance:

- [ ] The shipped native runner on Apple Silicon macOS 15 reports
  `runner.os=macOS` and `runner.arch=ARM64`, completes zero-resource Bash and
  `sh` jobs, and rejects actions, services, and containers before launch.
- [ ] Self-hosted macOS 15 differential fixtures cover stable environment,
  working-directory, command-file, output, timeout, cancellation, and
  conclusion behavior.
- [ ] Physical Apple Silicon acceptance proves VM template identity,
  filesystem/network separation, CPU/memory/process enforcement, helper-crash
  recovery, and repeated clean execution.

### PLAT-03 — Strong Windows isolation and parallelism

**Owner:** P with security review. **Size:** XL. **Dependencies:** WIN-03.

Tasks:

- [ ] Choose restricted-token native execution or disposable Hyper-V VMs.
- [ ] Isolate filesystem, identity, and network.
- [ ] Retain existing reparse-traversal containment, then attest runner-root
  DACL ownership/inheritance and hard-link counts at startup and before reuse.
- [ ] Permit multiple jobs only after path and identity isolation is proven.
- [ ] Add service installation, recovery, signing, and operator runbooks.
- [ ] Keep Windows job containers and service containers rejected in the
  capability registry because GitHub documents those features for Linux
  runners; treat any future Windows-container support as an Automata-specific
  extension with a separate isolation gate.
- [ ] Add private-network/static-egress and proxy/custom-CA profiles only after
  they preserve Job Object or Hyper-V containment.
- [ ] Preserve trusted-host labeling until completion.

Existing Job Object process, CPU, and memory limits are a component foundation;
they do not satisfy this isolation package or justify hostile workloads.

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

- [ ] Run the pinned cache action through the shipped Windows runner and native
  provider.
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
