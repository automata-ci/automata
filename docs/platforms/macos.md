# macOS runner implementation plan

This page records the accepted implementation order for macOS runner support.
The trusted-native slice described in stage 1 is experimental. Native macOS
validation is deferred until repository-scoped self-hosted capacity is
available, and the Virtualization.framework boundary in stage 3 remains
planned.

The first supported host is Apple Silicon running macOS 15 or newer. Workflow
syntax does not change: the first slice executes GitHub-compatible `run:` steps
through Bash or `sh`, with explicitly configured Python and PowerShell Core as
optional shells. Action steps, job and service containers, GPUs, Intel hosts,
signing jobs, and job-scoped Keychains remain out of scope.

## Stage 1: trusted native execution

Add a `macos_native` runner provider with one execution slot. It executes only
trusted work as the dedicated runner account and advertises process isolation,
host networking, a writable host filesystem, and the unchanged host identity.
This is not a hostile-workload boundary.

macOS cannot enforce Automata's whole-job CPU, memory, and process limits for a
native process tree. The execution contract therefore distinguishes enforced
limits from an explicit host-shared resource policy. Native macOS advertises
one operator-configured scheduling capacity and one execution slot, but those
CPU, memory, and PID values are admission metadata rather than hard per-job
ceilings. Ephemeral-disk and GPU capacity remain zero. Podman and Windows
continue to require and enforce their existing hard limits.

Each command is owned by a same-binary supervisor over a private bounded
control channel. The supervisor owns the POSIX process group and terminates it
on cancellation, timeout, or channel EOF. Provider state retains the existing
operation-replay, generation-fencing, bounded-WAL, and idempotent-destroy
contracts. Workspace and scratch access uses descriptor-relative, no-follow
filesystem operations below disjoint owner-only roots.

Runner-only secrets may be loaded from an exact macOS Keychain service/account
pair without authentication UI. This source is limited to runner mTLS, spool,
and object-store inputs and is never made available through a job-secret port.

## Stage 2: self-hosted macOS validation (deferred)

The GitHub-hosted `macos-15` lane is intentionally absent because its recurring
cost is not justified during the project's current stage. The macOS provider,
configuration, platform-specific tests, differential support, and supervisor
smoke script remain in the repository so validation can resume without
reimplementing the runner.

When repository-scoped self-hosted Apple Silicon capacity is available, add an
explicitly labeled macOS 15 lane and fail closed unless Rust's host triple is
`aarch64-apple-darwin`. It should build the shipped binaries and exercise the
macOS provider, product configuration, context, Keychain, shell executor,
durable state, supervisor cleanup, and shipped-runner process smoke test.

A deterministic differential fixture should run the same Bash and `sh` cases
under the self-hosted workflow and Automata and compare stable environment,
working-directory, command-file, output, timeout, cancellation, and conclusion
behavior.

## Stage 3: Virtualization.framework isolation

Add a `macos_virtualization` provider backed by a digest-verified Swift host
helper and an immutable macOS 15 ARM64 template. A versioned guest agent runs
inside each APFS-cloned disposable VM. Host and guest communicate over a
private, bounded protocol; no host directory is shared with the guest.

The VM boundary enforces memory and whole-vCPU limits. A dedicated non-admin
guest identity receives the configured process ceiling. Disabled networking
omits the virtual NIC, while private egress uses provider-owned NAT. Runner or
helper failure stops the VM and removes the clone through replay-safe provider
recovery.

GitHub-hosted ARM64 macOS runners do not provide nested virtualization. macOS-
specific build, Keychain, shell-differential, native-process, boot, isolation,
resource, crash-recovery, and repeated-clean-job coverage requires repository-
scoped self-hosted Apple Silicon capacity.

## Contract changes

- Execution requests select either enforced resource limits or the explicit
  host-shared policy. Provider capability checks must match that selection.
- Native POSIX and immutable virtual-machine launch material become first-class
  sandbox environment forms.
- Runner configuration accepts exactly one of `podman`, `windows_native`,
  `macos_native`, or `macos_virtualization`, plus the matching provider-state
  root.
- GitHub context construction receives the exact runner platform so macOS
  reports `RUNNER_OS=macOS` and `RUNNER_ARCH=ARM64` instead of inferring an OS
  from POSIX path syntax.
- The SHA-256 tool contract carries an executable and fixed arguments, allowing
  Linux `sha256sum` and macOS `shasum -a 256` without ambient tool lookup.

## Acceptance gates

- Existing Linux and Windows provider, executor, configuration, and workflow
  tests remain unchanged and green.
- Repository workflows do not schedule paid GitHub-hosted macOS runners while
  self-hosted Apple Silicon capacity is unavailable.
- Native configuration rejects the wrong OS/architecture, macOS below 15,
  parallel slots, overlapping roots, nonzero ephemeral-disk or GPU capacity,
  unsupported network/filesystem/privilege policies, and unsupported workflow
  features. Configured CPU, memory, and PID capacity is explicitly advisory.
- Native provider tests cover path attacks, bounded copies and output, WAL
  replay and corruption, stale generations, timeout, cancellation, process
  cleanup, supervisor loss, and restart recovery.
- Keychain tests cover missing, ambiguous, interactive-only, oversized, and
  malformed values without exposing secret bytes in diagnostics.
- The shipped runner completes a zero-resource shell job with the correct
  macOS context and rejects actions, services, and containers before launch.
- The virtual-machine gate additionally proves template attestation, guest/host
  filesystem separation, network modes, CPU/memory/process enforcement, helper
  crash cleanup, WAL reopen, and repeated clean execution on physical Apple
  Silicon.
