# Durable Windows release roadmap

This checklist tracks the work required to publish a durable Windows control
plane and trusted native runner. Update it when evidence changes; do not mark a
task complete merely because an API or unit test exists.

Current product availability remains owned by the
[platform support matrix](platform-support.md). This page owns planned Windows
release work and its acceptance evidence.

## Tracking rules

- Use `[ ]` for pending work and `[x]` only after the named evidence passes.
- Add a short evidence note beneath a completed milestone with commands, tests,
  or release artifacts.
- Record blockers in the milestone status table rather than weakening a gate.
- Commit after each milestone reaches its exit criteria. Keep incomplete work
  in focused commits that do not claim milestone completion.
- Changes to credentials, secure files, service identity, or isolation require
  a reviewed design issue before implementation.

## Milestone status

| Milestone | Status | Exit criterion |
| --- | --- | --- |
| W0 — native development surface | Component complete | Native binaries, preview, diagnostics, and smoke tests pass |
| W1 — trusted native runner | Experimental | Issue #13 execution and recovery evidence passes |
| W2 — release design authority | In progress | Durable Windows epic and reviewed security contracts exist |
| W3 — secure Windows adapters | Planned | Custody and filesystem adapters pass adversarial tests |
| W4 — durable control plane | Planned | `automata server` survives restart with PostgreSQL and S3 |
| W5 — Windows services | Planned | Separate control and runner services pass lifecycle tests |
| W6 — installation and upgrade | Planned | Signed MSI install, upgrade, rollback, and uninstall pass |
| W7 — production acceptance | Planned | Clean-machine E2E, reboot, recovery, and security gates pass |
| W8 — signed release | Planned | Exact public artifacts and provenance are published |

## Completed foundation

- [x] Build native `automata.exe` and `automata-runner.exe`.
- [x] Run preview, SSR, health, readiness, and status on Windows.
- [x] Run passive runner diagnostics without advertising Linux capabilities.
- [x] Fail unsupported CLI credential commands closed.
- [x] Implement trusted Windows native shell execution.
- [x] Assign processes to a Job Object before resume.
- [x] Enforce process-tree timeout, cancellation, destroy, and process limits.
- [x] Support PowerShell Core, Windows PowerShell, `cmd`, and configured Python.
- [x] Support Windows paths, case-insensitive environment names, and command
  files.
- [x] Implement Windows runner journal and encrypted spool adapters.
- [x] Exercise the shipped runner process through mTLS and S3 fixtures.
- [x] Stabilize transient teardown sharing and lock violations.
- [x] Enforce warning-free native product builds.
- [x] Add native preview and diagnostic smoke tooling.

Evidence: issue #13 and the consolidated Windows feature branch contain the
component, provider, shipped-process, recovery, and smoke tests. No Windows
release artifact is published.

## W2 — release design authority

The [durable Windows control-plane proposal](windows-control-plane-design-proposal.md)
was filed as [issue #16](https://github.com/automata-ci/automata/issues/16).
It is not accepted design authority until maintainers complete design review.

- [x] Open durable Windows control-plane issue #16.
- [x] Link issue #13 as the trusted-runner prerequisite.
- [ ] Obtain maintainer design approval for issue #16.
- [ ] Declare Windows Server 2025 x86-64 as the production target.
- [ ] Declare Windows 11 x86-64 as development and evaluation only.
- [ ] Define the first release's supported and unsupported surfaces.
- [ ] Decide whether gMSA support is required in the first release.
- [ ] Review the plan under `CONTRIBUTING.md`.
- [ ] Approve a threat model covering:
  - [ ] control-plane service identity;
  - [ ] runner service identity;
  - [ ] interactive CLI identity;
  - [ ] local administrator;
  - [ ] unprivileged local users; and
  - [ ] trusted workflow processes.
- [ ] Approve custody, filesystem, service lifecycle, and distribution
  contracts.

### Initial platform-boundary inventory

The first audit identified these implementation owners:

| Boundary | Current owner | Windows state |
| --- | --- | --- |
| CLI session custody | `crates/automata-ci/src/cli/credential_store.rs` | Unsupported module selected |
| Authentication and secret commands | `crates/automata-ci/src/cli/mod.rs` | Fixed fail-closed adapters |
| Bounded server secret files | `crates/automata-ci/src/server/config.rs` | Returns `FileSecurity` |
| Static registration custody | `crates/automata-ci/src/server/static_registration.rs` | Returns `UnsupportedPlatform` |
| Process shutdown | `crates/automata-ci/src/shutdown.rs` | Ctrl-C only; no SCM contract |
| Runner durable journal | `crates/automata-ci-runner-journal` | Windows adapter implemented |
| Runner encrypted spool | `crates/automata-ci-runner-spool` | Windows adapter implemented |
| Trusted execution | `crates/automata-ci-sandbox-windows` | Experimental provider implemented |
| Installation and service lifecycle | release and deployment tooling | Not implemented |

- [x] Record the initial server and custody boundary inventory.
- [x] Inventory every remaining server-side Unix/Linux conditional.
- [x] Map each conditional to portable core, custody, filesystem, lifecycle, or
  provider ownership.
- [ ] Record the result in the accepted durable Windows design epic.

## W3 — secure Windows adapter architecture

### Shared interfaces

- [ ] Define an explicit CLI session-custody interface.
- [ ] Define an explicit service secret-custody interface.
- [ ] Define a secure bounded-file input interface.
- [ ] Define certificate and private-key loading interfaces.
- [ ] Define durable atomic-file replacement behavior.
- [ ] Define Windows service shutdown and preshutdown behavior.
- [ ] Ensure a missing adapter returns a typed unavailable error.
- [ ] Prohibit plaintext and ordinary-file fallback.

### Secure filesystem adapter

- [ ] Select a reviewed safe Windows API dependency or wrapper.
- [ ] Open files without following reparse points.
- [ ] Verify every path ancestor from a trusted handle.
- [ ] Reject drive-relative, device, ambiguous verbatim, ADS, and prohibited UNC
  paths.
- [ ] Inspect owner SID and DACL entries.
- [ ] Reject broad read or write access where custody requires exclusivity.
- [ ] Inspect hard-link count.
- [ ] Support exclusive locking and bounded reads.
- [ ] Support staged writes, atomic replacement, and required flushes.
- [ ] Test sharing and lock violations.
- [ ] Test junction, symlink, ADS, hard-link, and ACL attacks.
- [ ] Test process crash and machine reboot recovery.

### CLI credential custody

- [ ] Implement a Windows Credential Manager adapter.
- [ ] Protect session payloads with user-scoped DPAPI.
- [ ] Bind every record to the exact server origin and audience.
- [ ] Preserve tenant separation.
- [ ] Bound record size and count.
- [ ] Implement login, status, refresh, logout, and corruption recovery.
- [ ] Prove unavailable custody performs no file or network fallback.

### Service credential custody

- [ ] Retain service-private environment references.
- [ ] Support Windows certificate-store TLS identity references.
- [ ] Implement service-account or machine-protected DPAPI records.
- [ ] Decide whether integrated PostgreSQL authentication is supported.
- [ ] Prove secrets never enter service arguments, registry configuration,
  Event Log messages, diagnostics, or crash output.

## W4 — durable Windows control plane

- [ ] Add a failing Windows composition test that enumerates missing adapters.
- [ ] Enable `automata server` only when all required adapters are present.
- [ ] Validate external PostgreSQL connectivity.
- [ ] Validate external S3-compatible storage.
- [ ] Load server TLS identity through reviewed custody.
- [ ] Start the human API and runner-control listeners.
- [ ] Start Results and cache listeners.
- [ ] Enable GitHub App and webhook credentials.
- [ ] Enable static runner registration.
- [ ] Enable secret-provider activation.
- [ ] Report dependency-specific readiness.
- [ ] Preserve fail-closed startup ordering.
- [ ] Prove preview cannot become a server fallback.
- [ ] Test graceful and forced shutdown.
- [ ] Test restart reconciliation.

## W5 — Windows service lifecycle

- [ ] Define separate control-plane and runner service identities.
- [ ] Define separate configuration, state, log, journal, spool, and provider
  roots.
- [ ] Implement Service Control Manager integration.
- [ ] Handle stop and preshutdown notifications.
- [ ] Define bounded graceful-shutdown deadlines and recovery actions.
- [ ] Add sanitized Windows Event Log output.
- [ ] Provision restrictive ACLs for each service identity.
- [ ] Reject prohibited administrator runner identities.
- [ ] Support operator-provisioned gMSAs if they are in scope.
- [ ] Add service validate, install, start, stop, status, and uninstall commands
  or equivalent installer actions.
- [ ] Keep secrets out of service command lines and `ImagePath` values.

## W6 — installation, upgrade, and rollback

- [ ] Produce release-mode MSVC binaries.
- [ ] Produce separate control-plane and runner MSI packages.
- [ ] Produce portable diagnostic ZIP files.
- [ ] Install per-machine without installer-time network downloads.
- [ ] Preserve configuration and state across upgrades.
- [ ] Preserve state during uninstall by default.
- [ ] Add an explicit destructive purge operation.
- [ ] Validate configuration before replacing a running service.
- [ ] Refuse incompatible schema downgrades.
- [ ] Roll back installation when startup validation fails.
- [ ] Test install, repair, upgrade, rollback, and uninstall on clean VMs.

## W7 — production acceptance

### Durable workflow E2E

- [ ] Install the control plane on a clean Windows Server 2025 VM.
- [ ] Install the runner under a separate non-administrative identity.
- [ ] Connect to external PostgreSQL and S3-compatible storage.
- [ ] Complete real mTLS registration and lease exchange.
- [ ] Admit and schedule a workflow through the durable API.
- [ ] Execute PowerShell followed by `cmd`.
- [ ] Propagate `GITHUB_ENV`, `GITHUB_PATH`, and `GITHUB_OUTPUT`.
- [ ] Stream logs and publish the result.
- [ ] Clean workspace and scratch roots.
- [ ] Poll the released runner slot again.

### Recovery

- [ ] Restart the control plane during admission, scheduling, and publication.
- [ ] Restart the runner during lease execution.
- [ ] Reboot control-plane and runner machines.
- [ ] Inject journal, spool, PostgreSQL, S3, and cleanup failures.
- [ ] Prove no duplicate execution or silent result loss.
- [ ] Prove fenced leases remain authoritative.
- [ ] Run a sustained restart and cleanup soak test.

### Security

- [ ] Prove standard users cannot read secrets or modify service configuration.
- [ ] Prove reparse points, hard links, and ACL changes cannot redirect custody.
- [ ] Prove service arguments and logs contain no secret material.
- [ ] Prove runner jobs cannot access control-plane state.
- [ ] Document that trusted native process containment is not hostile-workload
  isolation.

## W8 — signing, provenance, and publication

- [ ] Obtain an Authenticode signing identity.
- [ ] Sign executables and MSI packages with trusted timestamps.
- [ ] Generate SHA-256 checksums.
- [ ] Generate CycloneDX SBOMs and third-party license material.
- [ ] Produce build provenance attestations.
- [ ] Package debug symbols separately.
- [ ] Verify embedded commit and version identity.
- [ ] Verify PE imports and release runtime linkage.
- [ ] Publish signature-verification instructions.
- [ ] Publish a release candidate and validate it on a clean machine.
- [ ] Publish an exact release only after every required gate passes.

## Immediate work queue

1. [ ] Obtain design review for durable Windows control-plane issue #16.
2. [x] Complete the server-side platform-conditional inventory.
3. [ ] Draft custody and secure-file adapter interfaces.
4. [ ] Select the safe Windows API boundary for ACL and handle inspection.
5. [ ] Add the fail-closed Windows server composition test fixture.
6. [ ] Define service identities, directories, and ACL fixtures.
7. [ ] Implement the secure filesystem adapter before enabling any
   credential-bearing server path.
