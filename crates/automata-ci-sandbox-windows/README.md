# automata-ci-sandbox-windows

`automata-ci-sandbox-windows` implements Automata's one Windows execution
route: a fresh Hyper-V-isolated Windows container per job. There is no native
host, process-isolated container, full-VM, AppContainer, or Windows Sandbox
fallback.

## Restricted production path

The runner does not receive the engine pipe. It verifies and starts only the
digest-pinned `automata-windows-hyperv-broker-client.exe`, which forwards one
bounded versioned request to the fixed local pipe
`\\.\pipe\automata-windows-hyperv-broker-v1`. The broker service creates that
pipe with an explicit protected DACL containing only the distinct broker and
runner virtual-service SIDs. Remote and inherited pipe handles are disabled,
and the unsafe Windows default named-pipe ACL is never used. Process-ID and
primary-token checks are only secondary diagnostics: dispatch additionally
requires the SID and impersonation level from the exact impersonated pipe
client thread token. No reviewed safe dependency currently exposes that last
Windows boundary. The production authenticator
`authenticate_impersonated_client` therefore returns `false`
unconditionally, and every pipe request is rejected before dispatch. It must
not be enabled by falling back to the process token.

The service accepts only typed create, attach, inspect, exec, copy, destroy,
profile-attestation, and dedicated admission issue/resume/complete/renew
operations. There is no runner-facing generic custody read or write operation.
It accepts no engine endpoint, raw HCS/HCN document, isolation selector, host
command line, signal, wait, process-container, or full-VM operation. The fixed engine adapter uses
the local Docker Engine pipe and always creates with Hyper-V isolation,
networking disabled, `ContainerUser`, no mounts/pipes/devices/ports, and exact
hard limits. Every effective inspection rechecks ownership, generation,
profile, image, isolation, networking, identity, mounts, devices, and limits.

Docker's Windows backend waits for the asynchronous HCS operation result. The
broker first synchronizes a `Creating` intent; any create/start transport
failure is uncertain and reconciled by exact identity. Destroy first records a
`Destroying` intent, terminates descendants, removes the utility-VM-backed
container, and proves absence. Startup reconciliation and an in-process
watchdog reconcile uncertain creates/destroys, expired grants, and labelled
orphans without global prune. The component exposes an explicit runner-session
fence operation, but no production caller composes it yet. A separately
supervised watchdog service, with its own identity and engine access, is still
required before this path can claim cleanup independence from a broker crash or
deadlock.

## Placement authority

The component contract defines a server-only Ed25519-signed
`WindowsHyperVBrokerGrant`. The versioned grant binds the host, runner,
authenticated runner session and generations, slot, lease and fencing token,
attempt/run/job, JobIR version and digest, exact environment profile, resource
allocation, trust snapshot/policy/authority digests, and a bounded validity
interval. The server can load a signing seed and exact runner-to-host map, but
production composition does not yet install durable implementations of
`WindowsHyperVCurrentAdmissionReader`,
`WindowsHyperVPlacementRenewalRepository`, or
`WindowsHyperVBrokerGrantAuthorizationRepository`. Windows placement
therefore fails closed before a grant can be issued or delivered. The
repository does not claim PostgreSQL current-admission, renewal, or broker-grant
authorization/rehydration support.

The tested protocol carries a grant across the post-accept runtime-authority
command, journal, runtime, and executor unchanged, and the broker ledger
consumes it exactly once. The lease offer itself contains no broker capability. Replay
with different request material, an expired grant, a wrong host/session/
generation/profile/JobIR, or an unknown signing key fails before engine
mutation.

The checksummed ledger compacts automatically instead of permanently stopping
at its event or byte ceiling. Compaction retains every live or uncertain
resource and the latest terminal one-use-grant tombstone through grant expiry
plus the broker clock-skew window. A fully synchronized temporary snapshot is
rotated through explicit old/temp/new names; startup recognizes and validates
each possible interrupted rotation state before reopening the journal.

A malformed checksum or truncated record is never silently discarded. The
operator repair path is to stop the broker and watchdog, quarantine the host,
preserve the journal and both compaction sidecars, externally enumerate and
remove all broker-labelled resources, then restore a complete validated backup
or archive the corrupt state and re-provision a new broker host identity. The
host must be re-enrolled before it returns to scheduling; editing or truncating
the live journal in place is unsupported.

## Windows custody

Admission envelopes and promotion state are held only under the broker's
service-owned root and represented to the runner by random `bc1-...` handles.
Records are bounded, strict-schema, content-digest authenticated, atomically
published, reparse-safe, and sealed with DPAPI CurrentUser under the dedicated
broker virtual-service account with UI forbidden. Machine-scope DPAPI is not
used. A runner cannot create, read, or remove a custody record through generic
operations.

Production Windows runner enrollment remains deliberately unavailable: the
broker does not yet generate and retain a non-exportable enrollment key/CSR,
commit the returned certificate chain against that held key, or expose a
broker-backed TLS signing key to rustls. The existing runner enrollment stage
contains a PKCS#8 key and token and therefore remains Unix-only. Dedicated
admission issue/resume/complete/renew is composed with
`UnavailableWindowsBrokerSyntheticProbe` and therefore fails closed until the independent
create, inspect, cleanup, and absence synthetic probe is wired to the lifecycle
ledger. Neither gap may be bypassed with generic custody reads.

Run `automata-windows-hyperv-broker-service.exe install-root-v1 CONFIG` once
from an elevated deployment step, then configure the SCM service to execute
`service-v1 CONFIG` under the exact broker virtual-service account. The
installer uses only fixed `C:\Windows\System32\icacls.exe` arguments and the
service independently verifies that the root DACL contains one inheritable
full-control ACE for its SID. See
[`broker-service.windows.example.json`](broker-service.windows.example.json).

## Evidence boundary

Cross-platform fakes and Windows compilation prove protocol, replay, custody,
and lifecycle contracts; they do not prove physical HCS/Hyper-V behavior.
The service can attempt to open `WindowsEngineHostComputeAdapter` only on a
prepared physical Windows host; hosted CI supplies no HCS/Hyper-V engine, image,
or enrollment environment and cannot exercise that path.
Deployment signing, exact service installation evidence, supported engine and
host/image compatibility, adversarial network/escape tests, crash/reboot
campaigns, cleanup soak, and production Windows hardware qualification remain
external release gates documented in
[`docs/platforms/windows.md`](../../docs/platforms/windows.md).
