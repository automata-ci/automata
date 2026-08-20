# automata-ci-windows-broker

Privileged Windows Hyper-V lifecycle core. It owns grant verification,
closed lifecycle policy, durable reconciliation, and watchdog supervision.
The file ledger is isolated behind `BrokerLedger`; HCS is isolated behind
`WindowsHostComputeAdapter` and implemented by a separate adapter crate.

Successful exec and copy payloads are authenticated, encrypted, and
synchronized through `BrokerResultStore` before the lifecycle ledger adopts an
opaque protected-content reference. The ledger retains only operation kind,
request fingerprint, reference, and acknowledgement state; stdout, stderr, and
`copy_from` bytes never enter its JSON records. Startup authenticates every
retained reference before accepting calls, and a missing or mismatched object
fails reconciliation closed.

Replay metadata uses the shared execution endpoint-operation budget rather
than a smaller broker-only cache limit. Result-store capacity is reserved
before each host mutation. After the caller durably receives a response, an
exact acknowledgement first records a non-replayable tombstone and then
reclaims the protected object. A crash during deletion resumes that garbage
collection at startup. Until acknowledgement, response loss or broker restart
replays the exact protected result without a second host mutation; afterward,
the tombstone prevents delayed duplicates from repeating it. Reusing an
operation ID with different request material always fails closed.

The host-compute port also carries the immutable in-image guest-agent path and
the admitted process ceiling. Workload exec and copy data cross that boundary
only as bounded guest-protocol frames; the privileged adapter never receives a
caller-selected engine command.

This crate is service-side code. The runner sandbox adapter does not depend on
it, and no production service/IPC composition is claimed yet.
