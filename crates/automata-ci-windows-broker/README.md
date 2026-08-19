# automata-ci-windows-broker

Privileged Windows Hyper-V lifecycle core. It owns grant verification,
closed lifecycle policy, durable reconciliation, and watchdog supervision.
The file ledger is isolated behind `BrokerLedger`; HCS is isolated behind
`WindowsHostComputeAdapter` and implemented by a separate adapter crate.

Successful exec and copy operations are committed to the bounded durable
ledger before their result is returned. The record binds the operation ID to
the exact request fingerprint and bounded outcome, so a response-loss retry or
broker restart replays the original result without repeating the host mutation.
Reusing an operation ID with a different request fails closed.

The host-compute port also carries the immutable in-image guest-agent path and
the admitted process ceiling. Workload exec and copy data cross that boundary
only as bounded guest-protocol frames; the privileged adapter never receives a
caller-selected engine command.

This crate is service-side code. The runner sandbox adapter does not depend on
it, and no production service/IPC composition is claimed yet.
