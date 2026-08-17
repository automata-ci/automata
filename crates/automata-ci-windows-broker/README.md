# automata-ci-windows-broker

Privileged Windows Hyper-V lifecycle core. It owns grant verification,
closed lifecycle policy, durable reconciliation, and watchdog supervision.
The file ledger is isolated behind `BrokerLedger`; HCS is isolated behind
`WindowsHostComputeAdapter` and implemented by a separate adapter crate.

This crate is service-side code. The runner sandbox adapter does not depend on
it, and no production service/IPC composition is claimed yet.
