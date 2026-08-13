# automata-ci-conformance

Product-owned, provider-neutral contracts for deterministic conformance
fixtures. The crate keeps immutable fixture provenance, evidence classes,
parallel shard identity, fake-clock control, fault injection, and restart
checkpoints independent from the external integration-test harness.

It deliberately contains no live credentials and performs no provider I/O.
The companion harness supplies process and provider adapters while this crate
defines the fail-closed contracts those adapters must satisfy.
