# automata-ci-runner-runtime

`automata-ci-runner-runtime` is Automata's provider-neutral,
crash-recoverable runner session supervisor. It owns control-session, retry,
watchdog, outbox, cancellation, and delivery semantics while sandbox execution
remains behind an explicit `JobExecutor` port.

The `automata-runner` executable assembles this runtime with durable local
state, transport, a job executor, and the selected isolation provider.

For protocol-3 polling, the runtime snapshots registered provider-neutral
authority extensions into one canonical contribution bundle and retries the
same prepared request. It validates the correlated response and exact accepted
bundle digest before mutation. One journal commit records the nested command
effect, the carrier poll's successor, and its accepted-contribution receipts,
including when the command targets another slot. Pending receipts globally
fence slot processing after recovery; the command acknowledgement is flushed
before extension sources are acknowledged. Invalid or uncorrelated responses
advance neither checkpoint nor source acknowledgement.

The runtime treats both poll-contribution payloads and post-accept sandbox
authorizations as opaque provider-owned data. Provider adapters and restricted
consumers validate their own namespace and schema at the relevant mutation
boundary.

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- [Runtime-authority delivery](https://github.com/automata-ci/automata/blob/main/docs/runtime-authority-delivery.md)
- API documentation: run `cargo doc -p automata-ci-runner-runtime --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
