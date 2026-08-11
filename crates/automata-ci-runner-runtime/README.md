# automata-ci-runner-runtime

`automata-ci-runner-runtime` is Automata's provider-neutral,
crash-recoverable runner session supervisor. It owns control-session, retry,
watchdog, outbox, cancellation, and delivery semantics while sandbox execution
remains behind an explicit `JobExecutor` port.

The `automata-runner` executable assembles this runtime with durable local
state, transport, a job executor, and the selected isolation provider.

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-runner-runtime --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
