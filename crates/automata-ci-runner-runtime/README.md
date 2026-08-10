# automata-ci-runner-runtime

`automata-ci-runner-runtime` is Automata's provider-neutral,
crash-recoverable runner session supervisor. It owns control-session, retry,
watchdog, outbox, cancellation, and delivery semantics while sandbox execution
remains behind an explicit `JobExecutor` port.

The `automata-runner` executable assembles this runtime with durable local
state, transport, a job executor, and the selected isolation provider.

Automata is pre-1.0 and not production-ready. This is an internal runtime layer,
and its Rust API may change between releases.

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- [API documentation](https://docs.rs/automata-ci-runner-runtime)
- [Issues and support](https://github.com/automata-ci/automata/issues)
