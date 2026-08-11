# automata-ci-core

`automata-ci-core` provides the provider-neutral identifiers, digests,
capabilities, jobs, workflows, execution values, logs, and timestamps shared by
Automata components. Persisted values use validated constructors and explicit
schema versions instead of relying on Rust memory layout.

Most workspace crates depend on this domain vocabulary; product behavior lives
in higher-level application and adapter crates.

Internal run identities remain UUIDs. The compatibility surface adds an
immutable positive numeric run alias rather than replacing those internal
identifiers.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-core --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
