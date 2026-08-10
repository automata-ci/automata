# automata-ci-core

`automata-ci-core` provides the provider-neutral identifiers, digests,
capabilities, jobs, workflows, execution values, logs, and timestamps shared by
Automata components. Persisted values use validated constructors and explicit
schema versions instead of relying on Rust memory layout.

Most workspace crates depend on this domain vocabulary; product behavior lives
in higher-level application and adapter crates.

Automata is pre-1.0 and not production-ready. Durable schemas are versioned,
but this crate's Rust API may still change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-core)
- [Issues and support](https://github.com/automata-ci/automata/issues)
