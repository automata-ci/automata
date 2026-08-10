# automata-ci-scm

`automata-ci-scm` defines provider-neutral contracts for resolving source
revisions to immutable repository snapshots. Provider credentials are scoped to
one request and never retained in snapshot values or errors.

GitHub HTTP adapters implement these ports, and `automata-ci-action` consumes
them to build verified action bundles.

Automata is pre-1.0 and not production-ready. This is an internal architecture
layer rather than a general SCM client; its Rust API may change between
releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-scm)
- [Issues and support](https://github.com/automata-ci/automata/issues)
