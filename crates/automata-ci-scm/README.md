# automata-ci-scm

`automata-ci-scm` defines provider-neutral contracts for resolving source
revisions to immutable repository snapshots. Provider credentials are scoped to
one request and never retained in snapshot values or errors.

GitHub HTTP adapters implement these ports, and `automata-ci-action` consumes
them to build verified action bundles.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-scm --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
