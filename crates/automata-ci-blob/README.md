# automata-ci-blob

`automata-ci-blob` defines Automata's provider-neutral immutable storage
contracts and an in-memory adapter for tests. Content reads require a complete
descriptor. A separate narrow record port permits bounded lookup by one
deterministic key when an immutable manifest is itself the source of a content
descriptor. Both paths verify stored size and SHA-256 metadata against the
returned bytes; neither exposes listing, overwrite, or mutable coordination.

Storage adapters such as `automata-ci-blob-s3` implement these ports for the
control plane and runner.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-blob --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
