# automata-ci-blob

`automata-ci-blob` defines Automata's provider-neutral, content-addressed blob
storage contracts and an in-memory adapter for tests. Reads and writes verify
immutable descriptors; coordination and discovery deliberately stay outside
the object store.

Storage adapters such as `automata-ci-blob-s3` implement these ports for the
control plane and runner.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-blob --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
