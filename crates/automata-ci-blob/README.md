# automata-ci-blob

`automata-ci-blob` defines Automata's provider-neutral, content-addressed blob
storage contracts and an in-memory adapter for tests. Reads and writes verify
immutable descriptors; coordination and discovery deliberately stay outside
the object store.

Storage adapters such as `automata-ci-blob-s3` implement these ports for the
control plane and runner.

Automata is pre-1.0 and not production-ready. This is an internal architecture
layer, not a general-purpose object-store SDK; its Rust API may change between
releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-blob)
- [Issues and support](https://github.com/automata-ci/automata/issues)
