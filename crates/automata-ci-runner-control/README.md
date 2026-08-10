# automata-ci-runner-control

`automata-ci-runner-control` handles authenticated runner-control requests
against shared durable state. It reauthorizes machine identity and session
fences for each operation, publishes immutable job and result objects, and
keeps replica-local connections out of the authority model.

The `automata` control plane composes this application layer with mTLS transport,
PostgreSQL repositories, and object storage.

Automata is pre-1.0 and not production-ready. This is an internal application
layer, and its Rust API may change between releases.

- [Control-plane documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-runner-control)
- [Issues and support](https://github.com/automata-ci/automata/issues)
