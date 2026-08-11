# automata-ci-runner-control

`automata-ci-runner-control` handles authenticated runner-control requests
against shared durable state. It reauthorizes machine identity and session
fences for each operation, publishes immutable job and result objects, and
keeps replica-local connections out of the authority model.

The `automata` control plane composes this application layer with mTLS transport,
PostgreSQL repositories, and object storage.

- [Control-plane documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-runner-control --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
