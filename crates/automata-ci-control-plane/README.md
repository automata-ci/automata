# automata-ci-control-plane

`automata-ci-control-plane` contains Automata's pure, provider-neutral
scheduling domain. It reduces server-owned workflow requirements and validated
runner capabilities to deterministic placement decisions without depending on
a database, clock, transport, or executor.

`automata-ci-control` composes these policies with durable application ports;
the `automata` package supplies the product-level adapters.

Automata is pre-1.0 and not production-ready. This is an internal domain layer,
and its Rust API may change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-control-plane)
- [Issues and support](https://github.com/automata-ci/automata/issues)
