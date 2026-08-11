# automata-ci-control-plane

`automata-ci-control-plane` contains Automata's pure, provider-neutral
scheduling domain. It reduces server-owned workflow requirements and validated
runner capabilities to deterministic placement decisions without depending on
a database, clock, transport, or executor.

`automata-ci-control` composes these policies with durable application ports;
the `automata` package supplies the product-level adapters.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-control-plane --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
