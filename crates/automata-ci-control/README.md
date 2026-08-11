# automata-ci-control

`automata-ci-control` contains transport-neutral application services for the
Automata control plane. It composes scheduling policy from
`automata-ci-control-plane` with durable repository ports and versioned runner
messages.

HTTP serving, protobuf framing, database access, and product configuration stay
in separate adapters. The `automata` executable assembles those layers.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-control --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
