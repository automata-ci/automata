# automata-ci-control

`automata-ci-control` contains transport-neutral application services for the
Automata control plane. It composes scheduling policy from
`automata-ci-control-plane` with durable repository ports and versioned runner
messages.

HTTP serving, protobuf framing, database access, and product configuration stay
in separate adapters. The `automata` executable assembles those layers.

Automata is pre-1.0 and not production-ready. This is an internal application
layer, and its Rust API may change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-control)
- [Issues and support](https://github.com/automata-ci/automata/issues)
