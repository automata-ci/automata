# automata-ci-protocol

`automata-ci-protocol` owns the validated, transport-neutral messages exchanged
by `automata` and `automata-runner`. The Rust types are not themselves a wire
format; production framing is supplied by the separately versioned
`automata-ci-protocol-protobuf` adapter.

Control-plane and runner application layers depend on these messages without
depending on a particular HTTP or serialization implementation.

- [Protocol documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-protocol --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
