# automata-ci-protocol

`automata-ci-protocol` owns the validated, transport-neutral messages exchanged
by `automata` and `automata-runner`. The Rust types are not themselves a wire
format; production framing is supplied by the separately versioned
`automata-ci-protocol-protobuf` adapter.

Control-plane and runner application layers depend on these messages without
depending on a particular HTTP or serialization implementation.

Automata is pre-1.0 and not production-ready. The protocol is explicitly
versioned, but compatibility and the Rust API may change between releases.

- [Protocol documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-protocol)
- [Issues and support](https://github.com/automata-ci/automata/issues)
