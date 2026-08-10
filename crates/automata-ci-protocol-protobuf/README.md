# automata-ci-protocol-protobuf

`automata-ci-protocol-protobuf` is the canonical protobuf adapter for Automata's
runner protocol. It applies allocation bounds, keeps generated DTOs private,
and converts frames to validated messages owned by `automata-ci-protocol`.

Checked-in generated code keeps product and cross-compilation builds independent
of a local `protoc` installation.

Automata is pre-1.0 and not production-ready. The wire schema is versioned, but
protocol compatibility and this adapter's Rust API may change between releases.

- [Protocol documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-protocol-protobuf)
- [Issues and support](https://github.com/automata-ci/automata/issues)
