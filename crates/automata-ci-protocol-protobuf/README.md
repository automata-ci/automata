# automata-ci-protocol-protobuf

`automata-ci-protocol-protobuf` is the canonical protobuf adapter for Automata's
runner protocol. It applies allocation bounds, keeps generated DTOs private,
and converts frames to validated messages owned by `automata-ci-protocol`.

Checked-in generated code keeps product and cross-compilation builds independent
of a local `protoc` installation.

- [Protocol documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-protocol-protobuf --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
