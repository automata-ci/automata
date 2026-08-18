# automata-ci-protocol

`automata-ci-protocol` owns the validated, transport-neutral messages exchanged
by `automata` and `automata-runner`. The Rust types are not themselves a wire
format; production framing is supplied by the separately versioned
`automata-ci-protocol-protobuf` adapter.

Control-plane and runner application layers depend on these messages without
depending on a particular HTTP or serialization implementation.

Runner protocol 3 requires every `LeaseRequest` to carry a canonical
`LeaseAuthorityPollContributions` bundle, including the canonical empty bundle.
A result for that poll is accepted only through a correlated
`LeasePollResponse` whose accepted digest matches the exact contribution
bundle. The provider-owned poll payloads remain opaque to this generic layer.

After lease acceptance, protected `JobRuntimeAuthorities` schema 2 carries both
credential authorities and canonical provider-owned `SandboxAuthorizations`.
These post-accept authorizations are distinct from poll contributions and do
not add provider-specific fields to the generic lease protocol.

- [Protocol documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [Runtime-authority delivery](https://github.com/automata-ci/automata/blob/main/docs/runtime-authority-delivery.md)
- API documentation: run `cargo doc -p automata-ci-protocol --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
