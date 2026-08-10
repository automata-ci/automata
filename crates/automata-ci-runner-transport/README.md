# automata-ci-runner-transport

`automata-ci-runner-transport` provides the dedicated mutual-TLS, HTTP/2
transport for Automata's runner protocol. It validates peer certificates
directly, applies request bounds, and forwards authenticated evidence to
replica-neutral application ports without storing session authority locally.

The `automata` control plane uses the server adapter, while `automata-runner`
uses the client. Reverse-proxy certificate headers are not trusted by this
implementation.

Automata is pre-1.0 and not production-ready. This is an internal transport
layer, and its configuration and Rust API may change between releases.

- [Deployment documentation](https://github.com/automata-ci/automata/blob/main/docs/deployment.md)
- [API documentation](https://docs.rs/automata-ci-runner-transport)
- [Issues and support](https://github.com/automata-ci/automata/issues)
