# automata-ci-runner-transport

`automata-ci-runner-transport` provides the dedicated mutual-TLS, HTTP/2
transport for Automata's runner protocol. It validates peer certificates
directly, applies request bounds, and forwards authenticated evidence to
replica-neutral application ports without storing session authority locally.

The `automata` control plane uses the server adapter, while `automata-runner`
uses the client. Reverse-proxy certificate headers are not trusted by this
implementation.

- [Deployment documentation](https://github.com/automata-ci/automata/blob/main/docs/deployment.md)
- API documentation: run `cargo doc -p automata-ci-runner-transport --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
