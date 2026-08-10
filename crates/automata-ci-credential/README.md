# automata-ci-credential

`automata-ci-credential` defines provider-neutral contracts for issuing
short-lived repository credentials to an exact Automata workload. Requests bind
the workload, repository, permissions, and minimum validity without exposing a
provider's root credential.

Provider adapters such as `automata-ci-credential-github` implement the broker
used by runner execution layers.

Automata is pre-1.0 and not production-ready. This is an internal security
boundary, and its Rust API may change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-credential)
- [Issues and support](https://github.com/automata-ci/automata/issues)
