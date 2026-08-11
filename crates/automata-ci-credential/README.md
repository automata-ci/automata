# automata-ci-credential

`automata-ci-credential` defines provider-neutral contracts for issuing
short-lived repository credentials to an exact Automata workload. Requests bind
the workload, repository, permissions, and minimum validity without exposing a
provider's root credential.

Provider adapters such as `automata-ci-credential-github` implement the broker
used by runner execution layers.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-credential --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
