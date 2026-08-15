# automata-ci-scm

`automata-ci-scm` defines provider-neutral contracts for resolving source
revisions to immutable repository snapshots. Provider credentials are scoped to
one request and never retained in snapshot values or errors.

The namespaced `credential` module defines least-privilege contracts for issuing
short-lived repository credentials to an exact Automata workload. Requests bind
the workload, repository, permissions, and minimum validity without exposing a
provider's root credential.

GitHub HTTP adapters implement these ports, and `automata-ci-action` consumes
the snapshot contracts to build verified action bundles. Credential-provider
adapters implement `credential::RepositoryCredentialBroker` for runner execution
layers.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-scm --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
