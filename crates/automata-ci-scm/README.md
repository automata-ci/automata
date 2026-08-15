# automata-ci-scm

`automata-ci-scm` defines provider-neutral contracts for resolving source
revisions to immutable repository snapshots. Provider credentials are scoped to
one request and never retained in snapshot values or errors.

The namespaced `credential` module defines provider-neutral values and failures
for least-privilege, short-lived repository credentials. Requests bind the
workload, repository, permissions, and minimum validity without exposing a
provider's root credential.

GitHub HTTP adapters implement the snapshot ports, and `automata-ci-action`
consumes the snapshot contracts to build verified action bundles.
`automata-ci-credential-github` composes the credential values with
provider-specific, lifecycle-aware mint and revocation brokers.
Future provider integrations should define lifecycle-adequate ports once their
mint ambiguity and secret-custody semantics are known rather than reuse a
speculative generic broker.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-scm --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
