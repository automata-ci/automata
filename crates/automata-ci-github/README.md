# automata-ci-github

`automata-ci-github` contains bounded HTTP adapters for GitHub authentication,
membership, and repository APIs. It centralizes trusted-origin policy,
pagination limits, response validation, and secret-safe error handling for the
Automata control plane and runner.

Provider-neutral identity and SCM contracts remain in `automata-ci-auth` and
`automata-ci-scm`.

## Authenticated workflow-event contract

`GithubEventRegistryV1` is the closed, versioned registry for the four webhook
kinds that may produce workflows: `push`, `pull_request`, `merge_group`, and
`repository_dispatch`. Native `check_run` and `check_suite` rerun messages stay
on the control-event path and are rejected by the workflow-event envelope.

`GithubSealedEventEnvelopeV1` projects a verified webhook into bounded,
facts-only policy input. It retains stable actor, source/target repository,
activity, reference, revision, fork, and recursion facts appropriate to the
registered kind. It never embeds the raw webhook or an arbitrary repository
dispatch `client_payload`; instead it binds the raw object by the exact
content-addressed `BlobDescriptor` (key, SHA-256 digest, size, and media type).
Canonical rehydration rejects unknown or duplicate fields, unknown kinds,
prior/future schemas, noncanonical encodings, and external digest mismatch.
Missing or future actor classification stays explicit and must be denied by
AUTH-02 when a policy requires complete actor trust facts.

This is the EVT-01A contract-only slice. EVT-01B must persist the canonical
envelope bytes and envelope digest beside the existing raw-event object in one
delivery transaction, store both schema versions and the raw-object identity,
rehydrate through `GithubSealedEventEnvelopeV1::from_canonical_bytes`, migrate
or explicitly quarantine pre-envelope rows, and pass the rehydrated facts to
AUTH-02 without reparsing the raw JSON. No numbered database migration belongs
to this crate-only slice.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
