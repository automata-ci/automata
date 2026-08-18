# automata-ci-provider-github

`automata-ci-provider-github` contains bounded HTTP adapters for GitHub authentication,
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

The EVT-01A/EVT-01B foundation seals the envelope at authenticated ingress and
persists its canonical bytes, domain-separated digest, envelope schema, and
registry schema atomically beside the provider-delivery raw-object coordinates.
Claim rehydration validates the canonical encoding, both schema identities, the
raw-object binding, and the provider delivery/repository identity before any
blob or provider access. Exact envelope coordinates are required by the
greenfield schema. The verified envelope is carried on
`GithubDeliveryWorkflowRequest` so AUTH-02 can reduce authority from normalized
facts rather than guessing through raw JSON.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-provider-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
