# automata-ci-github-delivery

`automata-ci-github-delivery` implements the verified GitHub delivery boundary
used by Automata's control plane. It authenticates a request, stores the raw
event in immutable blob storage, and records a credential-free descriptor in
the provider inbox. A worker claims that entry, resolves public or explicitly
installation-authorized repository source, and submits the workflow through normal admission.

One canonical ingress normalizes authenticated `push`, `pull_request`,
`merge_group`, and `repository_dispatch` evidence, including the selected ref
and source revisions. The `automata server` webhook route sends every supported
event through this same durable path.

The crate also contains the restart-safe GitHub Checks publisher port and its
credential-custody interfaces. Provider credentials, webhook secrets, source
archives, and user-controlled payloads are never stored in the delivery row or
included in diagnostic output. Claim ownership, attempts, lease expiry, and
terminal transitions remain durable and fence-bound.

This is an internal library, not a webhook server or a complete GitHub product
integration. Product route composition, server-service credential authority,
publisher supervision, and trusted external configuration must all be present
before deployment can advertise GitHub delivery or Check Runs support.

- [Authentication and authorization](https://github.com/automata-ci/automata/blob/main/docs/authentication.md)
- [Architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [Issues and support](https://github.com/automata-ci/automata/issues)
