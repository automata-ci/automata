# automata-ci-github-delivery

`automata-ci-github-delivery` implements the verified GitHub delivery boundary
used by Automata's control plane. It authenticates an exact push request,
stores the raw event in immutable blob storage, and then records only a
credential-free descriptor in the durable provider inbox. A separate bounded
worker claims that inbox entry, resolves public or explicitly authorized
private source, and submits the resulting workflow through the ordinary
admission boundary.

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
