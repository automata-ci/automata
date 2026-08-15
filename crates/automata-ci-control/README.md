# automata-ci-control

`automata-ci-control` owns Automata's transport-neutral scheduling, lease, and
authenticated runner-control services. Its scheduling domain reduces
server-owned requirements and validated runner capabilities to deterministic
placement decisions. Its application services compose those decisions with
durable ports and versioned runner messages.

The public `runner_auth` module binds transport-validated mTLS evidence to
durable runner registrations without trusting certificate contents or protocol
fields. The public `github_oidc` module turns explicit GitHub `id-token: write`
permission into a durably reserved, replay-stable runtime authority.

The crate keeps database, object-storage, connection, and product-configuration
adapters outside these domains. The `automata` executable assembles those
layers.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-control --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
