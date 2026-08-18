# automata-ci-control

`automata-ci-control` owns Automata's transport-neutral scheduling and
authenticated runner-control services. It also owns the execution durability
contracts for attempt lifecycle, lease polling and runnable queues,
cancellation, replica-safe maintenance, and identifier-free control-plane
state snapshots. Its scheduling domain reduces server-owned requirements and
validated runner capabilities to deterministic placement decisions. Its
application services compose those decisions with durable ports and versioned
runner messages.

Runner lease-authority integrations cross one provider-neutral extension
boundary. Every canonical poll contribution is accepted before scheduling and
its exact bundle digest is acknowledged in the durable poll response. Offer
evidence is canonical, retained in the durable command, and limited to an
8 MiB encoded budget that leaves capacity for the rest of that command; after
acceptance, the matching extension prepares a sandbox authorization whose
commit is atomic with delivery of the complete runtime-authority bundle.
Unknown or unconfigured authorities fail closed. Provider-specific admission,
renewal, issuance, and one-use storage remain inside their adapter module.

First-party repository adapters use the feature-gated, documentation-hidden
`adapter-spi` trust boundary. That module is not a supported general-purpose
API.

The public `runner_auth` module binds transport-validated mTLS evidence to
durable runner registrations without trusting certificate contents or protocol
fields. The public `workload_oidc` module turns explicit GitHub `id-token: write`
permission into a durably reserved, replay-stable runtime authority.

The crate keeps database, object-storage, connection, and product-configuration
adapters outside these domains. The `automata` executable assembles those
layers.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-control --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
