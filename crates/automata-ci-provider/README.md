# automata-ci-provider

`automata-ci-provider` owns source-hosting provider identity, capability,
configuration, connection, delivery, factory-registry, and persistence-port
contracts for Automata. Delivery adapters authenticate bounded raw requests
before normalization into the closed trigger vocabulary. Opaque endpoints pin
exact instance, connection, and secret revisions; the replay-safe inbox owns
only evidence and worker lifecycle. GitHub, Forgejo, and future provider
adapters implement these contracts without entering the workflow, scheduler,
store, or runner domains.

The crate contains no network client and no concrete provider implementation.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- API documentation: run `cargo doc -p automata-ci-provider --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
