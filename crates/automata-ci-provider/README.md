# automata-ci-provider

`automata-ci-provider` owns source-hosting provider identity, capability,
configuration, connection, factory-registry, and persistence-port contracts for
Automata. GitHub, Forgejo, and future provider adapters implement these
contracts without entering the workflow, scheduler, store, or runner domains.

The crate contains no network client and no concrete provider implementation.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- API documentation: run `cargo doc -p automata-ci-provider --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
