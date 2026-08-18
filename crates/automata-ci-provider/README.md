# automata-ci-provider

`automata-ci-provider` owns source-hosting provider identity, capability,
configuration, connection, credentials, delivery, desired-result, human identity,
factory-registry, and persistence-port contracts for Automata. Delivery adapters authenticate bounded
raw requests before normalization into the closed trigger vocabulary. Opaque
endpoints pin exact instance, connection, and secret revisions; the replay-safe
inbox owns only evidence and worker lifecycle. GitHub, Forgejo, and future
provider adapters implement these contracts without entering the workflow,
scheduler, store, or runner domains.

Result adapters reconcile claim-frozen desired generations through deterministic
markers. The common outbox contract owns supersession, exclusive fences,
bounded retries, and terminal failure while preserving annotations even when a
provider cannot render them.

Credential ports separate control, workload, and human authority. Workload
credentials are bound to an exact repository, job attempt, runner lease, trust
class, and deterministic reconciliation marker. Human authorization always uses
S256 PKCE and namespaces identity and membership evidence by provider instance.

The crate contains no network client and no concrete provider implementation.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- API documentation: run `cargo doc -p automata-ci-provider --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
