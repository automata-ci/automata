# automata-ci-secret

`automata-ci-secret` defines provider-neutral contracts for logical secret
identity, hierarchical scope, output-publication safety, immutable secret
versions, and pluggable secret providers.

The crate contains no database, network, authentication, or provider-specific
implementation. Provider adapters receive exact-version requests after a
higher-level service has authorized the caller and resolved access policy.
Secret values cannot be cloned or serialized, redact debug output, and are
zeroized when dropped.

Ambiguous create recovery uses a separate, value-free reconciliation request.
It binds the same tenant, durable request ID, exact logical descriptor, and
exact optional predecessor as the immutable original create intent. Supporting
adapters may only look up and return that intent's already-committed opaque
locator/version, or prove that it definitively cannot commit; reconciliation
and its retries must never create a version.

Every adapter must attest one closed durable protection mode: Automata
authenticated envelope encryption, or verified provider-managed encryption.
There is no plaintext, unknown, or unspecified mode. Adapter diagnostics,
health state, metadata, and provider errors must remain value-free; temporary
plaintext must not be written to durable staging, swap, crash dumps, or logs.

These are adapter contracts, not a claim that every provider is available in
the product. The current product composes repository-scoped management,
recovery, and cleanup only with the built-in PostgreSQL provider. It delivers
no managed secret values to jobs, and external providers remain uncomposed and
unadvertised.

Publication safety is independent of provider selection. When user code can
read a secret, registered values are masked from stdout/stderr and its complete
logs and artifacts are capped at private even if repository settings request
public output. Secretless and capability-only work may retain the configured
audience.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-secret --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
