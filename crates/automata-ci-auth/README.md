# automata-ci-auth

This crate contains Automata's authentication and authorization domain contracts.
It deliberately has no HTTP client, database, web framework, or runtime dependency.

Human identity providers, machine identity verification, session issuance, RBAC,
provider-token custody, key encryption, and output publication policy are separate
boundaries. The GitHub App module models the browser and device authorization
protocols without deciding how HTTP or durable storage are implemented.

Provider access and refresh tokens are secret-bearing, non-serializable values.
They must be handed to a `ProviderTokenVault` implementation backed by authenticated
encryption. This crate exposes the vault and key-encryption ports; it does not pretend
that encoding or redaction is encryption.

Durable identity, session, machine-certificate, token-metadata, vault-key, and
key-encryption-context values have private fields and validated constructors. Their
deserializers run the same validation, so storage and wire round trips cannot bypass
domain invariants. Secret-bearing aggregates expose only focused borrowed accessors
and deliberate consuming `into_parts` methods; they remain non-serializable and
redacted in debug output.

Control-plane adapters must keep browser/device transaction state in a shared,
encrypted, single-use store so any orchestrator replica can finish a flow without
making callbacks replayable. After GitHub proves a user, Automata issues its own
short-lived session; GitHub credentials are never accepted as general Automata API
bearer tokens. Runner authentication is a separate mTLS machine-identity boundary.
An `ExternalRunnerIdentity` asserted by that boundary must be mapped explicitly to
the internal UUID `automata_ci_core::RunnerId`; the two identifiers are intentionally
different types.

Browser and CLI sessions are distinct audiences. A device-completed CLI session
must remain non-resolvable while `pending_activation`; only the exact CLI-domain
credential lookup may activate it after the client has secured the bearer.
Activation revalidates the current principal, membership, audience, and
authorization revision, while exact active replay is idempotent. Browser sessions
remain immediately active.

RBAC has no privileged role names. Authorization combines explicit permission
grants at tenant/resource scope with an independent repository publication policy
for dashboard metadata, logs, and artifacts. Publication can grant read access
only; readable-secret output safety may narrow logs and artifacts to private and
cannot be overridden by a public repository preference.

The namespaced `output_policy` module owns the shared publication lattice used by
authentication, persistence, UI, and secret-delivery layers. Its stable Serde
representations require all current audiences and reject unknown security fields.
