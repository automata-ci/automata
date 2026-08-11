# automata-ci-auth-postgres

Encrypted PostgreSQL adapters for Automata's provider-neutral human
authentication and RBAC ports. The crate persists:

- login transactions and durable sessions;
- GitHub membership and installation authority;
- tenant and repository role management;
- provider-token custody and request-authentication resolution; and
- atomic sign-in finalization.

Provider state and tokens are authenticated and envelope-encrypted before they
reach PostgreSQL. Session bearer values are never stored, only keyed digests.
Browser sessions become active at sign-in. Device-completed CLI sessions are
instead persisted with a bounded `pending_activation` deadline and are excluded
from ordinary resolve and touch queries. Exact CLI activation transactionally
rechecks current principal, membership, audience, and authorization revision,
then emits one sanitized audit; repeating activation for that exact active
session is safe.

RBAC management mutations reauthorize their actor from locked durable state and
commit authorization-revision changes, optimistic concurrency, last-manager
protection, and sanitized audits atomically. Numeric GitHub organization/team
evidence and direct bindings are resolved from the newest current state rather
than trusted from session claims.

- [Authentication design](https://github.com/automata-ci/automata/blob/main/docs/authentication.md)
- API documentation: run `cargo doc -p automata-ci-auth-postgres --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
