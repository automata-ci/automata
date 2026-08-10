# automata-ci-store

`automata-ci-store` defines Automata's durable control-plane repository ports
and their PostgreSQL implementation. It owns atomic workflow admission,
scheduling, leases, runner sessions, receipts, outboxes, reconciliation, and
related persistence invariants.

Application crates depend on the ports; the `automata` product composes the
PostgreSQL adapter and applies the embedded migrations during server startup.

The store also exposes revision-safe human RBAC and repository-publication
repositories, plus a separate repository-secret management boundary. Secret
metadata reads are value-free. Create/replace uses a durable mutation UUID that
binds the descriptor, expected revision and predecessor, deterministic provider
request, staged encrypted winner, terminal receipt, current actor authority,
and sanitized audit. Only confirmation may promote a staged version and advance
the logical head. Deletion schedules fenced cryptographic erasure rather than
placing a value or provider handle in an audit or diagnostic.

The durable secret ledger validates the closed tenant, repository, and
environment descriptor shapes. Its public management port is currently
repository-scoped. The product composes that boundary with the built-in
PostgreSQL provider and supervises ambiguous-mutation recovery and cleanup.
Jobs receive no managed secret values. Tenant/environment management and
external providers remain uncomposed and unadvertised.

Automata is pre-1.0 and not production-ready. This is an internal persistence
layer; its Rust API and database schema may change between releases.

- [Deployment documentation](https://github.com/automata-ci/automata/blob/main/docs/deployment.md)
- [API documentation](https://docs.rs/automata-ci-store)
- [Issues and support](https://github.com/automata-ci/automata/issues)
