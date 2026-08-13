# automata-ci-store

`automata-ci-store` defines Automata's durable control-plane repository ports
and their PostgreSQL implementation. It owns atomic workflow admission,
scheduling, leases, runner sessions, receipts, outboxes, reconciliation, and
related persistence invariants.

Application crates depend on the ports; the `automata` product composes the
PostgreSQL adapter and applies the embedded migrations during server startup.

The current schema gives every workflow run an immutable positive numeric
compatibility alias while retaining its internal UUID. It stores the admitted
base runtime context and value-level output classifications so public outputs
can survive independently of credential-derived values.

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
PostgreSQL provider and supervises ambiguous-mutation recovery and cleanup. For
an eligible leased Standard job, the store can issue exact pinned-version grants
and authorize a direct mTLS ephemeral fetch while keeping the durable lease
overlay value-free. The runner owns bounded zeroizing value custody and masks
every value before acknowledgement. Tenant/environment management, external and
dynamically leased providers, and variable-value delivery remain uncomposed and
unadvertised.

## Tests

Store integration tests are compiled into six reviewed targets: source
contracts, migration contracts, and four current-schema PostgreSQL domains.
The PostgreSQL runner prepares the current schema once, clones an isolated
database per test, executes current-schema tests with bounded parallelism, and
leaves the non-database migration inventory contract in the ordinary Rust test
lane. Run the complete database lane with `./scripts/ci/run-postgres-tests.sh`
after setting `AUTOMATA_TEST_DATABASE_URL`; see the development guide for the
namespace and PostgreSQL 18 requirements.

- [Deployment documentation](https://github.com/automata-ci/automata/blob/main/docs/deployment.md)
- API documentation: run `cargo doc -p automata-ci-store --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
