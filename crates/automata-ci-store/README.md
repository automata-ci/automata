# automata-ci-store

`automata-ci-store` defines backend-neutral durable values and repository ports
for workflow admission and planning, runner sessions, receipts, outboxes,
reconciliation, publication, and managed-secret metadata. Execution-control
contracts for attempts, lease polling and runnable queues, cancellation,
maintenance, and identifier-free state snapshots live in
`automata-ci-control`. Database drivers, schema migrations, and concrete
repositories live in `automata-ci-postgres`.

## Tests

Store contracts compile into one explicit integration target. PostgreSQL and
schema tests run from `automata-ci-postgres`; use
`./scripts/ci/run-postgres-tests.sh` with `AUTOMATA_TEST_DATABASE_URL` for the
database-backed lane.

- [Control-plane configuration](https://github.com/automata-ci/automata/blob/main/crates/automata-ci/README.md)
- API documentation: run `cargo doc -p automata-ci-store --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
