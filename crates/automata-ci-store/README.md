# automata-ci-store

`automata-ci-store` defines backend-neutral durable values and repository ports
for workflow admission and planning, runner sessions, receipts, outboxes,
reconciliation, publication, and managed-secret metadata. Execution-control
contracts for attempts, lease polling and runnable queues, cancellation,
maintenance, and identifier-free state snapshots live in
`automata-ci-control`. Database drivers, schema migrations, and concrete
repositories live in the owning domain adapter crates, including
`automata-ci-store-postgres`.

Workflow admission derives a durable priority from its trust source: ordinary
admission is level `0`, while merge-queue admission is the reserved level `100`.
Authorized operators can update queued or in-progress runs to a user level in
`0..=99`; merge-queue runs remain server-managed. The store contract owns the
bounded value and mutation outcome so HTTP and CLI adapters share one behavior.
Changing a value also invalidates that tenant's runnable keyset cursors, so a
bump cannot be hidden behind an already-open scan cycle.

## Tests

Store contracts compile into one explicit integration target. PostgreSQL and
schema tests run from `automata-ci-postgres`; use
`./scripts/ci/run-postgres-tests.sh` with `AUTOMATA_TEST_DATABASE_URL` for the
database-backed lane.

- [Control-plane configuration](https://github.com/automata-ci/automata/blob/main/crates/automata-ci/README.md)
- API documentation: run `cargo doc -p automata-ci-store --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
