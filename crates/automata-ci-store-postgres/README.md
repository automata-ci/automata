# automata-ci-store-postgres

PostgreSQL implementations of Automata's durable workflow, runner, publication,
provider, and managed-secret metadata repositories. This crate owns the SQLx
migration lineage and concrete `PostgresStore` lifecycle.

Portable callers should depend on the ports in `automata-ci-store` and
`automata-ci-control`; the `automata-ci-postgres` facade preserves the existing
`store` namespace for compatibility.

## Schema migrations

The crate uses SQLx's embedded migrator; another Rust migration framework would
duplicate its locking, transaction, checksum, and migration-ledger behavior.
The files numbered `0001` through `0026` are the frozen greenfield baseline,
split into bounded stages for routines, relations, catalog data, keys, indexes,
triggers, and foreign keys. Do not edit, renumber, squash, or delete an applied
migration. SQLx deliberately rejects checksum changes. An ordinary Rust
contract pins every applied filename and raw SQLx SHA-384 checksum. Each schema
change must append the next sequential version and its identity to that
inventory without changing an earlier entry.

With `sqlx-cli` installed, create a focused, forward-only migration from the
repository root with:

```sh
sqlx migrate add --sequential \
  --source crates/automata-ci-store-postgres/migrations \
  describe_the_schema_change
```

Keep migrations below 2,000 lines. Prefer one behavioral change per file, and
include any supporting index required by a new trigger query in the same
migration. The live schema catalog test rejects exact duplicate indexes and
non-covering indexes that merely extend an already-unique key.

Once a migration is applied, an older binary is not a rollback artifact: its
embedded inventory cannot validate the newer ledger. Roll behavior back with a
new binary built from the current migration lineage, or restore the database
and matching binary together from a pre-migration backup. Never rewrite SQLx's
migration ledger or configure it to ignore missing versions.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-store-postgres --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
