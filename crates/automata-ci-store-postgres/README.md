# automata-ci-store-postgres

PostgreSQL implementations of Automata's durable workflow, runner, publication,
provider, and managed-secret metadata repositories. This crate owns the SQLx
migration lineage and concrete `PostgresStore` lifecycle.

Portable callers should depend on the ports in `automata-ci-store` and
`automata-ci-control`; product composition and integration tests import this
concrete adapter directly. `automata-ci-postgres` owns only shared PostgreSQL
test support.

Provider-neutral workflow admission atomically records immutable trigger,
provider-selection, request, and original processing-fence evidence. A replay
must match that original evidence even when a newer live claim has reclaimed
the same delivery invocation.

## Schema migrations

The crate uses SQLx's embedded migrator; another Rust migration framework would
duplicate its locking, transaction, checksum, and migration-ledger behavior.
The files numbered `0001` through `0026` form the canonical greenfield baseline,
split into bounded stages for routines, relations, catalog data, keys, indexes,
triggers, and foreign keys. The project uses big-bang schema cutovers while it
remains greenfield: update the canonical lineage directly and recreate local
databases. A Rust contract pins every filename and raw SQLx SHA-384 checksum so
intentional schema rewrites cannot leave stale embedded migration metadata.

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
