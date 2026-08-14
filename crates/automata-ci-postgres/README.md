# automata-ci-postgres

PostgreSQL implementations of Automata's durable control-plane ports. The
crate groups concrete adapters behind five domain namespaces:

- `auth` persists encrypted login state, sessions, provider tokens, GitHub
  authority, installation state, RBAC management, and runner enrollment;
- `provisioning` atomically creates a workspace and its initial owner;
- `runner_auth` resolves server-owned runner-machine authority; and
- `secret` stores the built-in provider's envelope-encrypted secret values;
- `store` implements the durable workflow, runner, publication, and managed
  secret-metadata repositories and owns the embedded schema migrations.

The Automata server composes one pool and applies the embedded migrations before
starting these adapters. Transport configuration, wrapping-key custody, and
external-provider integrations remain outside this crate.

## Schema migrations

The crate uses SQLx's embedded migrator; another Rust migration framework would
duplicate its locking, transaction, checksum, and migration-ledger behavior.
The files numbered `0001` through `0026` are the frozen greenfield baseline,
split into bounded stages for routines, relations, catalog data, keys, indexes,
triggers, and foreign keys. Do not edit, renumber, squash, or delete an applied
migration. SQLx deliberately rejects checksum changes.

Every schema change after the baseline must be a focused, forward-only migration
with the next unused version. With `sqlx-cli` installed, create one from the
repository root with:

```sh
sqlx migrate add --sequential \
  --source crates/automata-ci-postgres/migrations \
  describe_the_schema_change
```

Keep migrations below 2,000 lines. Prefer one behavioral change per file, and
include any supporting index required by a new trigger query in the same
migration. The live schema catalog test rejects exact duplicate indexes and
non-covering indexes that merely extend an already-unique key.

PostgreSQL receives no plaintext login state, provider token, or managed secret
value. Session bearer values are represented by keyed digests, and runner
authority is resolved from fresh durable state rather than cached or inferred
from runner-supplied identity.

All PostgreSQL integration suites compile into the explicit `postgres` target.
Run the database-backed lane through `./scripts/ci/run-postgres-tests.sh`.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-postgres --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
