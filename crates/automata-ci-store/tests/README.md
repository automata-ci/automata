# Store contract tests

`store_contracts` contains source-only and in-memory contracts for Store values
and repository ports. It does not require PostgreSQL:

```sh
cargo test -p automata-ci-store --test store_contracts --all-features --locked
```

The concrete Store adapter, canonical migration, schema contracts, and live
database suites are owned by `automata-ci-postgres/tests`. Run those through
`scripts/ci/run-postgres-tests.sh` so they share the repository's bounded,
namespace-isolated PostgreSQL harness.
