# PostgreSQL integration tests

The repository tests are ignored by the default test run because they require
a live PostgreSQL server. Run them explicitly against a disposable database or
a role that may create schemas:

```sh
AUTOMATA_TEST_DATABASE_URL='postgresql://user:password@127.0.0.1:5432/database' \
  cargo test -p automata-store --locked --all-targets -- \
    --include-ignored --test-threads=1
```

Each test creates a collision-resistant `automata_test_<uuid>` schema, scopes
every pooled connection to that schema, and drops only that exact schema after
the scenario. The harness also performs cleanup before propagating assertion
panics. Tests never truncate shared tables or use filesystem temporary paths.
