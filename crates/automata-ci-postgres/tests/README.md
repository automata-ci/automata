# PostgreSQL aggregate tests

The explicit `postgres` target owns every PostgreSQL adapter suite, including
the Store adapter's schema and integration contracts. Ordinary constructor and
schema tests run with the workspace; live tests are ignored by default because
they require PostgreSQL 18.

Run the same bounded database lanes as CI:

```sh
AUTOMATA_TEST_DATABASE_URL='postgresql://user:password@127.0.0.1:5432/database' \
  ./scripts/ci/run-postgres-tests.sh
```

The harness creates collision-resistant schemas inside its owned namespace and
cleans that namespace after the lane. Use `--plan` to inspect the four exact
Cargo invocations without connecting to a database.
