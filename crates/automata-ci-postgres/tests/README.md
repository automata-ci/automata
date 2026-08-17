# PostgreSQL integration tests

The explicit `postgres` target covers the three database boundaries exercised
by production CI:

- GitHub sign-in and durable session creation;
- runner lease, command, log, and terminal-result transactions;
- authenticated public workflow, job, log, and artifact reads.

Lower-level domain behavior belongs in ordinary unit tests beside the owning
crate. This target intentionally does not duplicate every SQL race or corrupt
row permutation. Live tests are ignored by default because they require
PostgreSQL 18.

Run the same bounded database lanes as CI:

```sh
AUTOMATA_TEST_DATABASE_URL='postgresql://user:password@127.0.0.1:5432/database' \
  ./scripts/ci/run-postgres-tests.sh
```

The same lane also runs the provider admission matrix and the PostgreSQL
artifact/cache contracts. The harness creates collision-resistant databases
inside its owned namespace and cleans that namespace after the lane. Use
`--plan` to inspect the four exact Cargo invocations without connecting to a
database.
