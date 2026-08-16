# automata-ci-postgres

Shared PostgreSQL integration-test support for Automata's independently
compiled domain adapters. Product code depends directly on the smallest domain
crate it uses; this package owns only the consolidated PostgreSQL test target,
its cleanup utility, and the explicitly enabled `test-support` fixture API.

Schema migrations belong to `automata-ci-store-postgres`. All PostgreSQL
integration suites compile into the explicit `postgres` target; run the
database-backed lane through `./scripts/ci/run-postgres-tests.sh`.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-postgres --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
