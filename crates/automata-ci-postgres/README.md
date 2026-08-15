# automata-ci-postgres

Compatibility facade for Automata's domain-specific PostgreSQL adapters. Its
public namespaces re-export the independently compiled adapter crates:

- `auth` from `automata-ci-auth-postgres`;
- `provisioning` from `automata-ci-provisioning-postgres`;
- `runner_auth` from `automata-ci-runner-auth-postgres`;
- `secret` from `automata-ci-secret-postgres`;
- `store` from `automata-ci-store-postgres`.

New code should depend directly on the smallest domain crate it uses. The
facade preserves existing source compatibility and owns the consolidated
PostgreSQL integration-test target and unstable `test-support` feature.

Schema migrations belong to `automata-ci-store-postgres`. All PostgreSQL
integration suites compile into the explicit `postgres` target; run the
database-backed lane through `./scripts/ci/run-postgres-tests.sh`.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-postgres --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
