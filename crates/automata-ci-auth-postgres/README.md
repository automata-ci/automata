# automata-ci-auth-postgres

PostgreSQL persistence for Automata human authentication, authorization,
provider-token custody, GitHub identity mapping, RBAC, and runner enrollment.

This is a concrete adapter crate. Portable callers should depend on the ports
in `automata-ci-auth`; the `automata-ci-postgres` facade preserves the existing
`auth` namespace for server composition.
