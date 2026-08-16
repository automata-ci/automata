# automata-ci-auth-postgres

PostgreSQL persistence for Automata human authentication, authorization,
provider-token custody, GitHub identity mapping, RBAC, and runner enrollment.

This is a concrete adapter crate. Portable callers should depend on the ports
in `automata-ci-auth`; product composition and integration tests import this
adapter directly. `automata-ci-postgres` owns only shared PostgreSQL test
support and does not re-export adapter namespaces.
