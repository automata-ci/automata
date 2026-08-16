# automata-ci-runner-auth-postgres

PostgreSQL durable runner-machine authority lookup for Automata. Each lookup
uses current server-owned state and never trusts runner-supplied identity.

Product composition and integration tests import this adapter directly.
`automata-ci-postgres` owns only shared PostgreSQL test support and does not
re-export adapter namespaces.
