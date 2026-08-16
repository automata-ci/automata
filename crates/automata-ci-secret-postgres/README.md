# automata-ci-secret-postgres

Envelope-encrypted PostgreSQL storage for Automata's built-in secret provider.
Plaintext is encrypted before SQL execution and envelopes are bound to the
exact tenant and immutable secret version.

Product composition and integration tests import this adapter directly.
`automata-ci-postgres` owns only shared PostgreSQL test support and does not
re-export adapter namespaces.
