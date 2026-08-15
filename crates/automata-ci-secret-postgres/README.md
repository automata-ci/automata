# automata-ci-secret-postgres

Envelope-encrypted PostgreSQL storage for Automata's built-in secret provider.
Plaintext is encrypted before SQL execution and envelopes are bound to the
exact tenant and immutable secret version.

The `automata-ci-postgres` facade preserves the existing `secret` namespace.
