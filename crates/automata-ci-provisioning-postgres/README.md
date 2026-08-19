# automata-ci-provisioning-postgres

PostgreSQL adapters for atomic Automata tenant provisioning, entitlement
application, database-backed GitHub provider desired state, and
authority-scoped usage export. Provider credentials use the mandatory
control-plane envelope key provider; readers return one repeatable-read current
snapshot and never expose ciphertext as configuration.

Runner-policy-only updates advance the shared provider configuration revision
and the independent policy revision without decrypting, replacing, or
reauthenticating the retained credential envelopes.

Portable callers should depend on `automata-ci-provisioning`; product
composition and integration tests import this concrete adapter directly.
`automata-ci-postgres` owns only shared PostgreSQL test support.
