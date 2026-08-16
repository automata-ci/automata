# automata-ci-provisioning-postgres

PostgreSQL adapters for atomic Automata workspace provisioning, entitlement
application, database-backed GitHub provider desired state, and
authority-scoped usage export. Provider credentials use the mandatory
control-plane envelope key provider; readers return one repeatable-read current
snapshot and never expose ciphertext as configuration.

Portable callers should depend on `automata-ci-provisioning`; the
`automata-ci-postgres` facade preserves the existing `provisioning` namespace.
