# automata-runner-auth-postgres

This crate is the PostgreSQL adapter for `automata-runner-auth`'s narrow
`RunnerMachineDirectory` port. Each lookup joins one exact, unrevoked leaf
SHA-256 row to its runner registration and returns server-owned identity,
generation, expiration, and desired state atomically.

TLS chain validation is outside this crate. `automata-runner-transport` must
validate the peer chain before `automata-runner-auth` hashes the validated leaf.
This crate does not parse X.509, infer identity from certificates, cache
authority, or accept runner-supplied identity fields.

Legacy `runners.certificate_fingerprint` values are intentionally ignored.
Only explicit rows in `runner_machine_certificates` authorize a machine.
