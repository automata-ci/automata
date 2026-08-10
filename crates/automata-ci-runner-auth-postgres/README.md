# automata-ci-runner-auth-postgres

This crate is the PostgreSQL adapter for `automata-ci-runner-auth`'s narrow
`RunnerMachineDirectory` port. Each lookup joins one exact, unrevoked,
unexpired leaf SHA-256 row to its runner registration and returns server-owned
identity, generation, expiration, and desired state atomically. Expiration is
closed at equality against the PostgreSQL server clock on every fresh lookup;
the caller's process-clock checks remain an additional conservative cutoff.

TLS chain validation is outside this crate. `automata-ci-runner-transport` must
validate the peer chain before `automata-ci-runner-auth` hashes the validated leaf.
This crate does not parse X.509, infer identity from certificates, cache
authority, or accept runner-supplied identity fields.

Only explicit rows in `runner_machine_certificates` authorize a machine.
