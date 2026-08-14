# automata-ci-provisioning-postgres

This crate implements the transport-neutral Core workspace-provisioning port
against PostgreSQL. One transaction creates the workspace tenant, maps or
reuses the delegated external actor, grants the initial owner role, appends an
audit event, and commits an idempotent operation receipt.

It contains no gRPC, TLS, Cloud billing, or private Automata Cloud code. The
product composition root supplies this adapter to the public management gRPC
transport.

