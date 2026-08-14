# automata-ci-provisioning

This crate owns the transport-neutral application boundary for an authorized
external control plane to provision a workspace on one Automata Core shard. It
validates the public contract's domain values and keeps workload authority,
idempotency identity, and durable provisioning behind explicit ports.

It contains no gRPC, HTTP, SQL, Cloud billing, or private Automata Cloud code.
The public versioned wire schema lives beside its gRPC adapter in
`automata-ci-provisioning-grpc`; the atomic PostgreSQL adapter lives in
`automata-ci-provisioning-postgres`.
