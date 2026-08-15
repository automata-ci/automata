# automata-ci-provisioning

This crate owns the transport-neutral application boundary for an authorized
external control plane to provision workspaces, apply execution-entitlement
snapshots, apply database-backed GitHub provider desired state, and pull
immutable usage events from one Automata Core shard. It
validates the public contract's domain values and keeps workload authority,
idempotency identity, mutations, and export behind explicit ports.

It contains no gRPC, HTTP, SQL, Cloud billing, or private Automata Cloud code.
The public versioned wire schema lives beside its gRPC adapter in
`automata-ci-provisioning-grpc`; the atomic PostgreSQL adapter lives in
the `provisioning` namespace of `automata-ci-postgres`.

Usage export contains provider-neutral actual execution facts rather than
prices, invoices, or Stripe objects. A consumer deduplicates stable event IDs
and commits its continuation cursor with the accepted events.

Provider desired state separates the encrypted shard-wide GitHub App
configuration from each workspace's complete repository set. It contains no
Cloud billing or GitHub OAuth installation ownership policy.
