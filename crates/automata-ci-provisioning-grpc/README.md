# automata-ci-provisioning-grpc

This crate owns and serves the public
[`automata.management.v1.ShardManagementService`](proto/automata/management/v1/shard_management.proto)
schema over gRPC/HTTP/2. It requires a client certificate at the TLS handshake,
authenticates that verified certificate chain for every request, validates and
scope-checks the domain command, and calls transport-neutral workspace
provisioning or entitlement-application ports.

The server accepts a pre-bound listener so the product composition root retains
ownership of startup ordering and port conflicts. The Automata binary composes
it only when a complete private management-listener configuration is supplied;
standalone self-hosted deployments expose no placeholder endpoint. The product
maps a dedicated-CA-verified leaf certificate through an exact SHA-256 pin to a
stable shard-scoped authority, and supplies the durable
`automata-ci-postgres` management transaction adapters. Entitlement snapshots
are complete, monotonically revisioned workspace aggregates; the contract does
not allocate rolling per-job budget slices.

Cargo generates the private Rust wire module into `OUT_DIR` with Protox and
Tonic. Building therefore needs no separately installed `protoc` or Buf binary,
and generated Rust is never checked into the repository. Other implementations,
including Automata Cloud, generate their client from the same public schema.
