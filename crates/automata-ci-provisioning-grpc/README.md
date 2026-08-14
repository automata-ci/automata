# automata-ci-provisioning-grpc

This crate owns and serves the public
[`automata.management.v1.ShardManagementService`](proto/automata/management/v1/shard_management.proto)
schema over gRPC/HTTP/2. It requires a client certificate at the TLS handshake,
authenticates that verified certificate chain for every request, validates and
scope-checks the domain command, and calls the transport-neutral provisioning
port.

The server accepts a pre-bound listener so the product composition root retains
ownership of startup ordering and port conflicts. It is not yet wired into the
Automata binary: that happens with the durable workspace provisioning adapter,
so Core never advertises an endpoint that cannot perform its transaction.

Cargo generates the private Rust wire module into `OUT_DIR` with Protox and
Tonic. Building therefore needs no separately installed `protoc` or Buf binary,
and generated Rust is never checked into the repository. Other implementations,
including Automata Cloud, generate their client from the same public schema.
