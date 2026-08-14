# ADR 0001: Use purpose-specific protocol boundaries

- Status: Accepted
- Date: 2026-08-13
- Amended: 2026-08-14

## Context

Automata has several network boundaries with materially different consumers and
traffic profiles. Runners exchange frequent machine frames with Core, an
optional external control plane administers Core shards, browsers and third
parties need approachable HTTP APIs, and Core reports durable usage facts back
to an external control plane.

Browser and third-party APIs need a different shape from privileged machine
control. At the same time, implementing multiple custom binary RPC transports
would create unnecessary framing, error-model, client-generation, and
interoperability work. Centralizing unrelated schemas in a repository-level
contracts hierarchy also separates an interface from the code that owns it.

## Decision

Versioned Protobuf and gRPC are the default for privileged binary
machine-to-machine RPC. Each schema is public and lives beside the adapter that
owns it. Cargo generates Rust into `OUT_DIR` with Protox and Tonic, so generated
source is not committed and builds do not require a separately installed
`protoc` or Buf executable.

The current `automata.runner.v1` protocol remains Protobuf over its dedicated,
bounded HTTP/2 and mutual-TLS transport while the management boundary is built.
A separate change may express that protocol as gRPC so runner and management
RPC share one standard transport without coupling their services or trust
domains.

External-control-plane administration of a Core shard uses versioned Protobuf
service definitions and gRPC. The public Core repository owns these
provider-neutral schemas under the `automata.management` package; Automata
Cloud is one possible client. Workload authentication is mandatory and remains
orthogonal to gRPC. An implementation may use mutual TLS or a reviewed
provider-native workload identity adapter, but private networking alone is not
authentication. Management RPCs do not declare an HTTP projection.

Core owns a separate HTTP/JSON API for browsers, CLIs, and third-party
integrations. The self-hosted UI calls Core directly. Automata Cloud exposes its
own thin HTTP/JSON edge, authenticates SaaS users, and delegates ordinary
workspace operations to the same Core API on the selected shard. Cloud-only
billing and account routes are implemented with Fastify. HTTP schemas and
generated OpenAPI descriptions live with the route implementations rather than
in a centralized contracts directory.

Core does not synchronously consult Cloud while admitting jobs. Cloud pushes
durable configuration such as entitlement snapshots to Core. Core records
usage in a transactional outbox and delivers bounded, idempotent batches to
Cloud asynchronously.

The initial management schema is
[`automata.management.v1.ShardManagementService`](../../crates/automata-ci-provisioning-grpc/proto/automata/management/v1/shard_management.proto).

## Consequences

- Rust and TypeScript clients and server interfaces can be generated from one
  management service definition.
- Protobuf compatibility rules govern each machine API; semantic authorization,
  bounds, and transaction invariants remain explicit application
  responsibilities.
- Build-time Rust generation cannot drift from the checked-in schema and does
  not add generated source to review diffs.
- The public SaaS API may evolve without exposing private shard operations or
  making Core depend on private Cloud code.
- Runner and management services can converge on gRPC without sharing messages,
  authorization, or listener configuration.

## Alternatives considered

Defining both JSON Schema and Protobuf for management calls was rejected because
the two declarations could drift. Replacing every API with gRPC was rejected
because browser and third-party integrations benefit from ordinary HTTP/JSON.

Connect remains a possible future embedded multi-protocol adapter. It is not
selected for Core until its Rust implementation and Protobuf integration meet
the project's stability and dependency requirements.
