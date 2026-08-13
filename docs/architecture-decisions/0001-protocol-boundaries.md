# ADR 0001: Use purpose-specific protocol boundaries

- Status: Accepted
- Date: 2026-08-13

## Context

Automata has several network boundaries with materially different consumers and
traffic profiles. Runners exchange frequent machine frames with Core, an
optional external control plane administers Core shards, browsers and third
parties need approachable HTTP APIs, and Core reports durable usage facts back
to an external control plane.

Using one transport for all of these boundaries would couple public SaaS API
design to internal shard administration and would require replacing the
existing hardened runner transport. Handwritten JSON Schema and Protobuf
definitions for the same management operation would instead create two sources
of truth.

## Decision

The existing `automata.runner.v1` protocol remains canonical Protobuf over its
dedicated, bounded HTTP/2 and mutual-TLS transport. It is not migrated to gRPC
as part of the SaaS management work.

External-control-plane administration of a Core shard uses versioned Protobuf
service definitions and gRPC. The public Core repository owns these
provider-neutral contracts under the `automata.management` package; Automata
Cloud is one possible client. Workload authentication is mandatory and remains
orthogonal to gRPC. An implementation may use mutual TLS or a reviewed
provider-native workload identity adapter, but private networking alone is not
authentication.

Management methods include `google.api.http` annotations so their optional
ProtoJSON projection is declared with the RPC. Deploying an HTTP/JSON
transcoder is not required initially. A cloud deployment may add a reviewed
gateway, while a self-hosted single binary may later expose an embedded adapter.
Neither projection changes the gRPC service as the canonical machine contract.

Browser, CLI, and third-party calls to Automata Cloud remain a separately
versioned HTTP/JSON API described with OpenAPI and implemented by Fastify. The
public Cloud API is not a pass-through copy of the private shard-management
service. Existing JSON formats, including delegated-actor JWTs and shard
capability discovery, retain JSON Schema as their canonical representation.

Core does not synchronously consult Cloud while admitting jobs. Cloud pushes
durable configuration such as entitlement snapshots to Core. Core records
usage in a transactional outbox and delivers bounded, idempotent batches to
Cloud asynchronously.

The initial management contract is
[`automata.management.v1.ShardManagementService`](../../contracts/cloud-core/proto/automata/management/v1/shard_management.proto).

## Consequences

- Rust and TypeScript clients and server interfaces can be generated from one
  management service definition.
- Protobuf compatibility rules and automated breaking-change checks govern the
  management API; semantic authorization, bounds, and transaction invariants
  remain explicit application responsibilities.
- JSON transcoding requires a gateway or embedded adapter and must preserve
  ProtoJSON and gRPC status semantics.
- The public SaaS API may evolve without exposing private shard operations or
  making Core depend on private Cloud code.
- The runner protocol retains its reviewed certificate, retry, and canonical
  byte behavior.

## Alternatives considered

Defining both JSON Schema and Protobuf for management calls was rejected because
the two declarations could drift. Replacing every API with gRPC was rejected
because browser and third-party integrations benefit from ordinary HTTP/JSON,
and the runner transport already has the required binary efficiency.

Connect remains a possible future embedded multi-protocol adapter. It is not
selected for Core until its Rust implementation and Protobuf integration meet
the project's stability and dependency requirements.
