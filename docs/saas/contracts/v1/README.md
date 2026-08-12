# Automata Cloud/Core contracts v1

Status: initial working draft, 2026-08-12. Nothing in this directory is
implemented or committed as a compatibility promise yet.

This directory starts the language-neutral boundary between private Automata
Cloud and public Automata Core. It contains exact JSON Schemas, illustrative
OpenAPI documents, and the rules that future Fastify and Rust implementations
must share.

## Artifacts

- [Node API stack](node-api-stack.md)
- [Signed token profile](token-profile.md)
- [Semantic invariants](semantic-invariants.md)
- [Page-model and mutation boundary](page-model-and-mutations.md)
- [Core internal/data-plane OpenAPI](openapi-core.yaml)
- [Cloud ingestion OpenAPI](openapi-cloud.yaml)
- [JSON Schemas](schemas/)
- [Valid example messages](examples/)

The OpenAPI documents are design fixtures. Once routes exist, the Node service
must generate its OpenAPI document from the same route schemas used at runtime;
CI will compare the generated artifact with the reviewed contract. We should
not maintain a hand-written API description that can silently drift from the
server.

## Contract families started here

| Contract | Initial artifact | Status |
| --- | --- | --- |
| Delegated actor assertion | `delegated-actor-claims.schema.json` | Concrete draft |
| Shard discovery/capabilities | `shard-capabilities.schema.json` | Concrete draft |
| Tenant provisioning | `tenant-provisioning.schema.json` | Concrete draft |
| Live-log authorization and frames | `live-log.schema.json` | Concrete draft |
| Usage-event ingestion | `usage-events.schema.json` | Concrete draft |
| Entitlement projection | `entitlement-snapshot.schema.json` | Concrete draft |
| Error responses | `problem.schema.json` | Concrete draft |
| Core page models | Existing TypeScript model and validators | Needs extraction into `@automata/ui-core` schema |
| Core mutations | Repository publication-policy mutation | Recommended first vertical slice; exact schema follows the public UI extraction |

The page-model and mutation entries are deliberately not represented by a
permissive `object` schema. “Any JSON” would create an attractive but false API
contract. They enter OpenAPI only after their exact discriminated schemas exist.

## Wire rules

- JSON request and response objects are exact: unknown fields are rejected.
- Every Fastify route declares schemas for path parameters, query parameters,
  headers, body, successful responses, and error responses that it uses.
- JSON bodies use UTF-8 `application/json`. Errors use
  `application/problem+json` following RFC 9457 plus bounded Automata extension
  fields.
- IDs are canonical lowercase UUID strings unless their schema defines another
  portable identifier.
- Potentially lossless counters and cursors are decimal strings. They are not
  JSON numbers that JavaScript could round.
- Instants are non-negative Unix epoch milliseconds. JWT `iat`, `exp`, and
  `auth_time` remain JWT NumericDate seconds.
- Durations and metered quantities are integer seconds. Floating-point billing
  values never cross this boundary.
- Every mutation carries a UUID idempotency key. Replaying the same key and
  canonical request returns the recorded result; replaying it with different
  content returns a conflict.
- Request IDs are for tracing only and grant no idempotency or authority.
- Tokens and signed URLs are never accepted in query strings unless a future
  protocol documents an unavoidable exception.
- Secrets are marked `writeOnly` in documentation where applicable and are
  redacted from logs, traces, metrics, error details, and support tooling.

## Compatibility

- The HTTP major version is present in the path (`/internal/v1`, `/data/v1`).
- Each durable event/token/message also has a schema or protocol version.
- Adding a new endpoint is compatible. Removing or changing an endpoint is not.
- Because exact objects reject unknown fields, adding a field to an existing
  object requires a new supported schema version; it is not treated as a
  harmless optional change.
- Producers may support more than one message version during a rolling upgrade.
- Shard discovery advertises supported versions before Cloud routes customer
  traffic to a new Core release.
- Consumers reject unsupported versions rather than guessing or partially
  interpreting a message.

This strictness costs a little ceremony but gives us deterministic rolling
upgrades and makes Rust/TypeScript disagreement visible in tests.

## Authentication layers

Core internal endpoints require both:

1. workload/service authentication at the transport boundary; and
2. a short-lived delegated actor assertion when a human is acting.

The OpenAPI bearer scheme documents the actor assertion. It does not replace
mTLS or workload identity. Provisioning and entitlement delivery are service
operations and do not pretend to have a human actor.

Cloud validates JWT signature, algorithm, issuer, audience, expiry, and the
claim schema. Core does the same for Cloud-issued actor assertions, maps
`(issuer, subject)` to its durable principal, and loads current membership/RBAC.
No token claim contains authoritative Core roles or permissions.

Core issues a separate, narrow live-log capability after authorizing the actor.
That capability cannot call the control-plane API.

## Generation and conformance

The eventual repositories should enforce:

1. Route schemas are the runtime validator and response serializer source.
2. The built Fastify server emits OpenAPI after all routes register.
3. CI fails if emitted OpenAPI differs from the reviewed snapshot.
4. TypeScript request/response types are inferred from the schemas rather than
   duplicated manually.
5. Generated clients are tested against a live in-process server.
6. Rust has consumer/provider fixtures for the same valid and invalid examples.
7. Every example in `examples/` validates against its named schema.
8. Fuzz/property tests cover unknown fields, size bounds, malformed IDs,
   cross-workspace identities, event replay, and unsupported versions.

## Immediate review questions

- Confirm stable shard slugs such as `prod-us-east-1-001` as the initial shard
  ID format. Environment-profile IDs and manifest digests reuse Core's existing
  content-attested profile types.
- Review the proposed ES256/KMS/JWKS actor-signing profile and measure it with a
  Node-to-Rust spike.
- Validate private networking plus mTLS as the first workload-authentication
  layer in the target infrastructure.
- Validate the proposed 60-second log capability, 15-second heartbeat, and
  15-minute connection lifetime against the first load balancer.
- Spike TypeBox-authored page contracts in `@automata/ui-core` and Rust
  conformance fixtures without creating two hand-maintained definitions.

See [recommended starting points](../../05-decision-starting-points.md) for the
rationale and implementation order.
