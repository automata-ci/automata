# Node API stack

## Decision

Use Fastify for the Automata Cloud web/API process, schema every route surface,
generate OpenAPI from those route schemas, and use PostgreSQL through the low-
level `pg` driver with parameterized raw SQL. No ORM is required.

As of this draft, the current Fastify documentation is on v5. Fastify recommends
JSON Schema for request validation and response serialization, using Ajv and
`fast-json-stringify` internally. `@fastify/swagger` supports generating an
OpenAPI document from the same route definitions, and the official TypeBox type
provider derives TypeScript handler types from TypeBox/JSON schemas.

Primary references:

- [Fastify validation and serialization](https://fastify.dev/docs/latest/Reference/Validation-and-Serialization/)
- [`@fastify/swagger`](https://github.com/fastify/fastify-swagger)
- [Fastify TypeBox type provider](https://github.com/fastify/fastify-type-provider-typebox)
- [node-postgres parameterized queries](https://node-postgres.com/features/queries)
- [node-postgres transactions](https://node-postgres.com/features/transactions)
- [RFC 9457 problem details](https://datatracker.ietf.org/doc/html/rfc9457)

Exact versions will be pinned when `automata-cloud` is scaffolded.

## Schema source of truth

Use TypeBox-compatible JSON Schemas in application code so one definition
provides:

- Fastify input validation;
- Fastify response serialization/filtering;
- inferred TypeScript request and reply types;
- OpenAPI generation;
- documentation pages;
- generated client inputs; and
- language-neutral contract fixtures for Rust.

Do not separately maintain a TypeScript interface, validation schema, OpenAPI
component, and client DTO for the same message.

Every route must define:

```text
params + querystring + relevant headers + body + each emitted response
```

Body-less routes still schema their path/query/header inputs and responses.
Streaming routes schema the handshake and each application frame even though
OpenAPI represents the HTTP response as an event stream rather than ordinary
JSON.

All object schemas default to `additionalProperties: false`. Bounds are
required for strings, arrays, maps, batches, and uploaded bodies. Formats and
custom patterns must be registered explicitly and tested; TypeBox does not make
format validation magically authoritative.

Database lookups and network calls do not occur inside schema validators. They
run after structural validation in handlers/services. Fastify specifically
warns against asynchronous database work during initial validation.

## API documentation and clients

- Register `@fastify/swagger` before routes.
- Generate OpenAPI from the actual built application in CI.
- Commit a deterministic OpenAPI snapshot for review and client generation.
- Fail CI on an unexplained snapshot diff.
- Serve interactive documentation only in development or behind explicit staff
  authentication; internal routes and example credentials must not be public.
- Give every public/generatable route a stable `operationId`.
- Keep browser-session endpoints and internal service endpoints in distinct
  OpenAPI documents/security schemes even if one process serves both.
- Generate clients from the snapshot; never build URLs by string concatenation
  throughout feature code.

Fastify's automatic validation errors should be normalized by a central error
handler into the exact Automata RFC 9457 schema. Raw Ajv details, stack traces,
SQL errors, token contents, and upstream bodies must not leak to clients.

## Suggested Cloud module shape

```text
apps/cloud/src/
├── app.ts                 Fastify composition only
├── web.ts                 HTTP runtime role
├── worker.ts              durable background-work role
├── platform/
│   ├── database/
│   ├── http/
│   ├── observability/
│   └── stripe/
└── modules/
    ├── accounts/
    ├── workspaces/
    ├── deployments/
    ├── github/
    ├── entitlements/
    ├── usage/
    └── billing/
```

Each domain module may contain routes, schemas, services, repositories, and
tests. Route handlers remain thin; domain services do not depend on Fastify
request/reply objects.

## Raw SQL rules

Use `pg.Pool` for ordinary queries and acquire one `pg.Client` for an entire
transaction. PostgreSQL transactions are connection-scoped, so a transaction
must not mix `pool.query` calls with a checked-out client.

- Parameterize every data value (`$1`, `$2`, ...). Never interpolate user data.
- Dynamic identifiers are disallowed in ordinary product queries. A parameter
  cannot safely stand for a table or column name.
- List selected columns explicitly. Avoid `SELECT *` at durable boundaries.
- Put tenant/workspace predicates in every tenant-owned query and begin relevant
  indexes/unique constraints with that identity.
- Treat returned database rows as untrusted boundary data and map/validate them
  into domain types.
- Keep transaction ownership in the service/use-case layer so multiple
  repository operations can commit with the outbox/audit record atomically.
- Add statement and transaction timeouts, cancellation, bounded pool settings,
  and slow-query observability.
- Use numbered, immutable raw SQL migration files plus a migration ledger with
  checksums. Schema changes are reviewed like code and use expand/migrate/
  contract sequencing for rolling deploys.
- Outbox/inbox claiming uses PostgreSQL concurrency primitives explicitly; no
  in-memory worker queue is authoritative.

An ORM would not remove any of these requirements. Raw SQL is a sensible choice
for this domain because tenant scoping, idempotency, ledgers, inboxes/outboxes,
and reconciliation benefit from visible transactional semantics.

## Testing gates

- Route injection tests cover every status code and confirm response-schema
  serialization.
- Contract tests reject missing and unknown fields in params, query, headers,
  body, and responses.
- Repository integration tests run against real PostgreSQL migrations.
- Tenant-isolation tests seed at least two workspaces and attempt crossed IDs.
- Transaction tests terminate work at each durable step and verify replay.
- The generated OpenAPI document and generated client compile in CI.
- Logs are inspected in tests to ensure tokens, payment details, secrets, SQL
  parameters, and live-log contents are not accidentally recorded.
