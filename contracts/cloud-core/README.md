# Automata Cloud/Core contracts

This directory contains the public, language-neutral wire contracts between an
Automata Core deployment and an optional external control plane such as
Automata Cloud. Core implementations must not depend on private Cloud code.

Contracts are versioned independently from the Automata release. Within a
version, objects are exact and reject unknown fields; an incompatible change
requires a new contract version.

The current contract families are:

- [`v1/shard-capabilities.schema.json`](v1/shard-capabilities.schema.json)
  describes the response from `GET /internal/v1/capabilities`, allowing a
  control plane to verify a load-balanced Core shard before routing traffic.
- [`v1/delegated-actor.md`](v1/delegated-actor.md) profiles a short-lived ES256
  JWT used when an external control plane calls Core on behalf of a human. Its
  protected header and claims have exact JSON Schemas.

Consumers may vendor a released schema, but should record its upstream path and
SHA-256 digest so local generated types and runtime validators cannot drift
silently.
