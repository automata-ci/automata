# Automata Cloud/Core contracts

This directory contains the public, language-neutral wire contracts between an
Automata Core deployment and an optional external control plane such as
Automata Cloud. Core implementations must not depend on private Cloud code.

Contracts are versioned independently from the Automata release. Within a
version, objects are exact and reject unknown fields; an incompatible change
requires a new contract version.

The first contract is
[`v1/shard-capabilities.schema.json`](v1/shard-capabilities.schema.json). It
describes the response from `GET /internal/v1/capabilities`, allowing a control
plane to verify a load-balanced Core shard's identity, release, public data-plane
origin, and supported protocol versions before routing customer traffic.

Consumers may vendor a released schema, but should record its upstream path and
SHA-256 digest so local generated types and runtime validators cannot drift
silently.
