# Delegated actor assertion v1

An external control plane may call Automata Core on behalf of an authenticated
human using a short-lived JWT access assertion. The assertion proves identity;
it never grants a Core role or permission. Core maps `(iss, sub)` to a durable
principal and evaluates current workspace membership, RBAC, resource policy,
and audit rules for every operation.

## Wire profile

- The token is a compact JWS JWT.
- The protected header validates against
  `delegated-actor-protected-header.schema.json` and is exactly `typ`, `alg`, and
  `kid`.
- The claims validate against `delegated-actor-claims.schema.json`.
- `alg` is `ES256`; the signing key is a P-256 asymmetric key.
- `sub` is the external control plane's stable account UUID, not a GitHub login
  or access token.
- `aud` is the stable shard ID receiving the request.
- `workspace_id` is the only workspace for which the assertion may be used.
- `jti` is an audit/correlation identifier, not mutation idempotency authority.

## Issuer rules

The issuer and its JWKS URL are deployment configuration. A verifier must never
follow an issuer, key URL, or other location supplied by an unverified token.
The issuer comparison is exact. A production issuer uses HTTPS.

The JWKS publishes only public P-256 keys with `kty: EC`, `crv: P-256`,
`alg: ES256`, `use: sig`, and a matching `kid`. A private `d` member must never
be exposed. Multiple keys may overlap during rotation. An unknown `kid` may
trigger one bounded, rate-limited refresh before verification fails closed.

## Verification rules

1. Parse the compact token with bounded input size and reject malformed or
   duplicate JSON members.
2. Require the exact protected-header shape and an explicit `ES256` algorithm
   allowlist. Never choose acceptable algorithms from the token itself.
3. Select a configured issuer key by `kid` and verify the signature before
   trusting claims.
4. Validate the exact claims schema, issuer, shard audience, route workspace,
   and mapped external principal.
5. Require `auth_time <= iat < exp`. Apply bounded clock skew and reject any
   assertion whose `exp - iat` exceeds five minutes, even if its signature is
   valid. The recommended issuer lifetime is two minutes.
6. Resolve current Core authorization. A missing, removed, or suspended
   principal or membership fails closed.

The assertion is service-to-service material. It must not be persisted in the
browser or database, included in URLs, or recorded in logs, traces, analytics,
or error details. Transport-level workload authentication remains a separate
requirement for the private Core API.
