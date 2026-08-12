# Signed token profile

## Delegated actor assertion

Cloud issues a compact signed JWT for one short-lived Cloud-to-Core request
window. It is an access assertion for Core, not the Cloud browser session and
not a copy of the GitHub access token.

The payload must validate against
`delegated-actor-claims.schema.json`. The protected JOSE header must contain:

```json
{
  "typ": "at+jwt",
  "alg": "ES256",
  "kid": "<active signing-key identifier>"
}
```

Verification rules:

- Accept an explicit asymmetric algorithm allowlist; never derive acceptable
  algorithms from the token itself.
- Reject `none`, symmetric algorithms, missing/unknown `kid`, duplicate JSON
  fields, malformed compact encoding, or noncanonical claims.
- Match `iss` exactly to a configured Cloud issuer.
- Match `aud` exactly to the shard receiving the request.
- Match `workspace_id` to the route and resource context before lookup.
- Require `auth_time <= iat < exp`, bound clock skew, and impose a short maximum
  token lifetime even if `exp` claims longer.
- Treat `jti` as an audit/correlation identity, not as authorization or general
  mutation idempotency.
- Map `(iss, sub)` to a durable Core principal, then resolve current membership
  and role bindings. Absence, suspension, or revision conflict fails closed.
- Never accept a role or permission claim as Core authority.

Use a two-minute lifetime initially, with a hard five-minute verifier maximum.
Cloud may reuse one assertion for a small burst from the same session to the
same workspace and shard, but must not persist it in the browser or database.

## Signing-key distribution

Use ES256 with an AWS KMS `ECC_NIST_P256` asymmetric signing key in the Cloud
deployment so Core only needs verification material. Publish the public key at
an issuer-pinned JWKS endpoint. The signing and verification interfaces remain
provider-neutral so self-hosted deployments can use local PEM/JWK material.
The contract assumes:

- multiple verification keys may overlap during rotation;
- every token names its key with `kid`;
- a previously fetched key remains usable for a bounded cache period during a
  Cloud/JWKS outage;
- unknown keys trigger one bounded refresh, not an unbounded request storm;
- issuer configuration and key retrieval never follow arbitrary token-provided
  URLs; and
- removal/compromise has an explicit emergency revocation path.

Core does not require a complete interactive OIDC flow to consume these access
assertions. Ed25519/EdDSA remains a viable later alternative, but changing the
algorithm is a reviewed protocol migration rather than an automatic negotiation.

## Live-log capability

Core issues a different signed JWT whose payload validates against
`live-log.schema.json#/definitions/capabilityClaims`.

- It has a different audience and preferably a distinct signing-key domain.
- It grants only `logs:read` for one workspace, attempt, and stream.
- It cannot call Core internal APIs or authorize another log.
- Its initial lifetime should be roughly long enough to establish/retry a
  connection, for example 60 seconds.
- Expiry is checked when the connection is established. A connected stream has
  a separate bounded maximum connection lifetime, after which the browser gets
  a new capability and resumes by cursor.
- It is sent in an `Authorization` header, never in the stream URL.

The browser can see this capability by design, so narrow scope, short lifetime,
origin/CORS controls, redaction, and server-side authorization are essential.
