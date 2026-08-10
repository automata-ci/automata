# Automata GitHub Actions-compatible workload OIDC foundation

This crate implements the isolated protocol and cryptographic foundation needed
by actions that request an OIDC token through `@actions/core`:

- bearer-authenticated `GET /oidc/token?api-version=2.0` requests;
- optional caller-selected `audience` values;
- an Automata-owned issuer, RS256 ID tokens, discovery metadata, and JWKS;
- bounded, redacted request credentials and exact unexpired mint replay; and
- an injected repository port that must atomically authorize the current
workload before reserving an issuance.

Private request bearers have an independent maximum lifetime of 24 hours so a
bounded long-running job is not tied to its short renewable lease. Their exact
key ID and validity interval must be durably pinned before publication; retry
uses the retained named key to reproduce identical protected bytes. Every mint
still revalidates live authority, and each returned ID token remains capped at
one hour.

RS256 rotation is a required two-phase operation because discovery and JWKS
responses are publicly cacheable for 300 seconds. First, load and publish the
new public JWK alongside the old key on every serving instance while the old
key remains active. Do not activate the new private key until that publication
has been continuously available for at least the full 300-second cache
horizon; a verifier may otherwise retain an old-only JWKS through activation.

Second, make the new key active only for newly reserved issuances. Keep the old
private signing key loaded for exact durable replay and keep its public JWK
published until all three retirement horizons have closed: every request-
bearer interval that can replay an old-key issuance has expired, every ID token
signed by the old key has expired, and 300 seconds have elapsed since the last
possible old-key signing. Remove the old key only after the latest of those
horizons. The request-bearer and ID-token ceilings are independent (24 hours
and one hour respectively), so a single 300-second delay is not a safe
retirement policy.

Provider discovery receives one explicit bounded supported-claim universe.
Minting fails closed if durable authority returns an additional claim that was
not configured and advertised; the foundation does not hardcode mutable
provider claim policy.

Durable key history is also permanent. Each request-bearer or ID-token-signing
key ID is bound to its canonical key-material fingerprint; its retention
deadline may only advance and its row cannot be deleted. Expiry ends the
requirement to keep that key loaded, but the key ID can never be rebound to
different material.

The caller never supplies a subject or identity claim. The repository returns
those values only after checking the authenticated opaque authority ID. A
production repository must recheck current job permission, execution lifecycle,
attempt fence, repository binding, and event trust in the same transaction that
reserves or replays an issuance. It must also cap the token at the durable
authority deadline. The in-memory adapter exists for protocol tests and local
composition only.

Product composition supplies the durable authority and issuance repositories,
an optional fail-closed runner-control issuer, and `/oidc/token` on the
non-human Results listener. Workload OIDC nevertheless remains unsupported and
unadvertised to runners until the external TLS boundary, homogeneous
multi-replica/key fleet, and bounded authority/issuance retention policy are
release-ready. This foundation does not invent a default audience, subject
format, event-trust policy, or repository claim set; all remain explicit,
authenticated repository data.
