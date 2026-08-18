# Workload OIDC protocol

`automata-ci-workload-oidc` implements the protocol and cryptography needed by an
action that requests an OIDC token through `@actions/core`.

> [!IMPORTANT]
> Workload OIDC is not advertised to runners and is unsupported end to end.
> This crate has component coverage; the remaining product gates are listed
> below.

The implemented boundary provides:

- bearer-authenticated `GET /oidc/token?api-version=2.0`;
- an optional caller-selected audience;
- an Automata issuer, RS256 ID tokens, discovery metadata, and JWKS;
- bounded credentials and exact replay of an unexpired mint; and
- a repository port that authorizes the workload and reserves an issuance
  atomically.

The caller cannot choose its subject or identity claims. The repository returns
them only after checking an opaque authority ID. A production repository must
recheck job permission, attempt lifecycle and fence, repository binding, event
trust, and authority expiry in the same transaction that reserves or replays a
mint.

## Credential lifetimes

The private request bearer may live for at most 24 hours so a long-running job
is not tied to one short renewable lease. Its key ID and validity interval are
stored before publication. Every mint still revalidates live authority, and an
ID token lives for at most one hour.

The configured supported-claim universe is explicit. Minting fails if durable
authority returns a claim that was not configured and advertised. The crate
does not invent a default audience, subject format, event policy, or claim set.

## Rotate signing keys

Discovery and JWKS responses may be cached for 300 seconds, so rotation has two
phases:

1. Publish the new public JWK on every instance while the old key remains
   active. Wait at least 300 continuous seconds.
2. Make the new private key active for new issuances. Retain the old private
   key for replay and its public JWK for verification.

Retire the old key only after every request bearer that could replay an old-key
issuance has expired, every old-key ID token has expired, and another 300
seconds has passed since the last possible old-key signature. The 24-hour
bearer limit and one-hour token limit are separate; a single cache delay is not
enough.

Key IDs have permanent identity. Durable history binds each ID to one canonical
key-material fingerprint and permits only a later retention deadline. Expiry
ends the need to load the key, but the ID can never be rebound to different
material.

## Product status

The control plane composes the authority and issuance repositories, an optional
fail-closed control issuer, and `/oidc/token` on the non-human Results listener.
The in-memory repository exists for protocol tests only.

Runner inventory intentionally omits OIDC until the deployment proves external
TLS, consistent keys across all serving replicas, and bounded retention for
authority and issuance history. Until then, an entitled job remains ineligible
instead of receiving a partial OIDC environment.
