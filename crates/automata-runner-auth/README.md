# Runner machine authentication composition

This crate composes the runner transport's already-validated mTLS peer evidence
with shared durable registration state. It does not parse X.509 identities and
does not trust runner protocol fields or forwarded certificate headers.

`automata-runner-transport` must terminate mTLS itself and pass the rustls peer
chain only after WebPKI chain, time, trust-root, and client-auth-purpose
validation. Rustls supplies the leaf first. This crate applies allocation bounds,
hashes that leaf with SHA-256, and retrieves all authority through
`RunnerMachineDirectory`.

The production PostgreSQL adapter must perform one fresh indexed lookup by the
32-byte leaf SHA-256 and decode the external identity, internal runner UUID,
generation, exact registered digest, certificate expiration, and desired state
from one consistent row or transaction snapshot. Authentication and subsequent
registration authorization each perform their own lookup so certificate
rotation, generation changes, disabling, and identity drift take effect across
replicas without connection-local authorization state.
