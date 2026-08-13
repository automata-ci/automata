# Runner control-plane security and enrollment

This is the implementation plan and security contract for runner lifecycle and control-plane
communication. The enrollment baseline is implemented in this change; later work is explicit so
rotation, administration, and proxy support cannot grow ad hoc protocols.

## Current communication contract

Runner job traffic is outbound-only to a dedicated runner-control listener. It uses HTTP/2 over
TLS 1.3 with mandatory client certificates, explicit roots, and the single reviewed
`TLS_AES_256_GCM_SHA384` suite. There is no HTTP/1 fallback or forwarded-identity mode.

After rustls validates the full client chain, the server hashes the validated leaf and performs a
fresh `runner_machine_certificates` lookup. Durable state—not certificate subject text or request
fields—selects the runner ID. Every application request rechecks status, desired state,
generation, session epoch, and lease fencing before mutation.

TLS supplies confidentiality, integrity, peer authentication, and replay-safe records. Frames
are not independently signed: that would add no independent trust boundary on the same direct TLS
connection. A future TLS-terminating proxy needs the explicit channel-bound adapter below.

Sensitive durable runner command/RPC payloads use envelope encryption backed by the control-plane
AES-256-GCM keyring. Runner spool payloads use a separate rotation-aware AES-256-GCM keyring.
PostgreSQL is verify-full TLS outside explicit loopback development mode. These at-rest controls
are independent of transport TLS.

## Enrollment flow implemented here

1. An authenticated operator runs `automata runner token --group GROUP`. The client generates
   256 bits of entropy; the server stores only a domain-separated SHA-256 digest. The client
   retains an owner-only pending receipt until it has printed the token, so an ambiguous create
   is retried with the exact operation ID and token rather than creating a second credential.
   This receipt uses the private `XDG_RUNTIME_DIR` and guarantees process-restart recovery within
   the current login session; it is not a persistent host-reboot credential store.
2. Token creation is transactionally reauthorized from current durable `runners:enroll` grants.
   The token is tenant/group scoped, defaults to 15 minutes (one-hour maximum), and is audited.
   The server stores and returns only non-secret metadata; token plaintext stays in the operator
   process and is never echoed by the API.
3. The token is transferred once through a protected operator channel. It is never accepted in
   runner argv. `automata-runner enroll` reads an owner-only file, a dedicated environment value,
   or redirected stdin.
4. The runner loads its strict configuration, generates an ECDSA P-256 key locally, and sends
   only a signed CSR, canonical capabilities, runner name, stable operation ID, and token to the
   human HTTPS listener. It durably stages the operation, one-time token, and local key in one
   owner-only receipt before sending, so a committed response lost across process exit is
   retryable without a second token source.
5. The server validates the CSR, replaces all requested certificate extensions with a fixed
   client-auth-only profile whose validity is derived from PostgreSQL time, then locks the token
   and samples PostgreSQL time again. Runner identity, exact capabilities/labels/slots, leaf
   digest, consumption marker, exact response receipt, and audit event commit atomically.
6. The runner verifies the response against local identity/configuration and creates new
   file-backed roots, chain, and private-key destinations without overwriting different material.
   After a crash, any staged response must match a byte-exact server replay before matching partial
   publication is resumed. The durable request stage is removed only after all credential files and
   directory entries are synchronized. The private key never crosses the runner boundary.

Absent, expired, and mismatched consumed tokens return the same error. A matching retry receives
the byte-exact response committed by the first operation, including after an ambiguous HTTP
outcome; a concurrent different operation has one winner. A certificate from a losing race is
unusable because its digest is not registered. Manually supplied runner leaves are not an
interface. Enrollment serializes the capacity boundary and currently admits at
most 64 registered runners, matching the bounded control-plane capacity snapshot.

If a pending operator-side create is permanently rejected, rerun the exact group and lifetime
while recovery is still possible. Discard it only after a definitive non-ambiguous rejection or
after its original lifetime has elapsed, using `automata runner token --discard-pending`; that
command removes the local receipt and exits without issuing a replacement token.

## Deployment key separation

- `runner-server-cert-source` and `runner-server-key-source` identify runner-control.
- `runner-server-ca-source` is the public server trust bundle installed on runners.
- `runner-client-ca-cert-source` is the runner-client trust anchor and enrollment issuer cert.
- `runner-client-ca-key-source` is the issuer key. Production should use a narrowly readable
  secret mount and eventually the KMS/HSM signer port below.

Client and server CAs may differ. The issuer key must not share storage with runner private keys
or the control-plane/spool envelope keys.

## Delivery plan

### Phase 1: secure enrollment baseline (this change)

- [x] One-time short-lived tokens with digest-only storage and tenant/group scope.
- [x] Fresh `runners:enroll` authorization plus human and system audit events.
- [x] Runner-local key generation and fixed-profile CSR signing.
- [x] Atomic capability/certificate registration with exact idempotent response replay.
- [x] PostgreSQL-clock certificate validity and post-token-lock expiry revalidation.
- [x] Bounded response streaming and crash-reconcilable local credential publication.
- [x] Operator and runner CLIs with no token/private-key argv values.
- [x] Explicit client/server CA roles and removal of static server registration.
- [x] TLS 1.3, HTTP/2, direct mTLS, and AES-256-GCM-SHA384 pinning.
- [x] Accurate terminology: lease offers are mTLS-authenticated and fenced, not separately signed.

### Phase 2: certificate rotation and runner lifecycle

- [ ] Add an mTLS-authenticated rotation prepare endpoint taking a new local CSR.
- [ ] Register old/new digests with bounded overlap (at most two active leaves).
- [ ] Confirm the new leaf on its first session, then write-once revoke the old leaf; make every
  crash boundary retry-safe.
- [ ] Rotate automatically before a configurable renewal window and expose expiry/renewal in
  `doctor`, readiness, and metrics.
- [ ] Add `automata runner list|get|disable|enable|drain|delete` with `runners:read` or
  `runners:manage`, generation bumps, live-session fencing, destructive confirmation, and audit.
- [ ] Add token list/revoke operations that never return token plaintext.
- [ ] Define replacement as a new runner ID/key; preserving a display name requires an explicit
  replace operation.

### Phase 3: CA and credential custody

- [ ] Introduce a signer port with local-PEM, KMS, and HSM implementations so the API never needs
  exportable signing-key bytes.
- [x] Reject issuance beyond issuer or enrolled server-root expiry.
- [ ] Alert on issuer and server-root expiry thresholds.
- [ ] Support client-CA overlap: trust old/new, issue only from new, then remove old after all
  leaves and retained backups age out.
- [ ] Version the server-root bundle and design a trust-root update that cannot replace trust based
  only on the current response.
- [ ] Add CRL/OCSP only for external consumers; runner-control keeps its immediate durable leaf
  revocation lookup.

### Phase 4: scale, availability, and observability

- [ ] Raise the 64-runner bound only together with paginated readiness and capacity snapshots,
  load tests, and explicit per-tenant quotas.
- [ ] Keep fresh mutation authorization. Add a bounded invalidation-aware certificate cache only
  after profiling proves database pressure, with explicit tested revocation latency.
- [ ] Add attempt, denial, replay, CSR rejection, issue, rotation, expiry, and revocation metrics
  without tokens, PEM, names, or labels.
- [ ] Clean expired/consumed token metadata under a documented audit-retention policy.
- [ ] Test multi-replica redemption/rotation races, cancellation, and clock boundaries in
  PostgreSQL integration tests.
- [ ] End-to-end: enroll, run a job, rotate, disable mid-session, and prove the old leaf/session
  cannot resume.

### Phase 5: optional proxy or relay

- [ ] Keep direct mTLS as default. Use a separate listener/protocol; never infer identity from
  `X-Forwarded-*` or generic client-cert headers.
- [ ] Authenticate the proxy with its own mTLS identity and require a short-lived,
  audience-bound, nonce-bearing assertion containing the validated runner leaf digest and TLS
  exporter/channel binding.
- [ ] Use a dedicated assertion key set, replay storage, strict hop limits, and the same durable
  runner lookup/application fencing as direct mTLS.
- [ ] Threat-model smuggling, confused deputy, proxy compromise, partial rollout, and direct
  listener bypass before enabling it.

## Invariants and non-goals

- Enrollment tokens bootstrap a certificate; they are not runner session credentials.
- Certificate subjects and capability documents never grant identity by themselves.
- Ordinary reverse-proxy TLS termination is unsupported without the dedicated adapter.
- Frame signatures are added only if frames cross a trust boundary independent of TLS.
- Private keys, raw tokens, secret values, and decrypted payloads stay out of logs, errors,
  metrics, and durable audit fields.
