# Post-accept runtime-authority delivery

Automata delivers workload credentials only after the runner has durably
accepted an exact lease offer. The lease offer and its persisted outbox payload
contain authority metadata, never bearer values. A separate versioned exchange
binds any credential bundle to the accepted attempt, protects it on the runner,
and records runner custody before user code can start.

This contract is component complete across the protocol, control handler,
PostgreSQL adapter, runner journal, runner supervisor, and GitHub repository
authority composition. It has boundary, product-composition, restart, race, and
ignored PostgreSQL integration coverage. It is not by itself a claim that every
GitHub Actions workflow or runner provider is supported; the current product
limits remain in [authentication](authentication.md) and
[compatibility](compatibility.md).

## Security outcome

The delivery design enforces these invariants:

- `LeaseOffer` is value-free. It contains the accepted lease, immutable `JobIR`,
  stable slot, and optional value-free managed-secret bindings.
- The server does not invoke a runtime-authority issuer before the durable
  acceptance transaction admits the exact offer.
- Request, grant, and acknowledgement carry one identical delivery binding.
- The control database stores request and custody evidence plus SHA-256
  digests. It stores neither credential plaintext nor an encoded grant.
- The runner protects the complete canonical authority bundle in its encrypted
  spool before sending a custody acknowledgement.
- The journal records the protected content reference and exact digest before
  acknowledgement. The execution adapter receives authorities only after the
  acknowledgement is durably marked complete.
- A credential-free job receives an empty bundle. Explicit repository denial
  and OIDC-only permission maps do not call the GitHub repository-token issuer.
- A cancellation observed during request or acknowledgement stops the delivery
  exchange and terminalizes the attempt without invoking user code.
- Missing, stale, conflicting, transitive, or unsupported-generation evidence
  fails closed.

Transport encryption remains mandatory. The grant is an ephemeral value-bearing
message over the direct mTLS runner connection; the absence of durable plaintext
does not make an untrusted transport safe.

## Version and exact binding

Runtime-authority delivery is defined only for runner protocol version 2 and
delivery generation 1. Generation zero is invalid. A later generation is
rejected until refresh, predecessor, and revocation semantics are specified for
that generation. A protocol-1 runner cannot deserialize the new exchange as a
compatible legacy offer and is rejected during negotiation or message
validation.

Migration 0037 retains protocol-1 session rows as historical control-plane
evidence while admitting protocol-2 sessions. This is not a protocol-1 delivery
path: runtime-authority custody rows require protocol 2, and negotiation and
message validation reject protocol-1 execution.

Every delivery is bound to all of these coordinates:

| Coordinate | What it prevents |
| --- | --- |
| Runner session fence | Reuse by a different connection, runner generation, or session epoch. |
| Protocol version | Downgrade or reinterpretation by an older message contract. |
| Attempt ID | Moving authority between job attempts or reruns. |
| Stable runner slot | Cross-slot delivery and concurrent-slot confusion. |
| Lease ID and fencing token | Reuse after reassignment, expiry, or a newer lease generation. |
| Offer operation ID | Substitution of another durable lease-offer publication. |
| Offer command sequence | Reordering or replay outside the exact outbox command. |
| Canonical `JobIR` digest | Issuance for different steps, permissions, environment, or trust evidence. |
| Delivery generation | Silent credential refresh or rollback. |

The admission truth table exercises every combination of exact and mismatched
coordinates. The all-exact row is the only admitted row. A future generation is
rejected by the authorization constructor before it can reach offer admission;
every other mismatch returns a binding conflict.

## State machine

| Durable state | Allowed next action | Failure behavior |
| --- | --- | --- |
| Value-free offer published | Runner validates and records the exact offer. | Unknown fields, unsupported protocol, invalid `JobIR`, or command conflict reject the offer. |
| Offer accepted locally | Runner replays the deterministic accepted response until the server acknowledges it. | Restart reuses the same operation ID and canonical bytes. |
| Acceptance acknowledged | Runner sends `RuntimeAuthorityRequest` with the exact binding. | Cancellation stops delivery. A stale session, fence, offer, or digest fails closed. |
| Grant returned ephemerally | Runner validates binding, authorities, lease, canonical encoding, and bundle digest. | A malformed, over-broad, mismatched, expired, or differently encoded grant is discarded. |
| Protected bundle journaled | Runner sends `RuntimeAuthorityAck` with the same binding and bundle digest. | Restart skips minting and replays only the stable acknowledgement. |
| Server custody committed | Runner marks the delivery acknowledged in its journal. | A premature, different-operation, or different-digest acknowledgement conflicts. |
| Delivery acknowledged | Runner loads and decodes the protected bundle, applies authority aliases and secret masking, then admits execution. | Missing content, digest drift, decode failure, expiry, or credential-free contamination terminalizes or fails the attempt before user code. |

The request and acknowledgement operation IDs are deterministic functions of
the accepted offer, attempt, lease guard, `JobIR` digest, and generation. A
process crash at any boundary therefore resumes the same operation instead of
minting a second unrelated credential.

## What may be persisted

The control-plane migration
`0037_runtime_authority_deliveries.sql` adds metadata-only custody rows. A row
contains:

- attempt, runner, session, epoch, runner generation, slot, and lease fence;
- protocol and delivery generation;
- offer operation and command sequence;
- the immutable `JobIR` job/run IDs, schema, encoded size, digest, and object key;
- request and canonical bundle digests;
- stable request and acknowledgement operation IDs; and
- database-authoritative commit and acknowledgement times.

A single composite foreign key binds the delivery's attempt, lease/fence,
runner session, protocol, slot, offer command sequence, and complete immutable
`JobIR` descriptor to one exact lease-offer publication. A second composite key
binds the offer operation ID and that same session/sequence to one command
outbox record. The shared session/sequence proves both keys describe the same
published command. The table does not use independent existence-only foreign
keys that could assemble a delivery from unrelated publications. Check
constraints require protocol 2, generation 1, positive fences and sequences,
32-byte digests, and an all-null or all-complete acknowledgement tuple.

The following data is forbidden from the table, command outbox, operation
response receipts, audit records, metrics, and debug output:

- repository or OIDC bearer values;
- the canonical encoded authority bundle;
- a serialized `RuntimeAuthorityGrant`;
- provider secret handles that can resolve a value; and
- aliases expanded to credential values.

The runner spool is the one durable value-bearing location. It uses the runner
spool protector, a typed `RuntimeAuthority` content kind, a digest-addressed
content reference, bounded bytes, and normal retained-content reconciliation.
The journal contains only the protected content reference and delivery
metadata. Debug implementations redact authority credentials and value-bearing
payloads.

## Issuance and least authority

The control handler performs authorization in this order:

1. Authenticate and validate the runner session and protocol.
2. Canonicalize the value-free request and bind its operation digest.
3. Load the exact published offer and verify durable acceptance.
4. Compare every delivery coordinate with the offer and `JobIR` metadata.
5. Reload and validate the immutable `JobIR` bytes.
6. Revalidate the lease, fence, session, trust snapshot, and permission request.
7. Invoke the configured issuer only when the job requests repository
   authority.
8. Canonically encode the returned authorities and commit only their digest.
9. Return the value-bearing grant without persisting the response.

Explicit `none` permissions, an empty explicit map, and `id-token: write`
without repository permissions produce no GitHub repository token. They do not
fall back to provider defaults. `CredentialFree` jobs must have an empty
authority bundle and cannot receive secret environment values. Provider-default
or broad read/write requests still require an exact resolver result and fail
closed when the service authority is unavailable.

Fork and Dependabot authority reductions happen when the immutable trust policy
and `JobIR` permission request are built, before this delivery path. Delivery
cannot widen that reduced request. A rerun uses the original sealed actor and
event authority rather than the person who clicked rerun.

## Cancellation, revocation, and ambiguous issuance

A `CancelJob` command remains authoritative while the runner waits for either a
grant or the custody acknowledgement response. The runner commits and
acknowledges the cancellation command, stops the authority loop, records a
secretless cancelled result, and does not call the executor. If a protected
bundle was already written, it stays unacknowledged and is reclaimed with the
terminal slot.

The server revalidates cancellation, lease, session, and fence state before
authorization and before committing delivery metadata. Once cancellation or
revocation wins, a later request cannot create a new delivery row. A previously
committed exact request may replay only its digest-bound result; it cannot be
reinterpreted for another offer or generation.

Credential-provider operations can be indeterminate: a provider may have minted
a credential before a timeout made its result unknowable. The issuer lifecycle
owns cleanup or revocation of that provider operation. The delivery layer does
not guess that an uncommitted token is safe, persist it in a receipt, or mint a
replacement under a different identity. Operators should treat an
indeterminate provider outcome as a revocation/cleanup condition, not as a
retry with changed coordinates.

## Restart and replay behavior

| Crash boundary | Recovery action |
| --- | --- |
| Before durable acceptance | Replay or reject the value-free lease response; no issuer call is allowed. |
| After acceptance, before a committed delivery | Replay the same stable request. The server either authorizes once or returns the exact committed digest outcome. |
| After provider mint, before a trustworthy commit | Preserve the issuer's indeterminate state and fail closed; do not mint under a new operation. |
| After control metadata commit, before the grant arrives | Replay the exact request. A different bundle digest conflicts. |
| After runner protection, before ACK | Reload the protected content and send only the same stable ACK. Do not request or mint again. |
| After server ACK, before local ACK commit | Replay the same ACK, then mark the exact digest acknowledged. |
| After local ACK commit | Decode the protected bundle and recover execution subject to lease, authority expiry, and supported lifecycle rules. |

The runner journal schema is version 2. Old journal generations that cannot
represent protected delivery custody fail closed instead of treating a legacy
lease-offer bearer field as authority.

## Verification

Maintainers can run the component boundaries without external services:

```console
cargo test -p automata-ci-protocol --tests
cargo test -p automata-ci-protocol-protobuf --tests
cargo test -p automata-ci-control --tests
cargo test -p automata-ci-runner-journal --tests
cargo test -p automata-ci-runner-runtime --tests
cargo test -p automata-ci --lib github_job_runtime_authority -j 1
```

The ignored PostgreSQL contract test
`runtime_authority_delivery_is_post_accept_value_free_exact_and_replayable`
requires the repository's PostgreSQL integration-test environment. It verifies
pre-accept rejection, direct-SQL rejection of mixed publication evidence, exact
commit and acknowledgement replay, conflicting ACK rejection, cancellation,
persisted custody coordinates, and the absence of value-bearing schema columns.

Reviewers should also inspect serialized `LeaseOffer` and operation receipts.
Their key sets are intentionally closed; adding an authority value, credential,
token, or generic response-payload field is a protocol and security change, not
a backward-compatible extension.

## Limits

- Delivery generation 1 is initial-only. Refresh and rotation require a new
  reviewed generation contract.
- The direct mTLS runner listener is the supported transport. A generic
  TLS-terminating proxy cannot forward this authority safely.
- Runtime delivery does not make transformed or split secrets redactable.
  Workflow authors must still avoid printing externally sourced secrets.
- External and dynamically leased secret providers remain unsupported where
  [authentication](authentication.md) says so.
- Full release availability still requires the integration lineage, deployed
  migration, and end-to-end release gates in the
  [implementation plan](implementation-plan.md).
