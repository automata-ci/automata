# Semantic invariants

JSON Schema covers structure, bounds, and closed discriminated shapes. Services
must enforce the following cross-field and durable-state invariants after
structural validation and before committing work.

## All operations

- Path, token, body, and durable resource workspace identities agree.
- Request and event IDs are tenant/shard-bound in storage.
- Reusing an idempotency or event ID with different canonical content is a
  conflict, not an update.
- An unsupported protocol/schema version is rejected before partial handling.
- Server time and token clocks stay inside configured skew and lifetime bounds.
- Error details never contain a token, secret, payment value, SQL diagnostic,
  raw upstream response, or cross-tenant resource existence signal.

## Tenant provisioning

- Path `workspace_id`, body `workspace_id`, and created Core `tenant_id` are the
  same stable UUID.
- `(initial_owner.issuer, initial_owner.subject)` maps to the principal granted
  initial ownership.
- Exact replay returns the existing result. A different display name or owner
  under the same operation/workspace conflicts and creates nothing.
- Tenant, principal mapping, initial membership/role binding, authorization
  revision, audit event, and Core outbox state commit atomically.

## Delegated actor requests

- Token verification follows `token-profile.md` before identity mapping.
- Cloud proves identity only. Core resolves current membership, role bindings,
  resource scope, publication policy, and output-safety state.
- The resource belongs to the path/token workspace.
- Authorization is repeated in the mutation transaction; a prior page render or
  token mint is not lasting permission.

## Live logs

- Authorization path workspace/attempt match the actor token and the Core log
  stream metadata.
- Capability workspace, attempt, stream, principal, audience, and requested
  path all agree.
- `after_sequence` denotes the last frame the client accepted. The server emits
  only later frames, in increasing contiguous order; replay may duplicate a
  previously observed frame but must not create a gap.
- Each SSE `id` equals the decimal `sequence` in its `log` data.
- A terminal frame's `through_sequence` equals the last durable log sequence
  when one exists.
- `finalized_object_ready` becomes true only after immutable object publication
  is durable and its Core metadata transaction is visible.
- Token/connection loss affects viewing only, never job execution or durable
  log delivery.

## Usage events

- `occurred_at_ms >= allocated_at_ms` for a started event.
- A closed event has `released_at_ms >= allocated_at_ms` and
  `occurred_at_ms >= released_at_ms`.
- All events for an allocation agree on workspace, attempt, environment profile,
  resource allocation, and allocation timestamp.
- Start and close may arrive out of order. Cloud stores both idempotently and
  prices only a coherent closed interval.
- `accepted_count + duplicate_count == events.length` for an accepted batch.
- Acknowledgement means durable inbox acceptance, not pricing, billing, Stripe
  delivery, or settlement.
- Pricing and trial interpretation use an immutable Cloud policy version. Core
  emits no money, Stripe, plan, credit, or invoice field.

## Entitlement snapshots

- Path and body workspace IDs agree.
- Revisions are monotonic. Exact replay of the current revision is accepted;
  lower or content-divergent revisions conflict.
- `issued_at_ms <= effective_at_ms < expires_at_ms`.
- For an allowance,
  `effective_at_ms <= starts_at_ms < ends_at_ms <= expires_at_ms`.
- Absence of `compute_allowance` means the snapshot imposes no compute-seconds
  allowance; it does not disable metering.
- Core keys local allowance consumption by `allowance_id` and shares that state
  across replicas through durable shard storage.
- Environment profile ID and manifest digest must match an installed,
  content-attested Core profile.
- Expired/stale snapshots block new managed allocations according to policy but
  do not synchronously consult Cloud or Stripe and do not ordinarily kill work
  already running.

## Database transaction boundaries

- Inbox insert/deduplication and its acknowledgement state commit together.
- Domain mutation, authorization revision, audit record, and outbox event commit
  together where they describe one accepted change.
- Workers claim durable rows with bounded leases/locks and safe retry; an
  in-memory queue is never the only record of pending work.
- No transaction spans the Cloud and Core databases or includes a Stripe/network
  request.
