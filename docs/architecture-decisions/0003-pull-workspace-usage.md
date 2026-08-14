# ADR 0003: Pull immutable workspace usage by cursor

- Status: Accepted
- Date: 2026-08-14

## Context

Core accounts actual execution locally so entitlement enforcement does not
depend on a synchronous SaaS request. An external control plane such as Automata
Cloud also needs those facts for trial state, customer usage views, spend
controls, and provider-specific billing. The public Core product must remain
fully functional with a self-hosted control plane and must not contain Cloud or
Stripe code.

Usage delivery crosses a failure-prone network. Either side may restart after
accepting a batch but before acknowledging it. The protocol therefore needs an
explicit replay and idempotency model rather than assuming exactly-once network
delivery.

## Decision

Core exposes a privileged, authority-scoped gRPC usage feed on the management
trust boundary. The external control plane pulls bounded pages after an opaque,
exclusive cursor. An empty cursor means the beginning of the retained feed.
The cursor is meaningful only for the exact authenticated authority and shard
that issued it.

Each immutable event has a globally stable event ID, workspace and attempt
identity, entitlement revision, positive accounting interval, and actual
consumed compute in milliseconds. Events are raw provider-neutral accounting
facts. They contain no plan, price, currency, invoice, Stripe identifier, or
decision that the usage is commercially billable.

Core returns events in stable append order and a cursor after the returned page.
The consumer deduplicates by event ID and advances its cursor in the same local
transaction that accepts the events. A response lost after delivery can
therefore be retried safely. Delivery is at least once; exactly-once effects are
created by the consumer transaction rather than promised by the network.

Core derives the authority from verified workload identity on every request.
The durable feed filters by that exact authority even if multiple authorities
can manage workspaces on one shard. Cursors and page sizes are bounded. A stale
or unknown cursor fails explicitly; a consumer must alert and reconcile rather
than skip silently.

The schema and transport-neutral domain are introduced before the endpoint is
composed. Core advertises the capability only after accounting writes the
durable feed transactionally, the gRPC adapter is registered, and end-to-end
replay tests pass.

## Consequences

- Core never needs Cloud network reachability, credentials, retry workers, or
  provider-specific billing dependencies.
- Cloud controls polling rate and backpressure and can ingest several shards
  with independent cursors.
- Cursor lag and oldest retained event age become required operational signals.
- Both Core's event feed and the consumer's deduplication/cursor state are
  durable data that need backup and recovery procedures.
- Schema evolution is additive under normal Protobuf compatibility rules;
  future execution dimensions can be added without redefining existing facts.

## Alternatives considered

Core pushing batches to Cloud can reduce idle polling, but it gives every Core
shard outbound Cloud credentials and couples the public binary to destination
configuration and retry behavior. It was rejected for the initial design.

Cloud querying mutable aggregate counters is simpler but cannot safely recover
which intervals were already billed or explain corrections. It was rejected in
favor of immutable facts.

A bidirectional streaming RPC could reduce steady-state latency but complicates
reconnect, flow control, and checkpoint semantics without improving the billing
correctness model. Bounded unary pages are sufficient for the initial scale.
