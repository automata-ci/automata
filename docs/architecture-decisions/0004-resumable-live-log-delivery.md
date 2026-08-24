# ADR 0004: Deliver live logs through a resumable transport-neutral tail

- Status: Superseded by [ADR 0005](0005-structured-execution-log-groups.md)
- Date: 2026-08-15

This ADR records the transport design that introduced resumable delivery.
ADR 0005 replaced its snapshot fallback and flat-record assumptions with one
schema-2 structured replay-and-tail protocol.

## Context

Runners already publish bounded, immutable, sequence-ranged log segments to
Core. PostgreSQL owns the ordered segment metadata and object storage owns the
verified compressed payloads. The browser currently revalidates a bounded JSON
snapshot while a job is active. That is a safe fallback, but repeatedly
rebuilding page snapshots adds avoidable latency and work and cannot provide the
intended live-log experience at scale.

Automata Cloud must not proxy log bytes through its private API. A browser may
connect to any healthy Core replica in the tenant's shard, and no tenant
or runner connection is permanently assigned to one HTTP replica. A live
connection can nevertheless terminate on one replica for its lifetime, so
replica loss, deployment draining, network changes, and suspended browser tabs
must not lose output or require sticky tenant routing.

WebTransport is newly available across current major browsers and offers
reliable multiplexed streams, stream backpressure, and QUIC connection
migration. Its installed base will lag browser support, it depends on an HTTP/3
and QUIC-capable edge, and enterprise networks may block or degrade UDP.
Self-hosted installations may also run behind proxies without WebTransport
support. Server-Sent Events are widely deployable over ordinary HTTP and fit
the initial ordered, unidirectional text workload directly.

## Decision

Core owns one transport-neutral live-log tail with explicit checkpoint and
replay semantics. SSE and WebTransport are adapters over that tail; they do not
define independent cursor, authorization, ordering, or completion behavior.
The bounded JSON snapshot remains a final fallback and history-navigation API.

Every delivered log record retains its durable stream and sequence identity.
Core returns an opaque checkpoint bound to the exact tenant, repository, run,
job, attempt log stream, and protocol version. A checkpoint identifies the last
fully delivered record, not a particular Core replica or network connection.
On reconnect, the client presents its last fully applied checkpoint. Core may
replay the checkpoint record, and clients must deduplicate by durable identity.
The client advances its checkpoint only after it has decoded and accepted a
complete record.

Streaming `fetch` over SSE is the primary live transport and carries logical
records as UTF-8 JSON event data. It is expected to run over HTTP/2 in managed
production deployments so HTTP/1.1's low per-origin connection limit does not
constrain parallel jobs. The browser falls back to bounded snapshot polling.
A transport failure never changes the checkpoint.

WebTransport remains an optional future adapter rather than part of the
initial delivery. It will be added only if production measurements show that
multi-job multiplexing, connection limits, or transport latency justify a
second implementation and its infrastructure matrix. If added, one reliable
ordered stream carries records; log bytes do not use datagrams. Independent
streams may carry separate jobs or run-status events.

The shared UI package owns transport selection, strict decoding, durable
identity deduplication, checkpoint advancement, reconnects, and fallback. Its
ticket-provider boundary returns one normalized Core access capability, so the
embedded self-hosted UI can acquire a ticket with its Core session while the
Cloud SSR UI can acquire one through the private Cloud API. Neither adapter
handles log bytes. SSE JSON represents the durable `u64` sequence as canonical
decimal text so JavaScript clients do not lose identity precision.

The authoritative replay path reads committed segment metadata and verified
objects. A shard-wide notification is only a latency hint that new committed
data may be available. Notifications contain bounded identity and sequence
information, never log bytes. A missed or coalesced notification is harmless:
the serving replica reads forward from the durable checkpoint, and a bounded
periodic check prevents an indefinitely missed wake-up. Live bytes must not
exist solely in the memory of the replica that accepted the runner segment.

Cloud authenticates its user and asks the selected Core shard to authorize the
exact log resource. Core creates a short-lived, narrowly scoped log ticket and
returns the advertised transport endpoints. The browser then connects directly
to Core. Cloud does not mint Core authority independently and does not proxy log
payloads. Self-hosted installations use the same Core authorization and tail
with their configured human identity provider.

Tickets are never placed in URLs. The SSE adapter uses streaming `fetch` so it
can carry the one-time ticket in an authorization header. If WebTransport is
implemented, the browser sends the ticket on a bounded initial control stream
because WebTransport does not carry browser cookies or ordinary HTTP
authentication. Such pre-authentication sessions must have strict byte,
stream-count, and time limits. Core validates the exact browser origin for
every transport.

When a page becomes hidden or frozen, the UI persists only its non-secret
checkpoint and may close the live connection after a short grace period. On
visibility restoration, page restoration, or reload, it obtains a fresh ticket
and resumes. If WebTransport is later implemented, QUIC connection migration
may improve continuity across network changes but is not treated as protection
against browser suspension or page discard.

Core advertises transports as capabilities. SSE is the required baseline.
WebTransport may be advertised later only when the configured listener, TLS
identity, load balancer, and server implementation have passed conformance
checks and measured demand justifies enabling it.

## Consequences

- Core replicas remain interchangeable across reconnects; a live connection
  does not create tenant affinity.
- Ordering, replay, completion, authorization, and limits can be tested once
  below both streaming transports.
- PostgreSQL and object storage remain the recovery source of truth while the
  notification path can be replaced without changing browser semantics.
- The shared public UI can use the same transport controller in the embedded
  self-hosted build and the Cloud SSR build. Cloud supplies ticket acquisition
  and routing rather than a separate log implementation.
- A future production WebTransport adapter would require an end-to-end QUIC
  listener, TLS termination at Core or a reviewed WebTransport edge,
  connection-ID-aware load balancing, origin enforcement, draining, and
  browser interoperability tests.
- Slow clients require bounded per-session queues. Falling behind drops the
  connection and resumes from durable storage instead of accumulating
  unbounded process memory.

## Delivery sequence

1. Add an explicit forward checkpoint to the existing bounded log read and
   prove replay, duplicate, gap, and terminal behavior without a network
   transport.
2. Add one shard-wide committed-segment notification source with periodic
   durable-read fallback.
3. Implement streaming `fetch` SSE as the reference adapter and retain bounded
   snapshot polling as the final fallback.
4. Measure HTTP/2 connection use, multi-job viewing, latency, proxy failures,
   slow consumers, browser suspension, authorization expiry, and replica loss.
5. Only if measurements justify it, implement WebTransport behind the same tail
   interface and validate QUIC routing, draining, UDP-blocked fallback, network
   migration, and Chrome, Firefox, and Safari interoperability.

## Alternatives considered

WebTransport as the initial preferred transport was rejected because browser
API availability does not guarantee that the installed client, UDP, HTTP/3,
deployment proxy, or Rust server path is usable. Its advantages are not yet
material for one ordered server-to-browser text stream, while SSE must remain
production quality for fallback users regardless. WebSockets were not selected
for this unidirectional boundary. Routing a browser to the replica that owns a
runner connection was rejected because it would introduce replica affinity and
make recovery depend on process-local state. A dedicated live-log broker
remains an option if durable segment notification and replay cannot meet
measured latency or scale requirements; it is not required by the initial
design.
