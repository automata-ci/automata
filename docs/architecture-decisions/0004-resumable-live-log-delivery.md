# ADR 0004: Deliver live logs through a resumable transport-neutral tail

- Status: Accepted
- Date: 2026-08-15

## Context

Runners already publish bounded, immutable, sequence-ranged log segments to
Core. PostgreSQL owns the ordered segment metadata and object storage owns the
verified compressed payloads. The browser currently revalidates a bounded JSON
snapshot while a job is active. That is a safe fallback, but repeatedly
rebuilding page snapshots adds avoidable latency and work and cannot provide the
intended live-log experience at scale.

Automata Cloud must not proxy log bytes through its private API. A browser may
connect to any healthy Core replica in the workspace's shard, and no workspace
or runner connection is permanently assigned to one HTTP replica. A live
connection can nevertheless terminate on one replica for its lifetime, so
replica loss, deployment draining, network changes, and suspended browser tabs
must not lose output or require sticky workspace routing.

WebTransport is available in current major browsers and offers reliable
multiplexed streams, stream backpressure, and QUIC connection migration. It
still depends on an HTTP/3 and QUIC-capable edge, may be blocked by enterprise
networks, and has a less mature Rust server ecosystem than ordinary HTTP.
Self-hosted installations may also run behind proxies without WebTransport
support. Server-Sent Events are widely deployable but do not provide the same
multiplexed binary session.

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

One reliable ordered WebTransport stream carries log records. Log bytes do not
use datagrams. Separate reliable streams may later carry independent jobs or
run-status events so loss on one stream does not block another. The initial SSE
adapter carries the same logical records as UTF-8 JSON event data. The browser
tries WebTransport first with a short establishment deadline, falls back to
streaming `fetch` over SSE, and finally uses bounded snapshot polling. A
transport failure never changes the checkpoint.

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

WebTransport does not carry browser cookies or ordinary HTTP authentication.
The browser therefore sends the one-time log ticket on a bounded initial
control stream after session establishment. Tickets are not placed in URLs.
Pre-authentication sessions have strict byte, stream-count, and time limits,
and Core validates the exact browser origin. The SSE adapter uses streaming
`fetch` so it can carry the same ticket in an authorization header.

When a page becomes hidden or frozen, the UI persists only its non-secret
checkpoint and may close the live connection after a short grace period. On
visibility restoration, page restoration, or reload, it obtains a fresh ticket
and resumes. QUIC connection migration improves continuity across network
changes but is not treated as protection against browser suspension or page
discard.

Core advertises transports as capabilities. WebTransport is enabled only when
the configured listener, TLS identity, load balancer, and server implementation
have passed conformance checks. SSE remains a supported fallback rather than a
temporary migration mechanism.

## Consequences

- Core replicas remain interchangeable across reconnects; a live connection
  does not create workspace affinity.
- Ordering, replay, completion, authorization, and limits can be tested once
  below both streaming transports.
- PostgreSQL and object storage remain the recovery source of truth while the
  notification path can be replaced without changing browser semantics.
- The shared public UI can use the same transport controller in the embedded
  self-hosted build and the Cloud SSR build. Cloud supplies ticket acquisition
  and routing rather than a separate log implementation.
- Production WebTransport requires an end-to-end QUIC listener, TLS termination
  at Core or a reviewed WebTransport edge, connection-ID-aware load balancing,
  origin enforcement, draining, and browser interoperability tests.
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
4. Implement a WebTransport adapter behind the same tail interface and validate
   Chrome, Firefox, and Safari behavior against the selected Rust library.
5. Validate QUIC routing, pod draining, UDP-blocked fallback, network migration,
   slow consumers, browser suspension, authorization expiry, and replica loss
   before preferring WebTransport in Cloud.

## Alternatives considered

WebTransport without a fallback was rejected because browser API availability
does not guarantee that UDP, HTTP/3, the deployment proxy, or the Rust server
path is usable. SSE alone remains a sound simpler implementation, but it gives
up connection migration and an efficient multiplexed foundation for future
live run data. WebSockets were not selected for this boundary. Routing a
browser to the replica that owns a runner connection was rejected because it
would introduce replica affinity and make recovery depend on process-local
state. A dedicated live-log broker remains an option if durable segment
notification and replay cannot meet measured latency or scale requirements; it
is not required by the initial design.
