# Cloud-to-core protocols

## Boundary

Automata Cloud is the normal browser-facing control plane. It owns the browser
session, SaaS pages, workspace routing, and commercial workflows. Core owns
execution data and tenant authorization.

This is not an absolute browser proxy rule. Latency-sensitive or large data
plane operations may bypass Node after Cloud and Core authorize a narrow
capability. The first required exception is live job-log streaming. Finalized
logs and artifacts may later use short-lived object-store download URLs for the
same reason.

```text
Control plane
Browser ──session──> Cloud web/API ──service + actor identity──> Core internal LB

Live-log data plane
Browser ──session──> Cloud ──actor identity──> Core authorization
Browser <──────── short-lived stream capability and public endpoint
Browser ──stream capability──> Core public data-plane LB ──> live log

Runner data plane
Runner ──runner protocol──> Core runner gateway pool
```

The endpoint in each flow denotes a load-balanced service, not a tenant's Rust
process.

## Protocol families

The first integration should define five independently versioned contracts:

1. **Service and delegated actor identity** for synchronous Cloud-to-Core
   requests.
2. **Core page models and mutations** used by the Cloud SSR host.
3. **Capability-scoped data-plane access**, beginning with live logs.
4. **Core events to Cloud**, beginning with allocation/usage facts.
5. **Cloud entitlement snapshots to Core** for local admission.

Each contract declares a version, bounded payloads, stable identifiers, error
envelopes, idempotency behavior, and compatibility policy. A release exposes a
small capability/version document so Cloud can detect an incompatible shard
before sending customer traffic.

## Service and actor identity

Cloud-to-Core requests carry two distinct authorities:

- **Service identity:** proves that an approved Automata Cloud workload called
  the private Core API. Use workload identity or mTLS at the network boundary.
- **Delegated actor identity:** a short-lived signed assertion identifying the
  human on whose behalf Cloud is acting.

The delegated assertion should include at least issuer, audience/shard, stable
external subject, workspace ID, issued/expiry times, token ID, and session or
authentication context. It should not contain an authoritative role or
permission list. Core maps the external subject and applies its own current
membership and RBAC state.

Assertions are audience-bound, short-lived, key-rotatable, and rejected on
clock, issuer, audience, signature, or tenant mismatch. Cloud browser cookies
are never forwarded to or interpreted by Core.

Core should be understood as an OAuth/OIDC-style resource server in SaaS mode:
Cloud is a configured trusted issuer, and Core consumes its signed access
assertions. A full browser-facing OIDC flow between Cloud and Core is not
required merely to delegate one request.

This is an additional authentication adapter, not a replacement for the
open-source authentication system:

```text
self-hosted: browser -> Core GitHub OAuth -> Core session -> Core RBAC
SaaS:        browser -> Cloud GitHub OAuth -> signed actor assertion -> Core RBAC
```

The same Core principal mapping, membership, invitation, role, permission,
resource-policy, and audit machinery applies after either authentication path.
The built-in GitHub and session implementation remains supported and complete
for self-hosted installations.

## Page-model and mutation protocol

For a Core-owned page:

1. Cloud resolves the workspace to a shard.
2. Cloud calls the shard's internal load-balanced endpoint with service and
   delegated actor identity.
3. Core authenticates the actor, authorizes the request, and projects a bounded
   host-neutral page model.
4. Cloud validates the model and renders it with the public React UI package.
5. Cloud adds host-owned concerns such as CSP nonce, Cloud navigation, account
   controls, billing notices, and executable asset paths.

Core should return the page payload, allowed action capabilities, resource
revision, protocol version, and suitable cache policy—not a Node-specific view
or a database-shaped response. The current embedded `RenderRequest` remains the
self-hosted host contract; reusable page models should be extracted from it
rather than making Cloud impersonate the embedded host.

Browser mutations go to Cloud first. Cloud performs browser-session and CSRF
checks, then forwards a bounded mutation with delegated actor identity, the
Core-issued action capability or revision, and an idempotency key. Core
reauthorizes and returns a typed success, validation, conflict, or redirect
result. Cloud never treats a hidden field or route workspace ID as authority.

## Live-log protocol

### Why it is direct

An active job log is an ordered stream that has not yet become a finalized
object. Proxying it through the Node control plane adds another buffering and
failure hop and makes Cloud scale with every output byte. Object storage is
appropriate after finalization, not as the live tail transport.

[AWS S3 provides strong read-after-write and list consistency](https://aws.amazon.com/s3/consistency/)
for successful writes. Therefore the reason for the direct stream is not
eventual consistency of a completed S3 object; it is that the object is
incomplete or not yet published while the job is running, plus the latency and
connection behavior required for tailing. Other S3-compatible stores must
declare and test their own guarantees.

### Authorization flow

1. The browser asks Cloud for access to a specific job attempt's live log.
2. Cloud calls Core with the delegated actor identity.
3. Core checks the workspace, resource identity, current `ReadJobLog`
   permission, and output-visibility policy.
4. Core returns a very short-lived, audience-bound stream capability and the
   shard's public log origin.
5. The browser connects directly to the public Core data-plane load balancer.

The capability is restricted to one workspace, attempt/log stream, operation
(`read`), and expiry. It carries no general API authority. It must not be placed
in durable browser storage, analytics events, referrers, or ordinary access
logs. Prefer an authenticated streaming `fetch` so the token can be sent in an
authorization header rather than in the URL.

### Stream behavior

- Use a simple one-way, cursor-based stream; SSE framing over streaming `fetch`
  is a good initial fit unless testing finds a concrete blocker.
- Every frame or segment has a monotonic cursor already tied to the durable Core
  log identity.
- The browser reconnects with its last accepted cursor and safely receives
  duplicates rather than gaps.
- Heartbeats keep intermediaries from treating an idle job as a dead stream.
- The server enforces bounded frames, output limits, backpressure, connection
  limits, and slow-consumer behavior.
- A replica or connection failure does not fail the job. The browser reconnects
  through the load balancer and resumes from durable committed data.
- If live fan-out is initially owned in process, routing may consistently hash
  the attempt or stream ID. No URL exposes a pod address, and failover still
  resumes from the durable cursor.

When the terminal segment has been accepted and the final object is durable,
Core marks the log finalized. Subsequent page loads use the finalized log
metadata and can read through Core or a separately authorized short-lived
object URL. The database must never advertise finalization before the object is
known durable.

## Usage events

Core emits neutral allocation facts rather than Stripe concepts:

- stable event ID and schema version;
- workspace, run, job, and attempt IDs;
- resource profile and allocation identity;
- allocation and release timestamps;
- terminal disposition and platform-failure classification; and
- correction/supersession linkage when necessary.

Cloud receives these through a durable inbox, deduplicates them, applies an
immutable price/policy version, and writes the billable ledger. Acknowledgement
only means Cloud durably accepted the event. Core retains/retries its outbox
until that acknowledgement.

## Entitlement snapshots

Cloud sends generic, versioned entitlement snapshots such as:

- managed execution enabled;
- allowed resource profiles;
- concurrency and maximum-runtime limits;
- usage/spending allowance and validity window;
- trial or paid projection expiry; and
- administrative suspension.

Core stores the latest valid snapshot and uses it locally. Scheduling and job
continuation never synchronously call Cloud or Stripe. Updates are monotonic,
idempotent, signed or service-authenticated, and auditable.

The generic quota mechanism may count raw execution seconds locally so the
seven-day/6,000-second trial is enforceable without teaching Core about trials
or Stripe. Cloud remains authoritative for the commercial interpretation and
reconciles its ledger against Core usage.

## Idempotency and retries

- Every mutation and event has a stable operation or event ID.
- A client retry with the same ID and payload returns the original result.
- Reusing an ID with a different payload fails as a conflict.
- Read retries may go to any compatible replica.
- Mutation retries occur only when the method contract says they are safe.
- Timeouts are ambiguous outcomes and trigger lookup/reconciliation, not an
  assumed rollback.
- No protocol assumes exactly-once network delivery.

## Open implementation questions

- Whether the initial live fan-out uses database notification, a dedicated
  broker, or attempt-affine replicas backed by the durable segment store.
- Exact assertion format and key-distribution mechanism.
- Whether Core or a dedicated edge component signs finalized-object URLs.
- Exact page-model schema generation and compatibility-test tooling.
- Timeout, retry, frame-size, connection, and token-lifetime values.
