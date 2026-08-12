# Failure and security model

## Availability goals

- A Cloud or Stripe outage must not terminate running jobs.
- A browser or live-log connection failure must not affect execution or log
  durability.
- A single Core replica failure must be hidden by load balancing and resumable
  protocols.
- Failure must never broaden tenant access, resource profiles, or spending
  authority.
- Ambiguous cross-system outcomes are reconciled from durable state rather than
  repaired through direct database edits.

## Failure behavior

| Failure | Existing jobs | New jobs and mutations | Recovery behavior |
| --- | --- | --- | --- |
| Cloud web/API unavailable | Continue in Core | SaaS browser control operations unavailable | Restore Cloud; no Core rollback is required |
| Cloud database unavailable | Continue | Cloud account/routing/billing workflows fail closed | Workers retry durable work after database recovery |
| One Core replica unavailable | Continue unless that connection must reconnect | Load balancer selects another replica | Reads retry; streams resume by cursor; mutations reconcile by idempotency key |
| Shared Core shard/database unavailable | Runners continue or spool within bounded durability limits | Admission and Core mutations fail closed | Recover shard state; runners replay durable results/logs |
| Live-log endpoint unavailable | Execution continues and logs remain durable | New stream connections fail temporarily | Browser reconnects with last cursor; finalized log remains the fallback |
| Object storage unavailable | Execution continues while bounded local spooling is available | Finalization, artifact/cache operations may be delayed or rejected | Retry immutable writes; do not declare an object finalized early |
| Stripe API unavailable | Existing local entitlements continue | New card collection or commercial mutations may be unavailable | Durable retries and reconciliation; scheduler never calls Stripe |
| Stripe webhook delayed/duplicated/out of order | Continue under current bounded entitlement | Commercial projection may lag | Durable inbox deduplicates and periodic reconciliation repairs order/gaps |
| GitHub unavailable | Existing admitted jobs follow credential/runtime policy | Login, installation, sync, and new GitHub-dependent admission degrade | Retry idempotent reconciliation; expose provider status |
| Cloud-to-Core event delivery delayed | Continue under last valid local policy | Stale entitlement expiry may conservatively block new managed work | Retry outbox/inbox and alert on age |

Every bounded spool or stale-policy allowance needs an explicit maximum. “Keep
running” cannot mean accepting unbounded disk use, cost, or credential lifetime.

## Trial and payment failure behavior

- Core enforces a local generic allowance and expiry projection; it does not
  ask Stripe during admission.
- Trial concurrency and maximum runtime bound the possible overrun of an
  already-running job after the 6,000-second allowance is crossed.
- Exhaustion blocks new managed allocations. It does not silently convert the
  account or create an early usage charge.
- At the scheduled trial end, a verified Cloud subscription projection enables
  paid entitlements. Payment failure enters an explicit grace/recovery state;
  it is not inferred from a missing webhook.
- A stale entitlement snapshot has a defined expiry. Core may let existing jobs
  finish but fails closed for new managed allocations after the safe window.
- Administrative suspension is separately represented and may require
  immediate job cancellation for abuse or security reasons.

## Security boundaries

### Tenant isolation

- A trusted request context supplies the workspace ID; untrusted request
  bodies, form fields, object keys, and URLs do not grant tenant authority.
- Core reauthorizes every Core resource access even when Cloud authenticated
  the human.
- Tenant IDs participate in database keys, queries, uniqueness constraints,
  object metadata, cache namespaces, metrics dimensions, and audit events.
- Automated tests attempt cross-tenant reads and mutations for every repository
  adapter and public endpoint.
- Support/admin access is tenant-scoped, time-bounded where practical, and
  audited. Routine operations do not rely on production database consoles.

### Cloud-to-Core trust

- Private APIs require workload/service identity in addition to network
  reachability.
- Delegated actor assertions are short-lived, audience-bound, key-rotatable,
  and contain no authoritative Core roles.
- Protocol parsers reject unknown versions, unexpected fields, oversized
  inputs, noncanonical identifiers, expired authority, and workspace/resource
  mismatches.
- Mutation idempotency records are tenant-bound so one tenant cannot probe or
  collide with another tenant's operation IDs.

### Browser and live-log access

- Cloud sessions use secure, HTTP-only cookies, session rotation, CSRF
  protection for state changes, and a restrictive content-security policy.
- The public Rust data-plane origin has an explicit CORS allowlist and never
  treats `Origin` as authorization.
- Live-log capabilities authorize only one stream and operation for a short
  period. They are not accepted by control-plane endpoints.
- Capability values and signed object URLs are redacted from request logs,
  traces, error reports, analytics, and referrers.
- Stream authorization observes immutable output-visibility snapshots and
  current tenant access according to the Core security contract.
- Per-account, workspace, IP, and stream limits protect the service from
  connection and output amplification.

### Execution isolation

- Firecracker is the managed Linux job boundary; rootless containers are not
  the hostile multi-tenant boundary.
- Guests cannot reach host metadata, control-plane networks, other tenants, or
  infrastructure credentials.
- CPU, memory, disk, process, time, and network limits are enforced outside the
  guest where possible.
- Runner credentials are lease-bound, short-lived, scoped, and unusable after
  completion or revocation.
- Secrets are delivered only to the authorized execution boundary and are
  redacted from logs where the protocol can identify them; Cloud never receives
  plaintext repository secrets.
- Teardown, orphan detection, host replacement, image provenance, and patching
  are required parts of the isolation design.

### Billing and payment

- Stripe-hosted components collect card data. Automata stores only the Stripe
  customer/payment/subscription identifiers and safe display fields required by
  the product.
- Stripe webhook bodies are bounded, signatures are verified against the raw
  request bytes, and secrets rotate without downtime.
- Webhook receipt, processing, and projection are separate durable steps.
- Usage ledger entries are append-only, traceable to raw allocation facts, and
  priced with immutable policy versions.
- Refunds, credits, corrections, and platform-failure exclusions create
  explicit ledger entries rather than mutating history.
- Reconciliation compares Core allocation facts, the Cloud ledger, delivered
  Stripe meter events, invoices, and infrastructure occupancy.

## Abuse and cost containment

Card collection reduces low-effort abuse but is not an isolation or fraud
control. Before a public managed trial, Automata needs:

- conservative new-workspace concurrency, profile, runtime, and output limits;
- rate limits for signup, OAuth, GitHub installation, dispatch, logs, artifacts,
  caches, and mutation endpoints;
- payment and account-creation risk signals with a manual review/suspension
  path;
- egress and destination policy, including metadata and private-network blocks;
- bounded trial cost independent of user-supplied workflow behavior;
- auditable cancellation of queued/running work; and
- alerts on unusual resource occupancy, log volume, artifact volume, network
  use, and repeated account creation.

## Required verification before charging

- Cross-tenant authorization tests cover Cloud, Core, live logs, and object
  access.
- Shadow-meter totals reconcile with host allocation/occupancy measurements.
- Duplicate and reordered usage/Stripe events are exercised in tests.
- Key and webhook-secret rotation is rehearsed.
- Core replica termination during a log stream proves cursor-based recovery.
- Cloud, Stripe, and object-store fault tests prove that running work is not
  incorrectly terminated or double billed.
- Trial exhaustion and expiry cannot admit unbounded managed work.
- Restore tests demonstrate that Cloud and Core backups recover to compatible
  event cursors without granting stale authority.

## Incident principles

- Prefer denying new privileged or billable work over guessing during an
  authorization or entitlement outage.
- Preserve running customer work when doing so does not violate an explicit
  abuse/security suspension.
- Keep durable evidence sufficient to explain admission, execution, usage, and
  invoice decisions.
- Revoke and rotate narrow credentials rather than relying only on network
  isolation.
- Every manual override has an owner, reason, expiry, and audit event.
