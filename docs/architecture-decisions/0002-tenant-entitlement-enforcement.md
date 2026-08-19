# ADR 0002: Enforce aggregate tenant entitlements with periodic accounting

- Status: Accepted
- Date: 2026-08-14

## Context

An externally managed Automata tenant can receive a finite compute allowance,
an uncapped metered policy, or a paused policy. A finite allowance must work
across concurrent jobs whose durations cannot be predicted. Core must continue
to operate when its external control plane is temporarily unavailable, and
self-hosted tenants must remain fully functional without a SaaS entitlement
provider.

Automata already assigns each attempt through a short-lived, fenced runner
lease. That lease proves execution ownership and bounds recovery after a runner
or control-plane failure. Reusing the word "lease" for short per-job budget
slices would combine unrelated liveness and commercial-policy concepts.

An exact aggregate cutoff across concurrent jobs would require rolling budget
reservations, renewal, unused-reservation reclamation, crash recovery, and
fairness decisions. The trial and future user-configured spend-limit products
can tolerate a small bounded enforcement overshoot.

## Decision

Core receives a complete, monotonically revisioned tenant entitlement from
an authorized external control plane. The public management contract is
provider-neutral and supports:

- capped aggregate compute, with an optional Core-anchored validity period;
- uncapped metered execution; and
- paused execution.

The capped policy is a tenant aggregate. It does not distribute time to jobs
in advance and does not introduce rolling per-job budget leases. Core accounts
actual execution periodically against the active entitlement revision. When a
compute allowance or validity period is exhausted, Core durably marks the
tenant exhausted, rejects new execution, and issues ordinary durable
cancellation commands for active attempts.

Jobs do not pause when an entitlement is exhausted. Runners follow the existing
cancellation and sandbox-cleanup path. Existing runner leases remain solely an
execution-ownership, liveness, and fencing mechanism.

Threshold observation and cancellation delivery are asynchronous, so aggregate
execution can exceed a configured allowance by a small bounded amount. That
tolerance does not increase the configured allowance. A SaaS implementation
must not retroactively bill trial overshoot; a future product marketed as a
hard monetary cap must either absorb the termination overshoot or clearly
define a different customer-visible guarantee.

Externally provisioned tenants carry an immutable durable binding to their
management authority. Only that authority can apply entitlement snapshots.
Managed tenants fail closed until they have a usable snapshot. Tenants
without an external-management binding are self-hosted and remain unrestricted
by this mechanism.

Core uses database time to anchor relative validity periods and returns the
stable applied and expiry timestamps. Exact operation retries return their
original response; stale revisions fail; gaps between increasing revisions are
allowed.

## Consequences

- Ordinary paid metering and finite trials share execution accounting without
  imposing reservation machinery on uncapped jobs.
- Concurrent control-plane replicas coordinate entitlement changes and
  exhaustion through PostgreSQL rather than process-local state.
- Enforcement latency, active concurrency, heartbeat cadence, and cancellation
  cleanup bound overshoot and must be observable.
- A later prepaid-credit product requiring an exact aggregate cutoff may add
  rolling reservations without changing existing runner-lease semantics.

## Alternatives considered

Rolling per-job budget slices provide a tighter aggregate limit but add
reservation and recovery complexity that the accepted tolerance does not
justify. Restricting trials to one concurrent job reduces overshoot but gives a
poor CI evaluation experience. Accounting only at job completion cannot stop a
runaway job and was rejected.
