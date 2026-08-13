# Queue latency and capacity

Start with `automata_ci_control_plane_state_sampler_healthy` and the age of
`automata_ci_control_plane_state_sampler_last_success_timestamp_seconds`. A
failed refresh retains the previous snapshot. Do not treat non-zero cached
gauges as current while the sampler is unhealthy or stale.

Use the replicated recording rules, which apply `max without(instance)`:

- `cluster_state:automata_ci_control_plane_queue_jobs:max{state="queued"}` is
  every durably queued attempt.
- `cluster_state:automata_ci_control_plane_queue_jobs:max{state="eligible"}` is
  the exact currently runnable subset.
- `cluster_state:automata_ci_control_plane_queue_age_seconds:max` is emitted
  only when both the matching depth and oldest timestamp are positive.
- `cluster_reason:automata_ci_control_plane_eligible_queue_blocked_jobs:max`
  and `...blocked_age_seconds:max` split eligible candidates with no available
  compatible slot by a closed reason.

An eligible attempt is due, belongs to a queued or in-progress run, uses the
current admission epoch and JobIR, has no cancellation intent, owns its run's
concurrency group when applicable, and has a newest successful attempt for
every current prerequisite. A large difference between total queued and
eligible depth can therefore be expected dependency, concurrency,
cancellation, future-schedule, or obsolete-schema state; it is not evidence of
runner shortage by itself.

For `no_compatible_runner`, verify that a same-tenant runner is online,
desired-active, has a current live session and JobIR, is authorized for the
required group and labels, and advertises every required platform,
architecture, and resource capability in both registered and observed state.
The sampler uses their least-authority intersection. Restore or provision the
correct runner shape; a fleet-wide idle-slot total is not relevant.

For `compatible_runners_busy`, compatible runners exist but every authorized
slot is occupied. Confirm current runner slot conservation, lease expiry,
session health, and runner control progress. Restore healthy compatible capacity
first. Planned expansion requires a reviewed deployment change and a fresh
one-use enrollment token rather than an incident-time mutation of an existing
runner identity. A candidate with any available compatible slot is omitted from both
blocked reasons, so compare blocked depth with eligible depth rather than
assuming they are equal.

`AutomataEligibleQueueCompatibleCapacityExhausted` pages only when exact
eligible demand and blocked demand are both positive and blocked age exceeds
60 seconds for five minutes. Zero or absent timestamps, zero demand, and
available compatible capacity do not manufacture an age or page. Capacity
evidence is an exact per-candidate snapshot, not a batch assignment of all free
slots.

The compatibility snapshot is bounded to 1,000 exact eligible candidates, 64
effective runners, and 256 registered slots per runner. Exceeding a bound or a
two-second statement timeout fails the refresh and retains the last good
snapshot instead of publishing a partial answer. Treat the sampler health or
staleness alert as the primary signal in that case.

The queue-to-claim histogram observes work that was actually claimed.
`AutomataQueueClaimObjectiveMiss` requires fleet p99 above 60 seconds for ten
minutes and a five-minute claim rate above 0.01 observations per second. The
rate handles counter resets; the volume guard deliberately suppresses sparse
samples. Use the eligible-capacity page for work that never reaches a claim.

Finally, check lease-poll outcomes, candidates scanned, scheduler rejection
reasons, offer publication, runner session loss, control retries, lease expiry,
clock skew, and command-outbox staleness. Restore compatible capacity before
tuning polling. Do not weaken fencing, replay, or durable-claim guarantees to
reduce latency.
