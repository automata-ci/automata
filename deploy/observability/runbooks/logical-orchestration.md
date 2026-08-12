# logical workflow logical orchestration

Check the durable-state sampler first. It refreshes every 15 seconds and retains
the last good snapshot after an error, cancellation, timeout, or capacity-bound
failure. Confirm `automata_ci_control_plane_state_sampler_healthy` is 1 and the
last-success timestamp is advancing before interpreting logical state.

Use `cluster_state:automata_ci_control_plane_logical_workflow_runs:max` for the
current run markers and `cluster_state:automata_ci_control_plane_logical_jobs:max`
for logical jobs. Run marker states are `pending`, `active`, `completed`,
`cancelled`, and `failed`; logical-job states are `pending`, `activating`,
`activated`, `completed`, `skipped`, `cancelled`, and `failed`. Replicas expose
the same durable snapshot, so use `max without(instance)`, never `sum`.

Activation observations deliberately answer a narrower progress question:

- `pending` counts logical jobs awaiting an activation claim; its age starts at
  the oldest logical-job creation time.
- `activating` counts active claims; its age starts at the oldest claim time.
- `expired` counts the subset of activating claims whose durable expiry is at
  or before the trusted snapshot time; its age starts at the oldest expiry.

`cluster_state:automata_ci_control_plane_logical_activation_age_seconds:max` is
absent when the matching count is zero or its timestamp is zero. Do not convert
zero into an epoch-sized age. The activation-publication and
materialized-instance gauges are cumulative current durable row counts, useful
as corroborating progress evidence rather than rates.

Alert thresholds are:

- `AutomataLogicalActivationBacklogStale`: pending age above five minutes with
  positive pending demand for five minutes (warning).
- `AutomataLogicalActivationBacklogCritical`: pending age above 15 minutes with
  positive pending demand for five minutes (page).
- `AutomataLogicalActivationClaimExpired`: any expired claim for two minutes
  (warning).
- `AutomataLogicalActivationClaimStuck`: expired age above five minutes with a
  positive expired count for five minutes (page).

For pending backlog, confirm a current run marker is progressing from pending
to active and that activation publications and materialized instances advance.
Check the logical activation worker, PostgreSQL dependency health, transaction
timeouts, and bounded error outcomes around the alert window. A stable pending
count with no publication or instance growth points to claim/publication
progress rather than runner capacity.

For expired claims, verify worker process health, clock synchronization, claim
renewal, and fenced recovery. Compare activating and expired counts: expired is
an overlapping overdue subset, not an additional logical-job state. Use
structured logs and traces scoped by the alert time window to locate individual
runs; metrics intentionally expose no tenant, repository, run, invocation,
logical-job, claim, key, or digest labels.

After remediation, require the expired count to return to zero or pending work
to drain, then confirm publication and instance counts resume and terminal
logical states advance. Do not delete marker rows, clear claims manually, or
bypass activation fencing to silence the alert.
