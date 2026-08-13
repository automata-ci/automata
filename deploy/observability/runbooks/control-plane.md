# Control-plane health

1. Check `up`, `automata_ci_control_plane_ready`, and each
   `automata_ci_control_plane_dependency_ready` separately.
2. Use dependency probe outcomes and latency to distinguish PostgreSQL,
   object-store, timeout, and process-local problems.
3. Check HTTP request rate, status class, and p95/p99 by matched route. Exclude
   expected client errors from platform availability calculations.
4. Confirm the durable-state sampler and maintenance last-success timestamps
   advance. A stale sampler retains its last good values; do not interpret them
   as current merely because the gauges are non-zero.
5. Inspect PostgreSQL pool saturation and bounded storage operation outcomes.
6. Compare `automata_ci_control_plane_commands_pending` and
   `automata_ci_control_plane_cancellation_intents_pending` with their guarded
   oldest-age recording rules. A zero oldest timestamp means the corresponding
   set is empty and must not be converted into an epoch-sized age.
7. Compare total and eligible queue depth, then use the bounded blocked-capacity
   reasons rather than fleet-wide idle slots. See the queue runbook for the
   exact runnable predicate and sampler limits.
8. Check logical workflow marker, logical-job, activation, publication, and
   materialized-instance gauges. Pending backlog and expired claims have a
   dedicated logical-orchestration runbook.
9. Correlate with tracing and structured logs using time and stable operation
   categories. Metrics intentionally contain no tenant, run, job, SQL, or error
   text.

If every replica exports the same durable snapshot, use `max` aggregations.
Summing it creates false fleet totals.
