# Runner journal and spool durability

Journal or spool poison means the runner cannot prove the outcome of a durable
mutation and must fail closed.

1. Automata v0.1 has no online drain or mutable desired-state operation. Do
   not assume a graceful drain. If the runner must be isolated, stop its
   service while preserving its state, then account for active leases and
   orphan recovery before restart.
2. Capture process logs, filesystem and mount health, free space/inodes, and the
   exact journal/spool metric snapshot. Keep encrypted state protected.
3. Determine whether the failure is capacity, authentication/integrity,
   uncertain rename/fsync, reconciliation, or an unsupported format.
   Use `automata_ci_runner_journal_mutations_total` to distinguish a known
   pre-rename `io_error` from `uncertain` or `poisoned` outcomes, and inspect
   `automata_ci_runner_journal_size_bytes` against
   `automata_ci_runner_journal_max_bytes` without reading the state file.
   Use `automata_ci_runner_spool_capacity_rejections_total`,
   `automata_ci_runner_spool_failures_total`,
   `automata_ci_runner_spool_poison_events_total`, and the typed operation
   counters. Compare both protected bytes/max bytes and objects/max objects;
   either independent limit can reject a write. Never infer the cause from an
   object key or error string.
4. Do not edit journal files, remove encrypted spool objects, rotate keys, or
   restart repeatedly until the recovery contract for that failure is known.
5. If the host filesystem is full, restore or expand its backing storage. That
   repairs free space only; it does not change the product's fixed journal or
   spool bounds. When a product bound is reached, restore delivery/control
   progress or make a separately reviewed product change instead of editing
   durable state.
6. Restore the runner service or an existing operator-controlled routing
   boundary only after reconciliation and orphan cleanup complete and the
   replacement process reports healthy readiness and durability gauges.

For `AutomataRunnerPendingDeliveryStale`, inspect
`automata_ci_runner_pending_deliveries` and
`automata_ci_runner_pending_delivery_oldest_timestamp_seconds` for the alert's
exact `kind`. Both count and enqueue timestamp are durable across restarts. A
positive count with a zero timestamp is not an old-age signal. For `log_stream`
it can legitimately mean an opened stream has not produced its first retained
segment; no enqueue age exists yet. If retained log frames exist, or a terminal
result or lease rejection remains pending without its timestamp, capture the
raw snapshot for contract diagnosis. Restore the blocked control session,
acknowledgement path, or log delivery without editing the journal. The guarded
recording rule removes empty and zero-timestamp states instead of manufacturing
an epoch-sized age.

`AutomataRunnerPendingDeliveryTimestampFuture` is separate from the age alert:
it requires positive backlog and a persisted oldest timestamp more than sixty
seconds ahead of Prometheus. Check runner, collector, and control-plane clocks
and preserve the journal evidence. Do not apply `abs()` to the age expression or
rewrite the durable timestamp; either would turn future-skewed evidence into a
false stale-delivery age.
