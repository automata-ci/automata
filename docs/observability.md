# Prometheus and OpenMetrics observability

Automata exposes Prometheus-compatible metrics from the control plane and each
runner. This page is the metric reference: it defines the listeners, protocol,
families, allowed labels, cardinality budget, recording rules, alerts, and
verification.

When a metric changes, update this reference, the finite label definitions,
`deploy/observability/cardinality.json`, the recording and alert rules, and the
protocol tests in the same change.

## Collection topology

The control plane and runner each expose a dedicated operations listener. The
listener is disabled when its configuration is absent and accepts only the
fixed `GET /metrics` resource. It is not mounted on the human, Results, or
runner-control listener.

The first supported deployment binds the listener to a loopback address. A
control-plane host may be scraped directly by a co-located collector. An
outbound-only Linux runner host starts three independent single-slot processes
on ports 9464 through 9466. One node-local Prometheus Agent scrapes all three
and sends their samples to central storage with remote write.

Each target carries a stable globally unique process `instance`, its fixed
`runner_slot`, and one stable `host` identity shared by the trio. Reusing an
instance or leaving any checked-in placeholder causes remote-write label
collisions and fails deployment validation. These inventory identities are
scrape target labels, not application metric labels.

Node-local `up == 0` remains visible when the exporter fails but the Agent can
remote write. It cannot detect disappearance of the whole host or Agent because
that time series becomes stale. Production monitoring therefore also needs an
independent central inventory series,
`automata_ci_runner_inventory_expected{job="automata-runner",instance="...",
host="...",runner_slot="..."} 1`, and the supplied rules alert when an
expected identity has no current `up`. Inventory schema 3 accepts a host only
when it contains exactly slots 1, 2, and 3.

Do not use Pushgateway for runners and do not carry telemetry through the
runner-control protocol. Non-loopback exposure is unsupported by the current
products; any such design requires a private management network and independent
TLS or mTLS scraper credentials. Runner client certificates must not authorize
metrics access.

The metrics listener remains available while application readiness is false.
Prometheus `up` reports scrape health; `automata_ci_control_plane_ready` or
`automata_ci_runner_ready` reports application readiness. The control-plane
listener and process sampler start before fallible production adapter
composition, exposing `automata_ci_control_plane_ready 0` throughout startup.
The durable-state sampler is handed to that already-supervised listener only
after its repository has been composed.

Enable the control-plane listener explicitly:

```console
automata server --metrics-listen 127.0.0.1:9464 [OTHER SERVER OPTIONS]
```

`AUTOMATA_METRICS_LISTEN` is the equivalent control-plane environment setting.
Enable each runner listener in its strict JSON product configuration. The
first instance uses:

```json
{
  "metrics": {
    "listen": "127.0.0.1:9464"
  }
}
```

Instances two and three use `127.0.0.1:9465` and `127.0.0.1:9466`. The setting
is omitted to disable the listener. Both products accept only a literal IPv4
or IPv6 loopback socket address; DNS names, non-loopback addresses, and port
zero fail product configuration validation. Direct listener harnesses use port
zero only in tests.

## Prometheus and OpenMetrics endpoint contract

A production Prometheus 3.x scrape prefers the delimited Prometheus protobuf
representation required for native histograms:

```text
Content-Type: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited
```

The endpoint also supports UTF-8 OpenMetrics 1.0 text as the negotiated
fallback, with LF line endings:

```text
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8
Cache-Control: no-store
```

The complete OpenMetrics body ends with `# EOF\n`. An absent, wildcard-only,
or tied `Accept` falls back to OpenMetrics and uses the legacy-safe
`escaping=underscores` content-type parameter; an explicit supported
`escaping=allow-utf-8` range produces the text example above. The production
scrape configuration advertises `PrometheusProto` first and
`OpenMetricsText1.0.0` second. The handler responds with `406 Not Acceptable`
when the client explicitly excludes every supported representation. Modern
Prometheus `escaping=allow-utf-8` and the legacy-safe `escaping=underscores`
scheme are negotiated explicitly; the exporter does not claim schemes that
would require rewriting registry names. Other paths return a non-echoing
`404`; other methods return `405`; and a declared request body is rejected
with `400`. Error responses carry the same `no-store` and `nosniff`
protections as successful scrapes.

The exporter encodes a complete bounded body before returning status 200. It
does not stream a partial exposition and performs no database, object-store,
control-plane, Podman, journal decode, or spool decrypt operation during a
scrape. Initial limits are:

| Limit | Control plane | Runner |
| --- | ---: | ---: |
| Concurrent scrapes | 2 | 2 |
| Handler deadline | 5 seconds | 5 seconds |
| Encoded response | 2 MiB | 2 MiB |
| Series per target | 5,250 | 1,000 |

The canonical schema currently uses at most 5,024 control-plane series and 939
runner series per Linux target. With native and classic histograms ingested
together, the Prometheus maxima are 5,169 control-plane samples and 969 runner
samples per scrape. Both remain below the same 5,250 and 1,000 limits. The
limits are release gates; remaining headroom is not an invitation to add
unbounded labels.

## Naming and values

Automata families use the `automata_ci_` namespace, except for standard
`process_*` metrics. Names use base units such as seconds and bytes. Counters
end in `_total`; timestamp gauges end in `_timestamp_seconds`.

Durations are measured with a monotonic clock. Timestamp gauges contain Unix
seconds and are used in queries such as:

```promql
(time() - automata_ci_runner_control_last_success_timestamp_seconds)
and automata_ci_runner_control_last_success_timestamp_seconds > 0
```

Counters are process-local and reset at process start. Apply `rate()` before
aggregating replicas:

```promql
sum without (instance, host, runner_slot) (
  rate(automata_ci_control_plane_http_requests_total[5m])
)
```

Do not persist metric counters. Pre-initialize every known finite label
combination that operators need to distinguish from an absent target.

## Label and privacy policy

Metric labels are Rust enums or other closed code-defined value sets. Allowed
dimensions include operation, outcome, bounded reason, state, backend,
transport, component, method, matched route, status class, protocol version,
platform, architecture, and a bounded runner resource profile.

The following values are forbidden as labels, HELP text, or dynamically
constructed metric names:

- tenant, user, principal, owner, repository, workflow, ref, or workflow SHA;
- run, job, attempt, runner, session, lease, operation-instance, slot, sequence,
  artifact, upload, or stream identifiers;
- action, image, service, environment-variable, or step names;
- URL, host, path, query, object key, digest, provider handle, SQL, bucket, or
  endpoint;
- certificate identity, credential, wrapping-key, or secret identifier; and
- error, diagnostic, compiler, command-output, or other user-controlled text.

Hashing an identifier does not make it bounded or non-sensitive. Unknown
external values map to a finite `other` category. Per-tenant usage belongs in a
separate restricted accounting pipeline.

Deployment, cluster, region, environment, and target identity are scrape target
labels supplied by service discovery. They are not repeated by the application
on every family. A source build revision is allowed only on the single
`automata_ci_build_info` series.

HTTP instrumentation uses the Axum matched route template. It never uses the
raw URI or query.

## Common families

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `automata_ci_build_info` | info | `role`, `version`, `revision` | One series with value 1 for the running build |
| `automata_ci_metrics_scrapes_total` | counter | `outcome` | Scrape attempts classified by one of nine closed protocol/encoding outcomes |
| `automata_ci_metrics_scrape_duration_seconds` | histogram | none | Complete request handling duration |
| `automata_ci_metrics_exposition_size_bytes` | histogram | none | Successfully encoded response size |
| `automata_ci_metrics_scrapes_in_flight` | gauge | none | Active scrape handlers |
| `automata_ci_metrics_last_success_timestamp_seconds` | gauge | none | Last completely encoded exposition |
| `process_start_time_seconds` | gauge | none | Process start time |
| `process_cpu_seconds_total` | counter | none | Process user and system CPU time |
| `process_resident_memory_bytes` | gauge | none | Resident memory |
| `process_virtual_memory_bytes` | gauge | none | Virtual memory |
| `process_threads` | gauge | none | Process threads |
| `process_open_fds` | gauge | none | Open file descriptors |
| `process_max_fds` | gauge | none | Process file-descriptor limit |
| `automata_ci_metrics_process_snapshot_refreshes_total` | counter | `outcome` | Cached process snapshot refreshes |
| `automata_ci_metrics_process_snapshot_healthy` | gauge | none | Whether the latest refresh succeeded |
| `automata_ci_metrics_process_snapshot_last_success_timestamp_seconds` | gauge | none | Last successful process refresh |

On Linux, a bounded ten-second background sampler reads `/proc` and atomically
replaces this cached process snapshot; scrapes never access `/proc`. A failed
refresh preserves the last good values and marks the snapshot unhealthy. Host
CPU, memory, disk, and network remain node-exporter or container-runtime
responsibilities.

## Control-plane families

### Health and HTTP

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_control_plane_ready` | gauge | none |
| `automata_ci_control_plane_dependency_ready` | gauge | `dependency` |
| `automata_ci_control_plane_dependency_probes_total` | counter | `dependency`, `outcome` |
| `automata_ci_control_plane_dependency_probe_duration_seconds` | histogram | `dependency` |
| `automata_ci_control_plane_dependency_last_success_timestamp_seconds` | gauge | `dependency` |
| `automata_ci_control_plane_dependency_readiness_transitions_total` | counter | `dependency`, `state` |
| `automata_ci_control_plane_supervised_service_exits_total` | counter | `service`, `outcome` |
| `automata_ci_control_plane_http_requests_total` | counter | `method`, `route`, `status_class` |
| `automata_ci_control_plane_http_request_duration_seconds` | histogram | `route` |
| `automata_ci_control_plane_http_requests_in_flight` | gauge | `route` |

Dependencies are exactly `database` and `object_store`. Probe outcomes are
`success`, `error`, or `timeout`. Routes come from a fixed allowlist covering
the human UI, workflow ingress, GitHub sign-in/setup, and RBAC management
templates; unknown matched routes map to `other`, while requests without a
matched template map to `unmatched`. Method and status class also have closed
`other` values. Method is retained on the request counter but intentionally
omitted from the duration and in-flight families to bound the preinitialized
schema.

### Workflow admission and scheduling

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_control_plane_workflow_admissions_total` | counter | `outcome` |
| `automata_ci_control_plane_workflow_admission_duration_seconds` | histogram | `outcome` |
| `automata_ci_control_plane_workflow_admission_stages_total` | counter | `stage`, `outcome` |
| `automata_ci_control_plane_workflow_admission_stage_duration_seconds` | histogram | `stage` |
| `automata_ci_control_plane_workflow_jobs_committed_total` | counter | none |
| `automata_ci_control_plane_workflow_admission_receipt_replays_total` | counter | none |
| `automata_ci_control_plane_lease_polls_total` | counter | `outcome`, `disposition`, `reason` |
| `automata_ci_control_plane_lease_poll_duration_seconds` | histogram | `outcome` |
| `automata_ci_control_plane_lease_poll_candidates` | histogram | none |
| `automata_ci_control_plane_lease_queue_wait_seconds` | histogram | none |

Admission stages are exactly `prepare`, `materialize`, `encode`, `publish`, and
`commit`; their outcomes are `success` or `failure`. Final admission outcomes
are `new`, `replay`, `error_materialization`, `error_blob_store`,
`error_durable_store`, or `error_invalid_state`. Diagnostic text is never a
label.

A poll attempt is counted for every request. Its labels use a reviewed set of
21 reachable combinations rather than the full Cartesian product. Jobs and
claims are counted only after a new durable commit; receipt replay uses the
`replay` disposition and never increments a durable transition again.

### Runner-control server semantics

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_control_plane_runner_control_handshakes_total` | counter | `outcome` |
| `automata_ci_control_plane_runner_control_handshake_duration_seconds` | histogram | `outcome` |
| `automata_ci_control_plane_runner_control_messages_total` | counter | `kind`, `outcome` |
| `automata_ci_control_plane_runner_control_message_duration_seconds` | histogram | `kind` |
| `automata_ci_control_plane_runner_control_durable_transitions_total` | counter | `kind` |
| `automata_ci_control_plane_runner_control_receipt_replays_total` | counter | `kind` |
| `automata_ci_control_plane_runner_control_ingress_bytes_total` | counter | `kind` |
| `automata_ci_control_plane_runner_control_lease_offer_events_total` | counter | `outcome` |
| `automata_ci_control_plane_runner_transport_connection_events_total` | counter | `outcome` |
| `automata_ci_control_plane_runner_transport_tls_handshakes_total` | counter | `outcome` |
| `automata_ci_control_plane_runner_transport_tls_handshake_duration_seconds` | histogram | `outcome` |
| `automata_ci_control_plane_runner_transport_requests_total` | counter | `route`, `stage`, `outcome` |
| `automata_ci_control_plane_runner_transport_request_duration_seconds` | histogram | `route`, `stage` |
| `automata_ci_control_plane_runner_transport_requests_in_flight` | gauge | `route` |
| `automata_ci_control_plane_runner_transport_bytes_total` | counter | `route`, `direction` |

The application families start only after transport admission, authentication,
body collection, and decode. The separate transport families cover those
pre-handler branches, including overload, timeout, malformed input, and TLS
failure. These semantic families remain necessary because a valid HTTP 200
response can contain a protocol-level rejection. Request bytes count only
completely collected accepted bodies; response bytes count only successful
encodings.

### Maintenance, Results, and storage

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_control_plane_maintenance_passes_total` | counter | `outcome` |
| `automata_ci_control_plane_maintenance_pass_duration_seconds` | histogram | `outcome` |
| `automata_ci_control_plane_maintenance_last_success_timestamp_seconds` | gauge | none |
| `automata_ci_control_plane_maintenance_work_items_total` | counter | `kind` |
| `automata_ci_control_plane_maintenance_batch_saturated` | gauge | none |
| `automata_ci_results_operations_total` | counter | `operation`, `outcome` |
| `automata_ci_results_operation_duration_seconds` | histogram | `operation` |
| `automata_ci_results_bytes_total` | counter | `direction` |
| `automata_ci_storage_operations_total` | counter | `backend`, `operation`, `outcome` |
| `automata_ci_storage_operation_duration_seconds` | histogram | `backend`, `operation` |
| `automata_ci_storage_bytes_total` | counter | `backend`, `direction` |
| `automata_ci_results_http_requests_total` | counter | `method`, `route`, `outcome` |
| `automata_ci_results_http_request_duration_seconds` | histogram | `route` |
| `automata_ci_results_http_requests_in_flight` | gauge | `route` |
| `automata_ci_postgres_pool_connections` | gauge | `state` |
| `automata_ci_postgres_pool_max_connections` | gauge | none |

Maintenance work kinds are closed to the repository report fields:
`requeued_attempt`, `lost_attempt`, `skipped_blocked_attempt`, and
`closed_stale_session`. Results operations are `create`, `stage_block`,
`commit`, `finalize`, `list`, `prepare_download`, and `read_block`.

Every started Results service, repository, blob, and HTTP operation terminates
exactly once, including a dropped future classified as `cancelled`. PostgreSQL
uses eleven fixed repository operations; object storage uses `put|get`, with
closed provider outcomes. Upload bytes increment only after a staged block is
accepted. Download bytes increment only as verified response-body frames are
actually yielded, so a cancelled consumer does not claim undelivered bytes.
Raw artifact names, IDs, digests, MIME types, object keys, endpoints, and error
text never cross an observer seam.

### Cached durable state

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_control_plane_state_sampler_runs_total` | counter | `outcome` |
| `automata_ci_control_plane_state_sampler_duration_seconds` | histogram | `outcome` |
| `automata_ci_control_plane_state_sampler_healthy` | gauge | none |
| `automata_ci_control_plane_state_sampler_last_success_timestamp_seconds` | gauge | none |
| `automata_ci_control_plane_workflow_runs` | gauge | `status` |
| `automata_ci_control_plane_logical_workflow_runs` | gauge | `state` |
| `automata_ci_control_plane_logical_jobs` | gauge | `state` |
| `automata_ci_control_plane_logical_activations` | gauge | `state` |
| `automata_ci_control_plane_logical_activation_oldest_timestamp_seconds` | gauge | `state` |
| `automata_ci_control_plane_logical_activation_publications` | gauge | none |
| `automata_ci_control_plane_logical_materialized_instances` | gauge | none |
| `automata_ci_control_plane_job_attempts` | gauge | `lifecycle` |
| `automata_ci_control_plane_runners` | gauge | `observed_state`, `desired_state` |
| `automata_ci_control_plane_runner_sessions` | gauge | `state` |
| `automata_ci_control_plane_queue_jobs` | gauge | `state` |
| `automata_ci_control_plane_queue_oldest_timestamp_seconds` | gauge | `state` |
| `automata_ci_control_plane_eligible_queue_blocked_jobs` | gauge | `reason` |
| `automata_ci_control_plane_eligible_queue_blocked_oldest_timestamp_seconds` | gauge | `reason` |
| `automata_ci_control_plane_leases` | gauge | `state` |
| `automata_ci_control_plane_commands_pending` | gauge | none |
| `automata_ci_control_plane_commands_oldest_timestamp_seconds` | gauge | none |
| `automata_ci_control_plane_cancellation_intents_pending` | gauge | none |
| `automata_ci_control_plane_cancellation_intents_oldest_timestamp_seconds` | gauge | none |
| `automata_ci_control_plane_artifacts` | gauge | `state` |
| `automata_ci_control_plane_artifact_reservations` | gauge | `kind` |
| `automata_ci_control_plane_artifact_reservation_oldest_timestamp_seconds` | gauge | `kind` |
| `automata_ci_postgres_pool_connections` | gauge | `state` |
| `automata_ci_postgres_pool_max_connections` | gauge | none |

The sampler executes bounded statements in one read-only, repeatable-read
transaction with a two-second statement timeout immediately and then every 15
seconds. Every started refresh terminates as `success`, `error`, or `cancelled`;
cancellation is recorded by a drop guard even when shutdown interrupts an
in-flight backend future. Error and cancellation retain the last good snapshot
and mark the sampler unhealthy. Always check sampler health and last-success
age before treating any cached value as current.

Queue states are `queued` and `eligible`. `queued` counts every attempt whose
durable lifecycle is queued. `eligible` applies the production runnable
predicate at the snapshot's trusted time: the attempt is due, its run is queued
or in progress, its job has the current admission epoch and JobIR schema, it has
no cancellation intent, its run owns its concurrency group when one exists,
and the newest attempt for every current prerequisite succeeded. Thus the
difference between the two states is intentionally not schedulable demand.

Compatible-capacity evidence applies the scheduler's core evaluator to every
eligible candidate. It uses only same-tenant effective runners that are online,
desired-active, on a current live session, and support the current JobIR. The
effective capabilities are the least-authority intersection of registered and
observed capabilities; routing labels and group authorization, core runner
requirements, configured/effective parallelism, and occupied durable slots are
all evaluated exactly as scheduling evaluates them. `reason` is
`no_compatible_runner` when no effective runner satisfies all requirements, or
`compatible_runners_busy` when compatible runners exist but all authorized
slots are occupied. A candidate with an available compatible slot is not in a
blocked family. This is exact per-candidate evidence for one immutable snapshot,
not a speculative batch allocation of free slots among all candidates.

Capacity collection is exact up to 1,000 eligible candidates, 64 effective
runners, and 256 registered slots per runner. Queries request one sentinel row
beyond each applicable bound. Exceeding a bound, finding partial candidate
coverage, observing invalid capability state, or timing out fails the whole
refresh; no partial compatibility aggregate is published and the previous
snapshot remains cached. Candidate, tenant, runner, session, job, and attempt
identifiers exist only in the bounded in-memory evaluation and never become
metric labels or diagnostic fields.

logical workflow run states are `pending`, `active`, `completed`, `cancelled`,
and `failed`. Logical-job states are `pending`, `activating`, `activated`,
`completed`, `skipped`, `cancelled`, and `failed`. Activation observation states
are `pending`, `activating`, and `expired`: pending age starts at logical-job
creation, activating age starts when the claim was acquired, and expired age
starts at the claim expiry. `expired` is an overdue subset of `activating`, not
a separate durable logical-job state. Publication and materialized-instance
gauges count their current durable rows.

Lease states are `active`, `near_expiry`, and `expired`, with a fixed 60-second
near-expiry horizon. Oldest timestamps are zero for an empty queue, activation
state, capacity reason, outbox, cancellation set, or artifact-reservation kind.
Cancellation intents count requests whose runner acknowledgement is still
absent. Artifact states are `pending_upload`, `publication_reserved`, and
`finalized`; reservation kinds are `block` and `manifest`. If every
control-plane replica exports the same global snapshot, dashboards and rules
aggregate these families with `max without(instance)`, not `sum`.

## Runner families

### Connectivity and aggregate capacity

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_ready` | gauge | none |
| `automata_ci_runner_session_connected` | gauge | none |
| `automata_ci_runner_journal_session_present` | gauge | none |
| `automata_ci_runner_control_last_success_timestamp_seconds` | gauge | none |
| `automata_ci_runner_slots_configured` | gauge | none |
| `automata_ci_runner_slots` | gauge | `state` |
| `automata_ci_runner_slots_over_capacity` | gauge | none |
| `automata_ci_runner_slot_snapshot_conserved` | gauge | none |
| `automata_ci_runner_orphan_slots` | gauge | none |
| `automata_ci_runner_sandboxes` | gauge | none |
| `automata_ci_runner_pending_provider_operations` | gauge | none |
| `automata_ci_runner_snapshot_refreshes_total` | counter | `outcome` |
| `automata_ci_runner_snapshot_refresh_duration_seconds` | histogram | none |
| `automata_ci_runner_snapshot_refresh_healthy` | gauge | none |
| `automata_ci_runner_snapshot_last_success_timestamp_seconds` | gauge | none |

The slot collector publishes all buckets atomically. Durable slots can outlive
a lower replacement configuration, so the invariant is:

```promql
sum by (instance) (automata_ci_runner_slots)
  == on (instance)
     automata_ci_runner_slots_configured
     + on (instance) automata_ci_runner_slots_over_capacity
```

`automata_ci_runner_slot_snapshot_conserved` exposes that check directly;
`automata_ci_runner_slots_over_capacity` is the durable journal excess over
configured capacity. Operators must reconcile the configuration or safely
finish/recover durable work, never delete journal state merely to silence the
metric. Slot ordinals and attempt IDs never appear in the exposition.
`automata_ci_runner_session_connected` is live transport/session state; the
separate `automata_ci_runner_journal_session_present` gauge means a resumable
durable binding exists and may remain one during an outage.

### Physical control transport

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_control_requests_total` | counter | `kind`, `outcome` |
| `automata_ci_runner_control_request_duration_seconds` | histogram | `kind` |
| `automata_ci_runner_control_requests_in_flight` | gauge | `kind` |
| `automata_ci_runner_control_bytes_total` | counter | `direction` |
| `automata_ci_runner_control_retries_total` | counter | `kind` |

Control kinds are exactly `handshake`, `lease_request`, `lease_response`,
`heartbeat`, `job_state`, `job_result`, `log_batch`, and `command_ack`.
Outcomes are `success`, `transport_error`, `timeout`, `cancelled`, `http_error`,
or `invalid_response`. The supplied control-failure recording rule includes the
four error outcomes and excludes deliberate cancellation.

### Session, lease, delivery, and execution semantics

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_control_server_clock_offset_seconds` | gauge | none |
| `automata_ci_runner_control_retry_backoffs_total` | counter | `exchange`, `cause` |
| `automata_ci_runner_control_retry_backoff_duration_seconds` | histogram | none |
| `automata_ci_runner_control_remote_errors_total` | counter | `kind`, `disposition` |
| `automata_ci_runner_session_handshakes_total` | counter | `mode`, `outcome` |
| `automata_ci_runner_session_handshake_duration_seconds` | histogram | `mode` |
| `automata_ci_runner_session_reconnects_total` | counter | `reason` |
| `automata_ci_runner_orphan_recoveries_total` | counter | `outcome` |
| `automata_ci_runner_orphan_recovery_duration_seconds` | histogram | none |
| `automata_ci_runner_lease_polls_total` | counter | `outcome` |
| `automata_ci_runner_lease_poll_duration_seconds` | histogram | none |
| `automata_ci_runner_lease_responses_acknowledged_total` | counter | `disposition` |
| `automata_ci_runner_heartbeat_renewals_total` | counter | none |
| `automata_ci_runner_heartbeat_renewal_duration_seconds` | histogram | none |
| `automata_ci_runner_lease_expirations_total` | counter | none |
| `automata_ci_runner_commands_total` | counter | `kind`, `outcome` |
| `automata_ci_runner_command_gap_waits_total` | counter | none |
| `automata_ci_runner_command_acknowledgements_total` | counter | none |
| `automata_ci_runner_jobs_started_total` | counter | `mode` |
| `automata_ci_runner_jobs_completed_total` | counter | `conclusion` |
| `automata_ci_runner_job_duration_seconds` | histogram | `conclusion` |
| `automata_ci_runner_job_infrastructure_failures_total` | counter | `kind` |
| `automata_ci_runner_job_cancellations_total` | counter | `reason` |
| `automata_ci_runner_log_batches_acknowledged_total` | counter | none |
| `automata_ci_runner_log_frames_acknowledged_total` | counter | none |
| `automata_ci_runner_log_acknowledged_bytes_total` | counter | none |
| `automata_ci_runner_log_batch_acknowledgement_duration_seconds` | histogram | none |
| `automata_ci_runner_terminal_results_total` | counter | `stage`, `conclusion` |
| `automata_ci_runner_cleanups_total` | counter | `outcome` |
| `automata_ci_runner_cleanup_duration_seconds` | histogram | none |
| `automata_ci_runner_lease_earliest_expiry_timestamp_seconds` | gauge | none |

Retries count only after a retry delay completes, so cancellation during
backoff does not invent an attempt. Remote errors use nine fixed kinds and the
`retrying|terminal` disposition without the exchange dimension. Live session
connectivity is set only after durable session establishment and is cleared on
every exit. User job conclusions are workload outcomes; they are not
runner-platform error ratios. Infrastructure failures and local lease expiry
are separate platform signals.

### Cached snapshot, journal, and spool

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_pending_deliveries` | gauge | `kind` |
| `automata_ci_runner_pending_delivery_oldest_timestamp_seconds` | gauge | `kind` |
| `automata_ci_runner_pending_log_frames` | gauge | none |
| `automata_ci_runner_pending_log_bytes` | gauge | none |
| `automata_ci_runner_journal_revision` | gauge | none |
| `automata_ci_runner_journal_slots` | gauge | none |
| `automata_ci_runner_journal_max_slots` | gauge | none |
| `automata_ci_runner_journal_max_bytes` | gauge | none |
| `automata_ci_runner_journal_poisoned` | gauge | none |
| `automata_ci_runner_journal_size_bytes` | gauge | none |
| `automata_ci_runner_journal_mutations_total` | counter | `domain`, `outcome` |
| `automata_ci_runner_journal_mutation_duration_seconds` | histogram | none |
| `automata_ci_runner_spool_objects` | gauge | none |
| `automata_ci_runner_spool_protected_bytes` | gauge | none |
| `automata_ci_runner_spool_max_objects` | gauge | none |
| `automata_ci_runner_spool_max_bytes` | gauge | none |
| `automata_ci_runner_spool_poisoned` | gauge | none |

The sampler derives snapshot gauges from bounded in-memory state every five
seconds. It does not re-encode the journal, touch disk, or decrypt spool
payloads on scrape. Pending kinds are `terminal_result`, `lease_rejection`, and
`log_stream`. The oldest timestamp is the persisted enqueue time of the oldest
unacknowledged, non-abandoned delivery of that kind and is zero when its pending
count is zero. It therefore remains valid across runner restarts. Journal size
is captured from the canonical bytes already read at open or produced for a
successful commit; it is never recalculated for a scrape.

Journal mutation domains are exactly `session`, `lease_poll`, `command`,
`lease`, `lifecycle`, `result`, `provider`, `outbound`, `log`, `orphan`, and
`slot`. Outcomes are `committed`, idempotent `noop`, semantic `rejected`, known
pre-rename `io_error`, post-rename `uncertain`, and `poisoned`. The observer is
inside the physical adapter: `committed` is emitted only after the atomic
commit succeeds, while an uncertain rename poisons the handle. Durations are
process-observed and the observer never changes journal correctness.

### Durable spool operation detail

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_spool_operations_total` | counter | `operation`, `outcome` |
| `automata_ci_runner_spool_operation_duration_seconds` | histogram | none |
| `automata_ci_runner_spool_operations_in_flight` | gauge | `operation` |
| `automata_ci_runner_spool_failures_total` | counter | `kind` |
| `automata_ci_runner_spool_content_operations_total` | counter | `operation`, `kind` |
| `automata_ci_runner_spool_content_bytes_total` | counter | `operation`, `kind` |
| `automata_ci_runner_spool_protection_operations_total` | counter | `operation`, `outcome` |
| `automata_ci_runner_spool_capacity_rejections_total` | counter | `resource` |
| `automata_ci_runner_spool_reclaimed_objects_total` | counter | none |
| `automata_ci_runner_spool_reclaimed_bytes_total` | counter | none |
| `automata_ci_runner_spool_poison_events_total` | counter | `operation` |

Spool metrics are emitted inside the durable store, after the outcome is known;
the decorator does not guess about deduplication, adoption, reclaim, protection
authentication, or uncertain mutation. Runner-journal schema 7 persists the
bounded non-secret enqueue timestamps used by pending-delivery oldest-age
objectives. Metric counters remain process-local and are never persisted.

### Sandbox and provider detail

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_sandbox_provider_operations_total` | counter | `operation`, `outcome` |
| `automata_ci_runner_sandbox_provider_operation_duration_seconds` | histogram | none |
| `automata_ci_runner_sandbox_provider_operations_in_flight` | gauge | `operation` |
| `automata_ci_runner_sandbox_provider_errors_total` | counter | `kind` |
| `automata_ci_runner_sandbox_endpoint_operations_total` | counter | `operation`, `outcome` |
| `automata_ci_runner_sandbox_endpoint_operation_duration_seconds` | histogram | none |
| `automata_ci_runner_sandbox_endpoint_operations_in_flight` | gauge | `operation` |
| `automata_ci_runner_sandbox_endpoint_errors_total` | counter | `kind` |
| `automata_ci_runner_sandbox_endpoint_bytes_total` | counter | `direction` |
| `automata_ci_runner_sandbox_endpoint_terminations_total` | counter | `kind` |
| `automata_ci_runner_sandbox_endpoint_output_truncations_total` | counter | none |
| `automata_ci_runner_podman_commands_total` | counter | `stage` |
| `automata_ci_runner_podman_command_outcomes_total` | counter | `outcome` |
| `automata_ci_runner_podman_command_duration_seconds` | histogram | none |
| `automata_ci_runner_podman_commands_in_flight` | gauge | none |
| `automata_ci_runner_podman_command_output_bytes_total` | counter | `direction` |
| `automata_ci_runner_docker_proxy_requests_total` | counter | `route`, `outcome` |
| `automata_ci_runner_docker_proxy_request_duration_seconds` | histogram | none |
| `automata_ci_runner_docker_proxy_requests_in_flight` | gauge | `route` |
| `automata_ci_runner_docker_proxy_bytes_total` | counter | `direction` |
| `automata_ci_runner_docker_proxy_rejections_total` | counter | `reason` |

Provider stages and Docker routes are existing finite enums. Command argv,
container names, image references, environment values, and HTTP targets are
never inspected to construct labels.

### Aggregate sandbox cgroup resources

| Family | Type | Labels |
| --- | --- | --- |
| `automata_ci_runner_cgroup_snapshot_refreshes_total` | counter | `outcome` |
| `automata_ci_runner_cgroup_snapshot_healthy` | gauge | none |
| `automata_ci_runner_cgroup_snapshot_last_success_timestamp_seconds` | gauge | none |
| `automata_ci_runner_cgroup_cpu_usage_seconds_total` | counter | none |
| `automata_ci_runner_cgroup_cpu_throttled_seconds_total` | counter | none |
| `automata_ci_runner_cgroup_cpu_periods_total` | counter | none |
| `automata_ci_runner_cgroup_cpu_throttled_periods_total` | counter | none |
| `automata_ci_runner_cgroup_memory_current_bytes` | gauge | none |
| `automata_ci_runner_cgroup_memory_peak_bytes` | gauge | none |
| `automata_ci_runner_cgroup_pids_current` | gauge | none |
| `automata_ci_runner_cgroup_io_bytes_total` | counter | `direction` |
| `automata_ci_runner_cgroup_io_operations_total` | counter | `direction` |
| `automata_ci_runner_cgroup_memory_oom_events_total` | counter | `event` |

A timeout-bounded ten-second background sampler reads only the runner-owned
delegated cgroup-v2 parent. It aggregates all sandbox descendants without
attempt, device, path, or cgroup labels and never reads cgroup files on the
scrape path. Refresh outcomes are `success`, `error`, and `timeout`; a failed
refresh preserves the last good gauges and counters while setting healthy to
zero. Directions are `read|write`; OOM events are
`oom|oom_kill|oom_group_kill`.

Counters on the stable delegated parent remain cumulative when child sandboxes
disappear. The sampler converts their deltas into process-local monotonic
counters; a raw decrease means the parent was unexpectedly reset or recreated
and is treated as a new raw epoch. The initial observation establishes a
baseline and does not claim historical usage or OOM events. Use `rate()` or
`increase()` so a runner process restart is handled as a counter reset.

## Histogram buckets

Classic histograms are used because instances must aggregate. Summaries are not
part of the contract. Buckets must contain the corresponding SLO boundary and
remain identical across a rolling deployment.

| Class | Finite buckets |
| --- | --- |
| Exporter scrape seconds | `.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 5` |
| Exporter encoded bytes | `1024, 4096, 16384, 65536, 262144, 524288, 1048576, 2097152, 4194304` |
| Control/Results HTTP, semantic, state, and storage seconds | `.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30` |
| Control dependency seconds | `.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 30` |
| Control maintenance seconds | `.005, .01, .025, .05, .1, .25, .5, 1, 5, 30` |
| Queue wait seconds | `1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600` |
| Runner physical control seconds | `.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30` |
| Runner semantic/local/provider seconds | `.001, .005, .025, .1, .5, 1, 2.5, 10, 30` |
| Runner job seconds | `.1, .5, 1, 2.5, 5, 10, 30, 60, 300, 900, 3600, 21600` |
| Runner snapshot seconds | `.0001, .0005, .001, .005, .01, .05, .1` |

Validate distributions and series cost before treating these as frozen SLO
buckets. `prometheus-client` adds the mandatory `+Inf` bucket, then emits sum
and count, so a classic histogram creates `finite bucket count + 3` series for
each label combination.

Every production histogram retains these classic buckets and also carries a
standard-schema native histogram in Prometheus protobuf. Production scrapes
set `scrape_protocols: [PrometheusProto, OpenMetricsText1.0.0]`,
`scrape_native_histograms: true`, `always_scrape_classic_histograms: true`, a
160-bucket native cap, and a `1.09` minimum bucket factor (schema 3 ceiling).
OpenMetrics 1.0 text remains the fallback and contains the classic form only.
Keeping both forms preserves existing classic recording rules while operators
evaluate native-histogram storage cost and queries.

The runner Agent also sets `send_native_histograms: true`; Prometheus 3.x does
not remote-write them by default. Production metrics currently attach no
exemplars, and the selected client cannot encode a native histogram's exemplar
list, so the example intentionally does not enable exemplar remote write.

## Recording and alerting rules

Recording rules apply `rate()` before replica aggregation. Classic histogram
quantiles preserve `le`:

```promql
histogram_quantile(
  0.95,
  sum by (le, route) (
    rate(automata_ci_control_plane_http_request_duration_seconds_bucket[5m])
  )
)
```

Duplicated control-plane durable snapshots use `max without(instance)`. Queue,
blocked-capacity, logical-activation, and runner pending-delivery ages are
derived from absolute timestamps and guarded by both a positive timestamp and
their corresponding positive demand. The queue-to-claim p99 warning
additionally requires more than 0.01 observed claims per second over five
minutes, so an isolated slow claim cannot fire it. The compatible-capacity
page covers eligible work that is never claimed.

Alert on symptoms and correctness threats:

- missing scrape targets or desired-active runner sessions;
- sustained platform request-error budget burn or queue-to-claim latency
  objective misses, each with a traffic floor;
- oldest eligible queue work above objective while compatible capacity is
  insufficient;
- stale logical workflow activation backlog or unrecovered expired claims;
- lease expiration or lost attempts;
- stale maintenance, durable-state sampling, command/cancellation delivery,
  restart-correct runner outbound delivery, or artifact-reservation progress;
- blob-integrity, journal-poison, spool-protection, or capacity failures; and
- process or aggregate sandbox resource exhaustion threatening forward
  progress.

User-job failures and runner saturation alone do not page the platform team.
Retries, churn, RSS/fd pressure, scrape size/cardinality growth, clock skew,
OOM, and output truncation are warning or ticket signals unless they cause a
user-visible SLO burn.

Initial SLO hypotheses are 99.9% valid platform-request availability and 99%
of eligible work claimed within 60 seconds. Establish a production baseline
before ratifying them. Use minimum traffic guards, `for` durations, and
multi-window burn-rate alerts.

## Verification requirements

The metrics gate combines independent checks:

1. Rust golden tests assert names, HELP, TYPE, UNIT, escaping, zero series,
   buckets, exact content type, terminal EOF, and bounded error responses.
2. Negotiation tests cover Prometheus protobuf and OpenMetrics, wildcard,
   quality values, unsupported representations, fixed path/method behavior,
   and `no-store`; protobuf decoding proves native spans while OpenMetrics
   proves exact classic fallback buckets.
3. Semantic tests cover cancellation-safe in-flight gauges, retries and replay,
   durable-transition exactly-once behavior, sampler staleness, slot
   conservation, and journal/spool fault stages.
4. Privacy tests feed adversarial IDs, URLs, paths, image references, errors,
   payloads, and secret sentinels and assert that neither the series set nor
   exposition gains those values.
5. The logical-workflow cardinality manifest enumerates every family, type, unit,
   label key/domain or exact reachable tuple, histogram bucket, and maximum.
   Fresh control-plane and runner expositions must match it exactly.
6. `promtool check metrics --extended`, configuration and rule checks, and rule
   unit tests lint the operator artifacts.
7. An ephemeral pinned Prometheus performs a real HTTP scrape and verifies
   `Accept`, response headers, EOF, `up`, ingestion, resets, and recording-rule
   queries. `promtool check metrics` alone is not a protocol test.

The example collector configuration, rules, dashboards, and runbooks live in
[`deploy/observability`](../deploy/observability/README.md).
