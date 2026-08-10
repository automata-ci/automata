# Results and storage

1. Separate Results-listener transport symptoms in
   `automata_ci_results_http_requests_total` from application outcomes in
   `automata_ci_results_operations_total`. A cancelled operation is terminal
   and observable, but is excluded from the supplied failure ratio.
2. Follow one fixed operation through
   `automata_ci_results_operation_duration_seconds`, the PostgreSQL repository
   outcome in `automata_ci_storage_operations_total`, and the object-store
   outcome. Metrics intentionally contain no artifact ID, name, digest, object
   key, endpoint, or error text.
3. Treat `integrity` and `corrupt_data` storage outcomes as fail-closed data-
   integrity incidents. Preserve database rows and immutable objects; do not
   delete, overwrite, or retry around the verification boundary merely to
   restore throughput.
4. Check `automata_ci_control_plane_artifacts`,
   `automata_ci_control_plane_artifact_reservations`, and the guarded oldest-
   reservation age recording rule. These are replicated global snapshots: use
   `max without(instance)`, never `sum`, and confirm state-sampler freshness.
5. Inspect `automata_ci_postgres_pool_connections`, object-store dependency
   readiness, capacity outcomes, and process resource metrics before changing
   concurrency or storage limits.
6. Upload bytes count only staged blocks accepted by the service. Download
   bytes count only verified body frames yielded to the consumer, so compare
   byte rates with cancellations before diagnosing missing payloads.
