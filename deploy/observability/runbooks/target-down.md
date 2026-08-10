# Metrics target down

This alert means Prometheus cannot scrape an Automata process or the independent
runner-inventory exporter. It does not by itself prove that workflow traffic is
unavailable. While `AutomataRunnerInventoryExporterDown` is active, whole-runner
loss detection is not trustworthy because the expected-runner series can also
go stale.

1. Confirm whether the process is running and whether its desired deployment
   count or runner registration still expects the target.
2. Check the process supervisor for startup, bind, or unexpected metrics-service
   exit failures.
3. From the collector host, request the exact private `/metrics` address and
   inspect DNS, routing, firewall, TLS proxy, and scraper credentials.
4. Verify the response is a complete HTTP 200 negotiated metrics document. A
   protobuf response must use the delimited `MetricFamily` content type; an
   OpenMetrics fallback must use the expected content type and terminal
   `# EOF`.
5. Check Prometheus target details for timeout, body-size, sample, or label-limit
   rejection. Do not raise limits before finding the unexpected growth.
6. For a runner behind NAT, check the node-local Agent and remote-write queue;
   central `up` may describe the Agent target rather than direct reachability.
7. Confirm the central inventory still publishes
   `automata_ci_runner_inventory_expected` for this stable `instance`. A whole
   host or Agent loss makes `up` stale rather than zero, so the independent
   inventory join is the authoritative host-loss signal.
8. On the inventory host, render the current authoritative JSON with
   `inventory/render-runner-inventory.sh`, lint the temporary document, and
   atomically replace the node_exporter textfile. Then check the
   `automata-runner-inventory` target. It must be up, must preserve the exported
   runner `job`/`instance` labels, and must not expose a stale `.prom` file for a
   runner that is no longer desired.
   Confirm the exporter process was started with
   `--collector.disable-defaults --collector.textfile` and an inventory-only
   `--collector.textfile.directory`. Prometheus enforces its 2 MB body limit
   before metric relabeling; sharing this endpoint with default collectors or
   unrelated textfiles can reject an otherwise valid maximum-size inventory.
   Move the inventory to a dedicated textfile-only exporter instead of raising
   the bounded scrape limit without evidence.
   If the alert has no `instance` label, Prometheus discovered no inventory
   exporter at all: repair `targets/inventory-exporter.json` or its production
   service-discovery equivalent before investigating individual missing
   runners. If it has an `instance`, repair that failed exporter and verify at
   the one authoritative inventory source. The scrape contract permits exactly
   one active inventory target per Prometheus; remove a competing target rather
   than raising `target_limit` and creating duplicate expected-runner series.
   If the exporter is up but `AutomataRunnerInventoryDocumentEmpty` fires,
   verify that the rendered document is nonempty and that the metric relabel
   keep rule still admits `automata_ci_runner_inventory_expected`.
   `AutomataRunnerInventoryTextfileError` means
   `node_textfile_scrape_error > 0`; inspect node_exporter logs and every file in
   the configured textfile directory, then atomically replace the malformed
   `.prom` document with a validated current render. Do not leave the inventory
   absent or silence the alert by dropping the collector health metric.
   For `AutomataRunnerInventoryGenerationStale`, compare
   `automata_ci_runner_inventory_generation_timestamp_seconds` with `time()`.
   The authoritative producer must refresh at least every sixty seconds; zero,
   a missing series, age over five minutes, or more than sixty seconds of future
   skew is invalid. Repair the producer schedule or clock, rerender schema 2,
   validate it, and atomically publish it. Never patch the timestamp value in an
   old textfile merely to clear the page.
9. Run `inventory/validate-runner-deployment.sh` with the affected runner's
   rendered Agent, authoritative JSON, staged exposition, and final `.prom`
   destination. It Promtool-checks and publishes the same bounded snapshots;
   do not validate one revision and separately rename another. Fix identity,
   cluster, or environment drift at the inventory/deployment source; do not
   add those values to application metric labels.

Do not expose `/metrics` through a public application listener as a workaround.
