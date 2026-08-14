# Automata observability assets

This directory contains the versioned Prometheus scrape contract, recording and
alert rules, rule tests, Grafana dashboards, and operator runbooks for Automata.
The authoritative metric schema and privacy policy are in
[`docs/observability.md`](../../docs/observability.md).

These files are safe defaults and examples, not a complete production topology.
Keep metrics on a private operations network and replace every example target,
remote-write endpoint, cluster label, and runbook host before deployment.

## Files

- `prometheus.yml` is a central Prometheus example using file-based target
  discovery and strict scrape limits.
- `runner-agent.yml` is a node-local Prometheus Agent example for one outbound-
  only host running exactly three runner processes. Replace its three
  `instance` placeholders with stable globally unique process identities, its
  shared `host` placeholder with one stable machine identity, and the
  remote-write URL and credentials before starting it. It ingests and
  remote-writes native histograms while retaining the classic form.
- `inventory/` contains the bounded central runner-inventory renderer, its
  deployment validator, and an exact schema example. The renderer produces a
  node_exporter textfile-collector document; it does not run on runner hosts.
- `targets/*.json` are development target files. Inventory identity belongs in
  these target labels, not in application metric labels.
- `rules/automata-ci-recording.yml` contains reset-aware fleet aggregations.
- `rules/automata-ci-alerts.yml` contains symptom-oriented starter alerts.
- `rules/tests/automata-ci.test.yml` is executed with `promtool test rules`.
- `grafana/dashboards` contains the provisioned fleet, control-plane, runner,
  Results/storage, and SLO dashboards.
- `runbooks` contains first-response procedures referenced by alerts.

## Local validation

Build both products, enable their metrics listeners, and then run the repository
verification wrapper:

```console
scripts/ci/verify-metrics.sh
scripts/ci/verify-native-metrics.sh
```

The wrapper installs no global tools. It uses `promtool` from `PATH` when
available, or the pinned Prometheus container when an explicitly selected
container runtime is available. CI additionally starts a real Prometheus and
scrapes the shared exporter fixture endpoint; parser-only linting cannot
validate HTTP content negotiation, response headers, terminal EOF, or `up`.
The control-plane and runner exporters are covered by executable protocol,
privacy, and bounded-cardinality tests.

Current `promtool check metrics` uses the legacy text parser and rejects
OpenMetrics-only `info` and `UNIT` directives. The wrapper therefore feeds it a
mechanically downgraded lint-only view while preserving the original document
for header/EOF checks and real Prometheus ingestion.

To inspect these examples with a local Prometheus installation:

```console
promtool check config deploy/observability/prometheus.yml
promtool check rules \
  deploy/observability/rules/automata-ci-recording.yml \
  deploy/observability/rules/automata-ci-alerts.yml
promtool test rules deploy/observability/rules/tests/automata-ci.test.yml
```

Prometheus Agent mode is selected on the command line:

```console
prometheus \
  --agent \
  --config.file=deploy/observability/runner-agent.yml \
  --storage.agent.path=target/prometheus-agent
```

The control-plane and runner jobs negotiate `PrometheusProto` first and
`OpenMetricsText1.0.0` as fallback. Prometheus 3.x must explicitly set
`scrape_native_histograms: true`; `always_scrape_classic_histograms: true`
keeps existing bucket-based recording rules available. Each native histogram
is bounded to 160 buckets and schema 3 or lower through
`native_histogram_min_bucket_factor: 1.09`. The node-local Agent additionally
sets `send_native_histograms: true`, because native histograms are not sent by
default in Prometheus 3.x. Production instrumentation currently emits no
exemplars, so exemplar remote write remains disabled.

Every node-local Agent scrapes the three fixed process listeners at
`127.0.0.1:9464`, `:9465`, and `:9466`. Without three explicit unique
`instance` labels, the processes remote write colliding label sets. The shared
`host` label groups the trio without conflating their process identity. Treat
any unchanged placeholder as a deployment validation failure. These identities
belong to discovery/inventory configuration, never to application metric
labels, and remain stable across runner and host restarts.

Before deploying a runner Agent, render the authoritative inventory and verify
that the Agent's exact identity tuple is present:

```console
deploy/observability/inventory/render-runner-inventory.sh \
  /etc/automata/runner-inventory.json \
  > /var/lib/node_exporter/textfile_collector/automata-runner-inventory.prom.tmp
deploy/observability/inventory/validate-runner-deployment.sh \
  /etc/prometheus/runner-agent.yml \
  /etc/automata/runner-inventory.json \
  /var/lib/node_exporter/textfile_collector/automata-runner-inventory.prom.tmp \
  /var/lib/node_exporter/textfile_collector/automata-runner-inventory.prom
```

The validator bounds immutable non-symlink snapshots, enforces the exact
checked-in three-target Agent template after its identity and remote-write
substitutions, invokes `promtool` on those same snapshots, proves all three
slots match the exact JSON revision, and atomically publishes its validated
copy. It requires Python 3 and `jq`, plus local `promtool` or
`AUTOMATA_METRICS_CONTAINER_RUNTIME=podman|docker`. Configure that independent
central exporter as a dedicated textfile-only node_exporter with
`--collector.disable-defaults --collector.textfile` and an inventory-only
`--collector.textfile.directory`, for example:

```console
node_exporter \
  --collector.disable-defaults \
  --collector.textfile \
  --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
```

Do not share this endpoint with node_exporter's default collectors or place
unrelated textfiles in its directory. Prometheus applies the checked-in 2 MB
`body_size_limit` before metric relabeling, so the extra payload can reject a
valid maximum-size 9,999-runner inventory scrape even though the scrape job
keeps only three metric families. Populate `targets/inventory-exporter.json`
with the dedicated exporter's private scrape address. The scrape job keeps
`automata_ci_runner_inventory_expected`,
`automata_ci_runner_inventory_generation_timestamp_seconds`, and
`node_textfile_scrape_error` and uses `honor_labels: true`, preserving the
expected series' runner `job` and `instance` labels for the alert join. The
generation gauge is a metric value, not a Prometheus sample timestamp. The
textfile format intentionally has no sample timestamps and no OpenMetrics
`# EOF` marker.

Configure exactly one active inventory-exporter target per Prometheus. The
checked-in scrape job enforces `target_limit: 1`; two producers would publish
identical honor-label-preserved expected-runner series and can cause duplicate
or out-of-order ingestion. Each Prometheus replica may independently scrape the
same authoritative exporter, but one Prometheus must not scrape two competing
inventory producers.

The inventory JSON contract is exact and bounded: top-level `schema: 3`, a
positive integer `generated_at_seconds`, and a nonempty `runners` array of
globally unique `{instance, host, runner_slot, cluster, environment}` objects.
Every stable host must have exactly slots `1`, `2`, and `3`, all in one cluster
and environment. The authoritative producer refreshes the generation value and
atomically republishes at least once per minute even when membership is
unchanged; evidence older than five minutes or more than one minute in the
future fails validation and alerts. String values use only
`[A-Za-z0-9._:-]`, are at most 128 bytes, and must not use `replace-me`
placeholders. The renderer rejects symlinks, documents over 1 MiB, more than
9,999 records, extra keys, duplicate identities or slots, incomplete hosts,
and malformed values. Run the validator/publisher against every rendered Agent
before rollout: a missing trio member, host/slot mismatch, noncanonical YAML or
additional discovery, target/port drift, stale inventory, or an example/non-TLS
remote-write URL fails closed.

`up == 0` detects a local exporter failure only while the node-local Agent can
continue remote writing. If the runner host or Agent disappears, its `up`
series becomes stale and an equality alert no longer fires. Production must
also publish `automata_ci_runner_inventory_expected{job="automata-runner",
instance="...",host="...",runner_slot="...",cluster="...",environment="..."}
1` from an independent central inventory source; the included missing-runner
alert joins that durable expectation against `up`.

The independent inventory source is itself mandatory monitoring infrastructure.
The supplied rules page when its scrape is zero or when Prometheus discovers no
`automata-runner-inventory` target. Until that alert is cleared, absence of
individual missing-runner alerts is not evidence that the fleet is complete.
They also page if a healthy exporter publishes no expected-runner series or
node_exporter reports a textfile parse/read error; either condition can erase
the evidence needed by the missing-runner join. Generation is checked per
healthy exporter: absent or zero values, age over five minutes, and clock skew
over sixty seconds into the future all page.

Do not expose the runner endpoint centrally merely to avoid deploying a local
collector. Direct remote scraping is unsupported by the current runner and
requires a separate management-network and scraper-authentication design.
