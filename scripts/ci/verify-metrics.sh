#!/usr/bin/env bash
set -euo pipefail

readonly automata_prometheus_image='quay.io/prometheus/prometheus@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7'
readonly automata_prometheus_version='3.13.0'

automata_repo_root="$(git rev-parse --show-toplevel)"
readonly automata_repo_root
cd "$automata_repo_root"
# shellcheck source=scripts/ci/lib/target-paths.sh
source "$automata_repo_root/scripts/ci/lib/target-paths.sh"

automata_init_target_root "$automata_repo_root"
automata_set_target_tmpdir \
  "$automata_repo_root" \
  "$automata_repo_root/target/task-tmp/metrics-contract"

automata_promtool=''
automata_container_runtime="${AUTOMATA_METRICS_CONTAINER_RUNTIME:-}"
automata_fixture_pid=''
automata_prometheus_container=''
automata_scratch=''

cleanup_metrics_contract() {
  if [[ -n "$automata_prometheus_container" ]] &&
    [[ -n "$automata_container_runtime" ]]; then
    "$automata_container_runtime" rm --force \
      "$automata_prometheus_container" >/dev/null 2>&1 || true
  fi

  if [[ -n "$automata_fixture_pid" ]]; then
    kill "$automata_fixture_pid" >/dev/null 2>&1 || true
    wait "$automata_fixture_pid" >/dev/null 2>&1 || true
  fi

  if [[ -n "$automata_scratch" ]] && [[ -d "$automata_scratch" ]]; then
    rm -rf -- "$automata_scratch"
  fi
}

trap cleanup_metrics_contract EXIT

if command -v promtool >/dev/null 2>&1; then
  automata_promtool="$(command -v promtool)"
elif [[ -n "$automata_container_runtime" ]]; then
  case "$automata_container_runtime" in
    docker | podman)
      if ! command -v "$automata_container_runtime" >/dev/null 2>&1; then
        printf 'configured container runtime is unavailable: %s\n' \
          "$automata_container_runtime" >&2
        exit 1
      fi
      ;;
    *)
      printf 'AUTOMATA_METRICS_CONTAINER_RUNTIME must be docker or podman\n' >&2
      exit 1
      ;;
  esac
else
  printf '%s\n' \
    "promtool ${automata_prometheus_version} is required; install it or set AUTOMATA_METRICS_CONTAINER_RUNTIME" >&2
  exit 1
fi

run_promtool() {
  if [[ -n "$automata_promtool" ]]; then
    "$automata_promtool" "$@"
    return
  fi

  "$automata_container_runtime" run --rm --interactive \
    --volume "$automata_repo_root:/workspace:ro" \
    --workdir /workspace \
    --entrypoint /bin/promtool \
    "$automata_prometheus_image" \
    "$@"
}

automata_scratch="$(mktemp -d "$TMPDIR/automata-metrics-contract.XXXXXXXX")"
readonly automata_scratch

run_promtool_scratch_config() {
  local config_path="$1"
  local config_name

  if [[ "$config_path" != "$automata_scratch/"* ]]; then
    printf '%s\n' 'temporary Prometheus config escaped the metrics scratch directory' >&2
    return 1
  fi

  if [[ -n "$automata_promtool" ]]; then
    "$automata_promtool" check config "$config_path"
    return
  fi

  config_name="${config_path##*/}"
  "$automata_container_runtime" run --rm --interactive \
    --volume "$config_path:/$config_name:ro" \
    --workdir / \
    --entrypoint /bin/promtool \
    "$automata_prometheus_image" \
    check config "/$config_name"
}

readonly automata_inventory="$automata_scratch/runner-inventory.json"
readonly automata_inventory_metrics="$automata_scratch/runner-inventory.prom"
readonly automata_published_inventory_metrics="$automata_scratch/published-runner-inventory.prom"
readonly automata_rendered_agent="$automata_scratch/runner-agent.yml"
automata_inventory_generation="$(date +%s)"
readonly automata_inventory_generation
jq --null-input \
  --argjson generated_at_seconds "$automata_inventory_generation" '
  {
    schema: 3,
    generated_at_seconds: $generated_at_seconds,
    runners: [
      {
        instance: "runner-ci-03",
        host: "runner-host-ci-01",
        runner_slot: 3,
        cluster: "ci-cluster",
        environment: "staging"
      },
      {
        instance: "runner-ci-01",
        host: "runner-host-ci-01",
        runner_slot: 1,
        cluster: "ci-cluster",
        environment: "staging"
      },
      {
        instance: "runner-ci-02",
        host: "runner-host-ci-01",
        runner_slot: 2,
        cluster: "ci-cluster",
        environment: "staging"
      }
    ]
  }
' > "$automata_inventory"
deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_inventory" > "$automata_inventory_metrics"
run_promtool check metrics < "$automata_inventory_metrics"
if [[ "$(sed -n '3p' "$automata_inventory_metrics")" != \
  "automata_ci_runner_inventory_generation_timestamp_seconds $automata_inventory_generation" ]] ||
  [[ "$(sed -n '6p' "$automata_inventory_metrics")" != \
  'automata_ci_runner_inventory_expected{job="automata-runner",instance="runner-ci-01",host="runner-host-ci-01",runner_slot="1",cluster="ci-cluster",environment="staging"} 1' ]] ||
  [[ "$(sed -n '7p' "$automata_inventory_metrics")" != \
  'automata_ci_runner_inventory_expected{job="automata-runner",instance="runner-ci-02",host="runner-host-ci-01",runner_slot="2",cluster="ci-cluster",environment="staging"} 1' ]] ||
  [[ "$(sed -n '8p' "$automata_inventory_metrics")" != \
  'automata_ci_runner_inventory_expected{job="automata-runner",instance="runner-ci-03",host="runner-host-ci-01",runner_slot="3",cluster="ci-cluster",environment="staging"} 1' ]] ||
  [[ "$(wc -l < "$automata_inventory_metrics")" -ne 8 ]]; then
  printf '%s\n' 'runner inventory exposition is not exact and deterministic' >&2
  exit 1
fi

sed \
  -e 's/instance: replace-me-unique-1/instance: runner-ci-01/' \
  -e 's/instance: replace-me-unique-2/instance: runner-ci-02/' \
  -e 's/instance: replace-me-unique-3/instance: runner-ci-03/' \
  -e 's/host: replace-me-host/host: runner-host-ci-01/' \
  -e 's/environment: replace-me/environment: staging/' \
  -e 's/cluster: replace-me/cluster: ci-cluster/' \
  -e 's#https://prometheus\.example\.invalid/#https://metrics.company.net/#' \
  deploy/observability/runner-agent.yml > "$automata_rendered_agent"
AUTOMATA_PROMTOOL="$automata_promtool" \
AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_rendered_agent" \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_published_inventory_metrics"
if ! cmp --silent \
  "$automata_inventory_metrics" "$automata_published_inventory_metrics"; then
  printf '%s\n' 'runner deployment validator did not publish its exact staged snapshot' >&2
  exit 1
fi

mkdir "$automata_scratch/publication-race-target.prom"
cp "$automata_inventory_metrics" \
  "$automata_scratch/publication-race-source.prom"
if mv --no-target-directory -- \
  "$automata_scratch/publication-race-source.prom" \
  "$automata_scratch/publication-race-target.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' \
    'no-target-directory publication accepted a raced directory destination' >&2
  exit 1
fi

jq --argjson next_generation "$((automata_inventory_generation + 1))" \
  '.generated_at_seconds = $next_generation' \
  "$automata_inventory" > "$automata_scratch/runner-inventory-next-revision.json"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_rendered_agent" \
  "$automata_scratch/runner-inventory-next-revision.json" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-cross-revision.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator published a different inventory revision' >&2
  exit 1
fi

if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  deploy/observability/runner-agent.yml \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-placeholder.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted placeholder Agent identity' >&2
  exit 1
fi

jq '.runners += [.runners[0]]' "$automata_inventory" \
  > "$automata_scratch/runner-inventory-duplicate.json"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-duplicate.json" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer accepted a duplicate identity' >&2
  exit 1
fi

jq '.runners = .runners[0:2]' "$automata_inventory" \
  > "$automata_scratch/runner-inventory-incomplete-host.json"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-incomplete-host.json" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer accepted a host with only two runners' >&2
  exit 1
fi

jq '(.runners[] | select(.runner_slot == 3) | .runner_slot) = 2' \
  "$automata_inventory" \
  > "$automata_scratch/runner-inventory-duplicate-slot.json"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-duplicate-slot.json" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer accepted duplicate host runner slots' >&2
  exit 1
fi

jq '.runners[2].host = "other-host"' "$automata_inventory" \
  > "$automata_scratch/runner-inventory-split-host.json"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-split-host.json" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer accepted split host identity' >&2
  exit 1
fi

jq '(.runners[] | select(.instance == "runner-ci-01") | .instance) = "runner-inventory-other"' \
  "$automata_inventory" > "$automata_scratch/runner-inventory-mismatch.json"
deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-mismatch.json" \
  > "$automata_scratch/runner-inventory-mismatch.prom"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_rendered_agent" \
  "$automata_scratch/runner-inventory-mismatch.json" \
  "$automata_scratch/runner-inventory-mismatch.prom" \
  "$automata_scratch/unexpected-mismatch.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted an inconsistent inventory identity' >&2
  exit 1
fi

jq --argjson stale_generation "$((automata_inventory_generation - 301))" \
  '.generated_at_seconds = $stale_generation' \
  "$automata_inventory" > "$automata_scratch/runner-inventory-stale.json"
deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-stale.json" \
  > "$automata_scratch/runner-inventory-stale.prom"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_rendered_agent" \
  "$automata_scratch/runner-inventory-stale.json" \
  "$automata_scratch/runner-inventory-stale.prom" \
  "$automata_scratch/unexpected-stale.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted stale inventory evidence' >&2
  exit 1
fi

jq --argjson future_generation "$((automata_inventory_generation + 600))" \
  '.generated_at_seconds = $future_generation' \
  "$automata_inventory" > "$automata_scratch/runner-inventory-future.json"
deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-future.json" \
  > "$automata_scratch/runner-inventory-future.prom"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_rendered_agent" \
  "$automata_scratch/runner-inventory-future.json" \
  "$automata_scratch/runner-inventory-future.prom" \
  "$automata_scratch/unexpected-future.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted future inventory evidence' >&2
  exit 1
fi

sed '/          - 127[.]0[.]0[.]1:9464/a\          - 127.0.0.1:9470' \
  "$automata_rendered_agent" > "$automata_scratch/runner-agent-extra-target.yml"
run_promtool_scratch_config "$automata_scratch/runner-agent-extra-target.yml"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_scratch/runner-agent-extra-target.yml" \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-extra-target.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted an additional scrape target' >&2
  exit 1
fi

sed '/^remote_write:/i\    file_sd_configs:\
      - files:\
          - targets/extra-runners.json\
' "$automata_rendered_agent" > "$automata_scratch/runner-agent-extra-discovery.yml"
run_promtool_scratch_config "$automata_scratch/runner-agent-extra-discovery.yml"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_scratch/runner-agent-extra-discovery.yml" \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-extra-discovery.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted an additional discovery source' >&2
  exit 1
fi

sed '/^remote_write:/i\  - {job_name: flow-extra, static_configs: []}' \
  "$automata_rendered_agent" > "$automata_scratch/runner-agent-flow-job.yml"
run_promtool_scratch_config "$automata_scratch/runner-agent-flow-job.yml"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_scratch/runner-agent-flow-job.yml" \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-flow-job.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted a flow-style scrape job' >&2
  exit 1
fi

sed '$a\  - {url: "https://metrics2.company.net/api/v1/write"}' \
  "$automata_rendered_agent" > "$automata_scratch/runner-agent-flow-remote.yml"
run_promtool_scratch_config "$automata_scratch/runner-agent-flow-remote.yml"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_scratch/runner-agent-flow-remote.yml" \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-flow-remote.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted a flow-style remote-write target' >&2
  exit 1
fi

awk '
  !replaced && $0 == "        labels:" {
    print "        labels: {instance: runner-ci-01, host: runner-host-ci-01, runner_slot: \"1\", environment: staging, cluster: ci-cluster}"
    replaced = 1
    skip = 1
    next
  }
  skip && $0 == "      - targets:" {
    skip = 0
  }
  !skip { print }
' "$automata_rendered_agent" > "$automata_scratch/runner-agent-flow-labels.yml"
run_promtool_scratch_config "$automata_scratch/runner-agent-flow-labels.yml"
if AUTOMATA_PROMTOOL="$automata_promtool" \
  AUTOMATA_METRICS_CONTAINER_RUNTIME="$automata_container_runtime" \
  deploy/observability/inventory/validate-runner-deployment.sh \
  "$automata_scratch/runner-agent-flow-labels.yml" \
  "$automata_inventory" \
  "$automata_inventory_metrics" \
  "$automata_scratch/unexpected-flow-labels.prom" \
  > /dev/null 2>&1; then
  printf '%s\n' 'runner deployment validator accepted noncanonical identity placement' >&2
  exit 1
fi

ln -s "$automata_inventory" "$automata_scratch/runner-inventory-link.json"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-link.json" > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer followed a symlink' >&2
  exit 1
fi
mkfifo "$automata_scratch/runner-inventory.fifo"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory.fifo" > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer accepted a non-regular input' >&2
  exit 1
fi
truncate --size "$((1024 * 1024 + 1))" \
  "$automata_scratch/runner-inventory-oversized.json"
if deploy/observability/inventory/render-runner-inventory.sh \
  "$automata_scratch/runner-inventory-oversized.json" > /dev/null 2>&1; then
  printf '%s\n' 'runner inventory renderer accepted an oversized input' >&2
  exit 1
fi

run_promtool check config deploy/observability/prometheus.yml
run_promtool check config deploy/observability/runner-agent.yml
run_promtool check config deploy/observability/ci-prometheus.yml
run_promtool check rules \
  deploy/observability/rules/automata-ci-recording.yml \
  deploy/observability/rules/automata-ci-alerts.yml \
  deploy/observability/rules/metrics-contract.yml
run_promtool test rules deploy/observability/rules/tests/automata-ci.test.yml

readonly automata_dashboard_contract_rules="${automata_scratch#"$automata_repo_root/"}/dashboard-contract.json"
readonly automata_dashboard_expressions="${automata_scratch#"$automata_repo_root/"}/dashboard-expressions.promql"
jq --slurp '
  [
    .[]
    | ..
    | objects
    | select((.expr? | type) == "string" and (.expr | length) > 0)
    | .expr
    | gsub("\\$cluster"; ".*")
    | gsub("\\$environment"; ".*")
    | gsub("\\$instance"; ".*")
    | gsub("[\\r\\n\\t]+"; " ")
  ] as $expressions
  | if ($expressions | length) == 0 then
      error("dashboards contain no PromQL expressions")
    else
      {
        groups: [
          {
            name: "automata-ci-dashboard-contract",
            rules: (
              $expressions
              | to_entries
              | map({
                  record: "automata_ci_dashboard_contract_query_\(.key)",
                  expr: .value
                })
            )
          }
        ]
      }
    end
' deploy/observability/grafana/dashboards/*.json \
  > "$automata_dashboard_contract_rules"
jq --raw-output '.groups[0].rules[].expr' \
  "$automata_dashboard_contract_rules" > "$automata_dashboard_expressions"
run_promtool check rules /dev/stdin < "$automata_dashboard_contract_rules"

for automata_dashboard in deploy/observability/grafana/dashboards/*.json; do
  jq --exit-status \
    '(.uid | type == "string") and
     (.title | type == "string") and
     (.panels | type == "array") and
     (.panels | length > 0) and
     all(
       .. | objects | select(has("expr"));
       (.expr | type == "string" and length > 0)
     )' \
    "$automata_dashboard" >/dev/null
done

cargo run --quiet --locked -p automata-ci-metrics \
  --example metrics_fixture -- \
  --listen 127.0.0.1:19464 \
  >"$automata_scratch/fixture.log" 2>&1 &
automata_fixture_pid=$!

automata_fixture_ready='false'
for _ in {1..120}; do
  if curl --fail --silent \
    --header 'Accept: application/openmetrics-text; version=1.0.0; escaping=allow-utf-8' \
    --dump-header "$automata_scratch/headers" \
    --output "$automata_scratch/metrics.om" \
    http://127.0.0.1:19464/metrics; then
    automata_fixture_ready='true'
    break
  fi
  sleep 0.25
done

if [[ "$automata_fixture_ready" != 'true' ]]; then
  printf 'metrics fixture did not become ready\n' >&2
  sed -n '1,160p' "$automata_scratch/fixture.log" >&2
  exit 1
fi

automata_content_type="$(
  awk -F ': *' '
    tolower($1) == "content-type" {
      gsub("\\r", "", $2)
      print $2
    }
  ' "$automata_scratch/headers"
)"
if [[ "$automata_content_type" != 'application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8' ]]; then
  printf 'unexpected metrics content type: %s\n' "$automata_content_type" >&2
  exit 1
fi

if ! awk -F ': *' '
  tolower($1) == "cache-control" {
    gsub("\\r", "", $2)
    found = ($2 == "no-store")
  }
  END { exit !found }
' "$automata_scratch/headers"; then
  printf 'metrics response is missing Cache-Control: no-store\n' >&2
  exit 1
fi

if ! awk -F ': *' '
  tolower($1) == "x-content-type-options" {
    gsub("\\r", "", $2)
    found = ($2 == "nosniff")
  }
  END { exit !found }
' "$automata_scratch/headers"; then
  printf 'metrics response is missing X-Content-Type-Options: nosniff\n' >&2
  exit 1
fi

awk '
  {
    lines[NR] = $0
    if ($1 == "#" && $2 == "TYPE") {
      types[$3] = $4
    }
  }
  END {
    for (line_number = 1; line_number <= NR; line_number += 1) {
      line = lines[line_number]
      split(line, fields, " ")
      if (fields[1] == "#" && fields[2] == "UNIT") {
        continue
      }
      if (line == "# EOF") {
        continue
      }
      if (fields[1] == "#" && fields[2] == "HELP") {
        family = fields[3]
        lint_name = family
        if (types[family] == "counter") {
          lint_name = family "_total"
        } else if (types[family] == "info") {
          lint_name = family "_info"
        }
        sub("^# HELP " family " ", "# HELP " lint_name " ", line)
      } else if (fields[1] == "#" && fields[2] == "TYPE") {
        family = fields[3]
        if (fields[4] == "counter") {
          line = "# TYPE " family "_total counter"
        } else if (fields[4] == "info") {
          line = "# TYPE " family "_info gauge"
        }
      }
      print line
    }
  }
' "$automata_scratch/metrics.om" > "$automata_scratch/metrics.prometheus"
run_promtool check metrics --extended < "$automata_scratch/metrics.prometheus"

if [[ "$(tail -c 6 "$automata_scratch/metrics.om")" != '# EOF' ]]; then
  printf 'OpenMetrics fixture exposition does not end with # EOF and one newline\n' >&2
  exit 1
fi

if ! grep -Fq 'automata_ci_fixture_probe 1' "$automata_scratch/metrics.om"; then
  printf 'OpenMetrics fixture probe is absent\n' >&2
  exit 1
fi

if grep -Fq 'automata_ci_process_start_time_seconds' "$automata_scratch/metrics.om"; then
  printf 'standard process metric was incorrectly product-prefixed\n' >&2
  exit 1
fi

if [[ -n "$automata_container_runtime" ]]; then
  automata_prometheus_container="automata-metrics-contract-$$"
  "$automata_container_runtime" run --detach --rm \
    --name "$automata_prometheus_container" \
    --network host \
    --tmpfs /prometheus:rw,size=64m,mode=1777 \
    --volume "$automata_repo_root/deploy/observability:/etc/automata-observability:ro" \
    "$automata_prometheus_image" \
    --config.file=/etc/automata-observability/ci-prometheus.yml \
    --storage.tsdb.path=/prometheus \
    --storage.tsdb.retention.time=15m \
    --web.listen-address=127.0.0.1:19090 \
    --log.level=error >/dev/null

  automata_prometheus_ready='false'
  for _ in {1..120}; do
    if curl --fail --silent \
      http://127.0.0.1:19090/-/ready >/dev/null; then
      automata_prometheus_ready='true'
      break
    fi
    sleep 0.25
  done

  if [[ "$automata_prometheus_ready" != 'true' ]]; then
    printf 'real Prometheus did not become ready\n' >&2
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
    exit 1
  fi

  while IFS= read -r automata_dashboard_query; do
    automata_dashboard_ast="$(
      curl --fail --silent --show-error --get \
        --data-urlencode "query=$automata_dashboard_query" \
        http://127.0.0.1:19090/api/v1/parse_query
    )"
    if ! jq --exit-status '.status == "success"' \
      <<< "$automata_dashboard_ast" >/dev/null; then
      printf 'Prometheus rejected dashboard query: %s\n' \
        "$automata_dashboard_query" >&2
      exit 1
    fi
  done < "$automata_dashboard_expressions"

  automata_ingested='false'
  for _ in {1..40}; do
    if curl --fail --silent --show-error --get \
      --data-urlencode 'query=up{job="metrics-contract"}' \
      http://127.0.0.1:19090/api/v1/query \
      | jq --exit-status \
        '.status == "success" and any(.data.result[]; .value[1] == "1")' \
        >/dev/null; then
      automata_ingested='true'
      break
    fi
    sleep 0.25
  done

  if [[ "$automata_ingested" != 'true' ]]; then
    printf 'real Prometheus did not ingest a successful fixture scrape\n' >&2
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
    exit 1
  fi

  curl --fail --silent --show-error --get \
    --data-urlencode 'query=automata_ci_fixture_probe' \
    http://127.0.0.1:19090/api/v1/query \
    | jq --exit-status \
      '.status == "success" and any(.data.result[]; .value[1] == "1")' \
      >/dev/null

  automata_recording_rule_ready='false'
  for _ in {1..40}; do
    if curl --fail --silent --show-error --get \
      --data-urlencode 'query=automata_ci_metrics_contract_fixture_probe' \
      http://127.0.0.1:19090/api/v1/query \
      | jq --exit-status \
        '.status == "success" and any(.data.result[]; .value[1] == "1")' \
        >/dev/null; then
      automata_recording_rule_ready='true'
      break
    fi
    sleep 0.25
  done
  if [[ "$automata_recording_rule_ready" != 'true' ]]; then
    printf 'real Prometheus did not evaluate the fixture recording rule\n' >&2
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
    exit 1
  fi

  automata_counter_ready='false'
  for _ in {1..40}; do
    if curl --fail --silent --show-error --get \
      --data-urlencode 'query=automata_ci_metrics_scrapes_total{job="metrics-contract",outcome="success"} >= 2' \
      http://127.0.0.1:19090/api/v1/query \
      | jq --exit-status \
        '.status == "success" and (.data.result | length) > 0' \
        >/dev/null; then
      automata_counter_ready='true'
      break
    fi
    sleep 0.25
  done
  if [[ "$automata_counter_ready" != 'true' ]]; then
    printf 'real Prometheus did not ingest a pre-restart counter sequence\n' >&2
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
    exit 1
  fi

  kill "$automata_fixture_pid"
  wait "$automata_fixture_pid" >/dev/null 2>&1 || true
  automata_fixture_pid=''
  cargo run --quiet --locked -p automata-ci-metrics \
    --example metrics_fixture -- \
    --listen 127.0.0.1:19464 \
    >"$automata_scratch/fixture-restarted.log" 2>&1 &
  automata_fixture_pid=$!

  automata_fixture_restarted='false'
  for _ in {1..120}; do
    if curl --fail --silent \
      --header 'Accept: application/openmetrics-text; version=1.0.0; escaping=allow-utf-8' \
      http://127.0.0.1:19464/metrics >/dev/null; then
      automata_fixture_restarted='true'
      break
    fi
    sleep 0.25
  done
  if [[ "$automata_fixture_restarted" != 'true' ]]; then
    printf 'metrics fixture did not restart on its stable target\n' >&2
    sed -n '1,160p' "$automata_scratch/fixture-restarted.log" >&2
    exit 1
  fi

  automata_reset_observed='false'
  for _ in {1..40}; do
    if curl --fail --silent --show-error --get \
      --data-urlencode 'query=resets(automata_ci_metrics_scrapes_total{job="metrics-contract",outcome="success"}[5m]) >= 1' \
      http://127.0.0.1:19090/api/v1/query \
      | jq --exit-status \
        '.status == "success" and (.data.result | length) > 0' \
        >/dev/null; then
      automata_reset_observed='true'
      break
    fi
    sleep 0.25
  done
  if [[ "$automata_reset_observed" != 'true' ]]; then
    printf 'real Prometheus did not observe the fixture counter reset\n' >&2
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
    exit 1
  fi
fi

if [[ -n "${AUTOMATA_METRICS_EXPOSITION:-}" ]]; then
  run_promtool check metrics --extended < "$AUTOMATA_METRICS_EXPOSITION"

  if [[ "$(tail -c 6 "$AUTOMATA_METRICS_EXPOSITION")" != '# EOF' ]]; then
    printf 'OpenMetrics exposition does not end with # EOF and one newline\n' >&2
    exit 1
  fi
fi

printf 'Prometheus %s metrics configuration, rules, tests, and dashboards pass\n' \
  "$automata_prometheus_version"
