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

run_promtool_scratch_config_syntax_only() {
  local config_path="$1"
  local config_name

  if [[ "$config_path" != "$automata_scratch/"* ]]; then
    printf '%s\n' 'temporary Prometheus config escaped the metrics scratch directory' >&2
    return 1
  fi

  if [[ -n "$automata_promtool" ]]; then
    "$automata_promtool" check config --syntax-only "$config_path"
    return
  fi

  config_name="${config_path##*/}"
  "$automata_container_runtime" run --rm --interactive \
    --volume "$config_path:/$config_name:ro" \
    --workdir / \
    --entrypoint /bin/promtool \
    "$automata_prometheus_image" \
    check config --syntax-only "/$config_name"
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
    schema: 2,
    generated_at_seconds: $generated_at_seconds,
    runners: [
      {
        instance: "runner-ci-02",
        cluster: "ci-cluster",
        environment: "staging"
      },
      {
        instance: "runner-ci-01",
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
  'automata_ci_runner_inventory_expected{job="automata-runner",instance="runner-ci-01",cluster="ci-cluster",environment="staging"} 1' ]] ||
  [[ "$(sed -n '7p' "$automata_inventory_metrics")" != \
  'automata_ci_runner_inventory_expected{job="automata-runner",instance="runner-ci-02",cluster="ci-cluster",environment="staging"} 1' ]] ||
  [[ "$(wc -l < "$automata_inventory_metrics")" -ne 7 ]]; then
  printf '%s\n' 'runner inventory exposition is not exact and deterministic' >&2
  exit 1
fi

sed \
  -e 's/instance: replace-me-unique/instance: runner-ci-01/' \
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

if [[ "$(grep -Fxc "mv --no-target-directory -- \\" \
  deploy/observability/inventory/validate-runner-deployment.sh)" -ne 1 ]]; then
  printf '%s\n' \
    'runner inventory publication must use a no-target-directory atomic rename' >&2
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

jq '(.runners[] | select(.instance == "runner-ci-01") | .cluster) = "other-cluster"' \
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

sed '/          - 127[.]0[.]0[.]1:9464/a\          - 127.0.0.1:9465' \
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

sed '/        labels:/,+6c\        labels: {instance: runner-ci-01, environment: staging, cluster: ci-cluster}' \
  "$automata_rendered_agent" > "$automata_scratch/runner-agent-flow-labels.yml"
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

verify_canonical_prometheus_inventory_job() {
  local config_path="$1"

  if LC_ALL=C grep -q '[^ -~]' "$config_path"; then
    return 1
  fi
  if ! awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      advanced = "{}[]&*!?\"" sprintf("%c", 39) "#@`\\%><"
      for (index_ = 1; index_ <= length(advanced); index_ += 1) {
        if (index($0, substr(advanced, index_, 1)) != 0) {
          exit 1
        }
      }
      if ($0 ~ /^[[:space:]]*-[[:space:]]*$/ ||
          $0 ~ /^[[:space:]]*(---|\.\.\.)[[:space:]]*$/) {
        exit 1
      }
      if (index($0, "|") != 0 &&
          $0 != "        regex: automata_ci_runner_inventory_expected|automata_ci_runner_inventory_generation_timestamp_seconds|node_textfile_scrape_error") {
        exit 1
      }
    }
  ' "$config_path"; then
    return 1
  fi

  awk '
  /job_name/ { raw_job_keys += 1 }
  $1 == "-" && $2 == "job_name:" {
    total_jobs += 1
    current_job = "other"
  }
  $0 == "  - job_name: automata-control-plane" {
    control_jobs += 1
    current_job = "control-plane"
  }
  $0 == "  - job_name: automata-runner" {
    runner_jobs += 1
    current_job = "runner"
  }
  $0 == "  - job_name: automata-runner-inventory" {
    current_job = "inventory"
    inventory_job = 1
    jobs += 1
    inventory_lines += 1
    next
  }
  inventory_job && $0 ~ /^  - job_name:/ { inventory_job = 0 }
  inventory_job && $0 !~ /^[[:space:]]*#/ && $0 !~ /^[[:space:]]*$/ { inventory_lines += 1 }
  inventory_job && $0 == "    metrics_path: /metrics" { metrics_paths += 1 }
  inventory_job && $0 == "    scheme: http" { schemes += 1 }
  inventory_job && $0 == "    honor_labels: true" { honor_labels += 1 }
  inventory_job && $0 == "    scrape_protocols:" { protocol_blocks += 1 }
  inventory_job && $0 == "      - OpenMetricsText1.0.0" { openmetrics_protocols += 1 }
  inventory_job && $0 == "      - PrometheusText0.0.4" { prometheus_protocols += 1 }
  inventory_job && $0 == "    body_size_limit: 2MB" { body_limits += 1 }
  inventory_job && $0 == "    sample_limit: 10002" { sample_limits += 1 }
  current_job == "control-plane" && $1 == "sample_limit:" {
    control_raw_sample_limits += 1
  }
  current_job == "control-plane" && $0 == "    sample_limit: 5250" {
    control_sample_limits += 1
  }
  current_job == "runner" && $1 == "sample_limit:" {
    runner_raw_sample_limits += 1
  }
  current_job == "runner" && $0 == "    sample_limit: 1000" {
    runner_sample_limits += 1
  }
  inventory_job && $0 == "    target_limit: 1" { target_limits += 1 }
  inventory_job && $0 == "    label_limit: 24" { label_limits += 1 }
  inventory_job && $0 == "    label_name_length_limit: 128" { label_name_limits += 1 }
  inventory_job && $0 == "    label_value_length_limit: 256" { label_value_limits += 1 }
  inventory_job && $0 == "    metric_relabel_configs:" { metric_relabel_configs += 1 }
  inventory_job && $0 == "      - source_labels:" { source_label_blocks += 1 }
  inventory_job && $0 == "          - __name__" { name_sources += 1 }
  inventory_job && $0 == "        regex: automata_ci_runner_inventory_expected|automata_ci_runner_inventory_generation_timestamp_seconds|node_textfile_scrape_error" {
    keep_rules += 1
  }
  inventory_job && $0 == "        action: keep" { keep_actions += 1 }
  inventory_job && $0 == "    file_sd_configs:" { file_sd_configs += 1 }
  inventory_job && $0 == "      - files:" { file_blocks += 1 }
  inventory_job && $0 == "          - targets/inventory-exporter.json" { inventory_files += 1 }
  inventory_job && $0 == "        refresh_interval: 30s" { refresh_intervals += 1 }
  inventory_job && $1 == "static_configs:" { invalid = 1 }
  $0 == "    honor_labels: true" { global_honor_labels += 1 }
  $0 == "          - targets/inventory-exporter.json" { global_inventory_files += 1 }
  $0 == "        regex: automata_ci_runner_inventory_expected|automata_ci_runner_inventory_generation_timestamp_seconds|node_textfile_scrape_error" {
    global_inventory_keep_rules += 1
  }
  END {
    valid = raw_job_keys == 3 && total_jobs == 3 && control_jobs == 1 && runner_jobs == 1 && jobs == 1 && control_raw_sample_limits == 1 && control_sample_limits == 1 && runner_raw_sample_limits == 1 && runner_sample_limits == 1 && inventory_lines == 22 && metrics_paths == 1 && schemes == 1 && honor_labels == 1 && protocol_blocks == 1 && openmetrics_protocols == 1 && prometheus_protocols == 1 && body_limits == 1 && sample_limits == 1 && target_limits == 1 && label_limits == 1 && label_name_limits == 1 && label_value_limits == 1 && metric_relabel_configs == 1 && source_label_blocks == 1 && name_sources == 1 && keep_rules == 1 && keep_actions == 1 && file_sd_configs == 1 && file_blocks == 1 && inventory_files == 1 && refresh_intervals == 1 && global_honor_labels == 1 && global_inventory_files == 1 && global_inventory_keep_rules == 1 && invalid == 0
    exit !valid
  }
' "$config_path"
}

if ! verify_canonical_prometheus_inventory_job \
  deploy/observability/prometheus.yml; then
  printf '%s\n' \
    'independent inventory scrape topology or exact three-family keep rule drifted' >&2
  exit 1
fi

sed '/^  - job_name: automata-control-plane/i\  - !!map\
    ? "job\\u005fname"\
    : automata-runner-inventory-shadow\
    honor_labels: true\
    static_configs:\
      - targets:\
          - 127.0.0.1:9100\
' deploy/observability/prometheus.yml \
  > "$automata_scratch/prometheus-tagged-job.yml"
run_promtool_scratch_config_syntax_only \
  "$automata_scratch/prometheus-tagged-job.yml"
if verify_canonical_prometheus_inventory_job \
  "$automata_scratch/prometheus-tagged-job.yml"; then
  printf '%s\n' \
    'central Prometheus policy accepted a tagged or escaped scrape job' >&2
  exit 1
fi

sed '/^  - job_name: automata-control-plane/i\  -\
    job_name: automata-runner-inventory-shadow\
    honor_labels: true\
    static_configs:\
      - targets:\
          - 127.0.0.1:9100\
' deploy/observability/prometheus.yml \
  > "$automata_scratch/prometheus-bare-sequence-job.yml"
run_promtool_scratch_config_syntax_only \
  "$automata_scratch/prometheus-bare-sequence-job.yml"
if verify_canonical_prometheus_inventory_job \
  "$automata_scratch/prometheus-bare-sequence-job.yml"; then
  printf '%s\n' \
    'central Prometheus policy accepted a noncanonical scrape-job sequence' >&2
  exit 1
fi

awk '
  $0 == "  - job_name: automata-control-plane" {
    print "  - job_name: automata-runner-inventory-shadow"
    shadow = 1
    next
  }
  shadow && $0 == "    scheme: http" {
    print
    print "    honor_labels: true"
    next
  }
  shadow && $0 == "          - targets/control-plane.json" {
    print "          - targets/inventory-exporter.json"
    next
  }
  $0 == "  - job_name: automata-runner" { shadow = 0 }
  { print }
' deploy/observability/prometheus.yml \
  > "$automata_scratch/prometheus-duplicate-inventory-job.yml"
run_promtool_scratch_config_syntax_only \
  "$automata_scratch/prometheus-duplicate-inventory-job.yml"
if verify_canonical_prometheus_inventory_job \
  "$automata_scratch/prometheus-duplicate-inventory-job.yml"; then
  printf '%s\n' \
    'central Prometheus policy accepted a substituted inventory scrape job' >&2
  exit 1
fi

if [[ "$(grep -Fxc -- \
  '  # with --collector.disable-defaults --collector.textfile and an inventory-only' \
  deploy/observability/prometheus.yml)" -ne 1 ]] ||
  ! grep -Fq -- \
    "\`--collector.disable-defaults --collector.textfile\` and an inventory-only" \
    deploy/observability/README.md; then
  printf '%s\n' \
    'inventory exporter dedicated textfile-only launch contract drifted' >&2
  exit 1
fi

readonly automata_production_alerts="$automata_scratch/production-alerts.txt"
readonly automata_positive_alert_tests="$automata_scratch/positive-alert-tests.txt"
awk '
  BEGIN { prefix = "      - alert: " }
  index($0, prefix) == 1 {
    alert = substr($0, length(prefix) + 1)
    if (alert !~ /^Automata[A-Za-z0-9]+$/) {
      printf "invalid production alert name: %s\n", alert > "/dev/stderr"
      exit 1
    }
    if (seen[alert]++) {
      printf "duplicate production alert name: %s\n", alert > "/dev/stderr"
      exit 1
    }
    print alert
    count += 1
  }
  END {
    if (count == 0) {
      print "production alert file contains no alerts" > "/dev/stderr"
      exit 1
    }
  }
' deploy/observability/rules/automata-ci-alerts.yml \
  | sort > "$automata_production_alerts"
awk '
  BEGIN {
    alert_prefix = "        alertname: "
    alerts_prefix = "        exp_alerts:"
    list_item_prefix = "          - "
  }
  index($0, alert_prefix) == 1 {
    alert = substr($0, length(alert_prefix) + 1)
    next
  }
  $0 == alerts_prefix {
    if (alert == "") {
      print "exp_alerts block has no alertname" > "/dev/stderr"
      exit 1
    }
    in_expected_alerts = 1
    next
  }
  $0 == alerts_prefix " []" {
    alert = ""
    in_expected_alerts = 0
    next
  }
  index($0, alerts_prefix " ") == 1 {
    print "exp_alerts must use canonical block form or []" > "/dev/stderr"
    exit 1
  }
  in_expected_alerts && index($0, list_item_prefix) == 1 {
    print alert
    alert = ""
    in_expected_alerts = 0
    next
  }
  in_expected_alerts && index($0, "          ") != 1 {
    alert = ""
    in_expected_alerts = 0
  }
' deploy/observability/rules/tests/automata-ci.test.yml \
  | sort -u > "$automata_positive_alert_tests"

if ! cmp -s "$automata_production_alerts" "$automata_positive_alert_tests"; then
  comm -23 "$automata_production_alerts" "$automata_positive_alert_tests" \
    | sed 's/^/production alert lacks a positive promtool case: /' >&2
  comm -13 "$automata_production_alerts" "$automata_positive_alert_tests" \
    | sed 's/^/positive promtool case names no production alert: /' >&2
  exit 1
fi
automata_production_alert_count="$(wc -l < "$automata_production_alerts")"
readonly automata_production_alert_count
printf 'verified positive promtool coverage for %s production alerts\n' \
  "$automata_production_alert_count"

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

if ! jq --exit-status '
  def refs_for($title; $family):
    [
      .panels[]
      | select(.title == $title)
      | .targets[]
      | select(.expr | contains($family))
      | .refId
    ];
  def families_have_distinct_targets($title; $families):
    . as $dashboard
    | [
        $families[] as $family
        | ($dashboard | refs_for($title; $family))
      ] as $refs
    | all($refs[]; length == 1)
      and (($refs | map(.[0]) | unique | length) == ($families | length));
  families_have_distinct_targets(
    "Spool capacity utilization";
    [
      "automata_ci_runner_spool_protected_bytes",
      "automata_ci_runner_spool_objects"
    ]
  )
  and families_have_distinct_targets(
    "Durable bytes";
    [
      "automata_ci_runner_spool_protected_bytes",
      "automata_ci_runner_spool_max_bytes",
      "automata_ci_runner_pending_log_bytes",
      "automata_ci_runner_journal_size_bytes",
      "automata_ci_runner_journal_max_bytes"
    ]
  )
  and families_have_distinct_targets(
    "Pending durable work";
    [
      "automata_ci_runner_pending_deliveries",
      "automata_ci_runner_pending_log_frames",
      "automata_ci_runner_orphan_slots"
    ]
  )
  and families_have_distinct_targets(
    "Durability guards";
    [
      "automata_ci_runner_snapshot_refresh_healthy",
      "automata_ci_runner_slot_snapshot_conserved",
      "automata_ci_runner_slots_over_capacity",
      "automata_ci_runner_journal_poisoned",
      "automata_ci_runner_spool_poisoned"
    ]
  )
  and families_have_distinct_targets(
    "Aggregate sandbox CPU rates";
    [
      "automata_ci_runner_cgroup_cpu_usage_seconds_total",
      "automata_ci_runner_cgroup_cpu_throttled_seconds_total"
    ]
  )
  and families_have_distinct_targets(
    "Aggregate sandbox memory";
    [
      "automata_ci_runner_cgroup_memory_current_bytes",
      "automata_ci_runner_cgroup_memory_peak_bytes"
    ]
  )
' deploy/observability/grafana/dashboards/automata-runner.json >/dev/null; then
  printf '%s\n' \
    'runner dashboard recombined metric families with colliding label sets' >&2
  exit 1
fi

jq --exit-status '
  def positive_integer:
    type == "number" and . > 0 and floor == .;
  def unique_nonempty_strings:
    type == "array"
    and length > 0
    and all(.[]; type == "string" and length > 0)
    and length == (unique | length);
  def valid_label:
    (.name | type == "string" and test("^[a-zA-Z_][a-zA-Z0-9_]*$"))
    and (
      .name as $name
      | [
          "backend", "cause", "conclusion", "dependency", "desired_state",
          "direction", "disposition", "domain", "event", "exchange", "kind",
          "lifecycle", "method", "mode", "observed_state", "operation",
          "outcome", "reason", "resource", "revision", "role", "route",
          "service", "stage", "state", "status", "status_class", "version"
        ]
      | index($name) != null
    )
    and (
      (
        has("values")
        and (has("validator") | not)
        and (.values | unique_nonempty_strings)
      )
      or (
        has("validator")
        and (has("values") | not)
        and (
          .validator == "build_version"
          or .validator == "build_revision"
          or .validator == "process_role"
        )
      )
    );
  def valid_tuple($labels):
    . as $tuple
    | type == "array"
      and length == ($labels | length)
      and all(
        range(0; length);
        . as $index
        | ($labels[$index].values | index($tuple[$index])) != null
      );
  def valid_label_sets:
    . as $family
    | ($family.label_sets | type == "object")
      and if $family.label_sets.mode == "cartesian" then
        ($family.label_sets | keys == ["mode"])
        and all($family.labels[]; has("values"))
      elif $family.label_sets.mode == "explicit" then
        ($family.label_sets | keys == ["mode", "tuples"])
        and all($family.labels[]; has("values"))
        and ($family.label_sets.tuples | type == "array" and length > 0)
        and all($family.label_sets.tuples[]; valid_tuple($family.labels))
        and (($family.label_sets.tuples | length)
          == ($family.label_sets.tuples | unique | length))
      elif $family.label_sets.mode == "dynamic_singleton" then
        ($family.label_sets | keys == ["mode"])
        and all($family.labels[]; has("validator"))
      else
        false
      end;
  def label_set_count:
    if .label_sets.mode == "cartesian" then
      reduce .labels[] as $label (1; . * ($label.values | length))
    elif .label_sets.mode == "explicit" then
      .label_sets.tuples | length
    elif .label_sets.mode == "dynamic_singleton" then
      1
    else
      0
    end;
  def valid_buckets:
    if .type == "histogram" then
      (.buckets | unique_nonempty_strings)
      and (
        ([.buckets[] | try tonumber catch null]) as $values
        | all($values[]; type == "number")
          and all(range(1; $values | length); $values[. - 1] < $values[.])
      )
    else
      has("buckets") | not
    end;
  def series_per_label_set:
    if .type == "histogram" then (.buckets | length) + 3 else 1 end;
  def native_label_sets:
    [
      .families[]
      | select(.type == "histogram")
      | .maximum_series / ((.buckets | length) + 3)
    ]
    | add;
  (.schema_version == 2)
  and ((.profiles | keys | sort) == ["common", "control_plane", "runner"])
  and (.profiles.common | has("series_budget") | not)
  and (.profiles.control_plane.series_budget | positive_integer)
  and (.profiles.runner.series_budget | positive_integer)
  and all(
    .profiles[];
    (.families | type == "array" and length > 0)
  )
  and all(
    .profiles[].families[];
    (.name | type == "string"
      and test("^[a-zA-Z_:][a-zA-Z0-9_:]*$"))
    and (.type == "counter"
      or .type == "gauge"
      or .type == "histogram"
      or .type == "info")
    and ((has("unit") | not) or .unit == "seconds" or .unit == "bytes")
    and (.labels | type == "array")
    and all(.labels[]; valid_label)
    and ((.labels | map(.name) | length) == (.labels | map(.name) | unique | length))
    and valid_label_sets
    and valid_buckets
    and (.maximum_series | positive_integer)
    and (.maximum_series == (label_set_count * series_per_label_set))
  )
  and (
    [.profiles[].families[].name] as $names
    | ($names | length) == ($names | unique | length)
  )
  and (
  .profiles as $profiles
  | ($profiles.control_plane.series_budget == 5250)
    and ($profiles.runner.series_budget == 1000)
    and (($profiles.common.families | map(.maximum_series) | add) == 49)
    and (($profiles.control_plane.families | map(.maximum_series) | add) == 4975)
    and (($profiles.runner.families | map(.maximum_series) | add) == 890)
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.control_plane.families | map(.maximum_series) | add))
      == 5024
    )
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.runner.families | map(.maximum_series) | add))
      == 939
    )
    and (($profiles.common | native_label_sets) == 2)
    and (($profiles.control_plane | native_label_sets) == 143)
    and (($profiles.runner | native_label_sets) == 28)
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.control_plane.families | map(.maximum_series) | add)
       + ($profiles.common | native_label_sets)
       + ($profiles.control_plane | native_label_sets))
      == 5169
    )
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.runner.families | map(.maximum_series) | add)
       + ($profiles.common | native_label_sets)
       + ($profiles.runner | native_label_sets))
      == 969
    )
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.control_plane.families | map(.maximum_series) | add)
       + ($profiles.common | native_label_sets)
       + ($profiles.control_plane | native_label_sets))
      <= $profiles.control_plane.series_budget
    )
    and (
      $profiles.control_plane.series_budget
      - (($profiles.common.families | map(.maximum_series) | add)
         + ($profiles.control_plane.families | map(.maximum_series) | add)
         + ($profiles.common | native_label_sets)
         + ($profiles.control_plane | native_label_sets))
      == 81
    )
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.runner.families | map(.maximum_series) | add)
       + ($profiles.common | native_label_sets)
       + ($profiles.runner | native_label_sets))
      <= $profiles.runner.series_budget
    )
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.control_plane.families | map(.maximum_series) | add))
      <= $profiles.control_plane.series_budget
    )
    and (
      (($profiles.common.families | map(.maximum_series) | add)
       + ($profiles.runner.families | map(.maximum_series) | add))
      <= $profiles.runner.series_budget
    )
  )
' deploy/observability/cardinality.json >/dev/null

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

jq --raw-output '
  .profiles.common.families[]
  | "\(.name)|\(.type)|\(.maximum_series)"
' deploy/observability/cardinality.json \
  | sort > "$automata_scratch/manifest-common"

awk '
  $1 == "#" && $2 == "TYPE" {
    descriptor = $3
    metric_type = $4
    family = descriptor
    if (metric_type == "counter") {
      family = descriptor "_total"
    } else if (metric_type == "info") {
      family = descriptor "_info"
    }
    types[family] = metric_type
    next
  }
  $1 != "#" && NF > 0 && family != "automata_ci_fixture_probe" {
    counts[family] += 1
  }
  END {
    for (name in counts) {
      print name "|" types[name] "|" counts[name]
    }
  }
' "$automata_scratch/metrics.om" | sort > "$automata_scratch/exposition-common"

if ! diff --unified \
  "$automata_scratch/manifest-common" \
  "$automata_scratch/exposition-common"; then
  printf 'common exporter families/types/series differ from cardinality.json\n' >&2
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

  automata_dashboard_allowed_metrics="$automata_scratch/dashboard-allowed-metrics"
  automata_dashboard_referenced_metrics="$automata_scratch/dashboard-referenced-metrics"
  {
    jq --raw-output '
      .profiles[].families[]
      | if .type == "histogram" then
          .name + "_bucket", .name + "_sum", .name + "_count"
        else
          .name
        end
    ' deploy/observability/cardinality.json
    awk '$1 == "-" && $2 == "record:" { print $3 }' \
      deploy/observability/rules/automata-ci-recording.yml
    printf '%s\n' \
      ALERTS \
      automata_ci_runner_inventory_expected \
      scrape_samples_post_metric_relabeling \
      up
  } | sort --unique > "$automata_dashboard_allowed_metrics"

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
    jq --raw-output '
      ..
      | objects
      | select(
          (.type? == "vectorSelector" or .type? == "matrixSelector")
          and (.name? | type == "string")
        )
      | .name
    ' <<< "$automata_dashboard_ast"
  done < "$automata_dashboard_expressions" \
    | sort --unique > "$automata_dashboard_referenced_metrics"

  if ! comm -23 \
    "$automata_dashboard_referenced_metrics" \
    "$automata_dashboard_allowed_metrics" \
    > "$automata_scratch/dashboard-unknown-metrics"; then
    printf 'failed to compare dashboard metric references\n' >&2
    exit 1
  fi
  if [[ -s "$automata_scratch/dashboard-unknown-metrics" ]]; then
    printf 'dashboards reference metrics outside the canonical contract:\n' >&2
    sed -n '1,160p' "$automata_scratch/dashboard-unknown-metrics" >&2
    exit 1
  fi

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
