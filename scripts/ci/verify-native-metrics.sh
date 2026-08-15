#!/usr/bin/env bash
set -euo pipefail

readonly automata_prometheus_image='quay.io/prometheus/prometheus@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7'
readonly automata_prometheus_version='3.13.0'
readonly automata_fixture_address='127.0.0.1:19465'
readonly automata_prometheus_address='127.0.0.1:19091'

automata_repo_root="$(git rev-parse --show-toplevel)"
readonly automata_repo_root
cd "$automata_repo_root"
# shellcheck source=scripts/ci/lib/target-paths.sh
source "$automata_repo_root/scripts/ci/lib/target-paths.sh"

automata_init_target_root "$automata_repo_root"
automata_set_target_tmpdir \
  "$automata_repo_root" \
  "$automata_repo_root/target/task-tmp/native-metrics-contract"

automata_container_runtime="${AUTOMATA_METRICS_CONTAINER_RUNTIME:-}"
automata_promtool="${AUTOMATA_PROMTOOL:-}"
automata_prometheus="${AUTOMATA_PROMETHEUS:-}"
if [[ -z "$automata_promtool" ]] && command -v promtool >/dev/null 2>&1; then
  automata_promtool="$(command -v promtool)"
fi
if [[ -z "$automata_prometheus" ]] && command -v prometheus >/dev/null 2>&1; then
  automata_prometheus="$(command -v prometheus)"
fi
automata_native_runtime='false'
if [[ -z "$automata_container_runtime" ]]; then
  if [[ -n "$automata_promtool" && -n "$automata_prometheus" ]]; then
    automata_native_runtime='true'
  elif command -v podman >/dev/null 2>&1; then
    automata_container_runtime='podman'
  elif command -v docker >/dev/null 2>&1; then
    automata_container_runtime='docker'
  else
    printf '%s\n' 'podman or docker is required for the native-metrics contract' >&2
    exit 1
  fi
fi
if [[ "$automata_native_runtime" == true ]]; then
  [[ -x "$automata_promtool" && -x "$automata_prometheus" ]] || {
    printf '%s\n' 'AUTOMATA_PROMTOOL and AUTOMATA_PROMETHEUS must name executable files' >&2
    exit 1
  }
else
  case "$automata_container_runtime" in
    docker | podman)
      if ! command -v "$automata_container_runtime" >/dev/null 2>&1; then
        printf 'configured container runtime is unavailable: %s\n' \
          "$automata_container_runtime" >&2
        exit 1
      fi
      ;;
    *)
      printf '%s\n' 'AUTOMATA_METRICS_CONTAINER_RUNTIME must be docker or podman' >&2
      exit 1
      ;;
  esac
fi

automata_scratch="$(mktemp -d "$TMPDIR/automata-native-metrics.XXXXXXXX")"
readonly automata_scratch
chmod 0755 "$automata_scratch"
automata_fixture_pid=''
automata_prometheus_pid=''
automata_prometheus_container="automata-native-metrics-contract-$$"
readonly automata_prometheus_container

cleanup_native_metrics_contract() {
  if [[ -n "$automata_prometheus_pid" ]]; then
    kill "$automata_prometheus_pid" >/dev/null 2>&1 || true
    wait "$automata_prometheus_pid" >/dev/null 2>&1 || true
  elif [[ -n "$automata_container_runtime" ]]; then
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
trap cleanup_native_metrics_contract EXIT

cat > "$automata_scratch/prometheus.yml" <<'EOF'
global:
  scrape_interval: 1s
  scrape_timeout: 500ms

scrape_configs:
  - job_name: native-metrics-contract
    metrics_path: /metrics
    scheme: http
    scrape_protocols:
      - PrometheusProto
      - OpenMetricsText1.0.0
    scrape_native_histograms: true
    always_scrape_classic_histograms: true
    native_histogram_bucket_limit: 160
    native_histogram_min_bucket_factor: 1.09
    body_size_limit: 2MB
    sample_limit: 1000
    label_limit: 24
    label_name_length_limit: 128
    label_value_length_limit: 256
    static_configs:
      - targets:
          - 127.0.0.1:19465
EOF
chmod 0644 "$automata_scratch/prometheus.yml"

if [[ "$automata_native_runtime" == true ]]; then
  "$automata_promtool" check config "$automata_scratch/prometheus.yml" >/dev/null
else
  "$automata_container_runtime" run --rm \
    --volume "$automata_scratch:/contract:ro" \
    --entrypoint /bin/promtool \
    "$automata_prometheus_image" \
    check config /contract/prometheus.yml >/dev/null
fi

cargo run --quiet --locked -p automata-ci-metrics \
  --example metrics_fixture -- \
  --listen "$automata_fixture_address" \
  --native-probe \
  >"$automata_scratch/fixture.log" 2>&1 &
automata_fixture_pid=$!

automata_fixture_ready='false'
for _ in {1..120}; do
  if curl --fail --silent \
    --header 'Accept: application/openmetrics-text;version=1.0.0' \
    "http://$automata_fixture_address/metrics" >/dev/null; then
    automata_fixture_ready='true'
    break
  fi
  sleep 0.25
done
if [[ "$automata_fixture_ready" != 'true' ]]; then
  printf '%s\n' 'native metrics fixture did not become ready' >&2
  sed -n '1,160p' "$automata_scratch/fixture.log" >&2
  exit 1
fi

readonly automata_protobuf_accept='application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited'
curl --fail --silent --show-error \
  --header "Accept: $automata_protobuf_accept" \
  --dump-header "$automata_scratch/protobuf.headers" \
  --output "$automata_scratch/metrics.pb" \
  "http://$automata_fixture_address/metrics"
automata_protobuf_content_type="$(
  awk -F ': *' '
    tolower($1) == "content-type" {
      gsub("\\r", "", $2)
      print $2
    }
  ' "$automata_scratch/protobuf.headers"
)"
readonly automata_protobuf_content_type
if [[ "$automata_protobuf_content_type" != \
  'application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited' ]]; then
  printf 'unexpected protobuf content type: %s\n' \
    "$automata_protobuf_content_type" >&2
  exit 1
fi
if [[ ! -s "$automata_scratch/metrics.pb" ]]; then
  printf '%s\n' 'Prometheus protobuf response is empty' >&2
  exit 1
fi

curl --fail --silent --show-error \
  --header 'Accept: application/openmetrics-text;version=1.0.0' \
  --output "$automata_scratch/metrics.om" \
  "http://$automata_fixture_address/metrics"
if [[ "$(tail -c 6 "$automata_scratch/metrics.om")" != '# EOF' ]]; then
  printf '%s\n' 'OpenMetrics fallback is incomplete' >&2
  exit 1
fi
if ! grep -Fq 'automata_ci_fixture_native_probe_bucket' \
  "$automata_scratch/metrics.om"; then
  printf '%s\n' 'OpenMetrics fallback lacks classic histogram buckets' >&2
  exit 1
fi

if [[ "$automata_native_runtime" == true ]]; then
  install -d -m 0700 -- "$automata_scratch/prometheus-data"
  "$automata_prometheus" \
    --config.file="$automata_scratch/prometheus.yml" \
    --storage.tsdb.path="$automata_scratch/prometheus-data" \
    --storage.tsdb.retention.time=15m \
    --web.listen-address="$automata_prometheus_address" \
    --log.level=error \
    >"$automata_scratch/prometheus.log" 2>&1 &
  automata_prometheus_pid=$!
else
  "$automata_container_runtime" run --detach --rm \
    --name "$automata_prometheus_container" \
    --network host \
    --tmpfs /prometheus:rw,size=64m,mode=1777 \
    --volume "$automata_scratch:/contract:ro" \
    "$automata_prometheus_image" \
    --config.file=/contract/prometheus.yml \
    --storage.tsdb.path=/prometheus \
    --storage.tsdb.retention.time=15m \
    --web.listen-address="$automata_prometheus_address" \
    --log.level=error >/dev/null
fi

automata_prometheus_ready='false'
for _ in {1..120}; do
  if curl --fail --silent \
    "http://$automata_prometheus_address/-/ready" >/dev/null; then
    automata_prometheus_ready='true'
    break
  fi
  sleep 0.25
done
if [[ "$automata_prometheus_ready" != 'true' ]]; then
  printf '%s\n' 'real Prometheus did not become ready' >&2
  if [[ "$automata_native_runtime" == true ]]; then
    sed -n '1,160p' "$automata_scratch/prometheus.log" >&2
  else
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
  fi
  exit 1
fi

automata_native_ingested='false'
for _ in {1..80}; do
  if curl --fail --silent --show-error --get \
    --data-urlencode 'query=automata_ci_fixture_native_probe{job="native-metrics-contract"}' \
    "http://$automata_prometheus_address/api/v1/query" \
    | jq --exit-status '
        .status == "success"
        and any(
          .data.result[];
          (.histogram | type) == "array"
          and .histogram[1].count == "3"
          and (.histogram[1].buckets | length) >= 3
        )
      ' >/dev/null; then
    automata_native_ingested='true'
    break
  fi
  sleep 0.25
done
if [[ "$automata_native_ingested" != 'true' ]]; then
  printf '%s\n' 'Prometheus did not ingest the native histogram sample' >&2
  if [[ "$automata_native_runtime" == true ]]; then
    sed -n '1,160p' "$automata_scratch/prometheus.log" >&2
  else
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
  fi
  exit 1
fi

automata_classic_ingested='false'
for _ in {1..80}; do
  if curl --fail --silent --show-error --get \
    --data-urlencode 'query=automata_ci_fixture_native_probe_bucket{job="native-metrics-contract",le="+Inf"}' \
    "http://$automata_prometheus_address/api/v1/query" \
    | jq --exit-status '
        .status == "success"
        and any(.data.result[]; .value[1] == "3")
      ' >/dev/null; then
    automata_classic_ingested='true'
    break
  fi
  sleep 0.25
done
if [[ "$automata_classic_ingested" != 'true' ]]; then
  printf '%s\n' 'Prometheus did not ingest the parallel classic histogram buckets' >&2
  if [[ "$automata_native_runtime" == true ]]; then
    sed -n '1,160p' "$automata_scratch/prometheus.log" >&2
  else
    "$automata_container_runtime" logs "$automata_prometheus_container" >&2 || true
  fi
  exit 1
fi

printf 'Prometheus %s negotiated protobuf, ingested native and parallel classic buckets, and retained the OpenMetrics fallback\n' \
  "$automata_prometheus_version"
