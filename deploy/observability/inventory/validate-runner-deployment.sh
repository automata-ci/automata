#!/usr/bin/env bash
set -euo pipefail

readonly maximum_agent_bytes=$((256 * 1024))
readonly maximum_inventory_bytes=$((1024 * 1024))
readonly maximum_inventory_metrics_bytes=$((2 * 1024 * 1024))
readonly maximum_inventory_age_seconds=300
readonly maximum_inventory_future_skew_seconds=60
readonly prometheus_image='quay.io/prometheus/prometheus@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7'

if [[ $# -ne 4 ]]; then
  printf 'usage: %s RENDERED_AGENT.yml INVENTORY.json STAGED.prom PUBLISHED.prom\n' \
    "${0##*/}" >&2
  exit 2
fi

readonly agent_path="$1"
readonly inventory_path="$2"
readonly staged_metrics_path="$3"
readonly publication_path="$4"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
readonly canonical_agent_template="$script_directory/../runner-agent.yml"

agent_snapshot=''
inventory_snapshot=''
metrics_snapshot=''
expected_metrics=''
normalized_agent=''
publication_temporary=''

cleanup_deployment_validation() {
  local snapshot
  for snapshot in \
    "$agent_snapshot" \
    "$inventory_snapshot" \
    "$metrics_snapshot" \
    "$expected_metrics" \
    "$normalized_agent"; do
    if [[ -n "$snapshot" ]]; then
      rm -f -- "$snapshot"
    fi
  done
  if [[ -n "$publication_temporary" ]] && [[ -f "$publication_temporary" ]]; then
    rm -f -- "$publication_temporary"
  fi
}

trap cleanup_deployment_validation EXIT

require_private_temporary_parent() {
  local canonical_parent

  if [[ -z ${TMPDIR:-} ]] || [[ "$TMPDIR" != /* ]]; then
    printf '%s\n' 'TMPDIR must name an explicit absolute private directory' >&2
    return 1
  fi
  temporary_parent="${TMPDIR%/}"
  [[ -n "$temporary_parent" ]] || temporary_parent=/
  if [[ -L "$temporary_parent" ]] || [[ ! -d "$temporary_parent" ]] ||
    ! canonical_parent="$(realpath -e -- "$temporary_parent")" ||
    [[ "$canonical_parent" != "$temporary_parent" ]] ||
    [[ "$(stat -c '%u' -- "$temporary_parent")" != "$(id -u)" ]] ||
    [[ "$(stat -c '%a' -- "$temporary_parent")" != 700 ]] ||
    [[ ! -w "$temporary_parent" ]] || [[ ! -x "$temporary_parent" ]]; then
    printf '%s\n' 'TMPDIR must be an owner-only, non-symlink, writable directory' >&2
    return 1
  fi
}

temporary_parent=''
require_private_temporary_parent
readonly temporary_parent
agent_snapshot="$(mktemp "$temporary_parent/automata-runner-agent.XXXXXXXX")"
inventory_snapshot="$(mktemp "$temporary_parent/automata-runner-inventory.XXXXXXXX")"
metrics_snapshot="$(mktemp "$temporary_parent/automata-runner-inventory-metrics.XXXXXXXX")"
expected_metrics="$(mktemp "$temporary_parent/automata-runner-expected-metrics.XXXXXXXX")"
normalized_agent="$(mktemp "$temporary_parent/automata-runner-normalized-agent.XXXXXXXX")"
readonly agent_snapshot inventory_snapshot metrics_snapshot expected_metrics normalized_agent

snapshot_file() {
  local source_path="$1"
  local maximum_bytes="$2"
  local destination_path="$3"

  "$script_directory/bounded-file-snapshot.py" \
    "$source_path" "$maximum_bytes" > "$destination_path"
}

if ! snapshot_file "$agent_path" "$maximum_agent_bytes" "$agent_snapshot"; then
  printf '%s\n' 'runner Agent configuration could not be snapshotted safely' >&2
  exit 1
fi
if ! snapshot_file "$inventory_path" "$maximum_inventory_bytes" "$inventory_snapshot"; then
  printf '%s\n' 'runner inventory could not be snapshotted safely' >&2
  exit 1
fi
if ! snapshot_file \
  "$staged_metrics_path" "$maximum_inventory_metrics_bytes" "$metrics_snapshot"; then
  printf '%s\n' 'staged runner inventory metrics could not be snapshotted safely' >&2
  exit 1
fi

if ! "$script_directory/render-runner-inventory.sh" \
  "$inventory_snapshot" > "$expected_metrics"; then
  exit 1
fi
if ! cmp --silent "$expected_metrics" "$metrics_snapshot"; then
  printf '%s\n' 'staged metrics do not match the exact runner inventory revision' >&2
  exit 1
fi

awk '
  /^          instance: [^[:space:]]+$/ {
    print "          instance: replace-me-unique"
    next
  }
  /^          environment: [^[:space:]]+$/ {
    print "          environment: replace-me"
    next
  }
  /^          cluster: [^[:space:]]+$/ {
    print "          cluster: replace-me"
    next
  }
  /^  - url: https:\/\/[^[:space:]]+$/ {
    print "  - url: https://prometheus.example.invalid/api/v1/write"
    next
  }
  { print }
' "$agent_snapshot" > "$normalized_agent"
if ! cmp --silent "$canonical_agent_template" "$normalized_agent"; then
  printf '%s\n' \
    'runner Agent must be an exact canonical template with only identity and remote URL substituted' >&2
  exit 1
fi

extract_single_value() {
  local key="$1"
  local value
  mapfile -t values < <(
    awk -v key="$key" '$1 == key ":" { print $2 }' "$agent_snapshot"
  )
  if [[ ${#values[@]} -ne 1 ]]; then
    printf 'runner Agent must contain exactly one canonical %s label\n' "$key" >&2
    return 1
  fi
  value="${values[0]}"
  if [[ ! "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] ||
    [[ "$value" == replace-me ]] || [[ "$value" == replace-me-unique ]] ||
    [[ "$value" == example ]] || [[ "$value" == example-cluster ]] ||
    [[ "$value" == runner-example-01 ]]; then
    printf 'runner Agent %s label is invalid or still a placeholder\n' "$key" >&2
    return 1
  fi
  printf '%s\n' "$value"
}

runner_instance="$(extract_single_value instance)"
runner_cluster="$(extract_single_value cluster)"
runner_environment="$(extract_single_value environment)"
readonly runner_instance runner_cluster runner_environment

mapfile -t remote_write_urls < <(
  awk '$1 == "-" && $2 == "url:" { print $3 }' "$agent_snapshot"
)
if [[ ${#remote_write_urls[@]} -ne 1 ]] ||
  [[ ! "${remote_write_urls[0]}" =~ ^https://[^[:space:]]+$ ]] ||
  [[ "${remote_write_urls[0]}" == *example.invalid* ]] ||
  [[ "${remote_write_urls[0]}" == *example.com* ]] ||
  [[ "${remote_write_urls[0]}" == *example.net* ]] ||
  [[ "${remote_write_urls[0]}" == *example.org* ]]; then
  printf '%s\n' 'runner Agent requires one non-example HTTPS remote-write URL' >&2
  exit 1
fi

inventory_metrics="$(< "$metrics_snapshot")"
readonly inventory_metrics
mapfile -t inventory_generations < <(
  awk '$1 == "automata_ci_runner_inventory_generation_timestamp_seconds" { print $2 }' \
    <<< "$inventory_metrics"
)
if [[ ${#inventory_generations[@]} -ne 1 ]] ||
  [[ ! "${inventory_generations[0]}" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'runner inventory has no exact generation timestamp' >&2
  exit 1
fi
inventory_generation="${inventory_generations[0]}"
current_time="$(date +%s)"
if ((inventory_generation > current_time + maximum_inventory_future_skew_seconds)) ||
  ((current_time - inventory_generation > maximum_inventory_age_seconds)); then
  printf '%s\n' 'runner inventory generation timestamp is stale or in the future' >&2
  exit 1
fi
readonly inventory_generation current_time

expected_inventory_sample="automata_ci_runner_inventory_expected{job=\"automata-runner\",instance=\"$runner_instance\",cluster=\"$runner_cluster\",environment=\"$runner_environment\"} 1"
readonly expected_inventory_sample
if [[ "$(grep -Fxc "$expected_inventory_sample" <<< "$inventory_metrics")" -ne 1 ]]; then
  printf '%s\n' 'runner Agent identity is absent or inconsistent in central inventory' >&2
  exit 1
fi

promtool_path="${AUTOMATA_PROMTOOL:-}"
container_runtime="${AUTOMATA_METRICS_CONTAINER_RUNTIME:-}"
if [[ -z "$promtool_path" ]] && command -v promtool >/dev/null 2>&1; then
  promtool_path="$(command -v promtool)"
fi
if [[ -n "$promtool_path" ]]; then
  if [[ ! -x "$promtool_path" ]]; then
    printf '%s\n' 'AUTOMATA_PROMTOOL must name an executable promtool' >&2
    exit 1
  fi
elif [[ "$container_runtime" != docker && "$container_runtime" != podman ]]; then
  printf '%s\n' \
    'promtool is required; install it or set AUTOMATA_METRICS_CONTAINER_RUNTIME to docker or podman' >&2
  exit 1
elif ! command -v "$container_runtime" >/dev/null 2>&1; then
  printf '%s\n' 'configured metrics container runtime is unavailable' >&2
  exit 1
fi
readonly promtool_path container_runtime

if [[ -n "$promtool_path" ]]; then
  "$promtool_path" check config "$agent_snapshot"
  "$promtool_path" check metrics < "$metrics_snapshot"
else
  "$container_runtime" run --rm --interactive \
    --user 0 \
    --volume "$agent_snapshot:/runner-agent.yml:ro" \
    --workdir / \
    --entrypoint /bin/promtool \
    "$prometheus_image" \
    check config /runner-agent.yml
  "$container_runtime" run --rm --interactive \
    --user 0 \
    --entrypoint /bin/promtool \
    "$prometheus_image" \
    check metrics < "$metrics_snapshot"
fi

publication_time="$(date +%s)"
if ((inventory_generation > publication_time + maximum_inventory_future_skew_seconds)) ||
  ((publication_time - inventory_generation > maximum_inventory_age_seconds)); then
  printf '%s\n' 'runner inventory became stale before publication' >&2
  exit 1
fi
readonly publication_time

publication_directory="$(cd -- "$(dirname -- "$publication_path")" && pwd -P)"
publication_name="$(basename -- "$publication_path")"
if [[ "$publication_name" != *.prom ]] || [[ "$publication_name" == .* ]] ||
  [[ -L "$publication_path" ]] ||
  [[ -e "$publication_path" && ! -f "$publication_path" ]]; then
  printf '%s\n' 'published inventory target must be a regular non-symlink .prom path' >&2
  exit 1
fi
readonly publication_directory publication_name
publication_temporary="$(mktemp "$publication_directory/.${publication_name}.XXXXXXXX")"
cp -- "$metrics_snapshot" "$publication_temporary"
chmod 0644 "$publication_temporary"
mv --no-target-directory -- \
  "$publication_temporary" "$publication_directory/$publication_name"
publication_temporary=''
