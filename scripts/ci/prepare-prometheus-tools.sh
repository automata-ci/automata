#!/usr/bin/env bash
set -euo pipefail

readonly automata_prometheus_version='3.13.0'
automata_repo_root="$(git rev-parse --show-toplevel)"
readonly automata_repo_root
cd "$automata_repo_root"
# shellcheck source=scripts/ci/lib/target-paths.sh
source "$automata_repo_root/scripts/ci/lib/target-paths.sh"

case "$(uname -m)" in
  x86_64)
    automata_prometheus_platform='linux-amd64'
    automata_prometheus_sha256='744d93324cc024d82089921737bd797474d7f1e5dbbfd1c6b387bad258538cb9'
    ;;
  aarch64 | arm64)
    automata_prometheus_platform='linux-arm64'
    automata_prometheus_sha256='c11fbff0fde0e357e4cfcf2ec74b83d5475301da7e6777c6d7b6aa6d06a410f7'
    ;;
  *)
    printf 'unsupported Prometheus tool architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
readonly automata_prometheus_platform automata_prometheus_sha256

automata_init_target_root "$automata_repo_root"
automata_set_target_tmpdir \
  "$automata_repo_root" \
  "$automata_repo_root/target/task-tmp/prometheus-tools"

automata_prometheus_root="$automata_repo_root/target/task-tools/prometheus-${automata_prometheus_version}-${automata_prometheus_platform}"
automata_prometheus_bin="$automata_prometheus_root/bin"
readonly automata_prometheus_root automata_prometheus_bin

if [[ -x "$automata_prometheus_bin/promtool" && -x "$automata_prometheus_bin/prometheus" ]] &&
  "$automata_prometheus_bin/promtool" --version 2>&1 \
    | grep -Fq "version ${automata_prometheus_version}" &&
  "$automata_prometheus_bin/prometheus" --version 2>&1 \
    | grep -Fq "version ${automata_prometheus_version}"; then
  printf '%s\n' "$automata_prometheus_bin"
  exit 0
fi

automata_archive="prometheus-${automata_prometheus_version}.${automata_prometheus_platform}.tar.gz"
automata_scratch="$(mktemp -d "$TMPDIR/automata-prometheus-tools.XXXXXXXX")"
readonly automata_archive automata_scratch
cleanup_prometheus_tools() {
  if [[ "$automata_scratch" == "$TMPDIR"/automata-prometheus-tools.* ]] &&
    [[ -d "$automata_scratch" ]] && [[ ! -L "$automata_scratch" ]]; then
    rm -rf -- "$automata_scratch"
  fi
}
trap cleanup_prometheus_tools EXIT

curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --silent --show-error \
  --output "$automata_scratch/$automata_archive" \
  "https://github.com/prometheus/prometheus/releases/download/v${automata_prometheus_version}/${automata_archive}"
printf '%s  %s\n' \
  "$automata_prometheus_sha256" "$automata_scratch/$automata_archive" \
  | sha256sum --check --strict >/dev/null
tar --extract --gzip --file "$automata_scratch/$automata_archive" \
  --directory "$automata_scratch"
install -d -m 0755 -- "$automata_prometheus_bin"
install -m 0755 -- \
  "$automata_scratch/prometheus-${automata_prometheus_version}.${automata_prometheus_platform}/promtool" \
  "$automata_scratch/prometheus-${automata_prometheus_version}.${automata_prometheus_platform}/prometheus" \
  "$automata_prometheus_bin/"

"$automata_prometheus_bin/promtool" --version 2>&1 \
  | grep -Fq "version ${automata_prometheus_version}"
"$automata_prometheus_bin/prometheus" --version 2>&1 \
  | grep -Fq "version ${automata_prometheus_version}"
printf '%s\n' "$automata_prometheus_bin"
