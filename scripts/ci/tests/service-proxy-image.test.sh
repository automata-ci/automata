#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd)"
verifier="${repository_root}/scripts/ci/verify-service-proxy-image.sh"
candidate_builder="${repository_root}/scripts/ci/build-service-proxy-candidate.sh"
readonly repository_root verifier candidate_builder

install -d -m 0755 -- "${repository_root}/target"
scratch_directory="$(
  mktemp -d "${repository_root}/target/service-proxy-image-test.XXXXXXXX"
)"
readonly scratch_directory
cleanup() {
  rm -rf -- "$scratch_directory"
}
trap cleanup EXIT

fake_bin="${scratch_directory}/bin"
runtime_tmp="${scratch_directory}/tmp"
invocation_log="${scratch_directory}/podman.log"
stdout_log="${scratch_directory}/stdout"
stderr_log="${scratch_directory}/stderr"
install -d -m 0700 -- "$fake_bin" "$runtime_tmp"
readonly fake_bin runtime_tmp invocation_log stdout_log stderr_log

cat >"${fake_bin}/podman" <<'PODMAN'
#!/usr/bin/env bash
set -euo pipefail

{
  printf '%s' "$1"
  for argument in "${@:2}"; do
    printf ' %s' "$argument"
  done
  printf '\n'
} >>"${AUTOMATA_FAKE_PODMAN_LOG:?}"

if [[ "$1" == image && "${2:-}" == inspect && $# -eq 3 ]]; then
  cat -- "${AUTOMATA_FAKE_PODMAN_INSPECTION:?}"
  exit 0
fi
if [[ "$1" == inspect && "${2:-}" == --type && "${3:-}" == image && $# -eq 4 ]]; then
  cat -- "${AUTOMATA_FAKE_PODMAN_INSPECTION:?}"
  exit 0
fi

if [[ "$1" == run ]]; then
  case "${AUTOMATA_FAKE_PODMAN_RUN_RESULT:?}" in
    cgroup)
      printf 'Error: OCI runtime error: read-only cgroup filesystem\n' >&2
      exit 125
      ;;
    stdout)
      printf 'unexpected process output\n'
      printf 'automata-ci-service-proxy: usage-invalid\n' >&2
      exit 64
      ;;
    success)
      exit 0
      ;;
    protocol-v2)
      if (( $# == 6 )); then
        printf 'automata-ci-service-proxy: usage-invalid\n' >&2
        exit 64
      fi
      if (( $# == 7 )) && [[ "$7" == serve-results-v1 ]]; then
        printf 'automata-ci-service-proxy: configuration-invalid\n' >&2
        exit 64
      fi
      printf 'fake-podman: unexpected protocol probe\n' >&2
      exit 70
      ;;
    pre-v2)
      printf 'automata-ci-service-proxy: usage-invalid\n' >&2
      exit 64
      ;;
    *)
      printf 'fake-podman: unsupported run result\n' >&2
      exit 70
      ;;
  esac
fi

printf 'fake-podman: unsupported invocation\n' >&2
exit 70
PODMAN
chmod 0700 "${fake_bin}/podman"
ln -s podman "${fake_bin}/buildah"

valid_inspection="${scratch_directory}/valid-inspection.json"
buildah_inspection="${scratch_directory}/buildah-inspection.json"
bad_label_inspection="${scratch_directory}/bad-label-inspection.json"
stale_protocol_inspection="${scratch_directory}/stale-protocol-inspection.json"
bad_config_inspection="${scratch_directory}/bad-config-inspection.json"
readonly valid_inspection buildah_inspection bad_label_inspection \
  stale_protocol_inspection bad_config_inspection
python3 - \
  "$valid_inspection" \
  "$buildah_inspection" \
  "$bad_label_inspection" \
  "$stale_protocol_inspection" \
  "$bad_config_inspection" <<'PY'
import copy
import json
import pathlib
import sys

valid_path, buildah_path, bad_label_path, stale_protocol_path, bad_config_path = map(
    pathlib.Path, sys.argv[1:]
)
labels = {
    "org.opencontainers.image.created": "2026-08-15T08:00:00+00:00",
    "org.opencontainers.image.licenses": "MIT",
    "org.opencontainers.image.revision": "0123456789abcdef0123456789abcdef01234567",
    "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.version": "0.1.0",
    "io.automata.service-proxy.protocol-version": "2",
    "io.automata.service-proxy.binary.sha256": "0" * 64,
    "io.automata.service-proxy.sbom.sha256": "1" * 64,
    "io.automata.service-proxy.source.sha256": "2" * 64,
}
document = [
    {
        "Config": {
            "Cmd": None,
            "Entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Labels": labels,
            "User": "65532:65532",
            "Volumes": None,
            "WorkingDir": "/",
        }
    }
]


def write(path: pathlib.Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


write(valid_path, document)
write(buildah_path, {"OCIv1": {"config": document[0]["Config"]}})
bad_label = copy.deepcopy(document)
bad_label[0]["Config"]["Labels"]["org.opencontainers.image.version"] = "9.9.9"
write(bad_label_path, bad_label)
stale_protocol = copy.deepcopy(document)
stale_protocol[0]["Config"]["Labels"][
    "io.automata.service-proxy.protocol-version"
] = "1"
write(stale_protocol_path, stale_protocol)
bad_config = copy.deepcopy(document)
bad_config[0]["Config"]["Entrypoint"] = ["/bin/not-the-service-proxy"]
write(bad_config_path, bad_config)
PY

case_status=0
run_verifier() {
  local process_probe="$1"
  local run_result="$2"
  local inspection="$3"
  local runtime="${4:-podman}"
  local -a command=(
    env
    -u AUTOMATA_SERVICE_PROXY_PROCESS_PROBE
    "AUTOMATA_FAKE_PODMAN_INSPECTION=${inspection}"
    "AUTOMATA_FAKE_PODMAN_LOG=${invocation_log}"
    "AUTOMATA_FAKE_PODMAN_RUN_RESULT=${run_result}"
    "AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME=${runtime}"
    "PATH=${fake_bin}:${PATH}"
    "TMPDIR=${runtime_tmp}"
  )
  if [[ "$process_probe" != default ]]; then
    command+=("AUTOMATA_SERVICE_PROXY_PROCESS_PROBE=${process_probe}")
  fi
  : >"$invocation_log"
  set +e
  "${command[@]}" "$verifier" \
    localhost/automata-ci/service-proxy:test \
    0.1.0 \
    0123456789abcdef0123456789abcdef01234567 \
    2026-08-15T08:00:00+00:00 \
    >"$stdout_log" 2>"$stderr_log"
  case_status=$?
  set -e
}

expect_status() {
  local expected="$1"
  if (( case_status != expected )); then
    printf 'service-proxy image verifier returned %d, expected %d\n' \
      "$case_status" "$expected" >&2
    printf '%s\n' '--- stdout ---' >&2
    sed -n '1,120p' "$stdout_log" >&2
    printf '%s\n' '--- stderr ---' >&2
    sed -n '1,120p' "$stderr_log" >&2
    exit 1
  fi
}

expect_exact_stdout() {
  local expected="$1"
  cmp -s "$stdout_log" <(printf '%s\n' "$expected") || {
    printf 'service-proxy image verifier stdout differed\n' >&2
    exit 1
  }
}

expect_exact_stderr() {
  local expected="$1"
  cmp -s "$stderr_log" <(printf '%s\n' "$expected") || {
    printf 'service-proxy image verifier stderr differed\n' >&2
    exit 1
  }
}

expect_valid_metadata_log() {
  mapfile -t invocations <"$invocation_log"
  (( ${#invocations[@]} == 1 )) || {
    printf 'metadata-only verification did not inspect exactly once\n' >&2
    exit 1
  }
  [[ "${invocations[0]}" == \
    'image inspect localhost/automata-ci/service-proxy:test' ]] || {
    printf 'metadata-only verification used an unexpected runtime command\n' >&2
    exit 1
  }
}

expect_valid_buildah_metadata_log() {
  mapfile -t invocations <"$invocation_log"
  (( ${#invocations[@]} == 1 )) || {
    printf 'Buildah metadata verification did not inspect exactly once\n' >&2
    exit 1
  }
  [[ "${invocations[0]}" == \
    'inspect --type image localhost/automata-ci/service-proxy:test' ]] || {
    printf 'Buildah metadata verification used an unexpected command\n' >&2
    exit 1
  }
}

expect_required_log() {
  mapfile -t invocations <"$invocation_log"
  (( ${#invocations[@]} == 3 )) || {
    printf 'required verification did not inspect and run both probes\n' >&2
    exit 1
  }
  [[ "${invocations[0]}" == \
    'image inspect localhost/automata-ci/service-proxy:test' ]]
  [[ "${invocations[1]}" == \
    'run --rm --network none --read-only localhost/automata-ci/service-proxy:test' ]]
  [[ "${invocations[2]}" == \
    'run --rm --network none --read-only localhost/automata-ci/service-proxy:test serve-results-v1' ]]
}

expect_first_probe_log() {
  mapfile -t invocations <"$invocation_log"
  (( ${#invocations[@]} == 2 )) || {
    printf 'failed first process probe used unexpected runtime commands\n' >&2
    exit 1
  }
  [[ "${invocations[0]}" == \
    'image inspect localhost/automata-ci/service-proxy:test' ]]
  [[ "${invocations[1]}" == \
    'run --rm --network none --read-only localhost/automata-ci/service-proxy:test' ]]
}

run_verifier metadata-only protocol-v2 "$valid_inspection"
expect_status 0
expect_exact_stdout \
  'Service-proxy image metadata verified; process probe is covered by the static binary contract'
[[ ! -s "$stderr_log" ]]
expect_valid_metadata_log

run_verifier metadata-only protocol-v2 "$buildah_inspection" buildah
expect_status 0
expect_exact_stdout \
  'Service-proxy image metadata verified; process probe is covered by the static binary contract'
[[ ! -s "$stderr_log" ]]
expect_valid_buildah_metadata_log

run_verifier default protocol-v2 "$buildah_inspection" buildah
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: Buildah supports only metadata-only image verification'
[[ ! -s "$invocation_log" ]]

run_verifier metadata-only protocol-v2 "$valid_inspection" buildah
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: image configuration is missing'
expect_valid_buildah_metadata_log

run_verifier metadata-only protocol-v2 "$bad_label_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: candidate labels differ'
expect_valid_metadata_log

run_verifier metadata-only protocol-v2 "$stale_protocol_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: candidate labels differ'
expect_valid_metadata_log

run_verifier metadata-only protocol-v2 "$bad_config_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: candidate entrypoint differs'
expect_valid_metadata_log

run_verifier default protocol-v2 "$valid_inspection"
expect_status 0
expect_exact_stdout 'Service-proxy image process and metadata verified'
[[ ! -s "$stderr_log" ]]
expect_required_log

run_verifier default success "$valid_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: candidate accepted an absent protocol command'
expect_first_probe_log

run_verifier default stdout "$valid_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: candidate failure wrote to stdout'
expect_first_probe_log

run_verifier default cgroup "$valid_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr 'service-proxy-image: candidate process diagnostic differs'
expect_first_probe_log

run_verifier default pre-v2 "$valid_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr \
  'service-proxy-image: candidate does not implement the protocol 2 Results capability'
expect_required_log

run_verifier unsupported protocol-v2 "$valid_inspection"
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr \
  'service-proxy-image: AUTOMATA_SERVICE_PROXY_PROCESS_PROBE must be required or metadata-only'
[[ ! -s "$invocation_log" ]] || {
  printf 'invalid process-probe mode invoked the container runtime\n' >&2
  exit 1
}

builder_context="${scratch_directory}/builder-context"
builder_output="${scratch_directory}/builder-output"
install -d -m 0700 -- "$builder_context"
: >"$invocation_log"
set +e
env \
  "AUTOMATA_FAKE_PODMAN_INSPECTION=${valid_inspection}" \
  "AUTOMATA_FAKE_PODMAN_LOG=${invocation_log}" \
  AUTOMATA_FAKE_PODMAN_RUN_RESULT=protocol-v2 \
  AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME=podman \
  AUTOMATA_SERVICE_PROXY_OCI_BUILDER=buildah-chroot \
  AUTOMATA_SERVICE_PROXY_PROCESS_PROBE=metadata-only \
  "PATH=${fake_bin}:${PATH}" \
  "TMPDIR=${runtime_tmp}" \
  "$candidate_builder" "$builder_context" "$builder_output" \
  >"$stdout_log" 2>"$stderr_log"
case_status=$?
set -e
expect_status 1
[[ ! -s "$stdout_log" ]]
expect_exact_stderr \
  'service-proxy-candidate: buildah-chroot candidate builds require the Buildah image runtime'
[[ ! -s "$invocation_log" ]] || {
  printf 'rejected Buildah runtime selection performed image work\n' >&2
  exit 1
}
[[ ! -e "$builder_output" ]] || {
  printf 'rejected Buildah runtime selection created its output directory\n' >&2
  exit 1
}
if find "$runtime_tmp" -mindepth 1 -maxdepth 1 \
  -name 'podman-vfs.*' -print -quit | grep . >/dev/null; then
  printf 'rejected Buildah runtime selection leaked a VFS store\n' >&2
  exit 1
fi

python3 - "$repository_root" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
build = "./scripts/ci/build-service-proxy-candidate.sh"
load_review = "python3 scripts/ci/verify-service-proxy-candidate-load.py"
for relative in (".ci/workflows/release.yml", ".ci/workflows/service-proxy-image.yml"):
    publication = (root / relative).read_text(encoding="utf-8")
    if build not in publication:
        raise SystemExit(
            f"service-proxy-image-test: {relative} does not build a service-proxy candidate"
        )
    if (
        "AUTOMATA_SERVICE_PROXY_OCI_BUILDER" in publication
        or "AUTOMATA_SERVICE_PROXY_PROCESS_PROBE" in publication
    ):
        raise SystemExit(
            f"service-proxy-image-test: {relative} overrides Podman required-process defaults"
        )
    if "AUTOMATA_SERVICE_PROXY_CONTAINER_RUNTIME: podman" not in publication:
        raise SystemExit(
            f"service-proxy-image-test: {relative} does not pin the Podman runtime"
        )
    if load_review not in publication:
        raise SystemExit(
            f"service-proxy-image-test: {relative} does not verify Docker loading"
        )
PY

printf 'Service-proxy image verifier contract verified\n'
