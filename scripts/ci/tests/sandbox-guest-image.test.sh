#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH='' cd -- "${script_directory}/../../.." && pwd)"
verifier="${repository_root}/scripts/ci/verify-sandbox-guest-image.sh"
readonly repository_root verifier

install -d -m 0755 -- "${repository_root}/target"
scratch_directory="$(
  mktemp -d "${repository_root}/target/sandbox-guest-image-test.XXXXXXXX"
)"
readonly scratch_directory
cleanup() {
  rm -rf -- "$scratch_directory"
}
trap cleanup EXIT

fake_bin="${scratch_directory}/bin"
runtime_tmp="${scratch_directory}/tmp"
context="${scratch_directory}/context"
invocation_log="${scratch_directory}/docker.log"
image_state="${scratch_directory}/image"
stdout_log="${scratch_directory}/stdout"
stderr_log="${scratch_directory}/stderr"
install -d -m 0700 -- "$fake_bin" "$runtime_tmp" "$context/sbom"
readonly fake_bin runtime_tmp context invocation_log image_state stdout_log stderr_log

install -m 0444 -- \
  "${repository_root}/images/automata-sandbox-guest.Containerfile" \
  "$context/Containerfile"
for required in \
  LICENSE \
  THIRD_PARTY_LICENSES.txt \
  THIRD_PARTY_NOTICES.txt \
  automata-ci-sandbox-guest \
  sbom/automata-ci-sandbox-guest.cdx.json
do
  : >"$context/$required"
done
printf '1.2.3\n' >"$context/VERSION"

cat >"${fake_bin}/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail

{
  printf '%q' "$1"
  for argument in "${@:2}"; do
    printf ' %q' "$argument"
  done
  printf '\n'
} >>"${AUTOMATA_FAKE_DOCKER_LOG:?}"

if [[ "$1" == build ]]; then
  shift
  no_cache=0
  network=""
  platform=""
  pull=""
  containerfile=""
  image=""
  build_args=()
  while (( $# > 1 )); do
    case "$1" in
      --no-cache)
        no_cache=1
        shift
        ;;
      --network)
        network="${2:-}"
        shift 2
        ;;
      --platform)
        platform="${2:-}"
        shift 2
        ;;
      --pull=false)
        pull=false
        shift
        ;;
      --file)
        containerfile="${2:-}"
        shift 2
        ;;
      --tag)
        image="${2:-}"
        shift 2
        ;;
      --build-arg)
        build_args+=("${2:-}")
        shift 2
        ;;
      *)
        printf 'fake-docker: unexpected build option %s\n' "$1" >&2
        exit 70
        ;;
    esac
  done
  (( $# == 1 )) || exit 70
  [[ "$1" == "${AUTOMATA_FAKE_DOCKER_CONTEXT:?}" ]] || exit 70
  (( no_cache == 1 )) || exit 70
  [[ "$network" == none && "$platform" == linux/amd64 && "$pull" == false ]] \
    || exit 70
  [[ "$containerfile" == "$1/Containerfile" ]] || exit 70
  [[ "$image" == automata-ci/sandbox-guest-verification:* ]] || exit 70
  [[ "${build_args[*]}" == \
    "AUTOMATA_CREATED=2025-01-01T00:00:00Z AUTOMATA_REVISION=0123456789abcdef0123456789abcdef01234567 AUTOMATA_VERSION=1.2.3 SOURCE_DATE_EPOCH=1735689600" ]] \
    || exit 70
  printf '%s\n' "$image" >"${AUTOMATA_FAKE_DOCKER_IMAGE:?}"
  exit 0
fi

if [[ "$1" == image && "${2:-}" == inspect && $# -eq 3 ]]; then
  [[ "$3" == "$(<"${AUTOMATA_FAKE_DOCKER_IMAGE:?}")" ]] || exit 70
  cat -- "${AUTOMATA_FAKE_DOCKER_INSPECTION:?}"
  exit 0
fi

if [[ "$1" == image && "${2:-}" == rm && "${3:-}" == --force && $# -eq 4 ]]; then
  [[ "$4" == "$(<"${AUTOMATA_FAKE_DOCKER_IMAGE:?}")" ]] || exit 70
  exit 0
fi

if [[ "$1" == run ]]; then
  (( $# == 10 || $# == 11 )) || exit 70
  [[ "$2" == --rm ]] || exit 70
  [[ "$3" == --network && "$4" == none ]] || exit 70
  [[ "$5" == --read-only ]] || exit 70
  [[ "$6" == --security-opt && "$7" == no-new-privileges ]] || exit 70
  [[ "$8" == --cap-drop && "$9" == ALL ]] || exit 70
  [[ "${10}" == "$(<"${AUTOMATA_FAKE_DOCKER_IMAGE:?}")" ]] || exit 70
  if (( $# == 11 )); then
    [[ "${11}" == unsupported-command ]] || exit 70
  fi
  case "${AUTOMATA_FAKE_DOCKER_RUN_RESULT:?}" in
    silent)
      exit 1
      ;;
    noisy)
      printf 'unexpected guest diagnostic\n' >&2
      exit 1
      ;;
    empty-success)
      (( $# == 10 )) && exit 0
      exit 1
      ;;
    unsupported-success)
      (( $# == 11 )) && exit 0
      exit 1
      ;;
    *)
      exit 70
      ;;
  esac
fi

printf 'fake-docker: unsupported invocation\n' >&2
exit 70
DOCKER
chmod 0700 -- "${fake_bin}/docker"

valid_inspection="${scratch_directory}/valid-inspection.json"
extra_label_inspection="${scratch_directory}/extra-label-inspection.json"
bad_platform_inspection="${scratch_directory}/bad-platform-inspection.json"
bad_config_inspection="${scratch_directory}/bad-config-inspection.json"
readonly valid_inspection extra_label_inspection bad_platform_inspection \
  bad_config_inspection
python3 - \
  "$valid_inspection" \
  "$extra_label_inspection" \
  "$bad_platform_inspection" \
  "$bad_config_inspection" <<'PY'
import copy
import json
import pathlib
import sys

valid_path, extra_label_path, bad_platform_path, bad_config_path = map(
    pathlib.Path, sys.argv[1:]
)
labels = {
    "io.automata.sandbox-guest.protocol-version": "3",
    "org.opencontainers.image.created": "2025-01-01T00:00:00Z",
    "org.opencontainers.image.description": (
        "Fixed protocol guest for Automata local job sandboxes"
    ),
    "org.opencontainers.image.documentation": (
        "https://github.com/automata-ci/automata/blob/main/"
        "crates/automata-ci-sandbox-guest/README.md"
    ),
    "org.opencontainers.image.licenses": "MIT",
    "org.opencontainers.image.revision": (
        "0123456789abcdef0123456789abcdef01234567"
    ),
    "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.title": "Automata Sandbox Guest",
    "org.opencontainers.image.url": "https://github.com/automata-ci/automata",
    "org.opencontainers.image.version": "1.2.3",
}
document = [
    {
        "Architecture": "amd64",
        "Config": {
            "Entrypoint": ["/usr/local/bin/automata-ci-sandbox-guest"],
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Labels": labels,
            "User": "65532:65532",
            "WorkingDir": "/",
        },
        "Os": "linux",
        "RootFS": {"Layers": ["sha256:fixture"], "Type": "layers"},
    }
]


def write(path: pathlib.Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


write(valid_path, document)
extra_label = copy.deepcopy(document)
extra_label[0]["Config"]["Labels"]["unexpected"] = "surface"
write(extra_label_path, extra_label)
bad_platform = copy.deepcopy(document)
bad_platform[0]["Architecture"] = "arm64"
write(bad_platform_path, bad_platform)
bad_config = copy.deepcopy(document)
bad_config[0]["Config"]["Cmd"] = ["serve"]
write(bad_config_path, bad_config)
PY

case_status=0
run_verifier() {
  local inspection="$1"
  local run_result="$2"
  local source_date_epoch="${3:-1735689600}"
  : >"$invocation_log"
  rm -f -- "$image_state"
  set +e
  env \
    "AUTOMATA_FAKE_DOCKER_CONTEXT=$context" \
    "AUTOMATA_FAKE_DOCKER_IMAGE=$image_state" \
    "AUTOMATA_FAKE_DOCKER_INSPECTION=$inspection" \
    "AUTOMATA_FAKE_DOCKER_LOG=$invocation_log" \
    "AUTOMATA_FAKE_DOCKER_RUN_RESULT=$run_result" \
    "PATH=$fake_bin:$PATH" \
    "TMPDIR=$runtime_tmp" \
    bash "$verifier" \
      "$context" \
      1.2.3 \
      0123456789abcdef0123456789abcdef01234567 \
      2025-01-01T00:00:00Z \
      "$source_date_epoch" \
      >"$stdout_log" 2>"$stderr_log"
  case_status=$?
  set -e
}

expect_success() {
  (( case_status == 0 )) || {
    printf 'sandbox-guest image verifier unexpectedly returned %d\n' \
      "$case_status" >&2
    sed -n '1,120p' "$stderr_log" >&2
    exit 1
  }
  cmp -s "$stdout_log" <(
    printf 'Sandbox-guest image process and metadata verified\n'
  ) || {
    printf 'sandbox-guest image verifier success output differed\n' >&2
    exit 1
  }
  [[ ! -s "$stderr_log" ]] || {
    printf 'sandbox-guest image verifier wrote unexpected stderr\n' >&2
    exit 1
  }
}

expect_failure() {
  local diagnostic="$1"
  (( case_status != 0 )) || {
    printf 'sandbox-guest image verifier unexpectedly succeeded\n' >&2
    exit 1
  }
  grep -Fq -- "$diagnostic" "$stderr_log" || {
    printf 'sandbox-guest image verifier omitted diagnostic: %s\n' \
      "$diagnostic" >&2
    sed -n '1,120p' "$stderr_log" >&2
    exit 1
  }
}

expect_log_count() {
  local prefix="$1"
  local expected="$2"
  local actual
  actual="$(grep -c -- "^${prefix}" "$invocation_log" || true)"
  [[ "$actual" == "$expected" ]] || {
    printf 'fake Docker logged %s %s calls, expected %s\n' \
      "$actual" "$prefix" "$expected" >&2
    exit 1
  }
}

run_verifier "$valid_inspection" silent
expect_success
expect_log_count build 1
expect_log_count 'image inspect' 1
expect_log_count run 2
expect_log_count 'image rm' 1

: >"$context/unexpected"
run_verifier "$valid_inspection" silent
expect_failure 'prepared image context has a noncanonical entry set'
expect_log_count build 0
rm -f -- "$context/unexpected"

mv -- "$context/LICENSE" "$scratch_directory/LICENSE"
ln -s -- "$scratch_directory/LICENSE" "$context/LICENSE"
run_verifier "$valid_inspection" silent
expect_failure 'prepared image context is missing LICENSE'
expect_log_count build 0
rm -f -- "$context/LICENSE"
mv -- "$scratch_directory/LICENSE" "$context/LICENSE"

run_verifier "$extra_label_inspection" silent
expect_failure 'image labels differ'
expect_log_count run 0
expect_log_count 'image rm' 1

run_verifier "$bad_platform_inspection" silent
expect_failure 'image platform is not linux/amd64'

run_verifier "$bad_config_inspection" silent
expect_failure 'image declares an unexpected Cmd setting'

run_verifier "$valid_inspection" noisy
expect_failure 'empty invocation wrote to stderr'

run_verifier "$valid_inspection" empty-success
expect_failure 'empty invocation unexpectedly succeeded'

run_verifier "$valid_inspection" unsupported-success
expect_failure 'unsupported invocation unexpectedly succeeded'
expect_log_count run 2

run_verifier "$valid_inspection" silent 1735689601
expect_failure 'release timestamps differ'
expect_log_count build 0

printf 'sandbox-guest image verifier tests passed\n'
