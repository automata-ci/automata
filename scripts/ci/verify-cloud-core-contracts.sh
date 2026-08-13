#!/usr/bin/env bash
set -euo pipefail

script_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
repository_root="$(CDPATH='' cd -- "$script_directory/../.." && pwd)"
readonly repository_root
contract_root="${repository_root}/contracts/cloud-core"
readonly contract_root
buf_binary="${AUTOMATA_BUF_BINARY:-buf}"
readonly buf_binary

if ! command -v "$buf_binary" >/dev/null 2>&1; then
  printf 'error: Buf executable not found: %s\n' "$buf_binary" >&2
  exit 1
fi

"$buf_binary" format --diff --exit-code "$contract_root/proto"
"$buf_binary" lint "$contract_root"
"$buf_binary" build "$contract_root"
"$buf_binary" build "$contract_root" --output '-#format=json' \
  | jq --exit-status '
      any(
        .file[];
        .package == "automata.management.v1"
        and any(
          .service[]?;
          .name == "ShardManagementService"
          and any(
            .method[]?;
            .name == "ProvisionWorkspace"
            and .inputType == ".automata.management.v1.ProvisionWorkspaceRequest"
            and .outputType == ".automata.management.v1.ProvisionWorkspaceResponse"
            and .options.idempotencyLevel == "IDEMPOTENT"
            and .options["[google.api.http]"] == {
              "post": "/internal/v1/workspaces",
              "body": "*"
            }
          )
        )
      )
    ' \
  >/dev/null

"$buf_binary" convert "$contract_root" \
  --type automata.management.v1.ProvisionWorkspaceRequest \
  --from "$contract_root/v1/examples/workspace-provisioning-request.json#format=json" \
  --to '-#format=binpb' \
  >/dev/null
"$buf_binary" convert "$contract_root" \
  --type automata.management.v1.ProvisionWorkspaceResponse \
  --from "$contract_root/v1/examples/workspace-provisioning-response.json#format=json" \
  --to '-#format=binpb' \
  >/dev/null

breaking_against="${AUTOMATA_BUF_BREAKING_AGAINST:-}"
baseline_probe="${AUTOMATA_BUF_BREAKING_BASELINE_PROBE:-}"
if [[ -n "$breaking_against" || -n "$baseline_probe" ]]; then
  if [[ -z "$breaking_against" || -z "$baseline_probe" ]]; then
    printf '%s\n' \
      'error: both AUTOMATA_BUF_BREAKING_AGAINST and AUTOMATA_BUF_BREAKING_BASELINE_PROBE are required' \
      >&2
    exit 1
  fi

  baseline_status="$(
    curl \
      --location \
      --proto '=https' \
      --retry 3 \
      --show-error \
      --silent \
      --tlsv1.2 \
      --output /dev/null \
      --write-out '%{http_code}' \
      "$baseline_probe"
  )"
  readonly baseline_status
  case "$baseline_status" in
    200)
      "$buf_binary" breaking "$contract_root" --against "$breaking_against"
      ;;
    404)
      printf '%s\n' \
        'No Protobuf contract exists on the comparison branch; skipping the initial breaking check.'
      ;;
    *)
      printf 'error: Protobuf baseline probe returned HTTP %s\n' "$baseline_status" >&2
      exit 1
      ;;
  esac
fi
