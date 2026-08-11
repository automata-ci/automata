# Conformance testing

Automata exposes a private, versioned read surface for differential GitHub
Actions compatibility tests. It is a supported control-plane interface; test
harnesses must not query Automata's PostgreSQL tables or object store directly.

## Repository workflow selection

Each repository in the GitHub provider configuration may set one direct
workflow path:

```json
{
  "workflow_path": ".github/workflows/main.yml"
}
```

The field defaults to `.github/workflows/ci.yml` for existing configuration.
Only direct `.github/workflows/*.yml` and `.github/workflows/*.yaml` files are
accepted. The path is also the delivery's Check subject, preserving the current
one-delivery/one-workflow authority invariant.

This first slice supports repositories such as Chalk and p-limit that each use
one selected workflow. Multi-workflow delivery fanout requires a corresponding
multi-subject authority model and remains separate work.

## Delivery export

```text
GET /api/v1/conformance/repositories/{repository_id}/github-deliveries/{delivery_id}
Authorization: Bearer {cli_session_token}
Accept: application/json
```

The caller must use a current CLI session whose durable role grants include the
private `conformance:read` permission for the exact repository. Browser
sessions are rejected. Repository publication policy never grants this
permission. The immutable installation-owner role receives it during migration
and new installation bootstrap.

The `schemaVersion: 1` document contains:

- the external and internal delivery identities, lifecycle, attempts, and all
  path-keyed workflow outcomes;
- every admitted run's workflow identity, trigger, ref, commit, lifecycle, and
  conclusion;
- expanded jobs and their verified, decoded JobIR;
- a safe runtime-context subset containing exact matrix and strategy values;
- latest attempt lifecycle, runner identity, and verified terminal result;
- finalized artifact names, media types, sizes, and content SHA-256 digests.

Pending deliveries and non-terminal runs are valid snapshots. Clients should
poll until the delivery is completed or rejected and every admitted run is
terminal. The API bounds the aggregate immutable blobs decoded by one run to
128 MiB and fails closed on missing, malformed, or identity-inconsistent blob
data.

Runtime inputs, variables, prerequisite outputs, secret bindings, raw logs,
and artifact bytes are not returned. The runtime-context export includes only
matrix and strategy data so this diagnostic surface cannot become a secret
readback path.

## Current evidence gap

The runner terminal result retains job outputs and step conclusions,
annotations, summaries, and timestamps, but it does not yet retain per-step
outputs. A canonical differential adapter must treat those values as missing;
it must not invent empty output maps. Full evidence-schema conformance therefore
requires a versioned step-output addition across the runner result, protocol,
and persistence boundary.
