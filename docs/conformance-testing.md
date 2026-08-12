# Conformance testing

Automata exposes a private, versioned read surface for differential GitHub
Actions compatibility tests. It is a supported control-plane interface; test
harnesses must not query Automata's PostgreSQL tables or object store directly.

## Repository workflow selection

Each repository in the GitHub provider configuration selects either one direct
workflow path:

```json
{
  "workflow_path": ".ci/workflows/main.yml"
}
```

or every direct workflow:

```json
{
  "workflow_selection": { "mode": "all_direct" }
}
```

Rename `.github` to `.ci` (or move only `.github/workflows` to
`.ci/workflows` when the repository keeps other GitHub metadata). Workflow YAML
does not change. After `actions/checkout`, Automata exposes the checked-out
workflow files at `.github/workflows` as well, so unchanged steps that read the
GitHub path continue to work. Only direct `.ci/workflows/*.yml` and
`.ci/workflows/*.yaml` files are accepted. Every selected workflow is retained
as a separate delivery subject and Check Run.

## Delivery export

```text
GET /api/v1/conformance/github/repositories/{github_repository_id}/deliveries/{delivery_id}
Authorization: Bearer {bearer_token}
Accept: application/json
```

The caller must use a current CLI session whose durable role grants include the
private `conformance:read` permission for the exact repository. Browser
sessions are rejected. Repository publication policy never grants this
permission. The immutable installation-owner role receives it during migration
and new installation bootstrap.

An isolated loopback deployment with human authentication disabled may instead
configure `--conformance-export-token-source`. This deployment-scoped bearer
grants only this read surface for the configured fallback tenant. It is rejected
on a non-loopback listener or alongside human authentication. The server derives
the tenant-scoped internal repository identity from the positive numeric GitHub
repository ID in the URL; clients never manufacture or discover an internal
repository UUID.

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
