# Conformance testing

Automata exposes a private, versioned read surface for differential GitHub
Actions compatibility tests. It is a supported control-plane interface; test
harnesses must not query Automata's PostgreSQL tables or object store directly.

## Repository workflow selection

Each configured repository discovers every direct `.ci/workflows/*.yml` and
`.ci/workflows/*.yaml` file on its configured default branch.
Rename `.github` to `.ci` (or move only `.github/workflows` to
`.ci/workflows` when the repository keeps other GitHub metadata). Workflow YAML
does not otherwise change, except local reusable-workflow references use the
native `./.ci/workflows/<file>.yml` path. Automata never creates a shadow
`.github/workflows` tree. Only direct `.ci/workflows/*.yml` and
`.ci/workflows/*.yaml` files are accepted; the presence of a GitHub Actions
workflow tree rejects the repository archive. Every concrete job is retained as
its own Check Run and links to the exact Automata dashboard job.

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

Schema v1 remains the default compatibility response. New adapters should send
the exact media type below to opt in to the presence-aware schema v2 contract:

```text
Accept: application/vnd.automata.conformance.v2+json
```

Schema v2 retains the v1 identities and adds:

- decoded, integrity-checked, canonical masked log frames together with every
  immutable segment descriptor;
- explicit `present` or `unavailable` state for JobIR, runtime context, runner,
  terminal result, logs, step summaries, and per-step outputs;
- job outputs, step outcome/conclusion/timestamps, annotations, and summaries
  in a stable adapter-oriented shape;
- explicit unavailable markers for services, caches, effective authority, and
  cleanup until their product persistence contracts land.

An unavailable field is never encoded as an empty map or list. In particular,
the current terminal-result schema does not retain per-step outputs, so schema
v2 reports `not_retained_by_schema` instead of manufacturing `{}`. A future
result-schema owner can replace that marker with `present` without changing the
outer evidence model.

Pending deliveries and non-terminal runs are valid snapshots. Clients should
poll until the delivery is completed or rejected and every admitted run is
terminal. The API bounds the aggregate immutable blobs decoded by one run to
128 MiB and fails closed on missing, malformed, or identity-inconsistent blob
data.

Runtime inputs, variables, prerequisite outputs, secret bindings, and artifact
bytes are not returned. Schema v1 also omits logs. Schema v2 returns only the
runner-masked frames that passed immutable segment verification; exposure and
publication policy still bound access to the private conformance surface. The
runtime-context export includes only matrix and strategy data so this
diagnostic surface cannot become a secret readback path.

## Current evidence gap

The runner terminal result retains job outputs and step conclusions,
annotations, summaries, and timestamps, but it does not yet retain per-step
outputs. Schema v2 makes that absence machine-readable. Capturing actual
per-step output values still requires a versioned addition across the executor,
runner result, protocol, and persistence boundary.

## Product fixture contracts

The `automata-ci-conformance` crate owns the provider-neutral fixture contract
intended for consumption by the companion integration harness. Product-side
composition is exposed only when the `automata-ci/conformance-test-support`
Cargo feature is enabled; default production builds do not expose or select it.
A companion JSON/CLI adapter has not landed yet. The crate provides:

- immutable, canonically digestible fixture catalog entries;
- non-substitutable contract, provider-emulator, hermetic-product, live-GitHub,
  and live-Automata evidence classes;
- exact build provenance covering source cleanliness, control-plane and runner
  binaries, profile locks/images, service images, and all relevant schema
  versions;
- deterministic fake-clock, one-shot failure plans for source, token, Results,
  Checks, runner, and object storage, plus mandatory restart checkpoints between
  durable transitions;
- exact raw webhook-body/signature locks and an exact-order GitHub stub script
  for pagination, rate limiting, credential failures, and indeterminate
  mutations;
- deterministic shard identities with separate PostgreSQL schemas, object
  prefixes, credential scopes, and port-reservation keys;
- explicit skip outcomes for missing live prerequisites. A skip is not a pass.

The contract crate performs no provider I/O and contains no credentials. The
control-plane crate supplies an explicit opt-in conformance composition and a
`ProductConformanceShard` consumer of
one selected shard identity: it creates and marker-owns the exact PostgreSQL
schema with transaction-local `shard, pg_catalog, pg_temp` resolution, prefixes
and gates real `ImmutableBlobStore` operations through an implementation that
can be injected as `Arc<dyn ImmutableBlobStore>`, scopes
redacting hermetic GitHub credentials, and hands an already-bound loopback
listener to a server adapter. Each shard/purpose port-reservation identity is
single-use within the test process, including after listener handoff, so two
adapters cannot publish the same reservation evidence. Its PostgreSQL 18 integration test runs in the
repository's PostgreSQL lane; the object, credential, and listener tests are
secret-free. The opt-in composition consumes the held listener with the
exact-order GitHub stub, configures the real hardened GitHub HTTP client, and
installs the shared manual clock and operation-specific fault wrappers in real
workflow-admission, Results, GitHub-provider, credential, Checks-credential,
runner-control, and object-store ports. Production defaults remain unchanged.

This is product-side fixture composition, not a launched end-to-end run. The companion
harness still has to pass the held listeners and scoped configuration into the
real control-plane and runner processes, provision an external S3-compatible
bucket, drive the real workflow lifecycle through each injected fault, apply
the restart probe to every real service, emit retained evidence, and prove
cleanup. Live-provider setup remains
deployment-owned, so hermetic evidence cannot satisfy a live-provider gate.
