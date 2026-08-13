# Foundation governance registry

GitHub Actions decoder and upstream-reference governance is maintained in the
[capability and reference governance contract](github-actions-capabilities.md).
It is intentionally separate from the internal format, migration, and limit
registry described below.

[`foundation-governance-v1.json`](foundation-governance-v1.json) is the
machine-readable coordination boundary for the GitHub Actions parity
foundations. It records the current named/versioned internal durable and wire
formats and owners, the canonical greenfield migration inventory, shared
surfaces, the pinned GitHub limit catalog, and every reviewed parity-visible
stricter Automata limit.

The registry is active. Its validator discovers format/version constants and
requires each one to be registered or explicitly excluded. A separate
repository-wide derived-contract pass discovers every production Rust constant
whose value contains a version token after serialized-format declarations are
accounted for. This includes digest domains, cryptographic contexts, capability
and route discriminators, credential keys, and storage namespaces under every
crate source, regardless of the constant's name or indentation. Each such token
must carry a source-local owner/kind annotation or an exact-source exclusion.
The validator also requires the full
pinned GitHub limit ID set, and binds implemented limits to exact source,
reason, and boundary-test evidence. An entry documents an existing contract;
it does not make an unsupported product surface available. A future registry
schema or status transition must define and enforce its own completeness
semantics before use.

The machine-readable `format_scope` closes that claim over named/versioned
internal declarations under `crates/*/src` and `ui/src`, plus the separately
mapped canonical Store migration. Ordinary unversioned public JSON HTTP APIs
are explicitly out of scope; this registry does not claim that they have been
inventoried or given compatibility versions.

Run the validator before changing a registered source, migration, test, or
shared surface:

```console
python3 scripts/ci/verify-foundation-governance.py
python3 scripts/ci/tests/foundation-governance.test.py
```

The validator rejects unknown fields, non-canonical JSON, duplicate or
unsorted identifiers, missing owners and paths, source/version drift, migration
inventory drift, and limit entries without exact attributed Rust tests. Each
registered limit also binds its reason code and three distinct fragments in a
real test for `limit - 1`, `limit`, and `limit + 1`.

## Changing a format

The format owner coordinates the version, reader policy, fixtures, and tests
in one change. Every `version` source must bind the declared version; `evidence`
sources bind related generated or encoding material without masquerading as a
version. Named, attributed Rust tests are part of each entry. Update the
implementation first, then update the registry to the same exact evidence.
An initial sequenced v1 may use `exact-current-only` without a prior reader. A
sequenced version above v1 must use `backward-compatible` and declare a real
reader plus a non-ignored, non-empty attributed test for every prior version.
The validator rejects an `exact-current-only` v2 and incomplete prior-version
coverage; compatibility must not be inferred from permissive deserialization.
Each prior-reader test binding names the real reader symbol and binds three
distinct fragments inside the attributed, non-ignored test body: the prior
version, the reader call, and the asserted outcome. Comments and helper
functions cannot satisfy those bindings.

Versioned derived tokens such as digest domains, AAD/purpose labels, operation
kinds, and storage namespaces are not serialization readers. Annotate them
immediately above the declaration as
`foundation-governance: derived-contract owner=<owner> kind=<kind>`. Their
append-only-token-or-coordinated-migration policy is enforced separately from
serialized-format prior-reader policy; new tokens should normally be added
instead of mutating a token already used by durable data or another process.

## Changing the store schema

The repository currently has a canonical greenfield database with no supported
upgrade source. Its complete schema lives in
`0001_initial_schema.sql`, and new deployments start from an empty database.
While the registry's migration mode is `greenfield-canonical-baseline`, change
that canonical file and its empty-database tests instead of adding `0002` or
reserving a historical sequence number.

[`store-migration-format-map-v1.json`](store-migration-format-map-v1.json)
accounts for every schema-, version-, or epoch-like current-value literal in
the hash-pinned baseline. Each identifier is bound to its registered durable
format, or has an explicit reason that it is a business ordinal rather than a
format. Production Rust and TypeScript readers and writers must use registered
constants; the validator rejects new numeric SQL/JSON schema literals and
hardcoded media-type predicates outside tests.

A future decision to support durable upgrades must first change the governance
mode and define reservation, immutability, forward-reader, rollback, and mixed-
version rules. Parallel feature branches must not invent that transition.

## Changing a limit

Limit discovery is declaration-first across every production
`crates/*/src/**/*.rs` source. It scans module, local, and associated constants
whose token-bounded names or semantic types identify a maximum, minimum, limit,
ceiling, cap, bound, budget, quota, page size, or batch size. Source annotations
are consistency evidence; they do not opt a declaration into discovery.

Every discovered declaration must have exactly one of four dispositions:

- a registered GitHub-parity or stricter product limit, with one owner,
  enforcement phase, stable dimension-specific reason, exact source value, and
  tests for `limit - 1`, `limit`, and `limit + 1`;
- a structured equality or offset alias whose source and target values are
  checked and whose alias is exercised by a test;
- an operational/non-parity exclusion with an owner, phase, rationale, and a
  source-bound production use for every named constant; or
- a narrow lexical non-limit exclusion for names such as protocol/header tokens
  that contain a limit word but impose no behavioral ceiling.

Registered product limits carry an immediately preceding
`// foundation-governance: parity-limit` annotation. Structured aliases use
`// foundation-governance: limit-alias`. Existing
`// foundation-governance: operational-limit` annotations must resolve to
operational exclusions, but unannotated operational candidates still require
an explicit disposition. Add or update the inventory in the same change that
introduces, renames, aliases, or changes an enforced limit.

The repository's canonical Automata workflow invokes these checks through
`verify-product-targets.sh`. The GitHub-hosted workflow under
`.github/workflows` performs only scheduled/manual upstream-reference drift
detection; it is not a GitHub pull-request validation lane. An empty GitHub PR
check rollup is therefore not evidence that the governance checks ran.

## Shared surfaces

The rotating integration owner coordinates root manifests, the workspace lock,
and canonical shared CI. The protocol owner coordinates the protobuf source,
generated bindings, and wire fixtures. Feature branches should hand these
changes to the named owner rather than resolving the same generated or shared
file independently.
