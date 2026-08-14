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
requires each one to be registered or explicitly excluded. It also requires the
full pinned GitHub limit ID set, and binds implemented limits to exact source,
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
source and test binding is located in executable Rust or TypeScript tokens;
comments, ordinary/raw/template/regex literals, Rust token-quoting macros such
as `stringify!`/`quote!`, and fake declarations or tests inside them are not
evidence. Rust declarations behind a `cfg` predicate that
requires `test` are excluded from the production census, while production-
capable predicates such as `any(test, unix)` and `not(test)` remain censused.
Source filenames are not treated as cfg evidence: a production-capable
`src/tests.rs` remains in the census. Each registered limit also binds its
reason code and three distinct fragments in a
real test for `limit - 1`, `limit`, and `limit + 1`. Those labels are checked
against the complete arithmetic expression rooted at the declared source
constant (or an exact evaluated integer) as the direct value exercised by the
governed operation, not inferred from fragment names or an unrelated boolean
branch. A
test-local `value_alias` must bind directly to that source value. The narrow
`successor-attempt` relation is available when a stateful test proves the
at-limit state before negatively asserting a declared operation on that same
receiver. Aliases and successor receivers cannot be shadowed, rebound, or
reassigned between the declaration/base and governed evidence.

## Changing a format

The format owner coordinates the version, reader policy, fixtures, and tests
in one change. Every `version` source must bind the declared version; `evidence`
sources bind related generated or encoding material without masquerading as a
version. Non-declaration constructors such as `Self::v1()` and
`Self::constant(1)` are accepted only when the helper body is source-bound to
the same direct value. Named, attributed Rust tests are part of each entry. Update the
implementation first, then update the registry to the same exact evidence.
An initial sequenced v1 may use `exact-current-only` without a prior reader. A
sequenced version above v1 must choose one explicit policy. A
`backward-compatible` format declares a real reader plus a non-ignored,
non-empty attributed acceptance test for every prior version. A deliberately
incompatible `breaking-current-only` format instead binds the production
rejection guard and a non-ignored, non-empty attributed rejection test for
every prior version. The validator rejects an `exact-current-only` v2 and
incomplete prior-version coverage; compatibility must not be inferred from
permissive deserialization, and a breaking change must not masquerade as a
reader migration. Each prior-version test binding names the invoked reader and
binds three distinct fragments inside the attributed test body: the prior
version, the reader call, and the asserted outcome. The exact prior token must
flow directly into the declared reader argument (or through a structured
`version_input` with an explicit reader-argument index), and the asserted
success/rejection operation must apply directly to that reader result through a
closed assertion grammar. Comments, literals, unrelated status markers, and
arbitrary assertion macros cannot satisfy those bindings; the one external
rejection helper is accepted only when its body directly compares the reader
result with the declared rejected response.

Canonical `vN` tokens are sequenced automatically. Compact ordinal tokens such
as `bw1`, `dp1`, and `p1` declare a closed `version_sequence` with kind
`prefix-ordinal` and their exact stable nonnumeric prefix. This makes `bw2`
require `bw1` evidence without guessing that unrelated digit-ending opaque
tokens (for example hashes or dates) are compatibility ordinals. Each of the
three sequence requirements is independently anchored to its stable format ID
and discovered source declaration; retaining either anchor preserves the gate.
The `bw`, `dp`, and `p` token families are also reserved compact sequences at
the token level, including discovered declarations proposed for
`format_exclusions`. Renaming only the registry ID, refactoring only the source
declaration, changing both identities together, or moving the declaration into
`format_exclusions` therefore cannot remove compatibility enforcement.

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
ceiling, cap, bound, budget, quota, page size, or batch size.

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

Add or update the central inventory in the same change that introduces,
renames, aliases, or changes an enforced limit. Source files do not carry
governance annotations; declaration-first discovery and the four dispositions
above are the authority.

The repository's canonical Automata workflow invokes these checks through
`verify-product-targets.sh`. An empty GitHub pull-request check rollup is not
evidence that the governance checks ran.

## Shared surfaces

The rotating integration owner coordinates root manifests, the workspace lock,
and canonical shared CI. The protocol owner coordinates the protobuf source,
generated bindings, and wire fixtures. Feature branches should hand these
changes to the named owner rather than resolving the same generated or shared
file independently.
