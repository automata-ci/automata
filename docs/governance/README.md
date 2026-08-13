# Foundation governance registry

[`foundation-governance-v1.json`](foundation-governance-v1.json) is the
machine-readable coordination boundary for the GitHub Actions parity
foundations. It records the current internal format versions and owners, the
canonical greenfield migration inventory, selected shared surfaces, and the
first reviewed limit entries.

The registry is deliberately a bootstrap inventory. Its `status` remains
`bootstrap` until every durable/wire format and every GitHub or stricter
Automata limit is cataloged. An entry documents an existing contract; it does
not make an unsupported product surface available.

Run the validator before changing a registered source, migration, test, or
shared surface:

```console
python3 scripts/ci/verify-foundation-governance.py
python3 scripts/ci/tests/foundation-governance.test.py
```

The validator rejects unknown fields, non-canonical JSON, duplicate or
unsorted identifiers, missing owners and paths, source/version drift, migration
inventory drift, and limit entries without bound reason codes and explicit
boundary tests.

## Changing a format

The format owner coordinates the version, reader policy, fixtures, and tests
in one change. Update the implementation first, then update the registry to
the same exact source evidence. `exact-current-only` means a version change is
breaking until an explicit compatibility reader policy is designed and
recorded; it must not be inferred from permissive deserialization.

## Changing the store schema

The repository currently has a canonical greenfield database with no supported
upgrade source. Its complete schema lives in
`0001_initial_schema.sql`, and new deployments start from an empty database.
While the registry's migration mode is `greenfield-canonical-baseline`, change
that canonical file and its empty-database tests instead of adding `0002` or
reserving a historical sequence number.

A future decision to support durable upgrades must first change the governance
mode and define reservation, immutability, forward-reader, rollback, and mixed-
version rules. Parallel feature branches must not invent that transition.

## Changing a limit

Each limit records whether it mirrors GitHub or is a stricter Automata safety
boundary, its single owner, enforcement phase, stable reason code, source
constant, and tests for `limit - 1`, `limit`, and `limit + 1`. Add the inventory
entry in the same change that introduces a new enforced limit.

## Shared surfaces

The rotating integration owner coordinates root manifests, the workspace lock,
and canonical shared CI. The protocol owner coordinates the protobuf source,
generated bindings, and wire fixtures. Feature branches should hand these
changes to the named owner rather than resolving the same generated or shared
file independently.
