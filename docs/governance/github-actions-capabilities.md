# GitHub Actions capability and reference governance

[`github-actions-capabilities-v1.json`](github-actions-capabilities-v1.json) is
the fail-closed contract between workflow decoding and product compatibility.
It maps every accepted workflow/action field to a feature, gives every feature
its own independently reviewed decode, compile, projection, publication,
admission, scheduler, Linux, Windows, Kubernetes, Results, and differential
profile, and binds every compatibility-table claim to one or more attributed
Rust acceptance fixtures. Every fixture names semantic fragments that must
remain inside the test body, so replacing it with an unrelated non-empty test
fails validation. Profiles cannot be shared between features, so a supported
service-container path cannot hide a rejected job-container path in an
aggregate status. `Component complete` is explicit; it is never inferred from
a decoder or parser test.

Run the registry and mutation checks before changing a decoder, compiler,
runtime capability, or compatibility claim:

```console
python3 scripts/ci/verify-github-actions-capabilities.py
python3 scripts/ci/tests/github-actions-capabilities.test.py
```

The validator extracts accepted field names directly from the decoders. A new
field therefore fails CI until its feature mapping, evaluation phase, stage
profile, runtime/provider capability requirements, stable rejection behavior,
and acceptance fixtures are reviewed in the same change. Normally executed
tests may not be ignored or conditionally compiled. A fixture with an external
prerequisite may use `#[ignore]` only when it declares a machine-checked CI lane
whose workflow invokes the named runner and whose exact Cargo command selects
the package/test set with `--ignored`. The managed-secret lifecycle fixtures,
for example, are tied to the PostgreSQL lane rather than merely existing in the
source tree. Job, step, environment,
runner-selection, and resource fields are extracted in their defining function
scope, so identical YAML keys such as job-level and step-level `uses` cannot be
silently assigned to the same feature. It also extracts every
`AdmissionRejection` and `ExecutorErrorKind` variant from the runner-runtime
port and requires a stable classification and feature owner. The provider
event inventory is separately extracted from authenticated webhook
normalization. Decoder-recognized events outside that inventory must use the
rejected decoder-only profile; adding a normalizer arm fails CI until its
feature mapping is reviewed. The compatibility table in
[`docs/compatibility.md`](../compatibility.md) is checked for exact area and
status equality with the registry.

An attributed fixture is scoped evidence for the semantic fragments recorded
beside it; it is not, by itself, proof of every sentence in a compatibility
row or of production acceptance. Status profiles and each row's remaining-work
column continue to state those wider gaps. Features may bind multiple fixtures
when their claimed boundary crosses components. Managed secrets bind separate
PostgreSQL create/activate/read/delete and replacement scenarios plus normal
runner custody and durable value-free overlay tests.

## Unsupported semantics

Unsupported source syntax must be diagnosed before a run is published. Keep a
stable machine-readable diagnostic code and an exact source-span policy. A
renamed or removed code requires an explicit migration entry; do not silently
reuse a code for different semantics. The append-only
[`github-actions-diagnostic-history-v1.json`](github-actions-diagnostic-history-v1.json)
lock is separate from the active registry, so deleting an emitter and its
active registry row still requires a migration. Feature-level rejection
mappings must resolve to the same diagnostic owner and span policy. Projection
guards may remain for logical plans constructed by other frontends, but the
GitHub compiler must reject a known non-runnable GitHub field first.

An unsupported product surface does not need to invent a compiler diagnostic.
For example, arbitrary GitHub REST fallback is bound to the actual HTTP 404
route and its attributed response test; it is not represented as a nonexistent
workflow diagnostic.

## Replacing upstream references

[`github-actions-reference-snapshot-v1.json`](github-actions-reference-snapshot-v1.json)
pins the reviewed GitHub documentation and `actions/runner` sources by immutable
URL, byte count, SHA-256 digest, retrieval date, and parser version.
[`github-actions-reviewed-deltas-v1.json`](github-actions-reviewed-deltas-v1.json)
records review coverage for syntax, contexts, permissions, events, limits,
variables, default variables, and action runtimes.

Each reviewed delta is closed metadata, not free-form prose: its decision must
be `approved-baseline` or `approved-delta-without-baseline-advance`, and its
review date must be a real
canonical ISO 8601 date, and it must name at least two distinct canonical human
reviewer IDs. Source revisions are one or more lowercase GitHub `owner/repo`
names pinned to full 40-character object IDs. Every delta also binds at least
one sorted reference-snapshot ID; a review record with no immutable reference
link cannot satisfy the replacement gate.

To replace a pin:

1. Fetch the exact proposed GitHub documentation and `actions/runner`
   revisions, calculate their byte counts and digests, and compare them with
   the currently pinned immutable sources.
2. Review the bounded source delta and its compatibility impact. Update code,
   fixtures, stage claims, and diagnostics before changing the snapshot.
3. Record the immutable source revision, affected categories, decision, and at
   least two distinct human reviewers in the reviewed-delta registry.
4. Replace the snapshot metadata and run both registry checks. Never replace a
   digest without reviewing the bounded source delta.
