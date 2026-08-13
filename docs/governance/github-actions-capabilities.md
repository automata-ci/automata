# GitHub Actions capability and reference governance

[`github-actions-capabilities-v1.json`](github-actions-capabilities-v1.json) is
the fail-closed contract between workflow decoding and product compatibility.
It maps every accepted workflow/action field to a feature, gives every feature
an independently reviewed decode, compile, projection, publication, admission,
scheduler, Linux, Windows, Kubernetes, Results, and differential profile, and
binds every compatibility-table claim to an attributed Rust acceptance test.
`Component complete` is an explicit stage profile; it is never inferred from a
decoder or parser test.

Run the registry and mutation checks before changing a decoder, compiler,
runtime capability, or compatibility claim:

```console
python3 scripts/ci/verify-github-actions-capabilities.py
python3 scripts/ci/tests/github-actions-capabilities.test.py
```

The validator extracts accepted field names directly from the decoders. A new
field therefore fails CI until its feature mapping, evaluation phase, stage
profile, runtime/provider capability requirements, stable rejection behavior,
and acceptance fixture are reviewed in the same change. The compatibility
table in [`docs/compatibility.md`](../compatibility.md) is checked for exact
area and status equality with the registry.

## Unsupported semantics

Unsupported source syntax must be diagnosed before a run is published. Keep a
stable machine-readable diagnostic code and an exact source-span policy. A
renamed or removed code requires an explicit migration entry; do not silently
reuse a code for different semantics. Projection guards may remain for logical
plans constructed by other frontends, but the GitHub compiler must reject a
known non-runnable GitHub field first.

## Replacing upstream references

[`github-actions-reference-snapshot-v1.json`](github-actions-reference-snapshot-v1.json)
pins the reviewed GitHub documentation and `actions/runner` sources by immutable
URL, byte count, SHA-256 digest, retrieval date, and parser version.
[`github-actions-reviewed-deltas-v1.json`](github-actions-reviewed-deltas-v1.json)
records review coverage for syntax, contexts, permissions, events, limits,
variables, default variables, and action runtimes.

To replace a pin:

1. Run the scheduled detector or run
   `scripts/ci/check-github-actions-reference-drift.py` with explicit output
   and Markdown paths.
2. Review the bounded source delta and its compatibility impact. Update code,
   fixtures, stage claims, and diagnostics before changing the snapshot.
3. Record the immutable source revision, affected categories, decision, and at
   least two distinct human reviewers in the reviewed-delta registry.
4. Replace the snapshot metadata and run both registry checks. Never replace a
   digest solely because the detector reported drift.

The weekly GitHub-hosted detector verifies the old immutable bytes first,
compares the same files at the current documentation commit and latest stable
runner release, and opens or updates one bounded review issue. That issue is a
review prompt, not approval to move the baseline.
