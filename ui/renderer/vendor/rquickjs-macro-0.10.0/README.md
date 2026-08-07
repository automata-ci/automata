# Deterministic rquickjs macro patch

This directory vendors `rquickjs-macro` 0.10.0 from crates.io, whose archive
has SHA-256
`89f93602cc3112c7f30bf5f29e722784232138692c7df4c52ebbac7e035d900d`
and whose upstream Git revision is
`96987d4c61a203ce4468331a8a8c81f285e67171`.

Automata changes the two procedural-macro collections that are iterated while
generating Rust tokens from randomized `HashMap`s to insertion-ordered
`IndexMap`s. The
upstream implementation otherwise emits a different renderer component on
each clean build because JavaScript module declarations and class accessors are
expanded in a process-random order.

Automata also replaces the reachable `todo!()` branches in `#[methods]`
self-type naming with a deterministic, span-bound `syn::Error`. Unsupported
array, reference, and recursively nested tuple members therefore emit a normal
`compile_error!` diagnostic instead of panicking in the procedural macro. This
does not broaden the set of supported self types.

Upstream's inline embed tests have been moved to the external `tests/` tree.
The same contract suite also exercises method self-type naming and confirms
that ordinary class fields without `get` or `set` options expand to no
JavaScript property. The accessor expansion now represents that valid state as
`None` instead of relying on a caller-only panic invariant. Tuple-field access
and tracing use `syn::Index`, avoiding `format_ident!` panics on valid numeric
members. Missing `CARGO_MANIFEST_DIR` while resolving a relative embedded
module is likewise reported as a span-bound diagnostic rather than a macro
panic.

The package manifest is narrowed to the exact dependency versions and features
used by Automata's reviewed `p2,encoding` renderer profile. The original source
is MIT licensed; see `LICENSE`.
