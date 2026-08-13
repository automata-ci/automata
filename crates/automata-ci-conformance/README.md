# automata-ci-conformance

Product-owned, provider-neutral contracts for deterministic conformance
fixtures. This crate supplies the fail-closed boundary that a product or
integration-test adapter can consume; it does not claim that the separate
integration-test repository already uses these APIs.

The contracts enforce:

- byte-canonical fixture catalogs with normalized HTTPS source coordinates,
  exact commits/content digests, and namespaced immutable prerequisite locks;
- scenario admission derived from a catalog entry, including an explicit state
  for every required external prerequisite;
- evidence envelopes bound to the canonical catalog digest, fixture identity,
  evidence class, provider, operating system, and expected evidence digest;
- structural evidence comparison without type coercion, ignored fields, or
  implicit `null` values standing in for unavailable evidence;
- shard identities derived only by `ShardPlan`, then selected by
  `FixtureControl` rather than supplied by callers;
- restart records produced only after a `ServiceRestartProbe` observes a
  running generation, the same generation stopped, and exactly the next
  generation running under a new process identity;
- bounded exact-order GitHub stub scripts with strict origin-form paths and a
  whole-script response-body budget; and
- validated raw webhook fixtures that recompute their body digest when parsed.

The crate deliberately contains no live credentials, launches no processes,
and performs no provider I/O. Concrete hermetic and live adapters remain the
responsibility of the integration harness and must implement the probe and
transport boundaries defined here.
