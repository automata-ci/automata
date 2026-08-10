# automata-ci-runner-spool

`automata-ci-runner-spool` provides crash-durable, content-addressed local
storage for Automata runner recovery payloads. Construction requires an
explicit protection adapter, and publication is coordinated with the runner
journal so payload-first crash leftovers can be reclaimed safely.

`automata-ci-runner-crypto` supplies the current at-rest protector;
`automata-ci-runner-runtime` consumes durable content references during
recovery.

The protector port exposes one active ID for all new publications and may
explicitly support bounded decrypt-only IDs for online key rotation. Load,
authenticated removal, and reconciliation require the exact protection ID in
the durable reference. An unknown ID fails before missing-file or idempotent
deletion behavior can hide a retired key.

Automata is pre-1.0 and not production-ready. This is an internal durability
layer; its Rust API and local format may change between releases.

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- [API documentation](https://docs.rs/automata-ci-runner-spool)
- [Issues and support](https://github.com/automata-ci/automata/issues)
