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

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-runner-spool --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
