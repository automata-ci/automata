# automata-ci-runner-journal

`automata-ci-runner-journal` stores an Automata runner's crash-recovery state in
a bounded, canonical local format. It records semantic identifiers, immutable
digests, operation intentions, and recovery cursors without retaining transport
frames, provider credentials, or job payload bytes.

A lease-poll response is one journal transaction: its nested command effect,
carrier-slot successor, and pending provider-neutral authority receipts either
all survive a crash or none do, even when the command targets another slot.

`automata-ci-runner-runtime` uses the journal together with
`automata-ci-runner-spool` to reconcile interrupted work.

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-runner-journal --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
