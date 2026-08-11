# automata-ci-runner-journal

`automata-ci-runner-journal` stores an Automata runner's crash-recovery state in
a bounded, canonical local format. It records semantic identifiers, immutable
digests, operation intentions, and recovery cursors without retaining transport
frames, provider credentials, or job payload bytes.

`automata-ci-runner-runtime` uses the journal together with
`automata-ci-runner-spool` to reconcile interrupted work.

- [Runner documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-runner-journal --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
