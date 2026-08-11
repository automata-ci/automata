# automata-ci-action

`automata-ci-action` resolves repository action references into verified,
immutable, content-addressed bundles. The contracts are provider-neutral: SCM
access comes from `automata-ci-scm`, and bundle publication goes through
`automata-ci-blob`.

GitHub metadata decoding and step execution live in higher-level adapters. This
crate provides the shared resolution boundary used by `automata-runner`.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-action --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
