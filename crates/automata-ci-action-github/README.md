# automata-ci-action-github

`automata-ci-action-github` strictly decodes GitHub Actions `action.yml` and
`action.yaml` metadata from an immutable bundle resolved by
`automata-ci-action`. It applies explicit input limits and preserves values and
expressions for later compilation rather than executing them during parsing.

This adapter sits between provider-neutral action resolution and the GitHub
job executor used by `automata-runner`.

Automata is pre-1.0 and not production-ready. This is an internal compatibility
layer; supported metadata and its Rust API may change between releases.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- [API documentation](https://docs.rs/automata-ci-action-github)
- [Issues and support](https://github.com/automata-ci/automata/issues)
