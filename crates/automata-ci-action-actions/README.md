# automata-ci-action-actions

`automata-ci-action-actions` strictly decodes GitHub Actions `action.yml` and
`action.yaml` metadata from an immutable bundle resolved by
`automata-ci-action`. It applies explicit input limits and preserves values and
expressions for later compilation rather than executing them during parsing.

This adapter sits between provider-neutral action resolution and the GitHub
job executor used by `automata-runner`.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-action-actions --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
