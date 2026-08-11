# automata-ci-github

`automata-ci-github` contains bounded HTTP adapters for GitHub authentication,
membership, and repository APIs. It centralizes trusted-origin policy,
pagination limits, response validation, and secret-safe error handling for the
Automata control plane and runner.

Provider-neutral identity and SCM contracts remain in `automata-ci-auth` and
`automata-ci-scm`.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
