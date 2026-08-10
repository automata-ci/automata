# automata-ci-github

`automata-ci-github` contains bounded HTTP adapters for GitHub authentication,
membership, and repository APIs. It centralizes trusted-origin policy,
pagination limits, response validation, and secret-safe error handling for the
Automata control plane and runner.

Provider-neutral identity and SCM contracts remain in `automata-ci-auth` and
`automata-ci-scm`.

Automata is pre-1.0 and not production-ready. This is an internal provider
adapter, and its configuration and Rust API may change between releases.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- [API documentation](https://docs.rs/automata-ci-github)
- [Issues and support](https://github.com/automata-ci/automata/issues)
