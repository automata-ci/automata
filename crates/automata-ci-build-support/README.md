# automata-ci-build-support

`automata-ci-build-support` provides build-time provenance helpers for the
`automata` and `automata-runner` executables. Their build scripts use it to
embed a validated source commit and to require provenance for distribution
builds.

This crate is a build dependency only; it provides no command or runtime
service.

Automata is pre-1.0 and not production-ready. This helper follows the product's
release process and has no standalone compatibility guarantee.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- [API documentation](https://docs.rs/automata-ci-build-support)
- [Issues and support](https://github.com/automata-ci/automata/issues)
