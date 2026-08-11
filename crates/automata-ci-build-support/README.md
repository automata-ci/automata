# automata-ci-build-support

`automata-ci-build-support` provides build-time provenance helpers for the
`automata` and `automata-runner` executables. Their build scripts use it to
embed a validated source commit and to require provenance for distribution
builds.

This crate is a build dependency only; it provides no command or runtime
service.

- [Development documentation](https://github.com/automata-ci/automata/blob/main/docs/development.md)
- API documentation: run `cargo doc -p automata-ci-build-support --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
