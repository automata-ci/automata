# automata-ci-job-executor-github

`automata-ci-job-executor-github` implements GitHub Actions-compatible step
sequencing over Automata's provider-neutral whole-job sandbox contracts. Action
resolution, credentials, expression evaluation, runtime commands, clocks, and
operation identities cross explicit ports.

`automata-runner` composes this executor with the runtime, durable recovery, and
an isolation provider such as rootless Podman.

Automata is pre-1.0 and not production-ready. GitHub Actions compatibility is
incomplete, and this internal adapter's Rust API may change between releases.

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- [API documentation](https://docs.rs/automata-ci-job-executor-github)
- [Issues and support](https://github.com/automata-ci/automata/issues)
