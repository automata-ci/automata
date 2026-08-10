# automata-ci-execution

`automata-ci-execution` defines provider-neutral contracts for whole-job
sandboxes, command execution, and optional container engines. Executor logic can
target Podman today and other isolation providers later without changing the
runner's durable control protocol.

`automata-ci-sandbox-podman` implements these ports, while
`automata-ci-job-executor-github` consumes them to run GitHub-compatible jobs.

Automata is pre-1.0 and not production-ready. This is an internal architecture
layer, and its Rust API may change between releases.

- [Runner architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-execution)
- [Issues and support](https://github.com/automata-ci/automata/issues)
