# automata-ci-execution

`automata-ci-execution` defines provider-neutral contracts for whole-job
sandboxes, command execution, and optional container engines. Executor logic can
target Podman today and other isolation providers later without changing the
runner's durable control protocol.

`automata-ci-sandbox-podman` implements these ports, while
`automata-ci-job-executor-github` consumes them to run GitHub-compatible jobs.

- [Runner architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-execution --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
