# automata-ci-execution

`automata-ci-execution` defines provider-neutral contracts for whole-job
sandboxes, command execution, and service-container discovery. Runner and
executor logic target `SandboxProvider` and `ExecutionEndpoint` without
embedding a provider-specific protocol in durable control messages.

The Podman, Kubernetes, macOS Virtualization.framework, and Windows Hyper-V
sandbox adapters implement `SandboxProvider` directly. Providers that
advertise service-container support return the complete healthy discovery view
through `SandboxProvider::service_bindings`.

- [Runner architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-execution --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
