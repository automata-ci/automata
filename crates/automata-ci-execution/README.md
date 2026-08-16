# automata-ci-execution

`automata-ci-execution` defines provider-neutral contracts for whole-job
sandboxes, command execution, and service-container discovery. Runner and
executor logic target `SandboxProvider` and `ExecutionEndpoint` without
embedding a provider-specific protocol in durable control messages.

`RuntimeServiceRoutes` carries a bounded, credential-free set of exact
HTTP(S) origins into providers which advertise `RuntimeServiceProxy`. This is
a separate side channel from general sandbox networking: a provider must
enforce the supplied scheme, host, and port set and must not infer broader
egress authority from it.

`SandboxAuthorizations` carries a canonical bounded set of opaque,
provider-owned authorization payloads from a leased execution request into
the exact `SandboxSpec`. A provider must consume only its own namespace and
payload schema before mutation; providers without such a boundary reject a
nonempty set instead of ignoring it. `SandboxExecutionBinding` accompanies a
job authorization with the exact session, run, job, attempt, lease, accepted
offer, and immutable `JobIR` identity so a restricted adapter can reject an
authorization substituted from another execution.

The Podman, Kubernetes, macOS Virtualization.framework, and Windows Hyper-V
sandbox adapters implement `SandboxProvider` directly. Providers that
advertise service-container support return the complete healthy discovery view
through `SandboxProvider::service_bindings`.

Cooperative cancellation is a closed `Active | Terminate` disposition.
`Terminate` authorizes provider-specific termination handling when an adapter
reaches a cancellation checkpoint. The disposition or an adapter return is not
evidence that remote work has quiesced; callers must prove the exact sandbox
absent before treating an uncertain durable mutation as cancelled.

- [Runner architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-execution --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
