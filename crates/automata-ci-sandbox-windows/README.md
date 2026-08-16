# automata-ci-sandbox-windows

`automata-ci-sandbox-windows` implements Automata's only Windows execution
provider: one fresh Hyper-V-isolated Windows container per job. It contains no
native-host runner, process-isolated fallback, full-VM backend, AppContainer
backend, or Windows Sandbox backend.

Status: **Component complete**. There is no supported Windows runner deployment
until the least-privilege broker, watchdog, signed image, credential custody,
and physical-host acceptance gates pass.

## Fixed isolation contract

The provider accepts only `SandboxLaunch::WindowsHyperVContainer` and requires:

- a registry-qualified digest image that is already present and reports
  Windows AMD64 metadata;
- explicit Hyper-V isolation and disabled networking;
- `ContainerUser`, unprivileged mode, and a writable disposable root;
- no host bind, named pipe, device, socket, volume, or image-declared volume;
- exact CPU and memory limits, with no disk or GPU claim; and
- one provider-owned container with immutable ownership, generation, resource,
  image, entrypoint, and policy labels.

Job-custody creation also requires exactly one `windows-hyperv` sandbox
authorization at the current broker-grant payload schema and an injected
restricted-broker consumer. That consumer canonical-decodes, validates, and
atomically spends the signed grant against stable lease-fenced sandbox policy
before the provider performs any create mutation. Direct provider construction
remains valid for profile admission only; job creation without the consumer
fails closed.

An absolute container CLI executable is pinned by SHA-256, opened without
delete/write sharing, and invoked with a cleared environment and an empty,
reparse-safe provider-owned CLI configuration directory that is revalidated
before every invocation. Fixed argv selects only the local Docker named pipe;
no user proxy, credential-helper, context, or plugin configuration is
inherited. Invocations also use no window, bounded I/O, cancellation, timeout,
and reap behavior. Workload argv, environment, and file bytes use a bounded
versioned guest protocol over anonymous standard I/O; they are never
interpolated into host shell or raw container-runtime commands.
Effective container state is inspected before the guest endpoint is exposed.
Because the Windows guest transport is one process per request, the host keeps
only request fingerprints plus bounded results in a non-durable in-memory cache
for exact endpoint-operation replay; the cache is generation-scoped and erased
on destroy. Only the portable `Kill` signal is mapped to the runtime;
unsupported graceful and interrupt signals fail without mutating the container.

CPU and memory are enforced by the Hyper-V-container runtime. Each guest
command is also created in a nested Windows Job Object before it can run. That
in-container control enforces the configured process ceiling and provides
whole-tree termination on command timeout or cancellation; it is resource
control inside the one Hyper-V-container route, not another provider.

## Durable lifecycle recovery

The provider state root contains one exclusively locked, checksummed,
synchronized, size-bounded lifecycle journal. Create intent is durable before
runtime creation; its lifecycle entry and each destroy intent together bind
the exact operation, handle, generation, profile, resource name, and spec
fingerprint. Startup replays bounded records,
removes only journal-owned resources, enumerates Automata-labelled containers,
and rejects an owned orphan or ambiguous identity. It never performs global
prune. Corrupt records, non-contiguous sequences, reparse traversal, reserved
DOS names, ownership drift, and lifecycle ambiguity fail closed.

This is a component implementation, not production acceptance. The current
direct CLI boundary must be replaced or confined by the least-privilege broker,
independent watchdog, signed-image pipeline, and physical Windows host gates in
the [Windows runner isolation plan](../../docs/platforms/windows.md).
