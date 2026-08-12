# automata-ci-sandbox-macos

`automata-ci-sandbox-macos` executes trusted ARM64 macOS jobs as native
processes. Each job receives fresh workspace and scratch directories below one
dedicated provider root. Commands run under a same-binary supervisor that owns
their POSIX process group and terminates it on timeout, cancellation, provider
shutdown, or runner/control-channel loss.

This provider is deliberately not a hostile-workload boundary. It advertises
the host network, host filesystem, unchanged host identity, and shared host
resources. Deploy it only under a dedicated non-administrative runner account
and only for trusted repositories. Per-job CPU, memory, process, filesystem,
identity, and network isolation require the separate Virtualization.framework
provider.

Lifecycle mutations are operation-replay safe and generation fenced. The
provider owns and exclusively locks its state root, persists checksummed
create/destroy events before filesystem mutation, rejects corrupt history, and
recovers unfinished sandboxes by terminating their supervisor and removing the
owned directories.

Automata is pre-1.0 and not production-ready.
