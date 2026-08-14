# Automata local installation

`automata-ci-local` owns the cross-platform, disposable local-installation
boundary used by `automata local`. It validates the initial x86-64 Linux, Apple
Silicon macOS, or x86-64 Windows host tuple; a local Linux Docker Engine; Docker
API compatibility; and Compose plugin version 2.20.0 or newer. It will supervise
the local Compose project without adding container-engine behavior to the
control-plane crate.

The user-visible slice remains a read-only host preflight. It deliberately does
not create a host installation manifest, resource inventory, lifecycle state
machine, Docker-version pin, or secret value. Engine identity and ownership
contracts land with the first Docker adapter that consumes and
integration-tests them; they are not published as unused speculative APIs.

No product command creates, adopts, or deletes an engine resource yet. The
Docker adapter, checked-in Compose topology, workers, workflow execution, and
GitHub connection are added only with their own tested contracts.

This crate has no command-line parser. The `automata` product maps its public
CLI into the typed requests exposed here.
