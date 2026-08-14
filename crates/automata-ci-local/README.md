# Automata local lifecycle

`automata-ci-local` owns the cross-platform, disposable local-installation
boundary used by `automata local`. It validates the initial x86-64 Linux, Apple
Silicon macOS, or x86-64 Windows host tuple; a local Linux Docker Engine; Docker
API compatibility; Compose plugin version 2.20.0 or newer; and an absolute,
dedicated, non-broad platform state root. It will supervise the generated local
Compose project without adding container-engine behavior to the control-plane
crate.

The first public slice is a read-only host preflight. It does not create local
state or containers. Lifecycle mutations, generated configuration, workers,
and GitHub connection are added only with their own tested contracts.

This crate has no command-line parser. The `automata` product maps its public
CLI into the typed requests exposed here.
