# Automata local installation

`automata-ci-local` owns the cross-platform, disposable local-installation
boundary used by `automata local`. It validates the initial x86-64 Linux, Apple
Silicon macOS, or x86-64 Windows host tuple; a local Linux Docker Engine; Docker
API compatibility; and Compose plugin version 2.20.0 or newer. It will supervise
the local Compose project without adding container-engine behavior to the
control-plane crate.

The user-visible slice remains a read-only host preflight. Context discovery is
completed first, subsequent daemon probes are pinned to that exact local
Unix-socket or Windows-named-pipe endpoint, and JSON schema 3 reports the
bounded context name. The private endpoint URI is retained only so the library
adapter can connect to the same daemon and reverify its identity.

The first engine adapter can inspect or create-and-adopt one immutable external
identity volume for a named installation. It always post-inspects Docker's
deterministic volume name, exact Automata-managed labels, local driver/scope,
empty driver options, and container attachments. It exposes no generic Docker
mutation, delete, prune, image-pull, helper-container, or Compose API.

An installation is one reusable control-plane and runner-capacity domain, not
one repository. Repositories sharing an installation are one trusted set and
retain their own admission, authorization, secret, cache, and history scope in
the existing control plane. A separate `--installation` name is the explicit
way to request another deployment/capacity domain.

No product command creates, adopts, or deletes an engine resource yet. Desired
specification persistence, product-owned Compose rendering, workers, workflow
execution, and GitHub connection are added only with their own tested
contracts. There is still no host installation manifest, mirrored resource
inventory, lifecycle state machine, or secret value in this crate.

This crate has no command-line parser. The `automata` product maps its public
CLI into the typed requests exposed here.
