# Automata local installation

`automata-ci-local` owns the cross-platform, disposable local-installation
boundary used by `automata local`. It validates the initial x86-64 Linux, Apple
Silicon macOS, or x86-64 Windows host tuple; a local Linux Docker Engine; Docker
API compatibility; and Compose plugin version 2.20.0 or newer. It will supervise
the local Compose project without adding container-engine behavior to the
control-plane crate.

The user-visible surface remains read-only: `automata local doctor` performs
host preflight, while `automata local check [WORKFLOW]` validates exact local
workflow source without inspecting Docker. Context discovery for `doctor` is
completed first, subsequent daemon probes are pinned to that exact local
Unix-socket or Windows-named-pipe endpoint, and JSON schema 3 reports the
bounded context name. The private endpoint URI is retained only so the library
adapter can connect to the same daemon and reverify its identity.

The private local-snapshot foundation uses live bytes for staged additions
and tracked modifications, omits tracked deletions and ignored files, and seals
each leaf through descriptor- or handle-relative, no-follow ancestor traversal.
It pins the requested directory before Git runs, resolves Git's reported prefix
back to that same directory identity, and pins the worktree, Git directory,
common directory, and no-follow `.git` locator. A regular `.git` file is admitted
only for a linked worktree and its exact bytes are retained. Every later Git
query is explicitly bound to those pinned authorities and their identities are
verified before and after the process. Caller-path or `.git` locator links,
nested-repository confusion, locator retargeting, and `core.worktree`
redirection therefore cannot select a separate tree.
Git mode deterministically represents tracked executable files and symlinks,
including symlink placeholders. Contained Unix symlinks are preserved in the
archive; shared archive policy rejects escaping links, cycles, and aliases
before analysis. Sparse-checkout and assume-unchanged index flags are rejected
because they can hide live state. Ignored-path classification is one bounded
NUL-safe batch per scan. Index conflicts, submodules, path-prefix type
conflicts, Unicode-normalization or full-case-fold aliases, nonportable device
names, non-Unicode paths, bounded component-trie or ustar exhaustion, special
files, and concurrent mutation fail closed. The current source checkpoint is
available on Unix and fails closed on Windows until exact native mutation
evidence has been qualified.

`local check` consumes that archive through one high-level analysis boundary.
Only direct `.github/workflows/*.{yml,yaml}` members are eligible, and an
optional selector must be the exact canonical member path. It accepts only an
explicit local `workflow_dispatch`, recompiles reachable same-archive reusable
workflows, rejects remote or dynamic calls, and validates typed call contracts,
cycles, propagation, and bounds through the shared traversal. Reports retain
only discovered source metadata and value-free external secret/variable names
plus closed built-in requirements. `github.token` and `secrets.GITHUB_TOKEN`
are reported as the non-promptable `github_token` built-in; this checkpoint
does not supply it for execution. Local source and event provenance is distinct
from GitHub delivery evidence. The command is independent of `local doctor`,
Docker, network access, and GitHub tokens, and performs no admission, scheduling,
execution, or Check publication.

The installation adapter can inspect or create-and-adopt one immutable external
identity volume for a named installation. It always post-inspects Docker's
deterministic volume name, exact Automata-managed labels, local driver/scope,
empty driver options, and container attachments. It exposes no generic Docker
mutation, delete, prune, image-pull, helper-container, or Compose API.

An installation is one reusable control-plane and runner-capacity domain, not
one repository. Repositories sharing an installation are one trusted set and
retain their own admission, authorization, secret, cache, and history scope in
the existing control plane. A separate `--installation` name is the explicit
way to request another deployment/capacity domain.

No product command creates, adopts, or deletes an engine resource yet.
`local check` stops after source compilation, reusable-call validation, and
credential-name discovery: it does not admit or run work, mint GitHub evidence,
request a token, or publish a Check Run. Desired specification persistence,
product-owned Compose rendering, workers, workflow execution, and GitHub
connection are added only with their own tested contracts. There is still no
host installation manifest, mirrored resource inventory, lifecycle state
machine, or secret value in this crate.

This crate has no command-line parser. The `automata` product maps its public
CLI into the high-level local-check request; snapshot and archive authority stay
private.
