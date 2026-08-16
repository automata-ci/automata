# Automata local installation

`automata-ci-local` owns the cross-platform, disposable local-installation
boundary used by `automata local`. It validates the initial x86-64 Linux, Apple
Silicon macOS, or x86-64 Windows host tuple; a local Linux Docker Engine; Docker
API compatibility; and Compose plugin version 2.20.0 or newer. It will supervise
the local Compose project without adding container-engine behavior to the
control-plane crate.

The `automata local` user-visible surface remains read-only: `automata local doctor` performs
host preflight, while `automata local check [WORKFLOW]` validates exact local
workflow source without inspecting Docker. Context discovery for `doctor` is
completed first, subsequent daemon probes are pinned to that exact local
Unix-socket or Windows-named-pipe endpoint, and JSON schema 3 reports the
bounded context name. The private endpoint URI is retained only so the library
can pin the remaining probes in that one doctor invocation; it is not retained
in the report or exposed through a generic Engine adapter.

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

The crate also provides an evaluation-only `LocalDockerProvider` for the real
runner composition. It connects only to `/run/automata-engine/docker.sock`,
revalidates the pinned daemon and exact unattached installation anchor before
every mutation, and requires already-present digest-pinned Linux images. Each
sandbox is one sibling container with disabled networking, a writable root,
fixed resource/process limits, all capabilities dropped, built-in seccomp,
no-new-privileges, and no host binds, devices, sockets, services, or per-job
volumes. Admission requires at least 256 MiB, one CPU, and three PIDs for the
protected guest envelope. An exact memory-bounded tmpfs overlays the job
workspace so image contents cannot violate clean-workspace admission. A bounded, read-only,
non-root source container is never started: the provider exports the fixed guest
binary directly from its verified image rootfs, removes that exact container
ID, injects and reads back the bytes in the job's writable layer, and reinspects
the complete realized container configuration.

The guest is the real PID 1; Docker init is disabled. Before workload admission,
it and a distinct one-shot sealer establish an exact protected client in a
fixed `rw,exec,nosuid,nodev` control tmpfs. The sealed directory and client
cannot be traversed or changed by the capability-free UID 0 workload. Every
live operation, including readiness, uses that client as `65532:65532` against
the peer-credential-authenticated abstract broker. Exited job containers are
never restarted, and accepted live operations remain in the non-evicting guest
replay store for that container lifetime.

An installation is one reusable control-plane and runner-capacity domain, not
one repository. Repositories sharing an installation are one trusted set and
retain their own admission, authorization, secret, cache, and history scope in
the existing control plane. A separate `--installation` name is the explicit
way to request another deployment/capacity domain.

No `automata local` command invokes that provider yet. `local check` stops after
source compilation, reusable-call validation, and
credential-name discovery: it does not admit or run work, mint GitHub evidence,
request a token, or publish a Check Run. Desired specification persistence,
product-owned Compose rendering, local-run orchestration, and GitHub connection
remain separate work. The provider is consumed only when an operator explicitly
selects `local_docker` in current runner product schema 5; it does not create a
host installation manifest, desired-spec state, or Compose topology.

This crate has no command-line parser. The `automata` product maps its public
CLI into the high-level local-check request; snapshot and archive authority stay
private.
