# automata-ci-sandbox-windows

`automata-ci-sandbox-windows` implements Automata's whole-job sandbox contracts
for trusted native Windows jobs. Each sandbox owns fresh workspace and scratch
directories beneath one dedicated provider root and one Windows Job Object
with hard memory, CPU, and process caps.
Every child is assigned to the Job Object before it can run, and timeout,
cancellation, destroy, provider shutdown, and Job Object handle closure stop the
complete process tree.

This adapter deliberately provides process containment, not a container or VM.
It advertises host network, host filesystem, and host identity semantics,
requires `SandboxPrivilegePolicy::Host`, rejects service containers, clears the
ambient process environment, and allows file transfer only beneath the exact
owned workspace and scratch roots. Secret-marked profile defaults are rejected
before replay material is written; job and step secrets remain ephemeral exec
environment values.

## Mandatory account boundary

`processkit` 3.2 does **not** mint a restricted Windows access token. Every
child retains the token of the runner process. Job Objects contain the process
tree and enforce resource limits; they do not remove account privileges or
provide token-based privilege isolation. The provider's explicit `Host`
identity policy is an admission acknowledgement, not evidence that the token
is restricted. Deployment therefore **must** use a dedicated,
non-administrative Windows runner account and execute only trusted workflows.
Do not deploy it as Administrator, LocalSystem, or another privileged service
identity. Operator provisioning is responsible for that account boundary; the
current startup path does not attest or enforce the runner token's privilege
level. `HostIdentity` explicitly means that children inherit that token.

## Executable packaging requirement

Executables installed through MSIX/AppX under `WindowsApps` are unsupported.
Those packaged processes can inherit a package-managed Job Object; Windows can
then reject later assignment of an ordinary process to the sandbox's lifetime
Job Object with `ERROR_ACCESS_DENIED`. The provider deliberately fails closed
instead of replacing the Job Object or allowing a process to break away. Install
standalone executables instead (for example, the Program Files distribution of
PowerShell 7). Inbox Windows PowerShell remains supported for an explicit
`shell: powershell` step, but it does not replace the required standalone
`pwsh.exe` installation.

## Durable lifecycle recovery

The provider root contains one exclusively locked, checksummed append-only
event WAL. A synced `CreateIntent` precedes workspace creation, and a synced
`DestroyIntent` binds the caller's exact operation ID, handle, generation, and
profile before any process is quiesced or any directory is deleted. Phase and
completion records make directory creation and deletion idempotently
recoverable. Reopen parses the WAL as a bounded-memory stream, rejects corrupt
or non-contiguous records, and truncates only an unterminated final record left
by an interrupted append.

Windows Job Object handles and endpoint replay results do not survive provider
shutdown. Attached endpoints retain the provider lifetime and its exclusive WAL
lock, so another provider cannot reopen or reuse workspace paths while a stale
endpoint operation can still run. Before `open` returns, every recovered live
or partial entry is therefore treated as an orphan: an existing exact destroy
intent is completed,
or an internal recovery destroy intent is synced first, then scratch and
workspace are removed and the handle becomes a durable `Absent` tombstone. The
provider never reports a replacement empty Job Object as the old running
sandbox and never permits attach after reopen. Exact create/destroy witnesses
and tombstones are retained indefinitely so an old operation ID can never
allocate a second resource. The WAL grows linearly until ordinary storage
exhaustion; this version has no silent replay eviction or fixed whole-history
cap. Corrupt, path-escaping, overlapping, or concurrently opened state is
rejected before the provider is registered.

Automata is pre-1.0 and not production-ready. This adapter's host requirements
and Rust API may change between releases.
