# automata-ci-job-executor-github

`automata-ci-job-executor-github` implements GitHub Actions-compatible step
sequencing over Automata's provider-neutral whole-job sandbox contracts. Action
resolution, credentials, expression evaluation, runtime commands, clocks, and
operation identities cross explicit ports.

`automata-runner` composes this executor with the runtime, durable recovery, and
an isolation provider such as rootless Podman.

The executor currently carries public job outputs, summaries, annotations,
command-file effects, and registered masks across the execution boundary.
Secret-derived outputs and values matching registered credentials are marked
sensitive instead of being returned as public values. The product compatibility
limit is tracked separately from this component boundary.

The executor implements the reviewed `GITHUB_ARTIFACTS` environment-file
delta: every phase receives fresh declaration and read-only list files; file
subjects resolve relative to the job workspace and are SHA-256 hashed as
regular files inside the sandbox; OCI subjects are normalized; and successful
subjects become the deterministic list visible to later phases. Parsing and
job aggregation are atomic and bounded.

Every run, JavaScript pre/main/post, and composite child phase receives a fresh
set of seven attempt-scoped paths: `GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_PATH`,
`GITHUB_STATE`, `GITHUB_STEP_SUMMARY`, `GITHUB_ARTIFACTS`, and the read-only
`GITHUB_ARTIFACTS_LIST`. The first six start empty and the list starts from the
current canonical job artifact snapshot. Paths are deterministic within one
attempt and phase for recovery, while different phases and attempts are
disjoint. Same-attempt recovery reinitializes every file before the path is
reused, so stale bytes cannot become phase input.

After an execution endpoint returns a terminal output, the executor makes a
bounded collection attempt for success, nonzero exit, timeout, and
provider-reported cancellation. Collection or parsing failure cannot replace
an already-known failure, timeout, or cancellation outcome, and command state
plus retained attachments commit atomically. A missing or deleted summary is
treated as no summary; it does not suppress other valid phase-file effects. An
independently signaled execution-cancellation token remains dominant under the
executor's cancellation contract.

## Shell dispatch contract

Shell executables come only from the immutable environment toolchain; workflow
text is never searched on `PATH` and is never executed through an extra outer
shell. The POSIX default selects configured `bash`, then configured `sh`, with
`-e`. The Windows default selects configured PowerShell Core, then configured
Windows PowerShell. Explicit POSIX `bash` uses
`--noprofile --norc -e -o pipefail`; the other named-shell argument vectors
match the pinned runner contract.

The advertised named-shell matrix is:

| Target | Named shells |
| --- | --- |
| POSIX | `bash`, `sh`, `python`, `pwsh` |
| Windows Hyper-V container | `python`, `pwsh`, `powershell`, `cmd` |

Custom command templates use a deliberately closed grammar. A template must
use single ASCII spaces, contain exactly one `{0}` as its complete final token,
contain no other braces or control characters, and select one configured
interpreter. The accepted forms are:

- `bash {0}`, `bash -e {0}`,
  `bash --noprofile --norc -e -o pipefail {0}`, and
  `bash --noprofile --norc -eo pipefail {0}`;
- `sh {0}` and `sh -e {0}`;
- `python {0}` and `python -u {0}`;
- `pwsh -File {0}` and `powershell -File {0}` (case-insensitive `-File`).

The platform matrix still applies after parsing. In particular, the current
Windows Hyper-V profile does not advertise Git Bash or `sh`; those requests
fail at admission instead of relying on a host installation. Arbitrary
executables, quoted or embedded placeholders, command modes such as `-c` or
`-Command`, and custom `cmd` templates fail closed. Literal shell contracts and
tool availability are checked during admission, before provider work. A shell
derived from an expression is checked immediately after evaluation and before
the script is copied or any user command runs. Missing configured tools surface
as a capability change; malformed or platform-incompatible contracts surface
as invalid jobs.

Scripts are UTF-8 without a BOM. POSIX scripts retain LF input. Every Windows
script is normalized to CRLF; PowerShell scripts receive error-stop and
`$LASTEXITCODE` propagation guards, and `cmd` scripts receive `@echo off`.
Extensions follow the selected interpreter (`.sh`, `.py`, `.ps1`, or `.cmd`).
The hardened `cmd` divergence uses `/D /E:ON /V:OFF /C` with the script path as
a separately bounded argv value, rather than GitHub's nested `/S /C CALL`
command string. Paths containing `"`, `%`, `&`, `|`, `<`, `>`, `^`, `(`, or
`)` are rejected for `cmd`; `!` remains literal because delayed expansion is
disabled.

The executor receives the already-resolved workflow/job working-directory
default in the job IR. A step-local directory overrides it; otherwise the
resolved default applies, then the workspace. Every resulting path remains
confined to the workspace.

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- API documentation: run `cargo doc -p automata-ci-job-executor-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
