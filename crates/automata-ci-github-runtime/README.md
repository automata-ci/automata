# automata-ci-github-runtime

Pure, bounded protocol support for the communication surface between a GitHub
Actions step and its runner. The crate performs no process or filesystem I/O;
execution adapters provide captured bytes and consume typed effects.

The compatibility baseline is `actions/runner` **v2.336.0**, immutable commit
`98aabcd429c4e8402406c56ce2d26387fed3b9ce`. The implementation was reviewed
against these exact upstream files:

- `src/Runner.Common/ActionCommand.cs`
- `src/Runner.Worker/ActionCommandManager.cs`
- `src/Runner.Worker/FileCommandManager.cs`
- `src/Runner.Worker/ActionRunner.cs`
- `src/Runner.Worker/ExecutionContext.cs`
- `src/Test/L0/Worker/ActionCommandL0.cs`
- `src/Test/L0/Worker/ActionCommandManagerL0.cs`
- `src/Test/L0/Worker/SetEnvFileCommandL0.cs`
- `src/Test/L0/Worker/SetOutputFileCommandL0.cs`
- `src/Test/L0/Worker/SaveStateFileCommandL0.cs`

`GITHUB_ARTIFACTS` and read-only `GITHUB_ARTIFACTS_LIST` are a separately
reviewed delta from upstream pull request
[#4527](https://github.com/actions/runner/pull/4527), merge commit
[`35e45850b519df66a669e2c91e0917804a33d0c7`](https://github.com/actions/runner/commit/35e45850b519df66a669e2c91e0917804a33d0c7).
That review does not silently advance the v2.336.0 baseline. The delta review
set is recorded in `GITHUB_RUNTIME_ARTIFACTS_DELTA_UPSTREAM_SOURCES`.

Upstream deliberately accepts unbounded command input. Automata retains the
valid wire grammar while imposing configurable hard ceilings. Invalid UTF-8,
malformed heredocs, invalid stop tokens, and exceeded limits fail closed. No
error or `Debug` implementation contains command data, stop tokens, or mask
values.

Artifact declarations retain upstream's fixed 1 MiB per-step file and
500-subject job ceilings. Automata also applies its general bounded line and
record limits and a 16 MiB ceiling to the deterministic artifacts-list
snapshot. File declarations remain unresolved in this pure crate; the executor
resolves them against the job workspace and hashes regular files inside the
sandbox.

## Phase contract

`CompletedStepCommands` can only be applied after a step finishes. Environment
and PATH changes therefore become input to later steps, outputs belong only to
the completed step, and `GITHUB_STATE` is keyed by the exact action invocation
for its paired post action. A run step cannot publish post-action state.

The command-file decoder consumes one leading UTF-8 BOM, selects the pinned
runner's Unix or Windows line reader explicitly, and requires heredoc
delimiters to match a complete line. Duplicate records remain in source order
so the phase applicator produces the runner's last-write-wins environment,
output, and state behavior. Empty names, empty heredoc delimiters, missing
delimiters, and otherwise malformed records fail closed without including
workflow-controlled contents in diagnostics.

The pinned runner skips a step-summary file larger than 1 MiB after emitting a
diagnostic; it does not truncate that file. Automata currently enforces the
same byte ceiling as a fail-closed decoder limit. Preserving the runner's
diagnostic-and-skip behavior across the bounded executor copy interface is a
narrow compatibility follow-up; no truncation behavior is inferred here.

The parser supports only current `::command::data` syntax. The removed
`##[command]data` syntax and `set-output`, `save-state`, `set-env`, and
`add-path` stdout mutation commands are ordinary process output. Actions must
use the bounded command files for outputs, state, environment, and path changes.
