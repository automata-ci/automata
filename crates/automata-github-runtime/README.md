# automata-github-runtime

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

Upstream deliberately accepts unbounded command input. Automata retains the
valid wire grammar while imposing configurable hard ceilings. Invalid UTF-8,
malformed heredocs, invalid stop tokens, and exceeded limits fail closed. No
error or `Debug` implementation contains command data, stop tokens, or mask
values.

## Phase contract

`CompletedStepCommands` can only be applied after a step finishes. Environment
and PATH changes therefore become input to later steps, outputs belong only to
the completed step, and `GITHUB_STATE` is keyed by the exact action invocation
for its paired post action. A run step cannot publish post-action state.

The parser supports both current `::command::data` syntax and the runner's
legacy `##[command]data` syntax. Deprecated `set-output` and `save-state` are
represented as typed mutations. Insecure `set-env` and `add-path` stdout
commands remain disabled unless explicitly enabled in `WorkflowCommandPolicy`,
matching the upstream opt-in behavior.
