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

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- API documentation: run `cargo doc -p automata-ci-job-executor-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
