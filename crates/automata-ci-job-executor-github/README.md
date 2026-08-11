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

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- API documentation: run `cargo doc -p automata-ci-job-executor-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
