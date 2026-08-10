# automata-ci-workflow-github

`automata-ci-workflow-github` is Automata's loss-aware frontend for GitHub
Actions workflow YAML. It preserves source locations, reports bounded
diagnostics, compiles expressions, and evaluates jobs into provider-neutral
workflow and job models.

`automata-ci-workflow-service` uses this frontend during durable admission, and
the runner consumes its compiled GitHub expression program through a separate
runtime.

Automata is pre-1.0 and not production-ready. GitHub Actions compatibility is
incomplete, and this internal frontend's Rust API may change between releases.

The current logical plan represents bounded matrices, dependencies,
conditions, outputs, and deployment-environment syntax. The composed v0.1
product still supports only the subset listed in the
[compatibility matrix](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md);
unsupported runtime
semantics fail during compilation or admission instead of being silently
dropped.

## Updating the repository CI fixture

The repository CI fixture is an exact byte-for-byte mirror. After changing
`.github/workflows/ci.yml`, copy and verify it with:

```console
cp .github/workflows/ci.yml crates/automata-ci-workflow-github/tests/fixtures/repository-ci.yml
cargo test -p automata-ci-workflow-github --test ci_workflow --locked
```

The first test fails if the mirror differs from the canonical workflow. Other
compiler and service tests deliberately expose unsupported end-to-end features;
do not regenerate or weaken them to hide a compatibility failure.

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- [API documentation](https://docs.rs/automata-ci-workflow-github)
- [Issues and support](https://github.com/automata-ci/automata/issues)
