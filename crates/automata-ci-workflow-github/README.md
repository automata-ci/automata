# automata-ci-workflow-github

`automata-ci-workflow-github` is Automata's loss-aware frontend for GitHub
Actions workflow YAML. It preserves source locations, reports bounded
diagnostics, compiles expressions, and evaluates jobs into provider-neutral
workflow and job models.

`automata-ci-workflow-service` uses this frontend during durable admission, and
the runner consumes its compiled GitHub expression program through a separate
runtime.

The logical plan represents bounded matrices, dependencies, conditions,
outputs, and deployment-environment syntax. The product supports only the
subset listed in the
[compatibility matrix](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md);
unsupported runtime semantics fail during compilation or admission instead of
being silently dropped.

The source model also contains an Automata-only `concurrency.queue` extension.
It is under active implementation, has no GitHub counterpart, and is not part
of the supported compatibility surface. Standard workflows should use GitHub's
`group` and `cancel-in-progress` fields.

## Updating the repository CI fixture

The repository CI fixture is an exact byte-for-byte mirror. After changing
`.ci/workflows/ci.yml`, copy and verify it with:

```console
cp .ci/workflows/ci.yml crates/automata-ci-workflow-github/tests/fixtures/repository-ci.yml
cargo test -p automata-ci-workflow-github --test ci_workflow --locked
```

The first test fails if the mirror differs from the canonical workflow. Other
compiler and service tests deliberately expose unsupported end-to-end features;
do not regenerate or weaken them to hide a compatibility failure.

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- API documentation: run `cargo doc -p automata-ci-workflow-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
