# automata-ci-workflow-actions

`automata-ci-workflow-actions` is Automata's loss-aware frontend for GitHub
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

## YAML anchors and aliases

The frontend expands scalar, sequence, and mapping aliases in a derived YAML
tree before semantic decoding. The original document remains available as
source evidence; copied nodes use the alias token as their primary span and
retain the selected definition span in expansion provenance. Duplicate anchor
names rebind subsequent aliases without changing earlier bindings, matching the
pinned parser's point-in-time identities. Forward and undefined aliases, cycles,
merge keys, and custom tags fail with distinct diagnostics.

Expansion is independently bounded by alias uses, nested substitutions,
expanded nodes, decoded scalar bytes, and aggregate work. The defaults are
1,024 alias uses, depth 64, 100,000 expanded nodes, 8 MiB of expanded scalar
text, and 1,000,000 work units. Embedders can lower each ceiling through
`WorkflowParseLimits`.

The source model also contains an Automata-only `concurrency.queue` extension.
It is under active implementation, has no GitHub counterpart, and is not part
of the supported compatibility surface. Standard workflows should use GitHub's
`group` and `cancel-in-progress` fields.

- [Compatibility documentation](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md)
- API documentation: run `cargo doc -p automata-ci-workflow-actions --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
