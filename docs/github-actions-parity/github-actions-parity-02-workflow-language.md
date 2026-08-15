# GitHub Actions parity: Workflow language, expressions, and runtime contexts

Close YAML, expression, evaluation-phase, hashFiles, context, variable, and reserved-environment semantics.

This is one workstream in the
[GitHub Actions parity parallel execution plan](../github-actions-parity-execution-plan.md).
The [compatibility page](../compatibility.md) remains the source of truth for
current support; unchecked tasks in this file are planned work.

**Accountable lane:** Lane W, with runner and control-plane reviewers.

**Package IDs:** WF-01, WF-02, WF-03, WF-04, WF-05, WF-06.

## Related workstreams

- [Foundations, conformance, and governance](github-actions-parity-01-foundations.md)
- [Event ingress, identity, secrets, environments, OIDC, and security](github-actions-parity-06-trust-security.md)

Execution follows package dependencies rather than document order. Open the
parent plan for staffing waves, shared ownership locks, and the common
definition of done.

## Work packages

### WF-01 — Bounded YAML anchor and alias expansion

**Owner:** W. **Size:** L. **Dependencies:** FND-01.

**Primary scope:** workflow YAML syntax AST/parser, compiler safety pass,
frontend, and YAML tests.

Tasks:

- [ ] Build an anchor table from the existing anchor and alias AST nodes.
- [ ] Expand mapping, sequence, and scalar aliases before decode.
- [ ] Preserve alias-use span and definition provenance.
- [ ] Match verified duplicate-anchor and forward-reference behavior.
- [ ] Reject undefined aliases and cycles.
- [ ] Bound alias count, recursion, expanded nodes, scalar bytes, and total
  expansion to prevent alias bombs.
- [ ] Continue rejecting merge keys and custom tags unless separately proven
  compatible.
- [ ] Remove the unconditional anchor rejection only when the bounded pass is
  active.

Acceptance:

- [ ] Anchored and equivalent expanded workflows produce equivalent logical
  plans.
- [ ] Fixtures cover aliases in `env`, jobs, steps, services, and complete job
  definitions.
- [ ] Chained, repeated, duplicate, undefined, cyclic, and amplification cases
  fail or pass at the verified phase with useful spans.

Do not combine this security-sensitive work with general YAML cleanup.

### WF-02 — Workflow size, YAML semantics, schema, and diagnostics

**Owner:** W. **Size:** M. **Dependencies:** FND-01. **Parallel with:** WF-01
only if file ownership is partitioned.

Tasks:

- [ ] Change the default workflow source limit from 2 MiB to 500 KB at the
  verified pre/post-normalization phase.
- [ ] Test exact size boundaries, UTF-8 BOM, CRLF/LF, empty input, trailing
  documents, quoted/unquoted `on`, and YAML 1.2 scalars.
- [ ] Distinguish duplicate, unknown, unsupported, and type-invalid fields.
- [ ] Verify `.yml` and `.yaml` discovery.
- [ ] Complete `run-name`, workflow/job/step `env`, and `defaults.run`
  precedence tests.
- [ ] Reject decoded-but-unexecutable fields using FND-01 diagnostics.
- [ ] Document any stricter depth, scalar, collection, and expansion bounds.

Acceptance:

- [ ] All boundary tests are deterministic.
- [ ] No field is accepted merely because an unknown-field map retains it.
- [ ] Diagnostic classes and spans are stable.

### WF-03 — Expression semantic closure

**Owner:** W. **Size:** L. **Dependencies:** FND-01.

**Primary scope:** workflow expression compiler and
`automata-ci-expression-github` evaluator.

Tasks:

- [ ] Make compiler and evaluator arity rules agree, especially zero-argument
  `success()` and `failure()`.
- [ ] Add table-driven coercion tests for null, empty strings, numeric strings,
  hexadecimal, exponents, negative zero, and NaN.
- [ ] Match case-insensitive string equality, array/object identity, missing
  properties, and wildcard projection.
- [ ] Verify short-circuit behavior prevents evaluation of unavailable
  contexts and functions.
- [ ] Verify arity and conversion for `contains`, `startsWith`, `endsWith`,
  `format`, `join`, `fromJSON`, `toJSON`, and status functions.
- [ ] Bound `fromJSON` input and nesting.
- [ ] Prevent `toJSON` from exposing opaque secret material.
- [ ] Decide whether `case` is rejected in GitHub mode or documented as an
  extension.
- [ ] Fail malformed interpolation and unsupported calls at compile time.

Acceptance:

- [ ] Every expression accepted by the compiler has an evaluator path.
- [ ] No built-in silently falls through to an unavailable extension.
- [ ] Deviations from the pinned runner have explicit fixtures and policy.

### WF-04 — Declarative context and evaluation-phase registry

**Owner:** W. **Size:** L. **Dependencies:** WF-03, FND-01.

Tasks:

- [ ] Extract hardcoded field policies into a registry mapping YAML location
  to evaluation phase, allowed contexts/functions, secret availability, and
  result type.
- [ ] Cover `run-name`, conditions, matrices, `env`, defaults, `with`, outputs,
  environments, and concurrency.
- [ ] Generate positive and negative context-availability tests.
- [ ] Distinguish unavailable context, missing property, null, and empty
  string.
- [ ] Document which subsystem produces `github`, `needs`, `strategy`,
  `matrix`, `job`, `runner`, `steps`, `env`, `vars`, `inputs`, and `secrets`.
- [ ] Require a registry entry whenever a new expression-bearing field is
  added.

Acceptance:

- [ ] Compiler policy and runtime context producers cannot drift silently.
- [ ] Generated tests cover every registered location.

### WF-05 — Production `hashFiles()`

**Owner:** W defines the contract; R integrates it. **Size:** L.
**Dependencies:** WF-03, FND-03.

Tasks:

- [ ] Specify workspace-rooted glob, ordered negation, separator, case,
  symlink, missing-file, and directory behavior.
- [ ] Implement a production extension provider instead of
  `NoExtensionFunctions`.
- [ ] Sort matches deterministically and match GitHub aggregation hashing.
- [ ] Reject workspace traversal and reparse/symlink escape.
- [ ] Handle duplicate matches, empty files, inaccessible paths, and
  cancellation.
- [ ] Run the same fixture on Linux and Windows.

Acceptance:

- [ ] Results are independent of filesystem enumeration order.
- [ ] Evaluation occurs only when an eligible workspace exists.
- [ ] No glob can read outside the checkout root.

### WF-06 — Runtime contexts, variables, and reserved environment surface

**Owner:** R; C supplies authenticated facts and W reviews availability tests.
**Size:** L. **Dependencies:** WF-04, AUTH-02, CFG-02.

Tasks:

- [ ] Populate missing actor, triggering actor, repository/owner IDs,
  ref-protection, retention, action-ref, and secret-source fields.
- [ ] Correct pull-request ref name and type.
- [ ] Populate action-only values only during the matching invocation.
- [ ] Add x86 and ARM context mappings where supported.
- [ ] Set `RUNNER_DEBUG` and `runner.debug` from the debug policy.
- [x] Preserve the current phase-correct environment reconstruction for job
  and step overlays, command-file and `PATH` updates, and top-level or nested
  action post templates.
- [ ] Rotate command-file paths per phase.
- [ ] Implement complete `steps` outcome/conclusion and reusable `jobs`
  context behavior.
- [x] Enforce immutability for documented default variables in the `GITHUB_*`
  and `RUNNER_*` namespaces while preserving custom names and the documented
  `CI` exception.
- [ ] Apply organization, repository, and environment variable precedence and
  limits.

Acceptance:

- [ ] A generated field-by-field suite validates values and phase
  availability.
- [x] Lowercase or case-variant attempts cannot shadow reserved Windows
  variables.
- [ ] Unset values match GitHub empty/null behavior.

---

[Previous: Foundations, conformance, and governance](github-actions-parity-01-foundations.md) · [Next: Matrices, scheduling, dependencies, and reusable workflows](github-actions-parity-03-scheduling-reuse.md)
