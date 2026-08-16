# automata-ci-workflow-service

`automata-ci-workflow-service` implements provider-neutral, blob-first workflow
admission for Automata. Dialect adapters recompile exact source and verify its
current logical plan. The service publishes immutable source, event, and plan
evidence before atomically committing the logical run, invocation, job graph,
dependencies, and replay receipt. Concrete jobs and JobIR are created only by
later fenced activation.

The `automata` control plane composes the admission service with the GitHub
workflow frontend, object storage, durable repositories, and a mandatory
autonomous worker. That worker discovers durable admitted work and supervises
logical preparation, activation, and materialization. Separate database-time
result-projection and logical-run-finalization workers project terminal attempt
evidence and close runs with complete job-result graphs. Admission remains
asynchronous: its durable receipt is not a job-completion signal, and the full
runner, provider, and service-image acceptance gate remains separate.

The authenticated CLI control-plane API composes typed `workflow_dispatch`
inputs with the base runtime context and durable admission. It requires an
exact repository, workflow, branch or tag ref, and commit whose source was
already captured by an authenticated GitHub admission. Immutable dispatch
evidence and an authority-bound request digest protect replay; normal GitHub
webhook ingress does not produce `workflow_dispatch` events.

The composed endpoint is
`POST /api/v1/repositories/{repository_id}/workflows/{workflow_id}/dispatches`.
It accepts canonical internal target UUIDs plus `git_ref`, `commit_sha`,
`operation_id`, and bounded boolean/string `inputs`; actor and source fields
come only from authenticated server state. A new admission returns `201`, and
an exact replay returns the same run with `200`.

A first-party CLI command, browser form, mutable branch/tag resolution, and
complete repository variable and secret-reference hydration remain product
work. Scheduled workflows are discovered and admitted by the separate
product-supervised GitHub schedule service. The [compatibility matrix](https://github.com/automata-ci/automata/blob/main/docs/compatibility.md#v01-implementation-status)
records their experimental status and remaining acceptance gates.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-workflow-service --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
