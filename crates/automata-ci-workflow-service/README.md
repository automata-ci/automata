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

Automata is pre-1.0 and not production-ready. This is an internal application
layer, and its Rust API may change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-workflow-service)
- [Issues and support](https://github.com/automata-ci/automata/issues)
