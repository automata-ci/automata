# automata-ci-github-delivery

`automata-ci-github-delivery` implements GitHub-specific adapters behind
Automata's common provider runtime. It resolves GitHub repository source and
changed files for normalized triggers, handles native rerun controls, publishes
provider-neutral workflow results as GitHub Checks, and discovers scheduled
workflows.

Webhook verification, normalization, durable inbox acceptance, processing
leases, workflow admission, and result scheduling are provider-neutral. This
crate receives only exact manifest-pinned context and request-scoped credential
capabilities; it does not own an alternate GitHub ingress or processing loop.

- [Authentication and authorization](https://github.com/automata-ci/automata/blob/main/docs/authentication.md)
- [Architecture](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [Issues and support](https://github.com/automata-ci/automata/issues)
