# automata-ci-output-policy

`automata-ci-output-policy` defines the neutral publication policy shared by
authentication, persistence, UI, and secret-delivery layers. Dashboard, log,
and artifact audiences are independently configurable, then restricted by an
immutable secret-exposure safety ceiling.

Policy and safety classifications use stable, snake-case Serde representations
for durable snapshots. Snapshots require all three audience fields; missing or
unknown fields and unknown variants are rejected. The explicit Rust `Default`
still sets every audience to private for callers constructing a new policy in
memory.

Automata is pre-1.0 and not production-ready. This is an internal security
boundary, and its Rust API may change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-output-policy)
- [Issues and support](https://github.com/automata-ci/automata/issues)
