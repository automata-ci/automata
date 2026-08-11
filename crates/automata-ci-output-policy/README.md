# automata-ci-output-policy

`automata-ci-output-policy` defines the neutral publication policy shared by
authentication, persistence, UI, and secret-delivery layers. Dashboard, log,
and artifact audiences are independently configurable, then restricted by an
immutable secret-exposure safety ceiling.

Output values carry their own classification. Explicitly public job outputs
may retain their value, while secret-derived output and any value containing a
registered credential persist only a marker. A secret-readable job still
narrows its complete log and artifact resources to private because exact-value
redaction cannot detect transformed credentials.

Policy and safety classifications use stable, snake-case Serde representations
for durable snapshots. Snapshots require all three audience fields; missing or
unknown fields and unknown variants are rejected. The explicit Rust `Default`
still sets every audience to private for callers constructing a new policy in
memory.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- API documentation: run `cargo doc -p automata-ci-output-policy --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)
