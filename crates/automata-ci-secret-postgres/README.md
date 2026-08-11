# automata-ci-secret-postgres

The encrypted built-in PostgreSQL adapter for Automata's provider-neutral
secret contract. Plaintext values are envelope-encrypted in application memory;
PostgreSQL receives only authenticated ciphertext, a nonce, a wrapped data key,
and non-secret envelope metadata.

Every envelope is authenticated against its exact tenant and immutable secret
version identity. Provider locators and version identifiers exposed through the
generic provider interface are canonical internal references and are never
persisted as provider handles.

Creation accepts only the deterministic request bound to an exact durable
management mutation. It preflights that reservation before plaintext or key
management work, persists only one encrypted immutable `staged` version, and
does not advance the logical head. Staged versions are not resolvable. A
separate management confirmation transaction owns promotion, predecessor
supersession, logical-head advancement, receipt, and audit; exact provider replay
returns the same staged bytes.

The wrapping provider and its active/decrypt-only keys are supplied by the
embedding application and must remain outside PostgreSQL and its backups. This
crate implements the adapter boundary. The current `automata server` product
composes repository-scoped management with this adapter and supervises
ambiguous-mutation recovery and built-in cleanup. It does not deliver managed
secret values to jobs; external providers remain uncomposed and unadvertised.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [Issues and support](https://github.com/automata-ci/automata/issues)
