# automata-ci-actions-permissions

This crate owns Automata's closed, versioned catalog for permission names accepted
by the GitHub Actions workflow `permissions` key. It deliberately does not model
the broader GitHub App permission vocabulary.

The catalog is executable product policy. Workflow decoding, runtime-policy
validation, and Actions job projection must all consume this crate instead of
maintaining independent permission-name lists.
