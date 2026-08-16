# Automata Windows file security

This internal crate provides the one safe-Rust, handle-bound Windows reader
used for sensitive Automata configuration and secret files. It rejects
ambiguous namespaces, remote or non-approved volumes, reparse points,
hardlinks, unstable file identities, and broader-than-policy DACLs.

The crate does not create credential files and does not provide Windows runner
enrollment custody. That state remains broker-owned and fail-closed.
