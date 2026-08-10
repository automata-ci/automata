# automata-ci-runner-crypto

This crate supplies authenticated at-rest protection for the runner's durable
recovery spool. It is an adapter behind `automata-ci-runner-spool`'s
`ContentProtector` port; journal and recovery code do not depend on a concrete
cipher or key source.

The initial adapter uses AES-256-GCM through `ring` and is suitable for the
fully static Linux binary. Every protected object uses a fresh random nonce and
authenticates its complete durable identity (kind, size, digest, cache key, and
protection ID). Key bytes are accepted in zeroizing storage and are never
formatted, cloned, serialized, or written by this crate.

The local keyring has exactly one active protector and at most eight unique
decrypt-only protectors. New writes always use the active ID. Reads select only
the exact ID authenticated into each durable reference; keys are never tried in
sequence. Operators must retain an old key for as long as recovery objects
bearing its ID can exist. A missing, mismatched, duplicate, or oversized key
configuration fails closed and never enables plaintext fallback.
