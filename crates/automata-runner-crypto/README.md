# automata-runner-crypto

This crate supplies authenticated at-rest protection for the runner's durable
recovery spool. It is an adapter behind `automata-runner-spool`'s
`ContentProtector` port; journal and recovery code do not depend on a concrete
cipher or key source.

The initial adapter uses AES-256-GCM through `ring` and is suitable for the
fully static Linux binary. Every protected object uses a fresh random nonce and
authenticates its complete durable identity (kind, size, digest, cache key, and
protection ID). Key bytes are accepted in zeroizing storage and are never
formatted, cloned, serialized, or written by this crate.

Key acquisition and rotation are product-configuration concerns. Operators
must retain a key for as long as recovery objects bearing its protection ID can
exist. A missing or mismatched key fails closed; it never enables plaintext
fallback.
