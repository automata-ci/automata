# automata-ci-key-management

`automata-ci-key-management` defines an object-safe data-key wrapping port,
canonical authenticated encryption contexts, a bundled local AES-256-GCM
keyring, and a generic per-record envelope codec.

Each record receives a fresh random 256-bit data-encryption key and 96-bit
nonce. Key wrapping and payload encryption authenticate the exact tenant,
purpose, record ID, schema, and wrapping key ID. The local keyring supports one
active wrapping key, decrypt-only old keys for online rotation, and retired-key
tombstones for explicit cryptographic shredding.

Plaintext and key buffers are non-cloneable, non-serializable, redacted, and
zeroized. Durable adapters store only the envelope schema, wrapping key ID,
wrapped data key, nonce, and authenticated ciphertext.

Automata is pre-1.0 and not production-ready. This is an internal security
boundary, and its Rust API may change between releases.

- [Architecture documentation](https://github.com/automata-ci/automata/blob/main/docs/architecture.md)
- [API documentation](https://docs.rs/automata-ci-key-management)
- [Issues and support](https://github.com/automata-ci/automata/issues)
