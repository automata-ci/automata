//! Provider-neutral key management and envelope encryption for Automata.
//!
//! The port can be implemented by a KMS, HSM, transit service, or the bundled
//! local AES-256-GCM keyring. Every envelope uses a random per-record data key
//! and binds key wrapping and payload encryption to explicit canonical tenant,
//! purpose, and record contexts. Callers can use one context for both layers or
//! prepare a wrapped data key under an identity context before locally sealing
//! a payload under a more specific immutable-record context.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod context;
mod envelope;
mod local;
mod port;
mod secret;
mod wrapped;

pub use context::{
    KeyEncryptionContext, KeyEncryptionContextError, KeyId, KeyIdError, KeyPurpose, KeyPurposeError,
};
pub use envelope::{
    ENVELOPE_NONCE_BYTES, ENVELOPE_SCHEMA_V1, EncryptedEnvelope, EnvelopeCodec, EnvelopeError,
    MAX_ENVELOPE_CIPHERTEXT_BYTES, PreparedEnvelope,
};
pub use local::{
    AES_256_GCM_KEY_BYTES, LocalAes256GcmKeyring, LocalKeyMaterial, LocalKeyringConfigurationError,
};
pub use port::{KeyEncryptionError, KeyEncryptionProvider};
pub use secret::{MAX_ENVELOPE_PLAINTEXT_BYTES, SecretBytes, SecretBytesError};
pub use wrapped::{MAX_WRAPPED_DATA_KEY_BYTES, WrappedDataKey, WrappedDataKeyError};
