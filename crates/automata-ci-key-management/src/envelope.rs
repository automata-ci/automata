use std::{fmt, mem, sync::Arc};

use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom as _, SystemRandom},
};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    AES_256_GCM_KEY_BYTES, KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, KeyId,
    MAX_ENVELOPE_PLAINTEXT_BYTES, SecretBytes, WrappedDataKey,
};

/// Current durable envelope schema.
pub const ENVELOPE_SCHEMA_V1: u16 = 1;
/// Exact nonce length required by AES-256-GCM.
pub const ENVELOPE_NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
// foundation-governance: derived-contract owner=auth-security kind=cryptographic-context
const ENVELOPE_AAD_DOMAIN: &[u8] = b"automata-ci/envelope/payload/aes-256-gcm/v1";

/// Inclusive maximum ciphertext length accepted by the generic envelope boundary.
///
/// AES-256-GCM appends one 16-byte authentication tag to the bounded plaintext.
pub const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = MAX_ENVELOPE_PLAINTEXT_BYTES + TAG_BYTES;

/// Persistence-safe authenticated envelope.
///
/// The plaintext and DEK are absent. Schema, wrapping key ID, wrapped DEK,
/// nonce, ciphertext, and external authenticated context are all required to
/// recover a record.
pub struct EncryptedEnvelope {
    schema: u16,
    wrapped_data_key: WrappedDataKey,
    nonce: [u8; ENVELOPE_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Reconstructs an envelope from durable parts.
    ///
    /// Unknown nonzero schemas remain representable and fail explicitly when
    /// opened by a codec that does not support them.
    ///
    /// # Errors
    ///
    /// Rejects schema zero and ciphertext outside the supported record bound.
    pub fn from_parts(
        schema: u16,
        wrapped_data_key: WrappedDataKey,
        nonce: [u8; ENVELOPE_NONCE_BYTES],
        ciphertext: Vec<u8>,
    ) -> Result<Self, EnvelopeError> {
        if schema == 0
            || ciphertext.len() <= TAG_BYTES
            || ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES
        {
            return Err(EnvelopeError::InvalidEnvelope);
        }
        Ok(Self {
            schema,
            wrapped_data_key,
            nonce,
            ciphertext,
        })
    }

    /// Returns the durable envelope schema.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.schema
    }

    /// Returns the exact wrapping key version.
    #[must_use]
    pub const fn wrapping_key_id(&self) -> &KeyId {
        self.wrapped_data_key.key_id()
    }

    /// Returns the opaque wrapped DEK.
    #[must_use]
    pub const fn wrapped_data_key(&self) -> &WrappedDataKey {
        &self.wrapped_data_key
    }

    /// Returns the public per-record nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; ENVELOPE_NONCE_BYTES] {
        &self.nonce
    }

    /// Returns authenticated ciphertext for persistence.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes the envelope into persistence-safe parts.
    #[must_use]
    pub fn into_parts(self) -> (u16, WrappedDataKey, [u8; ENVELOPE_NONCE_BYTES], Vec<u8>) {
        (
            self.schema,
            self.wrapped_data_key,
            self.nonce,
            self.ciphertext,
        )
    }
}

impl fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedEnvelope")
            .field("schema", &self.schema)
            .field("wrapping_key_id", self.wrapping_key_id())
            .field("wrapped_data_key", &"[OPAQUE]")
            .field("nonce", &"[NONCE]")
            .field("ciphertext", &"[OPAQUE]")
            .field("ciphertext_length", &self.ciphertext.len())
            .finish()
    }
}

/// One fresh, provider-wrapped data key prepared for a later local seal.
///
/// Preparation deliberately contains no payload. It can therefore complete
/// every random-source and remote key-provider operation before a caller
/// performs an irreversible side effect that returns plaintext. The value is
/// move-only, its plaintext data key is held in zeroizing [`SecretBytes`], and
/// [`PreparedEnvelope::seal_prepared`] consumes it so a key/nonce pair cannot
/// be reused.
#[must_use = "a prepared envelope must be consumed by seal_prepared or dropped"]
pub struct PreparedEnvelope {
    data_key: SecretBytes,
    wrapped_data_key: WrappedDataKey,
    nonce: [u8; ENVELOPE_NONCE_BYTES],
}

impl PreparedEnvelope {
    /// Locally encrypts one payload and consumes this prepared key/nonce pair.
    ///
    /// This operation performs no key-provider or other asynchronous I/O. The
    /// payload context can be more specific than the identity context used to
    /// wrap the data key. The plaintext buffer and prepared plaintext data key
    /// are zeroized on every return path.
    ///
    /// The operation is infallible because this type can only be produced with
    /// an exact 256-bit data key and nonce, [`SecretBytes`] proves the payload
    /// is nonempty and bounded, and [`KeyEncryptionContext`] is already
    /// validated. AES-256-GCM accepts every buffer within that bound.
    ///
    /// # Panics
    ///
    /// Panics only if `ring` rejects the type-proven exact AES-256 key length
    /// or bounded plaintext. Either condition would contradict the validated
    /// construction invariants of [`PreparedEnvelope`] or [`SecretBytes`].
    #[must_use]
    pub fn seal_prepared(
        self,
        payload_context: &KeyEncryptionContext,
        mut plaintext: SecretBytes,
    ) -> EncryptedEnvelope {
        let Self {
            data_key,
            wrapped_data_key,
            nonce,
        } = self;
        let key = UnboundKey::new(&AES_256_GCM, data_key.expose_secret())
            .map(LessSafeKey::new)
            .expect("PreparedEnvelope always owns one exact AES-256-GCM key");
        let aad = payload_context.authenticated_data(
            ENVELOPE_AAD_DOMAIN,
            ENVELOPE_SCHEMA_V1,
            wrapped_data_key.key_id(),
        );
        let mut buffer = Zeroizing::new(plaintext.take_for_encryption());
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut *buffer,
        )
        .expect("SecretBytes is below AES-256-GCM's input limit");
        drop(data_key);

        let ciphertext = mem::take(&mut *buffer);
        EncryptedEnvelope {
            schema: ENVELOPE_SCHEMA_V1,
            wrapped_data_key,
            nonce,
            ciphertext,
        }
    }
}

impl fmt::Debug for PreparedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedEnvelope([REDACTED])")
    }
}

/// Generic per-record AES-256-GCM envelope codec.
pub struct EnvelopeCodec {
    provider: Arc<dyn KeyEncryptionProvider>,
    random: SystemRandom,
}

impl EnvelopeCodec {
    /// Creates a codec backed by any object-safe wrapping-key provider.
    #[must_use]
    pub fn new(provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            provider,
            random: SystemRandom::new(),
        }
    }

    /// Prepares a fresh data key and nonce without accepting any payload.
    ///
    /// Secure randomness and the asynchronous provider wrap both finish before
    /// this method returns. Dropping the returned move-only value without
    /// sealing zeroizes its plaintext data key.
    ///
    /// # Errors
    ///
    /// Fails closed on random-source or key-provider failure.
    pub async fn prepare(
        &self,
        wrapping_context: &KeyEncryptionContext,
    ) -> Result<PreparedEnvelope, EnvelopeError> {
        let mut data_key = SecretBytes::new(vec![0_u8; AES_256_GCM_KEY_BYTES])
            .map_err(|_| EnvelopeError::CryptographicFailure)?;
        self.random
            .fill(data_key.expose_secret_mut())
            .map_err(|_| EnvelopeError::RandomnessUnavailable)?;
        let mut nonce = [0_u8; ENVELOPE_NONCE_BYTES];
        self.random
            .fill(&mut nonce)
            .map_err(|_| EnvelopeError::RandomnessUnavailable)?;
        let wrapped_data_key = self
            .provider
            .wrap_data_key(&data_key, wrapping_context)
            .await
            .map_err(EnvelopeError::KeyEncryption)?;

        Ok(PreparedEnvelope {
            data_key,
            wrapped_data_key,
            nonce,
        })
    }

    /// Encrypts and consumes one plaintext record using a fresh 256-bit DEK and
    /// 96-bit nonce.
    ///
    /// The input buffer is zeroized on every return path. The DEK is wrapped
    /// under the provider's active key and then zeroized.
    ///
    /// # Errors
    ///
    /// Fails closed on random-source, provider, representation, or
    /// cryptographic errors.
    pub async fn seal(
        &self,
        context: &KeyEncryptionContext,
        plaintext: SecretBytes,
    ) -> Result<EncryptedEnvelope, EnvelopeError> {
        Ok(self
            .prepare(context)
            .await?
            .seal_prepared(context, plaintext))
    }

    /// Authenticates and decrypts one exact-context envelope.
    ///
    /// # Errors
    ///
    /// Fails closed for unsupported schemas, wrong tenant/purpose/record/key,
    /// tampering, provider failure, or malformed plaintext.
    pub async fn open(
        &self,
        context: &KeyEncryptionContext,
        envelope: &EncryptedEnvelope,
    ) -> Result<SecretBytes, EnvelopeError> {
        self.open_with_contexts(context, context, envelope).await
    }

    /// Authenticates and decrypts an envelope with distinct wrapping and
    /// payload contexts.
    ///
    /// The provider unwrap authenticates `wrapping_context`; AES-256-GCM
    /// independently authenticates the complete tenant, purpose, and record
    /// identity in `payload_context`.
    ///
    /// # Errors
    ///
    /// Fails closed for unsupported schemas, either wrong context, tampering,
    /// provider failure, or malformed plaintext.
    pub async fn open_with_contexts(
        &self,
        wrapping_context: &KeyEncryptionContext,
        payload_context: &KeyEncryptionContext,
        envelope: &EncryptedEnvelope,
    ) -> Result<SecretBytes, EnvelopeError> {
        if envelope.schema() != ENVELOPE_SCHEMA_V1 {
            return Err(EnvelopeError::UnsupportedSchema);
        }
        let data_key = self
            .provider
            .unwrap_data_key(envelope.wrapped_data_key(), wrapping_context)
            .await
            .map_err(EnvelopeError::KeyEncryption)?;
        if data_key.len() != AES_256_GCM_KEY_BYTES {
            return Err(EnvelopeError::KeyEncryption(
                KeyEncryptionError::InvalidDataKey,
            ));
        }
        let key = UnboundKey::new(&AES_256_GCM, data_key.expose_secret())
            .map(LessSafeKey::new)
            .map_err(|_| EnvelopeError::CryptographicFailure)?;
        let nonce = Nonce::assume_unique_for_key(*envelope.nonce());
        let aad = payload_context.authenticated_data(
            ENVELOPE_AAD_DOMAIN,
            envelope.schema(),
            envelope.wrapping_key_id(),
        );
        let mut buffer = Zeroizing::new(envelope.ciphertext().to_vec());
        let plaintext_length = key
            .open_in_place(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| EnvelopeError::AuthenticationFailed)?
            .len();
        drop(data_key);
        if plaintext_length == 0 || plaintext_length > MAX_ENVELOPE_PLAINTEXT_BYTES {
            return Err(EnvelopeError::AuthenticationFailed);
        }
        buffer[plaintext_length..].zeroize();
        buffer.truncate(plaintext_length);
        let plaintext = mem::take(&mut *buffer);
        SecretBytes::new(plaintext).map_err(|_| EnvelopeError::AuthenticationFailed)
    }
}

impl fmt::Debug for EnvelopeCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeCodec")
            .field("provider", &self.provider)
            .field("algorithm", &"AES-256-GCM")
            .finish_non_exhaustive()
    }
}

/// Envelope encoding, wrapping, or payload-authentication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnvelopeError {
    /// Durable envelope fields are structurally invalid.
    #[error("encrypted envelope is invalid")]
    InvalidEnvelope,
    /// The durable schema is nonzero but unsupported by this codec.
    #[error("encrypted envelope schema is unsupported")]
    UnsupportedSchema,
    /// Secure random key or nonce generation failed.
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    /// Payload ciphertext or authenticated metadata did not verify.
    #[error("encrypted envelope authentication failed")]
    AuthenticationFailed,
    /// The configured wrapping-key provider failed.
    #[error("encrypted envelope key operation failed: {0}")]
    KeyEncryption(KeyEncryptionError),
    /// The local payload cryptographic primitive rejected an operation.
    #[error("encrypted envelope cryptographic operation failed")]
    CryptographicFailure,
}
