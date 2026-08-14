use std::{collections::BTreeMap, collections::BTreeSet, fmt, mem};

use async_trait::async_trait;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom as _, SystemRandom},
};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, KeyId, SecretBytes,
    WrappedDataKey,
};

/// Exact wrapping and data-key length for AES-256-GCM.
pub const AES_256_GCM_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const WRAP_HEADER: &[u8; 4] = b"AKW1";
const WRAP_SCHEMA: u16 = 1;
const WRAP_AAD_DOMAIN: &[u8] = b"automata-ci/local-keyring/dek-wrap/aes-256-gcm/v1";
const WRAPPED_KEY_BYTES: usize =
    WRAP_HEADER.len() + NONCE_BYTES + AES_256_GCM_KEY_BYTES + TAG_BYTES;

/// One consumed local wrapping-key configuration entry.
///
/// Key material is non-cloneable, non-serializable, redacted, and zeroized
/// after construction of the in-memory keyring.
pub struct LocalKeyMaterial {
    id: KeyId,
    material: SecretBytes,
}

impl LocalKeyMaterial {
    /// Creates one exact-length AES-256-GCM wrapping key.
    ///
    /// # Errors
    ///
    /// Rejects material that is not exactly 32 bytes. Rejected material is
    /// consumed and zeroized.
    pub fn new(id: KeyId, material: SecretBytes) -> Result<Self, LocalKeyringConfigurationError> {
        if material.len() != AES_256_GCM_KEY_BYTES {
            return Err(LocalKeyringConfigurationError::InvalidKeyLength);
        }
        Ok(Self { id, material })
    }

    /// Returns the non-secret key version ID.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        &self.id
    }

    fn into_parts(self) -> (KeyId, SecretBytes) {
        (self.id, self.material)
    }
}

impl fmt::Debug for LocalKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalKeyMaterial")
            .field("id", &self.id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// Local AES-256-GCM keyring with one active wrapping key.
///
/// Decrypt-only old keys support online active-key rotation. Retired IDs are
/// tombstones with no retained key material and fail distinctly from IDs that
/// were never known.
pub struct LocalAes256GcmKeyring {
    active_id: KeyId,
    keys: BTreeMap<KeyId, LessSafeKey>,
    retired: BTreeSet<KeyId>,
    random: SystemRandom,
}

impl LocalAes256GcmKeyring {
    /// Consumes local key material and builds a rotation-aware keyring.
    ///
    /// # Errors
    ///
    /// Rejects any key ID repeated across active, decrypt-only, and retired
    /// entries, or key material rejected by the cryptographic backend.
    pub fn new(
        active: LocalKeyMaterial,
        decrypt_only: Vec<LocalKeyMaterial>,
        retired: impl IntoIterator<Item = KeyId>,
    ) -> Result<Self, LocalKeyringConfigurationError> {
        let mut seen = BTreeSet::new();
        if !seen.insert(active.id().clone()) {
            return Err(LocalKeyringConfigurationError::DuplicateKeyId);
        }
        for key in &decrypt_only {
            if !seen.insert(key.id().clone()) {
                return Err(LocalKeyringConfigurationError::DuplicateKeyId);
            }
        }
        let mut retired_set = BTreeSet::new();
        for key_id in retired {
            if !seen.insert(key_id.clone()) || !retired_set.insert(key_id) {
                return Err(LocalKeyringConfigurationError::DuplicateKeyId);
            }
        }

        let active_id = active.id().clone();
        let mut keys = BTreeMap::new();
        for configured in std::iter::once(active).chain(decrypt_only) {
            let (id, material) = configured.into_parts();
            let key = UnboundKey::new(&AES_256_GCM, material.expose_secret())
                .map(LessSafeKey::new)
                .map_err(|_| LocalKeyringConfigurationError::InvalidKeyMaterial)?;
            drop(material);
            if keys.insert(id, key).is_some() {
                return Err(LocalKeyringConfigurationError::DuplicateKeyId);
            }
        }

        Ok(Self {
            active_id,
            keys,
            retired: retired_set,
            random: SystemRandom::new(),
        })
    }

    /// Returns the only key ID permitted for new wraps.
    #[must_use]
    pub const fn active_key_id(&self) -> &KeyId {
        &self.active_id
    }

    fn key_for_unwrap(&self, key_id: &KeyId) -> Result<&LessSafeKey, KeyEncryptionError> {
        if let Some(key) = self.keys.get(key_id) {
            return Ok(key);
        }
        if self.retired.contains(key_id) {
            return Err(KeyEncryptionError::RetiredKey);
        }
        Err(KeyEncryptionError::UnknownKey)
    }

    fn wrap_aad(context: &KeyEncryptionContext, key_id: &KeyId) -> Vec<u8> {
        context.authenticated_data(WRAP_AAD_DOMAIN, WRAP_SCHEMA, key_id)
    }
}

impl fmt::Debug for LocalAes256GcmKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let decrypt_only_ids: Vec<_> = self
            .keys
            .keys()
            .filter(|id| *id != &self.active_id)
            .collect();
        formatter
            .debug_struct("LocalAes256GcmKeyring")
            .field("active_id", &self.active_id)
            .field("decrypt_only_ids", &decrypt_only_ids)
            .field("retired_ids", &self.retired)
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl KeyEncryptionProvider for LocalAes256GcmKeyring {
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        if plaintext_key.len() != AES_256_GCM_KEY_BYTES {
            return Err(KeyEncryptionError::InvalidDataKey);
        }
        let key = self
            .keys
            .get(&self.active_id)
            .ok_or(KeyEncryptionError::Unavailable)?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        self.random
            .fill(&mut nonce_bytes)
            .map_err(|_| KeyEncryptionError::RandomnessUnavailable)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buffer = Zeroizing::new(plaintext_key.expose_secret().to_vec());
        key.seal_in_place_append_tag(
            nonce,
            Aad::from(Self::wrap_aad(context, &self.active_id)),
            &mut *buffer,
        )
        .map_err(|_| KeyEncryptionError::Unavailable)?;

        let ciphertext = mem::take(&mut *buffer);
        let mut encoded = Vec::with_capacity(WRAPPED_KEY_BYTES);
        encoded.extend_from_slice(WRAP_HEADER);
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&ciphertext);
        WrappedDataKey::new(self.active_id.clone(), encoded)
            .map_err(|_| KeyEncryptionError::InvalidCiphertext)
    }

    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        let key = self.key_for_unwrap(wrapped_key.key_id())?;
        let encoded = wrapped_key.ciphertext();
        if encoded.len() != WRAPPED_KEY_BYTES || &encoded[..WRAP_HEADER.len()] != WRAP_HEADER {
            return Err(KeyEncryptionError::InvalidCiphertext);
        }
        let nonce_bytes: [u8; NONCE_BYTES] = encoded
            [WRAP_HEADER.len()..WRAP_HEADER.len() + NONCE_BYTES]
            .try_into()
            .map_err(|_| KeyEncryptionError::InvalidCiphertext)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buffer = Zeroizing::new(encoded[WRAP_HEADER.len() + NONCE_BYTES..].to_vec());
        let plaintext_length = key
            .open_in_place(
                nonce,
                Aad::from(Self::wrap_aad(context, wrapped_key.key_id())),
                &mut buffer,
            )
            .map_err(|_| KeyEncryptionError::AuthenticationFailed)?
            .len();
        if plaintext_length != AES_256_GCM_KEY_BYTES {
            return Err(KeyEncryptionError::AuthenticationFailed);
        }
        buffer[plaintext_length..].zeroize();
        buffer.truncate(plaintext_length);
        let plaintext = mem::take(&mut *buffer);
        SecretBytes::new(plaintext).map_err(|_| KeyEncryptionError::InvalidDataKey)
    }
}

/// Invalid local keyring configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalKeyringConfigurationError {
    /// A local AES-256-GCM wrapping key is not exactly 32 bytes.
    #[error("local wrapping key must contain exactly 32 bytes")]
    InvalidKeyLength,
    /// Active, decrypt-only, and retired key IDs must be globally unique.
    #[error("local keyring contains a duplicate key ID")]
    DuplicateKeyId,
    /// The cryptographic backend rejected exact-length key material.
    #[error("local wrapping key material was rejected")]
    InvalidKeyMaterial,
}

#[cfg(test)]
mod tests {
    use crate::KeyPurpose;
    use futures::executor::block_on;

    use super::*;

    #[test]
    fn local_wrapped_key_rejects_forward_wrap_schema() {
        let key_id = KeyId::new("local-key-v1").expect("key ID");
        let keyring = LocalAes256GcmKeyring::new(
            LocalKeyMaterial::new(
                key_id,
                SecretBytes::new(vec![0x51; AES_256_GCM_KEY_BYTES]).expect("key material"),
            )
            .expect("local key"),
            Vec::new(),
            Vec::new(),
        )
        .expect("keyring");
        let context = KeyEncryptionContext::new(
            "tenant-a",
            KeyPurpose::new("auth/provider-token:v1").expect("purpose"),
            "record-1",
        )
        .expect("context");
        let forward_schema = WRAP_SCHEMA.checked_add(1).expect("test schema");
        let nonce_bytes = [0x39; NONCE_BYTES];
        let mut ciphertext = vec![0x27; AES_256_GCM_KEY_BYTES];
        keyring
            .keys
            .get(&keyring.active_id)
            .expect("active key")
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(context.authenticated_data(
                    WRAP_AAD_DOMAIN,
                    forward_schema,
                    &keyring.active_id,
                )),
                &mut ciphertext,
            )
            .expect("future-schema wrap");
        let mut encoded = Vec::with_capacity(WRAPPED_KEY_BYTES);
        encoded.extend_from_slice(WRAP_HEADER);
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&ciphertext);
        let altered = WrappedDataKey::new(keyring.active_id.clone(), encoded)
            .expect("future-schema wrapped key");

        assert!(matches!(
            block_on(keyring.unwrap_data_key(&altered, &context)),
            Err(KeyEncryptionError::AuthenticationFailed)
        ));
    }
}
