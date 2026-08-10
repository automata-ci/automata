use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_KEY_ID_BYTES: usize = 64;
const MAX_PURPOSE_BYTES: usize = 128;
const MAX_CONTEXT_ID_BYTES: usize = 512;
const CONTEXT_HEADER: &[u8; 4] = b"AKC1";
const AAD_HEADER: &[u8; 4] = b"AKA1";

/// Stable identifier of one wrapping key version.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Creates a canonical lowercase wrapping-key identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, or noncanonical identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, KeyIdError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_KEY_ID_BYTES
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            })
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        valid.then_some(Self(value)).ok_or(KeyIdError)
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyId {
    type Error = KeyIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<KeyId> for String {
    fn from(value: KeyId) -> Self {
        value.0
    }
}

/// Invalid wrapping-key identifier.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("key ID is invalid")]
pub struct KeyIdError;

/// Stable domain-separation label for one encrypted record family.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyPurpose(String);

impl KeyPurpose {
    /// Creates a canonical lowercase purpose such as `auth/provider-tokens:v1`.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, or noncanonical purposes.
    pub fn new(value: impl Into<String>) -> Result<Self, KeyPurposeError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PURPOSE_BYTES
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'-' | b'_' | b':' | b'.' | b'/'))
            })
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        valid.then_some(Self(value)).ok_or(KeyPurposeError)
    }

    /// Returns the canonical purpose.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyPurpose {
    type Error = KeyPurposeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<KeyPurpose> for String {
    fn from(value: KeyPurpose) -> Self {
        value.0
    }
}

/// Invalid key-encryption purpose.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("key purpose is invalid")]
pub struct KeyPurposeError;

/// Non-secret identity authenticated by both DEK wrapping and record encryption.
///
/// The exact tenant, purpose, and record ID are length-prefixed in a versioned
/// canonical byte representation. A ciphertext must be re-encrypted before any
/// of these immutable bindings change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEncryptionContext {
    tenant_id: String,
    purpose: KeyPurpose,
    record_id: String,
}

impl KeyEncryptionContext {
    /// Creates a complete authenticated encryption context.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing tenant and record IDs.
    pub fn new(
        tenant_id: impl Into<String>,
        purpose: KeyPurpose,
        record_id: impl Into<String>,
    ) -> Result<Self, KeyEncryptionContextError> {
        let tenant_id = tenant_id.into();
        let record_id = record_id.into();
        validate_context_id(&tenant_id)
            .then_some(())
            .ok_or(KeyEncryptionContextError::InvalidTenantId)?;
        validate_context_id(&record_id)
            .then_some(())
            .ok_or(KeyEncryptionContextError::InvalidRecordId)?;
        Ok(Self {
            tenant_id,
            purpose,
            record_id,
        })
    }

    /// Returns the exact tenant binding.
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Returns the domain-separation purpose.
    #[must_use]
    pub const fn purpose(&self) -> &KeyPurpose {
        &self.purpose
    }

    /// Returns the exact durable record binding.
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// Returns the canonical, versioned, length-prefixed authenticated bytes.
    #[must_use]
    pub fn canonical_authenticated_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            CONTEXT_HEADER.len()
                + 12
                + self.tenant_id.len()
                + self.purpose.as_str().len()
                + self.record_id.len(),
        );
        encoded.extend_from_slice(CONTEXT_HEADER);
        append_length_prefixed(&mut encoded, self.tenant_id.as_bytes());
        append_length_prefixed(&mut encoded, self.purpose.as_str().as_bytes());
        append_length_prefixed(&mut encoded, self.record_id.as_bytes());
        encoded
    }

    pub(crate) fn authenticated_data(&self, domain: &[u8], schema: u16, key_id: &KeyId) -> Vec<u8> {
        let context = self.canonical_authenticated_bytes();
        let mut encoded = Vec::with_capacity(
            AAD_HEADER.len() + 2 + 12 + domain.len() + key_id.as_str().len() + context.len(),
        );
        encoded.extend_from_slice(AAD_HEADER);
        encoded.extend_from_slice(&schema.to_be_bytes());
        append_length_prefixed(&mut encoded, domain);
        append_length_prefixed(&mut encoded, key_id.as_str().as_bytes());
        append_length_prefixed(&mut encoded, &context);
        encoded
    }
}

fn validate_context_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_CONTEXT_ID_BYTES && !value.chars().any(char::is_control)
}

fn append_length_prefixed(destination: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("authenticated context fields are u32-bounded");
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
}

/// Invalid tenant or record binding in an encryption context.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyEncryptionContextError {
    /// Tenant identity is empty, oversized, or control-containing.
    #[error("key-encryption tenant ID is invalid")]
    InvalidTenantId,
    /// Record identity is empty, oversized, or control-containing.
    #[error("key-encryption record ID is invalid")]
    InvalidRecordId,
}
