use automata_ci_core::Sha256Digest;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_MEDIA_TYPE_BYTES: usize = 128;

/// Credential-free, provider-neutral object key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobKey(String);

impl BlobKey {
    /// Creates a canonical relative object key.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized keys, control characters, backslashes,
    /// absolute paths, empty components, and traversal aliases.
    pub fn new(value: impl Into<String>) -> Result<Self, BlobKeyError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_OBJECT_KEY_BYTES {
            return Err(BlobKeyError::InvalidLength);
        }
        if value.starts_with('/') {
            return Err(BlobKeyError::Absolute);
        }
        if value.chars().any(char::is_control) || value.contains('\\') {
            return Err(BlobKeyError::UnsafeCharacter);
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(BlobKeyError::InvalidComponent);
        }
        Ok(Self(value))
    }

    /// Returns the safe key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded media type retained as immutable object metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MediaType(String);

impl MediaType {
    /// Creates an ASCII media type without parameters.
    ///
    /// # Errors
    ///
    /// Rejects non-ASCII, whitespace, parameters, missing type/subtype, and
    /// values longer than 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, MediaTypeError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_MEDIA_TYPE_BYTES {
            return Err(MediaTypeError::InvalidLength);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'&'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'|'
                        | b'~'
                        | b'/'
                )
        }) {
            return Err(MediaTypeError::InvalidCharacter);
        }
        let mut components = value.split('/');
        if components.next().is_none_or(str::is_empty)
            || components.next().is_none_or(str::is_empty)
            || components.next().is_some()
        {
            return Err(MediaTypeError::MissingTypeOrSubtype);
        }
        Ok(Self(value))
    }

    /// Returns the canonical media type text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete immutable identity of one object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobDescriptor {
    key: BlobKey,
    digest: Sha256Digest,
    size: u64,
    media_type: MediaType,
}

impl BlobDescriptor {
    /// Creates immutable metadata for content already hashed by a trusted producer.
    #[must_use]
    pub const fn new(key: BlobKey, digest: Sha256Digest, size: u64, media_type: MediaType) -> Self {
        Self {
            key,
            digest,
            size,
            media_type,
        }
    }

    /// Returns the provider object key.
    #[must_use]
    pub const fn key(&self) -> &BlobKey {
        &self.key
    }

    /// Returns the expected SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the exact encoded byte count.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns immutable content-type metadata.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }
}

/// Validated bytes for an immutable put operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPayload {
    descriptor: BlobDescriptor,
    bytes: Bytes,
}

impl BlobPayload {
    /// Hashes bytes and derives their descriptor.
    #[must_use]
    pub fn from_bytes(key: BlobKey, media_type: MediaType, bytes: Bytes) -> Self {
        let digest = digest_bytes(&bytes);
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        Self {
            descriptor: BlobDescriptor::new(key, digest, size, media_type),
            bytes,
        }
    }

    /// Validates bytes against externally supplied immutable metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch without retaining the untrusted content.
    pub fn verify(descriptor: BlobDescriptor, bytes: Bytes) -> Result<Self, BlobPayloadError> {
        let size = u64::try_from(bytes.len()).map_err(|_| BlobPayloadError::SizeMismatch)?;
        if size != descriptor.size() {
            return Err(BlobPayloadError::SizeMismatch);
        }
        if digest_bytes(&bytes) != descriptor.digest() {
            return Err(BlobPayloadError::DigestMismatch);
        }
        Ok(Self { descriptor, bytes })
    }

    /// Returns immutable object metadata.
    #[must_use]
    pub const fn descriptor(&self) -> &BlobDescriptor {
        &self.descriptor
    }

    /// Returns the verified bytes.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Decomposes the payload for a provider adapter.
    #[must_use]
    pub fn into_parts(self) -> (BlobDescriptor, Bytes) {
        (self.descriptor, self.bytes)
    }
}

/// Bytes returned after exact metadata and digest verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlob(BlobPayload);

impl VerifiedBlob {
    /// Wraps a payload whose constructor already verified its descriptor.
    #[must_use]
    pub const fn from_payload(payload: BlobPayload) -> Self {
        Self(payload)
    }

    /// Returns the verified descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &BlobDescriptor {
        self.0.descriptor()
    }

    /// Returns verified content bytes.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        self.0.bytes()
    }

    /// Returns verified content bytes by value.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0.into_parts().1
    }
}

/// Outcome of an idempotent immutable put.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutBlobOutcome {
    /// This call created the object.
    Created,
    /// Identical bytes and metadata already existed.
    AlreadyPresent,
}

/// Invalid object key.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BlobKeyError {
    /// The key is empty or exceeds the 1,024-byte ceiling.
    #[error("blob key length must be 1..=1024 UTF-8 bytes")]
    InvalidLength,
    /// The key starts at a filesystem-style root instead of being relative.
    #[error("blob key must be relative")]
    Absolute,
    /// The key contains a control character or a platform-specific separator.
    #[error("blob key contains a control character or backslash")]
    UnsafeCharacter,
    /// A path component is empty, the current directory, or a parent traversal.
    #[error("blob key contains an empty, current-directory, or traversal component")]
    InvalidComponent,
}

/// Invalid immutable media type.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MediaTypeError {
    /// The media type is empty or exceeds the 128-byte ceiling.
    #[error("media type length must be 1..=128 ASCII bytes")]
    InvalidLength,
    /// The media type contains whitespace, parameters, or another unsupported byte.
    #[error("media type contains an unsupported character")]
    InvalidCharacter,
    /// The value does not contain exactly one nonempty type/subtype pair.
    #[error("media type must contain exactly one non-empty type/subtype separator")]
    MissingTypeOrSubtype,
}

/// Bytes did not match their immutable descriptor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BlobPayloadError {
    /// The byte count differs from the immutable descriptor.
    #[error("blob byte count does not match its descriptor")]
    SizeMismatch,
    /// The SHA-256 digest differs from the immutable descriptor.
    #[error("blob SHA-256 digest does not match its descriptor")]
    DigestMismatch,
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
