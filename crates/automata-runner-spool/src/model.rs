use std::fmt;

use automata_core::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    MAX_CONTENT_OBJECT_BYTES, MAX_CONTENT_OBJECTS, MAX_CONTENT_SPOOL_BYTES, SpoolInvariantError,
};

const MAX_PROTECTION_ID_BYTES: usize = 64;
const MAX_CACHE_KEY_BYTES: usize = 192;

/// Semantic role of immutable recovery content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    JobIr,
    RuntimeAuthority,
    TerminalResult,
    LogSpool,
}

impl ContentKind {
    const fn cache_prefix(self) -> &'static str {
        match self {
            Self::JobIr => "job-ir",
            Self::RuntimeAuthority => "runtime-authority",
            Self::TerminalResult => "terminal-result",
            Self::LogSpool => "log-spool",
        }
    }
}

/// Non-secret identifier selecting a key/cipher implementation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtectionId(String);

impl ProtectionId {
    /// Validates an adapter-owned key/cipher identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or non-portable identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, SpoolInvariantError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PROTECTION_ID_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if valid {
            Ok(Self(value))
        } else {
            Err(SpoolInvariantError::InvalidProtectionId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProtectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProtectionId")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ProtectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProtectionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Portable, deterministic filename key for one protected content object.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentCacheKey(String);

impl ContentCacheKey {
    fn derive(
        kind: ContentKind,
        digest: Sha256Digest,
        size: u64,
        protection_id: &ProtectionId,
    ) -> Result<Self, SpoolInvariantError> {
        let value = format!(
            "{}-{}-{digest}-{size}",
            kind.cache_prefix(),
            protection_id.as_str()
        );
        if value.len() <= MAX_CACHE_KEY_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(SpoolInvariantError::InvalidCacheKey)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ContentCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContentCacheKey")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ContentCacheKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentCacheKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let valid = !value.is_empty()
            && value.len() <= MAX_CACHE_KEY_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if valid {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(
                SpoolInvariantError::InvalidCacheKey,
            ))
        }
    }
}

/// Immutable identity of protected content already committed by an adapter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableContentRef {
    kind: ContentKind,
    size: u64,
    sha256: Sha256Digest,
    cache_key: ContentCacheKey,
    protection_id: ProtectionId,
}

impl DurableContentRef {
    /// Constructs the durable receipt returned by a storage adapter only after
    /// it has synchronized the verified bytes and directory metadata.
    ///
    /// # Errors
    ///
    /// Rejects content beyond the hard object bound.
    pub fn after_commit(
        kind: ContentKind,
        size: u64,
        sha256: Sha256Digest,
        protection_id: ProtectionId,
    ) -> Result<Self, SpoolInvariantError> {
        if size > MAX_CONTENT_OBJECT_BYTES {
            return Err(SpoolInvariantError::ObjectTooLarge);
        }
        let cache_key = ContentCacheKey::derive(kind, sha256, size, &protection_id)?;
        Ok(Self {
            kind,
            size,
            sha256,
            cache_key,
            protection_id,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> ContentKind {
        self.kind
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    #[must_use]
    pub const fn cache_key(&self) -> &ContentCacheKey {
        &self.cache_key
    }

    #[must_use]
    pub const fn protection_id(&self) -> &ProtectionId {
        &self.protection_id
    }

    pub(crate) fn validate(&self) -> Result<(), SpoolInvariantError> {
        let expected =
            ContentCacheKey::derive(self.kind, self.sha256, self.size, &self.protection_id)?;
        if self.size <= MAX_CONTENT_OBJECT_BYTES && self.cache_key == expected {
            Ok(())
        } else {
            Err(SpoolInvariantError::InvalidCacheKey)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableContentRefData {
    kind: ContentKind,
    size: u64,
    sha256: Sha256Digest,
    cache_key: ContentCacheKey,
    protection_id: ProtectionId,
}

impl<'de> Deserialize<'de> for DurableContentRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = DurableContentRefData::deserialize(deserializer)?;
        let reference = Self {
            kind: value.kind,
            size: value.size,
            sha256: value.sha256,
            cache_key: value.cache_key,
            protection_id: value.protection_id,
        };
        reference.validate().map_err(serde::de::Error::custom)?;
        Ok(reference)
    }
}

/// Explicit object and aggregate capacity limits for one local spool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolLimits {
    object_bytes: u64,
    total_bytes: u64,
    objects: u32,
    protection_overhead_bytes: u64,
}

impl SpoolLimits {
    /// Creates coherent spool limits bounded by global hard ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero, inverted, overflowing, or globally oversized limits.
    pub fn new(
        max_object_bytes: u64,
        max_total_bytes: u64,
        max_objects: u32,
        max_protection_overhead_bytes: u64,
    ) -> Result<Self, SpoolInvariantError> {
        let encoded_object = max_object_bytes.checked_add(max_protection_overhead_bytes);
        let valid = max_object_bytes > 0
            && max_object_bytes <= MAX_CONTENT_OBJECT_BYTES
            && max_total_bytes >= max_object_bytes
            && max_total_bytes <= MAX_CONTENT_SPOOL_BYTES
            && max_objects > 0
            && max_objects <= MAX_CONTENT_OBJECTS
            && encoded_object.is_some_and(|encoded| encoded <= max_total_bytes);
        if valid {
            Ok(Self {
                object_bytes: max_object_bytes,
                total_bytes: max_total_bytes,
                objects: max_objects,
                protection_overhead_bytes: max_protection_overhead_bytes,
            })
        } else {
            Err(SpoolInvariantError::InvalidLimits)
        }
    }

    #[must_use]
    pub const fn max_object_bytes(self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub const fn max_objects(self) -> u32 {
        self.objects
    }

    #[must_use]
    pub const fn max_protection_overhead_bytes(self) -> u64 {
        self.protection_overhead_bytes
    }

    pub(crate) fn max_encoded_object_bytes(self) -> u64 {
        self.object_bytes + self.protection_overhead_bytes
    }
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            object_bytes: MAX_CONTENT_OBJECT_BYTES,
            total_bytes: 1024 * 1024 * 1024,
            objects: 4_096,
            protection_overhead_bytes: 1024 * 1024,
        }
    }
}
