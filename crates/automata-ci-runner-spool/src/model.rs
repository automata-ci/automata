use std::fmt;

use automata_ci_core::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    MAX_CONTENT_OBJECT_BYTES, MAX_CONTENT_OBJECTS, MAX_CONTENT_SPOOL_BYTES, SpoolInvariantError,
};

const MAX_PROTECTION_ID_BYTES: usize = 64;
const MAX_CACHE_KEY_BYTES: usize = 192;
const ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES: u64 = 64 * 1024;
const ENDPOINT_RESULT_PROTECTED_ENVELOPE_BYTES: u64 = 76;

/// Returns the current padded protected allocation charged for an endpoint result.
///
/// The class includes the authenticated exact-length/digest envelope and the
/// protection nonce/tag overhead, rounded to a fixed 64-KiB boundary. It is a
/// capacity ceiling, never an exact plaintext length.
///
/// # Errors
///
/// Rejects plaintext beyond the global object bound or arithmetic overflow.
pub const fn endpoint_result_allocation(plaintext_bytes: u64) -> Result<u64, SpoolInvariantError> {
    if plaintext_bytes > MAX_CONTENT_OBJECT_BYTES {
        return Err(SpoolInvariantError::ObjectTooLarge);
    }
    let Some(required) = plaintext_bytes.checked_add(ENDPOINT_RESULT_PROTECTED_ENVELOPE_BYTES)
    else {
        return Err(SpoolInvariantError::ObjectTooLarge);
    };
    let Some(rounded) = required.checked_add(ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES - 1) else {
        return Err(SpoolInvariantError::ObjectTooLarge);
    };
    let rounded = rounded / ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES;
    match rounded.checked_mul(ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES) {
        Some(allocation) => Ok(allocation),
        None => Err(SpoolInvariantError::ObjectTooLarge),
    }
}

const fn valid_endpoint_result_allocation(allocation_bytes: u64) -> bool {
    allocation_bytes >= ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES
        && allocation_bytes.is_multiple_of(ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES)
        && allocation_bytes <= MAX_CONTENT_OBJECT_BYTES + ENDPOINT_RESULT_ALLOCATION_GRANULE_BYTES
}

/// Closed domain for commitments computed by the protected-content authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentCommitmentDomain {
    /// Exact execution-endpoint request replay identity.
    EndpointRequest,
    /// Opaque durable identity for an execution-endpoint result.
    EndpointResultIdentity,
}

impl ContentCommitmentDomain {
    /// Returns the fixed cryptographic domain separator.
    #[must_use]
    pub const fn separator(self) -> &'static [u8] {
        match self {
            Self::EndpointRequest => b"automata.runner.endpoint-request.commitment.v1\0",
            Self::EndpointResultIdentity => b"automata.runner.endpoint-result.identity.v1\0",
        }
    }
}

/// Keyed, fixed-size commitment produced by an exact spool protection key.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyedContentCommitment {
    protection_id: ProtectionId,
    bytes: [u8; 32],
}

impl KeyedContentCommitment {
    pub(crate) const fn new(protection_id: ProtectionId, bytes: [u8; 32]) -> Self {
        Self {
            protection_id,
            bytes,
        }
    }

    /// Returns the exact non-secret protection-key identifier used.
    #[must_use]
    pub const fn protection_id(&self) -> &ProtectionId {
        &self.protection_id
    }

    /// Borrows commitment bytes for protected persistence or constant-time comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for KeyedContentCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyedContentCommitment")
            .field("protection_id", &self.protection_id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Semantic role of immutable recovery content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// Canonical admitted job intermediate representation needed for restart.
    JobIr,
    /// Short-lived provider authority needed to resume the exact attempt.
    RuntimeAuthority,
    /// Terminal result payload awaiting durable control-plane acknowledgement.
    TerminalResult,
    /// Buffered log content awaiting replay or upload.
    LogSpool,
    /// Fixed-size commitment to one exact execution-endpoint request.
    EndpointRequest,
    /// Protected replay result from one execution-endpoint operation.
    EndpointResult,
}

impl ContentKind {
    const fn cache_prefix(self) -> &'static str {
        match self {
            Self::JobIr => "job-ir",
            Self::RuntimeAuthority => "runtime-authority",
            Self::TerminalResult => "terminal-result",
            Self::LogSpool => "log-spool",
            Self::EndpointRequest => "endpoint-request",
            Self::EndpointResult => "endpoint-result",
        }
    }
}

/// Protection-keyed, fixed-size identity for one endpoint result.
///
/// The bytes are safe to persist but intentionally hidden from debug output.
/// They cannot be recomputed from a low-entropy result without the exact spool
/// protection key.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueContentIdentity(Sha256Digest);

impl OpaqueContentIdentity {
    /// Wraps an identity produced by the protected-content authority.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Sha256Digest::from_bytes(bytes))
    }

    /// Borrows the opaque identity bytes for authenticated protection.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for OpaqueContentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueContentIdentity([REDACTED])")
    }
}

impl fmt::Display for OpaqueContentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl Serialize for OpaqueContentIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for OpaqueContentIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let digest = Sha256Digest::deserialize(deserializer)?;
        Ok(Self(digest))
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

    /// Returns the validated non-secret adapter identifier.
    ///
    /// The identifier may select key material, but is not itself key material.
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
    fn derive_public(
        kind: ContentKind,
        digest: Sha256Digest,
        size: u64,
        protection_id: &ProtectionId,
    ) -> Result<Self, SpoolInvariantError> {
        if kind == ContentKind::EndpointResult {
            return Err(SpoolInvariantError::InvalidContentIdentity);
        }
        let value = format!(
            "{}-{}-{digest}-{size}",
            kind.cache_prefix(),
            protection_id.as_str()
        );
        Self::validated(value)
    }

    fn derive_endpoint_result(
        identity: OpaqueContentIdentity,
        protected_allocation_bytes: u64,
        protection_id: &ProtectionId,
    ) -> Result<Self, SpoolInvariantError> {
        let value = format!(
            "{}-{}-{identity}-{protected_allocation_bytes}",
            ContentKind::EndpointResult.cache_prefix(),
            protection_id.as_str()
        );
        Self::validated(value)
    }

    fn validated(value: String) -> Result<Self, SpoolInvariantError> {
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

    /// Returns the portable filename key derived from immutable content identity.
    ///
    /// This value is non-secret but stable and therefore suitable as a local
    /// correlator only where the content receipt itself may be disclosed.
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

/// Kind-specific durable identity that never exposes endpoint-result plaintext
/// size or digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum DurableContentIdentity {
    Public {
        plaintext_bytes: u64,
        plaintext_sha256: Sha256Digest,
    },
    EndpointResult {
        protected_allocation_bytes: u64,
        opaque_identity: OpaqueContentIdentity,
    },
}

/// Immutable identity of protected content already committed by an adapter.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurableContentRef {
    kind: ContentKind,
    identity: DurableContentIdentity,
    cache_key: ContentCacheKey,
    protection_id: ProtectionId,
}

impl fmt::Debug for DurableContentRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("DurableContentRef");
        debug.field("kind", &self.kind);
        match &self.identity {
            DurableContentIdentity::Public {
                plaintext_bytes,
                plaintext_sha256,
            } => {
                debug
                    .field("plaintext_bytes", plaintext_bytes)
                    .field("plaintext_sha256", plaintext_sha256);
            }
            DurableContentIdentity::EndpointResult {
                protected_allocation_bytes,
                ..
            } => {
                debug
                    .field("protected_allocation_bytes", protected_allocation_bytes)
                    .field("opaque_identity", &"[REDACTED]");
            }
        }
        debug
            .field("cache_key", &self.cache_key)
            .field("protection_id", &self.protection_id)
            .finish()
    }
}

impl DurableContentRef {
    fn derive_cache_key(
        kind: ContentKind,
        identity: &DurableContentIdentity,
        protection_id: &ProtectionId,
    ) -> Result<ContentCacheKey, SpoolInvariantError> {
        match *identity {
            DurableContentIdentity::Public {
                plaintext_bytes,
                plaintext_sha256,
            } if kind != ContentKind::EndpointResult
                && plaintext_bytes <= MAX_CONTENT_OBJECT_BYTES =>
            {
                ContentCacheKey::derive_public(
                    kind,
                    plaintext_sha256,
                    plaintext_bytes,
                    protection_id,
                )
            }
            DurableContentIdentity::EndpointResult {
                protected_allocation_bytes,
                opaque_identity,
            } if kind == ContentKind::EndpointResult
                && valid_endpoint_result_allocation(protected_allocation_bytes) =>
            {
                ContentCacheKey::derive_endpoint_result(
                    opaque_identity,
                    protected_allocation_bytes,
                    protection_id,
                )
            }
            _ => Err(SpoolInvariantError::InvalidContentIdentity),
        }
    }

    /// Constructs the durable receipt returned by a storage adapter only after
    /// it has synchronized the verified bytes and directory metadata.
    ///
    /// # Errors
    ///
    /// Rejects content beyond the hard object bound.
    pub fn after_public_commit(
        kind: ContentKind,
        plaintext_bytes: u64,
        plaintext_sha256: Sha256Digest,
        protection_id: ProtectionId,
    ) -> Result<Self, SpoolInvariantError> {
        if kind == ContentKind::EndpointResult {
            return Err(SpoolInvariantError::InvalidContentIdentity);
        }
        if plaintext_bytes > MAX_CONTENT_OBJECT_BYTES {
            return Err(SpoolInvariantError::ObjectTooLarge);
        }
        let cache_key = ContentCacheKey::derive_public(
            kind,
            plaintext_sha256,
            plaintext_bytes,
            &protection_id,
        )?;
        Ok(Self {
            kind,
            identity: DurableContentIdentity::Public {
                plaintext_bytes,
                plaintext_sha256,
            },
            cache_key,
            protection_id,
        })
    }

    /// Constructs a receipt for an endpoint result after protected publication.
    ///
    /// # Errors
    ///
    /// Rejects a zero or globally oversized padded allocation class.
    pub fn after_endpoint_result_commit(
        protected_allocation_bytes: u64,
        opaque_identity: OpaqueContentIdentity,
        protection_id: ProtectionId,
    ) -> Result<Self, SpoolInvariantError> {
        if !valid_endpoint_result_allocation(protected_allocation_bytes) {
            return Err(SpoolInvariantError::InvalidContentIdentity);
        }
        let cache_key = ContentCacheKey::derive_endpoint_result(
            opaque_identity,
            protected_allocation_bytes,
            &protection_id,
        )?;
        Ok(Self {
            kind: ContentKind::EndpointResult,
            identity: DurableContentIdentity::EndpointResult {
                protected_allocation_bytes,
                opaque_identity,
            },
            cache_key,
            protection_id,
        })
    }

    /// Returns the semantic role included in this immutable identity.
    #[must_use]
    pub const fn kind(&self) -> ContentKind {
        self.kind
    }

    /// Returns capacity-accounted bytes for this object.
    ///
    /// Public kinds return exact plaintext bytes. Endpoint results return only
    /// their deterministic padded protected allocation class.
    #[must_use]
    pub const fn accounted_bytes(&self) -> u64 {
        match self.identity {
            DurableContentIdentity::Public {
                plaintext_bytes, ..
            } => plaintext_bytes,
            DurableContentIdentity::EndpointResult {
                protected_allocation_bytes,
                ..
            } => protected_allocation_bytes,
        }
    }

    /// Returns exact plaintext bytes only for a public content kind.
    #[must_use]
    pub const fn public_plaintext_bytes(&self) -> Option<u64> {
        match self.identity {
            DurableContentIdentity::Public {
                plaintext_bytes, ..
            } => Some(plaintext_bytes),
            DurableContentIdentity::EndpointResult { .. } => None,
        }
    }

    /// Returns the plaintext SHA-256 identity only for a public content kind.
    #[must_use]
    pub const fn public_plaintext_sha256(&self) -> Option<Sha256Digest> {
        match self.identity {
            DurableContentIdentity::Public {
                plaintext_sha256, ..
            } => Some(plaintext_sha256),
            DurableContentIdentity::EndpointResult { .. } => None,
        }
    }

    /// Returns the padded protected allocation only for an endpoint result.
    #[must_use]
    pub const fn endpoint_result_allocation_bytes(&self) -> Option<u64> {
        match self.identity {
            DurableContentIdentity::EndpointResult {
                protected_allocation_bytes,
                ..
            } => Some(protected_allocation_bytes),
            DurableContentIdentity::Public { .. } => None,
        }
    }

    /// Returns the protection-keyed identity only for an endpoint result.
    #[must_use]
    pub const fn endpoint_result_identity(&self) -> Option<&OpaqueContentIdentity> {
        match &self.identity {
            DurableContentIdentity::EndpointResult {
                opaque_identity, ..
            } => Some(opaque_identity),
            DurableContentIdentity::Public { .. } => None,
        }
    }

    /// Returns the deterministic local filename key for this identity.
    #[must_use]
    pub const fn cache_key(&self) -> &ContentCacheKey {
        &self.cache_key
    }

    /// Returns the identifier of the adapter configuration that protected the object.
    #[must_use]
    pub const fn protection_id(&self) -> &ProtectionId {
        &self.protection_id
    }

    pub(crate) fn validate(&self) -> Result<(), SpoolInvariantError> {
        let expected = Self::derive_cache_key(self.kind, &self.identity, &self.protection_id)?;
        if self.cache_key == expected {
            Ok(())
        } else {
            Err(SpoolInvariantError::InvalidCacheKey)
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableContentRefSerialize<'a> {
    Public(ContentKind, u64, Sha256Digest, &'a ProtectionId),
    Result(u64, &'a OpaqueContentIdentity, &'a ProtectionId),
}

impl Serialize for DurableContentRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = match &self.identity {
            DurableContentIdentity::Public {
                plaintext_bytes,
                plaintext_sha256,
            } => DurableContentRefSerialize::Public(
                self.kind,
                *plaintext_bytes,
                *plaintext_sha256,
                &self.protection_id,
            ),
            DurableContentIdentity::EndpointResult {
                protected_allocation_bytes,
                opaque_identity,
            } => DurableContentRefSerialize::Result(
                *protected_allocation_bytes,
                opaque_identity,
                &self.protection_id,
            ),
        };
        value.serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DurableContentRefData {
    Public(ContentKind, u64, Sha256Digest, ProtectionId),
    Result(u64, OpaqueContentIdentity, ProtectionId),
}

impl<'de> Deserialize<'de> for DurableContentRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match DurableContentRefData::deserialize(deserializer)? {
            DurableContentRefData::Public(kind, bytes, digest, protection_id) => {
                Self::after_public_commit(kind, bytes, digest, protection_id)
            }
            DurableContentRefData::Result(allocation, identity, protection_id) => {
                Self::after_endpoint_result_commit(allocation, identity, protection_id)
            }
        }
        .map_err(serde::de::Error::custom)
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

    /// Returns the maximum plaintext bytes accepted for one object.
    #[must_use]
    pub const fn max_object_bytes(self) -> u64 {
        self.object_bytes
    }

    /// Returns the maximum aggregate protected bytes retained by the spool.
    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.total_bytes
    }

    /// Returns the maximum number of immutable objects retained by the spool.
    #[must_use]
    pub const fn max_objects(self) -> u32 {
        self.objects
    }

    /// Returns the maximum encoded expansion allowed beyond plaintext length.
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
            total_bytes: MAX_CONTENT_SPOOL_BYTES,
            objects: MAX_CONTENT_OBJECTS,
            protection_overhead_bytes: 1024 * 1024,
        }
    }
}
