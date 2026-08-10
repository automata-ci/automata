use std::fmt;

use automata_ci_blob::BlobDescriptor;
use automata_ci_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::ExecutionAuthority;

/// GitHub cache access-control permission encoded in the runtime JWT `ac` claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CachePermission {
    /// The scope may restore cache entries but may not create them.
    Read = 1,
    /// The scope may create cache entries but may not restore them.
    Write = 2,
    /// The scope may both restore and create cache entries.
    ReadWrite = 3,
}

impl CachePermission {
    /// Returns whether the permission grants reads.
    #[must_use]
    pub const fn can_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Returns whether the permission grants writes.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

impl Serialize for CachePermission {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for CachePermission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::ReadWrite),
            _ => Err(serde::de::Error::custom(
                "cache permission must be 1, 2, or 3",
            )),
        }
    }
}

/// One bounded Git reference and permission carried in the authenticated `ac` claim.
///
/// The capitalized field names are the current GitHub runner representation and
/// are also consumed by `go-actions-cache`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheAccessScope {
    #[serde(rename = "Scope")]
    scope: String,
    #[serde(rename = "Permission")]
    permission: CachePermission,
}

impl CacheAccessScope {
    /// Creates a scope for one canonical full Git reference.
    ///
    /// # Errors
    ///
    /// Rejects non-`refs/` values, controls, whitespace, and values over 1,024 bytes.
    pub fn new(
        scope: impl Into<String>,
        permission: CachePermission,
    ) -> Result<Self, CacheModelError> {
        let scope = scope.into();
        if scope.len() < 6
            || scope.len() > 1_024
            || !scope.starts_with("refs/")
            || scope
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(CacheModelError::InvalidScope);
        }
        Ok(Self { scope, permission })
    }

    /// Returns the exact full Git reference.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the closed permission value.
    #[must_use]
    pub const fn permission(&self) -> CachePermission {
        self.permission
    }
}

/// Authenticated repository and reference authority for GitHub cache operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheAuthority {
    repository: String,
    scopes: Vec<CacheAccessScope>,
}

impl CacheAuthority {
    /// Creates required, bounded access controls for one GitHub repository.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical `owner/name`, an empty scope list, duplicate
    /// references, or more than eight references.
    pub fn new(
        repository: impl Into<String>,
        scopes: Vec<CacheAccessScope>,
    ) -> Result<Self, CacheModelError> {
        let repository = repository.into();
        let mut components = repository.split('/');
        let owner = components.next().unwrap_or_default();
        let name = components.next().unwrap_or_default();
        if repository.len() > 512
            || owner.is_empty()
            || name.is_empty()
            || components.next().is_some()
            || repository.bytes().any(|byte| {
                !byte.is_ascii()
                    || byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || byte == b'\\'
            })
            || scopes.is_empty()
            || scopes.len() > 8
        {
            return Err(CacheModelError::InvalidAuthority);
        }
        let mut ordered = scopes
            .iter()
            .map(CacheAccessScope::scope)
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CacheModelError::InvalidAuthority);
        }
        Ok(Self {
            repository: repository.to_ascii_lowercase(),
            scopes,
        })
    }

    /// Returns the normalized repository slug authenticated by the issuer.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns ordered reference permissions. The current reference is first.
    #[must_use]
    pub fn scopes(&self) -> &[CacheAccessScope] {
        &self.scopes
    }

    /// Returns the current writable reference, if any.
    #[must_use]
    pub fn writable_scope(&self) -> Option<&str> {
        self.scopes
            .iter()
            .find(|scope| scope.permission().can_write())
            .map(CacheAccessScope::scope)
    }

    /// Returns whether one exact reference is readable.
    #[must_use]
    pub fn can_read(&self, cache_ref: &str) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope.scope() == cache_ref && scope.permission().can_read())
    }
}

/// A validated cache key from the current `CacheService` protocol.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheKey(String);

impl CacheKey {
    /// Validates the 512-byte GitHub key limit and the protocol's comma ban.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, comma-containing, or control-containing keys.
    pub fn new(value: impl Into<String>) -> Result<Self, CacheModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value.contains(',')
            || value.chars().any(char::is_control)
        {
            return Err(CacheModelError::InvalidKey);
        }
        Ok(Self(value))
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque, bounded cache archive version computed by the action client.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheVersion(String);

impl CacheVersion {
    /// Creates a nonempty version no larger than 512 UTF-8 bytes.
    ///
    /// # Errors
    ///
    /// Rejects controls, whitespace, empty values, and oversized values.
    pub fn new(value: impl Into<String>) -> Result<Self, CacheModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(CacheModelError::InvalidVersion);
        }
        Ok(Self(value))
    }

    /// Returns the opaque version.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable UUID returned by `FinalizeCacheEntryUpload`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheEntryId(Uuid);

impl CacheEntryId {
    /// Creates an identity from a non-nil UUID.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID.
    pub const fn new(value: Uuid) -> Result<Self, CacheModelError> {
        if value.is_nil() {
            return Err(CacheModelError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for CacheEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Positive `int64` cache database identity returned by the current protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheProtocolEntryId(i64);

impl CacheProtocolEntryId {
    /// Creates a positive protocol identity.
    ///
    /// # Errors
    ///
    /// Rejects zero and negative database identities.
    pub const fn new(value: i64) -> Result<Self, CacheModelError> {
        if value <= 0 {
            return Err(CacheModelError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the protobuf-compatible signed 64-bit identity.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// One immutable staged block belonging to a cache entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheBlock {
    block_id: String,
    descriptor: BlobDescriptor,
}

impl CacheBlock {
    /// Creates a block after Azure block-ID validation.
    #[must_use]
    pub fn new(block_id: String, descriptor: BlobDescriptor) -> Self {
        Self {
            block_id,
            descriptor,
        }
    }

    /// Returns the encoded Azure block ID.
    #[must_use]
    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    /// Returns the exact immutable object descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &BlobDescriptor {
        &self.descriptor
    }
}

/// Durable create result used for exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatedCacheEntry {
    /// Stable entry and upload identity.
    pub entry_id: CacheEntryId,
}

/// A committed entry ready for server-side content verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCacheFinalization {
    /// Stable entry identity.
    pub entry_id: CacheEntryId,
    /// Ordered immutable blocks.
    pub blocks: Vec<CacheBlock>,
    /// Exact committed byte count.
    pub size: u64,
}

/// Durable response to a finalize preparation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheFinalizationPreparation {
    /// The exact request was already finalized and is an idempotent replay.
    Finalized(FinalizedCacheEntry),
    /// The committed blocks must be verified before publication.
    Verify(PreparedCacheFinalization),
}

/// Immutable finalized cache entry metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedCacheEntry {
    /// Stable entry identity.
    pub entry_id: CacheEntryId,
    /// Positive database identity exposed by `FinalizeCacheEntryUpload`.
    pub protocol_entry_id: CacheProtocolEntryId,
    /// Repository slug authenticated at creation.
    pub repository: String,
    /// Exact Git reference scope.
    pub cache_ref: String,
    /// Exact cache key.
    pub key: CacheKey,
    /// Exact version.
    pub version: CacheVersion,
    /// Concatenated archive digest.
    pub digest: Sha256Digest,
    /// Concatenated archive size.
    pub size: u64,
    /// Ordered immutable blocks.
    pub blocks: Vec<CacheBlock>,
}

/// Sanitized cache model validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheModelError {
    /// A cache key violates the protocol limits.
    #[error("cache key is invalid")]
    InvalidKey,
    /// A cache version violates the protocol limits.
    #[error("cache version is invalid")]
    InvalidVersion,
    /// A reference access-control scope is invalid.
    #[error("cache access-control scope is invalid")]
    InvalidScope,
    /// Repository or scope-set authority is invalid.
    #[error("cache authority is invalid")]
    InvalidAuthority,
    /// A cache identity is invalid.
    #[error("cache identity is invalid")]
    InvalidIdentity,
}

/// One cache create mutation bound to current execution authority.
#[derive(Clone, Debug)]
pub struct CreateCacheEntry {
    /// Current job-attempt fence.
    pub execution: ExecutionAuthority,
    /// Authenticated repository/ref authority.
    pub cache: CacheAuthority,
    /// Exact new/replayed entry identity.
    pub entry_id: CacheEntryId,
    /// Immutable cache key.
    pub key: CacheKey,
    /// Immutable cache version.
    pub version: CacheVersion,
    /// Server observation time.
    pub observed_at_seconds: u64,
}

/// One cache block reservation.
#[derive(Clone, Debug)]
pub struct ReserveCacheBlock {
    /// Entry identity from the signed upload URL.
    pub entry_id: CacheEntryId,
    /// Exact staged block.
    pub block: CacheBlock,
    /// Server observation time.
    pub observed_at_seconds: u64,
    /// Maximum blocks in an entry.
    pub maximum_blocks: usize,
    /// Maximum staged bytes in an entry.
    pub maximum_entry_bytes: u64,
}

/// One cache block completion after immutable object publication.
#[derive(Clone, Debug)]
pub struct CompleteCacheBlock {
    /// Entry identity.
    pub entry_id: CacheEntryId,
    /// Exact staged block.
    pub block: CacheBlock,
    /// Server observation time.
    pub observed_at_seconds: u64,
}

/// One ordered Azure block-list commit.
#[derive(Clone, Debug)]
pub struct CommitCacheBlocks {
    /// Entry identity.
    pub entry_id: CacheEntryId,
    /// Ordered block IDs.
    pub block_ids: Vec<String>,
    /// Domain-separated list digest.
    pub list_digest: Sha256Digest,
    /// Server observation time.
    pub observed_at_seconds: u64,
    /// Maximum blocks in an entry.
    pub maximum_blocks: usize,
    /// Maximum bytes in an entry.
    pub maximum_entry_bytes: u64,
}

/// Exact finalize request after HTTP and token validation.
#[derive(Clone, Debug)]
pub struct PrepareCacheFinalization {
    /// Current job-attempt fence.
    pub execution: ExecutionAuthority,
    /// Authenticated repository/ref authority.
    pub cache: CacheAuthority,
    /// Immutable key.
    pub key: CacheKey,
    /// Immutable version.
    pub version: CacheVersion,
    /// Client-declared archive size.
    pub claimed_size: u64,
}

/// Final publication after all block bytes were verified.
#[derive(Clone, Debug)]
pub struct CompleteCacheFinalization {
    /// Current job-attempt fence.
    pub execution: ExecutionAuthority,
    /// Authenticated repository/ref authority.
    pub cache: CacheAuthority,
    /// Stable entry identity.
    pub entry_id: CacheEntryId,
    /// Immutable key.
    pub key: CacheKey,
    /// Immutable version.
    pub version: CacheVersion,
    /// Verified concatenated digest.
    pub digest: Sha256Digest,
    /// Verified byte count.
    pub size: u64,
    /// Server observation time.
    pub observed_at_seconds: u64,
    /// Repository-wide finalized-byte ceiling.
    pub repository_quota_bytes: u64,
    /// Inactivity lifetime used before quota eviction.
    pub inactivity_seconds: u64,
}

/// Ordered lookup request from `GetCacheEntryDownloadURL`.
#[derive(Clone, Debug)]
pub struct LookupCacheEntry {
    /// Current caller job-attempt fence.
    pub execution: ExecutionAuthority,
    /// Authenticated repository/ref read authority.
    pub cache: CacheAuthority,
    /// Exact primary key.
    pub key: CacheKey,
    /// Ordered restore-key prefixes.
    pub restore_keys: Vec<CacheKey>,
    /// Exact version.
    pub version: CacheVersion,
    /// Server observation time.
    pub observed_at_seconds: u64,
    /// Inactivity lifetime.
    pub inactivity_seconds: u64,
}

/// Exact signed-download resolution.
#[derive(Clone, Copy, Debug)]
pub struct ResolveCacheDownload {
    /// Stable entry identity.
    pub entry_id: CacheEntryId,
    /// Immutable digest bound into the signed URL.
    pub digest: Sha256Digest,
    /// Server observation time.
    pub observed_at_seconds: u64,
    /// Inactivity lifetime.
    pub inactivity_seconds: u64,
}
