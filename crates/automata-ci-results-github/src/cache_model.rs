use std::fmt;

use automata_ci_blob::BlobDescriptor;
use automata_ci_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::ExecutionAuthority;

const MAX_CACHE_SCOPE_BYTES: usize = 1_024;
const MAX_CACHE_AUTHORITY_SCOPES: usize = 8;
const MAX_CACHE_KEY_BYTES: usize = 512;
const MAX_CACHE_KEY_COMPONENT_BYTES: usize = 512;
const MAX_CACHE_REPOSITORY_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheModelLimitRejection {
    ScopeBytes,
    AuthorityScopes,
    KeyBytes,
    VersionBytes,
    RepositoryBytes,
}

const fn cache_scope_byte_rejection(observed: usize) -> Option<CacheModelLimitRejection> {
    if observed > MAX_CACHE_SCOPE_BYTES {
        return Some(CacheModelLimitRejection::ScopeBytes);
    }
    None
}
const fn cache_authority_scope_count_rejection(
    observed: usize,
) -> Option<CacheModelLimitRejection> {
    if observed > MAX_CACHE_AUTHORITY_SCOPES {
        return Some(CacheModelLimitRejection::AuthorityScopes);
    }
    None
}
const fn cache_key_byte_rejection(observed: usize) -> Option<CacheModelLimitRejection> {
    if observed > MAX_CACHE_KEY_BYTES {
        return Some(CacheModelLimitRejection::KeyBytes);
    }
    None
}
const fn cache_version_byte_rejection(observed: usize) -> Option<CacheModelLimitRejection> {
    if observed > MAX_CACHE_KEY_COMPONENT_BYTES {
        return Some(CacheModelLimitRejection::VersionBytes);
    }
    None
}
const fn cache_repository_byte_rejection(observed: usize) -> Option<CacheModelLimitRejection> {
    if observed > MAX_CACHE_REPOSITORY_BYTES {
        return Some(CacheModelLimitRejection::RepositoryBytes);
    }
    None
}

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
            || cache_scope_byte_rejection(scope.len()).is_some()
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

/// Server-owned repository metadata used to derive default-branch cache reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheRepositoryMetadata {
    repository: String,
    default_branch_ref: String,
}

impl CacheRepositoryMetadata {
    /// Creates metadata from one repository slug and provider branch name.
    ///
    /// The branch input is a name such as `main`, never a caller-supplied full
    /// reference. The constructor validates it and derives the canonical
    /// `refs/heads/...` cache scope.
    ///
    /// # Errors
    ///
    /// Rejects invalid repositories and branch names that are not canonical
    /// Git branch references.
    pub fn new(
        repository: impl Into<String>,
        default_branch: impl Into<String>,
    ) -> Result<Self, CacheModelError> {
        let repository = repository.into();
        let repository = normalize_repository(&repository)?;
        let default_branch = default_branch.into();
        if !is_canonical_branch_name(&default_branch) {
            return Err(CacheModelError::InvalidDefaultBranch);
        }
        let default_branch_ref = format!("refs/heads/{default_branch}");
        CacheAccessScope::new(&default_branch_ref, CachePermission::Read)
            .map_err(|_| CacheModelError::InvalidDefaultBranch)?;
        Ok(Self {
            repository,
            default_branch_ref,
        })
    }

    /// Returns the normalized repository slug.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the canonical full default-branch reference.
    #[must_use]
    pub fn default_branch_ref(&self) -> &str {
        &self.default_branch_ref
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
        let repository = normalize_repository(&repository)?;
        if scopes.is_empty() || cache_authority_scope_count_rejection(scopes.len()).is_some() {
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
        Ok(Self { repository, scopes })
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
            || cache_key_byte_rejection(value.len()).is_some()
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
            || cache_version_byte_rejection(value.len()).is_some()
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
    /// Server-owned default-branch metadata is not a canonical branch name.
    #[error("cache default branch is invalid")]
    InvalidDefaultBranch,
    /// Repository or scope-set authority is invalid.
    #[error("cache authority is invalid")]
    InvalidAuthority,
    /// A cache identity is invalid.
    #[error("cache identity is invalid")]
    InvalidIdentity,
}

fn normalize_repository(repository: &str) -> Result<String, CacheModelError> {
    let mut components = repository.split('/');
    let owner = components.next().unwrap_or_default();
    let name = components.next().unwrap_or_default();
    if cache_repository_byte_rejection(repository.len()).is_some()
        || owner.is_empty()
        || name.is_empty()
        || components.next().is_some()
        || repository.bytes().any(|byte| {
            !byte.is_ascii()
                || byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || byte == b'\\'
        })
    {
        return Err(CacheModelError::InvalidAuthority);
    }
    Ok(repository.to_ascii_lowercase())
}

fn is_canonical_branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && branch != "@"
        && !branch.starts_with(['-', '/', '.'])
        && !branch.ends_with(['/', '.'])
        && !branch.contains("//")
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && branch.split('/').all(|component| {
            !component.starts_with('.') && !component.as_bytes().ends_with(b".lock")
        })
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

impl LookupCacheEntry {
    pub(crate) fn candidates(&self) -> Vec<CacheLookupCandidate<'_>> {
        let readable_scopes = self
            .cache
            .scopes()
            .iter()
            .filter(|scope| scope.permission().can_read());
        let mut candidates = Vec::with_capacity(
            readable_scopes
                .clone()
                .count()
                .saturating_mul(self.restore_keys.len().saturating_add(2)),
        );
        for scope in readable_scopes {
            candidates.push(CacheLookupCandidate {
                cache_ref: scope.scope(),
                key: self.key.as_str(),
                exact: true,
            });
            candidates.push(CacheLookupCandidate {
                cache_ref: scope.scope(),
                key: self.key.as_str(),
                exact: false,
            });
            candidates.extend(self.restore_keys.iter().map(|key| CacheLookupCandidate {
                cache_ref: scope.scope(),
                key: key.as_str(),
                exact: false,
            }));
        }
        candidates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheLookupCandidate<'a> {
    pub(crate) cache_ref: &'a str,
    pub(crate) key: &'a str,
    pub(crate) exact: bool,
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

#[cfg(test)]
mod tests {
    use automata_ci_core::{AttemptId, FencingToken, JobId, RunId};

    use super::*;

    #[test]
    fn lookup_plan_is_scope_first_then_exact_primary_and_ordered_prefixes() {
        let cache = CacheAuthority::new(
            "owner/repository",
            vec![
                CacheAccessScope::new("refs/heads/feature", CachePermission::ReadWrite)
                    .expect("current scope"),
                CacheAccessScope::new("refs/heads/main", CachePermission::Read)
                    .expect("default scope"),
                CacheAccessScope::new("refs/heads/write-only", CachePermission::Write)
                    .expect("write-only scope"),
            ],
        )
        .expect("cache authority");
        let request = LookupCacheEntry {
            execution: ExecutionAuthority::new(
                RunId::new(),
                JobId::new(),
                AttemptId::new(),
                FencingToken::new(1).expect("fence"),
            ),
            cache,
            key: CacheKey::new("cargo-linux-exact").expect("primary key"),
            restore_keys: vec![
                CacheKey::new("cargo-linux-").expect("specific restore key"),
                CacheKey::new("cargo-").expect("broad restore key"),
            ],
            version: CacheVersion::new("version-1").expect("version"),
            observed_at_seconds: 1,
            inactivity_seconds: 1,
        };

        let actual = request
            .candidates()
            .into_iter()
            .map(|candidate| (candidate.cache_ref, candidate.key, candidate.exact))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                ("refs/heads/feature", "cargo-linux-exact", true),
                ("refs/heads/feature", "cargo-linux-exact", false),
                ("refs/heads/feature", "cargo-linux-", false),
                ("refs/heads/feature", "cargo-", false),
                ("refs/heads/main", "cargo-linux-exact", true),
                ("refs/heads/main", "cargo-linux-exact", false),
                ("refs/heads/main", "cargo-linux-", false),
                ("refs/heads/main", "cargo-", false),
            ]
        );
    }

    #[test]
    fn cache_scope_byte_limit_has_exact_boundaries() {
        assert_eq!(cache_scope_byte_rejection(MAX_CACHE_SCOPE_BYTES - 1), None);
        assert_eq!(cache_scope_byte_rejection(MAX_CACHE_SCOPE_BYTES), None);
        assert_eq!(
            cache_scope_byte_rejection(MAX_CACHE_SCOPE_BYTES + 1),
            Some(CacheModelLimitRejection::ScopeBytes)
        );
    }
    #[test]
    fn cache_authority_scope_count_limit_has_exact_boundaries() {
        assert_eq!(
            cache_authority_scope_count_rejection(MAX_CACHE_AUTHORITY_SCOPES - 1),
            None
        );
        assert_eq!(
            cache_authority_scope_count_rejection(MAX_CACHE_AUTHORITY_SCOPES),
            None
        );
        assert_eq!(
            cache_authority_scope_count_rejection(MAX_CACHE_AUTHORITY_SCOPES + 1),
            Some(CacheModelLimitRejection::AuthorityScopes)
        );
    }
    #[test]
    fn cache_key_byte_limit_has_exact_boundaries() {
        assert_eq!(cache_key_byte_rejection(MAX_CACHE_KEY_BYTES - 1), None);
        assert_eq!(cache_key_byte_rejection(MAX_CACHE_KEY_BYTES), None);
        assert_eq!(
            cache_key_byte_rejection(MAX_CACHE_KEY_BYTES + 1),
            Some(CacheModelLimitRejection::KeyBytes)
        );
    }
    #[test]
    fn cache_version_byte_limit_has_exact_boundaries() {
        assert_eq!(
            cache_version_byte_rejection(MAX_CACHE_KEY_COMPONENT_BYTES - 1),
            None
        );
        assert_eq!(
            cache_version_byte_rejection(MAX_CACHE_KEY_COMPONENT_BYTES),
            None
        );
        assert_eq!(
            cache_version_byte_rejection(MAX_CACHE_KEY_COMPONENT_BYTES + 1),
            Some(CacheModelLimitRejection::VersionBytes)
        );
    }
    #[test]
    fn cache_repository_byte_limit_has_exact_boundaries() {
        assert_eq!(
            cache_repository_byte_rejection(MAX_CACHE_REPOSITORY_BYTES - 1),
            None
        );
        assert_eq!(
            cache_repository_byte_rejection(MAX_CACHE_REPOSITORY_BYTES),
            None
        );
        assert_eq!(
            cache_repository_byte_rejection(MAX_CACHE_REPOSITORY_BYTES + 1),
            Some(CacheModelLimitRejection::RepositoryBytes)
        );
    }
}
