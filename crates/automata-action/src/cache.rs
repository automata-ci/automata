use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use automata_blob::BlobDescriptor;
use automata_scm::{RepositoryId, ResolvedRevision, RevisionSpec, ScmProviderId};
use thiserror::Error;

use crate::ActionSubpath;

const GIT_COMMIT_SHA_HEX_BYTES: usize = 40;

/// Exact immutable action identity eligible for reference-index reuse.
///
/// Mutable tags and branches cannot construct this value. The requested commit
/// is retained alongside provider, repository, and action subpath so an index
/// adapter cannot alias content across provenance boundaries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImmutableActionReference {
    provider: ScmProviderId,
    repository: RepositoryId,
    revision: RevisionSpec,
    subpath: ActionSubpath,
}

impl ImmutableActionReference {
    /// Creates a reference pinned to one canonical full Git commit SHA.
    ///
    /// # Errors
    ///
    /// Rejects revisions other than exactly 40 hexadecimal bytes. The original
    /// spelling remains part of provenance even though commit comparison is
    /// ASCII case-insensitive.
    pub fn new(
        provider: ScmProviderId,
        repository: RepositoryId,
        revision: RevisionSpec,
        subpath: ActionSubpath,
    ) -> Result<Self, ImmutableActionReferenceError> {
        if !is_full_commit_sha(revision.as_str()) {
            return Err(ImmutableActionReferenceError);
        }
        Ok(Self {
            provider,
            repository,
            revision,
            subpath,
        })
    }

    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    #[must_use]
    pub const fn revision(&self) -> &RevisionSpec {
        &self.revision
    }

    #[must_use]
    pub const fn subpath(&self) -> &ActionSubpath {
        &self.subpath
    }
}

/// Complete immutable mapping stored by an action reference index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedActionBundle {
    reference: ImmutableActionReference,
    resolved_revision: ResolvedRevision,
    archive: BlobDescriptor,
}

impl IndexedActionBundle {
    /// Binds an immutable reference to an exact verified archive descriptor.
    ///
    /// # Errors
    ///
    /// Rejects a provider result that does not exactly match the requested
    /// commit or a descriptor that does not use the canonical action key and
    /// media type.
    pub fn new(
        reference: ImmutableActionReference,
        resolved_revision: ResolvedRevision,
        archive: BlobDescriptor,
    ) -> Result<Self, ImmutableActionReferenceError> {
        if !reference
            .revision()
            .as_str()
            .eq_ignore_ascii_case(resolved_revision.as_str())
            || archive.size() == 0
            || archive.media_type().as_str() != "application/gzip"
            || archive.key().as_str() != format!("actions/v1/sha256/{}.tar.gz", archive.digest())
        {
            return Err(ImmutableActionReferenceError);
        }
        Ok(Self {
            reference,
            resolved_revision,
            archive,
        })
    }

    #[must_use]
    pub const fn reference(&self) -> &ImmutableActionReference {
        &self.reference
    }

    #[must_use]
    pub const fn resolved_revision(&self) -> &ResolvedRevision {
        &self.resolved_revision
    }

    #[must_use]
    pub const fn archive(&self) -> &BlobDescriptor {
        &self.archive
    }
}

/// Object-safe authoritative mapping from immutable references to content.
///
/// Implementations must make `put_if_absent` atomic for one reference. An
/// existing non-identical mapping is a conflict and must never be overwritten.
#[async_trait]
pub trait ActionReferenceIndex: std::fmt::Debug + Send + Sync {
    /// Looks up one exact provider/repository/revision/subpath tuple.
    async fn get(
        &self,
        reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError>;

    /// Publishes one mapping exactly once or verifies the existing mapping.
    async fn put_if_absent(
        &self,
        bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError>;
}

/// Idempotent immutable-reference publication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutActionReferenceOutcome {
    Created,
    AlreadyPresent,
}

/// Stable action-reference index failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionReferenceIndexErrorKind {
    Conflict,
    Corrupt,
    ResourceExhausted,
    Unavailable,
    AlreadyLocked,
    Unsupported,
}

/// Sanitized index error that does not expose repository identities or paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("immutable action reference index failed: {kind:?}")]
pub struct ActionReferenceIndexError {
    kind: ActionReferenceIndexErrorKind,
}

impl ActionReferenceIndexError {
    #[must_use]
    pub const fn new(kind: ActionReferenceIndexErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> ActionReferenceIndexErrorKind {
        self.kind
    }
}

/// A revision or indexed record was not an exact immutable action identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("action reference is not one exact immutable commit and archive")]
pub struct ImmutableActionReferenceError;

/// Deterministic bounded in-memory index for contracts and embedded adapters.
#[derive(Clone, Debug)]
pub struct MemoryActionReferenceIndex {
    maximum_entries: usize,
    entries: Arc<RwLock<BTreeMap<ImmutableActionReference, IndexedActionBundle>>>,
}

impl MemoryActionReferenceIndex {
    /// Creates a bounded index using deterministic oldest-key eviction.
    ///
    /// # Errors
    ///
    /// Rejects a zero entry bound.
    pub fn new(maximum_entries: usize) -> Result<Self, ActionReferenceIndexError> {
        if maximum_entries == 0 {
            return Err(ActionReferenceIndexError::new(
                ActionReferenceIndexErrorKind::ResourceExhausted,
            ));
        }
        Ok(Self {
            maximum_entries,
            entries: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }
}

#[async_trait]
impl ActionReferenceIndex for MemoryActionReferenceIndex {
    async fn get(
        &self,
        reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError> {
        let entries = self.entries.read().map_err(|_| {
            ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Unavailable)
        })?;
        Ok(entries.get(reference).cloned())
    }

    async fn put_if_absent(
        &self,
        bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError> {
        let mut entries = self.entries.write().map_err(|_| {
            ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Unavailable)
        })?;
        if let Some(existing) = entries.get(bundle.reference()) {
            return if existing == &bundle {
                Ok(PutActionReferenceOutcome::AlreadyPresent)
            } else {
                Err(ActionReferenceIndexError::new(
                    ActionReferenceIndexErrorKind::Conflict,
                ))
            };
        }
        if entries.len() == self.maximum_entries {
            let oldest = entries.keys().next().cloned().ok_or_else(|| {
                ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Corrupt)
            })?;
            entries.remove(&oldest);
        }
        entries.insert(bundle.reference().clone(), bundle);
        Ok(PutActionReferenceOutcome::Created)
    }
}

fn is_full_commit_sha(value: &str) -> bool {
    value.len() == GIT_COMMIT_SHA_HEX_BYTES && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
