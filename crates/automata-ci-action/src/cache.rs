use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use automata_ci_blob::BlobDescriptor;
use automata_ci_core::GitObjectId;
use automata_ci_scm::{RepositoryId, ScmProviderId};
use thiserror::Error;

use crate::ActionSubpath;

/// Exact immutable action identity eligible for reference-index reuse.
///
/// Mutable tags and branches cannot construct this value. The requested commit
/// is retained alongside provider, repository, and action subpath so an index
/// adapter cannot alias content across provenance boundaries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImmutableActionReference {
    provider: ScmProviderId,
    repository: RepositoryId,
    revision: GitObjectId,
    subpath: ActionSubpath,
}

impl ImmutableActionReference {
    /// Creates a reference pinned to one already-validated full Git object ID.
    #[must_use]
    pub fn new(
        provider: ScmProviderId,
        repository: RepositoryId,
        revision: GitObjectId,
        subpath: ActionSubpath,
    ) -> Self {
        Self {
            provider,
            repository,
            revision,
            subpath,
        }
    }

    /// Returns the SCM provider identity.
    #[must_use]
    pub const fn provider(&self) -> &ScmProviderId {
        &self.provider
    }

    /// Returns the canonical repository identity.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Returns the exact requested commit revision.
    #[must_use]
    pub const fn revision(&self) -> &GitObjectId {
        &self.revision
    }

    /// Returns the selected action subpath.
    #[must_use]
    pub const fn subpath(&self) -> &ActionSubpath {
        &self.subpath
    }
}

/// Complete immutable mapping stored by an action reference index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedActionBundle {
    reference: ImmutableActionReference,
    resolved_revision: GitObjectId,
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
        resolved_revision: GitObjectId,
        archive: BlobDescriptor,
    ) -> Result<Self, ImmutableActionReferenceError> {
        if *reference.revision() != resolved_revision
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

    /// Returns the indexed immutable reference.
    #[must_use]
    pub const fn reference(&self) -> &ImmutableActionReference {
        &self.reference
    }

    /// Returns the provider-confirmed immutable revision.
    #[must_use]
    pub const fn resolved_revision(&self) -> GitObjectId {
        self.resolved_revision
    }

    /// Returns the verified shared archive descriptor.
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
    /// The mapping was created.
    Created,
    /// The identical mapping already existed.
    AlreadyPresent,
}

/// Stable action-reference index failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionReferenceIndexErrorKind {
    /// An existing mapping contradicts the proposed immutable mapping.
    Conflict,
    /// Durable index content failed integrity validation.
    Corrupt,
    /// A configured or durable resource bound was exceeded.
    ResourceExhausted,
    /// The local index could not complete the operation.
    Unavailable,
    /// Another process already holds the index lock.
    AlreadyLocked,
    /// The platform or configured root is unsupported.
    Unsupported,
}

/// Sanitized index error that does not expose repository identities or paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("immutable action reference index failed: {kind:?}")]
pub struct ActionReferenceIndexError {
    kind: ActionReferenceIndexErrorKind,
}

impl ActionReferenceIndexError {
    /// Creates a sanitized index error.
    #[must_use]
    pub const fn new(kind: ActionReferenceIndexErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
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
