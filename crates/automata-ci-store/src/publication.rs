use async_trait::async_trait;
use automata_ci_auth::{
    authorization::RepositoryPublicationPolicy,
    management::{ManagementActor, ManagementRevision},
    time::UnixTimestamp,
};
use thiserror::Error;

use crate::RepositoryId;

/// Current independently configurable publication preferences for one repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPublicationSettings {
    repository_id: RepositoryId,
    policy: RepositoryPublicationPolicy,
    revision: ManagementRevision,
    updated_at: UnixTimestamp,
}

impl RepositoryPublicationSettings {
    #[must_use]
    pub const fn new(
        repository_id: RepositoryId,
        policy: RepositoryPublicationPolicy,
        revision: ManagementRevision,
        updated_at: UnixTimestamp,
    ) -> Self {
        Self {
            repository_id,
            policy,
            revision,
            updated_at,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    #[must_use]
    pub const fn policy(&self) -> RepositoryPublicationPolicy {
        self.policy
    }

    #[must_use]
    pub const fn revision(&self) -> ManagementRevision {
        self.revision
    }

    #[must_use]
    pub const fn updated_at(&self) -> UnixTimestamp {
        self.updated_at
    }
}

/// Revision-guarded update of dashboard, log, and artifact preferences.
///
/// Public log/artifact preference is still subject to each immutable output's
/// secret-exposure ceiling. This command cannot widen that ceiling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateRepositoryPublication {
    actor: ManagementActor,
    repository_id: RepositoryId,
    expected_revision: ManagementRevision,
    policy: RepositoryPublicationPolicy,
}

impl UpdateRepositoryPublication {
    #[must_use]
    pub const fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        expected_revision: ManagementRevision,
        policy: RepositoryPublicationPolicy,
    ) -> Self {
        Self {
            actor,
            repository_id,
            expected_revision,
            policy,
        }
    }

    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    #[must_use]
    pub const fn expected_revision(&self) -> ManagementRevision {
        self.expected_revision
    }

    #[must_use]
    pub const fn policy(&self) -> RepositoryPublicationPolicy {
        self.policy
    }
}

/// Closed, non-enumerating result of a publication preference update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateRepositoryPublicationOutcome {
    Applied(RepositoryPublicationSettings),
    Forbidden,
    SessionStale,
    NotFound,
    RevisionConflict { current: ManagementRevision },
}

/// Backend-neutral repository publication mutation boundary.
#[async_trait]
pub trait RepositoryPublicationRepository: std::fmt::Debug + Send + Sync {
    async fn update_repository_publication(
        &self,
        request: UpdateRepositoryPublication,
    ) -> Result<UpdateRepositoryPublicationOutcome, PublicationRepositoryError>;
}

/// Sanitized publication-settings persistence failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicationRepositoryError {
    #[error("repository publication request is invalid")]
    InvalidRequest,
    #[error("repository publication storage is unavailable")]
    Unavailable,
    #[error("durable repository publication data violates an invariant")]
    CorruptData,
}
