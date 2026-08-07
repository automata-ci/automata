use std::sync::Arc;

use async_trait::async_trait;
use automata_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType};
use automata_scm::ScmProvider;

use crate::{
    ActionReferenceIndex, ActionResolveError, ActionResolveErrorKind, ImmutableActionReference,
    IndexedActionBundle, RepositoryActionRequest, ResolvedActionBundle, inspect_archive,
    inspect_archive_bytes, model::ResolvedActionIdentity,
};

/// Resolves an action reference into one immutable, persisted bundle.
#[async_trait]
pub trait ActionResolver: std::fmt::Debug + Send + Sync {
    async fn resolve(
        &self,
        request: RepositoryActionRequest<'_>,
    ) -> Result<ResolvedActionBundle, ActionResolveError>;
}

/// Composition of any SCM provider and immutable object-store adapter.
#[derive(Debug)]
pub struct ImmutableActionResolver {
    scm: Arc<dyn ScmProvider>,
    blobs: Arc<dyn ImmutableBlobStore>,
    references: Option<Arc<dyn ActionReferenceIndex>>,
}

impl ImmutableActionResolver {
    #[must_use]
    pub fn new(scm: Arc<dyn ScmProvider>, blobs: Arc<dyn ImmutableBlobStore>) -> Self {
        Self {
            scm,
            blobs,
            references: None,
        }
    }

    /// Adds a durable immutable-reference index consulted before SCM access.
    #[must_use]
    pub fn with_reference_index(mut self, references: Arc<dyn ActionReferenceIndex>) -> Self {
        self.references = Some(references);
        self
    }
}

#[async_trait]
impl ActionResolver for ImmutableActionResolver {
    async fn resolve(
        &self,
        request: RepositoryActionRequest<'_>,
    ) -> Result<ResolvedActionBundle, ActionResolveError> {
        let immutable_reference = ImmutableActionReference::new(
            self.scm.provider_id().clone(),
            request.repository().clone(),
            request.revision().clone(),
            request.subpath().clone(),
        )
        .ok();
        if let (Some(references), Some(reference)) =
            (self.references.as_ref(), immutable_reference.as_ref())
            && let Some(indexed) = references
                .get(reference)
                .await
                .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::ReferenceCache))?
        {
            if indexed.reference() != reference {
                return Err(ActionResolveError::new(
                    ActionResolveErrorKind::ReferenceCache,
                ));
            }
            let archive = self
                .blobs
                .get_verified(
                    indexed.archive(),
                    request.limits().compressed().maximum_bytes(),
                )
                .await
                .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::BlobStore))?;
            let definition =
                inspect_archive_bytes(archive.bytes(), request.subpath(), request.limits())
                    .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Archive))?;
            return Ok(ResolvedActionBundle::new(
                ResolvedActionIdentity::new(
                    reference.provider().clone(),
                    reference.repository().clone(),
                    reference.revision().clone(),
                    indexed.resolved_revision().clone(),
                    reference.subpath().clone(),
                ),
                indexed.archive().clone(),
                definition,
            ));
        }

        let snapshot = self
            .scm
            .fetch_snapshot(request.snapshot_request())
            .await
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Scm))?;
        if snapshot.provider() != self.scm.provider_id()
            || snapshot.repository() != request.repository()
            || snapshot.requested_revision() != request.revision()
            || snapshot.format() != automata_scm::ArchiveFormat::TarGzip
            || snapshot.size() > request.limits().compressed().maximum_bytes()
        {
            return Err(ActionResolveError::new(ActionResolveErrorKind::Internal));
        }
        let definition = inspect_archive(&snapshot, request.subpath(), request.limits())
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Archive))?;
        let digest = snapshot.digest();
        let key = BlobKey::new(format!("actions/v1/sha256/{digest}.tar.gz"))
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Internal))?;
        let media_type = MediaType::new("application/gzip")
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Internal))?;
        let payload = BlobPayload::from_bytes(key, media_type, snapshot.bytes().clone());
        let archive = payload.descriptor().clone();
        self.blobs
            .put_if_absent(payload)
            .await
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::BlobStore))?;

        if let (Some(references), Some(reference)) = (self.references.as_ref(), immutable_reference)
        {
            let indexed = IndexedActionBundle::new(
                reference,
                snapshot.resolved_revision().clone(),
                archive.clone(),
            )
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Internal))?;
            references
                .put_if_absent(indexed)
                .await
                .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::ReferenceCache))?;
        }

        Ok(ResolvedActionBundle::new(
            ResolvedActionIdentity::new(
                snapshot.provider().clone(),
                snapshot.repository().clone(),
                snapshot.requested_revision().clone(),
                snapshot.resolved_revision().clone(),
                request.subpath().clone(),
            ),
            archive,
            definition,
        ))
    }
}
