use std::sync::Arc;

use async_trait::async_trait;
use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType};
use automata_ci_core::GitObjectId;
use automata_ci_scm::{RevisionSpec, ScmProvider};

use crate::{
    ActionReferenceIndex, ActionResolveError, ActionResolveErrorKind, ImmutableActionReference,
    IndexedActionBundle, RepositoryActionRequest, ResolvedActionBundle,
    archive::inspect_archive_bytes, inspect_archive, model::ResolvedActionIdentity,
};

/// Resolves an action reference into one immutable, persisted bundle.
#[async_trait]
pub trait ActionResolver: std::fmt::Debug + Send + Sync {
    /// Fetches, fully inspects, and persists one repository action.
    ///
    /// Implementations must bind returned provenance to the request and must not
    /// treat an object-store digest check as a substitute for bounded semantic
    /// archive validation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized [`ActionResolveError`] identifying only the failed
    /// resolution stage.
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
    local_blobs: Option<Arc<dyn ImmutableBlobStore>>,
    references: Option<Arc<dyn ActionReferenceIndex>>,
}

impl ImmutableActionResolver {
    /// Creates a resolver backed by one SCM provider and immutable blob store.
    ///
    /// Every resolution fetches through `scm` and publishes archive bytes
    /// idempotently to the content-addressed `blobs` store.
    #[must_use]
    pub fn new(scm: Arc<dyn ScmProvider>, blobs: Arc<dyn ImmutableBlobStore>) -> Self {
        Self {
            scm,
            blobs,
            local_blobs: None,
            references: None,
        }
    }

    /// Adds a best-effort host-local immutable archive cache.
    #[must_use]
    pub fn with_local_blob_cache(mut self, local_blobs: Arc<dyn ImmutableBlobStore>) -> Self {
        self.local_blobs = Some(local_blobs);
        self
    }

    /// Adds a durable index for credential-free exact public references.
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
        // A cache hit is authorization-safe only for an unauthenticated,
        // canonical exact commit. Credentialed/private and mutable requests
        // always cross the SCM authority boundary.
        let immutable_reference = if request.is_public() {
            GitObjectId::from_provider_hex(request.revision().as_str())
                .ok()
                .map(|revision| {
                    ImmutableActionReference::new(
                        self.scm.provider_id().clone(),
                        request.repository().clone(),
                        revision,
                        request.subpath().clone(),
                    )
                })
        } else {
            None
        };
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
                .load_cached_blob(indexed.archive(), request.limits())
                .await?;
            let definition =
                inspect_archive_bytes(archive.bytes(), request.subpath(), request.limits())
                    .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Archive))?;
            let archive_bytes = archive.into_bytes();
            return Ok(ResolvedActionBundle::new(
                ResolvedActionIdentity::new(
                    reference.provider().clone(),
                    reference.repository().clone(),
                    RevisionSpec::new(reference.revision().to_string())
                        .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Internal))?,
                    indexed.resolved_revision(),
                    reference.subpath().clone(),
                ),
                indexed.archive().clone(),
                archive_bytes,
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
            || snapshot.format() != automata_ci_scm::ArchiveFormat::TarGzip
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
            .put_if_absent(payload.clone())
            .await
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::BlobStore))?;
        if let Some(local) = &self.local_blobs {
            // Shared immutable storage is authoritative. A local cache failure
            // cannot fail an otherwise valid resolution.
            let _ = local.put_if_absent(payload).await;
        }

        if let (Some(references), Some(reference)) = (self.references.as_ref(), immutable_reference)
        {
            let indexed =
                IndexedActionBundle::new(reference, snapshot.resolved_revision(), archive.clone())
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
                snapshot.resolved_revision(),
                request.subpath().clone(),
            ),
            archive,
            snapshot.bytes().clone(),
            definition,
        ))
    }
}

impl ImmutableActionResolver {
    async fn load_cached_blob(
        &self,
        descriptor: &automata_ci_blob::BlobDescriptor,
        limits: crate::ActionBundleLimits,
    ) -> Result<automata_ci_blob::VerifiedBlob, ActionResolveError> {
        let maximum = limits.compressed().maximum_bytes();
        if let Some(local) = &self.local_blobs
            && let Ok(blob) = local.get_verified(descriptor, maximum).await
        {
            return Ok(blob);
        }
        let blob = self
            .blobs
            .get_verified(descriptor, maximum)
            .await
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::BlobStore))?;
        if let Some(local) = &self.local_blobs {
            let payload = BlobPayload::verify(descriptor.clone(), blob.bytes().clone())
                .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::Internal))?;
            let _ = local.put_if_absent(payload).await;
        }
        Ok(blob)
    }
}
