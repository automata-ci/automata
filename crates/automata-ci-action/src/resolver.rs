use std::sync::Arc;

use async_trait::async_trait;
use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType};
use automata_ci_scm::ScmProvider;

use crate::{
    ActionResolveError, ActionResolveErrorKind, RepositoryActionRequest, ResolvedActionBundle,
    inspect_archive, model::ResolvedActionIdentity,
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
}

impl ImmutableActionResolver {
    /// Creates a resolver backed by one SCM provider and immutable blob store.
    ///
    /// Every resolution fetches through `scm` and publishes archive bytes
    /// idempotently to the content-addressed `blobs` store.
    #[must_use]
    pub fn new(scm: Arc<dyn ScmProvider>, blobs: Arc<dyn ImmutableBlobStore>) -> Self {
        Self { scm, blobs }
    }
}

#[async_trait]
impl ActionResolver for ImmutableActionResolver {
    async fn resolve(
        &self,
        request: RepositoryActionRequest<'_>,
    ) -> Result<ResolvedActionBundle, ActionResolveError> {
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
            .put_if_absent(payload)
            .await
            .map_err(|_| ActionResolveError::new(ActionResolveErrorKind::BlobStore))?;

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
