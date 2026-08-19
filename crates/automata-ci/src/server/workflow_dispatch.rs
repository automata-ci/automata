use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretStringRef;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_provider::{
    ControlCredentialClaim, ControlCredentialProvider, ControlCredentialProviderError,
    ControlCredentialRequest, ProviderControlCredentialId, ProviderControlCredentialWorkerId,
    ProviderControlOperation, ProviderControlOperationSet, ProviderLifecycleState,
    ProviderManifestRepository,
};
use automata_ci_provider_github::GithubConnectionPolicy;
use automata_ci_scm::{
    ArchiveFormat, ArchiveLimits, RepositoryId as ScmRepositoryId, RevisionSpec, ScmErrorKind,
    ScmProvider, SnapshotRequest,
};
use automata_ci_store::{
    AdmissionObject, AuthenticatedWorkflowDispatchSource, BeginWorkflowDispatchSourceResolution,
    CompleteWorkflowDispatchSourceResolution, GithubProviderManifestRepository,
    GithubServerServiceWorkerId, LogicalWorkflowAdmissionStoreError,
    MAX_WORKFLOW_DISPATCH_SOURCE_CLAIM_MILLIS, ObjectKey, StoreError, WorkflowDispatchSourceClaim,
    WorkflowDispatchSourceResolutionOutcome, WorkflowDispatchSourceResolutionRepository,
    WorkflowDispatchSourceResolutionStoreError,
};
use automata_ci_workflow_actions::{
    RepositoryWorkflowDiscoveryLimits, discover_provider_workflows,
};
use automata_ci_workflow_service::{
    GITHUB_WORKFLOW_MEDIA_TYPE, GithubWorkflowDispatchError, GithubWorkflowDispatchInputValue,
    GithubWorkflowDispatchInputs, GithubWorkflowDispatchService, WorkflowAdmissionError,
    WorkflowDispatchAuthorization,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use crate::app::workflow_dispatch_api::{
    WorkflowDispatchApiBackend, WorkflowDispatchApiBackendError, WorkflowDispatchApiInputValue,
    WorkflowDispatchApiOutcome, WorkflowDispatchApiRequest,
};

/// Product adapter from authenticated CLI input to exact durable-source dispatch.
pub(crate) struct OperationalWorkflowDispatchBackend {
    service: GithubWorkflowDispatchService,
    source_resolutions: Arc<dyn WorkflowDispatchSourceResolutionRepository>,
    manifests: Arc<dyn GithubProviderManifestRepository>,
    connections: Arc<dyn ProviderManifestRepository>,
    source: Arc<dyn ScmProvider>,
    blobs: Arc<dyn ImmutableBlobStore>,
    credentials: Arc<dyn ControlCredentialProvider>,
    worker_id: GithubServerServiceWorkerId,
}

impl OperationalWorkflowDispatchBackend {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        service: GithubWorkflowDispatchService,
        source_resolutions: Arc<dyn WorkflowDispatchSourceResolutionRepository>,
        manifests: Arc<dyn GithubProviderManifestRepository>,
        connections: Arc<dyn ProviderManifestRepository>,
        source: Arc<dyn ScmProvider>,
        blobs: Arc<dyn ImmutableBlobStore>,
        credentials: Arc<dyn ControlCredentialProvider>,
        worker_id: GithubServerServiceWorkerId,
    ) -> Self {
        Self {
            service,
            source_resolutions,
            manifests,
            connections,
            source,
            blobs,
            credentials,
            worker_id,
        }
    }

    async fn resolve_source(
        &self,
        authorization: &WorkflowDispatchAuthorization,
        git_ref: &str,
        operation_id: automata_ci_core::OperationId,
    ) -> Result<(AuthenticatedWorkflowDispatchSource, Bytes), WorkflowDispatchApiBackendError> {
        let observed_at = system_now().ok_or(WorkflowDispatchApiBackendError::Unavailable)?;
        let request = BeginWorkflowDispatchSourceResolution::new(
            authorization.actor().clone(),
            authorization.repository_id(),
            authorization.workflow_id(),
            git_ref,
            operation_id,
            self.worker_id,
            observed_at,
            MAX_WORKFLOW_DISPATCH_SOURCE_CLAIM_MILLIS,
        )
        .map_err(|_| WorkflowDispatchApiBackendError::InvalidRequest)?;
        match self
            .source_resolutions
            .begin_workflow_dispatch_source_resolution(request)
            .await
            .map_err(|error| classify_source_store_error(&error))?
        {
            WorkflowDispatchSourceResolutionOutcome::Resolved(source) => {
                let bytes = self.load_source(&source).await?;
                Ok((source, bytes))
            }
            WorkflowDispatchSourceResolutionOutcome::Claimed(claim) => {
                match self.resolve_claimed_source(claim.clone()).await {
                    Ok(source) => {
                        let bytes = self.load_source(&source).await?;
                        Ok((source, bytes))
                    }
                    Err(error) => {
                        if self
                            .source_resolutions
                            .release_workflow_dispatch_source_resolution(claim)
                            .await
                            .is_err()
                        {
                            return Err(WorkflowDispatchApiBackendError::Unavailable);
                        }
                        Err(error)
                    }
                }
            }
        }
    }

    async fn resolve_claimed_source(
        &self,
        claim: WorkflowDispatchSourceClaim,
    ) -> Result<AuthenticatedWorkflowDispatchSource, WorkflowDispatchApiBackendError> {
        let record = self
            .manifests
            .load_github_provider_manifest_revision(
                claim.tenant(),
                claim.connection_id(),
                claim.manifest_revision(),
            )
            .await
            .map_err(|_| WorkflowDispatchApiBackendError::Unavailable)?;
        let manifest = record.manifest();
        if manifest.digest() != claim.manifest_digest()
            || manifest.repository_id() != claim.repository_id()
            || manifest.connection_id() != claim.connection_id()
        {
            return Err(WorkflowDispatchApiBackendError::Conflict);
        }
        let connection = self.load_dispatch_connection(&claim, manifest).await?;
        let repository = ScmRepositoryId::new(manifest.github_repository_name().as_str())
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        let revision = RevisionSpec::new(claim.git_ref())
            .map_err(|_| WorkflowDispatchApiBackendError::InvalidRequest)?;
        let limits = ArchiveLimits::new(manifest.limits().archive_max_compressed_bytes())
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        let observed_at = system_now().ok_or(WorkflowDispatchApiBackendError::Unavailable)?;
        let operation = ProviderControlOperation::RepositoryRead;
        let request = workflow_dispatch_credential_request(&claim, &connection, observed_at)?;
        let credential = self
            .credentials
            .acquire(&request)
            .await
            .map_err(classify_source_credential_error)?;
        if credential.request_digest() != request.digest() || !credential.permits(operation) {
            credential.release().await;
            return Err(WorkflowDispatchApiBackendError::Invariant);
        }
        let Ok(token) = SecretStringRef::new(credential.expose_secret()) else {
            credential.release().await;
            return Err(WorkflowDispatchApiBackendError::Invariant);
        };
        let result = self
            .source
            .fetch_snapshot(SnapshotRequest::authenticated(
                &repository,
                &revision,
                token,
                limits,
            ))
            .await;
        credential.release().await;
        let snapshot = result.map_err(classify_scm_error)?;
        if snapshot.provider().as_str() != "github"
            || snapshot.repository() != &repository
            || snapshot.requested_revision() != &revision
            || snapshot.format() != ArchiveFormat::TarGzip
            || snapshot.size() > limits.maximum_bytes()
        {
            return Err(WorkflowDispatchApiBackendError::Invariant);
        }
        let commit_sha = snapshot.resolved_revision();
        let workflows = discover_provider_workflows(snapshot.bytes(), discovery_limits(manifest)?)
            .map_err(|_| WorkflowDispatchApiBackendError::InvalidRequest)?;
        let mut matching = workflows
            .into_iter()
            .filter(|workflow| workflow.path() == claim.workflow_path());
        let workflow = matching
            .next()
            .ok_or(WorkflowDispatchApiBackendError::NotFound)?;
        if matching.next().is_some() {
            return Err(WorkflowDispatchApiBackendError::Invariant);
        }
        let (_, source) = workflow.into_parts();
        let bytes =
            Bytes::from(source.map_err(|_| WorkflowDispatchApiBackendError::InvalidRequest)?);
        let source = self.store_source(bytes).await?;
        let complete = CompleteWorkflowDispatchSourceResolution::new(claim, commit_sha, source)
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        self.source_resolutions
            .complete_workflow_dispatch_source_resolution(complete)
            .await
            .map_err(|error| classify_source_store_error(&error))
    }

    async fn load_dispatch_connection(
        &self,
        claim: &WorkflowDispatchSourceClaim,
        manifest: &automata_ci_store::GithubProviderManifest,
    ) -> Result<automata_ci_provider::ProviderConnectionManifest, WorkflowDispatchApiBackendError>
    {
        let connection = self
            .connections
            .current_connection(claim.connection_id())
            .await
            .map_err(|_| WorkflowDispatchApiBackendError::Unavailable)?
            .ok_or(WorkflowDispatchApiBackendError::Conflict)?;
        let policy = GithubConnectionPolicy::decode(connection.configuration().adapter_policy())
            .map_err(|_| WorkflowDispatchApiBackendError::Conflict)?;
        if connection.state() != ProviderLifecycleState::Active
            || connection.configuration().workspace_id().to_string() != claim.tenant().as_str()
            || connection
                .configuration()
                .repository()
                .external_id()
                .as_str()
                != manifest.github_repository_id().get().to_string()
            || policy.installation_id().get() != manifest.installation_id().get()
            || policy.repository().as_str() != manifest.github_repository_name().as_str()
        {
            return Err(WorkflowDispatchApiBackendError::Conflict);
        }
        Ok(connection)
    }

    async fn store_source(
        &self,
        bytes: Bytes,
    ) -> Result<AdmissionObject, WorkflowDispatchApiBackendError> {
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let key_text = format!("admission/v2/workflow-source/sha256/{digest}");
        let key = BlobKey::new(key_text.clone())
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        let media_type = MediaType::new(GITHUB_WORKFLOW_MEDIA_TYPE)
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        let payload = BlobPayload::from_bytes(key, media_type, bytes);
        let source = AdmissionObject::new(
            digest,
            ObjectKey::new(key_text).map_err(|_| WorkflowDispatchApiBackendError::Invariant)?,
            payload.descriptor().size(),
            GITHUB_WORKFLOW_MEDIA_TYPE,
        )
        .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        self.blobs
            .put_if_absent(payload)
            .await
            .map_err(|error| classify_blob_error(error.kind()))?;
        Ok(source)
    }

    async fn load_source(
        &self,
        source: &AuthenticatedWorkflowDispatchSource,
    ) -> Result<Bytes, WorkflowDispatchApiBackendError> {
        let object = source.source();
        let descriptor = BlobDescriptor::new(
            BlobKey::new(object.object_key().as_str())
                .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?,
            object.digest(),
            object.encoded_size(),
            MediaType::new(object.media_type())
                .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?,
        );
        self.blobs
            .get_verified(&descriptor, object.encoded_size())
            .await
            .map(automata_ci_blob::VerifiedBlob::into_bytes)
            .map_err(|error| classify_blob_error(error.kind()))
    }
}

impl fmt::Debug for OperationalWorkflowDispatchBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalWorkflowDispatchBackend")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl WorkflowDispatchApiBackend for OperationalWorkflowDispatchBackend {
    async fn dispatch(
        &self,
        request: WorkflowDispatchApiRequest,
    ) -> Result<WorkflowDispatchApiOutcome, WorkflowDispatchApiBackendError> {
        let authorization = WorkflowDispatchAuthorization::new(
            request.actor().clone(),
            request.repository_id(),
            request.workflow_id(),
        )
        .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        let inputs = request
            .inputs()
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    WorkflowDispatchApiInputValue::Boolean(value) => {
                        GithubWorkflowDispatchInputValue::Boolean(*value)
                    }
                    WorkflowDispatchApiInputValue::String(value) => {
                        GithubWorkflowDispatchInputValue::String(value.clone())
                    }
                };
                (key.as_str().to_owned(), value)
            })
            .collect::<Vec<_>>();
        let inputs = GithubWorkflowDispatchInputs::try_new(inputs)
            .map_err(|_| WorkflowDispatchApiBackendError::InvalidRequest)?;
        let (source, bytes) = self
            .resolve_source(&authorization, request.git_ref(), request.operation_id())
            .await?;
        let result = self
            .service
            .dispatch_from_authenticated_source(
                authorization,
                source,
                bytes,
                inputs,
                request.operation_id(),
                None,
            )
            .await
            .map_err(|error| classify_dispatch_error(&error))?;
        WorkflowDispatchApiOutcome::new(
            result.receipt().run_id(),
            result.receipt().run_number(),
            result.receipt().is_replay(),
        )
    }
}

fn discovery_limits(
    manifest: &automata_ci_store::GithubProviderManifest,
) -> Result<RepositoryWorkflowDiscoveryLimits, WorkflowDispatchApiBackendError> {
    let limits = manifest.limits();
    RepositoryWorkflowDiscoveryLimits::new(
        limits.archive_max_compressed_bytes(),
        limits.archive_max_decompressed_bytes(),
        usize::try_from(limits.archive_max_entries())
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?,
        limits.archive_max_expanded_bytes(),
        usize::try_from(limits.archive_max_entry_path_bytes())
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?,
        usize::try_from(limits.archive_max_workflows())
            .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?,
        limits.workflow_max_bytes(),
    )
    .map_err(|_| WorkflowDispatchApiBackendError::Invariant)
}

fn system_now() -> Option<UnixMillis> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok().map(UnixMillis::new)
}

fn workflow_dispatch_credential_request(
    claim: &WorkflowDispatchSourceClaim,
    connection: &automata_ci_provider::ProviderConnectionManifest,
    observed_at: UnixMillis,
) -> Result<ControlCredentialRequest, WorkflowDispatchApiBackendError> {
    if observed_at < claim.claimed_at() || observed_at >= claim.expires_at() {
        return Err(WorkflowDispatchApiBackendError::Conflict);
    }
    let required_through = claim
        .expires_at()
        .get()
        .checked_add(5 * 60 * 1_000)
        .ok_or(WorkflowDispatchApiBackendError::Invariant)?;
    let validity_millis = required_through
        .checked_sub(observed_at.get())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(WorkflowDispatchApiBackendError::Invariant)?;
    let control_claim = workflow_dispatch_control_claim(claim)?;
    let operations = ProviderControlOperationSet::new([ProviderControlOperation::RepositoryRead])
        .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
    ControlCredentialRequest::new(
        control_claim,
        connection,
        operations,
        observed_at,
        validity_millis,
    )
    .map_err(|_| WorkflowDispatchApiBackendError::Invariant)
}

fn workflow_dispatch_control_claim(
    claim: &WorkflowDispatchSourceClaim,
) -> Result<ControlCredentialClaim, WorkflowDispatchApiBackendError> {
    let credential_id = ProviderControlCredentialId::from_uuid(claim.operation_id().as_uuid())
        .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
    let worker_id = ProviderControlCredentialWorkerId::from_uuid(claim.worker_id().as_uuid())
        .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
    ControlCredentialClaim::new(
        credential_id,
        worker_id,
        claim.fence().get(),
        1,
        claim.expires_at(),
    )
    .map_err(|_| WorkflowDispatchApiBackendError::Invariant)
}

fn classify_source_store_error(
    error: &WorkflowDispatchSourceResolutionStoreError,
) -> WorkflowDispatchApiBackendError {
    match error {
        WorkflowDispatchSourceResolutionStoreError::AuthorityRejected => {
            WorkflowDispatchApiBackendError::Forbidden
        }
        WorkflowDispatchSourceResolutionStoreError::NotFound => {
            WorkflowDispatchApiBackendError::NotFound
        }
        WorkflowDispatchSourceResolutionStoreError::Conflict
        | WorkflowDispatchSourceResolutionStoreError::ClaimRejected => {
            WorkflowDispatchApiBackendError::Conflict
        }
        WorkflowDispatchSourceResolutionStoreError::Store(_) => {
            WorkflowDispatchApiBackendError::Unavailable
        }
    }
}

const fn classify_source_credential_error(
    error: ControlCredentialProviderError,
) -> WorkflowDispatchApiBackendError {
    match error {
        ControlCredentialProviderError::RateLimited
        | ControlCredentialProviderError::Unavailable
        | ControlCredentialProviderError::Indeterminate => {
            WorkflowDispatchApiBackendError::Unavailable
        }
        ControlCredentialProviderError::Unauthorized
        | ControlCredentialProviderError::Forbidden => WorkflowDispatchApiBackendError::Forbidden,
        ControlCredentialProviderError::Unsupported
        | ControlCredentialProviderError::InvalidResponse => {
            WorkflowDispatchApiBackendError::Invariant
        }
    }
}

const fn classify_scm_error(error: automata_ci_scm::ScmError) -> WorkflowDispatchApiBackendError {
    match error.kind() {
        ScmErrorKind::NotFound => WorkflowDispatchApiBackendError::NotFound,
        ScmErrorKind::Unauthorized | ScmErrorKind::Forbidden => {
            WorkflowDispatchApiBackendError::Forbidden
        }
        ScmErrorKind::RateLimited | ScmErrorKind::Unavailable => {
            WorkflowDispatchApiBackendError::Unavailable
        }
        ScmErrorKind::TooLarge => WorkflowDispatchApiBackendError::InvalidRequest,
        ScmErrorKind::InvalidResponse | ScmErrorKind::Integrity => {
            WorkflowDispatchApiBackendError::Invariant
        }
    }
}

const fn classify_blob_error(kind: BlobStoreErrorKind) -> WorkflowDispatchApiBackendError {
    match kind {
        BlobStoreErrorKind::NotFound => WorkflowDispatchApiBackendError::NotFound,
        BlobStoreErrorKind::Unauthorized | BlobStoreErrorKind::Unavailable => {
            WorkflowDispatchApiBackendError::Unavailable
        }
        BlobStoreErrorKind::TooLarge => WorkflowDispatchApiBackendError::InvalidRequest,
        BlobStoreErrorKind::Conflict
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::InvalidResponse => WorkflowDispatchApiBackendError::Invariant,
    }
}

fn classify_dispatch_error(error: &GithubWorkflowDispatchError) -> WorkflowDispatchApiBackendError {
    match error {
        GithubWorkflowDispatchError::DurableSourceNotFound => {
            WorkflowDispatchApiBackendError::NotFound
        }
        GithubWorkflowDispatchError::CompilationRejected(_) => {
            WorkflowDispatchApiBackendError::InvalidRequest
        }
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected,
        )) => WorkflowDispatchApiBackendError::Forbidden,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::IdempotencyConflict
            | LogicalWorkflowAdmissionStoreError::WorkflowDisabled,
        )) => WorkflowDispatchApiBackendError::Conflict,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::Store(StoreError::Operation(_)),
        )) => WorkflowDispatchApiBackendError::Unavailable,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Blob(error))
            if matches!(
                error.kind(),
                BlobStoreErrorKind::Unauthorized | BlobStoreErrorKind::Unavailable
            ) =>
        {
            WorkflowDispatchApiBackendError::Unavailable
        }
        GithubWorkflowDispatchError::Request(_)
        | GithubWorkflowDispatchError::InvalidSourceEncoding
        | GithubWorkflowDispatchError::FrontendRejected(_)
        | GithubWorkflowDispatchError::InvalidSourcePlan
        | GithubWorkflowDispatchError::DurableSourceMismatch
        | GithubWorkflowDispatchError::InvalidBaseContext
        | GithubWorkflowDispatchError::Evidence(_)
        | GithubWorkflowDispatchError::AdmissionRequest(_)
        | GithubWorkflowDispatchError::Admission(_) => WorkflowDispatchApiBackendError::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_source_fence_maps_exactly_to_common_control_claim() {
        use automata_ci_core::{OperationId, WorkflowId};
        use automata_ci_provider::ProviderConnectionId;
        use automata_ci_store::{
            GithubProviderManifestRevision, GithubServerServiceAuthorityId,
            GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
            GithubServerServiceRevision, TenantScope,
        };
        use uuid::Uuid;

        let operation_id = OperationId::from_uuid(Uuid::from_u128(0x81));
        let worker_id = GithubServerServiceWorkerId::from_uuid(Uuid::from_u128(0x82))
            .expect("dispatch worker ID");
        let tenant =
            TenantScope::from_authenticated_tenant_id("dispatch-tenant").expect("dispatch tenant");
        let selector = GithubServerServiceAuthoritySelector::from_durable_parts(
            tenant.clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x83)).expect("authority ID"),
            Sha256Digest::from_bytes([0x84; 32]),
            GithubServerServiceRevision::new(1).expect("app revision"),
            GithubServerServiceRevision::new(1).expect("policy revision"),
        );
        let claim = WorkflowDispatchSourceClaim::from_durable_parts(
            tenant,
            automata_ci_store::RepositoryId::from_uuid(Uuid::from_u128(0x85)),
            WorkflowId::from_uuid(Uuid::from_u128(0x86)),
            ".github/workflows/ci.yml",
            "refs/heads/main",
            operation_id,
            ProviderConnectionId::from_uuid(Uuid::from_u128(0x87)).expect("connection ID"),
            GithubProviderManifestRevision::new(3).expect("manifest revision"),
            Sha256Digest::from_bytes([0x88; 32]),
            selector,
            worker_id,
            GithubServerServiceClaimFence::new(7).expect("claim fence"),
            UnixMillis::new(1_000),
            UnixMillis::new(301_000),
        )
        .expect("dispatch source claim");

        let mapped = workflow_dispatch_control_claim(&claim).expect("common control claim");
        assert_eq!(mapped.credential_id().as_uuid(), operation_id.as_uuid());
        assert_eq!(mapped.worker_id().as_uuid(), worker_id.as_uuid());
        assert_eq!(mapped.fence(), 7);
        assert_eq!(mapped.revision(), 1);
        assert_eq!(mapped.expires_at(), UnixMillis::new(301_000));
    }

    #[test]
    fn disabled_workflow_is_a_dispatch_conflict() {
        let error = GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::WorkflowDisabled,
        ));
        assert_eq!(
            classify_dispatch_error(&error),
            WorkflowDispatchApiBackendError::Conflict
        );
    }
}
