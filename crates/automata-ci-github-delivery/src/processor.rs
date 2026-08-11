use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::BlobStoreErrorKind;
use automata_ci_core::{
    ContextValue, JobRuntimeContext, Sha256Digest, UnixMillis, WorkflowEventProvenance,
};
use automata_ci_scm::{ArchiveFormat, RepositorySource};
use automata_ci_store::{
    AuthenticatedGithubDeliveryClaim, GITHUB_PROVIDER_API_ORIGIN, GITHUB_PROVIDER_ARCHIVE_ACCEPT,
    GITHUB_PROVIDER_ARCHIVE_FORMAT, GITHUB_PROVIDER_ARCHIVE_ORIGIN,
    GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION, GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
    GITHUB_PROVIDER_REST_ACCEPT, GITHUB_PROVIDER_REST_API_VERSION, GITHUB_PROVIDER_SOURCE_REVISION,
    GITHUB_PROVIDER_WEB_ORIGIN, GithubServerServiceAuthoritySelector,
    LogicalWorkflowAdmissionStoreError, MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS,
    ManifestPinnedGithubDeliveryEvidence, ProviderDeliveryFailureKind, ProviderDeliveryIdentity,
    ProviderDeliveryWorkflowConclusion, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    StoreError, WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_github::{
    CompilationDisposition, CompileWorkflowRequest, GithubChangedFilesV1, GithubEventMetadataV1,
    GithubWorkflowCompiler, GithubWorkflowFrontend, GithubWorkflowSourcePlan, ParseWorkflowRequest,
    RepositoryWorkflowDiscoveryLimits, SourceId, SourceOrigin, SourceProvenance,
    WorkflowFrontend as _, WorkflowNotSelectedReason, discover_repository_workflows,
};
use automata_ci_workflow_service::{
    AdmissionRepositoryCoordinates, RepositoryWorkflowSource, WorkflowAdmissionError,
    WorkflowAdmissionRequest, WorkflowAdmissionRequestError, WorkflowAdmissionService,
};
use bytes::Bytes;
use thiserror::Error;
use tokio::sync::OwnedMutexGuard;

use crate::{
    GITHUB_AUTHENTICATED_EVENT_V1_MEDIA_TYPE, GITHUB_PUSH_EVENT_MEDIA_TYPE,
    GithubDeliveryEventWorkflowRequest, GithubDeliveryPrivateRepositoryAction,
    GithubDeliverySourceCredential, GithubDeliverySourceCredentialProvider,
    GithubDeliverySourceCredentialProviderError, GithubDeliverySourceCredentialRequest,
    GithubDeliveryWorkerError, GithubDeliveryWorkerPrerequisite, GithubDeliveryWorkflowProcessor,
    GithubDeliveryWorkflowProcessorCompletion, GithubDeliveryWorkflowProcessorError,
    GithubDeliveryWorkflowRequest,
    service::{credential_matches_request, poll_provider_once, provider_required_through},
    worker::GithubDeliveryClaimSnapshot,
};

const GITHUB_PROVIDER: &str = "github";

/// Exact repository authority supplied to one changed-files provider call.
///
/// Public requests carry no credential. Private requests borrow only the
/// distinct changed-files handoff token and never reuse the revision archive
/// token.
pub enum GithubPushChangedFilesAuthority<'credential> {
    /// Query public changed-file evidence anonymously.
    PublicAnonymous,
    /// Query private changed-file evidence with exact installation
    /// `contents: read` authority.
    PrivateInstallationContentsRead(&'credential SecretString),
}

#[cfg(test)]
mod changed_files_provider_tests;

impl fmt::Debug for GithubPushChangedFilesAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicAnonymous => formatter.write_str("PublicAnonymous"),
            Self::PrivateInstallationContentsRead(_) => {
                formatter.write_str("PrivateInstallationContentsRead([redacted])")
            }
        }
    }
}

/// Exact authenticated push coordinates for provider changed-file selection.
///
/// The request carries either explicit anonymous authority or one move-only
/// private changed-files credential. Implementations bind the response to the
/// exact consumer snapshot, before/after, and pushed-commit evidence in
/// `push`. Commit summaries are identities only and never changed-file paths.
pub struct GithubPushChangedFilesRequest<'a> {
    identity: &'a ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    push: &'a automata_ci_github::VerifiedGithubPush,
    snapshot: GithubDeliveryClaimSnapshot,
    observed_at: UnixMillis,
    required_through: UnixMillis,
    authority: GithubPushChangedFilesAuthority<'a>,
}

impl GithubPushChangedFilesRequest<'_> {
    /// Returns the exact durable tenant, connection, installation, and repository identity.
    #[must_use]
    pub const fn identity(&self) -> &ProviderDeliveryIdentity {
        self.identity
    }

    /// Returns the authenticated ingress request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the strictly rehydrated authenticated push evidence.
    #[must_use]
    pub const fn push(&self) -> &automata_ci_github::VerifiedGithubPush {
        self.push
    }

    /// Returns the exact live delivery consumer snapshot revalidated before
    /// this provider future was first polled.
    #[must_use]
    pub const fn snapshot(&self) -> GithubDeliveryClaimSnapshot {
        self.snapshot
    }

    /// Returns the trusted immediate provider-operation observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the lease expiry plus the bounded provider uncertainty tail.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }

    /// Returns the exact anonymous or request-scoped private authority.
    #[must_use]
    pub const fn authority(&self) -> &GithubPushChangedFilesAuthority<'_> {
        &self.authority
    }

    /// Returns the disjoint server-service action for a private request.
    #[must_use]
    pub const fn private_action(&self) -> Option<GithubDeliveryPrivateRepositoryAction> {
        match self.authority {
            GithubPushChangedFilesAuthority::PublicAnonymous => None,
            GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(_) => {
                Some(GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles)
            }
        }
    }
}

impl fmt::Debug for GithubPushChangedFilesRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPushChangedFilesRequest")
            .field("identity", &"[redacted]")
            .field("request_digest", &self.request_digest)
            .field("push", &"[redacted]")
            .field("snapshot", &self.snapshot)
            .field("observed_at", &self.observed_at)
            .field("required_through", &self.required_through)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Sanitized failure from exact provider changed-file selection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GithubPushChangedFilesError {
    /// Provider authority or transport is temporarily unavailable.
    #[error("GitHub changed-file selection is temporarily unavailable")]
    Unavailable,
    /// The provider response could not be bound to the exact push request.
    #[error("GitHub changed-file evidence is invalid")]
    InvalidEvidence,
}

/// Least-authority provider port for one exact GitHub push diff.
///
/// Implementations must reproduce the provider's push path-filter selection,
/// return at most its documented 3,000-file window, and return
/// [`GithubChangedFilesV1::BypassPathFilters`] only with affirmative provider
/// evidence that path filters are bypassed. Returned paths must never enter
/// diagnostics.
#[async_trait]
pub trait GithubPushChangedFilesProvider: fmt::Debug + Send + Sync {
    /// Resolves provider-verified changed-file evidence for one exact push.
    ///
    /// # Errors
    ///
    /// Returns only a sanitized transient or invalid-evidence classification.
    async fn changed_files(
        &self,
        request: GithubPushChangedFilesRequest<'_>,
    ) -> Result<GithubChangedFilesV1, GithubPushChangedFilesError>;
}

/// Product-composed GitHub delivery processor backed by logical admission.
///
/// Source parsing and trigger selection happen before any admission write. A
/// provider diff is requested only after the compiler returns its typed
/// `RequiresChangedFiles` disposition. Accepted plans are then reverified and
/// materialized by the blob-first [`WorkflowAdmissionService`].
#[derive(Clone)]
pub struct GithubDeliveryWorkflowAdmissionProcessor {
    admission: WorkflowAdmissionService,
    changed_files: Option<Arc<dyn GithubPushChangedFilesProvider>>,
}

impl GithubDeliveryWorkflowAdmissionProcessor {
    /// Creates a processor that can admit workflows without path-filter diffs.
    ///
    /// If a selected workflow requires a provider diff, processing returns the
    /// typed `ProviderChangedFiles` prerequisite without performing admission.
    #[must_use]
    pub const fn new(admission: WorkflowAdmissionService) -> Self {
        Self {
            admission,
            changed_files: None,
        }
    }

    /// Installs the provider authority used lazily for path-filter selection.
    #[must_use]
    pub fn with_changed_files_provider(
        mut self,
        provider: Arc<dyn GithubPushChangedFilesProvider>,
    ) -> Self {
        self.changed_files = Some(provider);
        self
    }

    async fn process(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        if !valid_request(request) {
            return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
        }
        let Ok(source) = std::str::from_utf8(request.workflow_source()) else {
            return Ok(failed("github.workflow.invalid_source_encoding"));
        };
        let parsed = GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
            source_provenance(request),
            source,
        ));
        if !parsed.is_accepted() {
            return Ok(failed("github.workflow.frontend_rejected"));
        }
        let Some(source_plan) = parsed.plan() else {
            return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
        };
        let event = event_provenance(request);
        let initial = compile(
            source_plan,
            event.clone(),
            GithubEventMetadataV1::push(request.push().deleted()),
        );
        match initial.disposition() {
            CompilationDisposition::RequiresChangedFiles => {
                let changed_files = self.resolve_changed_files(request).await?;
                let Some(changed_files) = changed_files else {
                    return Ok(failed("github.workflow.changed_files_invalid"));
                };
                let selected = compile(
                    source_plan,
                    event,
                    GithubEventMetadataV1::push_with_changed_files(
                        request.push().deleted(),
                        changed_files,
                    ),
                );
                Box::pin(self.finish_compilation(request, selected)).await
            }
            _ => Box::pin(self.finish_compilation(request, initial)).await,
        }
    }

    async fn process_authenticated_event_v1(
        &self,
        request: &GithubDeliveryEventWorkflowRequest<'_>,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        if !valid_authenticated_event_request(request) {
            return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
        }
        let Ok(source) = std::str::from_utf8(request.workflow_source()) else {
            return Ok(failed("github.workflow.invalid_source_encoding"));
        };
        let parsed = GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
            authenticated_event_source_provenance(request),
            source,
        ));
        if !parsed.is_accepted() {
            return Ok(failed("github.workflow.frontend_rejected"));
        }
        let Some(source_plan) = parsed.plan() else {
            return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
        };
        let metadata = match request.event() {
            automata_ci_github::VerifiedGithubWebhook::Push(push) => {
                GithubEventMetadataV1::push(push.deleted())
            }
            automata_ci_github::VerifiedGithubWebhook::PullRequest(pull_request) => {
                GithubEventMetadataV1::pull_request(
                    pull_request.action().as_str(),
                    pull_request.base_ref(),
                )
            }
            automata_ci_github::VerifiedGithubWebhook::MergeGroup(merge_group) => {
                GithubEventMetadataV1::merge_group(
                    merge_group.action().as_str(),
                    merge_group.base_ref().full(),
                )
            }
            automata_ci_github::VerifiedGithubWebhook::RepositoryDispatch(dispatch) => {
                GithubEventMetadataV1::repository_dispatch(dispatch.event_type())
            }
            _ => return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation),
        };
        let report = compile(
            source_plan,
            authenticated_event_provenance(request),
            metadata,
        );
        if matches!(
            report.disposition(),
            CompilationDisposition::RequiresChangedFiles
        ) {
            if matches!(
                request.event(),
                automata_ci_github::VerifiedGithubWebhook::RepositoryDispatch(_)
            ) {
                return Ok(failed(
                    "github.workflow.repository_dispatch_changed_files_unsupported",
                ));
            }
            return Err(GithubDeliveryWorkflowProcessorError::Prerequisite(
                GithubDeliveryWorkerPrerequisite::ProviderChangedFiles,
            ));
        }
        Box::pin(self.finish_authenticated_event_compilation(request, report)).await
    }

    async fn resolve_changed_files(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
    ) -> Result<Option<GithubChangedFilesV1>, GithubDeliveryWorkflowProcessorError> {
        let path_filter_commit_limit = request
            .manifest_pinned_evidence()
            .manifest()
            .limits()
            .path_filter_max_commits();
        if u64::try_from(request.push().commit_count()).unwrap_or(u64::MAX)
            > path_filter_commit_limit
        {
            return Ok(Some(GithubChangedFilesV1::bypass_path_filters()));
        }
        let provider = self.changed_files.as_ref().ok_or(
            GithubDeliveryWorkflowProcessorError::Prerequisite(
                GithubDeliveryWorkerPrerequisite::ProviderChangedFiles,
            ),
        )?;
        match request.identity().repository_visibility() {
            ProviderRepositoryVisibility::Public => {
                self.resolve_public_changed_files(request, provider.as_ref())
                    .await
            }
            ProviderRepositoryVisibility::Private => {
                self.resolve_private_changed_files(request, provider.as_ref())
                    .await
            }
        }
    }

    async fn resolve_public_changed_files(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
        provider: &dyn GithubPushChangedFilesProvider,
    ) -> Result<Option<GithubChangedFilesV1>, GithubDeliveryWorkflowProcessorError> {
        if request
            .manifest_pinned_evidence()
            .private_source_authority()
            .is_some()
        {
            return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
        }
        let operation = request.lease().lock_operation().await;
        let observed_at = request.clock().now();
        let snapshot = request
            .lease()
            .require_live_at(observed_at)
            .map_err(processor_claim_error)?;
        if snapshot != request.claim_snapshot() {
            return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
        }
        let required_through = provider_required_through(snapshot, observed_at)
            .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let provider_call = tokio::time::timeout(
            provider_tail(),
            provider.changed_files(GithubPushChangedFilesRequest {
                identity: request.identity(),
                request_digest: request.request_digest(),
                push: request.push(),
                snapshot,
                observed_at,
                required_through,
                authority: GithubPushChangedFilesAuthority::PublicAnonymous,
            }),
        );
        tokio::pin!(provider_call);
        let ready = poll_provider_once(request.lease(), provider_call.as_mut())
            .await
            .map_err(processor_claim_error)?;
        drop(operation);
        let result = match ready {
            Some(result) => result,
            None => provider_call.await,
        };
        let _operation = request.lease().lock_operation().await;
        let latest = request
            .lease()
            .require_live_at(request.clock().now())
            .map_err(processor_claim_error)?;
        if latest != snapshot {
            return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
        }
        let result = result.map_err(|_| GithubDeliveryWorkflowProcessorError::Unavailable)?;
        changed_files_result(
            result,
            request
                .manifest_pinned_evidence()
                .manifest()
                .limits()
                .path_filter_max_changed_files(),
        )
    }

    async fn resolve_private_changed_files(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
        provider: &dyn GithubPushChangedFilesProvider,
    ) -> Result<Option<GithubChangedFilesV1>, GithubDeliveryWorkflowProcessorError> {
        let (authority_selector, credentials) = private_changed_files_context(request)?;
        let observed_at = request.clock().now();
        let requested_snapshot = request
            .lease()
            .require_live_at(observed_at)
            .map_err(processor_claim_error)?;
        if requested_snapshot != request.claim_snapshot() {
            return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
        }
        let credential_request = private_changed_files_credential_request(
            request.identity(),
            request.push().repository().owner_id().get(),
            authority_selector,
            requested_snapshot,
            observed_at,
        )?;
        let (credential, operation, provider_observed_at) =
            acquire_private_changed_files_credential(
                request,
                credentials,
                credential_request,
                requested_snapshot,
            )
            .await?;
        let result = {
            let provider_call = tokio::time::timeout(
                provider_tail(),
                provider.changed_files(GithubPushChangedFilesRequest {
                    identity: request.identity(),
                    request_digest: request.request_digest(),
                    push: request.push(),
                    snapshot: requested_snapshot,
                    observed_at: provider_observed_at,
                    required_through: credential_request.required_through(),
                    authority: GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(
                        credential.token(),
                    ),
                }),
            );
            tokio::pin!(provider_call);
            let ready = poll_provider_once(request.lease(), provider_call.as_mut()).await;
            drop(operation);
            match ready {
                Ok(Some(result)) => Ok(result),
                Ok(None) => Ok(provider_call.await),
                Err(error) => Err(error),
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                credential.release().await;
                return Err(processor_claim_error(error));
            }
        };
        let operation = request.lease().lock_operation().await;
        let latest = request
            .lease()
            .require_live_at(request.clock().now())
            .map_err(processor_claim_error);
        let latest = match latest {
            Ok(latest) => latest,
            Err(error) => {
                drop(operation);
                credential.release().await;
                return Err(error);
            }
        };
        if latest != requested_snapshot {
            drop(operation);
            credential.release().await;
            return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
        }
        let outcome = match result {
            Ok(result) => changed_files_result(
                result,
                request
                    .manifest_pinned_evidence()
                    .manifest()
                    .limits()
                    .path_filter_max_changed_files(),
            ),
            Err(_) => Err(GithubDeliveryWorkflowProcessorError::Unavailable),
        };
        drop(operation);
        credential.release().await;
        outcome
    }

    async fn finish_compilation(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
        report: automata_ci_workflow_github::CompilationReport,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        match report.disposition() {
            CompilationDisposition::Accepted => {
                let inputs = report
                    .workflow_dispatch_inputs()
                    .cloned()
                    .unwrap_or_else(ContextValue::empty_object);
                let Some(plan) = report.into_parts().0 else {
                    return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
                };
                let base_context = JobRuntimeContext::new_base(
                    inputs,
                    ContextValue::empty_object(),
                    BTreeMap::new(),
                )
                .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
                Box::pin(self.admit(request, plan, base_context)).await
            }
            CompilationDisposition::NotSelected(reason) => Ok(skipped(reason)),
            CompilationDisposition::Rejected => Ok(failed("github.workflow.compilation_rejected")),
            CompilationDisposition::RequiresChangedFiles => {
                Err(GithubDeliveryWorkflowProcessorError::InvariantViolation)
            }
            _ => Ok(failed(
                "github.workflow.unsupported_compilation_disposition",
            )),
        }
    }

    async fn admit(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
        plan: automata_ci_core::WorkflowPlan,
        base_context: JobRuntimeContext,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        let coordinates = AdmissionRepositoryCoordinates::new(
            GITHUB_PROVIDER,
            request.identity().repository_id().get().to_string(),
            request.push().repository().owner(),
            request.push().repository().name(),
        )
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let idempotency = WorkflowAdmissionIdempotency::provider_delivery(
            request.identity().delivery_id().to_owned(),
        )
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let workflow_name = plan.name().map_or_else(
            || request.workflow_path().to_owned(),
            |name| name.value().clone(),
        );
        let admission = WorkflowAdmissionRequest::builder(
            request.identity().tenant().clone(),
            coordinates,
            request.workflow_path(),
            Bytes::copy_from_slice(request.workflow_source()),
            request.push().raw_body().clone(),
            plan,
            base_context,
            idempotency,
        )
        .commit_sha(request.repository_source().revision().as_str())
        .git_ref(request.push().git_ref().full())
        .workflow_name(workflow_name)
        .run_attempt(1)
        .repository_workflow_sources(repository_workflow_sources(
            request.repository_source(),
            request.manifest_pinned_evidence(),
        )?)
        .build();
        let admission = match admission {
            Ok(admission) => admission,
            Err(
                WorkflowAdmissionRequestError::InvalidPlan
                | WorkflowAdmissionRequestError::ProvenanceMismatch
                | WorkflowAdmissionRequestError::DeliveryMismatch,
            ) => return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation),
            Err(_) => return Ok(failed("github.workflow.admission_request_rejected")),
        };
        let operation = request.lease().lock_operation().await;
        let observed_at = request.clock().now();
        let current_snapshot = request
            .lease()
            .require_live_at(observed_at)
            .map_err(processor_claim_error)?;
        if !request
            .claim_snapshot()
            .has_same_live_lineage(current_snapshot)
            || current_snapshot.claim().delivery_id() != request.delivery_id()
        {
            return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
        }
        let current_claim = AuthenticatedGithubDeliveryClaim::new(
            current_snapshot.claim(),
            current_snapshot.attempt(),
            current_snapshot.claimed_at(),
            current_snapshot.expires_at(),
        )
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let admission_result = self
            .admission
            .admit_authenticated_github_delivery(admission, current_claim)
            .await;
        drop(operation);
        match admission_result {
            Ok(result) => {
                let run_id = result.receipt().run_id();
                if run_id.as_uuid().is_nil() {
                    return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
                }
                Ok(ProviderDeliveryWorkflowConclusion::Admitted { run_id })
            }
            Err(WorkflowAdmissionError::Store(
                LogicalWorkflowAdmissionStoreError::RunNumberExhausted,
            )) => Ok(failed("github.workflow.run_number_exhausted")),
            Err(error) => Err(admission_error(&error)),
        }
    }

    async fn finish_authenticated_event_compilation(
        &self,
        request: &GithubDeliveryEventWorkflowRequest<'_>,
        report: automata_ci_workflow_github::CompilationReport,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        match report.disposition() {
            CompilationDisposition::Accepted => {
                let inputs = report
                    .workflow_dispatch_inputs()
                    .cloned()
                    .unwrap_or_else(ContextValue::empty_object);
                let Some(plan) = report.into_parts().0 else {
                    return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
                };
                let base_context = JobRuntimeContext::new_base(
                    inputs,
                    ContextValue::empty_object(),
                    BTreeMap::new(),
                )
                .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
                Box::pin(self.admit_authenticated_event(request, plan, base_context)).await
            }
            CompilationDisposition::NotSelected(reason) => Ok(skipped(reason)),
            CompilationDisposition::Rejected => Ok(failed("github.workflow.compilation_rejected")),
            CompilationDisposition::RequiresChangedFiles => {
                if matches!(
                    request.event(),
                    automata_ci_github::VerifiedGithubWebhook::RepositoryDispatch(_)
                ) {
                    return Ok(failed(
                        "github.workflow.repository_dispatch_changed_files_unsupported",
                    ));
                }
                Err(GithubDeliveryWorkflowProcessorError::Prerequisite(
                    GithubDeliveryWorkerPrerequisite::ProviderChangedFiles,
                ))
            }
            _ => Ok(failed(
                "github.workflow.unsupported_compilation_disposition",
            )),
        }
    }

    async fn admit_authenticated_event(
        &self,
        request: &GithubDeliveryEventWorkflowRequest<'_>,
        plan: automata_ci_core::WorkflowPlan,
        base_context: JobRuntimeContext,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        let repository = request.event().repository();
        let event_coordinates = request
            .manifest_pinned_evidence()
            .authenticated_event_v1()
            .ok_or(GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let coordinates = AdmissionRepositoryCoordinates::new(
            GITHUB_PROVIDER,
            request.identity().repository_id().get().to_string(),
            repository.owner(),
            repository.name(),
        )
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let idempotency = WorkflowAdmissionIdempotency::provider_delivery(
            request.identity().delivery_id().to_owned(),
        )
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let workflow_name = plan.name().map_or_else(
            || request.workflow_path().to_owned(),
            |name| name.value().clone(),
        );
        let admission = WorkflowAdmissionRequest::builder(
            request.identity().tenant().clone(),
            coordinates,
            request.workflow_path(),
            Bytes::copy_from_slice(request.workflow_source()),
            request.event().raw_body().clone(),
            plan,
            base_context,
            idempotency,
        )
        .commit_sha(request.repository_source().revision().as_str())
        .git_ref(event_coordinates.git_ref())
        .workflow_name(workflow_name)
        .run_attempt(1)
        .repository_workflow_sources(repository_workflow_sources(
            request.repository_source(),
            request.manifest_pinned_evidence(),
        )?)
        .build();
        let admission = match admission {
            Ok(admission) => admission,
            Err(
                WorkflowAdmissionRequestError::InvalidPlan
                | WorkflowAdmissionRequestError::ProvenanceMismatch
                | WorkflowAdmissionRequestError::DeliveryMismatch,
            ) => return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation),
            Err(_) => return Ok(failed("github.workflow.admission_request_rejected")),
        };
        let operation = request.lease().lock_operation().await;
        let observed_at = request.clock().now();
        let current_snapshot = request
            .lease()
            .require_live_at(observed_at)
            .map_err(processor_claim_error)?;
        if !request
            .claim_snapshot()
            .has_same_live_lineage(current_snapshot)
            || current_snapshot.claim().delivery_id() != request.delivery_id()
        {
            return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
        }
        let current_claim = AuthenticatedGithubDeliveryClaim::new(
            current_snapshot.claim(),
            current_snapshot.attempt(),
            current_snapshot.claimed_at(),
            current_snapshot.expires_at(),
        )
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
        let admission_result = self
            .admission
            .admit_authenticated_github_delivery(admission, current_claim)
            .await;
        drop(operation);
        match admission_result {
            Ok(result) => {
                let run_id = result.receipt().run_id();
                if run_id.as_uuid().is_nil() {
                    return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
                }
                Ok(ProviderDeliveryWorkflowConclusion::Admitted { run_id })
            }
            Err(WorkflowAdmissionError::Store(
                LogicalWorkflowAdmissionStoreError::RunNumberExhausted,
            )) => Ok(failed("github.workflow.run_number_exhausted")),
            Err(error) => Err(admission_error(&error)),
        }
    }
}

impl fmt::Debug for GithubDeliveryWorkflowAdmissionProcessor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryWorkflowAdmissionProcessor")
            .field("admission", &"[workflow admission service]")
            .field(
                "changed_files",
                &self.changed_files.as_ref().map(|_| "[provider authority]"),
            )
            .finish()
    }
}

#[async_trait]
impl GithubDeliveryWorkflowProcessor for GithubDeliveryWorkflowAdmissionProcessor {
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        let result = Box::pin(self.process(&request)).await;
        if matches!(result, Err(GithubDeliveryWorkflowProcessorError::ClaimLost)) {
            request.finish(result).await
        } else {
            request.finish_same_lineage(result).await
        }
    }

    async fn process_authenticated_event_v1_workflow(
        &self,
        request: GithubDeliveryEventWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        let result = Box::pin(self.process_authenticated_event_v1(&request)).await;
        if matches!(result, Err(GithubDeliveryWorkflowProcessorError::ClaimLost)) {
            request.finish(result).await
        } else {
            request.finish_same_lineage(result).await
        }
    }
}

fn changed_files_result(
    result: Result<GithubChangedFilesV1, GithubPushChangedFilesError>,
    maximum_changed_files: u64,
) -> Result<Option<GithubChangedFilesV1>, GithubDeliveryWorkflowProcessorError> {
    match result {
        Ok(changed_files) if valid_changed_files_limit(&changed_files, maximum_changed_files) => {
            Ok(Some(changed_files))
        }
        Ok(_) | Err(GithubPushChangedFilesError::InvalidEvidence) => Ok(None),
        Err(GithubPushChangedFilesError::Unavailable) => {
            Err(GithubDeliveryWorkflowProcessorError::Unavailable)
        }
    }
}

fn private_changed_files_credential_request<'a>(
    identity: &'a ProviderDeliveryIdentity,
    repository_owner_id: u64,
    authority_selector: &'a GithubServerServiceAuthoritySelector,
    snapshot: GithubDeliveryClaimSnapshot,
    observed_at: UnixMillis,
) -> Result<GithubDeliverySourceCredentialRequest<'a>, GithubDeliveryWorkflowProcessorError> {
    let repository_owner_id = ProviderRepositoryOwnerId::new(repository_owner_id)
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
    GithubDeliverySourceCredentialRequest::from_live_snapshot(
        identity,
        repository_owner_id,
        authority_selector,
        snapshot,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
        observed_at,
    )
    .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)
}

fn private_changed_files_context<'a>(
    request: &'a GithubDeliveryWorkflowRequest<'_>,
) -> Result<
    (
        &'a GithubServerServiceAuthoritySelector,
        &'a dyn GithubDeliverySourceCredentialProvider,
    ),
    GithubDeliveryWorkflowProcessorError,
> {
    let authority_selector = request
        .manifest_pinned_evidence()
        .private_source_authority()
        .ok_or(GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
    let credentials =
        request
            .private_credentials()
            .ok_or(GithubDeliveryWorkflowProcessorError::Prerequisite(
                GithubDeliveryWorkerPrerequisite::ProviderChangedFiles,
            ))?;
    Ok((authority_selector, credentials))
}

async fn acquire_private_changed_files_credential(
    request: &GithubDeliveryWorkflowRequest<'_>,
    credentials: &dyn GithubDeliverySourceCredentialProvider,
    credential_request: GithubDeliverySourceCredentialRequest<'_>,
    requested_snapshot: GithubDeliveryClaimSnapshot,
) -> Result<
    (
        GithubDeliverySourceCredential,
        OwnedMutexGuard<()>,
        UnixMillis,
    ),
    GithubDeliveryWorkflowProcessorError,
> {
    let operation = request.lease().lock_operation().await;
    let current = request
        .lease()
        .require_live_at(request.clock().now())
        .map_err(processor_claim_error)?;
    if current != requested_snapshot {
        return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
    }
    let credential = credentials.acquire(credential_request);
    tokio::pin!(credential);
    let ready = poll_provider_once(request.lease(), credential.as_mut())
        .await
        .map_err(processor_claim_error)?;
    drop(operation);
    let credential = match ready {
        Some(credential) => credential,
        None => credential.await,
    };
    let operation = request.lease().lock_operation().await;
    let provider_observed_at = request.clock().now();
    let latest = match request.lease().require_live_at(provider_observed_at) {
        Ok(latest) => latest,
        Err(error) => {
            drop(operation);
            if let Ok(credential) = credential {
                credential.release().await;
            }
            return Err(processor_claim_error(error));
        }
    };
    if latest != requested_snapshot {
        drop(operation);
        if let Ok(credential) = credential {
            credential.release().await;
        }
        return Err(GithubDeliveryWorkflowProcessorError::ClaimLost);
    }
    let credential = credential.map_err(private_credential_error)?;
    if !credential_matches_request(&credential, credential_request)
        || credential.acquired_at() > provider_observed_at
    {
        drop(operation);
        credential.release().await;
        return Err(GithubDeliveryWorkflowProcessorError::InvariantViolation);
    }
    Ok((credential, operation, provider_observed_at))
}

fn valid_changed_files_limit(changed_files: &GithubChangedFilesV1, maximum: u64) -> bool {
    match changed_files {
        GithubChangedFilesV1::Complete(files) => {
            u64::try_from(files.len()).is_ok_and(|count| count <= maximum)
        }
        GithubChangedFilesV1::BypassPathFilters => true,
        _ => false,
    }
}

fn private_credential_error(
    error: GithubDeliverySourceCredentialProviderError,
) -> GithubDeliveryWorkflowProcessorError {
    match error {
        GithubDeliverySourceCredentialProviderError::Unavailable => {
            GithubDeliveryWorkflowProcessorError::Unavailable
        }
        GithubDeliverySourceCredentialProviderError::Rejected
        | GithubDeliverySourceCredentialProviderError::InvariantViolation => {
            GithubDeliveryWorkflowProcessorError::InvariantViolation
        }
    }
}

fn processor_claim_error(error: GithubDeliveryWorkerError) -> GithubDeliveryWorkflowProcessorError {
    match error {
        GithubDeliveryWorkerError::ClaimRejected => GithubDeliveryWorkflowProcessorError::ClaimLost,
        GithubDeliveryWorkerError::InvalidTrustedTime
        | GithubDeliveryWorkerError::InboxUnavailable
        | GithubDeliveryWorkerError::InboxRejected
        | GithubDeliveryWorkerError::InvariantViolation
        | GithubDeliveryWorkerError::Prerequisite(_) => {
            GithubDeliveryWorkflowProcessorError::InvariantViolation
        }
    }
}

fn provider_tail() -> std::time::Duration {
    std::time::Duration::from_millis(
        u64::try_from(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
            .expect("fixed GitHub provider tail is positive"),
    )
}

fn source_provenance(request: &GithubDeliveryWorkflowRequest<'_>) -> SourceProvenance {
    SourceProvenance::new(
        SourceId::new(request.workflow_path()),
        SourceOrigin::Repository {
            repository: Arc::from(request.repository_source().repository().as_str()),
            revision: Arc::from(request.repository_source().revision().as_str()),
            path: Arc::from(request.workflow_path()),
        },
    )
}

fn event_provenance(request: &GithubDeliveryWorkflowRequest<'_>) -> WorkflowEventProvenance {
    WorkflowEventProvenance::new(GITHUB_PROVIDER, request.push().event_name())
        .with_delivery_id(request.push().delivery_id())
        .with_commit_sha(request.repository_source().revision().as_str())
        .with_git_ref(request.push().git_ref().full())
}

fn authenticated_event_source_provenance(
    request: &GithubDeliveryEventWorkflowRequest<'_>,
) -> SourceProvenance {
    SourceProvenance::new(
        SourceId::new(request.workflow_path()),
        SourceOrigin::Repository {
            repository: Arc::from(request.repository_source().repository().as_str()),
            revision: Arc::from(request.repository_source().revision().as_str()),
            path: Arc::from(request.workflow_path()),
        },
    )
}

fn authenticated_event_provenance(
    request: &GithubDeliveryEventWorkflowRequest<'_>,
) -> WorkflowEventProvenance {
    let git_ref = request
        .manifest_pinned_evidence()
        .authenticated_event_v1()
        .map(automata_ci_store::GithubAuthenticatedEventV1::git_ref);
    let provenance = WorkflowEventProvenance::new(GITHUB_PROVIDER, request.event().event_name())
        .with_delivery_id(request.event().delivery_id())
        .with_commit_sha(request.repository_source().revision().as_str());
    match git_ref {
        Some(git_ref) => provenance.with_git_ref(git_ref),
        None => provenance,
    }
}

fn compile(
    source_plan: &GithubWorkflowSourcePlan,
    event: WorkflowEventProvenance,
    metadata: GithubEventMetadataV1,
) -> automata_ci_workflow_github::CompilationReport {
    GithubWorkflowCompiler::new()
        .compile(CompileWorkflowRequest::new(source_plan, event).with_event_metadata_v1(metadata))
}

fn repository_workflow_sources(
    source: &RepositorySource,
    evidence: &ManifestPinnedGithubDeliveryEvidence,
) -> Result<Vec<RepositoryWorkflowSource>, GithubDeliveryWorkflowProcessorError> {
    let limits = evidence.manifest().limits();
    let discovery_limits = RepositoryWorkflowDiscoveryLimits::new(
        limits.archive_max_compressed_bytes(),
        limits.archive_max_decompressed_bytes(),
        usize::try_from(limits.archive_max_entries())
            .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?,
        limits.archive_max_expanded_bytes(),
        usize::try_from(limits.archive_max_entry_path_bytes())
            .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?,
        usize::try_from(limits.archive_max_workflows())
            .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?,
        limits.workflow_max_bytes(),
    )
    .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)?;
    discover_repository_workflows(source.bytes(), discovery_limits)
        .map_err(|_| GithubDeliveryWorkflowProcessorError::InvariantViolation)
        .map(|workflows| {
            workflows
                .into_iter()
                .filter_map(|workflow| {
                    let (path, source) = workflow.into_parts();
                    source
                        .ok()
                        .map(|source| RepositoryWorkflowSource::new(path, Bytes::from(source)))
                })
                .collect()
        })
}

fn valid_request(request: &GithubDeliveryWorkflowRequest<'_>) -> bool {
    let identity = request.identity();
    let push = request.push();
    let source = request.repository_source();
    let evidence = request.manifest_pinned_evidence();
    let manifest = evidence.manifest();
    let origins = manifest.origins();
    let raw_size = u64::try_from(push.raw_body().len()).unwrap_or(u64::MAX);
    let check_head_matches =
        crate::check_head_sha(push).is_ok_and(|check_head| check_head == evidence.check_head_sha());
    let visibility_authority_matches = matches!(
        (
            identity.repository_visibility(),
            evidence.private_source_authority()
        ),
        (ProviderRepositoryVisibility::Public, None)
            | (ProviderRepositoryVisibility::Private, Some(_))
    );
    let source_authentication = match identity.repository_visibility() {
        ProviderRepositoryVisibility::Public => GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
        ProviderRepositoryVisibility::Private => GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION,
    };
    let commit_count = u64::try_from(push.commit_count()).unwrap_or(u64::MAX);
    let path_filter_commit_evidence_matches = match push.complete_pushed_commit_revisions() {
        Some(revisions) => {
            commit_count <= manifest.limits().path_filter_max_commits()
                && revisions.len() == push.commit_count()
        }
        None => commit_count > manifest.limits().path_filter_max_commits(),
    };
    identity.provider() == GITHUB_PROVIDER
        && evidence.delivery_id() == request.delivery_id()
        && evidence.accepted_at() == request.accepted_at()
        && evidence.tenant() == identity.tenant()
        && manifest.matches_delivery_identity(identity)
        && visibility_authority_matches
        && identity.delivery_id() == push.delivery_id()
        && identity.installation_id().get() == push.installation_id().get()
        && identity.repository_id().get() == push.repository().id().get()
        && evidence.repository_owner_id().get() == push.repository().owner_id().get()
        && matches!(
            (
                identity.repository_visibility(),
                push.repository().visibility()
            ),
            (
                ProviderRepositoryVisibility::Public,
                automata_ci_github::GithubRepositoryVisibility::Public
            ) | (
                ProviderRepositoryVisibility::Private,
                automata_ci_github::GithubRepositoryVisibility::Private
            )
        )
        && identity.repository_identity() == push.repository().full_name()
        && request.raw_event().digest().as_bytes() == push.body_sha256().as_bytes()
        && request.raw_event().encoded_size() == raw_size
        && request.raw_event().media_type() == GITHUB_PUSH_EVENT_MEDIA_TYPE
        && raw_size <= manifest.limits().webhook_max_body_bytes()
        && check_head_matches
        && push.event_name() == manifest.event_name()
        && push.git_ref().full() == manifest.git_ref()
        && !push.deleted()
        && commit_count <= manifest.limits().push_webhook_max_commits()
        && path_filter_commit_evidence_matches
        && source.provider().as_str() == GITHUB_PROVIDER
        && source.repository().as_str() == push.repository().full_name()
        && source.revision().as_str() == push.after_commit_sha()
        && source.format() == ArchiveFormat::TarGzip
        && source.size() <= manifest.limits().archive_max_compressed_bytes()
        && manifest.selects_workflow_path(request.workflow_path())
        && u64::try_from(request.workflow_source().len()).unwrap_or(u64::MAX)
            <= manifest.limits().workflow_max_bytes()
        && origins.web_origin() == GITHUB_PROVIDER_WEB_ORIGIN
        && origins.api_origin() == GITHUB_PROVIDER_API_ORIGIN
        && origins.archive_origin() == GITHUB_PROVIDER_ARCHIVE_ORIGIN
        && manifest.rest_api_version() == GITHUB_PROVIDER_REST_API_VERSION
        && manifest.rest_accept() == GITHUB_PROVIDER_REST_ACCEPT
        && manifest.archive_accept() == GITHUB_PROVIDER_ARCHIVE_ACCEPT
        && manifest.source_authentication() == source_authentication
        && manifest.source_revision() == GITHUB_PROVIDER_SOURCE_REVISION
        && manifest.archive_format() == GITHUB_PROVIDER_ARCHIVE_FORMAT
}

fn valid_authenticated_event_request(request: &GithubDeliveryEventWorkflowRequest<'_>) -> bool {
    let identity = request.identity();
    let event = request.event();
    let repository = event.repository();
    let source = request.repository_source();
    let evidence = request.manifest_pinned_evidence();
    let manifest = evidence.manifest();
    let origins = manifest.origins();
    let raw_size = u64::try_from(event.raw_body().len()).unwrap_or(u64::MAX);
    let Some(authenticated_event) = evidence.authenticated_event_v1() else {
        return false;
    };
    let event_coordinates_match =
        authenticated_event_coordinates_match(event, evidence, authenticated_event);
    let source_revision_matches = authenticated_event_source_matches(event, evidence, source);
    let visibility_authority_matches = matches!(
        (
            identity.repository_visibility(),
            evidence.private_source_authority()
        ),
        (ProviderRepositoryVisibility::Public, None)
            | (ProviderRepositoryVisibility::Private, Some(_))
    );
    let source_authentication = match identity.repository_visibility() {
        ProviderRepositoryVisibility::Public => GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
        ProviderRepositoryVisibility::Private => GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION,
    };
    let push_policy_matches = match event {
        automata_ci_github::VerifiedGithubWebhook::Push(push) => {
            let commit_count = u64::try_from(push.commit_count()).unwrap_or(u64::MAX);
            let path_evidence = match push.complete_pushed_commit_revisions() {
                Some(revisions) => {
                    commit_count <= manifest.limits().path_filter_max_commits()
                        && revisions.len() == push.commit_count()
                }
                None => commit_count > manifest.limits().path_filter_max_commits(),
            };
            !push.deleted()
                && commit_count <= manifest.limits().push_webhook_max_commits()
                && path_evidence
        }
        automata_ci_github::VerifiedGithubWebhook::PullRequest(_)
        | automata_ci_github::VerifiedGithubWebhook::MergeGroup(_)
        | automata_ci_github::VerifiedGithubWebhook::RepositoryDispatch(_) => true,
        _ => false,
    };
    identity.provider() == GITHUB_PROVIDER
        && evidence.delivery_id() == request.delivery_id()
        && evidence.accepted_at() == request.accepted_at()
        && evidence.tenant() == identity.tenant()
        && manifest.matches_delivery_identity(identity)
        && visibility_authority_matches
        && identity.delivery_id() == event.delivery_id()
        && identity.installation_id().get() == event.installation_id().get()
        && identity.repository_id().get() == repository.id().get()
        && evidence.repository_owner_id().get() == repository.owner_id().get()
        && matches!(
            (identity.repository_visibility(), repository.visibility()),
            (
                ProviderRepositoryVisibility::Public,
                automata_ci_github::GithubRepositoryVisibility::Public
            ) | (
                ProviderRepositoryVisibility::Private,
                automata_ci_github::GithubRepositoryVisibility::Private
            )
        )
        && identity.repository_identity() == repository.full_name()
        && request.raw_event().digest().as_bytes() == event.body_sha256().as_bytes()
        && request.raw_event().encoded_size() == raw_size
        && request.raw_event().media_type() == GITHUB_AUTHENTICATED_EVENT_V1_MEDIA_TYPE
        && raw_size <= manifest.limits().webhook_max_body_bytes()
        && event_coordinates_match
        && push_policy_matches
        && source.provider().as_str() == GITHUB_PROVIDER
        && source.repository().as_str() == repository.full_name()
        && source_revision_matches
        && source.format() == ArchiveFormat::TarGzip
        && source.size() <= manifest.limits().archive_max_compressed_bytes()
        && manifest.selects_workflow_path(request.workflow_path())
        && u64::try_from(request.workflow_source().len()).unwrap_or(u64::MAX)
            <= manifest.limits().workflow_max_bytes()
        && origins.web_origin() == GITHUB_PROVIDER_WEB_ORIGIN
        && origins.api_origin() == GITHUB_PROVIDER_API_ORIGIN
        && origins.archive_origin() == GITHUB_PROVIDER_ARCHIVE_ORIGIN
        && manifest.rest_api_version() == GITHUB_PROVIDER_REST_API_VERSION
        && manifest.rest_accept() == GITHUB_PROVIDER_REST_ACCEPT
        && manifest.archive_accept() == GITHUB_PROVIDER_ARCHIVE_ACCEPT
        && manifest.source_authentication() == source_authentication
        && manifest.source_revision() == GITHUB_PROVIDER_SOURCE_REVISION
        && manifest.archive_format() == GITHUB_PROVIDER_ARCHIVE_FORMAT
}

fn authenticated_event_coordinates_match(
    event: &automata_ci_github::VerifiedGithubWebhook,
    evidence: &ManifestPinnedGithubDeliveryEvidence,
    authenticated_event: &automata_ci_store::GithubAuthenticatedEventV1,
) -> bool {
    match event {
        automata_ci_github::VerifiedGithubWebhook::RepositoryDispatch(dispatch) => {
            authenticated_event.kind()
                == automata_ci_store::GithubAuthenticatedEventKind::RepositoryDispatch
                && authenticated_event.git_ref() == dispatch.git_ref()
                && evidence.repository_dispatch_resolution().is_some()
        }
        _ => crate::authenticated_event_coordinates(event).is_ok_and(|coordinates| {
            coordinates.event == *authenticated_event
                && coordinates.head_sha == evidence.check_head_sha()
                && evidence.repository_dispatch_resolution().is_none()
        }),
    }
}

fn authenticated_event_source_matches(
    event: &automata_ci_github::VerifiedGithubWebhook,
    evidence: &ManifestPinnedGithubDeliveryEvidence,
    source: &RepositorySource,
) -> bool {
    match event {
        automata_ci_github::VerifiedGithubWebhook::RepositoryDispatch(_) => evidence
            .repository_dispatch_resolution()
            .is_some_and(|resolution| {
                resolution.source_revision() == evidence.check_head_sha()
                    && crate::check_head_sha_from_revision(source.revision().as_str())
                        .is_ok_and(|revision| revision == resolution.source_revision())
            }),
        _ => authenticated_event_source_revision(event)
            .is_some_and(|revision| revision == source.revision().as_str()),
    }
}

fn authenticated_event_source_revision(
    event: &automata_ci_github::VerifiedGithubWebhook,
) -> Option<&str> {
    match event {
        automata_ci_github::VerifiedGithubWebhook::Push(push) if !push.deleted() => {
            Some(push.after_commit_sha())
        }
        automata_ci_github::VerifiedGithubWebhook::PullRequest(pull_request) => {
            Some(pull_request.merge_revision().as_str())
        }
        automata_ci_github::VerifiedGithubWebhook::MergeGroup(merge_group) => {
            Some(merge_group.head_revision().as_str())
        }
        _ => None,
    }
}

fn skipped(reason: WorkflowNotSelectedReason) -> ProviderDeliveryWorkflowConclusion {
    let reason = match reason {
        WorkflowNotSelectedReason::EventNotConfigured => "github.workflow.event_not_configured",
        WorkflowNotSelectedReason::DeletedPush => "github.workflow.deleted_push",
        WorkflowNotSelectedReason::EventFiltersNotMatched => {
            "github.workflow.event_filters_not_matched"
        }
        WorkflowNotSelectedReason::ScheduleNotConfigured => {
            "github.workflow.schedule_not_configured"
        }
        _ => "github.workflow.not_selected",
    };
    ProviderDeliveryWorkflowConclusion::Skipped {
        reason: failure_kind(reason),
    }
}

fn failed(kind: &'static str) -> ProviderDeliveryWorkflowConclusion {
    ProviderDeliveryWorkflowConclusion::Failed {
        failure_kind: failure_kind(kind),
    }
}

fn failure_kind(value: &'static str) -> ProviderDeliveryFailureKind {
    ProviderDeliveryFailureKind::new(value)
        .expect("fixed GitHub workflow outcome kind is canonical and bounded")
}

fn admission_error(error: &WorkflowAdmissionError) -> GithubDeliveryWorkflowProcessorError {
    match error {
        WorkflowAdmissionError::Blob(error)
            if matches!(
                error.kind(),
                BlobStoreErrorKind::Unavailable | BlobStoreErrorKind::Unauthorized
            ) =>
        {
            GithubDeliveryWorkflowProcessorError::Unavailable
        }
        WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::Store(
            StoreError::Operation(_),
        )) => GithubDeliveryWorkflowProcessorError::Unavailable,
        WorkflowAdmissionError::Verification(_)
        | WorkflowAdmissionError::ReusableExpansion(_)
        | WorkflowAdmissionError::CredentialDiscovery(_)
        | WorkflowAdmissionError::Blob(_)
        | WorkflowAdmissionError::Store(_)
        | WorkflowAdmissionError::AdmissionValue(_)
        | WorkflowAdmissionError::LogicalValue(_)
        | WorkflowAdmissionError::ConcurrencyEvaluation
        | WorkflowAdmissionError::WorkflowDispatchEvidence
        | WorkflowAdmissionError::Serialization
        | WorkflowAdmissionError::Internal => {
            GithubDeliveryWorkflowProcessorError::InvariantViolation
        }
    }
}

#[cfg(test)]
mod renewal_tests {
    use std::{
        fmt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use automata_ci_auth::secret::SecretString;
    use automata_ci_blob::{BlobKey, BlobPayload, MediaType, MemoryBlobStore};
    use automata_ci_core::{Sha256Digest, UnixMillis};
    use automata_ci_github::{
        GithubRepositoryVisibility, GithubWebhookBodyDigest, StoredAuthenticatedGithubPush,
        VerifiedGithubPush, rehydrate_stored_authenticated_github_push,
    };
    use automata_ci_scm::{
        ArchiveFormat, ExactRevision, RepositoryId as ScmRepositoryId, RepositorySource,
        RepositorySourcePort, RepositorySourceRequest, ScmError, ScmProviderId,
    };
    use automata_ci_store::{
        AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
        AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim, ClaimProviderDelivery,
        ClaimedProviderDelivery, CompleteProviderDelivery, GithubCheckName, GithubCheckSubjectId,
        GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRevision,
        GithubProviderOrigins, GithubProviderWebhookVerifierFingerprint, GithubRepositoryName,
        GithubServerServiceAction, GithubServerServiceAppClientId, GithubServerServiceAppId,
        GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
        GithubServerServiceConsumerClaim, GithubServerServiceHandoffId,
        GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubSubjectEvidenceRepository,
        GithubSubjectEvidenceStoreError, GithubWorkflowRunSubjectEvidence,
        LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionRepository,
        LogicalWorkflowAdmissionStoreError, ManifestPinnedGithubDeliveryEvidence,
        ManifestPinnedGithubDeliveryReceipt, ObjectKey, ProviderConnectionId,
        ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryId,
        ProviderDeliveryIdentity, ProviderDeliveryReceipt, ProviderDeliveryRepository,
        ProviderDeliveryState, ProviderDeliveryStoreError, ProviderInstallationId,
        ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
        ProviderRepositoryVisibility, RejectProviderDelivery, RenewedProviderDeliveryClaim,
        RepositoryId as StoreRepositoryId, RetryProviderDelivery, TenantScope,
    };
    use automata_ci_workflow_github::GithubChangedFilesV1;
    use automata_ci_workflow_service::{
        GithubWorkflowPlanVerifier, ReusableWorkflowExpansionError, WorkflowAdmissionError,
        WorkflowAdmissionService,
    };
    use bytes::Bytes;
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, EntryType, Header};
    use tokio::{sync::Notify, time::Instant};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{
        GithubDeliveryWorkflowAdmissionProcessor, GithubPushChangedFilesAuthority,
        GithubPushChangedFilesError, GithubPushChangedFilesProvider, GithubPushChangedFilesRequest,
        admission_error,
    };
    use crate::{
        GITHUB_PUSH_EVENT_MEDIA_TYPE, GithubDeliveryClock, GithubDeliveryPrivateRepositoryAction,
        GithubDeliverySourceCredential, GithubDeliverySourceCredentialBinding,
        GithubDeliverySourceCredentialProvider, GithubDeliverySourceCredentialProviderError,
        GithubDeliverySourceCredentialRequest, GithubDeliveryWorker, GithubDeliveryWorkerConfig,
        GithubDeliveryWorkerOutcome, GithubServerServiceCredentialRelease,
        worker::{
            GithubDeliveryClaimLease, GithubDeliveryClaimRenewalApplyOutcome,
            GithubDeliveryClaimSnapshot, PreparedGithubDelivery,
        },
    };

    const BEFORE: &str = "fedcba9876543210fedcba9876543210fedcba98";
    const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
    const OWNER: &str = "octo-private";
    const REPOSITORY: &str = "private-repository";
    const REPOSITORY_ID: u64 = 9_001;
    const REPOSITORY_OWNER_ID: u64 = 8_001;
    const INSTALLATION_ID: u64 = 4_242;
    const DELIVERY: &str = "delivery-private-renewal-race";

    #[test]
    fn workflow_dispatch_evidence_is_a_webhook_delivery_invariant() {
        assert_eq!(
            admission_error(&WorkflowAdmissionError::WorkflowDispatchEvidence),
            crate::GithubDeliveryWorkflowProcessorError::InvariantViolation
        );
    }

    #[test]
    fn reusable_workflow_expansion_failure_is_a_webhook_delivery_invariant() {
        assert_eq!(
            admission_error(&WorkflowAdmissionError::ReusableExpansion(
                ReusableWorkflowExpansionError::RootPlanMismatch,
            )),
            crate::GithubDeliveryWorkflowProcessorError::InvariantViolation
        );
    }
    const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
    const PATH_WORKFLOW: &[u8] = b"name: Paths CI\non:\n  push:\n    paths: ['src/**']\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo paths\n";
    const SUCCESSOR_TOKEN: &str = "successor-changed-files-token";

    #[derive(Debug)]
    struct ExactRelease;

    #[async_trait]
    impl GithubServerServiceCredentialRelease for ExactRelease {
        async fn release(self: Box<Self>) {}
    }

    #[derive(Debug)]
    struct ReleaseGate {
        calls: AtomicUsize,
        entered: AtomicBool,
        entered_notify: Notify,
        unblock: CancellationToken,
    }

    impl ReleaseGate {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                entered: AtomicBool::new(false),
                entered_notify: Notify::new(),
                unblock: CancellationToken::new(),
            }
        }

        async fn wait_entered(&self) {
            wait_flag(&self.entered, &self.entered_notify).await;
        }
    }

    #[derive(Debug)]
    struct GatedRelease(Arc<ReleaseGate>);

    #[async_trait]
    impl GithubServerServiceCredentialRelease for GatedRelease {
        async fn release(self: Box<Self>) {
            self.0.calls.fetch_add(1, Ordering::SeqCst);
            self.0.entered.store(true, Ordering::SeqCst);
            self.0.entered_notify.notify_waiters();
            self.0.unblock.cancelled().await;
        }
    }

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl GithubDeliveryClock for TestClock {
        fn now(&self) -> UnixMillis {
            UnixMillis::new(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct UnusedSource(ScmProviderId);

    #[async_trait]
    impl RepositorySourcePort for UnusedSource {
        fn provider_id(&self) -> &ScmProviderId {
            &self.0
        }

        async fn fetch_repository_source(
            &self,
            _request: RepositorySourceRequest<'_>,
        ) -> Result<RepositorySource, ScmError> {
            panic!("source fetch is bypassed by the fetched-source renewal test")
        }
    }

    #[derive(Debug)]
    struct UnexpectedAdmissions;

    #[async_trait]
    impl LogicalWorkflowAdmissionRepository for UnexpectedAdmissions {
        async fn admit_logical_workflow(
            &self,
            _command: AdmitLogicalWorkflowRun,
        ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
            panic!("path non-selection must not reach ordinary admission")
        }

        async fn admit_authenticated_github_delivery(
            &self,
            _command: AdmitLogicalWorkflowRun,
            _current_claim: AuthenticatedGithubDeliveryClaim,
            _observed_at: UnixMillis,
        ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
            panic!("path non-selection must not reach signed admission")
        }
    }

    #[derive(Debug)]
    struct UnusedSubjectEvidence;

    #[async_trait]
    impl GithubSubjectEvidenceRepository for UnusedSubjectEvidence {
        async fn accept_manifest_pinned_github_delivery(
            &self,
            _request: AcceptManifestPinnedGithubDelivery,
        ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
            panic!("subject acceptance is outside the fetched-source renewal test")
        }

        async fn load_manifest_pinned_github_delivery_evidence(
            &self,
            _tenant: &TenantScope,
            _delivery_id: ProviderDeliveryId,
        ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
            panic!("push rehydration is bypassed by the fetched-source renewal test")
        }

        async fn load_github_workflow_run_subject_evidence(
            &self,
            _tenant: &TenantScope,
            _repository_id: StoreRepositoryId,
            _run_id: automata_ci_core::RunId,
        ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
            panic!("run evidence lookup is outside the fetched-source renewal test")
        }
    }

    #[derive(Debug, Default)]
    struct RecordingDeliveries {
        completions: Mutex<Vec<CompleteProviderDelivery>>,
        retries: Mutex<Vec<RetryProviderDelivery>>,
        rejections: Mutex<Vec<RejectProviderDelivery>>,
    }

    #[async_trait]
    impl ProviderDeliveryRepository for RecordingDeliveries {
        async fn accept_provider_delivery(
            &self,
            _request: AcceptProviderDelivery,
        ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
            panic!("delivery acceptance is outside the fetched-source renewal test")
        }

        async fn claim_provider_delivery(
            &self,
            _request: ClaimProviderDelivery,
        ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError> {
            panic!("delivery claiming is outside the fetched-source renewal test")
        }

        async fn complete_provider_delivery(
            &self,
            request: CompleteProviderDelivery,
        ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
            let receipt = terminal_receipt(request.claim(), ProviderDeliveryState::Completed);
            self.completions
                .lock()
                .expect("completion lock")
                .push(request);
            Ok(receipt)
        }

        async fn retry_provider_delivery(
            &self,
            request: RetryProviderDelivery,
        ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
            let receipt = terminal_receipt(request.claim(), ProviderDeliveryState::RetryPending);
            self.retries.lock().expect("retry lock").push(request);
            Ok(receipt)
        }

        async fn reject_provider_delivery(
            &self,
            request: RejectProviderDelivery,
        ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
            let receipt = terminal_receipt(request.claim(), ProviderDeliveryState::Rejected);
            self.rejections
                .lock()
                .expect("rejection lock")
                .push(request);
            Ok(receipt)
        }
    }

    fn terminal_receipt(
        claim: ProviderDeliveryClaimFence,
        state: ProviderDeliveryState,
    ) -> ProviderDeliveryReceipt {
        ProviderDeliveryReceipt::from_durable_parts(
            claim.delivery_id(),
            state,
            1,
            UnixMillis::new(50),
        )
        .expect("terminal receipt")
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StaleCredentialOutcome {
        Rejected,
        MalformedSuccess,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CredentialObservation {
        claim: ProviderDeliveryClaimFence,
        attempt: u16,
        owner_id: ProviderRepositoryOwnerId,
        action: GithubDeliveryPrivateRepositoryAction,
    }

    #[derive(Debug)]
    struct ReleaseGatedCredentials {
        calls: AtomicUsize,
        release: Arc<ReleaseGate>,
    }

    #[async_trait]
    impl GithubDeliverySourceCredentialProvider for ReleaseGatedCredentials {
        async fn acquire(
            &self,
            request: GithubDeliverySourceCredentialRequest<'_>,
        ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            credential_with_release(
                request,
                request.action(),
                "release-gated-private-token",
                Box::new(GatedRelease(Arc::clone(&self.release))),
            )
        }
    }

    struct RotatingCredentials {
        first_outcome: StaleCredentialOutcome,
        observations: Mutex<Vec<CredentialObservation>>,
        first_entered: AtomicBool,
        first_entered_notify: Notify,
        first_returned: AtomicBool,
        first_returned_notify: Notify,
        first_release: CancellationToken,
        durable_fence: Arc<AtomicU64>,
    }

    impl RotatingCredentials {
        fn new(first_outcome: StaleCredentialOutcome, durable_fence: Arc<AtomicU64>) -> Self {
            Self {
                first_outcome,
                observations: Mutex::new(Vec::new()),
                first_entered: AtomicBool::new(false),
                first_entered_notify: Notify::new(),
                first_returned: AtomicBool::new(false),
                first_returned_notify: Notify::new(),
                first_release: CancellationToken::new(),
                durable_fence,
            }
        }

        async fn wait_first_entered(&self) {
            wait_flag(&self.first_entered, &self.first_entered_notify).await;
        }

        async fn wait_first_returned(&self) {
            wait_flag(&self.first_returned, &self.first_returned_notify).await;
        }

        fn observations(&self) -> Vec<CredentialObservation> {
            self.observations
                .lock()
                .expect("credential observation lock")
                .clone()
        }
    }

    impl fmt::Debug for RotatingCredentials {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("RotatingCredentials")
                .field("first_outcome", &self.first_outcome)
                .field("observations", &"[credential requests]")
                .field("durable_fence", &self.durable_fence.load(Ordering::SeqCst))
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl GithubDeliverySourceCredentialProvider for RotatingCredentials {
        async fn acquire(
            &self,
            request: GithubDeliverySourceCredentialRequest<'_>,
        ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError>
        {
            let call = {
                let mut observations = self
                    .observations
                    .lock()
                    .expect("credential observation lock");
                let call = observations.len();
                observations.push(CredentialObservation {
                    claim: request.snapshot().claim(),
                    attempt: request.snapshot().attempt(),
                    owner_id: request.repository_owner_id(),
                    action: request.action(),
                });
                call
            };
            if call != 0 {
                return credential(request, request.action(), SUCCESSOR_TOKEN);
            }

            self.first_entered.store(true, Ordering::SeqCst);
            self.first_entered_notify.notify_waiters();
            self.first_release.cancelled().await;
            assert_eq!(
                self.durable_fence.load(Ordering::SeqCst),
                8,
                "the predecessor result must complete only after the successor fence commits"
            );
            let result = match self.first_outcome {
                StaleCredentialOutcome::Rejected => {
                    Err(GithubDeliverySourceCredentialProviderError::Rejected)
                }
                StaleCredentialOutcome::MalformedSuccess => credential(
                    request,
                    GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
                    "malformed-predecessor-token",
                ),
            };
            self.first_returned.store(true, Ordering::SeqCst);
            self.first_returned_notify.notify_waiters();
            result
        }
    }

    fn credential(
        request: GithubDeliverySourceCredentialRequest<'_>,
        action: GithubDeliveryPrivateRepositoryAction,
        token: &'static str,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        credential_with_release(request, action, token, Box::new(ExactRelease))
    }

    fn credential_with_release(
        request: GithubDeliverySourceCredentialRequest<'_>,
        action: GithubDeliveryPrivateRepositoryAction,
        token: &'static str,
        release: Box<dyn GithubServerServiceCredentialRelease>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let requested_consumer = request
            .consumer_claim()
            .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        let consumer = GithubServerServiceConsumerClaim::new(
            requested_consumer.consumer_id(),
            requested_consumer.owner(),
            requested_consumer.fence(),
            match action {
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision => {
                    GithubServerServiceAction::FetchPrivateRepositoryRevision
                }
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles => {
                    GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
                }
            },
            requested_consumer.revision(),
        );
        let binding = GithubDeliverySourceCredentialBinding::new(
            request.identity().clone(),
            request.repository_owner_id(),
            ScmRepositoryId::new(request.identity().repository_identity())
                .expect("credential repository"),
            request.authority_selector().clone(),
            GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x7500)).expect("handoff ID"),
            consumer,
            request.required_through(),
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        GithubDeliverySourceCredential::new(
            binding,
            request.observed_at(),
            SecretString::new(token).expect("credential token"),
            request.required_through(),
            release,
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)
    }

    async fn wait_flag(flag: &AtomicBool, notification: &Notify) {
        loop {
            let notified = notification.notified();
            if flag.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ChangedFilesObservation {
        snapshot: GithubDeliveryClaimSnapshot,
        action: Option<GithubDeliveryPrivateRepositoryAction>,
        successor_token: bool,
    }

    #[derive(Debug, Default)]
    struct RecordingChangedFiles {
        observations: Mutex<Vec<ChangedFilesObservation>>,
    }

    #[async_trait]
    impl GithubPushChangedFilesProvider for RecordingChangedFiles {
        async fn changed_files(
            &self,
            request: GithubPushChangedFilesRequest<'_>,
        ) -> Result<GithubChangedFilesV1, GithubPushChangedFilesError> {
            let successor_token = match request.authority() {
                GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(token) => {
                    token.expose_secret() == SUCCESSOR_TOKEN
                }
                GithubPushChangedFilesAuthority::PublicAnonymous => false,
            };
            self.observations
                .lock()
                .expect("changed-files observation lock")
                .push(ChangedFilesObservation {
                    snapshot: request.snapshot(),
                    action: request.private_action(),
                    successor_token,
                });
            Ok(GithubChangedFilesV1::complete(["docs/readme.md"]))
        }
    }

    struct RenewalFixture {
        claimed: ClaimedProviderDelivery,
        push: VerifiedGithubPush,
        evidence: ManifestPinnedGithubDeliveryEvidence,
        source: RepositorySource,
    }

    fn fixture() -> RenewalFixture {
        let body = push_body();
        let payload = BlobPayload::from_bytes(
            BlobKey::new("provider-deliveries/github/push/renewal-race.json").expect("raw key"),
            MediaType::new(GITHUB_PUSH_EVENT_MEDIA_TYPE).expect("raw media type"),
            body.clone(),
        );
        let descriptor = payload.descriptor().clone();
        let raw_event = AdmissionObject::new(
            descriptor.digest(),
            ObjectKey::new("provider-deliveries/github/push/renewal-race.json")
                .expect("raw object key"),
            descriptor.size(),
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
        )
        .expect("raw event");
        let stored = StoredAuthenticatedGithubPush::from_durable_coordinates(
            body,
            GithubWebhookBodyDigest::from_bytes(*descriptor.digest().as_bytes()),
            descriptor.size(),
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID,
            GithubRepositoryVisibility::Private,
            OWNER,
            REPOSITORY,
        );
        let push = rehydrate_stored_authenticated_github_push(stored).expect("verified push");
        let claimed = claimed(raw_event);
        let evidence = subject_evidence(&claimed, &push);
        let source = RepositorySource::from_bytes(
            ScmProviderId::new("github").expect("provider"),
            ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
            ExactRevision::new(AFTER).expect("revision"),
            ArchiveFormat::TarGzip,
            workflow_archive(),
        );
        RenewalFixture {
            claimed,
            push,
            evidence,
            source,
        }
    }

    fn subject_evidence(
        claimed: &ClaimedProviderDelivery,
        push: &VerifiedGithubPush,
    ) -> ManifestPinnedGithubDeliveryEvidence {
        let identity = claimed.identity();
        let revision = GithubServerServiceRevision::new(1).expect("service revision");
        let webhook_fingerprint = GithubProviderWebhookVerifierFingerprint::from_sha256(
            Sha256Digest::from_bytes([0x42; 32]),
        )
        .expect("webhook fingerprint");
        let runtime_policy = crate::tests::fixture_github_runtime_policy(1);
        let manifest = GithubProviderManifest::new(
            identity.tenant().clone(),
            identity.connection_id(),
            identity.installation_id(),
            identity.repository_id(),
            GithubRepositoryName::new(identity.repository_identity().to_owned())
                .expect("repository name"),
            identity.repository_visibility(),
            GithubServerServiceAppId::new(1).expect("App ID"),
            GithubServerServiceAppClientId::new("Iv1.renewal").expect("App client ID"),
            GithubServerServiceJwtIssuer::AppClientId,
            Sha256Digest::from_bytes([0x43; 32]),
            revision,
            webhook_fingerprint,
            revision,
            revision,
            automata_ci_core::JobAuthorityProfile::Standard,
            runtime_policy.runner_policy,
            runtime_policy.revision,
            runtime_policy.semantic_digest,
            GithubCheckName::new("Automata CI").expect("Check name"),
            GithubProviderOrigins::github_dot_com(),
            GithubProviderManifestLimits::github_dot_com_ci(),
            GithubProviderManifestRevision::new(1).expect("manifest revision"),
        );
        let checks_authority = GithubServerServiceAuthoritySelector::from_durable_parts(
            identity.tenant().clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x7600))
                .expect("checks selector"),
            Sha256Digest::from_bytes([0x44; 32]),
            revision,
            revision,
        );
        let private_source_authority = GithubServerServiceAuthoritySelector::from_durable_parts(
            identity.tenant().clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x7601))
                .expect("source selector"),
            Sha256Digest::from_bytes([0x45; 32]),
            revision,
            revision,
        );
        ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
            claimed.receipt().id(),
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
            manifest,
            webhook_fingerprint,
            revision,
            checks_authority,
            Some(private_source_authority),
            GithubCheckSubjectId::from_uuid(Uuid::from_u128(0x7602)).expect("Check subject ID"),
            crate::check_head_sha(push).expect("Check head"),
            claimed.receipt().accepted_at(),
        )
        .expect("manifest-pinned evidence")
    }

    fn claimed(raw_event: AdmissionObject) -> ClaimedProviderDelivery {
        let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(1)).expect("delivery ID");
        let receipt = ProviderDeliveryReceipt::from_durable_parts(
            delivery_id,
            ProviderDeliveryState::Claimed,
            1,
            UnixMillis::new(50),
        )
        .expect("claim receipt");
        let claim = ProviderDeliveryClaimFence::from_durable_parts(
            delivery_id,
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("claim owner"),
            7,
        )
        .expect("claim fence");
        let repository = ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(REPOSITORY_ID).expect("repository ID"),
            ProviderRepositoryVisibility::Private,
            format!("{OWNER}/{REPOSITORY}"),
        )
        .expect("repository coordinates");
        let identity = ProviderDeliveryIdentity::new(
            TenantScope::from_authenticated_tenant_id("tenant-private").expect("tenant"),
            "github",
            ProviderConnectionId::from_uuid(Uuid::from_u128(3)).expect("connection"),
            ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
            repository,
            DELIVERY,
        )
        .expect("identity");
        ClaimedProviderDelivery::from_durable_parts(
            receipt,
            identity,
            Sha256Digest::from_bytes([0x42; 32]),
            raw_event,
            claim,
            UnixMillis::new(100),
            UnixMillis::new(10_000),
        )
        .expect("claimed delivery")
    }

    fn push_body() -> Bytes {
        Bytes::from(format!(
            r#"{{"ref":"refs/heads/main","before":"{BEFORE}","after":"{AFTER}","created":false,"deleted":false,"forced":false,"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"commits":[]}}"#,
        ))
    }

    fn workflow_archive() -> Bytes {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        append_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
        append_entry(
            &mut builder,
            &format!("repository-root/{WORKFLOW_PATH}"),
            EntryType::Regular,
            PATH_WORKFLOW,
        );
        let encoder = builder.into_inner().expect("finish tar");
        Bytes::from(encoder.finish().expect("finish gzip"))
    }

    fn append_entry(
        builder: &mut Builder<GzEncoder<Vec<u8>>>,
        path: &str,
        entry_type: EntryType,
        bytes: &[u8],
    ) {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(if entry_type.is_dir() { 0o755 } else { 0o644 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(u64::try_from(bytes.len()).expect("entry size"));
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("append archive entry");
    }

    fn worker(
        clock: Arc<TestClock>,
        deliveries: Arc<RecordingDeliveries>,
        changed_files: Arc<RecordingChangedFiles>,
    ) -> GithubDeliveryWorker {
        let admission = WorkflowAdmissionService::with_system_ports(
            Arc::new(MemoryBlobStore::default()),
            Arc::new(UnexpectedAdmissions),
            Arc::new(GithubWorkflowPlanVerifier::new()),
        );
        let processor = GithubDeliveryWorkflowAdmissionProcessor::new(admission)
            .with_changed_files_provider(changed_files);
        GithubDeliveryWorker::new(
            Arc::new(MemoryBlobStore::default()),
            Arc::new(UnusedSource(
                ScmProviderId::new("github").expect("source provider"),
            )),
            Arc::new(processor),
            deliveries,
            Arc::new(UnusedSubjectEvidence),
            clock,
            GithubDeliveryWorkerConfig::default(),
        )
        .expect("delivery worker")
    }

    #[tokio::test]
    async fn stale_credential_rejection_is_reacquired_after_committed_fence_rotation() {
        assert_stale_credential_is_reacquired(StaleCredentialOutcome::Rejected).await;
    }

    #[tokio::test]
    async fn stale_malformed_credential_is_reacquired_after_committed_fence_rotation() {
        assert_stale_credential_is_reacquired(StaleCredentialOutcome::MalformedSuccess).await;
    }

    #[tokio::test]
    async fn completed_provider_result_is_not_replayed_when_renewal_waits_on_release() {
        let fixture = fixture();
        let predecessor = fixture.claimed.claim();
        let successor = ProviderDeliveryClaimFence::from_durable_parts(
            predecessor.delivery_id(),
            predecessor.owner(),
            8,
        )
        .expect("successor claim");
        let clock = Arc::new(TestClock(AtomicI64::new(500)));
        let deliveries = Arc::new(RecordingDeliveries::default());
        let changed_files = Arc::new(RecordingChangedFiles::default());
        let worker = worker(clock.clone(), deliveries.clone(), changed_files.clone());
        let release = Arc::new(ReleaseGate::new());
        let credentials = Arc::new(ReleaseGatedCredentials {
            calls: AtomicUsize::new(0),
            release: Arc::clone(&release),
        });
        let predecessor_deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("predecessor deadline");
        let successor_deadline = predecessor_deadline
            .checked_add(Duration::from_secs(10))
            .expect("successor deadline");
        let lease = GithubDeliveryClaimLease::new(fixture.claimed.clone(), predecessor_deadline);
        let prepared =
            PreparedGithubDelivery::from_parts(fixture.push.clone(), fixture.evidence.clone());

        let processing = worker.process_fetched_source_leased(
            &lease,
            &prepared,
            &fixture.source,
            Some(credentials.as_ref()),
        );
        let rotation = async {
            release.wait_entered().await;
            let operation = tokio::time::timeout(Duration::from_secs(2), lease.lock_operation())
                .await
                .expect("credential release must not retain lease-operation ownership");
            clock.set(600);
            let renewal = RenewedProviderDeliveryClaim::from_durable_parts(
                successor,
                1,
                UnixMillis::new(100),
                UnixMillis::new(600),
                UnixMillis::new(20_000),
            )
            .expect("successor renewal");
            assert_eq!(
                lease
                    .apply_renewal(renewal, successor_deadline)
                    .expect("apply successor renewal"),
                GithubDeliveryClaimRenewalApplyOutcome::Applied
            );
            drop(operation);
            release.unblock.cancel();
        };
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(processing, rotation)
        })
        .await
        .expect("release and renewal race must not hang");

        assert!(matches!(
            outcome.expect("successor-safe processing"),
            GithubDeliveryWorkerOutcome::Completed(_)
        ));
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 1);
        assert_eq!(release.calls.load(Ordering::SeqCst), 1);
        let observations = changed_files
            .observations
            .lock()
            .expect("changed-files observations");
        assert_eq!(observations.len(), 1, "the completed GET must not replay");
        assert_eq!(observations[0].snapshot.claim(), predecessor);
        drop(observations);
        assert_terminal_transition(&deliveries, successor);
    }

    async fn assert_stale_credential_is_reacquired(first_outcome: StaleCredentialOutcome) {
        let fixture = fixture();
        let predecessor = fixture.claimed.claim();
        let successor = ProviderDeliveryClaimFence::from_durable_parts(
            predecessor.delivery_id(),
            predecessor.owner(),
            8,
        )
        .expect("successor claim");
        let clock = Arc::new(TestClock(AtomicI64::new(500)));
        let deliveries = Arc::new(RecordingDeliveries::default());
        let changed_files = Arc::new(RecordingChangedFiles::default());
        let worker = worker(clock.clone(), deliveries.clone(), changed_files.clone());
        let durable_fence = Arc::new(AtomicU64::new(7));
        let credentials = Arc::new(RotatingCredentials::new(
            first_outcome,
            durable_fence.clone(),
        ));
        let predecessor_deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("predecessor deadline");
        let successor_deadline = predecessor_deadline
            .checked_add(Duration::from_secs(10))
            .expect("successor deadline");
        let lease = GithubDeliveryClaimLease::new(fixture.claimed.clone(), predecessor_deadline);

        let prepared =
            PreparedGithubDelivery::from_parts(fixture.push.clone(), fixture.evidence.clone());

        let processing = worker.process_fetched_source_leased(
            &lease,
            &prepared,
            &fixture.source,
            Some(credentials.as_ref()),
        );
        let rotation = async {
            credentials.wait_first_entered().await;
            let operation = lease.lock_operation().await;
            durable_fence.store(8, Ordering::SeqCst);
            credentials.first_release.cancel();
            credentials.wait_first_returned().await;
            assert_eq!(
                lease.latest().expect("predecessor snapshot").claim(),
                predecessor,
                "the stale result must return inside the durable-commit/apply gap"
            );
            clock.set(600);
            let renewal = RenewedProviderDeliveryClaim::from_durable_parts(
                successor,
                1,
                UnixMillis::new(100),
                UnixMillis::new(600),
                UnixMillis::new(20_000),
            )
            .expect("successor renewal");
            assert_eq!(
                lease
                    .apply_renewal(renewal, successor_deadline)
                    .expect("apply successor renewal"),
                GithubDeliveryClaimRenewalApplyOutcome::Applied
            );
            drop(operation);
        };
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(processing, rotation)
        })
        .await
        .expect("credential rotation race must not hang");
        assert!(matches!(
            outcome.expect("processing after successor reacquisition"),
            GithubDeliveryWorkerOutcome::Completed(_)
        ));

        assert_credential_requests(&credentials.observations(), predecessor, successor);
        let provider_observations = changed_files
            .observations
            .lock()
            .expect("changed-files observation lock");
        assert_eq!(
            provider_observations.as_slice(),
            [ChangedFilesObservation {
                snapshot: lease.latest().expect("successor snapshot"),
                action: Some(
                    GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles
                ),
                successor_token: true,
            }],
            "only exact successor authority may reach the provider"
        );
        drop(provider_observations);
        assert_terminal_transition(&deliveries, successor);
    }

    fn assert_credential_requests(
        observations: &[CredentialObservation],
        predecessor: ProviderDeliveryClaimFence,
        successor: ProviderDeliveryClaimFence,
    ) {
        let expected = |claim| CredentialObservation {
            claim,
            attempt: 1,
            owner_id: ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
            action: GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
        };
        assert_eq!(
            observations,
            [expected(predecessor), expected(successor)],
            "stale predecessor authority must be discarded and reacquired exactly once"
        );
    }

    fn assert_terminal_transition(
        deliveries: &RecordingDeliveries,
        successor: ProviderDeliveryClaimFence,
    ) {
        let completions = deliveries.completions.lock().expect("completion lock");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].claim(), successor);
        assert_eq!(completions[0].outcomes().len(), 1);
        assert!(matches!(
            completions[0].outcomes()[0].conclusion(),
            automata_ci_store::ProviderDeliveryWorkflowConclusion::Skipped { .. }
        ));
        assert!(deliveries.retries.lock().expect("retry lock").is_empty());
        assert!(
            deliveries
                .rejections
                .lock()
                .expect("rejection lock")
                .is_empty()
        );
    }
}
