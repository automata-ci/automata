use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubDeliveryWorkerError,
    GithubDeliveryWorkerPrerequisite, GithubDeliveryWorkflowProcessor,
    GithubDeliveryWorkflowProcessorCompletion, GithubDeliveryWorkflowProcessorError,
    GithubDeliveryWorkflowRequest,
};
use async_trait::async_trait;
use automata_ci_blob::BlobStoreErrorKind;
use automata_ci_core::{ContextValue, JobRuntimeContext, WorkflowEventProvenance};
use automata_ci_scm::{ArchiveFormat, RepositorySource};
use automata_ci_store::{
    AuthenticatedGithubDeliveryClaim, GITHUB_PROVIDER_API_ORIGIN, GITHUB_PROVIDER_ARCHIVE_ACCEPT,
    GITHUB_PROVIDER_ARCHIVE_FORMAT, GITHUB_PROVIDER_ARCHIVE_ORIGIN,
    GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION, GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
    GITHUB_PROVIDER_REST_ACCEPT, GITHUB_PROVIDER_REST_API_VERSION, GITHUB_PROVIDER_SOURCE_REVISION,
    GITHUB_PROVIDER_WEB_ORIGIN, LogicalWorkflowAdmissionStoreError,
    ManifestPinnedGithubDeliveryEvidence, ProviderDeliveryFailureKind,
    ProviderDeliveryWorkflowConclusion, ProviderRepositoryVisibility, StoreError,
    WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_github::{
    CompilationDisposition, CompileWorkflowRequest, GithubEventMetadataV1, GithubWorkflowCompiler,
    GithubWorkflowFrontend, GithubWorkflowSourcePlan, ParseWorkflowRequest,
    RepositoryWorkflowDiscoveryLimits, SourceId, SourceOrigin, SourceProvenance,
    WorkflowFrontend as _, WorkflowNotSelectedReason, discover_repository_workflows,
};
use automata_ci_workflow_service::{
    AdmissionRepositoryCoordinates, RepositoryWorkflowSource, WorkflowAdmissionError,
    WorkflowAdmissionRequest, WorkflowAdmissionRequestError, WorkflowAdmissionService,
};
use bytes::Bytes;

const GITHUB_PROVIDER: &str = "github";

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

/// Product-composed GitHub delivery processor backed by logical admission.
///
/// Source parsing and trigger selection happen before any admission write. A
/// provider diff is requested only after the compiler returns its typed
/// `RequiresChangedFiles` disposition. Accepted plans are then reverified and
/// materialized by the blob-first [`WorkflowAdmissionService`].
#[derive(Clone)]
pub struct GithubDeliveryWorkflowAdmissionProcessor {
    admission: WorkflowAdmissionService,
}

impl GithubDeliveryWorkflowAdmissionProcessor {
    /// Creates a processor that can admit workflows without path-filter diffs.
    ///
    /// If a selected workflow requires a provider diff, processing returns the
    /// typed `ProviderChangedFiles` prerequisite without performing admission.
    #[must_use]
    pub const fn new(admission: WorkflowAdmissionService) -> Self {
        Self { admission }
    }

    async fn process_authenticated_event(
        &self,
        request: &GithubDeliveryWorkflowRequest<'_>,
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

    async fn finish_authenticated_event_compilation(
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
        request: &GithubDeliveryWorkflowRequest<'_>,
        plan: automata_ci_core::WorkflowPlan,
        base_context: JobRuntimeContext,
    ) -> Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError> {
        let repository = request.event().repository();
        let event_coordinates = request.manifest_pinned_evidence().authenticated_event();
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
            .finish()
    }
}

#[async_trait]
impl GithubDeliveryWorkflowProcessor for GithubDeliveryWorkflowAdmissionProcessor {
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        let result = Box::pin(self.process_authenticated_event(&request)).await;
        if matches!(result, Err(GithubDeliveryWorkflowProcessorError::ClaimLost)) {
            request.finish(result).await
        } else {
            request.finish_same_lineage(result).await
        }
    }
}

fn authenticated_event_source_provenance(
    request: &GithubDeliveryWorkflowRequest<'_>,
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
    request: &GithubDeliveryWorkflowRequest<'_>,
) -> WorkflowEventProvenance {
    let git_ref = request
        .manifest_pinned_evidence()
        .authenticated_event()
        .git_ref();
    let provenance = WorkflowEventProvenance::new(GITHUB_PROVIDER, request.event().event_name())
        .with_delivery_id(request.event().delivery_id())
        .with_commit_sha(request.repository_source().revision().as_str());
    provenance.with_git_ref(git_ref)
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

fn valid_authenticated_event_request(request: &GithubDeliveryWorkflowRequest<'_>) -> bool {
    let identity = request.identity();
    let event = request.event();
    let repository = event.repository();
    let source = request.repository_source();
    let evidence = request.manifest_pinned_evidence();
    let manifest = evidence.manifest();
    let origins = manifest.origins();
    let raw_size = u64::try_from(event.raw_body().len()).unwrap_or(u64::MAX);
    let authenticated_event = evidence.authenticated_event();
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
        && request.raw_event().media_type() == GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
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
    authenticated_event: &automata_ci_store::GithubAuthenticatedEvent,
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
mod tests {
    use automata_ci_workflow_service::{ReusableWorkflowExpansionError, WorkflowAdmissionError};

    use super::admission_error;

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
}
