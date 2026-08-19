//! Provider-neutral application of normalized triggers to Actions workflows.

use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_core::{JobRuntimeContext, TrustSnapshot, WorkflowEventProvenance};
use automata_ci_provider::{
    ClaimedProviderProcessing, NormalizedTrigger, ProviderConnectionManifest, ProviderGitRef,
    ProviderLifecycleState, ProviderProcessingClaimSource, ProviderProcessingInput,
    ProviderWorkflowSource, VerifiedProviderTriggerDelivery,
};
use automata_ci_scm::{ArchiveFormat, RepositorySourceArchive};
use automata_ci_store::{
    LogicalWorkflowAdmissionStoreError, StoreError, TenantScope, WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_actions::{
    ActionsProviderEventDocument, CompilationDisposition, CompileWorkflowRequest,
    GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest, ProviderEventMetadata,
    RepositoryWorkflowDiscoveryLimits, SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend,
    WorkflowNotSelectedReason, discover_provider_workflows,
};
use bytes::Bytes;
use thiserror::Error;

use crate::{
    AdmissionRepositoryCoordinates, ProviderWorkflowResultRequest, ProviderWorkflowResultService,
    ProviderWorkflowResultServiceError, RepositoryWorkflowSource, WorkflowAdmissionError,
    WorkflowAdmissionRequest, WorkflowAdmissionRequestError, WorkflowAdmissionResult,
    WorkflowAdmissionService,
};

/// Exact resolved inputs for one normalized provider-trigger application.
pub struct ProviderWorkflowApplicationRequest {
    connection: ProviderConnectionManifest,
    delivery: VerifiedProviderTriggerDelivery,
    processing: ClaimedProviderProcessing,
    claim_source: Arc<dyn ProviderProcessingClaimSource>,
    source: RepositorySourceArchive,
    execution_ref: ProviderGitRef,
    trust: TrustSnapshot,
    metadata: ProviderEventMetadata,
}

impl ProviderWorkflowApplicationRequest {
    /// Binds resolved source, dialect selection, and current processing authority.
    ///
    /// The request accepts repository-dispatch coordinates resolved after
    /// normalization. Every other event must retain its normalized source and
    /// execution coordinates exactly.
    ///
    /// # Errors
    ///
    /// Rejects mismatched connection, trigger, processing, source, repository,
    /// revision, execution ref, or archive evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection: ProviderConnectionManifest,
        delivery: VerifiedProviderTriggerDelivery,
        processing: ClaimedProviderProcessing,
        claim_source: Arc<dyn ProviderProcessingClaimSource>,
        source: RepositorySourceArchive,
        execution_ref: ProviderGitRef,
        trust: TrustSnapshot,
        metadata: ProviderEventMetadata,
    ) -> Result<Self, ProviderWorkflowApplicationRequestError> {
        let trigger = delivery.trigger().trigger();
        let configuration = connection.configuration();
        let processing_trigger = match processing.input() {
            ProviderProcessingInput::Trigger(value) => value,
            ProviderProcessingInput::Control(_) => {
                return Err(ProviderWorkflowApplicationRequestError);
            }
        };
        if processing_trigger.as_ref() != &delivery
            || processing.receipt().source_delivery_id() != Some(delivery.evidence().delivery_id())
            || delivery.evidence().connection_id() != connection.connection_id()
            || delivery.evidence().connection_revision() != connection.revision()
            || connection.state() != ProviderLifecycleState::Active
            || delivery.evidence().provider_revision() != configuration.provider_revision()
            || trigger.target_repository().identity() != configuration.repository()
            || trigger.target_repository().visibility() != configuration.visibility()
            || source.connection_id() != connection.connection_id()
            || source.external_repository_id() != configuration.repository().external_id()
            || source.repository().as_str() != trigger.target_repository().path().as_str()
            || source.format() != ArchiveFormat::TarGzip
            || source.size() > configuration.archive_limits().compressed_bytes()
            || !valid_actions_workflow_selection(configuration.workflow_source())
            || trigger
                .workflow_source_revision()
                .is_some_and(|revision| revision != *source.revision())
            || trigger
                .workflow_execution_ref()
                .is_some_and(|git_ref| git_ref != &execution_ref)
            || !metadata.matches_normalized_trigger(trigger)
        {
            return Err(ProviderWorkflowApplicationRequestError);
        }
        Ok(Self {
            connection,
            delivery,
            processing,
            claim_source,
            source,
            execution_ref,
            trust,
            metadata,
        })
    }

    /// Returns exact normalized trigger evidence.
    #[must_use]
    pub const fn delivery(&self) -> &VerifiedProviderTriggerDelivery {
        &self.delivery
    }
}

impl fmt::Debug for ProviderWorkflowApplicationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWorkflowApplicationRequest")
            .field("connection", &self.connection)
            .field("delivery", &self.delivery)
            .field("processing", &self.processing)
            .field("claim_source", &"[live processing fence]")
            .field("source", &self.source)
            .field("execution_ref", &self.execution_ref)
            .field("trust", &"[derived trust snapshot]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Invalid resolved provider-trigger application evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("provider workflow application request is inconsistent")]
pub struct ProviderWorkflowApplicationRequestError;

/// Shared Actions workflow selection and common admission service.
#[derive(Clone)]
pub struct ProviderWorkflowApplicationService {
    admission: WorkflowAdmissionService,
    results: ProviderWorkflowResultService,
}

impl ProviderWorkflowApplicationService {
    /// Composes trigger application over the canonical workflow admission service.
    #[must_use]
    pub const fn new(
        admission: WorkflowAdmissionService,
        results: ProviderWorkflowResultService,
    ) -> Self {
        Self { admission, results }
    }

    /// Selects every configured workflow and admits each accepted plan.
    ///
    /// Selection is a two-pass boundary. If any workflow requires changed-file
    /// evidence, no workflow is admitted and the caller receives
    /// [`ProviderWorkflowApplicationOutcome::RequiresChangedFiles`]. The
    /// provider adapter obtains one complete or explicitly incomplete
    /// observation, rebuilds `ProviderEventMetadata`, and replays this method.
    ///
    /// # Errors
    ///
    /// Returns a sanitized application error for invalid archive/evidence,
    /// request construction, unavailable admission infrastructure, or a
    /// contradictory durable admission.
    pub async fn apply(
        &self,
        request: ProviderWorkflowApplicationRequest,
    ) -> Result<ProviderWorkflowApplicationOutcome, ProviderWorkflowApplicationError> {
        let prepared = prepare(&request)?;
        if prepared
            .iter()
            .any(|workflow| workflow.disposition == CompilationDisposition::RequiresChangedFiles)
        {
            return Ok(ProviderWorkflowApplicationOutcome::RequiresChangedFiles);
        }
        let (object, attempt, created_at) = result_coordinates(&request)?;
        let mut results = Vec::with_capacity(prepared.len());
        for workflow in prepared {
            let outcome = match workflow.disposition {
                CompilationDisposition::Accepted => {
                    let plan = workflow
                        .plan
                        .ok_or(ProviderWorkflowApplicationError::InvalidEvidence)?;
                    let inputs = workflow
                        .inputs
                        .unwrap_or_else(automata_ci_core::ContextValue::empty_object);
                    let base_context = JobRuntimeContext::new_base(
                        inputs,
                        automata_ci_core::ContextValue::empty_object(),
                        BTreeMap::new(),
                    )
                    .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
                    let workflow_name = plan
                        .name()
                        .map_or_else(|| workflow.path.clone(), |name| name.value().clone());
                    let admission = admission_request(
                        &request,
                        &workflow.path,
                        workflow.source,
                        plan,
                        base_context,
                        workflow_name,
                        &workflow.repository_sources,
                    )?;
                    match self
                        .admission
                        .admit_authenticated_provider_delivery(
                            admission,
                            request.delivery.evidence().delivery_id(),
                            request.processing.receipt(),
                            Arc::clone(&request.claim_source),
                        )
                        .await
                    {
                        Ok(result) => ProviderWorkflowDisposition::Admitted(result),
                        Err(WorkflowAdmissionError::Store(
                            LogicalWorkflowAdmissionStoreError::WorkflowDisabled,
                        )) => ProviderWorkflowDisposition::Rejected(
                            ProviderWorkflowRejection::WorkflowDisabled,
                        ),
                        Err(WorkflowAdmissionError::Store(
                            LogicalWorkflowAdmissionStoreError::RunNumberExhausted,
                        )) => ProviderWorkflowDisposition::Rejected(
                            ProviderWorkflowRejection::RunNumberExhausted,
                        ),
                        Err(error) => return Err(admission_error(&error)),
                    }
                }
                CompilationDisposition::NotSelected(reason) => {
                    ProviderWorkflowDisposition::NotSelected(reason)
                }
                CompilationDisposition::Rejected => ProviderWorkflowDisposition::Rejected(
                    workflow
                        .rejection
                        .unwrap_or(ProviderWorkflowRejection::Compilation),
                ),
                CompilationDisposition::RequiresChangedFiles => {
                    return Err(ProviderWorkflowApplicationError::InvalidEvidence);
                }
                _ => ProviderWorkflowDisposition::Rejected(
                    ProviderWorkflowRejection::UnsupportedCompilationDisposition,
                ),
            };
            self.results
                .project(ProviderWorkflowResultRequest {
                    connection: &request.connection,
                    delivery: &request.delivery,
                    object,
                    workflow_path: &workflow.path,
                    attempt,
                    created_at,
                    disposition: outcome,
                })
                .await
                .map_err(provider_result_error)?;
            results.push(ProviderWorkflowApplicationReport {
                path: workflow.path,
                disposition: outcome,
            });
        }
        Ok(ProviderWorkflowApplicationOutcome::Applied(results))
    }
}

impl fmt::Debug for ProviderWorkflowApplicationService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWorkflowApplicationService")
            .field("admission", &"[workflow admission service]")
            .field("results", &self.results)
            .finish()
    }
}

const fn provider_result_error(
    error: ProviderWorkflowResultServiceError,
) -> ProviderWorkflowApplicationError {
    match error {
        ProviderWorkflowResultServiceError::Unavailable => {
            ProviderWorkflowApplicationError::Unavailable
        }
        ProviderWorkflowResultServiceError::InvalidConfiguration
        | ProviderWorkflowResultServiceError::InvalidEvidence => {
            ProviderWorkflowApplicationError::InvalidEvidence
        }
        ProviderWorkflowResultServiceError::SubjectNotReady
        | ProviderWorkflowResultServiceError::Inconsistent => {
            ProviderWorkflowApplicationError::Inconsistent
        }
    }
}

fn result_coordinates(
    request: &ProviderWorkflowApplicationRequest,
) -> Result<
    (
        automata_ci_core::GitObjectId,
        u32,
        automata_ci_core::UnixMillis,
    ),
    ProviderWorkflowApplicationError,
> {
    let object = request
        .trust
        .evidence()
        .execution_revision()
        .ok_or(ProviderWorkflowApplicationError::InvalidEvidence)
        .and_then(|revision| {
            automata_ci_core::GitObjectId::from_provider_hex(revision)
                .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)
        })?;
    let receipt = request.processing.receipt();
    Ok((object, u32::from(receipt.attempts()), receipt.created_at()))
}

/// Result of applying every selected workflow in one provider delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderWorkflowApplicationOutcome {
    /// At least one workflow requires a provider changed-file observation;
    /// nothing was admitted.
    RequiresChangedFiles,
    /// All workflows reached an idempotent admission or terminal selection result.
    Applied(Vec<ProviderWorkflowApplicationReport>),
}

/// One deterministic workflow-path result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderWorkflowApplicationReport {
    path: String,
    disposition: ProviderWorkflowDisposition,
}

impl ProviderWorkflowApplicationReport {
    /// Returns the canonical repository-relative workflow path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the terminal application disposition.
    #[must_use]
    pub const fn disposition(&self) -> &ProviderWorkflowDisposition {
        &self.disposition
    }
}

/// Terminal result for one workflow path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWorkflowDisposition {
    /// A logical workflow run exists, including an exact idempotent replay.
    Admitted(WorkflowAdmissionResult),
    /// The valid workflow did not select this trigger.
    NotSelected(WorkflowNotSelectedReason),
    /// The workflow reached a closed terminal rejection.
    Rejected(ProviderWorkflowRejection),
}

/// Closed terminal workflow rejection suitable for result projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWorkflowRejection {
    /// The workflow file was empty, oversized, or not UTF-8.
    Source,
    /// Parsing or semantic decoding rejected the source.
    Frontend,
    /// Event selection or provider-neutral lowering rejected the workflow.
    Compilation,
    /// Current connection policy disables the workflow.
    WorkflowDisabled,
    /// The repository exhausted its durable run-number range.
    RunNumberExhausted,
    /// The compiler returned a future disposition unknown to this application version.
    UnsupportedCompilationDisposition,
}

/// Sanitized trigger application failure.
#[derive(Debug, Error)]
pub enum ProviderWorkflowApplicationError {
    /// Provider evidence, source, selection, or request construction disagreed.
    #[error("provider workflow application evidence is invalid")]
    InvalidEvidence,
    /// Blob, database, or other retryable admission infrastructure is unavailable.
    #[error("provider workflow application is unavailable")]
    Unavailable,
    /// Durable admission state contradicted the exact application request.
    #[error("provider workflow application state is inconsistent")]
    Inconsistent,
}

struct PreparedWorkflow {
    path: String,
    source: Bytes,
    plan: Option<automata_ci_core::WorkflowPlan>,
    inputs: Option<automata_ci_core::ContextValue>,
    disposition: CompilationDisposition,
    rejection: Option<ProviderWorkflowRejection>,
    repository_sources: Arc<[RepositoryWorkflowSource]>,
}

fn prepare(
    request: &ProviderWorkflowApplicationRequest,
) -> Result<Vec<PreparedWorkflow>, ProviderWorkflowApplicationError> {
    let event =
        ActionsProviderEventDocument::from_normalized_trigger(request.delivery.trigger().trigger())
            .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
    let limits = discovery_limits(request.connection.configuration().archive_limits())?;
    let discovered = discover_provider_workflows(request.source.bytes(), limits)
        .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
    let mut selected = Vec::new();
    let mut reusable = Vec::new();
    for workflow in discovered {
        let (path, source) = workflow.into_parts();
        let selected_for_trigger =
            workflow_selected(request.connection.configuration().workflow_source(), &path);
        match source {
            Ok(source) => {
                reusable.push(RepositoryWorkflowSource::new(
                    path.clone(),
                    Bytes::copy_from_slice(&source),
                ));
                if selected_for_trigger {
                    selected.push((path, Some(source)));
                }
            }
            Err(_) if selected_for_trigger => selected.push((path, None)),
            Err(_) => {
                // A malformed non-selected sibling grants no reusable source
                // authority and does not reject an otherwise exact trigger.
            }
        }
    }
    if let ProviderWorkflowSource::File(path) = request.connection.configuration().workflow_source()
        && selected.is_empty()
    {
        selected.push((path.as_str().to_owned(), None));
    }
    let repository_sources: Arc<[RepositoryWorkflowSource]> = reusable.into();
    let trigger = request.delivery.trigger().trigger();
    let event_provenance = event_provenance(request, event.event_name());
    let mut prepared = Vec::with_capacity(selected.len());
    for (path, source) in selected {
        let Some(source) = source else {
            prepared.push(PreparedWorkflow {
                path,
                source: Bytes::new(),
                plan: None,
                inputs: None,
                disposition: CompilationDisposition::Rejected,
                rejection: Some(ProviderWorkflowRejection::Source),
                repository_sources: Arc::clone(&repository_sources),
            });
            continue;
        };
        let Ok(text) = std::str::from_utf8(&source) else {
            prepared.push(PreparedWorkflow {
                path,
                source: Bytes::from(source),
                plan: None,
                inputs: None,
                disposition: CompilationDisposition::Rejected,
                rejection: Some(ProviderWorkflowRejection::Source),
                repository_sources: Arc::clone(&repository_sources),
            });
            continue;
        };
        let parsed = GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
            source_provenance(request, &path),
            text,
        ));
        let Some(source_plan) = parsed.plan().filter(|_| parsed.is_accepted()) else {
            prepared.push(PreparedWorkflow {
                path,
                source: Bytes::from(source),
                plan: None,
                inputs: None,
                disposition: CompilationDisposition::Rejected,
                rejection: Some(ProviderWorkflowRejection::Frontend),
                repository_sources: Arc::clone(&repository_sources),
            });
            continue;
        };
        let report = GithubWorkflowCompiler::new().compile(
            CompileWorkflowRequest::new(source_plan, event_provenance.clone())
                .with_event_metadata(request.metadata.clone()),
        );
        let disposition = report.disposition();
        let inputs = report.workflow_dispatch_inputs().cloned();
        let plan = report.into_parts().0;
        prepared.push(PreparedWorkflow {
            path,
            source: Bytes::from(source),
            plan,
            inputs,
            disposition,
            rejection: None,
            repository_sources: Arc::clone(&repository_sources),
        });
    }
    if trigger.target_repository().identity() != request.connection.configuration().repository() {
        return Err(ProviderWorkflowApplicationError::InvalidEvidence);
    }
    Ok(prepared)
}

fn admission_request(
    request: &ProviderWorkflowApplicationRequest,
    path: &str,
    source: Bytes,
    plan: automata_ci_core::WorkflowPlan,
    base_context: JobRuntimeContext,
    workflow_name: String,
    repository_sources: &[RepositoryWorkflowSource],
) -> Result<WorkflowAdmissionRequest, ProviderWorkflowApplicationError> {
    let trigger = request.delivery.trigger().trigger();
    let repository = trigger.target_repository();
    let provider = request.delivery.evidence().provider_type().as_str();
    let coordinates = AdmissionRepositoryCoordinates::new(
        provider,
        repository.identity().external_id().as_str(),
        repository.path().as_str(),
    )
    .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
    let tenant = TenantScope::from_authenticated_tenant_id(
        request
            .connection
            .configuration()
            .workspace_id()
            .to_string(),
    )
    .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
    let idempotency = WorkflowAdmissionIdempotency::provider_delivery(
        request.delivery.evidence().delivery_id().to_string(),
    )
    .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
    let event = ActionsProviderEventDocument::from_normalized_trigger(trigger)
        .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?;
    let mut builder = WorkflowAdmissionRequest::builder(
        tenant,
        coordinates,
        path,
        source,
        Bytes::from(event.into_canonical_bytes()),
        plan,
        base_context,
        idempotency,
        *request.source.revision(),
    )
    .trust_snapshot(request.trust.clone())
    .git_ref(request.execution_ref.full())
    .workflow_name(workflow_name)
    .run_attempt(1)
    .repository_workflow_sources(repository_sources.iter().cloned());
    if let Some(actor) = trigger_actor(trigger) {
        builder = builder.actor(actor.external_id().as_str());
    }
    builder.build().map_err(admission_request_error)
}

fn event_provenance(
    request: &ProviderWorkflowApplicationRequest,
    event_name: &str,
) -> WorkflowEventProvenance {
    // `github` is the current durable identifier of the Actions-compatible
    // source/event dialect. Host-provider identity is stored separately in
    // admission repository and common delivery evidence.
    WorkflowEventProvenance::new("github", event_name)
        .with_delivery_id(
            request
                .delivery
                .evidence()
                .external_delivery()
                .external_id()
                .as_str(),
        )
        .with_commit_sha(*request.source.revision())
        .with_git_ref(request.execution_ref.full())
}

fn source_provenance(request: &ProviderWorkflowApplicationRequest, path: &str) -> SourceProvenance {
    SourceProvenance::new(
        SourceId::new(path),
        SourceOrigin::Repository {
            repository: Arc::from(request.source.repository().as_str()),
            revision: *request.source.revision(),
            path: Arc::from(path),
        },
    )
}

fn workflow_selected(selection: &ProviderWorkflowSource, path: &str) -> bool {
    match selection {
        ProviderWorkflowSource::File(selected) => path == selected.as_str(),
        ProviderWorkflowSource::Directory(selected) => path
            .strip_prefix(selected.as_str())
            .is_some_and(|tail| tail.starts_with('/')),
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn valid_actions_workflow_selection(selection: &ProviderWorkflowSource) -> bool {
    match selection {
        ProviderWorkflowSource::Directory(path) => path.as_str() == ".ci/workflows",
        ProviderWorkflowSource::File(path) => path
            .as_str()
            .strip_prefix(".ci/workflows/")
            .is_some_and(|name| {
                !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
            }),
    }
}

fn discovery_limits(
    limits: automata_ci_provider::ProviderArchiveLimits,
) -> Result<RepositoryWorkflowDiscoveryLimits, ProviderWorkflowApplicationError> {
    RepositoryWorkflowDiscoveryLimits::new(
        limits.compressed_bytes(),
        limits.expanded_bytes(),
        usize::try_from(limits.entries())
            .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?,
        limits.expanded_bytes(),
        usize::try_from(limits.entry_path_bytes())
            .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?,
        usize::try_from(limits.workflows())
            .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)?,
        limits.workflow_bytes(),
    )
    .map_err(|_| ProviderWorkflowApplicationError::InvalidEvidence)
}

fn trigger_actor(
    trigger: &NormalizedTrigger,
) -> Option<&automata_ci_provider::ExternalSubjectIdentity> {
    match trigger {
        NormalizedTrigger::Push(value) => value.actor(),
        NormalizedTrigger::PullRequest(value) => value.actor(),
        NormalizedTrigger::MergeQueue(value) => value.actor(),
        NormalizedTrigger::RepositoryDispatch(value) => value.actor(),
    }
}

const fn admission_request_error(
    _error: WorkflowAdmissionRequestError,
) -> ProviderWorkflowApplicationError {
    ProviderWorkflowApplicationError::InvalidEvidence
}

fn admission_error(error: &WorkflowAdmissionError) -> ProviderWorkflowApplicationError {
    match error {
        WorkflowAdmissionError::Blob(error)
            if matches!(
                error.kind(),
                automata_ci_blob::BlobStoreErrorKind::Unavailable
                    | automata_ci_blob::BlobStoreErrorKind::Unauthorized
            ) =>
        {
            ProviderWorkflowApplicationError::Unavailable
        }
        WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::Store(
            StoreError::Operation(_),
        )) => ProviderWorkflowApplicationError::Unavailable,
        _ => ProviderWorkflowApplicationError::Inconsistent,
    }
}
