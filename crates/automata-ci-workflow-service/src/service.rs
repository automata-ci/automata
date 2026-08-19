use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledValueTemplate,
    ExpressionInstruction, ExpressionLiteral, ExpressionSegment, LogicalJobKind,
    MAX_LOGICAL_FIELD_BYTES, OutputSensitivity, PermissionLevel, PlanSourceOrigin, Sha256Digest,
    WorkflowJobKey,
};
use automata_ci_expression_actions::{
    GithubExpressionEvaluator, GithubObject, GithubStatus, GithubValue, MapContext,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AdmittedReusableInput, AdmittedReusableInputKind, AdmittedReusableInvocation,
    AdmittedReusableJob, AdmittedReusableOutput, AdmittedReusablePermissions,
    AdmittedReusableSecret, AdmittedReusableWorkflowCatalogEntry,
    AdmittedReusableWorkflowExpansion, AuthenticatedGithubDeliveryClaim,
    AuthenticatedProviderDeliveryClaim, AuthenticatedWorkflowDispatchClaim,
    AuthenticatedWorkflowDispatchSource, GithubScheduleFireClaim, JobCredentialRequirements,
    JobEnvironmentRequirement, LogicalWorkflowAdmissionRepository,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowAdmissionValueError, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, ProviderDeliveryId, ProviderProcessingClaimSource,
    ProviderProcessingReceipt, ResolveAuthenticatedWorkflowDispatchSource,
    WorkflowAdmissionIdempotency, WorkflowAdmissionValueError, WorkflowConcurrency,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AdmissionClock, AdmissionIdGenerator, CredentialDiscoveryError, ExpandReusableWorkflowRequest,
    GITHUB_WORKFLOW_MEDIA_TYPE, GithubReusableWorkflowCatalog, JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    NoopWorkflowAdmissionObserver, ReusableInputBindingSource, ReusableWorkflowExpander,
    ReusableWorkflowExpansionError, ReusableWorkflowPermissions, Sha256AdmissionIdGenerator,
    SystemAdmissionClock, WORKFLOW_PLAN_MEDIA_TYPE, WorkflowAdmissionFailure,
    WorkflowAdmissionObservation, WorkflowAdmissionObserver, WorkflowAdmissionRequest,
    WorkflowAdmissionResult, WorkflowAdmissionStage, WorkflowAdmissionStageOutcome,
    WorkflowDispatchAuthorization, WorkflowPlanVerificationError, WorkflowPlanVerifier,
    github_activation::context_to_github_value,
    github_dispatch::{
        AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE, GithubWorkflowDispatchEvidence,
    },
};

const REQUEST_DIGEST_DOMAIN_V9: &[u8] = b"automata.workflow-admission.request.v9.repository-path\0";
const AUTHENTICATED_PROVIDER_REQUEST_DIGEST_DOMAIN_V10: &[u8] =
    b"automata.workflow-admission.request.v10.authenticated-provider.repository-path\0";
const AUTHENTICATED_WORKFLOW_DISPATCH_REQUEST_DIGEST_DOMAIN_V9: &[u8] =
    b"automata.workflow-admission.request.v9.control-plane-dispatch.repository-path\0";
const SCHEDULED_GITHUB_REQUEST_DIGEST_DOMAIN_V9: &[u8] =
    b"automata.workflow-admission.request.v9.scheduled-github.repository-path\0";
const ADMISSION_GITHUB_PROPERTIES: &[&str] = &[
    "actor",
    "event",
    "event_name",
    "ref",
    "ref_name",
    "ref_type",
    "repository",
    "repository_id",
    "repository_owner",
    "run_attempt",
    "sha",
    "triggering_actor",
    "workflow",
    "workflow_ref",
    "workflow_sha",
];
const MAX_RUN_DISPLAY_TITLE_BYTES: usize = 1_024;

enum AdmissionAuthority {
    ProviderNeutral,
    AuthenticatedProvider {
        delivery_id: ProviderDeliveryId,
        processing: ProviderProcessingReceipt,
        claim_source: Arc<dyn ProviderProcessingClaimSource>,
    },
    AuthenticatedGithub(AuthenticatedGithubDeliveryClaim),
    AuthenticatedWorkflowDispatch(WorkflowDispatchAuthorization),
    ScheduledGithub(GithubScheduleFireClaim),
}

/// Blob-first, provider-pluggable logical workflow admission service.
#[derive(Clone)]
pub struct WorkflowAdmissionService {
    blobs: Arc<dyn ImmutableBlobStore>,
    repository: Arc<dyn LogicalWorkflowAdmissionRepository>,
    verifier: Arc<dyn WorkflowPlanVerifier>,
    ids: Arc<dyn AdmissionIdGenerator>,
    clock: Arc<dyn AdmissionClock>,
    observer: Arc<dyn WorkflowAdmissionObserver>,
}

impl WorkflowAdmissionService {
    /// Creates the service with explicit infrastructure and policy ports.
    #[must_use]
    pub fn new(
        blobs: Arc<dyn ImmutableBlobStore>,
        repository: Arc<dyn LogicalWorkflowAdmissionRepository>,
        verifier: Arc<dyn WorkflowPlanVerifier>,
        ids: Arc<dyn AdmissionIdGenerator>,
        clock: Arc<dyn AdmissionClock>,
    ) -> Self {
        Self {
            blobs,
            repository,
            verifier,
            ids,
            clock,
            observer: Arc::new(NoopWorkflowAdmissionObserver),
        }
    }

    /// Installs a provider-neutral admission observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn WorkflowAdmissionObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Creates the service with production identity and clock implementations.
    #[must_use]
    pub fn with_system_ports(
        blobs: Arc<dyn ImmutableBlobStore>,
        repository: Arc<dyn LogicalWorkflowAdmissionRepository>,
        verifier: Arc<dyn WorkflowPlanVerifier>,
    ) -> Self {
        Self::new(
            blobs,
            repository,
            verifier,
            Arc::new(Sha256AdmissionIdGenerator),
            Arc::new(SystemAdmissionClock),
        )
    }

    /// Publishes immutable evidence and atomically admits one logical workflow DAG.
    ///
    /// No concrete job or `JobIR` exists at this phase. Logical jobs become
    /// executable only after their prerequisite result snapshot is available.
    /// Blob publication intentionally precedes the relational transaction, so
    /// a failed commit can leave only safe content-addressed orphans.
    ///
    /// # Errors
    ///
    /// Fails closed on exact-source verification, invalid logical graph data,
    /// object-store failure, or atomic store rejection.
    pub fn admit(
        &self,
        request: WorkflowAdmissionRequest,
    ) -> impl Future<Output = Result<WorkflowAdmissionResult, WorkflowAdmissionError>> + Send + '_
    {
        Box::pin(self.admit_with_authority(request, AdmissionAuthority::ProviderNeutral))
    }

    /// Publishes and admits one workflow selected from an authenticated
    /// provider trigger under the common processing lease.
    ///
    /// The service reads `claim_source` immediately before the atomic durable
    /// commit, so lease renewal during verification or blob publication cannot
    /// leave admission using a stale fence horizon.
    ///
    /// # Errors
    ///
    /// Fails closed when the processing receipt, latest fence, trigger
    /// delivery, request, or durable provider evidence disagree.
    pub fn admit_authenticated_provider_delivery(
        &self,
        request: WorkflowAdmissionRequest,
        delivery_id: ProviderDeliveryId,
        processing: ProviderProcessingReceipt,
        claim_source: Arc<dyn ProviderProcessingClaimSource>,
    ) -> impl Future<Output = Result<WorkflowAdmissionResult, WorkflowAdmissionError>> + Send + '_
    {
        Box::pin(self.admit_with_authority(
            request,
            AdmissionAuthority::AuthenticatedProvider {
                delivery_id,
                processing,
                claim_source,
            },
        ))
    }

    /// Publishes and admits one workflow selected from an authenticated GitHub
    /// delivery while atomically binding its signed subject evidence.
    ///
    /// `current_claim` is the exact live inbox owner/attempt/fence snapshot
    /// obtained by the signed delivery worker, not provider-controlled input.
    /// The durable adapter row-locks and validates it together with all exact
    /// manifest, queued-Check, repository, source, plan, and run evidence in
    /// the admission transaction. The ordinary [`Self::admit`] path cannot
    /// create or backfill that evidence.
    ///
    /// # Errors
    ///
    /// Fails closed on the same admission errors as [`Self::admit`], and when
    /// signed GitHub subject evidence is absent or does not match the request.
    pub fn admit_authenticated_github_delivery(
        &self,
        request: WorkflowAdmissionRequest,
        current_claim: AuthenticatedGithubDeliveryClaim,
    ) -> impl Future<Output = Result<WorkflowAdmissionResult, WorkflowAdmissionError>> + Send + '_
    {
        Box::pin(self.admit_with_authority(
            request,
            AdmissionAuthority::AuthenticatedGithub(current_claim),
        ))
    }

    /// Publishes and admits one invocation from an exact live scheduled fire.
    ///
    /// # Errors
    ///
    /// Fails closed unless the operation idempotency, schedule event, source,
    /// manifest, pre-admission Check, and current fire fence all agree.
    pub fn admit_scheduled_github_workflow(
        &self,
        request: WorkflowAdmissionRequest,
        claim: GithubScheduleFireClaim,
    ) -> impl Future<Output = Result<WorkflowAdmissionResult, WorkflowAdmissionError>> + Send + '_
    {
        Box::pin(self.admit_with_authority(request, AdmissionAuthority::ScheduledGithub(claim)))
    }

    /// Publishes and admits one authenticated Automata control-plane manual
    /// dispatch with exact repository/workflow/ref identity.
    ///
    /// This boundary does not represent a GitHub webhook. The durable adapter
    /// reauthorizes current Core or delegated authority for `runs:dispatch`
    /// and retains exact digest and audit evidence for replay.
    ///
    /// # Errors
    ///
    /// Fails closed when evidence, exact target identity, current authority,
    /// immutable publication, or durable replay does not agree.
    pub fn admit_authenticated_workflow_dispatch(
        &self,
        request: WorkflowAdmissionRequest,
        authorization: WorkflowDispatchAuthorization,
    ) -> impl Future<Output = Result<WorkflowAdmissionResult, WorkflowAdmissionError>> + Send + '_
    {
        Box::pin(self.admit_with_authority(
            request,
            AdmissionAuthority::AuthenticatedWorkflowDispatch(authorization),
        ))
    }

    pub(crate) async fn resolve_authenticated_workflow_dispatch_source(
        &self,
        request: ResolveAuthenticatedWorkflowDispatchSource,
    ) -> Result<Option<(AuthenticatedWorkflowDispatchSource, Bytes)>, WorkflowAdmissionError> {
        let Some(source) = self
            .repository
            .resolve_authenticated_workflow_dispatch_source(request)
            .await?
        else {
            return Ok(None);
        };
        if !crate::github_workflow_media_type_is_current(source.source().media_type()) {
            return Err(WorkflowAdmissionError::WorkflowDispatchEvidence);
        }
        let descriptor = BlobDescriptor::new(
            BlobKey::new(source.source().object_key().as_str().to_owned())
                .map_err(|_| WorkflowAdmissionError::WorkflowDispatchEvidence)?,
            source.source().digest(),
            source.source().encoded_size(),
            MediaType::new(source.source().media_type().to_owned())
                .map_err(|_| WorkflowAdmissionError::WorkflowDispatchEvidence)?,
        );
        let bytes = self
            .blobs
            .get_verified(&descriptor, source.source().encoded_size())
            .await
            .map_err(WorkflowAdmissionError::Blob)?
            .into_bytes();
        Ok(Some((source, bytes)))
    }

    async fn admit_with_authority(
        &self,
        request: WorkflowAdmissionRequest,
        authority: AdmissionAuthority,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        let started = Instant::now();
        let jobs = request.plan().jobs().len();
        let result = Box::pin(self.admit_inner(request, authority)).await;
        let outcome = match &result {
            Ok(value) if value.receipt().is_replay() => WorkflowAdmissionObservation::Replay,
            Ok(_) => WorkflowAdmissionObservation::New { jobs },
            Err(error) => WorkflowAdmissionObservation::Failed(observe_failure(error)),
        };
        self.observer.observe_admission(outcome, started.elapsed());
        result
    }

    #[allow(clippy::too_many_lines)] // Keeps the five observed admission stages in one auditable flow.
    async fn admit_inner(
        &self,
        request: WorkflowAdmissionRequest,
        authority: AdmissionAuthority,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        let delivery_id = match &authority {
            AdmissionAuthority::AuthenticatedProvider { delivery_id, .. } => Some(*delivery_id),
            AdmissionAuthority::AuthenticatedGithub(claim) => Some(claim.claim().delivery_id()),
            AdmissionAuthority::ProviderNeutral
            | AdmissionAuthority::AuthenticatedWorkflowDispatch(_)
            | AdmissionAuthority::ScheduledGithub(_) => None,
        };
        let schedule_fire_id = match &authority {
            AdmissionAuthority::ScheduledGithub(claim) => Some(claim.fire_id()),
            AdmissionAuthority::ProviderNeutral
            | AdmissionAuthority::AuthenticatedProvider { .. }
            | AdmissionAuthority::AuthenticatedGithub(_)
            | AdmissionAuthority::AuthenticatedWorkflowDispatch(_) => None,
        };
        let (
            source_blob,
            event_blob,
            plan_blob,
            base_context_blob,
            repository_id,
            workflow_id,
            snapshot_id,
            durable_idempotency,
            run_id,
            dispatch_claim,
        ) = self.observe_sync_stage(WorkflowAdmissionStage::Prepare, || {
            if delivery_id.is_some()
                && !matches!(
                    request.idempotency(),
                    WorkflowAdmissionIdempotency::ProviderDelivery(_)
                )
            {
                return Err(WorkflowAdmissionError::Internal);
            }
            if let Some(fire_id) = schedule_fire_id {
                let exact = request.repository().provider() == "github"
                    && request.plan().event().name() == "schedule"
                    && request.actor() == Some(automata_ci_store::GITHUB_SCHEDULE_SERVICE_ACTOR)
                    && matches!(
                        request.idempotency(),
                        WorkflowAdmissionIdempotency::Operation(operation_id)
                            if operation_id.as_uuid() == fire_id.as_uuid()
                    );
                if !exact {
                    return Err(WorkflowAdmissionError::Internal);
                }
            }
            let source_blob = prepare_blob(
                "workflow-source",
                GITHUB_WORKFLOW_MEDIA_TYPE,
                request.source().clone(),
            )?;
            let event_blob = prepare_event_blob(
                "workflow-event",
                request.event_media_type(),
                request.event().clone(),
            )?;
            let plan_bytes = Bytes::from(
                serde_json::to_vec(request.plan())
                    .map_err(|_| WorkflowAdmissionError::Serialization)?,
            );
            let plan_blob = prepare_blob("workflow-plan", WORKFLOW_PLAN_MEDIA_TYPE, plan_bytes)?;
            let base_context_bytes = automata_ci_protocol_protobuf::encode_job_runtime_context(
                request.base_context(),
                &ProtocolLimits::default(),
            )
            .map_err(|_| WorkflowAdmissionError::Serialization)?;
            let base_context_blob = prepare_blob(
                "base-runtime-context",
                JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
                Bytes::from(base_context_bytes),
            )?;
            let repository_id = self
                .ids
                .repository_id(request.tenant(), request.repository());
            let workflow_id = self.ids.workflow_id(repository_id, request.workflow_path());
            let snapshot_id = self
                .ids
                .snapshot_id(workflow_id, source_blob.metadata.digest());
            let durable_idempotency = namespace_idempotency(&request)?;
            let run_id = self.ids.run_id(request.tenant(), &durable_idempotency);
            let dispatch_claim = match &authority {
                AdmissionAuthority::AuthenticatedWorkflowDispatch(authorization) => {
                    if request.event_media_type()
                        != AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE
                    {
                        return Err(WorkflowAdmissionError::WorkflowDispatchEvidence);
                    }
                    let evidence = GithubWorkflowDispatchEvidence::decode(request.event())
                        .map_err(|_| WorkflowAdmissionError::WorkflowDispatchEvidence)?;
                    if !evidence.matches_admission(&request)
                        || !evidence.authority_matches(authorization)
                        || evidence.repository_id() != repository_id
                        || evidence.workflow_id() != workflow_id
                    {
                        return Err(WorkflowAdmissionError::WorkflowDispatchEvidence);
                    }
                    let operation_id = match request.idempotency() {
                        WorkflowAdmissionIdempotency::Operation(operation_id) => *operation_id,
                        WorkflowAdmissionIdempotency::ProviderDelivery(_) => {
                            return Err(WorkflowAdmissionError::WorkflowDispatchEvidence);
                        }
                    };
                    Some(AuthenticatedWorkflowDispatchClaim::new(
                        authorization.actor().clone(),
                        repository_id,
                        workflow_id,
                        request.workflow_path(),
                        request.git_ref(),
                        request.commit_sha(),
                        source_blob.metadata.clone(),
                        operation_id,
                        event_blob.metadata.digest(),
                        base_context_blob.metadata.digest(),
                    )?)
                }
                AdmissionAuthority::ProviderNeutral
                | AdmissionAuthority::AuthenticatedProvider { .. }
                | AdmissionAuthority::AuthenticatedGithub(_)
                | AdmissionAuthority::ScheduledGithub(_) => {
                    if request.event_media_type()
                        == AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE
                    {
                        return Err(WorkflowAdmissionError::WorkflowDispatchEvidence);
                    }
                    None
                }
            };
            Ok((
                source_blob,
                event_blob,
                plan_blob,
                base_context_blob,
                repository_id,
                workflow_id,
                snapshot_id,
                durable_idempotency,
                run_id,
                dispatch_claim,
            ))
        })?;

        let reusable = self.observe_sync_stage(WorkflowAdmissionStage::Materialize, || {
            self.verifier.verify(&request)?;
            prepare_reusable_workflow_expansion(
                &request,
                &*self.ids,
                run_id,
                &source_blob,
                &plan_blob,
            )
        })?;

        let command = self.observe_sync_stage(WorkflowAdmissionStage::Encode, || {
            let concurrency = resolve_workflow_concurrency(&request)?;
            let display_title = resolve_run_display_title(&request)?;
            let request_digest = canonical_request_digest(
                &request,
                delivery_id,
                schedule_fire_id,
                dispatch_claim.as_ref(),
                &source_blob,
                &event_blob,
                &plan_blob,
                &base_context_blob,
                display_title.as_deref(),
                concurrency.as_ref(),
                reusable.as_ref().map(|prepared| &prepared.graph),
            );
            build_command(
                &request,
                &*self.ids,
                self.clock.now(),
                repository_id,
                workflow_id,
                snapshot_id,
                durable_idempotency,
                run_id,
                request_digest,
                &source_blob,
                &event_blob,
                &plan_blob,
                &base_context_blob,
                display_title.as_deref(),
                concurrency,
                reusable.as_ref().map(|prepared| prepared.graph.clone()),
            )
        })?;

        let publication_started = Instant::now();
        let publication = async {
            self.publish(&source_blob).await?;
            self.publish(&event_blob).await?;
            self.publish(&plan_blob).await?;
            self.publish(&base_context_blob).await?;
            if let Some(reusable) = &reusable {
                for blob in &reusable.blobs {
                    self.publish(blob).await?;
                }
            }
            Ok::<(), WorkflowAdmissionError>(())
        }
        .await;
        self.observe_stage(
            WorkflowAdmissionStage::Publish,
            publication.is_ok(),
            publication_started.elapsed(),
        );
        publication?;

        let commit_started = Instant::now();
        let receipt = match authority {
            AdmissionAuthority::AuthenticatedProvider {
                delivery_id,
                processing,
                claim_source,
            } => {
                let observed_at = self.clock.now();
                let current_claim = AuthenticatedProviderDeliveryClaim::new(
                    delivery_id,
                    processing,
                    claim_source.current_fence(),
                )
                .map_err(|_| WorkflowAdmissionError::ProviderAdmissionAuthority)?;
                let command = build_command(
                    &request,
                    &*self.ids,
                    observed_at,
                    repository_id,
                    workflow_id,
                    snapshot_id,
                    command.idempotency().clone(),
                    run_id,
                    command.request_digest(),
                    &source_blob,
                    &event_blob,
                    &plan_blob,
                    &base_context_blob,
                    command.display_title(),
                    command.concurrency().cloned(),
                    command.reusable_workflows().cloned(),
                )?;
                self.repository
                    .admit_authenticated_provider_delivery(command, current_claim, observed_at)
                    .await
            }
            AdmissionAuthority::AuthenticatedGithub(current_claim) => {
                let observed_at = self.clock.now();
                // The provider path binds run creation to the same immediate
                // trusted observation that the Store validates against the
                // row-locked claim. Blob publication may be slow, so the
                // earlier encode-stage timestamp is not commit authority.
                let command = build_command(
                    &request,
                    &*self.ids,
                    observed_at,
                    repository_id,
                    workflow_id,
                    snapshot_id,
                    command.idempotency().clone(),
                    run_id,
                    command.request_digest(),
                    &source_blob,
                    &event_blob,
                    &plan_blob,
                    &base_context_blob,
                    command.display_title(),
                    command.concurrency().cloned(),
                    command.reusable_workflows().cloned(),
                )?;
                self.repository
                    .admit_authenticated_github_delivery(command, current_claim, observed_at)
                    .await
            }
            AdmissionAuthority::AuthenticatedWorkflowDispatch(_) => {
                let observed_at = self.clock.now();
                let command = build_command(
                    &request,
                    &*self.ids,
                    observed_at,
                    repository_id,
                    workflow_id,
                    snapshot_id,
                    command.idempotency().clone(),
                    run_id,
                    command.request_digest(),
                    &source_blob,
                    &event_blob,
                    &plan_blob,
                    &base_context_blob,
                    command.display_title(),
                    command.concurrency().cloned(),
                    command.reusable_workflows().cloned(),
                )?;
                self.repository
                    .admit_authenticated_workflow_dispatch(
                        command,
                        dispatch_claim.ok_or(WorkflowAdmissionError::WorkflowDispatchEvidence)?,
                    )
                    .await
            }
            AdmissionAuthority::ScheduledGithub(claim) => {
                let observed_at = self.clock.now();
                let command = build_command(
                    &request,
                    &*self.ids,
                    observed_at,
                    repository_id,
                    workflow_id,
                    snapshot_id,
                    command.idempotency().clone(),
                    run_id,
                    command.request_digest(),
                    &source_blob,
                    &event_blob,
                    &plan_blob,
                    &base_context_blob,
                    command.display_title(),
                    command.concurrency().cloned(),
                    command.reusable_workflows().cloned(),
                )?;
                self.repository
                    .admit_scheduled_github_workflow(command, claim)
                    .await
            }
            AdmissionAuthority::ProviderNeutral => {
                self.repository.admit_logical_workflow(command).await
            }
        };
        self.observe_stage(
            WorkflowAdmissionStage::Commit,
            receipt.is_ok(),
            commit_started.elapsed(),
        );
        Ok(WorkflowAdmissionResult::new(receipt?))
    }

    fn observe_sync_stage<T>(
        &self,
        stage: WorkflowAdmissionStage,
        operation: impl FnOnce() -> Result<T, WorkflowAdmissionError>,
    ) -> Result<T, WorkflowAdmissionError> {
        let started = Instant::now();
        let result = operation();
        self.observe_stage(stage, result.is_ok(), started.elapsed());
        result
    }

    fn observe_stage(&self, stage: WorkflowAdmissionStage, success: bool, duration: Duration) {
        self.observer.observe_stage(
            stage,
            if success {
                WorkflowAdmissionStageOutcome::Success
            } else {
                WorkflowAdmissionStageOutcome::Failure
            },
            duration,
        );
    }

    async fn publish(&self, blob: &PreparedBlob) -> Result<(), WorkflowAdmissionError> {
        self.blobs
            .put_if_absent(blob.payload.clone())
            .await
            .map(|_| ())
            .map_err(WorkflowAdmissionError::Blob)
    }
}

impl std::fmt::Debug for WorkflowAdmissionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkflowAdmissionService")
            .field("blobs", &self.blobs)
            .field("repository", &self.repository)
            .field("verifier", &self.verifier)
            .field("ids", &self.ids)
            .field("clock", &self.clock)
            .field("observer", &self.observer)
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_command(
    request: &WorkflowAdmissionRequest,
    ids: &dyn AdmissionIdGenerator,
    admitted_at: automata_ci_core::UnixMillis,
    repository_id: automata_ci_store::RepositoryId,
    workflow_id: automata_ci_core::WorkflowId,
    snapshot_id: automata_ci_store::WorkflowSnapshotId,
    idempotency: WorkflowAdmissionIdempotency,
    run_id: automata_ci_core::RunId,
    request_digest: Sha256Digest,
    source: &PreparedBlob,
    event: &PreparedBlob,
    plan: &PreparedBlob,
    base_context: &PreparedBlob,
    display_title: Option<&str>,
    concurrency: Option<WorkflowConcurrency>,
    reusable_workflows: Option<AdmittedReusableWorkflowExpansion>,
) -> Result<AdmitLogicalWorkflowRun, WorkflowAdmissionError> {
    let logical_job_ids = request
        .plan()
        .jobs()
        .iter()
        .map(|job| {
            let key = job.key().value().clone();
            let id = ids.logical_job_id(run_id, &key);
            (key, id)
        })
        .collect::<BTreeMap<WorkflowJobKey, LogicalWorkflowJobId>>();
    let jobs = request
        .plan()
        .jobs()
        .iter()
        .map(|job| {
            let key = job.key().value().clone();
            let id = *logical_job_ids
                .get(&key)
                .ok_or(WorkflowAdmissionError::Internal)?;
            let source_order =
                u16::try_from(job.source_order()).map_err(|_| WorkflowAdmissionError::Internal)?;
            let kind = match job.execution() {
                LogicalJobKind::Steps(_) => LogicalWorkflowJobKind::Steps,
                LogicalJobKind::ReusableWorkflow(_) => LogicalWorkflowJobKind::ReusableWorkflow,
            };
            let prerequisites = job
                .needs()
                .iter()
                .map(|dependency| {
                    logical_job_ids
                        .get(dependency.value())
                        .copied()
                        .ok_or(WorkflowAdmissionError::Internal)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let credential_requirements =
                crate::credential_requirements::discover_external_job_credentials(
                    request.plan().logical(),
                    job,
                )?;
            AdmittedLogicalWorkflowJob::new(id, key, source_order, kind, prerequisites)
                .map(|job| job.with_credential_requirements(credential_requirements))
                .map_err(WorkflowAdmissionError::LogicalValue)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let repository = AdmissionRepository::new(
        repository_id,
        request.repository().provider(),
        request.repository().provider_repository_id(),
        request.repository().path(),
    )?;
    let mut command = AdmitLogicalWorkflowRun::builder(
        request.tenant().clone(),
        idempotency,
        request_digest,
        repository,
        workflow_id,
        request.workflow_path(),
        request.workflow_name(),
        request.git_ref(),
        snapshot_id,
        source.metadata.clone(),
        plan.metadata.clone(),
        run_id,
        request.run_attempt().unwrap_or(1),
        ids.logical_invocation_id(run_id),
        request.plan().event().name(),
        event.metadata.clone(),
        request.commit_sha(),
        jobs,
        admitted_at,
    )
    .base_context(base_context.metadata.clone())
    .trust_snapshot(request.trust_snapshot().clone())
    .concurrency(concurrency)
    .reusable_workflows(reusable_workflows);
    if let Some(actor) = request.actor() {
        command = command.actor(actor);
    }
    if let Some(display_title) = display_title {
        command = command.display_title(display_title);
    }
    if let Some(commit_subject) = request.commit_subject() {
        command = command.commit_subject(commit_subject);
    }
    command
        .build()
        .map_err(WorkflowAdmissionError::LogicalValue)
}

#[derive(Clone, Debug)]
struct PreparedBlob {
    payload: BlobPayload,
    metadata: AdmissionObject,
}

struct PreparedReusableWorkflowExpansion {
    blobs: Vec<PreparedBlob>,
    graph: AdmittedReusableWorkflowExpansion,
}

#[allow(clippy::too_many_lines)] // Keeps graph and immutable evidence construction auditable together.
fn prepare_reusable_workflow_expansion(
    request: &WorkflowAdmissionRequest,
    ids: &dyn AdmissionIdGenerator,
    run_id: automata_ci_core::RunId,
    root_source: &PreparedBlob,
    root_plan: &PreparedBlob,
) -> Result<Option<PreparedReusableWorkflowExpansion>, WorkflowAdmissionError> {
    if !request
        .plan()
        .jobs()
        .iter()
        .any(|job| matches!(job.execution(), LogicalJobKind::ReusableWorkflow(_)))
    {
        return Ok(None);
    }
    let catalog = GithubReusableWorkflowCatalog::compile_reachable(
        request.repository().path(),
        request.commit_sha(),
        request.plan(),
        request.repository_workflow_sources().iter().cloned(),
    )?;
    let root_permissions = ReusableWorkflowPermissions::new(PermissionLevel::Write, [])?;
    let root_secret_names = request
        .base_context()
        .secrets()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let root_invocation_id = ids.logical_invocation_id(run_id);
    let expansion = ReusableWorkflowExpander::new().expand(ExpandReusableWorkflowRequest::new(
        run_id,
        root_invocation_id,
        request.workflow_path(),
        request.source(),
        request.plan(),
        &catalog,
        &root_secret_names,
        &root_permissions,
    ))?;
    let repository_id = ids.repository_id(request.tenant(), request.repository());
    let mut blobs = Vec::new();
    let mut catalog_objects = BTreeMap::new();
    let root_catalog_id = ids.snapshot_id(
        ids.workflow_id(repository_id, request.workflow_path()),
        root_source.metadata.digest(),
    );
    catalog_objects.insert(
        request.workflow_path().to_owned(),
        (
            root_catalog_id,
            root_source.metadata.clone(),
            root_plan.metadata.clone(),
        ),
    );
    for entry in catalog.entries() {
        let source = prepare_blob(
            "reusable-workflow-source",
            GITHUB_WORKFLOW_MEDIA_TYPE,
            entry.source().clone(),
        )?;
        let plan = prepare_blob(
            "reusable-workflow-plan",
            WORKFLOW_PLAN_MEDIA_TYPE,
            Bytes::from(
                serde_json::to_vec(entry.plan())
                    .map_err(|_| WorkflowAdmissionError::Serialization)?,
            ),
        )?;
        if source.metadata.digest() != entry.source_digest()
            || plan.metadata.digest() != entry.plan_digest()
        {
            return Err(WorkflowAdmissionError::Internal);
        }
        let catalog_id = ids.snapshot_id(
            ids.workflow_id(repository_id, entry.path()),
            entry.source_digest(),
        );
        catalog_objects.insert(
            entry.path().to_owned(),
            (catalog_id, source.metadata.clone(), plan.metadata.clone()),
        );
        blobs.push(source);
        blobs.push(plan);
    }

    let mut admitted_catalog = Vec::with_capacity(catalog_objects.len());
    for (path, (id, source, plan)) in &catalog_objects {
        let workflow_plan = workflow_plan_for_path(request, &catalog, path)
            .ok_or(WorkflowAdmissionError::Internal)?;
        let contract_digest = workflow_plan
            .logical()
            .invocation()
            .map(digest_json)
            .transpose()?;
        let logical_job_count = u16::try_from(workflow_plan.jobs().len())
            .map_err(|_| WorkflowAdmissionError::Internal)?;
        let reusable_call_count = u16::try_from(
            workflow_plan
                .jobs()
                .iter()
                .filter(|job| matches!(job.execution(), LogicalJobKind::ReusableWorkflow(_)))
                .count(),
        )
        .map_err(|_| WorkflowAdmissionError::Internal)?;
        let descriptor_digest = catalog_descriptor_digest(
            path,
            request.commit_sha(),
            source.digest(),
            plan.digest(),
            contract_digest,
            logical_job_count,
            reusable_call_count,
        );
        admitted_catalog.push(AdmittedReusableWorkflowCatalogEntry::new(
            *id,
            path,
            request.commit_sha(),
            source.clone(),
            plan.clone(),
            contract_digest,
            descriptor_digest,
            logical_job_count,
            reusable_call_count,
        ));
    }

    let mut invocation_paths = BTreeMap::new();
    let mut admitted_invocations = Vec::with_capacity(expansion.invocations().len());
    for invocation in expansion.invocations() {
        let (catalog_entry_id, _, _) = catalog_objects
            .get(invocation.workflow_path())
            .ok_or(WorkflowAdmissionError::Internal)?;
        let mut call_path = if let Some(parent_id) = invocation.parent_id() {
            invocation_paths
                .get(&parent_id.as_uuid())
                .cloned()
                .ok_or(WorkflowAdmissionError::Internal)?
        } else {
            Vec::new()
        };
        call_path.push(invocation.workflow_path().to_owned());
        invocation_paths.insert(invocation.id().as_uuid(), call_path.clone());
        let call_reference_digest = invocation
            .parent_id()
            .zip(invocation.caller_job_id())
            .map(|(parent_id, caller_job_id)| {
                reusable_call_reference(
                    request,
                    &catalog,
                    expansion.invocations(),
                    parent_id,
                    caller_job_id,
                )
                .map(call_reference_digest)
            })
            .transpose()?;
        let inputs = invocation
            .inputs()
            .iter()
            .map(|input| {
                let (kind, value_digest) = match input.source() {
                    ReusableInputBindingSource::Caller(value) => {
                        (AdmittedReusableInputKind::Caller, Some(digest_json(value)?))
                    }
                    ReusableInputBindingSource::Default(value) => (
                        AdmittedReusableInputKind::Default,
                        Some(digest_json(value)?),
                    ),
                    ReusableInputBindingSource::ImplicitDefault => {
                        (AdmittedReusableInputKind::ImplicitDefault, None)
                    }
                };
                Ok(AdmittedReusableInput::new(
                    input.target(),
                    input.input_type(),
                    kind,
                    value_digest,
                ))
            })
            .collect::<Result<Vec<_>, WorkflowAdmissionError>>()?;
        let secrets = invocation
            .secrets()
            .iter()
            .map(|secret| AdmittedReusableSecret::new(secret.target(), secret.source()))
            .collect::<Vec<_>>();
        let outputs = invocation
            .outputs()
            .iter()
            .map(|output| AdmittedReusableOutput::new(output.key(), output.sensitivity()))
            .collect::<Vec<_>>();
        let permission_digest = permissions_digest(invocation.permissions());
        let permissions = AdmittedReusablePermissions::new(
            invocation.permissions().default_level(),
            invocation
                .permissions()
                .grants()
                .iter()
                .map(|(name, level)| (name.clone(), *level))
                .collect(),
            permission_digest,
        );
        let invocation_plan = workflow_plan_for_path(request, &catalog, invocation.workflow_path())
            .ok_or(WorkflowAdmissionError::Internal)?;
        let jobs = invocation
            .jobs()
            .iter()
            .map(|job| {
                let logical_job = invocation_plan
                    .jobs()
                    .iter()
                    .find(|candidate| candidate.key().value() == job.key())
                    .ok_or(WorkflowAdmissionError::Internal)?;
                let credential_requirements =
                    crate::credential_requirements::discover_external_job_credentials(
                        invocation_plan.logical(),
                        logical_job,
                    )?;
                Ok(AdmittedReusableJob::new(
                    job.id(),
                    job.key().clone(),
                    job.source_order(),
                    job.is_reusable(),
                    reusable_job_descriptor_digest(invocation.id(), job, &credential_requirements),
                    job.prerequisites().to_vec(),
                )
                .with_credential_requirements(credential_requirements))
            })
            .collect::<Result<Vec<_>, WorkflowAdmissionError>>()?;
        let input_bindings_digest = admitted_inputs_digest(&inputs);
        let secret_bindings_digest = admitted_secrets_digest(&secrets);
        let output_contract_digest = admitted_outputs_digest(&outputs);
        let descriptor_digest = invocation_descriptor_digest(
            invocation.id(),
            invocation.parent_id(),
            invocation.caller_job_id(),
            *catalog_entry_id,
            invocation.depth(),
            &call_path,
            invocation.source_digest(),
            invocation.plan_digest(),
            call_reference_digest,
            input_bindings_digest,
            secret_bindings_digest,
            output_contract_digest,
            permission_digest,
            &jobs,
        );
        admitted_invocations.push(AdmittedReusableInvocation::new(
            invocation.id(),
            invocation.parent_id(),
            invocation.caller_job_id(),
            *catalog_entry_id,
            invocation.depth(),
            call_path,
            invocation.workflow_path(),
            invocation.source_digest(),
            invocation.plan_digest(),
            call_reference_digest,
            input_bindings_digest,
            secret_bindings_digest,
            output_contract_digest,
            descriptor_digest,
            inputs,
            secrets,
            outputs,
            permissions,
            jobs,
        ));
    }
    Ok(Some(PreparedReusableWorkflowExpansion {
        blobs,
        graph: AdmittedReusableWorkflowExpansion::new(
            expansion.digest(),
            admitted_catalog,
            admitted_invocations,
        ),
    }))
}

fn workflow_plan_for_path<'a>(
    request: &'a WorkflowAdmissionRequest,
    catalog: &'a GithubReusableWorkflowCatalog,
    path: &str,
) -> Option<&'a automata_ci_core::WorkflowPlan> {
    if path == request.workflow_path() {
        Some(request.plan())
    } else {
        catalog
            .entries()
            .find(|entry| entry.path() == path)
            .map(crate::CatalogedReusableWorkflow::plan)
    }
}

fn reusable_call_reference<'a>(
    request: &'a WorkflowAdmissionRequest,
    catalog: &'a GithubReusableWorkflowCatalog,
    invocations: &[crate::ReusableWorkflowInvocationExpansion],
    parent_id: automata_ci_store::LogicalWorkflowInvocationId,
    caller_job_id: LogicalWorkflowJobId,
) -> Result<&'a str, WorkflowAdmissionError> {
    let parent = invocations
        .iter()
        .find(|invocation| invocation.id() == parent_id)
        .ok_or(WorkflowAdmissionError::Internal)?;
    let parent_job = parent
        .jobs()
        .iter()
        .find(|job| job.id() == caller_job_id)
        .ok_or(WorkflowAdmissionError::Internal)?;
    let plan = workflow_plan_for_path(request, catalog, parent.workflow_path())
        .ok_or(WorkflowAdmissionError::Internal)?;
    let job = plan
        .jobs()
        .iter()
        .find(|job| job.key().value() == parent_job.key())
        .ok_or(WorkflowAdmissionError::Internal)?;
    let LogicalJobKind::ReusableWorkflow(call) = job.execution() else {
        return Err(WorkflowAdmissionError::Internal);
    };
    Ok(call.reference().value())
}

fn digest_json(value: &impl serde::Serialize) -> Result<Sha256Digest, WorkflowAdmissionError> {
    serde_json::to_vec(value)
        .map(|bytes| Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
        .map_err(|_| WorkflowAdmissionError::Serialization)
}

fn descriptor_digest(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        digest_field(&mut hasher, part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn catalog_descriptor_digest(
    path: &str,
    revision: automata_ci_core::GitObjectId,
    source: Sha256Digest,
    plan: Sha256Digest,
    contract: Option<Sha256Digest>,
    jobs: u16,
    calls: u16,
) -> Sha256Digest {
    let contract = contract.map_or([0; 32], Sha256Digest::into_bytes);
    descriptor_digest(
        b"automata.reusable-workflow.catalog.v1\0",
        &[
            path.as_bytes(),
            revision.as_bytes(),
            source.as_bytes(),
            plan.as_bytes(),
            &contract,
            &jobs.to_be_bytes(),
            &calls.to_be_bytes(),
        ],
    )
}

fn call_reference_digest(reference: &str) -> Sha256Digest {
    descriptor_digest(
        b"automata.reusable-workflow.call-reference.v1\0",
        &[reference.as_bytes()],
    )
}

fn permissions_digest(permissions: &ReusableWorkflowPermissions) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.reusable-workflow.permissions.v1\0");
    hash_permission(&mut hasher, permissions.default_level());
    digest_field(
        &mut hasher,
        &u64::try_from(permissions.grants().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (name, level) in permissions.grants() {
        digest_field(&mut hasher, name.as_bytes());
        hash_permission(&mut hasher, *level);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_permission(hasher: &mut Sha256, level: PermissionLevel) {
    digest_field(
        hasher,
        match level {
            PermissionLevel::None => b"none",
            PermissionLevel::Read => b"read",
            PermissionLevel::Write => b"write",
        },
    );
}

fn admitted_inputs_digest(inputs: &[AdmittedReusableInput]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.reusable-workflow.inputs.v1\0");
    for input in inputs {
        digest_field(&mut hasher, input.key().as_bytes());
        digest_field(&mut hasher, format!("{:?}", input.input_type()).as_bytes());
        digest_field(&mut hasher, input.kind().as_str().as_bytes());
        match input.value_digest() {
            Some(digest) => digest_field(&mut hasher, digest.as_bytes()),
            None => digest_field(&mut hasher, &[]),
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn admitted_secrets_digest(secrets: &[AdmittedReusableSecret]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.reusable-workflow.secrets.v1\0");
    for secret in secrets {
        digest_field(&mut hasher, secret.target().as_bytes());
        digest_field(&mut hasher, secret.source().as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn admitted_outputs_digest(outputs: &[AdmittedReusableOutput]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.reusable-workflow.outputs.v1\0");
    for output in outputs {
        digest_field(&mut hasher, output.key().as_bytes());
        digest_field(
            &mut hasher,
            match output.sensitivity() {
                OutputSensitivity::Public => b"public",
                OutputSensitivity::SecretDerived => b"secret_derived",
            },
        );
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn reusable_job_descriptor_digest(
    invocation_id: automata_ci_store::LogicalWorkflowInvocationId,
    job: &crate::ExpandedReusableJob,
    credential_requirements: &JobCredentialRequirements,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.reusable-workflow.job-descriptor.v2\0");
    for part in [
        invocation_id.as_uuid().as_bytes().as_slice(),
        job.id().as_uuid().as_bytes().as_slice(),
        job.key().as_str().as_bytes(),
        &job.source_order().to_be_bytes(),
        &[u8::from(job.is_reusable())],
    ] {
        digest_field(&mut hasher, part);
    }
    for prerequisite in job.prerequisites() {
        digest_field(&mut hasher, prerequisite.as_uuid().as_bytes());
    }
    match credential_requirements.environment() {
        JobEnvironmentRequirement::None => digest_field(&mut hasher, b"environment:none"),
        JobEnvironmentRequirement::Environment(digest) => {
            digest_field(&mut hasher, b"environment:template");
            digest_field(&mut hasher, digest.as_bytes());
        }
    }
    digest_field(&mut hasher, b"secrets");
    for name in credential_requirements.secret_names() {
        digest_field(&mut hasher, name.as_bytes());
    }
    digest_field(&mut hasher, b"variables");
    for name in credential_requirements.variable_names() {
        digest_field(&mut hasher, name.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn invocation_descriptor_digest(
    invocation_id: automata_ci_store::LogicalWorkflowInvocationId,
    parent_id: Option<automata_ci_store::LogicalWorkflowInvocationId>,
    caller_job_id: Option<LogicalWorkflowJobId>,
    catalog_id: automata_ci_store::WorkflowSnapshotId,
    depth: u16,
    call_path: &[String],
    source: Sha256Digest,
    plan: Sha256Digest,
    call_reference: Option<Sha256Digest>,
    inputs: Sha256Digest,
    secrets: Sha256Digest,
    outputs: Sha256Digest,
    permissions: Sha256Digest,
    jobs: &[AdmittedReusableJob],
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.reusable-workflow.invocation-descriptor.v1\0");
    digest_field(&mut hasher, invocation_id.as_uuid().as_bytes());
    for value in [
        parent_id.map(automata_ci_store::LogicalWorkflowInvocationId::as_uuid),
        caller_job_id.map(LogicalWorkflowJobId::as_uuid),
    ] {
        digest_field(
            &mut hasher,
            value
                .as_ref()
                .map_or(&[][..], |value| value.as_bytes().as_slice()),
        );
    }
    digest_field(&mut hasher, catalog_id.as_uuid().as_bytes());
    digest_field(&mut hasher, &depth.to_be_bytes());
    for path in call_path {
        digest_field(&mut hasher, path.as_bytes());
    }
    for digest in [source, plan, inputs, secrets, outputs, permissions] {
        digest_field(&mut hasher, digest.as_bytes());
    }
    match call_reference {
        Some(digest) => digest_field(&mut hasher, digest.as_bytes()),
        None => digest_field(&mut hasher, &[]),
    }
    for job in jobs {
        digest_field(&mut hasher, job.descriptor_digest().as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn prepare_blob(
    kind: &str,
    media_type: &str,
    bytes: Bytes,
) -> Result<PreparedBlob, WorkflowAdmissionError> {
    prepare_blob_with_limit(kind, media_type, bytes, AdmissionBlobLimit::Standard)
}

fn prepare_event_blob(
    kind: &str,
    media_type: &str,
    bytes: Bytes,
) -> Result<PreparedBlob, WorkflowAdmissionError> {
    prepare_blob_with_limit(kind, media_type, bytes, AdmissionBlobLimit::ProviderEvent)
}

#[derive(Clone, Copy)]
enum AdmissionBlobLimit {
    Standard,
    ProviderEvent,
}

fn prepare_blob_with_limit(
    kind: &str,
    media_type: &str,
    bytes: Bytes,
    limit: AdmissionBlobLimit,
) -> Result<PreparedBlob, WorkflowAdmissionError> {
    let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    let key_text = format!("admission/v2/{kind}/sha256/{digest}");
    let blob_key = BlobKey::new(key_text.clone()).map_err(|_| WorkflowAdmissionError::Internal)?;
    let media_type_value =
        MediaType::new(media_type).map_err(|_| WorkflowAdmissionError::Internal)?;
    let payload = BlobPayload::from_bytes(blob_key, media_type_value, bytes);
    let object_key = ObjectKey::new(key_text).map_err(|_| WorkflowAdmissionError::Internal)?;
    let metadata = match limit {
        AdmissionBlobLimit::Standard => {
            AdmissionObject::new(digest, object_key, payload.descriptor().size(), media_type)
        }
        AdmissionBlobLimit::ProviderEvent => {
            AdmissionObject::new_event(digest, object_key, payload.descriptor().size(), media_type)
        }
    }?;
    Ok(PreparedBlob { payload, metadata })
}

fn resolve_workflow_concurrency(
    request: &WorkflowAdmissionRequest,
) -> Result<Option<WorkflowConcurrency>, WorkflowAdmissionError> {
    let Some(template) = request.plan().logical().concurrency() else {
        return Ok(None);
    };
    if request.repository().provider() != "github" {
        return Err(WorkflowAdmissionError::ConcurrencyEvaluation);
    }
    let context = admission_expression_context(request)?;
    let evaluator = GithubExpressionEvaluator::default();
    let group = match template.group().value() {
        CompiledValueTemplate::Literal(group) => group.clone(),
        CompiledValueTemplate::Expression(expression) => {
            evaluate_admission_string(expression, &evaluator, &context)?
        }
    };
    let cancel_in_progress = match template
        .cancel_in_progress()
        .map(automata_ci_core::Located::value)
    {
        None => false,
        Some(CompiledBooleanTemplate::Literal(value)) => *value,
        Some(CompiledBooleanTemplate::Expression(expression)) => {
            evaluate_admission_boolean(expression, &evaluator, &context)?
        }
    };
    WorkflowConcurrency::new(group, cancel_in_progress)
        .and_then(|concurrency| concurrency.with_queue_policy(template.queue()))
        .map(Some)
        .map_err(WorkflowAdmissionError::AdmissionValue)
}

fn resolve_run_display_title(
    request: &WorkflowAdmissionRequest,
) -> Result<Option<String>, WorkflowAdmissionError> {
    let explicit = request.plan().logical().run_name().map(|run_name| {
        let rendered = match run_name.value() {
            CompiledValueTemplate::Literal(value) => Ok(value.clone()),
            CompiledValueTemplate::Expression(expression) => {
                if request.repository().provider() != "github" {
                    return Err(WorkflowAdmissionError::RunNameEvaluation);
                }
                let context = admission_expression_context(request)
                    .map_err(|_| WorkflowAdmissionError::RunNameEvaluation)?;
                evaluate_admission_string(
                    expression,
                    &GithubExpressionEvaluator::default(),
                    &context,
                )
                .map_err(|_| WorkflowAdmissionError::RunNameEvaluation)
            }
        }?;
        validate_run_display_title(rendered)
    });
    if let Some(title) = explicit
        .transpose()?
        .filter(|title| !title.trim().is_empty())
    {
        return Ok(Some(title));
    }
    request
        .display_title()
        .filter(|title| !title.trim().is_empty())
        .or_else(|| {
            request
                .commit_subject()
                .filter(|subject| !subject.trim().is_empty())
        })
        .map(|title| validate_run_display_title(title.to_owned()))
        .transpose()
}

fn validate_run_display_title(title: String) -> Result<String, WorkflowAdmissionError> {
    if title.len() > MAX_RUN_DISPLAY_TITLE_BYTES || title.chars().any(char::is_control) {
        return Err(WorkflowAdmissionError::RunNameEvaluation);
    }
    Ok(title)
}

fn admission_expression_context(
    request: &WorkflowAdmissionRequest,
) -> Result<MapContext, WorkflowAdmissionError> {
    let event: serde_json::Value = serde_json::from_slice(request.event())
        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)?;
    let PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = request.plan().source().origin()
    else {
        return Err(WorkflowAdmissionError::ConcurrencyEvaluation);
    };
    let (ref_name, ref_type) = github_ref_parts(request.git_ref());
    let mut github = vec![
        ("event".to_owned(), json_to_github_value(event)?),
        (
            "event_name".to_owned(),
            GithubValue::string(request.plan().event().name()),
        ),
        ("ref".to_owned(), GithubValue::string(request.git_ref())),
        ("ref_name".to_owned(), GithubValue::string(ref_name)),
        ("ref_type".to_owned(), GithubValue::string(ref_type)),
        (
            "repository".to_owned(),
            GithubValue::string(repository.as_str()),
        ),
        (
            "repository_id".to_owned(),
            GithubValue::string(request.repository().provider_repository_id()),
        ),
        (
            "repository_owner".to_owned(),
            GithubValue::string(request.repository().namespace()),
        ),
        (
            "run_attempt".to_owned(),
            GithubValue::number(f64::from(request.run_attempt().unwrap_or(1))),
        ),
        ("sha".to_owned(), GithubValue::string(revision.to_string())),
        (
            "workflow".to_owned(),
            GithubValue::string(request.workflow_name()),
        ),
        (
            "workflow_ref".to_owned(),
            GithubValue::string(format!("{repository}/{}@{}", path, request.git_ref())),
        ),
        (
            "workflow_sha".to_owned(),
            GithubValue::string(revision.to_string()),
        ),
    ];
    if let Some(actor) = request.actor() {
        github.push(("actor".to_owned(), GithubValue::string(actor)));
        github.push(("triggering_actor".to_owned(), GithubValue::string(actor)));
    }
    let github = GithubObject::new(github)
        .map(GithubValue::object)
        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)?;
    let named = BTreeMap::from([
        ("github".to_owned(), github),
        (
            "inputs".to_owned(),
            context_to_github_value(request.base_context().inputs())
                .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)?,
        ),
        (
            "vars".to_owned(),
            context_to_github_value(request.base_context().vars())
                .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)?,
        ),
    ]);
    MapContext::without_extensions(named, GithubStatus::Success)
        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)
}

fn github_ref_parts(git_ref: &str) -> (&str, &str) {
    if let Some(name) = git_ref.strip_prefix("refs/heads/") {
        (name, "branch")
    } else if let Some(name) = git_ref.strip_prefix("refs/tags/") {
        (name, "tag")
    } else {
        (git_ref.strip_prefix("refs/").unwrap_or(git_ref), "branch")
    }
}

fn json_to_github_value(value: serde_json::Value) -> Result<GithubValue, WorkflowAdmissionError> {
    match value {
        serde_json::Value::Null => Ok(GithubValue::Null),
        serde_json::Value::Bool(value) => Ok(GithubValue::Boolean(value)),
        serde_json::Value::Number(value) => value
            .as_f64()
            .map(GithubValue::number)
            .ok_or(WorkflowAdmissionError::ConcurrencyEvaluation),
        serde_json::Value::String(value) => Ok(GithubValue::string(value)),
        serde_json::Value::Array(values) => GithubValue::array(
            values
                .into_iter()
                .map(json_to_github_value)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation),
        serde_json::Value::Object(values) => GithubObject::new(
            values
                .into_iter()
                .map(|(key, value)| json_to_github_value(value).map(|value| (key, value)))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map(GithubValue::object)
        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation),
    }
}

fn evaluate_admission_string(
    expression: &CompiledExpressionTemplate,
    evaluator: &GithubExpressionEvaluator,
    context: &MapContext,
) -> Result<String, WorkflowAdmissionError> {
    validate_admission_expression(expression)?;
    let mut programs = expression.programs().iter();
    let mut rendered = String::new();
    for segment in expression.expression().segments() {
        match segment {
            ExpressionSegment::Literal(value) => rendered.push_str(value),
            ExpressionSegment::Evaluation(_) => {
                let program = programs
                    .next()
                    .ok_or(WorkflowAdmissionError::ConcurrencyEvaluation)?;
                rendered.push_str(
                    &evaluator
                        .evaluate(program, context)
                        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)?
                        .coerce_to_string(),
                );
            }
        }
        if rendered.len() > MAX_LOGICAL_FIELD_BYTES {
            return Err(WorkflowAdmissionError::ConcurrencyEvaluation);
        }
    }
    if programs.next().is_some() {
        return Err(WorkflowAdmissionError::ConcurrencyEvaluation);
    }
    Ok(rendered)
}

fn evaluate_admission_boolean(
    expression: &CompiledExpressionTemplate,
    evaluator: &GithubExpressionEvaluator,
    context: &MapContext,
) -> Result<bool, WorkflowAdmissionError> {
    validate_admission_expression(expression)?;
    let [program] = expression.programs() else {
        return Err(WorkflowAdmissionError::ConcurrencyEvaluation);
    };
    evaluator
        .evaluate(program, context)
        .map_err(|_| WorkflowAdmissionError::ConcurrencyEvaluation)?
        .as_bool()
        .ok_or(WorkflowAdmissionError::ConcurrencyEvaluation)
}

fn validate_admission_expression(
    expression: &CompiledExpressionTemplate,
) -> Result<(), WorkflowAdmissionError> {
    if expression.programs().iter().any(|program| {
        program.instructions().iter().any(|instruction| {
            matches!(
                instruction,
                ExpressionInstruction::Call { name, .. }
                    if name.eq_ignore_ascii_case("hashfiles")
                        || ["always", "success", "failure", "cancelled"]
                            .iter()
                            .any(|candidate| name.eq_ignore_ascii_case(candidate))
            )
        }) || program_uses_unavailable_admission_context(program.instructions())
    }) {
        return Err(WorkflowAdmissionError::ConcurrencyEvaluation);
    }
    Ok(())
}

#[derive(Clone)]
enum AdmissionTraceKind {
    GithubRoot,
    LiteralString(String),
    Other,
}

#[derive(Clone)]
struct AdmissionTrace {
    kind: AdmissionTraceKind,
    late_bound: bool,
}

fn program_uses_unavailable_admission_context(instructions: &[ExpressionInstruction]) -> bool {
    let mut stack: Vec<AdmissionTrace> = Vec::with_capacity(instructions.len());
    for instruction in instructions {
        let trace = match instruction {
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String { value },
            } => AdmissionTrace {
                kind: AdmissionTraceKind::LiteralString(value.clone()),
                late_bound: false,
            },
            ExpressionInstruction::Literal { .. } | ExpressionInstruction::Wildcard => {
                AdmissionTrace {
                    kind: AdmissionTraceKind::Other,
                    late_bound: false,
                }
            }
            ExpressionInstruction::NamedValue { name } => AdmissionTrace {
                kind: if name.eq_ignore_ascii_case("github") {
                    AdmissionTraceKind::GithubRoot
                } else {
                    AdmissionTraceKind::Other
                },
                late_bound: false,
            },
            ExpressionInstruction::Index => {
                let Some(index) = stack.pop() else {
                    return true;
                };
                let Some(target) = stack.pop() else {
                    return true;
                };
                let mut late_bound = target.late_bound || index.late_bound;
                if matches!(target.kind, AdmissionTraceKind::GithubRoot) {
                    late_bound |= match index.kind {
                        AdmissionTraceKind::LiteralString(property) => !ADMISSION_GITHUB_PROPERTIES
                            .iter()
                            .any(|candidate| property.eq_ignore_ascii_case(candidate)),
                        AdmissionTraceKind::GithubRoot | AdmissionTraceKind::Other => true,
                    };
                }
                AdmissionTrace {
                    kind: AdmissionTraceKind::Other,
                    late_bound,
                }
            }
            ExpressionInstruction::Not => combine_traces(&mut stack, 1),
            ExpressionInstruction::Compare { .. } => combine_traces(&mut stack, 2),
            ExpressionInstruction::Logical { operand_count, .. } => {
                combine_traces(&mut stack, usize::from(*operand_count))
            }
            ExpressionInstruction::Call { argument_count, .. } => {
                combine_traces(&mut stack, usize::from(*argument_count))
            }
        };
        stack.push(trace);
    }
    let [trace] = stack.as_slice() else {
        return true;
    };
    trace.late_bound || matches!(trace.kind, AdmissionTraceKind::GithubRoot)
}

fn combine_traces(stack: &mut Vec<AdmissionTrace>, count: usize) -> AdmissionTrace {
    if stack.len() < count {
        return AdmissionTrace {
            kind: AdmissionTraceKind::Other,
            late_bound: true,
        };
    }
    let mut late_bound = false;
    for _ in 0..count {
        let trace = stack.pop().expect("trace count was checked");
        late_bound |= trace.late_bound || matches!(trace.kind, AdmissionTraceKind::GithubRoot);
    }
    AdmissionTrace {
        kind: AdmissionTraceKind::Other,
        late_bound,
    }
}

fn namespace_idempotency(
    request: &WorkflowAdmissionRequest,
) -> Result<WorkflowAdmissionIdempotency, WorkflowAdmissionError> {
    match request.idempotency() {
        WorkflowAdmissionIdempotency::ProviderDelivery(delivery) => {
            WorkflowAdmissionIdempotency::namespaced_provider_delivery(
                request.repository().provider(),
                request.repository().provider_repository_id(),
                delivery,
                request.workflow_path(),
            )
            .map_err(WorkflowAdmissionError::AdmissionValue)
        }
        WorkflowAdmissionIdempotency::Operation(operation_id) => {
            Ok(WorkflowAdmissionIdempotency::operation(*operation_id))
        }
    }
}

#[allow(clippy::too_many_arguments)] // Every immutable descriptor and authority mode is domain-bound explicitly.
fn canonical_request_digest(
    request: &WorkflowAdmissionRequest,
    delivery_id: Option<ProviderDeliveryId>,
    schedule_fire_id: Option<automata_ci_store::GithubScheduleFireId>,
    dispatch_claim: Option<&AuthenticatedWorkflowDispatchClaim>,
    source: &PreparedBlob,
    event: &PreparedBlob,
    plan: &PreparedBlob,
    base_context: &PreparedBlob,
    resolved_display_title: Option<&str>,
    concurrency: Option<&WorkflowConcurrency>,
    reusable_workflows: Option<&AdmittedReusableWorkflowExpansion>,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(if schedule_fire_id.is_some() {
        SCHEDULED_GITHUB_REQUEST_DIGEST_DOMAIN_V9
    } else if dispatch_claim.is_some() {
        AUTHENTICATED_WORKFLOW_DISPATCH_REQUEST_DIGEST_DOMAIN_V9
    } else if delivery_id.is_some() {
        AUTHENTICATED_PROVIDER_REQUEST_DIGEST_DOMAIN_V10
    } else {
        REQUEST_DIGEST_DOMAIN_V9
    });
    for value in [
        request.tenant().as_str(),
        request.repository().provider(),
        request.repository().provider_repository_id(),
        request.repository().path(),
        request.workflow_path(),
        request.git_ref(),
        request.workflow_name(),
        request.plan().event().name(),
    ] {
        digest_field(&mut digest, value.as_bytes());
    }
    digest_field(&mut digest, request.commit_sha().as_bytes());
    digest_optional_field(&mut digest, request.actor());
    digest_optional_field(&mut digest, request.display_title());
    digest_optional_field(&mut digest, request.commit_subject());
    digest_optional_field(&mut digest, resolved_display_title);
    digest_field(
        &mut digest,
        &request.run_attempt().unwrap_or(1).to_be_bytes(),
    );
    digest_field(&mut digest, request.trust_snapshot().digest().as_bytes());
    for blob in [source, event, plan, base_context] {
        digest_field(&mut digest, blob.metadata.digest().as_bytes());
        digest_field(&mut digest, &blob.metadata.encoded_size().to_be_bytes());
        digest_field(&mut digest, blob.metadata.media_type().as_bytes());
    }
    match concurrency {
        Some(concurrency) => {
            digest.update([1]);
            digest_field(&mut digest, concurrency.display_key().as_bytes());
            digest_field(&mut digest, concurrency.normalized_key().as_bytes());
            digest.update([u8::from(concurrency.cancel_in_progress())]);
            digest.update([match concurrency.queue_policy() {
                automata_ci_core::QueuePolicy::Single => 1,
                automata_ci_core::QueuePolicy::Max => 2,
            }]);
        }
        None => digest.update([0]),
    }
    if let Some(expansion) = reusable_workflows {
        digest.update([1]);
        digest_field(&mut digest, expansion.digest().as_bytes());
    }
    if let Some(delivery_id) = delivery_id {
        digest_field(&mut digest, delivery_id.as_uuid().as_bytes());
    }
    if let Some(fire_id) = schedule_fire_id {
        digest_field(&mut digest, fire_id.as_uuid().as_bytes());
    }
    if let Some(claim) = dispatch_claim {
        let actor = claim.actor();
        let session_id = actor.correlation_session_id();
        for value in [
            actor.tenant_id().as_str(),
            actor.principal_id().as_str(),
            session_id.as_str(),
            claim.workflow_path(),
            claim.git_ref(),
        ] {
            digest_field(&mut digest, value.as_bytes());
        }
        digest_field(&mut digest, &actor.authorization_revision().to_be_bytes());
        digest_field(&mut digest, claim.repository_id().as_uuid().as_bytes());
        digest_field(&mut digest, claim.workflow_id().as_uuid().as_bytes());
        digest_field(&mut digest, claim.operation_id().as_uuid().as_bytes());
        digest_field(&mut digest, claim.event_digest().as_bytes());
        digest_field(&mut digest, claim.base_context_digest().as_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn digest_optional_field(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest_field(digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

/// Application-level workflow admission failure.
#[derive(Debug, Error)]
pub enum WorkflowAdmissionError {
    /// Exact-source recompilation or plan comparison failed.
    #[error(transparent)]
    Verification(#[from] WorkflowPlanVerificationError),
    /// Repository-local reusable workflow planning failed closed.
    #[error(transparent)]
    ReusableExpansion(#[from] ReusableWorkflowExpansionError),
    /// Immutable evidence could not be published or verified.
    #[error("immutable blob publication failed")]
    Blob(#[source] BlobStoreError),
    /// The durable logical-admission repository rejected or failed the command.
    #[error(transparent)]
    Store(#[from] LogicalWorkflowAdmissionStoreError),
    /// Provider-neutral admission metadata failed value validation.
    #[error(transparent)]
    AdmissionValue(#[from] WorkflowAdmissionValueError),
    /// Logical workflow graph or receipt metadata failed value validation.
    #[error(transparent)]
    LogicalValue(#[from] LogicalWorkflowAdmissionValueError),
    /// Credential contexts used a dynamic or malformed name.
    #[error(transparent)]
    CredentialDiscovery(#[from] CredentialDiscoveryError),
    /// Canonical serialization of the validated workflow plan failed.
    #[error("workflow plan serialization failed")]
    Serialization,
    /// Workflow-level concurrency could not be resolved from admission-safe context.
    #[error("workflow concurrency could not be resolved at admission")]
    ConcurrencyEvaluation,
    /// Workflow `run-name` could not be resolved into a bounded durable title.
    #[error("workflow run-name could not be resolved at admission")]
    RunNameEvaluation,
    /// Canonical manual-dispatch evidence did not match the authenticated target.
    #[error("authenticated workflow dispatch evidence did not match admission")]
    WorkflowDispatchEvidence,
    /// Common processing evidence was not a valid live trigger authority.
    #[error("authenticated provider admission authority is invalid")]
    ProviderAdmissionAuthority,
    /// A server-derived identity or invariant was internally inconsistent.
    #[error("internal workflow admission invariant failed")]
    Internal,
}

const fn observe_failure(error: &WorkflowAdmissionError) -> WorkflowAdmissionFailure {
    match error {
        WorkflowAdmissionError::Verification(_) | WorkflowAdmissionError::ReusableExpansion(_) => {
            WorkflowAdmissionFailure::Materialization
        }
        WorkflowAdmissionError::Blob(_) => WorkflowAdmissionFailure::BlobStore,
        WorkflowAdmissionError::Store(_) => WorkflowAdmissionFailure::DurableStore,
        WorkflowAdmissionError::AdmissionValue(_)
        | WorkflowAdmissionError::LogicalValue(_)
        | WorkflowAdmissionError::CredentialDiscovery(_)
        | WorkflowAdmissionError::Serialization
        | WorkflowAdmissionError::ConcurrencyEvaluation
        | WorkflowAdmissionError::RunNameEvaluation
        | WorkflowAdmissionError::WorkflowDispatchEvidence
        | WorkflowAdmissionError::ProviderAdmissionAuthority
        | WorkflowAdmissionError::Internal => WorkflowAdmissionFailure::InvalidState,
    }
}
