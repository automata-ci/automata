use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use automata_ci_blob::{BlobKey, BlobPayload, BlobStoreError, ImmutableBlobStore, MediaType};
use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledValueTemplate,
    ExpressionInstruction, ExpressionLiteral, ExpressionSegment, LogicalJobKind,
    MAX_LOGICAL_FIELD_BYTES, PlanSourceOrigin, Sha256Digest, WorkflowJobKey,
};
use automata_ci_expression_github::{
    GithubExpressionEvaluator, GithubObject, GithubStatus, GithubValue, MapContext,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, LogicalWorkflowAdmissionRepository,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowAdmissionValueError, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, ProviderDeliveryId, WorkflowAdmissionIdempotency,
    WorkflowAdmissionValueError, WorkflowConcurrency,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    AdmissionClock, AdmissionIdGenerator, GITHUB_WORKFLOW_MEDIA_TYPE,
    JOB_RUNTIME_CONTEXT_MEDIA_TYPE, NoopWorkflowAdmissionObserver, Sha256AdmissionIdGenerator,
    SystemAdmissionClock, WORKFLOW_EVENT_MEDIA_TYPE, WORKFLOW_PLAN_MEDIA_TYPE,
    WorkflowAdmissionFailure, WorkflowAdmissionObservation, WorkflowAdmissionObserver,
    WorkflowAdmissionRequest, WorkflowAdmissionResult, WorkflowAdmissionStage,
    WorkflowAdmissionStageOutcome, WorkflowPlanVerificationError, WorkflowPlanVerifier,
    github_activation::context_to_github_value,
};

const REQUEST_DIGEST_DOMAIN_V4: &[u8] = b"automata.workflow-admission.request.v4\0";
const AUTHENTICATED_GITHUB_REQUEST_DIGEST_DOMAIN_V5: &[u8] =
    b"automata.workflow-admission.request.v5\0";
const PROVIDER_DELIVERY_NAMESPACE_DOMAIN: &[u8] =
    b"automata.workflow-admission.provider-delivery.v2\0";
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
    pub async fn admit(
        &self,
        request: WorkflowAdmissionRequest,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        self.admit_with_delivery(request, None).await
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
    pub async fn admit_authenticated_github_delivery(
        &self,
        request: WorkflowAdmissionRequest,
        current_claim: AuthenticatedGithubDeliveryClaim,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        self.admit_with_delivery(request, Some(current_claim)).await
    }

    async fn admit_with_delivery(
        &self,
        request: WorkflowAdmissionRequest,
        current_claim: Option<AuthenticatedGithubDeliveryClaim>,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        let started = Instant::now();
        let jobs = request.plan().jobs().len();
        let result = self.admit_inner(request, current_claim).await;
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
        current_claim: Option<AuthenticatedGithubDeliveryClaim>,
    ) -> Result<WorkflowAdmissionResult, WorkflowAdmissionError> {
        let delivery_id = current_claim.map(|claim| claim.claim().delivery_id());
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
        ) = self.observe_sync_stage(WorkflowAdmissionStage::Prepare, || {
            if delivery_id.is_some()
                && (request.repository().provider() != "github"
                    || !matches!(
                        request.idempotency(),
                        WorkflowAdmissionIdempotency::ProviderDelivery(_)
                    ))
            {
                return Err(WorkflowAdmissionError::Internal);
            }
            let source_blob = prepare_blob(
                "workflow-source",
                GITHUB_WORKFLOW_MEDIA_TYPE,
                request.source().clone(),
            )?;
            let event_blob = prepare_event_blob(
                "workflow-event",
                WORKFLOW_EVENT_MEDIA_TYPE,
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
            ))
        })?;

        self.observe_sync_stage(WorkflowAdmissionStage::Materialize, || {
            self.verifier.verify(&request)?;
            Ok(())
        })?;

        let command = self.observe_sync_stage(WorkflowAdmissionStage::Encode, || {
            let concurrency = resolve_workflow_concurrency(&request)?;
            let request_digest = canonical_request_digest(
                &request,
                delivery_id,
                &source_blob,
                &event_blob,
                &plan_blob,
                &base_context_blob,
                concurrency.as_ref(),
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
                concurrency,
            )
        })?;

        let publication_started = Instant::now();
        let publication = async {
            self.publish(&source_blob).await?;
            self.publish(&event_blob).await?;
            self.publish(&plan_blob).await?;
            self.publish(&base_context_blob).await?;
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
        let receipt = match current_claim {
            Some(current_claim) => {
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
                    command.concurrency().cloned(),
                )?;
                self.repository
                    .admit_authenticated_github_delivery(command, current_claim, observed_at)
                    .await
            }
            None => self.repository.admit_logical_workflow(command).await,
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
    concurrency: Option<WorkflowConcurrency>,
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
            AdmittedLogicalWorkflowJob::new(id, key, source_order, kind, prerequisites)
                .map_err(WorkflowAdmissionError::LogicalValue)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let repository = AdmissionRepository::new(
        repository_id,
        request.repository().provider(),
        request.repository().provider_repository_id(),
        request.repository().owner(),
        request.repository().name(),
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
        decode_hex(request.commit_sha())?,
        jobs,
        admitted_at,
    )
    .base_context(base_context.metadata.clone())
    .concurrency(concurrency);
    if let Some(actor) = request.actor() {
        command = command.actor(actor);
    }
    if let Some(display_title) = request.display_title() {
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
        .map(|concurrency| concurrency.with_queue_policy(template.queue()))
        .map(Some)
        .map_err(WorkflowAdmissionError::AdmissionValue)
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
            GithubValue::string(request.repository().owner()),
        ),
        (
            "run_attempt".to_owned(),
            GithubValue::number(f64::from(request.run_attempt().unwrap_or(1))),
        ),
        ("sha".to_owned(), GithubValue::string(revision.as_str())),
        (
            "workflow".to_owned(),
            GithubValue::string(request.workflow_name()),
        ),
        (
            "workflow_ref".to_owned(),
            GithubValue::string(format!("{repository}/{path}@{}", request.git_ref())),
        ),
        (
            "workflow_sha".to_owned(),
            GithubValue::string(revision.as_str()),
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
            let mut digest = Sha256::new();
            digest.update(PROVIDER_DELIVERY_NAMESPACE_DOMAIN);
            for field in [
                request.repository().provider(),
                request.repository().provider_repository_id(),
                delivery,
                request.workflow_path(),
            ] {
                digest_field(&mut digest, field.as_bytes());
            }
            let digest = Sha256Digest::from_bytes(digest.finalize().into());
            WorkflowAdmissionIdempotency::provider_delivery(format!(
                "provider-delivery-v2:{digest}"
            ))
            .map_err(WorkflowAdmissionError::AdmissionValue)
        }
        WorkflowAdmissionIdempotency::Operation(operation_id) => {
            Ok(WorkflowAdmissionIdempotency::operation(*operation_id))
        }
    }
}

fn canonical_request_digest(
    request: &WorkflowAdmissionRequest,
    delivery_id: Option<ProviderDeliveryId>,
    source: &PreparedBlob,
    event: &PreparedBlob,
    plan: &PreparedBlob,
    base_context: &PreparedBlob,
    concurrency: Option<&WorkflowConcurrency>,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(if delivery_id.is_some() {
        AUTHENTICATED_GITHUB_REQUEST_DIGEST_DOMAIN_V5
    } else {
        REQUEST_DIGEST_DOMAIN_V4
    });
    for value in [
        request.tenant().as_str(),
        request.repository().provider(),
        request.repository().provider_repository_id(),
        request.repository().owner(),
        request.repository().name(),
        request.workflow_path(),
        request.commit_sha(),
        request.git_ref(),
        request.workflow_name(),
        request.plan().event().name(),
    ] {
        digest_field(&mut digest, value.as_bytes());
    }
    digest_optional_field(&mut digest, request.actor());
    digest_optional_field(&mut digest, request.display_title());
    digest_optional_field(&mut digest, request.commit_subject());
    digest_field(
        &mut digest,
        &request.run_attempt().unwrap_or(1).to_be_bytes(),
    );
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
    if let Some(delivery_id) = delivery_id {
        digest_field(&mut digest, delivery_id.as_uuid().as_bytes());
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

fn decode_hex(value: &str) -> Result<Vec<u8>, WorkflowAdmissionError> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(WorkflowAdmissionError::Internal)?;
            let low = hex_nibble(pair[1]).ok_or(WorkflowAdmissionError::Internal)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Application-level workflow admission failure.
#[derive(Debug, Error)]
pub enum WorkflowAdmissionError {
    /// Exact-source recompilation or plan comparison failed.
    #[error(transparent)]
    Verification(#[from] WorkflowPlanVerificationError),
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
    /// Canonical serialization of the validated workflow plan failed.
    #[error("workflow plan serialization failed")]
    Serialization,
    /// Workflow-level concurrency could not be resolved from admission-safe context.
    #[error("workflow concurrency could not be resolved at admission")]
    ConcurrencyEvaluation,
    /// A server-derived identity or invariant was internally inconsistent.
    #[error("internal workflow admission invariant failed")]
    Internal,
}

const fn observe_failure(error: &WorkflowAdmissionError) -> WorkflowAdmissionFailure {
    match error {
        WorkflowAdmissionError::Verification(_) => WorkflowAdmissionFailure::Materialization,
        WorkflowAdmissionError::Blob(_) => WorkflowAdmissionFailure::BlobStore,
        WorkflowAdmissionError::Store(_) => WorkflowAdmissionFailure::DurableStore,
        WorkflowAdmissionError::AdmissionValue(_)
        | WorkflowAdmissionError::LogicalValue(_)
        | WorkflowAdmissionError::Serialization
        | WorkflowAdmissionError::ConcurrencyEvaluation
        | WorkflowAdmissionError::Internal => WorkflowAdmissionFailure::InvalidState,
    }
}
