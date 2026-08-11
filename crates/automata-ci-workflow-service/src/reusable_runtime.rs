//! Autonomous publication and completion of repository-local reusable calls.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType,
};
use automata_ci_core::{
    ContextValue, InvocationInputDefault, InvocationInputType, JobRuntimeContext, LogicalJobKind,
    LogicalJobOutputSource, LogicalResultValue, NeedContext, NeedOutput, OutputSensitivity,
    SecretBinding, Sha256Digest, StrategyContext, WorkflowPlan,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, AdmittedReusableInputKind, CompleteReusableWorkflowCall,
    EvaluatedReusableWorkflowOutput, LogicalActivationAggregateStatus,
    LogicalActivationPreparationDescriptor, ObjectKey, PublishReusableWorkflowCall,
    ReadyReusableWorkflowCall, ReadyReusableWorkflowCompletion, ReusableCallOutputMapping,
    ReusableWorkflowCompletionReceipt, ReusableWorkflowOperationId,
    ReusableWorkflowPublicationReceipt, ReusableWorkflowRuntimeRepository,
    ReusableWorkflowRuntimeStoreError, StoreError,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    ActivateLogicalJobRequest, ActivationEvaluationContext, ActivationStatus, ActivationValue,
    GithubLogicalActivationEvaluator, JOB_RUNTIME_CONTEXT_MEDIA_TYPE, LogicalActivationEvaluator,
    LogicalJobActivator, ValidatedLogicalPlan, activation::evaluate_reusable_input_template,
    orchestration::github_activation_context,
};

const IDLE_POLL: Duration = Duration::from_millis(250);
const OPERATION_ID_DOMAIN: &[u8] = b"automata.workflow-service.reusable-operation.v1\0";
const ACTIVATION_DIGEST_DOMAIN: &[u8] = b"automata.workflow-service.reusable-activation.v1\0";
const OUTPUT_EVALUATION_DOMAIN: &[u8] =
    b"automata.workflow-service.reusable-output-evaluation.v1\0";

/// Result of one bounded reusable-runtime poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReusableWorkflowRuntimeOutcome {
    /// No dependency-ready call or complete child was visible.
    Idle,
    /// Another worker won an exact publication/completion race.
    Contended,
    /// One child graph was sealed and made visible.
    Published(ReusableWorkflowPublicationReceipt),
    /// One child result set was rolled into its parent call job.
    Completed(ReusableWorkflowCompletionReceipt),
}

/// Autonomous blob-first reusable call coordinator.
#[derive(Clone)]
pub struct ReusableWorkflowRuntimeService {
    repository: Arc<dyn ReusableWorkflowRuntimeRepository>,
    blobs: Arc<dyn ImmutableBlobStore>,
    limits: ProtocolLimits,
}

impl fmt::Debug for ReusableWorkflowRuntimeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReusableWorkflowRuntimeService")
    }
}

impl ReusableWorkflowRuntimeService {
    /// Composes the production coordinator with the default protocol budget.
    #[must_use]
    pub fn new(
        repository: Arc<dyn ReusableWorkflowRuntimeRepository>,
        blobs: Arc<dyn ImmutableBlobStore>,
    ) -> Self {
        Self::with_limits(repository, blobs, ProtocolLimits::default())
    }

    /// Composes the coordinator with an explicit protocol budget.
    #[must_use]
    pub const fn with_limits(
        repository: Arc<dyn ReusableWorkflowRuntimeRepository>,
        blobs: Arc<dyn ImmutableBlobStore>,
        limits: ProtocolLimits,
    ) -> Self {
        Self {
            repository,
            blobs,
            limits,
        }
    }

    /// Completes or publishes at most one reusable call.
    ///
    /// # Errors
    ///
    /// Returns a sanitized object, plan, evaluation, or persistence failure.
    pub async fn run_once(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<ReusableWorkflowRuntimeOutcome, ReusableWorkflowRuntimeError> {
        if shutdown.is_cancelled() {
            return Err(ReusableWorkflowRuntimeError::Shutdown);
        }
        if let Some(candidate) = self.repository.next_reusable_workflow_completion().await? {
            return self.complete(candidate, shutdown).await;
        }
        let Some(candidate) = self.repository.next_reusable_workflow_call().await? else {
            return Ok(ReusableWorkflowRuntimeOutcome::Idle);
        };
        self.publish(candidate, shutdown).await
    }

    /// Polls until cancellation or a non-retryable integrity failure.
    ///
    /// # Errors
    ///
    /// Returns the first non-operation failure; transient storage failures are
    /// retried after a bounded cancellation-aware delay.
    pub async fn run(
        &self,
        shutdown: CancellationToken,
    ) -> Result<(), ReusableWorkflowRuntimeError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            let delay = match self.run_once(&shutdown).await {
                Ok(
                    ReusableWorkflowRuntimeOutcome::Published(_)
                    | ReusableWorkflowRuntimeOutcome::Completed(_),
                ) => {
                    tokio::task::yield_now().await;
                    None
                }
                Ok(
                    ReusableWorkflowRuntimeOutcome::Idle
                    | ReusableWorkflowRuntimeOutcome::Contended,
                )
                | Err(ReusableWorkflowRuntimeError::Store(
                    ReusableWorkflowRuntimeStoreError::Store(StoreError::Operation(_)),
                )) => Some(IDLE_POLL),
                Err(ReusableWorkflowRuntimeError::Blob(error)) if retryable_blob_error(error) => {
                    Some(IDLE_POLL)
                }
                Err(ReusableWorkflowRuntimeError::Shutdown) if shutdown.is_cancelled() => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if let Some(delay) = delay {
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = sleep(delay) => {}
                }
            }
        }
    }

    async fn publish(
        &self,
        candidate: ReadyReusableWorkflowCall,
        shutdown: &CancellationToken,
    ) -> Result<ReusableWorkflowRuntimeOutcome, ReusableWorkflowRuntimeError> {
        let (payload, request) = self.prepare_publication(&candidate).await?;
        if shutdown.is_cancelled() {
            return Err(ReusableWorkflowRuntimeError::Shutdown);
        }
        self.blobs.put_if_absent(payload).await?;
        if shutdown.is_cancelled() {
            return Err(ReusableWorkflowRuntimeError::Shutdown);
        }
        match self
            .repository
            .publish_reusable_workflow_call(request)
            .await
        {
            Ok(receipt) => Ok(ReusableWorkflowRuntimeOutcome::Published(receipt)),
            Err(
                ReusableWorkflowRuntimeStoreError::NotReady
                | ReusableWorkflowRuntimeStoreError::Conflict,
            ) => Ok(ReusableWorkflowRuntimeOutcome::Contended),
            Err(error) => Err(error.into()),
        }
    }

    async fn complete(
        &self,
        candidate: ReadyReusableWorkflowCompletion,
        shutdown: &CancellationToken,
    ) -> Result<ReusableWorkflowRuntimeOutcome, ReusableWorkflowRuntimeError> {
        let child_plan_bytes = self.load(candidate.child_plan()).await?;
        let child_plan = decode_plan(&child_plan_bytes)?;
        let (outputs, evaluation_digest) = evaluate_outputs(&candidate, &child_plan)?;
        let operation_id = operation_id(
            candidate.publication().run_id(),
            candidate.publication().parent_invocation_id(),
            candidate.publication().caller_logical_job_id(),
            candidate.publication().child_invocation_id(),
            b"complete",
        )?;
        let request = CompleteReusableWorkflowCall::new(
            candidate.publication().clone(),
            operation_id,
            candidate.child_plan().digest(),
            evaluation_digest,
            outputs,
            candidate.ready_at(),
        )
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        if shutdown.is_cancelled() {
            return Err(ReusableWorkflowRuntimeError::Shutdown);
        }
        match self
            .repository
            .complete_reusable_workflow_call(request)
            .await
        {
            Ok(receipt) => Ok(ReusableWorkflowRuntimeOutcome::Completed(receipt)),
            Err(
                ReusableWorkflowRuntimeStoreError::NotReady
                | ReusableWorkflowRuntimeStoreError::Conflict
                | ReusableWorkflowRuntimeStoreError::ChildResultsPending,
            ) => Ok(ReusableWorkflowRuntimeOutcome::Contended),
            Err(error) => Err(error.into()),
        }
    }

    #[allow(clippy::too_many_lines)] // Every exact object and typed boundary remains explicit.
    async fn prepare_publication(
        &self,
        candidate: &ReadyReusableWorkflowCall,
    ) -> Result<(BlobPayload, PublishReusableWorkflowCall), ReusableWorkflowRuntimeError> {
        let preparation = candidate.preparation();
        let parent_plan_bytes = self.load(preparation.plan()).await?;
        let event_bytes = self.load(preparation.event()).await?;
        let base_bytes = self.load(preparation.base_context()).await?;
        let child_plan_bytes = self.load(candidate.child_plan()).await?;
        let parent_plan = decode_plan(&parent_plan_bytes)?;
        let child_plan = decode_plan(&child_plan_bytes)?;
        let base = decode_context(&base_bytes, &self.limits)?;
        let validated = ValidatedLogicalPlan::new(&parent_plan)
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        let job = validated
            .job(preparation.logical_key())
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        let LogicalJobKind::ReusableWorkflow(call) = job.execution() else {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        };
        if job.strategy().is_some()
            || u16::try_from(job.source_order()).ok() != Some(preparation.source_order())
        {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        }
        let needs = prerequisite_needs(preparation)?;
        let status = activation_status(preparation.status());
        let github = github_activation_context(&parent_plan, preparation.execution(), &event_bytes)
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        let evaluator = GithubLogicalActivationEvaluator::new(github);
        let activation = LogicalJobActivator::new(evaluator.clone())
            .activate(ActivateLogicalJobRequest::new(
                job,
                base.inputs(),
                base.vars(),
                &needs,
                base.secrets(),
                status,
            ))
            .map_err(|_| ReusableWorkflowRuntimeError::Evaluation)?;
        if activation.instances().len() > 1 {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        }
        let contract = child_plan
            .logical()
            .invocation()
            .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?;
        let runtime_context = if activation.condition_matched() {
            let instance = activation
                .instances()
                .first()
                .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?;
            callee_context(
                candidate,
                call,
                contract,
                instance.runtime_context(),
                status,
                &evaluator,
            )?
        } else {
            empty_callee_context(base.vars().clone())?
        };
        let context_bytes = automata_ci_protocol_protobuf::encode_job_runtime_context(
            &runtime_context,
            &self.limits,
        )
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        let context_key = BlobKey::new(format!(
            "workflow-plan-v2/reusable-contexts/{}/{}.pb",
            preparation.target().run_id().as_uuid(),
            candidate.child_invocation_id().as_uuid(),
        ))
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        let payload = BlobPayload::from_bytes(
            context_key,
            MediaType::new(JOB_RUNTIME_CONTEXT_MEDIA_TYPE)
                .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?,
            Bytes::from(context_bytes),
        );
        let runtime_context_object = admission_object(payload.descriptor())?;
        let mappings = output_mappings(job.outputs(), contract)?;
        let matrix_digest = activation.instances().first().map_or_else(
            || digest_parts(b"automata.workflow-service.reusable-empty-matrix.v1\0", &[]),
            |instance| instance.identity().matrix_digest(),
        );
        let activation_input_digest = activation_digest(candidate, runtime_context_object.digest());
        let operation_id = operation_id(
            preparation.target().run_id(),
            preparation.target().invocation_id(),
            preparation.target().logical_job_id(),
            candidate.child_invocation_id(),
            b"publish",
        )?;
        let request = PublishReusableWorkflowCall::new(
            preparation.target().tenant().clone(),
            candidate.repository_id(),
            preparation.target().run_id(),
            preparation.target().invocation_id(),
            preparation.target().logical_job_id(),
            candidate.child_invocation_id(),
            operation_id,
            activation_input_digest,
            activation.condition_matched(),
            matrix_digest,
            runtime_context_object,
            candidate.permissions().digest(),
            mappings,
            preparation.runtime_policy().pin().clone(),
            preparation.evidence_ready_at(),
        )
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
        Ok((payload, request))
    }

    async fn load(&self, object: &AdmissionObject) -> Result<Bytes, ReusableWorkflowRuntimeError> {
        let descriptor = blob_descriptor(object)?;
        self.blobs
            .get_verified(&descriptor, object.encoded_size())
            .await
            .map(automata_ci_blob::VerifiedBlob::into_bytes)
            .map_err(ReusableWorkflowRuntimeError::Blob)
    }
}

const fn retryable_blob_error(error: BlobStoreError) -> bool {
    matches!(
        error.kind(),
        BlobStoreErrorKind::Unavailable
            | BlobStoreErrorKind::Unauthorized
            | BlobStoreErrorKind::InvalidResponse
    )
}

fn callee_context(
    candidate: &ReadyReusableWorkflowCall,
    call: &automata_ci_core::ReusableWorkflowInvocation,
    contract: &automata_ci_core::WorkflowInvocationContract,
    caller: &JobRuntimeContext,
    status: ActivationStatus,
    evaluator: &GithubLogicalActivationEvaluator,
) -> Result<JobRuntimeContext, ReusableWorkflowRuntimeError> {
    if candidate.inputs().len() != contract.inputs().len() {
        return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
    }
    let logical_key = candidate.preparation().logical_key().clone();
    let evaluation_context = ActivationEvaluationContext::reusable_input(
        &logical_key,
        caller.inputs(),
        caller.vars(),
        caller.needs(),
        status,
    );
    let session = evaluator
        .prepare(&evaluation_context)
        .map_err(|_| ReusableWorkflowRuntimeError::Evaluation)?;
    let supplied = call
        .inputs()
        .iter()
        .map(|binding| (binding.target().value().as_str(), binding.value().value()))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = BTreeMap::new();
    for (definition, evidence) in contract.inputs().iter().zip(candidate.inputs()) {
        if definition.key().value().as_str() != evidence.key()
            || *definition.input_type().value() != evidence.input_type()
        {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        }
        let value = match evidence.kind() {
            AdmittedReusableInputKind::Caller => {
                let template = supplied
                    .get(evidence.key())
                    .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?;
                require_value_digest(template, evidence.value_digest())?;
                let value =
                    evaluate_reusable_input_template(&session, template, &evaluation_context)
                        .map_err(|_| ReusableWorkflowRuntimeError::Evaluation)?;
                activation_input_value(value, evidence.input_type())?
            }
            AdmittedReusableInputKind::Default => {
                let default = definition
                    .default()
                    .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?
                    .value();
                require_value_digest(default, evidence.value_digest())?;
                default_input_value(default)?
            }
            AdmittedReusableInputKind::ImplicitDefault => {
                if evidence.value_digest().is_some() {
                    return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
                }
                implicit_input_value(evidence.input_type())
            }
        };
        inputs.insert(evidence.key().to_owned(), value);
    }
    let inputs =
        ContextValue::object(inputs).map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    let secrets = forwarded_secrets(candidate, call, caller.secrets())?;
    let strategy = StrategyContext::new(true, 0, 1, 1)
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    JobRuntimeContext::new(
        inputs,
        caller.vars().clone(),
        ContextValue::empty_object(),
        strategy,
        BTreeMap::new(),
        secrets,
    )
    .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)
}

fn forwarded_secrets(
    candidate: &ReadyReusableWorkflowCall,
    call: &automata_ci_core::ReusableWorkflowInvocation,
    available: &BTreeMap<String, SecretBinding>,
) -> Result<BTreeMap<String, SecretBinding>, ReusableWorkflowRuntimeError> {
    let expected = match call.secrets() {
        automata_ci_core::ReusableSecretForwarding::Mapping(bindings) => bindings
            .iter()
            .map(|binding| {
                (
                    binding.target().value().as_str().to_owned(),
                    binding.source().value().as_str().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>(),
        automata_ci_core::ReusableSecretForwarding::Inherit(_) => available
            .keys()
            .map(|name| (name.clone(), name.clone()))
            .collect(),
    };
    if expected.len() != candidate.secrets().len()
        || candidate
            .secrets()
            .iter()
            .any(|edge| expected.get(edge.target()).map(String::as_str) != Some(edge.source()))
    {
        return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
    }
    candidate
        .secrets()
        .iter()
        .map(|edge| {
            available
                .get(edge.source())
                .cloned()
                .map(|binding| (edge.target().to_owned(), binding))
                .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)
        })
        .collect()
}

fn output_mappings(
    outputs: &[automata_ci_core::LogicalJobOutputDefinition],
    contract: &automata_ci_core::WorkflowInvocationContract,
) -> Result<Vec<ReusableCallOutputMapping>, ReusableWorkflowRuntimeError> {
    let declared = contract
        .outputs()
        .iter()
        .map(|output| (output.key().value(), output))
        .collect::<BTreeMap<_, _>>();
    outputs
        .iter()
        .map(|output| {
            let LogicalJobOutputSource::InvocationOutput(child) = output.source() else {
                return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
            };
            let definition = declared
                .get(child.value())
                .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?;
            if output.sensitivity() == OutputSensitivity::Public
                && definition.sensitivity() == OutputSensitivity::SecretDerived
            {
                return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
            }
            Ok(ReusableCallOutputMapping::new(
                output.key().value().clone(),
                child.value().clone(),
                output.sensitivity(),
            ))
        })
        .collect()
}

fn evaluate_outputs(
    candidate: &ReadyReusableWorkflowCompletion,
    child_plan: &WorkflowPlan,
) -> Result<(Vec<EvaluatedReusableWorkflowOutput>, Sha256Digest), ReusableWorkflowRuntimeError> {
    if candidate.child_plan().digest() != digest_json(child_plan)? {
        return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
    }
    let contract = child_plan
        .logical()
        .invocation()
        .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?;
    let values = candidate
        .outputs()
        .iter()
        .map(|output| {
            (
                (output.job_key().clone(), output.output_name().clone()),
                output,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut hasher = Sha256::new();
    hasher.update(OUTPUT_EVALUATION_DOMAIN);
    hash_part(&mut hasher, candidate.child_plan().digest().as_bytes());
    let mut outputs = Vec::with_capacity(contract.outputs().len());
    for output in contract.outputs() {
        let [reference] = output.references() else {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        };
        let LogicalResultValue::Output(output_name) = reference.value().value() else {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        };
        let value = values
            .get(&(reference.value().job().clone(), output_name.clone()))
            .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?;
        if value.sensitivity() != output.sensitivity() {
            return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
        }
        hash_part(&mut hasher, output.key().value().as_str().as_bytes());
        hash_part(&mut hasher, digest_json(output.value().value())?.as_bytes());
        hash_part(&mut hasher, reference.value().job().as_str().as_bytes());
        hash_part(&mut hasher, output_name.as_str().as_bytes());
        hash_part(
            &mut hasher,
            match output.sensitivity() {
                OutputSensitivity::Public => b"public",
                OutputSensitivity::SecretDerived => b"secret_derived",
            },
        );
        hash_part(&mut hasher, value.public_value().unwrap_or("").as_bytes());
        outputs.push(
            EvaluatedReusableWorkflowOutput::new(
                output.key().value().clone(),
                output.sensitivity(),
                value.public_value().map(str::to_owned),
            )
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?,
        );
    }
    Ok((outputs, Sha256Digest::from_bytes(hasher.finalize().into())))
}

fn prerequisite_needs(
    preparation: &LogicalActivationPreparationDescriptor,
) -> Result<BTreeMap<String, NeedContext>, ReusableWorkflowRuntimeError> {
    preparation
        .prerequisites()
        .iter()
        .map(|prerequisite| {
            let outputs = prerequisite
                .outputs()
                .iter()
                .map(|output| {
                    let value = match output.sensitivity() {
                        OutputSensitivity::Public => output
                            .public_value()
                            .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)?,
                        OutputSensitivity::SecretDerived => "",
                    };
                    NeedOutput::new(value, output.sensitivity())
                        .map(|value| (output.name().as_str().to_owned(), value))
                        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            NeedContext::new(prerequisite.effective_conclusion(), outputs)
                .map(|need| (prerequisite.logical_key().as_str().to_owned(), need))
                .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)
        })
        .collect()
}

const fn activation_status(status: LogicalActivationAggregateStatus) -> ActivationStatus {
    match status {
        LogicalActivationAggregateStatus::Success => ActivationStatus::Success,
        LogicalActivationAggregateStatus::Failure => ActivationStatus::Failure,
        LogicalActivationAggregateStatus::Cancelled => ActivationStatus::Cancelled,
        LogicalActivationAggregateStatus::Skipped => ActivationStatus::Skipped,
    }
}

fn activation_input_value(
    value: ActivationValue,
    expected: InvocationInputType,
) -> Result<ContextValue, ReusableWorkflowRuntimeError> {
    match (expected, value) {
        (InvocationInputType::Boolean, ActivationValue::Boolean(value)) => {
            Ok(ContextValue::boolean(value))
        }
        (InvocationInputType::Number, ActivationValue::Number(bits)) => {
            Ok(ContextValue::number(f64::from_bits(bits)))
        }
        (InvocationInputType::String, ActivationValue::String(value)) => {
            Ok(ContextValue::string(value))
        }
        _ => Err(ReusableWorkflowRuntimeError::Evaluation),
    }
}

fn default_input_value(
    value: &InvocationInputDefault,
) -> Result<ContextValue, ReusableWorkflowRuntimeError> {
    match value {
        InvocationInputDefault::Boolean(value) => Ok(ContextValue::boolean(*value)),
        InvocationInputDefault::Number(value) => value
            .parse::<f64>()
            .map(ContextValue::number)
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence),
        InvocationInputDefault::String(value) => Ok(ContextValue::string(value.clone())),
    }
}

const fn implicit_input_value(input_type: InvocationInputType) -> ContextValue {
    match input_type {
        InvocationInputType::Boolean => ContextValue::boolean(false),
        InvocationInputType::Number => ContextValue::Number { ieee754_bits: 0 },
        InvocationInputType::String => ContextValue::String {
            value: String::new(),
        },
    }
}

fn empty_callee_context(
    vars: ContextValue,
) -> Result<JobRuntimeContext, ReusableWorkflowRuntimeError> {
    JobRuntimeContext::new(
        ContextValue::empty_object(),
        vars,
        ContextValue::empty_object(),
        StrategyContext::new(true, 0, 1, 1)
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?,
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)
}

fn activation_digest(
    candidate: &ReadyReusableWorkflowCall,
    runtime_context_digest: Sha256Digest,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ACTIVATION_DIGEST_DOMAIN);
    hash_part(
        &mut hasher,
        candidate.preparation().descriptor_digest().as_bytes(),
    );
    hash_part(&mut hasher, candidate.child_plan().digest().as_bytes());
    hash_part(
        &mut hasher,
        candidate.child_invocation_id().as_uuid().as_bytes(),
    );
    hash_part(&mut hasher, candidate.permissions().digest().as_bytes());
    hash_part(&mut hasher, runtime_context_digest.as_bytes());
    for input in candidate.inputs() {
        hash_part(&mut hasher, input.key().as_bytes());
        match input.value_digest() {
            Some(digest) => hash_part(&mut hasher, digest.as_bytes()),
            None => hash_part(&mut hasher, &[]),
        }
    }
    for secret in candidate.secrets() {
        hash_part(&mut hasher, secret.target().as_bytes());
        hash_part(&mut hasher, secret.source().as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn operation_id(
    run_id: automata_ci_core::RunId,
    parent_invocation_id: automata_ci_store::LogicalWorkflowInvocationId,
    caller_job_id: automata_ci_store::LogicalWorkflowJobId,
    child_invocation_id: automata_ci_store::LogicalWorkflowInvocationId,
    operation: &[u8],
) -> Result<ReusableWorkflowOperationId, ReusableWorkflowRuntimeError> {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_ID_DOMAIN);
    for value in [
        run_id.as_uuid(),
        parent_invocation_id.as_uuid(),
        caller_job_id.as_uuid(),
        child_invocation_id.as_uuid(),
    ] {
        hash_part(&mut hasher, value.as_bytes());
    }
    hash_part(&mut hasher, operation);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ReusableWorkflowOperationId::from_uuid(Uuid::from_bytes(bytes))
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)
}

fn require_value_digest<T: serde::Serialize>(
    value: &T,
    expected: Option<Sha256Digest>,
) -> Result<(), ReusableWorkflowRuntimeError> {
    (expected == Some(digest_json(value)?))
        .then_some(())
        .ok_or(ReusableWorkflowRuntimeError::InvalidEvidence)
}

fn digest_json<T: serde::Serialize>(
    value: &T,
) -> Result<Sha256Digest, ReusableWorkflowRuntimeError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hash_part(&mut hasher, part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn decode_plan(bytes: &[u8]) -> Result<WorkflowPlan, ReusableWorkflowRuntimeError> {
    let plan: WorkflowPlan =
        serde_json::from_slice(bytes).map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    plan.validate()
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    let canonical =
        serde_json::to_vec(&plan).map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    if canonical != bytes {
        return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
    }
    Ok(plan)
}

fn decode_context(
    bytes: &[u8],
    limits: &ProtocolLimits,
) -> Result<JobRuntimeContext, ReusableWorkflowRuntimeError> {
    let context = automata_ci_protocol_protobuf::decode_job_runtime_context(bytes, limits)
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    let canonical = automata_ci_protocol_protobuf::encode_job_runtime_context(&context, limits)
        .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?;
    if canonical != bytes {
        return Err(ReusableWorkflowRuntimeError::InvalidEvidence);
    }
    Ok(context)
}

fn blob_descriptor(
    object: &AdmissionObject,
) -> Result<BlobDescriptor, ReusableWorkflowRuntimeError> {
    Ok(BlobDescriptor::new(
        BlobKey::new(object.object_key().as_str().to_owned())
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?,
        object.digest(),
        object.encoded_size(),
        MediaType::new(object.media_type().to_owned())
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?,
    ))
}

fn admission_object(
    descriptor: &BlobDescriptor,
) -> Result<AdmissionObject, ReusableWorkflowRuntimeError> {
    AdmissionObject::new(
        descriptor.digest(),
        ObjectKey::new(descriptor.key().as_str().to_owned())
            .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)?,
        descriptor.size(),
        descriptor.media_type().as_str(),
    )
    .map_err(|_| ReusableWorkflowRuntimeError::InvalidEvidence)
}

/// Sanitized reusable-runtime worker failure.
#[derive(Debug, Error)]
pub enum ReusableWorkflowRuntimeError {
    /// Local cancellation stopped new work.
    #[error("reusable workflow runtime stopped")]
    Shutdown,
    /// Immutable object I/O failed.
    #[error(transparent)]
    Blob(#[from] BlobStoreError),
    /// Durable state was unavailable or rejected.
    #[error(transparent)]
    Store(#[from] ReusableWorkflowRuntimeStoreError),
    /// Exact plan or relational evidence was inconsistent.
    #[error("reusable workflow runtime evidence is invalid")]
    InvalidEvidence,
    /// A typed activation-time value could not be evaluated safely.
    #[error("reusable workflow input evaluation failed")]
    Evaluation,
}
