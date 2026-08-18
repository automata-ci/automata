//! Blob-first orchestration of one claimed current logical GitHub job.

use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType,
};
use automata_ci_core::{
    JobAuthorityProfile, JobContentReference, JobExecutionContext, JobId, JobRuntimeContext,
    PlanSourceOrigin, RunId, Sha256Digest, TrustSnapshot, TrustSourceClass, UnixMillis,
    WorkflowJobKey, WorkflowPlan,
};
use automata_ci_expression_actions::{GithubObject, GithubValue};
use automata_ci_job_executor_actions::ActionPreparationPort;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    ActivatedLogicalInstanceDescriptor, AdmissionObject, ClaimedLogicalJobActivation,
    DeploymentEnvironmentName, JobEnvironmentActivationEvidence, JobEventTrust, JobSourceKind,
    LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE, LogicalActivationExecutionContext,
    LogicalActivationObject, LogicalActivationPublicationReceipt, LogicalActivationRepository,
    LogicalActivationStoreError, LogicalActivationValueError, LogicalActivationWorkerId,
    LogicalWorkQuarantineKind, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, PinnedWorkflowRuntimePolicy, PublishLogicalJobActivation,
    ResolvedLogicalJobSchedulingPolicy, ReusableSecretPermission, StoreError, TenantScope,
};
use automata_ci_workflow_actions::{GithubRunnerProfileCatalog, GithubRunnerProfileMapping};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::activation_preparation::prepared_from_receipt;
use crate::runtime_requirements::{
    RuntimeRequirementDiscoveryError, discover_runtime_requirements,
};
use crate::{
    ActivateLogicalJobRequest, ActivationStatus, AdmissionClock, AutonomousActivationLease,
    AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError,
    GITHUB_RUNNER_POLICY_MEDIA_TYPE, GithubActivationContext, GithubLogicalActivationEvaluator,
    GithubLogicalJobProjector, JOB_RUNTIME_CONTEXT_MEDIA_TYPE, LogicalJobActivator,
    LogicalJobProjectionError, MAX_GITHUB_RUNNER_POLICY_BYTES, ProjectGithubLogicalJobRequest,
    ValidatedLogicalPlan, WORKFLOW_PLAN_MEDIA_TYPE,
};

const ACTIVATION_INPUT_DIGEST_DOMAIN: &[u8] =
    b"automata.workflow-service.logical-activation-input.v5\0";
const JOB_ID_DOMAIN: &[u8] = b"automata.workflow-service.logical-job-id.v1\0";
const MAX_EXACT_GITHUB_INTEGER: u64 = 9_007_199_254_740_992;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubOrchestrationLimitRejection {
    ExactInteger,
}

const fn exact_github_integer_rejection(
    observed: u64,
) -> Option<GithubOrchestrationLimitRejection> {
    if observed > MAX_EXACT_GITHUB_INTEGER {
        return Some(GithubOrchestrationLimitRejection::ExactInteger);
    }
    None
}

/// Exact durable target of one logical-job orchestration attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LogicalJobOrchestrationTarget {
    tenant: TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
}

impl LogicalJobOrchestrationTarget {
    /// Creates one typed orchestration target.
    ///
    /// # Errors
    ///
    /// Rejects the nil workflow-run sentinel.
    pub(crate) fn new(
        tenant: TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
    ) -> Result<Self, LogicalOrchestrationValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalOrchestrationValueError::NilRunId);
        }
        Ok(Self {
            tenant,
            run_id,
            invocation_id,
            logical_job_id,
        })
    }

    #[must_use]
    /// Returns the tenant that owns the logical run.
    pub(crate) const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    /// Returns the server-owned workflow run identity.
    pub(crate) const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    /// Returns the logical invocation identity within the run.
    pub(crate) const fn invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.invocation_id
    }

    #[must_use]
    /// Returns the exact logical job identity to activate.
    pub(crate) const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }
}

/// Store-authenticated descriptors and metadata prepared before a claim.
///
/// The two context objects are canonical protobuf-encoded
/// [`JobRuntimeContext`] v1 snapshots. `base_context` carries admission-bound
/// inputs, repository variables, and opaque secret locators;
/// `prerequisite_context` carries direct `needs` results and
/// sensitivity-classified outputs. Every unused field has a canonical empty
/// shape and is checked after loading.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedLogicalJobActivation {
    target: LogicalJobOrchestrationTarget,
    logical_key: WorkflowJobKey,
    source_order: u16,
    execution: LogicalActivationExecutionContext,
    authority_profile: JobAuthorityProfile,
    runner_policy: AdmissionObject,
    runtime_policy: PinnedWorkflowRuntimePolicy,
    plan: AdmissionObject,
    event: AdmissionObject,
    base_context: AdmissionObject,
    prerequisite_context: AdmissionObject,
    status: ActivationStatus,
    workspace: String,
    input_digest: Sha256Digest,
}

impl PreparedLogicalJobActivation {
    /// Constructs a validated, digest-bound preparation result.
    ///
    /// This constructor does not confer claim authority. Every field must be
    /// derived from trusted durable preparation state, and the selected claim
    /// is compared exactly before any object is read.
    ///
    /// # Errors
    ///
    /// Rejects media-type mismatches or a noncanonical workspace.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        target: LogicalJobOrchestrationTarget,
        logical_key: WorkflowJobKey,
        source_order: u16,
        execution: LogicalActivationExecutionContext,
        authority_profile: JobAuthorityProfile,
        runner_policy: AdmissionObject,
        runtime_policy: PinnedWorkflowRuntimePolicy,
        plan: AdmissionObject,
        event: AdmissionObject,
        base_context: AdmissionObject,
        prerequisite_context: AdmissionObject,
        status: ActivationStatus,
    ) -> Result<Self, LogicalOrchestrationValueError> {
        require_media_type(&runner_policy, GITHUB_RUNNER_POLICY_MEDIA_TYPE)?;
        if runner_policy.encoded_size()
            > u64::try_from(MAX_GITHUB_RUNNER_POLICY_BYTES).unwrap_or(u64::MAX)
        {
            return Err(LogicalOrchestrationValueError::InvalidRuntimePolicy);
        }
        require_media_type(&plan, WORKFLOW_PLAN_MEDIA_TYPE)?;
        if !crate::workflow_event_media_type_is_current(event.media_type()) {
            return Err(LogicalOrchestrationValueError::InvalidMediaType);
        }
        require_media_type(&base_context, JOB_RUNTIME_CONTEXT_MEDIA_TYPE)?;
        require_media_type(&prerequisite_context, JOB_RUNTIME_CONTEXT_MEDIA_TYPE)?;
        if runtime_policy.run_id() != target.run_id()
            || runtime_policy.pin().tenant() != target.tenant()
        {
            return Err(LogicalOrchestrationValueError::InvalidRuntimePolicy);
        }
        let workspace = runtime_policy
            .policy()
            .derive_workspace(
                target.run_id(),
                target.invocation_id(),
                target.logical_job_id(),
            )
            .map_err(|_| LogicalOrchestrationValueError::InvalidRuntimePolicy)?;
        let mut prepared = Self {
            target,
            logical_key,
            source_order,
            execution,
            authority_profile,
            runner_policy,
            runtime_policy,
            plan,
            event,
            base_context,
            prerequisite_context,
            status,
            workspace: workspace.as_str().to_owned(),
            input_digest: Sha256Digest::from_bytes([0; 32]),
        };
        prepared.input_digest = activation_input_digest(&prepared);
        Ok(prepared)
    }

    #[must_use]
    /// Returns the exact durable target authenticated by preparation.
    pub(crate) const fn target(&self) -> &LogicalJobOrchestrationTarget {
        &self.target
    }

    #[must_use]
    /// Returns the logical job key expected in the immutable plan.
    pub(crate) const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    #[must_use]
    /// Returns the job's stable source ordering.
    pub(crate) const fn source_order(&self) -> u16 {
        self.source_order
    }

    #[must_use]
    /// Returns the store-authenticated execution metadata.
    pub(crate) const fn execution(&self) -> &LogicalActivationExecutionContext {
        &self.execution
    }

    #[must_use]
    /// Returns the exact historical authority profile bound by preparation.
    pub(crate) const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    #[must_use]
    /// Returns the exact structured runtime policy pinned to this run.
    pub(crate) const fn runtime_policy(&self) -> &PinnedWorkflowRuntimePolicy {
        &self.runtime_policy
    }

    #[must_use]
    /// Returns the immutable workflow-plan object descriptor.
    pub(crate) const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    #[must_use]
    /// Returns the immutable provider-event object descriptor.
    pub(crate) const fn event(&self) -> &AdmissionObject {
        &self.event
    }

    #[must_use]
    /// Returns the canonical root invocation-context descriptor.
    pub(crate) const fn base_context(&self) -> &AdmissionObject {
        &self.base_context
    }

    #[must_use]
    /// Returns the canonical prerequisite-results context descriptor.
    pub(crate) const fn prerequisite_context(&self) -> &AdmissionObject {
        &self.prerequisite_context
    }

    #[must_use]
    /// Returns the aggregate prerequisite status used by conditions.
    pub(crate) const fn status(&self) -> ActivationStatus {
        self.status
    }

    #[must_use]
    /// Returns the server-selected canonical runner workspace.
    pub(crate) fn workspace(&self) -> &str {
        &self.workspace
    }

    #[must_use]
    /// Returns the digest binding every prepared activation input.
    pub(crate) const fn input_digest(&self) -> Sha256Digest {
        self.input_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum LogicalActivationPreparationError {
    /// Store-authenticated preparation evidence violates an invariant.
    #[error("logical activation preparation state is corrupt")]
    Corrupt,
}

/// Invalid application-level orchestration value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum LogicalOrchestrationValueError {
    /// The target uses the reserved nil workflow run identity.
    #[error("workflow run ID must not be nil")]
    NilRunId,
    /// An immutable preparation object has a media type inappropriate to its role.
    #[error("logical activation preparation object has the wrong media type")]
    InvalidMediaType,
    /// The structured runner catalog or workspace policy disagreed with the run.
    #[error("logical activation runtime policy is invalid")]
    InvalidRuntimePolicy,
    /// A trusted observation or claim interval is negative, stale, or overflowing.
    #[error("logical activation timestamp is invalid or exhausted")]
    InvalidTimestamp,
}

fn require_media_type(
    object: &AdmissionObject,
    expected: &str,
) -> Result<(), LogicalOrchestrationValueError> {
    if object.media_type() != expected {
        return Err(LogicalOrchestrationValueError::InvalidMediaType);
    }
    Ok(())
}

fn activation_input_digest(prepared: &PreparedLogicalJobActivation) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ACTIVATION_INPUT_DIGEST_DOMAIN);
    hash_text(&mut hasher, prepared.target.tenant().as_str());
    hasher.update(prepared.target.run_id().as_uuid().as_bytes());
    hasher.update(prepared.target.invocation_id().as_uuid().as_bytes());
    hasher.update(prepared.target.logical_job_id().as_uuid().as_bytes());
    hash_text(&mut hasher, prepared.logical_key.as_str());
    hasher.update(prepared.source_order.to_be_bytes());
    hash_execution(&mut hasher, &prepared.execution);
    hasher.update([match prepared.authority_profile {
        JobAuthorityProfile::Standard => 1,
        JobAuthorityProfile::CredentialFree => 2,
    }]);
    hash_admission_object(&mut hasher, b"runner-policy", &prepared.runner_policy);
    hash_runtime_policy_pin(&mut hasher, &prepared.runtime_policy);
    hash_admission_object(&mut hasher, b"plan", &prepared.plan);
    hash_admission_object(&mut hasher, b"event", &prepared.event);
    hash_admission_object(&mut hasher, b"base-context", &prepared.base_context);
    hash_admission_object(
        &mut hasher,
        b"prerequisite-context",
        &prepared.prerequisite_context,
    );
    hasher.update([match prepared.status {
        ActivationStatus::Success => 0,
        ActivationStatus::Failure => 1,
        ActivationStatus::Cancelled => 2,
        ActivationStatus::Skipped => 3,
    }]);
    hash_text(&mut hasher, &prepared.workspace);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_execution(hasher: &mut Sha256, execution: &LogicalActivationExecutionContext) {
    hasher.update(execution.workflow_id().as_uuid().as_bytes());
    hash_text(hasher, execution.workflow_name());
    hash_text(hasher, execution.git_ref());
    match execution.actor() {
        Some(actor) => {
            hasher.update([1]);
            hash_text(hasher, actor);
        }
        None => hasher.update([0]),
    }
    match execution.triggering_actor() {
        Some(actor) => {
            hasher.update([1]);
            hash_text(hasher, actor);
        }
        None => hasher.update([0]),
    }
    hasher.update(execution.run_id_alias().get().to_be_bytes());
    hasher.update(execution.run_number().to_be_bytes());
    hasher.update(execution.run_attempt().to_be_bytes());
}

fn hash_admission_object(hasher: &mut Sha256, label: &[u8], object: &AdmissionObject) {
    hash_bytes(hasher, label);
    hash_text(hasher, object.object_key().as_str());
    hasher.update(object.digest().as_bytes());
    hasher.update(object.encoded_size().to_be_bytes());
    hash_text(hasher, object.media_type());
}

fn hash_runtime_policy_pin(hasher: &mut Sha256, policy: &PinnedWorkflowRuntimePolicy) {
    hash_text(hasher, policy.pin().tenant().as_str());
    hasher.update(policy.pin().repository_id().as_uuid().as_bytes());
    hasher.update(policy.pin().revision().get().to_be_bytes());
    hasher.update(policy.pin().digest().as_bytes());
}

fn runtime_profile_catalog(
    policy: &PinnedWorkflowRuntimePolicy,
) -> Result<GithubRunnerProfileCatalog, GithubLogicalJobOrchestrationError> {
    let mappings = policy
        .policy()
        .mappings()
        .iter()
        .map(|mapping| {
            GithubRunnerProfileMapping::new(
                mapping.selector().as_str(),
                mapping.environment().clone(),
                mapping.operating_system().clone(),
                mapping.architecture().clone(),
            )
            .map(|profile| {
                let mut profile =
                    profile.with_container_features(mapping.container_features().iter().cloned());
                if let Some(policy) = mapping.runner_feature_policy() {
                    profile =
                        profile.with_supported_runner_features(policy.supported().iter().cloned());
                }
                profile
            })
            .map_err(|_| GithubLogicalJobOrchestrationError::Internal)
        })
        .collect::<Result<Vec<_>, _>>()?;
    GithubRunnerProfileCatalog::new(mappings)
        .map_err(|_| GithubLogicalJobOrchestrationError::Internal)
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod preparation_context_tests {
    use automata_ci_core::{
        ContextValue, JobConclusion, NeedContext, NeedOutput, OutputSensitivity,
    };

    use super::*;

    fn context(inputs: ContextValue, needs: BTreeMap<String, NeedContext>) -> JobRuntimeContext {
        JobRuntimeContext::new(
            inputs,
            ContextValue::empty_object(),
            ContextValue::empty_object(),
            automata_ci_core::StrategyContext::new(true, 0, 1, 1).expect("strategy"),
            needs,
            BTreeMap::new(),
        )
        .expect("context")
    }

    #[test]
    fn split_context_accepts_admission_fields_and_rejects_instance_fields_or_plaintext() {
        let empty_base = context(ContextValue::empty_object(), BTreeMap::new());
        let mut input_values = BTreeMap::new();
        input_values.insert("target".to_owned(), ContextValue::string("linux"));
        let admitted_base = context(
            ContextValue::object(input_values).expect("inputs"),
            BTreeMap::new(),
        );
        assert!(validate_split_contexts(&admitted_base, &empty_base).is_ok());

        let instance_base = JobRuntimeContext::new(
            ContextValue::empty_object(),
            ContextValue::empty_object(),
            ContextValue::object(BTreeMap::from([(
                "target".to_owned(),
                ContextValue::string("linux"),
            )]))
            .expect("matrix"),
            automata_ci_core::StrategyContext::new(true, 0, 1, 1).expect("strategy"),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("instance context");
        assert!(validate_split_contexts(&instance_base, &empty_base).is_err());

        let mut outputs = BTreeMap::new();
        outputs.insert(
            "token".to_owned(),
            NeedOutput::new("must-not-survive", OutputSensitivity::SecretDerived).expect("output"),
        );
        let mut needs = BTreeMap::new();
        needs.insert(
            "build".to_owned(),
            NeedContext::new(JobConclusion::Success, outputs).expect("need"),
        );
        let unsafe_prerequisites = context(ContextValue::empty_object(), needs);
        assert!(validate_split_contexts(&empty_base, &unsafe_prerequisites).is_err());
    }
}

/// Current-only GitHub logical-job orchestration service.
#[derive(Clone, Debug)]
pub(crate) struct GithubLogicalJobOrchestrationService {
    blobs: Arc<dyn ImmutableBlobStore>,
    activations: Arc<dyn LogicalActivationRepository>,
    clock: Arc<dyn AdmissionClock>,
    limits: ProtocolLimits,
    actions: Option<Arc<dyn ActionPreparationPort>>,
}

/// Opaque exact activation publication prepared under one selected authority.
///
/// Queue-local worker custody retains this value before the Store operation is
/// first polled. Its debug representation intentionally excludes all tenant and
/// immutable-object evidence.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReadyLogicalJobActivation {
    authority: ClaimedLogicalJobActivation,
    request: PublishLogicalJobActivation,
}

impl fmt::Debug for ReadyLogicalJobActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadyLogicalJobActivation([REDACTED])")
    }
}

impl ReadyLogicalJobActivation {
    fn new(
        authority: ClaimedLogicalJobActivation,
        request: PublishLogicalJobActivation,
    ) -> Result<Self, AutonomousWorkflowLeaseError> {
        if request.claim() != authority.claim() {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        Ok(Self { authority, request })
    }

    pub(crate) fn matches_authority(&self, authority: &ClaimedLogicalJobActivation) -> bool {
        &self.authority == authority && self.request.claim() == authority.claim()
    }

    pub(crate) const fn request(&self) -> &PublishLogicalJobActivation {
        &self.request
    }
}

impl GithubLogicalJobOrchestrationService {
    pub(crate) fn with_limits(
        blobs: Arc<dyn ImmutableBlobStore>,
        activations: Arc<dyn LogicalActivationRepository>,
        clock: Arc<dyn AdmissionClock>,
        limits: ProtocolLimits,
    ) -> Self {
        Self {
            blobs,
            activations,
            clock,
            limits,
            actions: None,
        }
    }

    pub(crate) fn with_limits_and_action_preparer(
        blobs: Arc<dyn ImmutableBlobStore>,
        activations: Arc<dyn LogicalActivationRepository>,
        clock: Arc<dyn AdmissionClock>,
        limits: ProtocolLimits,
        actions: Arc<dyn ActionPreparationPort>,
    ) -> Self {
        Self {
            blobs,
            activations,
            clock,
            limits,
            actions: Some(actions),
        }
    }

    /// Activates one already-selected logical job without acquiring another claim.
    #[allow(clippy::too_many_lines)] // The selected pipeline keeps every evidence and I/O boundary explicit.
    pub(crate) async fn activate_selected(
        &self,
        lease: &mut AutonomousActivationLease,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
        let claimed = lease.authority().clone();
        let Some(preparation) = claimed.preparation() else {
            return Ok(activation_relational_failure());
        };
        let Ok(prepared) = prepared_from_receipt(preparation) else {
            return Ok(activation_relational_failure());
        };
        if !claim_matches_preparation(
            &claimed,
            &prepared,
            claimed.claim().owner(),
            prepared.input_digest(),
        ) {
            return Ok(activation_relational_failure());
        }

        lease.before_io(shutdown)?;
        let plan_bytes = match load_object(self.blobs.as_ref(), prepared.plan()).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Ok(report_activation_failure(
                    "plan_object_load",
                    prepared.target(),
                    &error,
                ));
            }
        };
        lease.before_io(shutdown)?;
        let event_bytes = match load_object(self.blobs.as_ref(), prepared.event()).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Ok(report_activation_failure(
                    "event_object_load",
                    prepared.target(),
                    &error,
                ));
            }
        };
        lease.before_io(shutdown)?;
        let base_bytes = match load_object(self.blobs.as_ref(), prepared.base_context()).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Ok(report_activation_failure(
                    "base_context_object_load",
                    prepared.target(),
                    &error,
                ));
            }
        };
        lease.before_io(shutdown)?;
        let prerequisite_bytes =
            match load_object(self.blobs.as_ref(), prepared.prerequisite_context()).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Ok(report_activation_failure(
                        "prerequisite_context_object_load",
                        prepared.target(),
                        &error,
                    ));
                }
            };

        let plan = match decode_plan(&plan_bytes) {
            Ok(plan) => plan,
            Err(error) => {
                return Ok(report_activation_failure(
                    "plan_decode",
                    prepared.target(),
                    &error,
                ));
            }
        };
        lease.before_io(shutdown)?;
        let permission_ceiling = match self
            .activations
            .reusable_workflow_permission_snapshot(
                prepared.target().tenant(),
                prepared.target().run_id(),
                prepared.target().invocation_id(),
            )
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => return classify_activation_store_failure(&error),
        };
        if plan.logical().invocation().is_some() != permission_ceiling.is_some() {
            return Ok(activation_relational_failure());
        }
        let Ok(validated_plan) = ValidatedLogicalPlan::new(&plan) else {
            return Ok(report_activation_payload_failure(
                "plan_validation",
                prepared.target(),
            ));
        };
        let Ok(logical_job) = validated_plan.job(prepared.logical_key()) else {
            return Ok(report_activation_payload_failure(
                "logical_job_selection",
                prepared.target(),
            ));
        };
        if u16::try_from(logical_job.source_order()).ok() != Some(prepared.source_order()) {
            return Ok(activation_relational_failure());
        }
        let base = match decode_context(&base_bytes, &self.limits) {
            Ok(context) => context,
            Err(error) => {
                return Ok(report_activation_failure(
                    "base_context_decode",
                    prepared.target(),
                    &error,
                ));
            }
        };
        let prerequisites = match decode_context(&prerequisite_bytes, &self.limits) {
            Ok(context) => context,
            Err(error) => {
                return Ok(report_activation_failure(
                    "prerequisite_context_decode",
                    prepared.target(),
                    &error,
                ));
            }
        };
        if let Err(error) = validate_split_contexts(&base, &prerequisites) {
            return Ok(report_activation_failure(
                "context_role_validation",
                prepared.target(),
                &error,
            ));
        }
        let github = match github_activation_context(&plan, prepared.execution(), &event_bytes) {
            Ok(context) => context,
            Err(error) => {
                return Ok(report_activation_failure(
                    "github_context",
                    prepared.target(),
                    &error,
                ));
            }
        };
        let activation_evaluator = GithubLogicalActivationEvaluator::new(github);
        let activator = LogicalJobActivator::new(activation_evaluator.clone());
        let Ok(activation) = activator.activate(ActivateLogicalJobRequest::new(
            logical_job,
            base.inputs(),
            base.vars(),
            prerequisites.needs(),
            base.secrets(),
            prepared.status(),
        )) else {
            return Ok(report_activation_payload_failure(
                "logical_job_activation",
                prepared.target(),
            ));
        };
        let Ok(profiles) = runtime_profile_catalog(prepared.runtime_policy()) else {
            return Ok(activation_relational_failure());
        };
        let runtime_features = if activation.instances().is_empty() {
            std::collections::BTreeSet::new()
        } else {
            let references = match crate::logical_projection::logical_action_references(logical_job)
            {
                Ok(references) => references,
                Err(error) => {
                    return Ok(report_activation_failure(
                        "action_reference_projection",
                        prepared.target(),
                        &GithubLogicalJobOrchestrationError::Projection(error),
                    ));
                }
            };
            let discovery = {
                let mut before_prepare = || lease.before_io(shutdown);
                discover_runtime_requirements(
                    self.actions.as_ref(),
                    &references,
                    shutdown,
                    &mut before_prepare,
                )
                .await
            };
            match discovery {
                Ok(features) => features,
                Err(RuntimeRequirementDiscoveryError::Cancelled) => {
                    return Err(AutonomousWorkflowLeaseError::Shutdown);
                }
                Err(RuntimeRequirementDiscoveryError::Lease(error)) => return Err(error),
                Err(
                    RuntimeRequirementDiscoveryError::Unavailable
                    | RuntimeRequirementDiscoveryError::Retryable,
                ) => return Ok(AutonomousWorkflowExecutionOutcome::Retryable),
                Err(RuntimeRequirementDiscoveryError::Invalid) => {
                    return Ok(report_activation_payload_failure(
                        "runtime_requirement_discovery",
                        prepared.target(),
                    ));
                }
            }
        };
        let Ok(credential_requirements) =
            crate::credential_requirements::discover_external_job_credentials(
                plan.logical(),
                &logical_job,
            )
        else {
            return Ok(report_activation_payload_failure(
                "credential_requirement_discovery",
                prepared.target(),
            ));
        };
        let job_references_secret = !credential_requirements.secret_names().is_empty();
        let (event_trust, source_kind) = trust_gate_evidence(prepared.execution().trust_snapshot());
        let reusable_secret_permission =
            reusable_secret_permission(permission_ceiling.is_some(), job_references_secret);
        let gate_evidence = ActivationGateEvidence {
            event_trust,
            source_kind,
            reusable_secret_permission,
        };

        lease.renew(shutdown).await?;
        if !claim_matches_preparation(
            lease.authority(),
            &prepared,
            claimed.claim().owner(),
            prepared.input_digest(),
        ) {
            return Ok(activation_relational_failure());
        }
        let mut descriptors = Vec::with_capacity(activation.instances().len());
        for instance in activation.instances() {
            let descriptor = match self
                .project_and_publish_selected_instance(
                    lease,
                    shutdown,
                    &prepared,
                    logical_job,
                    instance,
                    &profiles,
                    &runtime_features,
                    &activation_evaluator,
                    permission_ceiling.as_ref(),
                    gate_evidence,
                )
                .await
            {
                Ok(descriptor) => descriptor,
                Err(SelectedActivationFailure::Lease(error)) => return Err(error),
                Err(SelectedActivationFailure::Operation(error)) => {
                    return Ok(report_activation_failure(
                        "instance_projection",
                        prepared.target(),
                        &error,
                    ));
                }
            };
            descriptors.push(descriptor);
            lease.renew(shutdown).await?;
            if !claim_matches_preparation(
                lease.authority(),
                &prepared,
                claimed.claim().owner(),
                prepared.input_digest(),
            ) {
                return Ok(activation_relational_failure());
            }
        }

        let claim = lease.authority().claim().clone();
        let mut published_at = trusted_now(self.clock.as_ref())
            .map_err(|_| AutonomousWorkflowLeaseError::AuthorityRejected)?;
        if published_at < claim.claimed_at() {
            published_at = claim.claimed_at();
        }
        if published_at >= claim.expires_at() {
            return Err(AutonomousWorkflowLeaseError::DeadlineElapsed);
        }
        let Ok(scheduling_policy) = ResolvedLogicalJobSchedulingPolicy::for_claim(
            &claim,
            activation.requested_max_parallel(),
            descriptors.len(),
        ) else {
            return Ok(activation_relational_failure());
        };
        let Ok(publication) = PublishLogicalJobActivation::new_with_scheduling_policy(
            claim,
            activation.condition_matched(),
            descriptors,
            scheduling_policy,
            published_at,
        ) else {
            return Ok(activation_relational_failure());
        };
        let ready = ReadyLogicalJobActivation::new(lease.authority().clone(), publication)?;
        lease.retain_ready_final(ready)?;
        Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady)
    }

    pub(crate) async fn submit_ready_publication(
        &self,
        lease: &AutonomousActivationLease,
    ) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
        let ready = lease.pending_final_request()?;
        if !ready.matches_authority(lease.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        let publication = ready.request();
        match self
            .activations
            .publish_logical_job_activation(publication.clone())
            .await
        {
            Err(LogicalActivationStoreError::Store(StoreError::Operation(_))) => {
                Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation)
            }
            Ok(receipt)
                if receipt
                    == LogicalActivationPublicationReceipt::new(
                        publication,
                        receipt.is_replay(),
                    ) =>
            {
                Ok(AutonomousWorkflowExecutionOutcome::Completed)
            }
            Ok(_) => Ok(activation_relational_failure()),
            Err(error) => classify_activation_store_failure(&error),
        }
    }

    #[allow(clippy::too_many_arguments)] // Lease, exact evidence, and projection policy remain separate trust boundaries.
    async fn project_and_publish_selected_instance(
        &self,
        lease: &AutonomousActivationLease,
        shutdown: &CancellationToken,
        prepared: &PreparedLogicalJobActivation,
        job: crate::ValidatedLogicalJob<'_>,
        instance: &crate::ActivatedJobInstance,
        profiles: &GithubRunnerProfileCatalog,
        runtime_features: &std::collections::BTreeSet<automata_ci_core::RunnerFeature>,
        activation_evaluator: &GithubLogicalActivationEvaluator,
        permission_ceiling: Option<&automata_ci_store::ReusableWorkflowPermissionSnapshot>,
        gate_evidence: ActivationGateEvidence,
    ) -> Result<ActivatedLogicalInstanceDescriptor, SelectedActivationFailure> {
        let (runtime_payload, job_payload) = self
            .project_instance_payloads(
                prepared,
                job,
                instance,
                profiles,
                runtime_features,
                activation_evaluator,
                permission_ceiling,
            )
            .map_err(SelectedActivationFailure::Operation)?;
        let runtime_descriptor = runtime_payload.descriptor().clone();
        let job_descriptor = job_payload.descriptor().clone();
        lease
            .before_io(shutdown)
            .map_err(SelectedActivationFailure::Lease)?;
        self.blobs
            .put_if_absent(runtime_payload)
            .await
            .map_err(GithubLogicalJobOrchestrationError::Blob)
            .map_err(SelectedActivationFailure::Operation)?;
        lease
            .before_io(shutdown)
            .map_err(SelectedActivationFailure::Lease)?;
        self.blobs
            .put_if_absent(job_payload)
            .await
            .map_err(GithubLogicalJobOrchestrationError::Blob)
            .map_err(SelectedActivationFailure::Operation)?;
        activated_instance_descriptor(
            lease.authority(),
            prepared,
            instance,
            &job_descriptor,
            &runtime_descriptor,
            gate_evidence,
        )
        .map_err(SelectedActivationFailure::Operation)
    }

    #[allow(clippy::too_many_arguments)] // Exact activation evidence stays explicit at projection.
    fn project_instance_payloads(
        &self,
        prepared: &PreparedLogicalJobActivation,
        job: crate::ValidatedLogicalJob<'_>,
        instance: &crate::ActivatedJobInstance,
        profiles: &GithubRunnerProfileCatalog,
        runtime_features: &std::collections::BTreeSet<automata_ci_core::RunnerFeature>,
        activation_evaluator: &GithubLogicalActivationEvaluator,
        permission_ceiling: Option<&automata_ci_store::ReusableWorkflowPermissionSnapshot>,
    ) -> Result<(BlobPayload, BlobPayload), GithubLogicalJobOrchestrationError> {
        let runtime_key = instance_object_key(prepared.target(), instance, "runtime-context.pb")?;
        let runtime_bytes = automata_ci_protocol_protobuf::encode_job_runtime_context(
            instance.runtime_context(),
            &self.limits,
        )
        .map_err(|_| GithubLogicalJobOrchestrationError::Encoding)?;
        let runtime_payload = BlobPayload::from_bytes(
            runtime_key,
            MediaType::new(JOB_RUNTIME_CONTEXT_MEDIA_TYPE)
                .map_err(|_| GithubLogicalJobOrchestrationError::Internal)?,
            Bytes::from(runtime_bytes),
        );
        let event_reference = job_content_reference(prepared.event());
        let runtime_reference = descriptor_content_reference(runtime_payload.descriptor());
        let mut execution = JobExecutionContext::new(
            prepared.execution().workflow_name(),
            prepared.execution().git_ref(),
            prepared.workspace(),
            event_reference,
            runtime_reference,
        )
        .with_run_id_alias(prepared.execution().run_id_alias())
        .with_run_number(prepared.execution().run_number())
        .with_run_attempt(prepared.execution().run_attempt());
        if let Some(actor) = prepared.execution().actor() {
            execution = execution.with_actor(actor);
        }
        if let Some(actor) = prepared.execution().triggering_actor() {
            execution = execution.with_triggering_actor(actor);
        }
        let job_id = deterministic_job_id(prepared.target(), instance);
        let mut projection = ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            prepared.execution().workflow_id(),
            prepared.target().run_id(),
            job_id,
            execution,
            profiles,
            prepared.authority_profile(),
            prepared.runtime_policy().policy().permission_policy(),
            prepared.runtime_policy().policy().resource_policy(),
        )
        .with_trust_snapshot(prepared.execution().trust_snapshot())
        .with_runtime_features(runtime_features.iter().cloned())
        .with_activation_evaluation(activation_evaluator, prepared.status());
        if let Some(permission_ceiling) = permission_ceiling {
            projection = projection.with_permission_ceiling(permission_ceiling);
        }
        let projected = GithubLogicalJobProjector::new()
            .project(projection)
            .map_err(GithubLogicalJobOrchestrationError::Projection)?;
        if projected.runtime_context_bytes() != runtime_payload.bytes() {
            return Err(GithubLogicalJobOrchestrationError::EncodingMismatch);
        }

        let job_key = instance_object_key(prepared.target(), instance, "job-ir.pb")?;
        let encoded_job =
            automata_ci_protocol_protobuf::encode_job_ir(projected.envelope(), &self.limits)
                .map_err(|_| GithubLogicalJobOrchestrationError::Encoding)?;
        let job_payload = BlobPayload::from_bytes(
            job_key,
            MediaType::new(LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE)
                .map_err(|_| GithubLogicalJobOrchestrationError::Internal)?,
            Bytes::from(encoded_job),
        );
        Ok((runtime_payload, job_payload))
    }
}

enum SelectedActivationFailure {
    Lease(AutonomousWorkflowLeaseError),
    Operation(GithubLogicalJobOrchestrationError),
}

#[derive(Clone, Copy)]
struct ActivationGateEvidence {
    event_trust: JobEventTrust,
    source_kind: JobSourceKind,
    reusable_secret_permission: ReusableSecretPermission,
}

const fn reusable_secret_permission(
    reusable_invocation: bool,
    job_references_secret: bool,
) -> ReusableSecretPermission {
    if reusable_invocation && job_references_secret {
        ReusableSecretPermission::Explicit
    } else {
        ReusableSecretPermission::None
    }
}

#[cfg(test)]
mod reusable_secret_evidence_tests {
    use super::*;

    #[test]
    fn permission_is_scoped_to_secret_references_in_the_selected_reusable_job() {
        assert_eq!(
            reusable_secret_permission(true, true),
            ReusableSecretPermission::Explicit
        );
        assert_eq!(
            reusable_secret_permission(true, false),
            ReusableSecretPermission::None
        );
        assert_eq!(
            reusable_secret_permission(false, true),
            ReusableSecretPermission::None
        );
    }
}

fn activated_instance_descriptor(
    claimed: &ClaimedLogicalJobActivation,
    prepared: &PreparedLogicalJobActivation,
    instance: &crate::ActivatedJobInstance,
    job_descriptor: &BlobDescriptor,
    runtime_descriptor: &BlobDescriptor,
    gate_evidence: ActivationGateEvidence,
) -> Result<ActivatedLogicalInstanceDescriptor, GithubLogicalJobOrchestrationError> {
    let runtime = logical_activation_object(runtime_descriptor, false)?;
    let job_object = logical_activation_object(job_descriptor, true)?;
    let environment = instance
        .deployment_environment()
        .map(|environment| DeploymentEnvironmentName::new(environment.as_str()))
        .transpose()
        .map_err(|_| GithubLogicalJobOrchestrationError::Internal)?;
    let evidence = JobEnvironmentActivationEvidence::new(
        environment,
        gate_evidence.event_trust,
        gate_evidence.source_kind,
        gate_evidence.reusable_secret_permission,
    );
    ActivatedLogicalInstanceDescriptor::new(
        claimed,
        instance.identity(),
        prepared.workspace(),
        job_object,
        runtime,
        evidence,
    )
    .map_err(GithubLogicalJobOrchestrationError::PersistenceValue)
}

#[derive(Debug, Error)]
pub(crate) enum GithubLogicalJobOrchestrationError {
    /// The selected plan job disagrees with the store-authenticated claim.
    #[error("workflow plan job did not match durable claim evidence")]
    PlanClaimMismatch,
    /// The immutable plan bytes are invalid or not canonical current JSON.
    #[error("workflow plan object is malformed, noncanonical, or unsupported")]
    InvalidPlan,
    /// The immutable provider event cannot form the bounded activation context.
    #[error("provider event object is malformed or exceeds activation limits")]
    InvalidEvent,
    /// A base or prerequisite context is invalid, noncanonical, or in the wrong role.
    #[error("activation context object is malformed, noncanonical, or has the wrong role")]
    InvalidContext,
    /// Projection into current executable `JobIR` failed.
    #[error(transparent)]
    Projection(#[from] LogicalJobProjectionError),
    /// Canonical current protobuf encoding failed.
    #[error("current protobuf object encoding failed")]
    Encoding,
    /// Independently projected runtime-context bytes disagreed.
    #[error("projector runtime-context encoding disagreed with its content reference")]
    EncodingMismatch,
    /// Immutable blob reading or publication failed.
    #[error(transparent)]
    Blob(#[from] BlobStoreError),
    /// Durable activation command construction failed validation.
    #[error(transparent)]
    PersistenceValue(#[from] LogicalActivationValueError),
    /// A server-derived descriptor or identity violated an internal invariant.
    #[error("logical activation internal invariant failed")]
    Internal,
}

const fn activation_relational_failure() -> AutonomousWorkflowExecutionOutcome {
    AutonomousWorkflowExecutionOutcome::EvidenceFailure(
        LogicalWorkQuarantineKind::RelationalEvidence,
    )
}

const fn activation_payload_failure() -> AutonomousWorkflowExecutionOutcome {
    AutonomousWorkflowExecutionOutcome::EvidenceFailure(LogicalWorkQuarantineKind::PayloadEvidence)
}

fn classify_activation_failure(
    error: &GithubLogicalJobOrchestrationError,
) -> AutonomousWorkflowExecutionOutcome {
    match error {
        GithubLogicalJobOrchestrationError::Blob(error) => match error.kind() {
            BlobStoreErrorKind::Unavailable
            | BlobStoreErrorKind::Unauthorized
            | BlobStoreErrorKind::InvalidResponse => AutonomousWorkflowExecutionOutcome::Retryable,
            BlobStoreErrorKind::NotFound
            | BlobStoreErrorKind::Conflict
            | BlobStoreErrorKind::Integrity
            | BlobStoreErrorKind::TooLarge => AutonomousWorkflowExecutionOutcome::EvidenceFailure(
                LogicalWorkQuarantineKind::ObjectEvidence,
            ),
        },
        GithubLogicalJobOrchestrationError::InvalidPlan
        | GithubLogicalJobOrchestrationError::InvalidEvent
        | GithubLogicalJobOrchestrationError::InvalidContext
        | GithubLogicalJobOrchestrationError::Projection(_)
        | GithubLogicalJobOrchestrationError::Encoding
        | GithubLogicalJobOrchestrationError::EncodingMismatch => activation_payload_failure(),
        GithubLogicalJobOrchestrationError::PlanClaimMismatch
        | GithubLogicalJobOrchestrationError::PersistenceValue(_)
        | GithubLogicalJobOrchestrationError::Internal => activation_relational_failure(),
    }
}

fn report_activation_failure(
    stage: &'static str,
    target: &LogicalJobOrchestrationTarget,
    error: &GithubLogicalJobOrchestrationError,
) -> AutonomousWorkflowExecutionOutcome {
    tracing::warn!(
        stage,
        run_id = %target.run_id(),
        logical_job_id = ?target.logical_job_id(),
        %error,
        "logical workflow activation rejected evidence"
    );
    classify_activation_failure(error)
}

fn report_activation_payload_failure(
    stage: &'static str,
    target: &LogicalJobOrchestrationTarget,
) -> AutonomousWorkflowExecutionOutcome {
    tracing::warn!(
        stage,
        run_id = %target.run_id(),
        logical_job_id = ?target.logical_job_id(),
        "logical workflow activation rejected payload evidence"
    );
    activation_payload_failure()
}

fn classify_activation_store_failure(
    error: &LogicalActivationStoreError,
) -> Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError> {
    match error {
        LogicalActivationStoreError::Store(StoreError::Operation(_)) => {
            Ok(AutonomousWorkflowExecutionOutcome::Retryable)
        }
        LogicalActivationStoreError::InvalidTarget | LogicalActivationStoreError::ClaimRejected => {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
        LogicalActivationStoreError::Store(_)
        | LogicalActivationStoreError::InputConflict
        | LogicalActivationStoreError::GenerationExhausted
        | LogicalActivationStoreError::PublicationConflict => Ok(activation_relational_failure()),
    }
}

fn trusted_now(clock: &dyn AdmissionClock) -> Result<UnixMillis, LogicalOrchestrationValueError> {
    let value = clock.now();
    if value.get() < 0 {
        return Err(LogicalOrchestrationValueError::InvalidTimestamp);
    }
    Ok(value)
}

fn claim_matches_preparation(
    claimed: &ClaimedLogicalJobActivation,
    prepared: &PreparedLogicalJobActivation,
    worker: LogicalActivationWorkerId,
    expected_input_digest: Sha256Digest,
) -> bool {
    let claim = claimed.claim();
    claim.tenant() == prepared.target().tenant()
        && claim.run_id() == prepared.target().run_id()
        && claim.invocation_id() == prepared.target().invocation_id()
        && claim.logical_job_id() == prepared.target().logical_job_id()
        && claim.owner() == worker
        && claim.input_digest() == expected_input_digest
        && claimed.logical_key() == prepared.logical_key()
        && claimed.source_order() == prepared.source_order()
        && claimed.kind() == LogicalWorkflowJobKind::Steps
        && claimed.execution() == prepared.execution()
        && claimed.plan() == prepared.plan()
        && claimed.event() == prepared.event()
}

async fn load_object(
    blobs: &dyn ImmutableBlobStore,
    object: &AdmissionObject,
) -> Result<Bytes, GithubLogicalJobOrchestrationError> {
    let descriptor = admission_blob_descriptor(object)?;
    blobs
        .get_verified(&descriptor, object.encoded_size())
        .await
        .map(automata_ci_blob::VerifiedBlob::into_bytes)
        .map_err(GithubLogicalJobOrchestrationError::Blob)
}

fn admission_blob_descriptor(
    object: &AdmissionObject,
) -> Result<BlobDescriptor, GithubLogicalJobOrchestrationError> {
    let key = BlobKey::new(object.object_key().as_str().to_owned())
        .map_err(|_| GithubLogicalJobOrchestrationError::Internal)?;
    let media_type = MediaType::new(object.media_type().to_owned())
        .map_err(|_| GithubLogicalJobOrchestrationError::Internal)?;
    Ok(BlobDescriptor::new(
        key,
        object.digest(),
        object.encoded_size(),
        media_type,
    ))
}

fn decode_plan(bytes: &[u8]) -> Result<WorkflowPlan, GithubLogicalJobOrchestrationError> {
    let plan: WorkflowPlan = serde_json::from_slice(bytes)
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidPlan)?;
    plan.validate()
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidPlan)?;
    let canonical =
        serde_json::to_vec(&plan).map_err(|_| GithubLogicalJobOrchestrationError::InvalidPlan)?;
    if canonical != bytes {
        return Err(GithubLogicalJobOrchestrationError::InvalidPlan);
    }
    Ok(plan)
}

fn decode_context(
    bytes: &[u8],
    limits: &ProtocolLimits,
) -> Result<JobRuntimeContext, GithubLogicalJobOrchestrationError> {
    let context = automata_ci_protocol_protobuf::decode_job_runtime_context(bytes, limits)
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidContext)?;
    let canonical = automata_ci_protocol_protobuf::encode_job_runtime_context(&context, limits)
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidContext)?;
    if canonical != bytes {
        return Err(GithubLogicalJobOrchestrationError::InvalidContext);
    }
    Ok(context)
}

fn validate_split_contexts(
    base: &JobRuntimeContext,
    prerequisites: &JobRuntimeContext,
) -> Result<(), GithubLogicalJobOrchestrationError> {
    let base_shape = base.matrix().as_object().is_some_and(BTreeMap::is_empty)
        && base.needs().is_empty()
        && is_base_strategy(base.strategy());
    let prerequisite_shape = prerequisites
        .inputs()
        .as_object()
        .is_some_and(BTreeMap::is_empty)
        && prerequisites
            .vars()
            .as_object()
            .is_some_and(BTreeMap::is_empty)
        && prerequisites
            .matrix()
            .as_object()
            .is_some_and(BTreeMap::is_empty)
        && prerequisites.secrets().is_empty()
        && is_base_strategy(prerequisites.strategy())
        && prerequisites.needs().values().all(|need| {
            need.outputs().values().all(|output| {
                output.sensitivity() == automata_ci_core::OutputSensitivity::Public
                    || output.expose_value().is_empty()
            })
        });
    if base_shape && prerequisite_shape {
        Ok(())
    } else {
        Err(GithubLogicalJobOrchestrationError::InvalidContext)
    }
}

const fn is_base_strategy(strategy: automata_ci_core::StrategyContext) -> bool {
    strategy.fail_fast()
        && strategy.job_index() == 0
        && strategy.job_total() == 1
        && strategy.max_parallel() == 1
}

pub(crate) fn github_activation_context(
    plan: &WorkflowPlan,
    execution: &LogicalActivationExecutionContext,
    event_bytes: &[u8],
) -> Result<GithubActivationContext, GithubLogicalJobOrchestrationError> {
    let event: serde_json::Value = serde_json::from_slice(event_bytes)
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidEvent)?;
    let PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = plan.source().origin()
    else {
        return Err(GithubLogicalJobOrchestrationError::PlanClaimMismatch);
    };
    let mut values = vec![
        ("event".to_owned(), github_value(event)?),
        (
            "event_name".to_owned(),
            GithubValue::string(plan.event().name()),
        ),
        ("ref".to_owned(), GithubValue::string(execution.git_ref())),
        (
            "repository".to_owned(),
            GithubValue::string(repository.as_str()),
        ),
        (
            "run_id".to_owned(),
            exact_github_integer(execution.run_id_alias().get())?,
        ),
        (
            "run_attempt".to_owned(),
            GithubValue::number(f64::from(execution.run_attempt())),
        ),
        (
            "run_number".to_owned(),
            exact_github_integer(execution.run_number())?,
        ),
        ("sha".to_owned(), GithubValue::string(revision.to_string())),
        (
            "workflow".to_owned(),
            GithubValue::string(execution.workflow_name()),
        ),
        (
            "workflow_ref".to_owned(),
            GithubValue::string(format!("{repository}/{}@{}", path, execution.git_ref())),
        ),
        (
            "workflow_sha".to_owned(),
            GithubValue::string(revision.to_string()),
        ),
    ];
    if let Some(actor) = execution.actor() {
        values.push(("actor".to_owned(), GithubValue::string(actor)));
    }
    if let Some(actor) = execution.triggering_actor().or_else(|| execution.actor()) {
        values.push(("triggering_actor".to_owned(), GithubValue::string(actor)));
    }
    let object =
        GithubObject::new(values).map_err(|_| GithubLogicalJobOrchestrationError::InvalidEvent)?;
    GithubActivationContext::new(GithubValue::object(object))
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidEvent)
}

const fn trust_gate_evidence(snapshot: &TrustSnapshot) -> (JobEventTrust, JobSourceKind) {
    match snapshot.source_class() {
        TrustSourceClass::SameRepository => (JobEventTrust::Trusted, JobSourceKind::SameRepository),
        TrustSourceClass::Dependabot | TrustSourceClass::Automation => {
            (JobEventTrust::Untrusted, JobSourceKind::Dependabot)
        }
        // The durable job gate has no `incomplete` variant. Snapshot authority is
        // authoritative and denies environments/secrets; `fork` is retained
        // only as a conservative storage-compatible projection.
        TrustSourceClass::Fork | TrustSourceClass::MergeQueue | TrustSourceClass::Incomplete => {
            (JobEventTrust::Untrusted, JobSourceKind::Fork)
        }
    }
}

#[cfg(test)]
mod source_evidence_tests {
    use automata_ci_core::{
        TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence,
        TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSourceClass,
        TrustTokenRecursion,
    };

    use super::*;

    fn actor(automation: TrustAutomationKind) -> TrustActorEvidence {
        TrustActorEvidence::new("100", TrustActorKind::User, automation).expect("valid actor")
    }

    fn repository(id: &str) -> TrustRepositoryEvidence {
        TrustRepositoryEvidence::new(id, "7").expect("valid repository")
    }

    fn same_repository_push(automation: TrustAutomationKind) -> TrustSnapshot {
        TrustPolicy::current()
            .evaluate(
                TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                    .with_original_actor(actor(automation))
                    .with_repositories(repository("42"), repository("42"))
                    .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                    .with_revisions("source", "target", "execution")
                    .with_fork(false)
                    .with_token_recursion(TrustTokenRecursion::Suppressed),
            )
            .expect("valid push trust")
    }

    fn merge_queue() -> TrustSnapshot {
        TrustPolicy::current()
            .evaluate(
                TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::MergeGroup)
                    .with_original_actor(actor(TrustAutomationKind::None))
                    .with_repositories(repository("42"), repository("42"))
                    .with_refs(
                        "refs/heads/gh-readonly-queue/main/pr-7",
                        "refs/heads/main",
                        "refs/heads/gh-readonly-queue/main/pr-7",
                    )
                    .with_revisions("group", "target", "group")
                    .with_fork(false)
                    .with_token_recursion(TrustTokenRecursion::Suppressed),
            )
            .expect("valid merge-queue trust")
    }

    #[test]
    fn exact_github_integer_limit_has_exact_boundaries() {
        assert_eq!(
            exact_github_integer_rejection(MAX_EXACT_GITHUB_INTEGER - 1),
            None
        );
        assert_eq!(
            exact_github_integer_rejection(MAX_EXACT_GITHUB_INTEGER),
            None
        );
        assert_eq!(
            exact_github_integer_rejection(MAX_EXACT_GITHUB_INTEGER + 1),
            Some(GithubOrchestrationLimitRejection::ExactInteger)
        );
    }

    #[test]
    fn job_gate_is_only_a_projection_of_the_exact_snapshot() {
        let trusted = same_repository_push(TrustAutomationKind::None);
        assert_eq!(
            trust_gate_evidence(&trusted),
            (JobEventTrust::Trusted, JobSourceKind::SameRepository)
        );

        let automation = same_repository_push(TrustAutomationKind::Other);
        assert_eq!(automation.source_class(), TrustSourceClass::Automation);
        assert_eq!(
            trust_gate_evidence(&automation),
            (JobEventTrust::Untrusted, JobSourceKind::Dependabot)
        );

        let merge_queue = merge_queue();
        assert_eq!(merge_queue.source_class(), TrustSourceClass::MergeQueue);
        assert_eq!(
            trust_gate_evidence(&merge_queue),
            (JobEventTrust::Untrusted, JobSourceKind::Fork)
        );

        let incomplete = TrustPolicy::current()
            .evaluate(TrustEvidence::new(
                TrustOriginKind::ProviderWebhook,
                TrustEventKind::Push,
            ))
            .expect("missing evidence fails closed");
        assert_eq!(incomplete.source_class(), TrustSourceClass::Incomplete);
        assert_eq!(
            trust_gate_evidence(&incomplete),
            (JobEventTrust::Untrusted, JobSourceKind::Fork)
        );
    }
}

fn exact_github_integer(value: u64) -> Result<GithubValue, GithubLogicalJobOrchestrationError> {
    if exact_github_integer_rejection(value).is_some() {
        return Err(GithubLogicalJobOrchestrationError::InvalidEvent);
    }
    value
        .to_string()
        .parse::<f64>()
        .map(GithubValue::number)
        .map_err(|_| GithubLogicalJobOrchestrationError::InvalidEvent)
}

fn github_value(
    value: serde_json::Value,
) -> Result<GithubValue, GithubLogicalJobOrchestrationError> {
    match value {
        serde_json::Value::Null => Ok(GithubValue::Null),
        serde_json::Value::Bool(value) => Ok(GithubValue::Boolean(value)),
        serde_json::Value::Number(value) => value
            .as_f64()
            .map(GithubValue::number)
            .ok_or(GithubLogicalJobOrchestrationError::InvalidEvent),
        serde_json::Value::String(value) => Ok(GithubValue::string(value)),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(github_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|values| {
                GithubValue::array(values)
                    .map_err(|_| GithubLogicalJobOrchestrationError::InvalidEvent)
            }),
        serde_json::Value::Object(values) => {
            let entries = values
                .into_iter()
                .map(|(key, value)| github_value(value).map(|value| (key, value)))
                .collect::<Result<Vec<_>, _>>()?;
            GithubObject::new(entries)
                .map(GithubValue::object)
                .map_err(|_| GithubLogicalJobOrchestrationError::InvalidEvent)
        }
    }
}

fn instance_object_key(
    target: &LogicalJobOrchestrationTarget,
    instance: &crate::ActivatedJobInstance,
    name: &str,
) -> Result<BlobKey, GithubLogicalJobOrchestrationError> {
    BlobKey::new(format!(
        "logical-activation/v2/{}/{}/{}/{:08}-{}-{name}",
        target.run_id(),
        target.invocation_id().as_uuid(),
        target.logical_job_id().as_uuid(),
        instance.identity().matrix_index(),
        instance.identity().matrix_digest(),
    ))
    .map_err(|_| GithubLogicalJobOrchestrationError::Internal)
}

fn deterministic_job_id(
    target: &LogicalJobOrchestrationTarget,
    instance: &crate::ActivatedJobInstance,
) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(JOB_ID_DOMAIN);
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.invocation_id().as_uuid().as_bytes());
    hasher.update(target.logical_job_id().as_uuid().as_bytes());
    hasher.update(instance.identity().matrix_index().to_be_bytes());
    hasher.update(instance.identity().matrix_total().to_be_bytes());
    hasher.update(instance.identity().matrix_digest().as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    JobId::from_uuid(Uuid::from_bytes(bytes))
}

fn job_content_reference(object: &AdmissionObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}

fn descriptor_content_reference(descriptor: &BlobDescriptor) -> JobContentReference {
    JobContentReference::new(
        descriptor.key().as_str(),
        descriptor.digest(),
        descriptor.size(),
        descriptor.media_type().as_str(),
    )
}

fn logical_activation_object(
    descriptor: &BlobDescriptor,
    is_job_ir: bool,
) -> Result<LogicalActivationObject, GithubLogicalJobOrchestrationError> {
    let key = ObjectKey::new(descriptor.key().as_str().to_owned())
        .map_err(|_| GithubLogicalJobOrchestrationError::Internal)?;
    if is_job_ir {
        LogicalActivationObject::job_ir(descriptor.digest(), key, descriptor.size())
    } else {
        LogicalActivationObject::runtime_context(descriptor.digest(), key, descriptor.size())
    }
    .map_err(GithubLogicalJobOrchestrationError::PersistenceValue)
}
