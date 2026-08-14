//! Repository-local reusable-workflow publication and completion contracts.
//!
//! Reusable call jobs are coordinators, never runnable jobs.  Publication
//! copies one exact preplanned child graph into logical orchestration under an
//! immutable, credential-free runtime-context descriptor.  Completion binds
//! an exact child plan and finalized child result set, then produces the normal
//! parent logical-job result that unlocks `needs`.

use async_trait::async_trait;
use std::collections::BTreeMap;

use automata_ci_core::{
    InvocationInputType, JOB_RUNTIME_CONTEXT_MEDIA_TYPE, OutputSensitivity, PermissionLevel, RunId,
    Sha256Digest, UnixMillis, WorkflowJobKey, WorkflowOutputKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmissionObject, AdmittedReusableInputKind, LogicalActivationPreparationDescriptor,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, RepositoryId, StoreError, TenantScope,
    WorkflowRuntimePolicyPin,
};

const CALL_INSTANCE_ID_DOMAIN: &[u8] = b"automata.store.reusable-call-instance.v1\0";
const OUTPUT_MAPPING_DIGEST_DOMAIN: &[u8] = b"automata.store.reusable-output-mappings.v1\0";
const PUBLICATION_DIGEST_DOMAIN: &[u8] = b"automata.store.reusable-publication.v1\0";
const EVALUATED_OUTPUTS_DIGEST_DOMAIN: &[u8] = b"automata.store.reusable-evaluated-outputs.v1\0";

/// Maximum caller-visible or callee-declared outputs at one call boundary.
pub const MAX_REUSABLE_CALL_OUTPUTS: usize = 256;

/// One immutable input-binding row used to verify runtime evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowInputBindingEvidence {
    key: String,
    input_type: InvocationInputType,
    kind: AdmittedReusableInputKind,
    value_digest: Option<Sha256Digest>,
}

impl ReusableWorkflowInputBindingEvidence {
    /// Creates one typed input-evidence row returned by a repository adapter.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        input_type: InvocationInputType,
        kind: AdmittedReusableInputKind,
        value_digest: Option<Sha256Digest>,
    ) -> Self {
        Self {
            key: key.into(),
            input_type,
            kind,
            value_digest,
        }
    }

    /// Returns the callee input key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the declared callee type.
    #[must_use]
    pub const fn input_type(&self) -> InvocationInputType {
        self.input_type
    }

    /// Returns why this binding obtains a value.
    #[must_use]
    pub const fn kind(&self) -> AdmittedReusableInputKind {
        self.kind
    }

    /// Returns the exact source-value digest when one is present.
    #[must_use]
    pub const fn value_digest(&self) -> Option<Sha256Digest> {
        self.value_digest
    }
}

/// One immutable name-only secret forwarding edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowSecretBindingEvidence {
    target: String,
    source: String,
}

impl ReusableWorkflowSecretBindingEvidence {
    /// Creates one name-only secret edge returned by a repository adapter.
    #[must_use]
    pub fn new(target: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            source: source.into(),
        }
    }

    /// Returns the secret name visible to the callee.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the caller-side opaque secret binding name.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Immutable least-authority permission ceiling for one child invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowPermissionSnapshot {
    default_level: PermissionLevel,
    grants: BTreeMap<String, PermissionLevel>,
    digest: Sha256Digest,
}

impl ReusableWorkflowPermissionSnapshot {
    /// Creates one exact digest-bound permission snapshot returned by an adapter.
    #[must_use]
    pub fn new(
        default_level: PermissionLevel,
        grants: BTreeMap<String, PermissionLevel>,
        digest: Sha256Digest,
    ) -> Self {
        Self {
            default_level,
            grants,
            digest,
        }
    }

    /// Returns the level used for an unlisted permission scope.
    #[must_use]
    pub const fn default_level(&self) -> PermissionLevel {
        self.default_level
    }

    /// Returns normalized explicit scope overrides.
    #[must_use]
    pub const fn grants(&self) -> &BTreeMap<String, PermissionLevel> {
        &self.grants
    }

    /// Resolves a permission scope against the immutable snapshot.
    #[must_use]
    pub fn level(&self, name: &str) -> PermissionLevel {
        self.grants.get(name).copied().unwrap_or(self.default_level)
    }

    /// Returns the exact admission-bound snapshot digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Dependency-ready, unclaimed reusable call selected from immutable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyReusableWorkflowCall {
    repository_id: RepositoryId,
    preparation: LogicalActivationPreparationDescriptor,
    child_invocation_id: LogicalWorkflowInvocationId,
    child_plan: AdmissionObject,
    inputs: Vec<ReusableWorkflowInputBindingEvidence>,
    secrets: Vec<ReusableWorkflowSecretBindingEvidence>,
    permissions: ReusableWorkflowPermissionSnapshot,
}

impl ReadyReusableWorkflowCall {
    /// Creates one dependency-ready call selected from exact durable evidence.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        repository_id: RepositoryId,
        preparation: LogicalActivationPreparationDescriptor,
        child_invocation_id: LogicalWorkflowInvocationId,
        child_plan: AdmissionObject,
        inputs: Vec<ReusableWorkflowInputBindingEvidence>,
        secrets: Vec<ReusableWorkflowSecretBindingEvidence>,
        permissions: ReusableWorkflowPermissionSnapshot,
    ) -> Self {
        Self {
            repository_id,
            preparation,
            child_invocation_id,
            child_plan,
            inputs,
            secrets,
            permissions,
        }
    }

    /// Returns the owning repository.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns exact parent activation evidence and prerequisite results.
    #[must_use]
    pub const fn preparation(&self) -> &LogicalActivationPreparationDescriptor {
        &self.preparation
    }

    /// Returns the one preplanned child invocation.
    #[must_use]
    pub const fn child_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.child_invocation_id
    }

    /// Returns the exact callee plan object.
    #[must_use]
    pub const fn child_plan(&self) -> &AdmissionObject {
        &self.child_plan
    }

    /// Returns source-ordered typed input evidence.
    #[must_use]
    pub fn inputs(&self) -> &[ReusableWorkflowInputBindingEvidence] {
        &self.inputs
    }

    /// Returns source-ordered name-only secret edges.
    #[must_use]
    pub fn secrets(&self) -> &[ReusableWorkflowSecretBindingEvidence] {
        &self.secrets
    }

    /// Returns the child permission ceiling.
    #[must_use]
    pub const fn permissions(&self) -> &ReusableWorkflowPermissionSnapshot {
        &self.permissions
    }
}

/// One finalized child logical-job output visible to workflow output evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowResultOutput {
    job_key: WorkflowJobKey,
    output_name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

impl ReusableWorkflowResultOutput {
    /// Creates one finalized child output without interpreting its value.
    #[must_use]
    pub const fn new(
        job_key: WorkflowJobKey,
        output_name: WorkflowOutputKey,
        sensitivity: OutputSensitivity,
        public_value: Option<String>,
    ) -> Self {
        Self {
            job_key,
            output_name,
            sensitivity,
            public_value,
        }
    }

    /// Returns the child logical job key.
    #[must_use]
    pub const fn job_key(&self) -> &WorkflowJobKey {
        &self.job_key
    }

    /// Returns the child job output key.
    #[must_use]
    pub const fn output_name(&self) -> &WorkflowOutputKey {
        &self.output_name
    }

    /// Returns the durable sensitivity classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns public data only; secret-derived bytes are absent.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }
}

/// Sealed publication whose child results are complete and immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyReusableWorkflowCompletion {
    publication: PublishReusableWorkflowCall,
    child_plan: AdmissionObject,
    outputs: Vec<ReusableWorkflowResultOutput>,
    ready_at: UnixMillis,
}

impl ReadyReusableWorkflowCompletion {
    /// Creates one completion candidate from a sealed publication and results.
    #[must_use]
    pub fn new(
        publication: PublishReusableWorkflowCall,
        child_plan: AdmissionObject,
        outputs: Vec<ReusableWorkflowResultOutput>,
        ready_at: UnixMillis,
    ) -> Self {
        Self {
            publication,
            child_plan,
            outputs,
            ready_at,
        }
    }

    /// Returns the exact durable publication to complete.
    #[must_use]
    pub const fn publication(&self) -> &PublishReusableWorkflowCall {
        &self.publication
    }

    /// Returns the exact digest-bound child plan.
    #[must_use]
    pub const fn child_plan(&self) -> &AdmissionObject {
        &self.child_plan
    }

    /// Returns all finalized child job outputs ordered by job and output.
    #[must_use]
    pub fn outputs(&self) -> &[ReusableWorkflowResultOutput] {
        &self.outputs
    }

    /// Returns a deterministic time no earlier than every consumed result.
    #[must_use]
    pub const fn ready_at(&self) -> UnixMillis {
        self.ready_at
    }
}

/// Non-nil idempotency identity for publication or completion.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReusableWorkflowOperationId(Uuid);

impl ReusableWorkflowOperationId {
    /// Constructs a non-nil operation identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, ReusableWorkflowRuntimeValueError> {
        if value.is_nil() {
            return Err(ReusableWorkflowRuntimeValueError::NilUuid(
                "reusable workflow operation ID",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the durable UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// One parent output alias bound to an exact callee workflow output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableCallOutputMapping {
    parent_name: WorkflowOutputKey,
    callee_name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
}

impl ReusableCallOutputMapping {
    /// Constructs one validated alias.
    #[must_use]
    pub const fn new(
        parent_name: WorkflowOutputKey,
        callee_name: WorkflowOutputKey,
        sensitivity: OutputSensitivity,
    ) -> Self {
        Self {
            parent_name,
            callee_name,
            sensitivity,
        }
    }

    /// Returns the parent call-job output name.
    #[must_use]
    pub const fn parent_name(&self) -> &WorkflowOutputKey {
        &self.parent_name
    }

    /// Returns the callee workflow output name.
    #[must_use]
    pub const fn callee_name(&self) -> &WorkflowOutputKey {
        &self.callee_name
    }

    /// Returns the non-reducing sensitivity exposed by the parent.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }
}

/// Exact request to publish one non-runnable reusable call and child graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReusableWorkflowCall {
    tenant: TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    parent_invocation_id: LogicalWorkflowInvocationId,
    caller_logical_job_id: LogicalWorkflowJobId,
    caller_instance_id: Uuid,
    child_invocation_id: LogicalWorkflowInvocationId,
    operation_id: ReusableWorkflowOperationId,
    activation_input_digest: Sha256Digest,
    condition_matched: bool,
    matrix_digest: Sha256Digest,
    runtime_context: AdmissionObject,
    permission_digest: Sha256Digest,
    output_mappings: Vec<ReusableCallOutputMapping>,
    output_mapping_digest: Sha256Digest,
    runtime_policy: WorkflowRuntimePolicyPin,
    publication_digest: Sha256Digest,
    published_at: UnixMillis,
}

impl PublishReusableWorkflowCall {
    /// Binds one parent call instance to its exact planned child graph.
    ///
    /// `runtime_context` must use the current protobuf metadata schema.
    /// The object contains evaluated public context and name-only secret
    /// bindings, never a `JobIR` or runnable command.
    ///
    /// # Errors
    ///
    /// Rejects cross-scope policy evidence, invalid object metadata, duplicate
    /// output aliases, too many mappings, nil identities, or negative time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        run_id: RunId,
        parent_invocation_id: LogicalWorkflowInvocationId,
        caller_logical_job_id: LogicalWorkflowJobId,
        child_invocation_id: LogicalWorkflowInvocationId,
        operation_id: ReusableWorkflowOperationId,
        activation_input_digest: Sha256Digest,
        condition_matched: bool,
        matrix_digest: Sha256Digest,
        runtime_context: AdmissionObject,
        permission_digest: Sha256Digest,
        output_mappings: Vec<ReusableCallOutputMapping>,
        runtime_policy: WorkflowRuntimePolicyPin,
        published_at: UnixMillis,
    ) -> Result<Self, ReusableWorkflowRuntimeValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(ReusableWorkflowRuntimeValueError::NilUuid(
                "workflow run ID",
            ));
        }
        if runtime_policy.tenant() != &tenant || runtime_policy.repository_id() != repository_id {
            return Err(ReusableWorkflowRuntimeValueError::RuntimePolicyMismatch);
        }
        if runtime_context.media_type() != JOB_RUNTIME_CONTEXT_MEDIA_TYPE {
            return Err(ReusableWorkflowRuntimeValueError::InvalidRuntimeContext);
        }
        if published_at.get() < 0 {
            return Err(ReusableWorkflowRuntimeValueError::NegativeTimestamp);
        }
        if output_mappings.len() > MAX_REUSABLE_CALL_OUTPUTS {
            return Err(ReusableWorkflowRuntimeValueError::TooManyOutputs);
        }
        let mut parent_names = std::collections::BTreeSet::new();
        if output_mappings
            .iter()
            .any(|mapping| !parent_names.insert(mapping.parent_name().clone()))
        {
            return Err(ReusableWorkflowRuntimeValueError::DuplicateOutput);
        }
        let caller_instance_id = derive_call_instance_id(
            run_id,
            parent_invocation_id,
            caller_logical_job_id,
            child_invocation_id,
        );
        let output_mapping_digest = output_mapping_digest(&output_mappings);
        let publication_digest = publication_digest(
            run_id,
            parent_invocation_id,
            caller_logical_job_id,
            caller_instance_id,
            child_invocation_id,
            operation_id,
            activation_input_digest,
            condition_matched,
            matrix_digest,
            &runtime_context,
            permission_digest,
            output_mapping_digest,
            &runtime_policy,
            published_at,
        );
        Ok(Self {
            tenant,
            repository_id,
            run_id,
            parent_invocation_id,
            caller_logical_job_id,
            caller_instance_id,
            child_invocation_id,
            operation_id,
            activation_input_digest,
            condition_matched,
            matrix_digest,
            runtime_context,
            permission_digest,
            output_mappings,
            output_mapping_digest,
            runtime_policy,
            publication_digest,
            published_at,
        })
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the workflow run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the parent invocation.
    #[must_use]
    pub const fn parent_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.parent_invocation_id
    }

    /// Returns the parent reusable call job.
    #[must_use]
    pub const fn caller_logical_job_id(&self) -> LogicalWorkflowJobId {
        self.caller_logical_job_id
    }

    /// Returns the deterministic non-runnable call-instance identity.
    #[must_use]
    pub const fn caller_instance_id(&self) -> Uuid {
        self.caller_instance_id
    }

    /// Returns the exact planned child invocation.
    #[must_use]
    pub const fn child_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.child_invocation_id
    }

    /// Returns the idempotency identity.
    #[must_use]
    pub const fn operation_id(&self) -> ReusableWorkflowOperationId {
        self.operation_id
    }

    /// Returns the exact activation inputs digest.
    #[must_use]
    pub const fn activation_input_digest(&self) -> Sha256Digest {
        self.activation_input_digest
    }

    /// Reports whether the parent call condition selected the child.
    #[must_use]
    pub const fn condition_matched(&self) -> bool {
        self.condition_matched
    }

    /// Returns the exact empty/non-matrix identity digest.
    #[must_use]
    pub const fn matrix_digest(&self) -> Sha256Digest {
        self.matrix_digest
    }

    /// Returns the credential-free runtime-context descriptor.
    #[must_use]
    pub const fn runtime_context(&self) -> &AdmissionObject {
        &self.runtime_context
    }

    /// Returns the effective least-authority permission digest.
    #[must_use]
    pub const fn permission_digest(&self) -> Sha256Digest {
        self.permission_digest
    }

    /// Returns parent/callee output aliases in source order.
    #[must_use]
    pub fn output_mappings(&self) -> &[ReusableCallOutputMapping] {
        &self.output_mappings
    }

    /// Returns the exact ordered output-alias digest.
    #[must_use]
    pub const fn output_mapping_digest(&self) -> Sha256Digest {
        self.output_mapping_digest
    }

    /// Returns the pinned runtime policy.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicyPin {
        &self.runtime_policy
    }

    /// Returns the canonical replay digest.
    #[must_use]
    pub const fn publication_digest(&self) -> Sha256Digest {
        self.publication_digest
    }

    /// Returns the trusted publication time.
    #[must_use]
    pub const fn published_at(&self) -> UnixMillis {
        self.published_at
    }
}

/// One workflow output evaluated from an exact child plan and result context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedReusableWorkflowOutput {
    name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

impl EvaluatedReusableWorkflowOutput {
    /// Constructs one evaluated output without retaining secret-derived bytes.
    ///
    /// # Errors
    ///
    /// Public outputs require a value of at most 2 MiB. Secret-derived outputs
    /// must not carry plaintext.
    pub fn new(
        name: WorkflowOutputKey,
        sensitivity: OutputSensitivity,
        public_value: Option<String>,
    ) -> Result<Self, ReusableWorkflowRuntimeValueError> {
        match (sensitivity, &public_value) {
            (OutputSensitivity::Public, Some(value)) if value.len() <= 2 * 1024 * 1024 => {}
            (OutputSensitivity::SecretDerived, None) => {}
            _ => return Err(ReusableWorkflowRuntimeValueError::InvalidOutput),
        }
        Ok(Self {
            name,
            sensitivity,
            public_value,
        })
    }

    /// Returns the callee workflow output name.
    #[must_use]
    pub const fn name(&self) -> &WorkflowOutputKey {
        &self.name
    }

    /// Returns its declared sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns public data only; secret-derived data is never retained here.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }
}

/// Exact request to roll one sealed child invocation into its parent job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteReusableWorkflowCall {
    publication: PublishReusableWorkflowCall,
    operation_id: ReusableWorkflowOperationId,
    callee_plan_digest: Sha256Digest,
    workflow_output_evaluation_digest: Sha256Digest,
    outputs: Vec<EvaluatedReusableWorkflowOutput>,
    outputs_digest: Sha256Digest,
    completed_at: UnixMillis,
}

impl CompleteReusableWorkflowCall {
    /// Binds outputs evaluated from the exact callee plan to one publication.
    ///
    /// # Errors
    ///
    /// Rejects an operation replay identity collision, duplicate/oversized
    /// outputs, or completion before publication.
    pub fn new(
        publication: PublishReusableWorkflowCall,
        operation_id: ReusableWorkflowOperationId,
        callee_plan_digest: Sha256Digest,
        workflow_output_evaluation_digest: Sha256Digest,
        outputs: Vec<EvaluatedReusableWorkflowOutput>,
        completed_at: UnixMillis,
    ) -> Result<Self, ReusableWorkflowRuntimeValueError> {
        if operation_id == publication.operation_id() {
            return Err(ReusableWorkflowRuntimeValueError::OperationReuse);
        }
        if outputs.len() > MAX_REUSABLE_CALL_OUTPUTS {
            return Err(ReusableWorkflowRuntimeValueError::TooManyOutputs);
        }
        let mut names = std::collections::BTreeSet::new();
        if outputs
            .iter()
            .any(|output| !names.insert(output.name().clone()))
        {
            return Err(ReusableWorkflowRuntimeValueError::DuplicateOutput);
        }
        if completed_at < publication.published_at() {
            return Err(ReusableWorkflowRuntimeValueError::CompletionBeforePublication);
        }
        let outputs_digest = evaluated_outputs_digest(&outputs);
        Ok(Self {
            publication,
            operation_id,
            callee_plan_digest,
            workflow_output_evaluation_digest,
            outputs,
            outputs_digest,
            completed_at,
        })
    }

    /// Returns the exact publication being completed.
    #[must_use]
    pub const fn publication(&self) -> &PublishReusableWorkflowCall {
        &self.publication
    }

    /// Returns the completion idempotency identity.
    #[must_use]
    pub const fn operation_id(&self) -> ReusableWorkflowOperationId {
        self.operation_id
    }

    /// Returns the exact loaded callee plan digest.
    #[must_use]
    pub const fn callee_plan_digest(&self) -> Sha256Digest {
        self.callee_plan_digest
    }

    /// Returns the evaluator input/output digest.
    #[must_use]
    pub const fn workflow_output_evaluation_digest(&self) -> Sha256Digest {
        self.workflow_output_evaluation_digest
    }

    /// Returns evaluated callee outputs in contract order.
    #[must_use]
    pub fn outputs(&self) -> &[EvaluatedReusableWorkflowOutput] {
        &self.outputs
    }

    /// Returns the exact evaluated output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the trusted completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
}

/// Exact immutable publication acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowPublicationReceipt {
    caller_instance_id: Uuid,
    child_invocation_id: LogicalWorkflowInvocationId,
    publication_digest: Sha256Digest,
    published_at: UnixMillis,
    replayed: bool,
}

impl ReusableWorkflowPublicationReceipt {
    /// Derives an acknowledgement from the exact request an adapter persisted.
    #[must_use]
    pub const fn new(request: &PublishReusableWorkflowCall, replayed: bool) -> Self {
        Self {
            caller_instance_id: request.caller_instance_id(),
            child_invocation_id: request.child_invocation_id(),
            publication_digest: request.publication_digest(),
            published_at: request.published_at(),
            replayed,
        }
    }

    /// Returns the stable call-instance identity.
    #[must_use]
    pub const fn caller_instance_id(&self) -> Uuid {
        self.caller_instance_id
    }

    /// Returns the exact planned child identity.
    #[must_use]
    pub const fn child_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.child_invocation_id
    }

    /// Returns the canonical publication digest.
    #[must_use]
    pub const fn publication_digest(&self) -> Sha256Digest {
        self.publication_digest
    }

    /// Returns the publication time.
    #[must_use]
    pub const fn published_at(&self) -> UnixMillis {
        self.published_at
    }

    /// Reports an exact durable replay.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Exact immutable completion acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowCompletionReceipt {
    caller_instance_id: Uuid,
    child_invocation_id: LogicalWorkflowInvocationId,
    outputs_digest: Sha256Digest,
    completed_at: UnixMillis,
    replayed: bool,
}

impl ReusableWorkflowCompletionReceipt {
    /// Derives an acknowledgement from the exact request an adapter persisted.
    #[must_use]
    pub const fn new(request: &CompleteReusableWorkflowCall, replayed: bool) -> Self {
        Self {
            caller_instance_id: request.publication().caller_instance_id(),
            child_invocation_id: request.publication().child_invocation_id(),
            outputs_digest: request.outputs_digest(),
            completed_at: request.completed_at(),
            replayed,
        }
    }

    /// Returns the stable parent-call identity.
    #[must_use]
    pub const fn caller_instance_id(&self) -> Uuid {
        self.caller_instance_id
    }

    /// Returns the completed child invocation.
    #[must_use]
    pub const fn child_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.child_invocation_id
    }

    /// Returns the exact evaluated callee output digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    /// Reports an exact durable replay.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Store port for reusable call publication and completion transactions.
#[async_trait]
pub trait ReusableWorkflowRuntimeRepository: Send + Sync {
    /// Selects one dependency-ready, unpublished reusable call.
    async fn next_reusable_workflow_call(
        &self,
    ) -> Result<Option<ReadyReusableWorkflowCall>, ReusableWorkflowRuntimeStoreError>;

    /// Selects one sealed call whose complete child result set is immutable.
    async fn next_reusable_workflow_completion(
        &self,
    ) -> Result<Option<ReadyReusableWorkflowCompletion>, ReusableWorkflowRuntimeStoreError>;

    /// Publishes or exactly replays one sealed child graph.
    async fn publish_reusable_workflow_call(
        &self,
        request: PublishReusableWorkflowCall,
    ) -> Result<ReusableWorkflowPublicationReceipt, ReusableWorkflowRuntimeStoreError>;

    /// Completes or exactly replays one call and its parent logical result.
    async fn complete_reusable_workflow_call(
        &self,
        request: CompleteReusableWorkflowCall,
    ) -> Result<ReusableWorkflowCompletionReceipt, ReusableWorkflowRuntimeStoreError>;
}

/// Invalid bounded reusable runtime request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReusableWorkflowRuntimeValueError {
    /// A durable UUID used the nil sentinel.
    #[error("{0} must not be nil")]
    NilUuid(&'static str),
    /// Runtime policy evidence belongs to another scope.
    #[error("reusable workflow runtime policy scope does not match")]
    RuntimePolicyMismatch,
    /// The immutable runtime-context descriptor is not current.
    #[error("reusable workflow runtime context is invalid")]
    InvalidRuntimeContext,
    /// A trusted timestamp preceded the Unix epoch.
    #[error("reusable workflow runtime timestamp is invalid")]
    NegativeTimestamp,
    /// A call exceeded the fixed output count.
    #[error("reusable workflow call has too many outputs")]
    TooManyOutputs,
    /// An output namespace contains a duplicate name.
    #[error("reusable workflow output name is duplicated")]
    DuplicateOutput,
    /// Output sensitivity and retained value disagree.
    #[error("reusable workflow output value is invalid")]
    InvalidOutput,
    /// Completion and publication reused one operation identity.
    #[error("reusable workflow completion must use a distinct operation ID")]
    OperationReuse,
    /// Completion preceded its immutable publication.
    #[error("reusable workflow completion precedes publication")]
    CompletionBeforePublication,
}

/// Sanitized durable reusable runtime failure.
#[derive(Debug, Error)]
pub enum ReusableWorkflowRuntimeStoreError {
    /// The relational backend failed or returned malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The callsite is absent, cross-scope, stale, or not dependency-ready.
    #[error("reusable workflow call target is not ready")]
    NotReady,
    /// A prior operation or callsite row disagrees with this exact request.
    #[error("reusable workflow request conflicts with durable evidence")]
    Conflict,
    /// Completion is waiting for every child logical result.
    #[error("reusable workflow child results are not complete")]
    ChildResultsPending,
}

fn derive_call_instance_id(
    run_id: RunId,
    parent_invocation_id: LogicalWorkflowInvocationId,
    caller_logical_job_id: LogicalWorkflowJobId,
    child_invocation_id: LogicalWorkflowInvocationId,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(CALL_INSTANCE_ID_DOMAIN);
    for value in [
        run_id.as_uuid(),
        parent_invocation_id.as_uuid(),
        caller_logical_job_id.as_uuid(),
        child_invocation_id.as_uuid(),
    ] {
        hash_part(&mut hasher, value.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn output_mapping_digest(mappings: &[ReusableCallOutputMapping]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(OUTPUT_MAPPING_DIGEST_DOMAIN);
    hash_usize(&mut hasher, mappings.len());
    for mapping in mappings {
        hash_part(&mut hasher, mapping.parent_name().as_str().as_bytes());
        hash_part(&mut hasher, mapping.callee_name().as_str().as_bytes());
        hash_part(&mut hasher, sensitivity_name(mapping.sensitivity()));
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn publication_digest(
    run_id: RunId,
    parent_invocation_id: LogicalWorkflowInvocationId,
    caller_logical_job_id: LogicalWorkflowJobId,
    caller_instance_id: Uuid,
    child_invocation_id: LogicalWorkflowInvocationId,
    operation_id: ReusableWorkflowOperationId,
    activation_input_digest: Sha256Digest,
    condition_matched: bool,
    matrix_digest: Sha256Digest,
    runtime_context: &AdmissionObject,
    permission_digest: Sha256Digest,
    output_mapping_digest: Sha256Digest,
    runtime_policy: &WorkflowRuntimePolicyPin,
    published_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(PUBLICATION_DIGEST_DOMAIN);
    for value in [
        run_id.as_uuid(),
        parent_invocation_id.as_uuid(),
        caller_logical_job_id.as_uuid(),
        caller_instance_id,
        child_invocation_id.as_uuid(),
        operation_id.as_uuid(),
    ] {
        hash_part(&mut hasher, value.as_bytes());
    }
    hash_part(&mut hasher, activation_input_digest.as_bytes());
    hasher.update([u8::from(condition_matched)]);
    hash_part(&mut hasher, matrix_digest.as_bytes());
    hash_part(&mut hasher, runtime_context.digest().as_bytes());
    hash_part(
        &mut hasher,
        runtime_context.object_key().as_str().as_bytes(),
    );
    hasher.update(runtime_context.encoded_size().to_be_bytes());
    hash_part(&mut hasher, permission_digest.as_bytes());
    hash_part(&mut hasher, output_mapping_digest.as_bytes());
    hasher.update(runtime_policy.revision().get().to_be_bytes());
    hash_part(&mut hasher, runtime_policy.digest().as_bytes());
    hasher.update(published_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn evaluated_outputs_digest(outputs: &[EvaluatedReusableWorkflowOutput]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(EVALUATED_OUTPUTS_DIGEST_DOMAIN);
    hash_usize(&mut hasher, outputs.len());
    for output in outputs {
        hash_part(&mut hasher, output.name().as_str().as_bytes());
        hash_part(&mut hasher, sensitivity_name(output.sensitivity()));
        match output.public_value() {
            Some(value) => {
                hasher.update([1]);
                hash_part(&mut hasher, value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

const fn sensitivity_name(value: OutputSensitivity) -> &'static [u8] {
    match value {
        OutputSensitivity::Public => b"public",
        OutputSensitivity::SecretDerived => b"secret_derived",
    }
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hash_usize(hasher: &mut Sha256, value: usize) {
    hasher.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_instance_identity_is_deterministic_and_domain_bound() {
        let run_id = RunId::from_uuid(Uuid::from_u128(1));
        let parent = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("parent");
        let caller = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("caller");
        let child = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(4)).expect("child");
        let first = derive_call_instance_id(run_id, parent, caller, child);
        assert_eq!(
            first,
            derive_call_instance_id(run_id, parent, caller, child)
        );
        assert_ne!(
            first,
            derive_call_instance_id(run_id, parent, caller, parent)
        );
        assert_eq!(first.get_version_num(), 8);
    }
}
