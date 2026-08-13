//! Durable preparation of exact current logical-job activation inputs.
//!
//! Preparation pins the immutable plan, event, execution metadata, direct
//! prerequisite logical results, classified outputs, transitive status, and a
//! trusted workspace-policy output before any activation claim can be issued.
//! Blob reads and writes remain outside this repository boundary.

use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use crate::{
    AdmissionObject, GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    LogicalActivationExecutionContext, LogicalActivationWorkerId, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, PinnedWorkflowRuntimePolicy, StoreError, TenantScope,
    WORKFLOW_PLAN_SCHEMA,
};
use async_trait::async_trait;
use automata_ci_core::{
    JobAuthorityProfile, JobConclusion, MAX_JOB_RESULT_OUTPUT_UTF16_BYTES, MAX_LOGICAL_JOB_NEEDS,
    MAX_LOGICAL_JOB_OUTPUTS, OutputSensitivity, RunId, Sha256Digest, UnixMillis, WorkflowJobKey,
    WorkflowOutputKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Exact current `WorkflowPlan` object media type accepted by preparation.
pub const LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE: &str =
    "application/vnd.automata.workflow-plan+json";
/// Exact current provider-event media type accepted by preparation.
pub const LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE: &str =
    automata_ci_core::WORKFLOW_EVENT_MEDIA_TYPE;
/// Maximum duration of one preparation claim.
pub const MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;

const DESCRIPTOR_DOMAIN: &[u8] = b"automata.store.logical-activation-preparation.v5\0";
const PREREQUISITES_DOMAIN: &[u8] =
    b"automata.store.logical-activation-preparation-prerequisites.v1\0";
const ACTIVATION_INPUT_DIGEST_DOMAIN: &[u8] =
    b"automata.workflow-service.logical-activation-input.v5\0";

/// Exact tenant-scoped logical job selected for activation preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationPreparationTarget {
    tenant: TenantScope,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
}

impl LogicalActivationPreparationTarget {
    /// Constructs one exact current target.
    ///
    /// # Errors
    ///
    /// Rejects the nil workflow-run sentinel.
    pub fn new(
        tenant: TenantScope,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(LogicalActivationPreparationValueError::NilRunId);
        }
        Ok(Self {
            tenant,
            run_id,
            invocation_id,
            logical_job_id,
        })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the workflow-run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the invocation identity.
    #[must_use]
    pub const fn invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.invocation_id
    }

    /// Returns the logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }
}

/// Canonical workspace selected by a trusted server workspace policy.
///
/// This value is deliberately absent from the public orchestration request.
/// A production preparation adapter obtains it from server-owned policy and
/// the durable claim binds it to the exact target and prerequisite evidence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalActivationPreparationWorkspace(String);

impl LogicalActivationPreparationWorkspace {
    /// Validates one absolute, normalized workspace-policy output.
    ///
    /// # Errors
    ///
    /// Rejects empty, relative, traversal-bearing, control-bearing, or
    /// oversized paths.
    pub fn new(value: impl Into<String>) -> Result<Self, LogicalActivationPreparationValueError> {
        let value = value.into();
        validate_workspace(&value)?;
        Ok(Self(value))
    }

    /// Returns the canonical path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Current base-context authority supported by this preparation phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalActivationBaseContextKind {
    /// Canonical `JobRuntimeContext` object admitted with the root invocation.
    Admission,
}

/// Full transitive prerequisite status bound to activation functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalActivationAggregateStatus {
    /// No failure, cancellation, or skip exists in the prerequisite closure.
    Success,
    /// Failure or timeout exists anywhere in the prerequisite closure.
    Failure,
    /// Cancellation exists in the closure and no failure exists.
    Cancelled,
    /// A skipped job exists in the closure and no failure/cancellation exists.
    Skipped,
}

/// One sensitivity-safe output pinned from a prerequisite logical result.
#[derive(Clone, Eq, PartialEq)]
pub struct LogicalActivationPrerequisiteOutput {
    name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
}

impl fmt::Debug for LogicalActivationPrerequisiteOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalActivationPrerequisiteOutput")
            .field("name", &self.name)
            .field("sensitivity", &self.sensitivity)
            .field(
                "public_value",
                &self.public_value.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl LogicalActivationPrerequisiteOutput {
    /// Rehydrates one exact classified logical output.
    ///
    /// Public values may be empty. Secret-derived outputs must be value-free.
    ///
    /// # Errors
    ///
    /// Rejects classification/value disagreement or an oversized public value.
    pub fn new(
        name: WorkflowOutputKey,
        sensitivity: OutputSensitivity,
        public_value: Option<String>,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        match (sensitivity, public_value.as_deref()) {
            (OutputSensitivity::Public, Some(value))
                if value.encode_utf16().count().saturating_mul(2)
                    <= MAX_JOB_RESULT_OUTPUT_UTF16_BYTES => {}
            (OutputSensitivity::SecretDerived, None) => {}
            _ => {
                return Err(LogicalActivationPreparationValueError::InvalidPrerequisiteOutput);
            }
        }
        Ok(Self {
            name,
            sensitivity,
            public_value,
        })
    }

    /// Returns the canonical output name.
    #[must_use]
    pub const fn name(&self) -> &WorkflowOutputKey {
        &self.name
    }

    /// Returns the exact output classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns plaintext only for a public output. The value may be empty.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }
}

/// Exact immutable logical-result evidence for one direct prerequisite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationPrerequisiteEvidence {
    logical_job_id: LogicalWorkflowJobId,
    logical_key: WorkflowJobKey,
    source_order: u16,
    result_descriptor_digest: Sha256Digest,
    outputs_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    outputs: Vec<LogicalActivationPrerequisiteOutput>,
    finalized_at: UnixMillis,
}

impl LogicalActivationPrerequisiteEvidence {
    /// Rehydrates one finalized direct prerequisite and all declared outputs.
    ///
    /// # Errors
    ///
    /// Rejects malformed closure flags, unordered/duplicate outputs, excessive
    /// outputs, an invalid source order, or a negative finalization time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        logical_job_id: LogicalWorkflowJobId,
        logical_key: WorkflowJobKey,
        source_order: u16,
        result_descriptor_digest: Sha256Digest,
        outputs_digest: Sha256Digest,
        commit_digest: Sha256Digest,
        effective_conclusion: JobConclusion,
        closure_has_failure: bool,
        closure_has_cancelled: bool,
        closure_has_skipped: bool,
        mut outputs: Vec<LogicalActivationPrerequisiteOutput>,
        finalized_at: UnixMillis,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        if source_order > 1_023 || outputs.len() > MAX_LOGICAL_JOB_OUTPUTS {
            return Err(LogicalActivationPreparationValueError::InvalidPrerequisite);
        }
        validate_timestamp(finalized_at, "prerequisite finalization time")?;
        let own_failure = matches!(
            effective_conclusion,
            JobConclusion::Failure | JobConclusion::TimedOut
        );
        if (own_failure && !closure_has_failure)
            || (effective_conclusion == JobConclusion::Cancelled && !closure_has_cancelled)
            || (effective_conclusion == JobConclusion::Skipped && !closure_has_skipped)
        {
            return Err(LogicalActivationPreparationValueError::InvalidPrerequisite);
        }
        outputs.sort_by(|left, right| left.name().cmp(right.name()));
        if outputs
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(LogicalActivationPreparationValueError::InvalidPrerequisiteOutput);
        }
        Ok(Self {
            logical_job_id,
            logical_key,
            source_order,
            result_descriptor_digest,
            outputs_digest,
            commit_digest,
            effective_conclusion,
            closure_has_failure,
            closure_has_cancelled,
            closure_has_skipped,
            outputs,
            finalized_at,
        })
    }

    /// Returns the direct prerequisite logical-job identity.
    #[must_use]
    pub const fn logical_job_id(&self) -> LogicalWorkflowJobId {
        self.logical_job_id
    }

    /// Returns the direct prerequisite source key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    /// Returns the prerequisite's canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Returns the exact prerequisite result descriptor digest.
    #[must_use]
    pub const fn result_descriptor_digest(&self) -> Sha256Digest {
        self.result_descriptor_digest
    }

    /// Returns the exact prerequisite output-set digest.
    #[must_use]
    pub const fn outputs_digest(&self) -> Sha256Digest {
        self.outputs_digest
    }

    /// Returns the exact prerequisite commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }

    /// Returns the prerequisite's own effective conclusion.
    #[must_use]
    pub const fn effective_conclusion(&self) -> JobConclusion {
        self.effective_conclusion
    }

    /// Reports failure or timeout anywhere in the prerequisite closure.
    #[must_use]
    pub const fn closure_has_failure(&self) -> bool {
        self.closure_has_failure
    }

    /// Reports cancellation anywhere in the prerequisite closure.
    #[must_use]
    pub const fn closure_has_cancelled(&self) -> bool {
        self.closure_has_cancelled
    }

    /// Reports a skipped job anywhere in the prerequisite closure.
    #[must_use]
    pub const fn closure_has_skipped(&self) -> bool {
        self.closure_has_skipped
    }

    /// Returns every declared output in canonical name order.
    #[must_use]
    pub fn outputs(&self) -> &[LogicalActivationPrerequisiteOutput] {
        &self.outputs
    }

    /// Returns the durable logical-result finalization time.
    #[must_use]
    pub const fn finalized_at(&self) -> UnixMillis {
        self.finalized_at
    }
}

/// Store-authenticated immutable evidence pinned by a preparation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationPreparationDescriptor {
    target: LogicalActivationPreparationTarget,
    logical_key: WorkflowJobKey,
    source_order: u16,
    execution: LogicalActivationExecutionContext,
    authority_profile: JobAuthorityProfile,
    runner_policy: AdmissionObject,
    runtime_policy: PinnedWorkflowRuntimePolicy,
    plan: AdmissionObject,
    event: AdmissionObject,
    base_context_kind: LogicalActivationBaseContextKind,
    base_context: AdmissionObject,
    workspace: LogicalActivationPreparationWorkspace,
    prerequisites: Vec<LogicalActivationPrerequisiteEvidence>,
    prerequisites_digest: Sha256Digest,
    status: LogicalActivationAggregateStatus,
    evidence_ready_at: UnixMillis,
    descriptor_digest: Sha256Digest,
}

impl LogicalActivationPreparationDescriptor {
    /// Constructs a canonical current root-invocation preparation descriptor.
    ///
    /// # Errors
    ///
    /// Rejects non-current objects, duplicate prerequisite identity/key/order,
    /// invalid source/time bounds, or an excessive direct prerequisite set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: LogicalActivationPreparationTarget,
        logical_key: WorkflowJobKey,
        source_order: u16,
        execution: LogicalActivationExecutionContext,
        authority_profile: JobAuthorityProfile,
        runner_policy: AdmissionObject,
        runtime_policy: PinnedWorkflowRuntimePolicy,
        plan: AdmissionObject,
        event: AdmissionObject,
        base_context_kind: LogicalActivationBaseContextKind,
        base_context: AdmissionObject,
        mut prerequisites: Vec<LogicalActivationPrerequisiteEvidence>,
        durable_ready_at: UnixMillis,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        if source_order > 1_023 {
            return Err(LogicalActivationPreparationValueError::InvalidSourceOrder);
        }
        if runtime_policy.run_id() != target.run_id()
            || runtime_policy.pin().tenant() != target.tenant()
        {
            return Err(LogicalActivationPreparationValueError::InvalidRuntimePolicy);
        }
        let canonical_size = runtime_policy
            .policy()
            .canonical_bytes()
            .map_err(|_| LogicalActivationPreparationValueError::InvalidRuntimePolicy)?
            .len();
        let expected_object_key = format!(
            "github/runner-policy/v1/{}.json",
            runtime_policy.policy().canonical_digest()
        );
        if runner_policy.media_type() != GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE
            || runner_policy.encoded_size() > GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES
            || runner_policy.digest() != runtime_policy.policy().canonical_digest()
            || u64::try_from(canonical_size).ok() != Some(runner_policy.encoded_size())
            || runner_policy.object_key().as_str() != expected_object_key
        {
            return Err(LogicalActivationPreparationValueError::InvalidRunnerPolicyObject);
        }
        let workspace = runtime_policy
            .policy()
            .derive_workspace(
                target.run_id(),
                target.invocation_id(),
                target.logical_job_id(),
            )
            .map_err(|_| LogicalActivationPreparationValueError::InvalidRuntimePolicy)?;
        if plan.media_type() != LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE
            || event.media_type() != LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE
            || base_context.media_type() != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
        {
            return Err(LogicalActivationPreparationValueError::InvalidObject);
        }
        if prerequisites.len() > MAX_LOGICAL_JOB_NEEDS {
            return Err(LogicalActivationPreparationValueError::InvalidPrerequisiteSet);
        }
        validate_timestamp(durable_ready_at, "preparation durable-ready time")?;
        prerequisites.sort_by_key(LogicalActivationPrerequisiteEvidence::source_order);
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut orders = BTreeSet::new();
        if prerequisites.iter().any(|prerequisite| {
            !ids.insert(prerequisite.logical_job_id())
                || !keys.insert(prerequisite.logical_key().clone())
                || !orders.insert(prerequisite.source_order())
        }) {
            return Err(LogicalActivationPreparationValueError::InvalidPrerequisiteSet);
        }
        let prerequisites_digest = prerequisites_digest(&prerequisites);
        let status = aggregate_status(&prerequisites);
        let evidence_ready_at = prerequisites
            .iter()
            .map(LogicalActivationPrerequisiteEvidence::finalized_at)
            .fold(durable_ready_at, std::cmp::max);
        let descriptor_digest = descriptor_digest(
            &target,
            &logical_key,
            source_order,
            &execution,
            authority_profile,
            &runner_policy,
            &runtime_policy,
            &plan,
            &event,
            base_context_kind,
            &base_context,
            &workspace,
            prerequisites_digest,
            status,
            evidence_ready_at,
        );
        Ok(Self {
            target,
            logical_key,
            source_order,
            execution,
            authority_profile,
            runner_policy,
            runtime_policy,
            plan,
            event,
            base_context_kind,
            base_context,
            workspace,
            prerequisites,
            prerequisites_digest,
            status,
            evidence_ready_at,
            descriptor_digest,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalActivationPreparationTarget {
        &self.target
    }

    /// Returns the exact source-level job key.
    #[must_use]
    pub const fn logical_key(&self) -> &WorkflowJobKey {
        &self.logical_key
    }

    /// Returns the canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Returns exact store-authenticated execution metadata.
    #[must_use]
    pub const fn execution(&self) -> &LogicalActivationExecutionContext {
        &self.execution
    }

    /// Returns the exact historical manifest authority profile.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    /// Returns the exact historical runner/workspace policy object.
    #[must_use]
    pub const fn runner_policy(&self) -> &AdmissionObject {
        &self.runner_policy
    }

    /// Returns the exact structured runtime policy pinned when the run was admitted.
    #[must_use]
    pub const fn runtime_policy(&self) -> &PinnedWorkflowRuntimePolicy {
        &self.runtime_policy
    }

    /// Returns the exact current plan descriptor.
    #[must_use]
    pub const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    /// Returns the exact provider-event descriptor.
    #[must_use]
    pub const fn event(&self) -> &AdmissionObject {
        &self.event
    }

    /// Returns the explicit supported base-context authority.
    #[must_use]
    pub const fn base_context_kind(&self) -> LogicalActivationBaseContextKind {
        self.base_context_kind
    }

    /// Returns the exact admission-time base runtime-context descriptor.
    #[must_use]
    pub const fn base_context(&self) -> &AdmissionObject {
        &self.base_context
    }

    /// Returns the exact trusted workspace-policy output.
    #[must_use]
    pub const fn workspace(&self) -> &LogicalActivationPreparationWorkspace {
        &self.workspace
    }

    /// Returns source-ordered direct prerequisite evidence.
    #[must_use]
    pub fn prerequisites(&self) -> &[LogicalActivationPrerequisiteEvidence] {
        &self.prerequisites
    }

    /// Returns the digest of complete ordered prerequisite evidence.
    #[must_use]
    pub const fn prerequisites_digest(&self) -> Sha256Digest {
        self.prerequisites_digest
    }

    /// Returns full-closure aggregate status.
    #[must_use]
    pub const fn status(&self) -> LogicalActivationAggregateStatus {
        self.status
    }

    /// Returns the latest durable time among all pinned evidence.
    #[must_use]
    pub const fn evidence_ready_at(&self) -> UnixMillis {
        self.evidence_ready_at
    }

    /// Returns the canonical descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
}

/// Request to acquire or take over one exact preparation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLogicalActivationPreparation {
    target: LogicalActivationPreparationTarget,
    owner: LogicalActivationWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimLogicalActivationPreparation {
    /// Constructs a bounded server-side preparation request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or overlong claim interval.
    pub fn new(
        target: LogicalActivationPreparationTarget,
        owner: LogicalActivationWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        validate_claim_interval(observed_at, expires_at)?;
        Ok(Self {
            target,
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalActivationPreparationTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalActivationWorkerId {
        self.owner
    }

    /// Returns the trusted observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the requested expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Positive monotonic generation of one preparation claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalActivationPreparationGeneration(NonZeroU64);

impl LogicalActivationPreparationGeneration {
    /// Constructs a positive generation representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalActivationPreparationValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(LogicalActivationPreparationValueError::InvalidGeneration)?;
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.get()).expect("validated preparation generation fits i64")
    }
}

/// Exact live proof required to bind prepared context descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationPreparationClaimFence {
    target: LogicalActivationPreparationTarget,
    owner: LogicalActivationWorkerId,
    generation: LogicalActivationPreparationGeneration,
    descriptor_digest: Sha256Digest,
    selection_origin: crate::LogicalWorkSelectionId,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl LogicalActivationPreparationClaimFence {
    /// Rehydrates inert selector-origin fence evidence for a repository adapter.
    ///
    /// Construction does not confer durable authority. Renew, bind, and
    /// quarantine operations still compare every field under repository locks.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_selection(
        target: LogicalActivationPreparationTarget,
        owner: LogicalActivationWorkerId,
        generation: LogicalActivationPreparationGeneration,
        descriptor_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
        selection_origin: crate::LogicalWorkSelectionId,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        validate_claim_interval(claimed_at, expires_at)?;
        Ok(Self {
            target,
            owner,
            generation,
            descriptor_digest,
            selection_origin,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &LogicalActivationPreparationTarget {
        &self.target
    }

    /// Returns the claim owner.
    #[must_use]
    pub const fn owner(&self) -> LogicalActivationWorkerId {
        self.owner
    }

    /// Returns the monotonic generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalActivationPreparationGeneration {
        self.generation
    }

    /// Returns the exact pinned descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the mandatory exact selector origin.
    #[must_use]
    pub const fn selection_origin(&self) -> crate::LogicalWorkSelectionId {
        self.selection_origin
    }

    /// Returns the durable claim start.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the durable claim expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Immutable evidence returned under one live preparation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedLogicalActivationPreparation {
    descriptor: LogicalActivationPreparationDescriptor,
    claim: LogicalActivationPreparationClaimFence,
    replayed: bool,
}

impl ClaimedLogicalActivationPreparation {
    /// Binds one descriptor to an exact repository-issued fence.
    ///
    /// # Errors
    ///
    /// Rejects target/digest disagreement or a claim preceding its evidence.
    pub fn new(
        descriptor: LogicalActivationPreparationDescriptor,
        claim: LogicalActivationPreparationClaimFence,
        replayed: bool,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        if claim.target() != descriptor.target()
            || claim.descriptor_digest() != descriptor.descriptor_digest()
        {
            return Err(LogicalActivationPreparationValueError::ClaimDescriptorMismatch);
        }
        if claim.claimed_at() < descriptor.evidence_ready_at() {
            return Err(LogicalActivationPreparationValueError::ClaimBeforeEvidence);
        }
        Ok(Self {
            descriptor,
            claim,
            replayed,
        })
    }

    /// Returns the exact store-authenticated descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalActivationPreparationDescriptor {
        &self.descriptor
    }

    /// Returns the live preparation fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationPreparationClaimFence {
        &self.claim
    }

    /// Reports whether the exact claim request was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Request to replace one live preparation fence with its next generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewLogicalActivationPreparation {
    claim: LogicalActivationPreparationClaimFence,
    duration_ms: i64,
}

impl RenewLogicalActivationPreparation {
    /// Constructs one bounded, extending preparation renewal.
    ///
    /// # Errors
    ///
    /// Rejects a stale/non-extending observation or an overlong interval.
    pub fn new(
        claim: LogicalActivationPreparationClaimFence,
        duration_ms: i64,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        if !(crate::MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS
            ..=MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS)
            .contains(&duration_ms)
        {
            return Err(LogicalActivationPreparationValueError::InvalidRenewalInterval);
        }
        Ok(Self { claim, duration_ms })
    }

    /// Returns the exact current fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationPreparationClaimFence {
        &self.claim
    }

    /// Returns the requested database-issued renewal duration.
    #[must_use]
    pub const fn duration_ms(&self) -> i64 {
        self.duration_ms
    }
}

/// Non-authorizing acknowledgement of one exact preparation renewal.
///
/// This value is immutable receipt evidence, not a current claim. Callers must
/// consume the retained work selection again before continuing with a fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewedLogicalActivationPreparation {
    request: RenewLogicalActivationPreparation,
    successor_generation: LogicalActivationPreparationGeneration,
    successor_claimed_at: UnixMillis,
    successor_expires_at: UnixMillis,
    validated_at: UnixMillis,
}

impl RenewedLogicalActivationPreparation {
    /// Constructs exact, non-authorizing renewal acknowledgement evidence.
    ///
    /// # Errors
    ///
    /// Rejects a non-selector predecessor, a generation skip, or successor
    /// times that do not exactly describe the requested extending interval.
    pub fn new(
        request: RenewLogicalActivationPreparation,
        successor_generation: LogicalActivationPreparationGeneration,
        successor_claimed_at: UnixMillis,
        successor_expires_at: UnixMillis,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        let predecessor = request.claim();
        let expected_generation = predecessor
            .generation()
            .get()
            .checked_add(1)
            .and_then(|value| LogicalActivationPreparationGeneration::new(value).ok());
        if expected_generation != Some(successor_generation)
            || successor_claimed_at < predecessor.claimed_at()
            || successor_claimed_at >= predecessor.expires_at()
            || successor_expires_at <= predecessor.expires_at()
            || successor_expires_at
                .get()
                .checked_sub(successor_claimed_at.get())
                != Some(request.duration_ms())
            || validated_at < successor_claimed_at
            || validated_at >= successor_expires_at
        {
            return Err(LogicalActivationPreparationValueError::InvalidRenewalInterval);
        }
        Ok(Self {
            request,
            successor_generation,
            successor_claimed_at,
            successor_expires_at,
            validated_at,
        })
    }

    /// Returns the exact request acknowledged by this receipt.
    #[must_use]
    pub const fn request(&self) -> &RenewLogicalActivationPreparation {
        &self.request
    }

    /// Returns the immutable predecessor fence named by the request.
    #[must_use]
    pub const fn predecessor(&self) -> &LogicalActivationPreparationClaimFence {
        self.request.claim()
    }

    /// Returns the acknowledged successor generation.
    #[must_use]
    pub const fn successor_generation(&self) -> LogicalActivationPreparationGeneration {
        self.successor_generation
    }

    /// Returns the acknowledged successor claim start.
    #[must_use]
    pub const fn successor_claimed_at(&self) -> UnixMillis {
        self.successor_claimed_at
    }

    /// Returns the acknowledged successor expiration.
    #[must_use]
    pub const fn successor_expires_at(&self) -> UnixMillis {
        self.successor_expires_at
    }

    /// Returns the immutable database validation time stored with the receipt.
    #[must_use]
    pub const fn validated_at(&self) -> UnixMillis {
        self.validated_at
    }
}

/// Exact prepared context descriptors bound under a live fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindLogicalActivationPreparation {
    descriptor: LogicalActivationPreparationDescriptor,
    claim: LogicalActivationPreparationClaimFence,
    base_context: AdmissionObject,
    prerequisite_context: AdmissionObject,
    input_digest: Sha256Digest,
    bound_at: UnixMillis,
}

impl BindLogicalActivationPreparation {
    /// Constructs a sensitivity-safe immutable binding request.
    ///
    /// The input digest is derived internally from the exact descriptor and
    /// context objects; callers cannot supply it independently.
    ///
    /// # Errors
    ///
    /// Rejects descriptor/fence disagreement, non-current context objects,
    /// object aliasing, or binding outside the live fence.
    pub fn new(
        descriptor: LogicalActivationPreparationDescriptor,
        claim: LogicalActivationPreparationClaimFence,
        base_context: AdmissionObject,
        prerequisite_context: AdmissionObject,
        bound_at: UnixMillis,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        if claim.target() != descriptor.target()
            || claim.descriptor_digest() != descriptor.descriptor_digest()
        {
            return Err(LogicalActivationPreparationValueError::ClaimDescriptorMismatch);
        }
        if &base_context != descriptor.base_context()
            || base_context.media_type() != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
            || prerequisite_context.media_type() != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE
            || base_context.object_key() == prerequisite_context.object_key()
        {
            return Err(LogicalActivationPreparationValueError::InvalidContextObject);
        }
        validate_timestamp(bound_at, "preparation binding time")?;
        if bound_at < claim.claimed_at() || bound_at >= claim.expires_at() {
            return Err(LogicalActivationPreparationValueError::BindOutsideClaim);
        }
        let input_digest =
            activation_input_digest(&descriptor, &base_context, &prerequisite_context);
        Ok(Self {
            descriptor,
            claim,
            base_context,
            prerequisite_context,
            input_digest,
            bound_at,
        })
    }

    /// Returns the exact immutable evidence descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalActivationPreparationDescriptor {
        &self.descriptor
    }

    /// Returns the live binding fence.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationPreparationClaimFence {
        &self.claim
    }

    /// Returns the exact admission-bound base-context object.
    #[must_use]
    pub const fn base_context(&self) -> &AdmissionObject {
        &self.base_context
    }

    /// Returns the canonical direct-prerequisite context object.
    #[must_use]
    pub const fn prerequisite_context(&self) -> &AdmissionObject {
        &self.prerequisite_context
    }

    /// Returns the exact activation-input digest derived by the store domain.
    #[must_use]
    pub const fn input_digest(&self) -> Sha256Digest {
        self.input_digest
    }

    /// Returns the trusted binding time.
    #[must_use]
    pub const fn bound_at(&self) -> UnixMillis {
        self.bound_at
    }
}

/// Immutable receipt for one bound logical activation preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalActivationPreparationReceipt {
    descriptor: LogicalActivationPreparationDescriptor,
    claim: LogicalActivationPreparationClaimFence,
    base_context: AdmissionObject,
    prerequisite_context: AdmissionObject,
    input_digest: Sha256Digest,
    bound_at: UnixMillis,
    replayed: bool,
}

impl LogicalActivationPreparationReceipt {
    /// Constructs an exact receipt from one validated binding request.
    #[must_use]
    pub fn new(request: &BindLogicalActivationPreparation, replayed: bool) -> Self {
        Self {
            descriptor: request.descriptor.clone(),
            claim: request.claim.clone(),
            base_context: request.base_context.clone(),
            prerequisite_context: request.prerequisite_context.clone(),
            input_digest: request.input_digest,
            bound_at: request.bound_at,
            replayed,
        }
    }

    /// Rehydrates exact durable binding evidence and recomputes its digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed objects, time/fence disagreement, or a different
    /// durable input digest.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable(
        descriptor: LogicalActivationPreparationDescriptor,
        claim: LogicalActivationPreparationClaimFence,
        base_context: AdmissionObject,
        prerequisite_context: AdmissionObject,
        input_digest: Sha256Digest,
        bound_at: UnixMillis,
        replayed: bool,
    ) -> Result<Self, LogicalActivationPreparationValueError> {
        let request = BindLogicalActivationPreparation::new(
            descriptor,
            claim,
            base_context,
            prerequisite_context,
            bound_at,
        )?;
        if request.input_digest() != input_digest {
            return Err(LogicalActivationPreparationValueError::InputDigestMismatch);
        }
        Ok(Self::new(&request, replayed))
    }

    /// Returns the exact immutable preparation descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &LogicalActivationPreparationDescriptor {
        &self.descriptor
    }

    /// Returns the fence that won immutable binding.
    #[must_use]
    pub const fn claim(&self) -> &LogicalActivationPreparationClaimFence {
        &self.claim
    }

    /// Returns the exact base-context descriptor.
    #[must_use]
    pub const fn base_context(&self) -> &AdmissionObject {
        &self.base_context
    }

    /// Returns the exact prerequisite-context descriptor.
    #[must_use]
    pub const fn prerequisite_context(&self) -> &AdmissionObject {
        &self.prerequisite_context
    }

    /// Returns the activation-input digest accepted by the activation claim.
    #[must_use]
    pub const fn input_digest(&self) -> Sha256Digest {
        self.input_digest
    }

    /// Returns the durable binding time.
    #[must_use]
    pub const fn bound_at(&self) -> UnixMillis {
        self.bound_at
    }

    /// Reports whether prior immutable evidence was replayed.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Outcome of attempting to acquire one preparation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum LogicalActivationPreparationClaimOutcome {
    /// Every direct prerequisite is finalized and the claim was acquired.
    Claimed(ClaimedLogicalActivationPreparation),
    /// The target is current but prerequisite evidence is incomplete.
    NotReady,
    /// Another worker owns the unexpired claim.
    Busy,
    /// Immutable context descriptors were already bound.
    Prepared(LogicalActivationPreparationReceipt),
}

/// Invalid logical activation preparation value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalActivationPreparationValueError {
    /// The workflow run used the nil sentinel.
    #[error("workflow run ID must not be nil")]
    NilRunId,
    /// A trusted time preceded the Unix epoch.
    #[error("{0} must not precede the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// A claim interval was empty or exceeded its bound.
    #[error("logical activation preparation claim interval is invalid")]
    InvalidClaimInterval,
    /// A renewal did not extend the exact live claim.
    #[error("logical activation preparation renewal interval is invalid")]
    InvalidRenewalInterval,
    /// A claim generation was zero or exceeded `BIGINT`.
    #[error("logical activation preparation generation is invalid")]
    InvalidGeneration,
    /// A source order exceeded the current plan bound.
    #[error("logical activation preparation source order is invalid")]
    InvalidSourceOrder,
    /// The plan or event object was not current.
    #[error("logical activation preparation object is invalid")]
    InvalidObject,
    /// The historical runner-policy descriptor is absent, excessive, or non-current.
    #[error("logical activation runner-policy object is invalid")]
    InvalidRunnerPolicyObject,
    /// The structured runtime policy was absent or disagreed with the run pin.
    #[error("logical activation runtime policy is invalid")]
    InvalidRuntimePolicy,
    /// The workspace-policy output was not canonical.
    #[error("logical activation preparation workspace is invalid")]
    InvalidWorkspace,
    /// A prerequisite evidence row was malformed.
    #[error("logical activation prerequisite evidence is invalid")]
    InvalidPrerequisite,
    /// The direct prerequisite set was malformed or duplicated.
    #[error("logical activation prerequisite set is invalid")]
    InvalidPrerequisiteSet,
    /// A classified prerequisite output was malformed.
    #[error("logical activation prerequisite output is invalid")]
    InvalidPrerequisiteOutput,
    /// A claim did not bind the supplied descriptor.
    #[error("logical activation preparation claim does not bind its descriptor")]
    ClaimDescriptorMismatch,
    /// A claim began before all immutable evidence was ready.
    #[error("logical activation preparation claim precedes its evidence")]
    ClaimBeforeEvidence,
    /// A context object was non-current or aliased the other context.
    #[error("logical activation preparation context object is invalid")]
    InvalidContextObject,
    /// Binding fell outside the exact live claim.
    #[error("logical activation preparation binding falls outside its claim")]
    BindOutsideClaim,
    /// Durable input digest disagreed with exact recomputation.
    #[error("logical activation preparation input digest is invalid")]
    InputDigestMismatch,
}

/// Durable preparation claim or binding failure.
#[derive(Debug, Error)]
pub enum LogicalActivationPreparationStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The target is absent, cross-tenant, non-root, non-current, or non-step.
    #[error("logical activation preparation target is invalid")]
    InvalidTarget,
    /// A durable claim pinned a different workspace or evidence descriptor.
    #[error("logical activation preparation conflicts with durable evidence")]
    PreparationConflict,
    /// The monotonic claim generation cannot advance.
    #[error("logical activation preparation generation is exhausted")]
    GenerationExhausted,
    /// Renewal or binding did not own the exact current fence.
    #[error("logical activation preparation fence was rejected")]
    ClaimRejected,
    /// Binding disagreed with immutable durable preparation evidence.
    #[error("logical activation preparation binding conflicts with durable evidence")]
    BindConflict,
}

/// Persistence boundary for current logical activation preparation.
#[async_trait]
pub trait LogicalActivationPreparationStore: fmt::Debug + Send + Sync {
    /// Replaces one exact live preparation fence with its next generation.
    async fn renew_logical_activation_preparation(
        &self,
        request: RenewLogicalActivationPreparation,
    ) -> Result<RenewedLogicalActivationPreparation, LogicalActivationPreparationStoreError>;

    /// Atomically binds canonical context descriptors and activation digest.
    async fn bind_logical_activation_preparation(
        &self,
        request: BindLogicalActivationPreparation,
    ) -> Result<LogicalActivationPreparationReceipt, LogicalActivationPreparationStoreError>;
}

fn aggregate_status(
    prerequisites: &[LogicalActivationPrerequisiteEvidence],
) -> LogicalActivationAggregateStatus {
    if prerequisites.iter().any(|prerequisite| {
        prerequisite.closure_has_failure()
            || matches!(
                prerequisite.effective_conclusion(),
                JobConclusion::Failure | JobConclusion::TimedOut
            )
    }) {
        LogicalActivationAggregateStatus::Failure
    } else if prerequisites.iter().any(|prerequisite| {
        prerequisite.closure_has_cancelled()
            || prerequisite.effective_conclusion() == JobConclusion::Cancelled
    }) {
        LogicalActivationAggregateStatus::Cancelled
    } else if prerequisites.iter().any(|prerequisite| {
        prerequisite.closure_has_skipped()
            || prerequisite.effective_conclusion() == JobConclusion::Skipped
    }) {
        LogicalActivationAggregateStatus::Skipped
    } else {
        LogicalActivationAggregateStatus::Success
    }
}

fn prerequisites_digest(prerequisites: &[LogicalActivationPrerequisiteEvidence]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(PREREQUISITES_DOMAIN);
    hasher.update(u64_len(prerequisites.len()));
    for prerequisite in prerequisites {
        hasher.update(prerequisite.logical_job_id().as_uuid().as_bytes());
        hash_text(&mut hasher, prerequisite.logical_key().as_str());
        hasher.update(prerequisite.source_order().to_be_bytes());
        hasher.update(prerequisite.result_descriptor_digest().as_bytes());
        hasher.update(prerequisite.outputs_digest().as_bytes());
        hasher.update(prerequisite.commit_digest().as_bytes());
        hasher.update([conclusion_code(prerequisite.effective_conclusion())]);
        hasher.update([
            u8::from(prerequisite.closure_has_failure()),
            u8::from(prerequisite.closure_has_cancelled()),
            u8::from(prerequisite.closure_has_skipped()),
        ]);
        hasher.update(u64_len(prerequisite.outputs().len()));
        for output in prerequisite.outputs() {
            hash_text(&mut hasher, output.name().as_str());
            hasher.update([sensitivity_code(output.sensitivity())]);
            hash_optional_text(&mut hasher, output.public_value());
        }
        hasher.update(prerequisite.finalized_at().get().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn descriptor_digest(
    target: &LogicalActivationPreparationTarget,
    logical_key: &WorkflowJobKey,
    source_order: u16,
    execution: &LogicalActivationExecutionContext,
    authority_profile: JobAuthorityProfile,
    runner_policy: &AdmissionObject,
    runtime_policy: &PinnedWorkflowRuntimePolicy,
    plan: &AdmissionObject,
    event: &AdmissionObject,
    base_context_kind: LogicalActivationBaseContextKind,
    base_context: &AdmissionObject,
    workspace: &LogicalActivationPreparationWorkspace,
    prerequisites_digest: Sha256Digest,
    status: LogicalActivationAggregateStatus,
    evidence_ready_at: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    hash_text(&mut hasher, target.tenant().as_str());
    hasher.update(target.run_id().as_uuid().as_bytes());
    hasher.update(target.invocation_id().as_uuid().as_bytes());
    hasher.update(target.logical_job_id().as_uuid().as_bytes());
    hash_text(&mut hasher, logical_key.as_str());
    hasher.update(source_order.to_be_bytes());
    hash_execution(&mut hasher, execution);
    hasher.update([authority_profile_code(authority_profile)]);
    hash_admission_object(&mut hasher, b"runner-policy", runner_policy);
    hash_runtime_policy_pin(&mut hasher, runtime_policy);
    hash_admission_object(&mut hasher, b"plan", plan);
    hasher.update(WORKFLOW_PLAN_SCHEMA.to_be_bytes());
    hash_admission_object(&mut hasher, b"event", event);
    hasher.update([base_context_kind_code(base_context_kind)]);
    hash_admission_object(&mut hasher, b"base-context", base_context);
    hash_text(&mut hasher, workspace.as_str());
    hasher.update(prerequisites_digest.as_bytes());
    hasher.update([status_code(status)]);
    hasher.update(evidence_ready_at.get().to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn activation_input_digest(
    descriptor: &LogicalActivationPreparationDescriptor,
    base_context: &AdmissionObject,
    prerequisite_context: &AdmissionObject,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ACTIVATION_INPUT_DIGEST_DOMAIN);
    hash_text(&mut hasher, descriptor.target().tenant().as_str());
    hasher.update(descriptor.target().run_id().as_uuid().as_bytes());
    hasher.update(descriptor.target().invocation_id().as_uuid().as_bytes());
    hasher.update(descriptor.target().logical_job_id().as_uuid().as_bytes());
    hash_text(&mut hasher, descriptor.logical_key().as_str());
    hasher.update(descriptor.source_order().to_be_bytes());
    hash_execution(&mut hasher, descriptor.execution());
    hasher.update([authority_profile_code(descriptor.authority_profile())]);
    hash_admission_object(&mut hasher, b"runner-policy", descriptor.runner_policy());
    hash_runtime_policy_pin(&mut hasher, descriptor.runtime_policy());
    hash_admission_object(&mut hasher, b"plan", descriptor.plan());
    hash_admission_object(&mut hasher, b"event", descriptor.event());
    hash_admission_object(&mut hasher, b"base-context", base_context);
    hash_admission_object(&mut hasher, b"prerequisite-context", prerequisite_context);
    hasher.update([status_code(descriptor.status())]);
    hash_text(&mut hasher, descriptor.workspace().as_str());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

const fn authority_profile_code(profile: JobAuthorityProfile) -> u8 {
    match profile {
        JobAuthorityProfile::Standard => 1,
        JobAuthorityProfile::CredentialFree => 2,
    }
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

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_text(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64_len(value.len()));
    hasher.update(value);
}

fn u64_len(value: usize) -> [u8; 8] {
    u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes()
}

const fn conclusion_code(value: JobConclusion) -> u8 {
    match value {
        JobConclusion::Success => 1,
        JobConclusion::Failure => 2,
        JobConclusion::Cancelled => 3,
        JobConclusion::TimedOut => 4,
        JobConclusion::Skipped => 5,
    }
}

const fn sensitivity_code(value: OutputSensitivity) -> u8 {
    match value {
        OutputSensitivity::Public => 1,
        OutputSensitivity::SecretDerived => 2,
    }
}

const fn status_code(value: LogicalActivationAggregateStatus) -> u8 {
    match value {
        LogicalActivationAggregateStatus::Success => 0,
        LogicalActivationAggregateStatus::Failure => 1,
        LogicalActivationAggregateStatus::Cancelled => 2,
        LogicalActivationAggregateStatus::Skipped => 3,
    }
}

const fn base_context_kind_code(value: LogicalActivationBaseContextKind) -> u8 {
    match value {
        LogicalActivationBaseContextKind::Admission => 1,
    }
}

fn validate_claim_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), LogicalActivationPreparationValueError> {
    validate_timestamp(observed_at, "preparation claim start")?;
    validate_timestamp(expires_at, "preparation claim expiration")?;
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| {
            *duration > 0 && *duration <= MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS
        })
        .ok_or(LogicalActivationPreparationValueError::InvalidClaimInterval)?;
    Ok(())
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), LogicalActivationPreparationValueError> {
    if value.get() < 0 {
        return Err(LogicalActivationPreparationValueError::NegativeTimestamp(
            field,
        ));
    }
    Ok(())
}

fn validate_workspace(value: &str) -> Result<(), LogicalActivationPreparationValueError> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > 1_024
        || value.chars().any(char::is_control)
    {
        return Err(LogicalActivationPreparationValueError::InvalidWorkspace);
    }
    let unix = value.starts_with('/')
        && value != "/"
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."));
    let bytes = value.as_bytes();
    let windows = bytes.len() >= 4
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains('/')
        && !value.contains("\\\\")
        && value
            .split('\\')
            .skip(1)
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."));
    if unix || windows {
        Ok(())
    } else {
        Err(LogicalActivationPreparationValueError::InvalidWorkspace)
    }
}
