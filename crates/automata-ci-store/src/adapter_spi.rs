//! Unstable trust-boundary operations for Automata's first-party durable adapters.
//!
//! This is deliberately not a general-purpose construction API. Callers must
//! establish the documented durable-row predicates before invoking these hooks.
//! The feature and every item in this module may change without notice.

use automata_ci_auth::management::ManagementActor;
use automata_ci_core::{
    AttemptId, FencingToken, JobConclusion, JobId, JobSecretExposure, Lease, LeaseId,
    OutputSensitivity, RunId, Sha256Digest, UnixMillis, WorkflowOutputKey,
};
use automata_ci_key_management::KeyId;
use automata_ci_workload_oidc::{
    OidcAudience, OidcAuthorityId, OidcClaimSet, OidcKeyId, OidcSubject,
};

/// Rehydrates one workflow result after the adapter has decoded its closed state.
#[must_use]
pub fn conformance_workflow_result(
    workflow_path: String,
    outcome: crate::ConformanceWorkflowOutcome,
) -> crate::ConformanceWorkflowResult {
    crate::ConformanceWorkflowResult::new(workflow_path, outcome)
}

/// Rehydrates one exact workflow enable-state transition receipt.
#[must_use]
pub const fn workflow_enable_state_receipt(
    current: crate::WorkflowEnableStateRecord,
    replay: bool,
) -> crate::WorkflowEnableStateReceipt {
    crate::WorkflowEnableStateReceipt::new(current, replay)
}

/// Rehydrates a selection/control registration receipt after checking its
/// exact immutable binding.
pub fn event_subject_registration_receipt(
    selection: crate::EventSubjectSelection,
    control: crate::EventControlSubject,
    replay: bool,
) -> Result<crate::EventSubjectRegistrationReceipt, crate::EventSubjectValueError> {
    crate::EventSubjectRegistrationReceipt::new(selection, control, replay)
}

/// Rehydrates one validated terminal-progress receipt.
#[must_use]
pub const fn event_subject_progress_receipt(
    progress: crate::EventSubjectProgress,
    replay: bool,
) -> crate::EventSubjectProgressReceipt {
    crate::EventSubjectProgressReceipt::new(progress, replay)
}

/// Rehydrates a complete delivery projection from one coherent durable snapshot.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn conformance_delivery(
    id: crate::ProviderDeliveryId,
    external_delivery_id: String,
    state: crate::ConformanceDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
    completed_at: Option<UnixMillis>,
    workflows: Vec<crate::ConformanceWorkflowResult>,
) -> crate::ConformanceDelivery {
    crate::ConformanceDelivery::new(
        id,
        external_delivery_id,
        state,
        attempts,
        accepted_at,
        completed_at,
        workflows,
    )
}

/// Rehydrates durable request-bearer coordinates already proven to belong to
/// the locked authority row.
#[must_use]
pub const fn reserved_workload_oidc_authority(
    authority_id: OidcAuthorityId,
    request_bearer_key_id: OidcKeyId,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    request_bearer_sha256: Sha256Digest,
) -> crate::ReservedWorkloadOidcAuthority {
    crate::ReservedWorkloadOidcAuthority::new(
        authority_id,
        request_bearer_key_id,
        issued_at_seconds,
        expires_at_seconds,
        request_bearer_sha256,
    )
}

/// Rehydrates a locked durable key-retention deadline.
///
/// `key_sha256` may be absent only for legacy retained rows written before key
/// fingerprints became mandatory. New retention requests must continue to use
/// [`crate::WorkloadOidcKeyDeadline::from_retention`].
#[must_use]
pub const fn workload_oidc_key_deadline(
    key_use: crate::WorkloadOidcKeyUse,
    key_id: OidcKeyId,
    key_sha256: Option<Sha256Digest>,
    not_after_seconds: u64,
) -> crate::WorkloadOidcKeyDeadline {
    crate::WorkloadOidcKeyDeadline::new(key_use, key_id, key_sha256, not_after_seconds)
}

/// Rechecks the durable repository and digest roots of a decoded manifest.
pub fn github_provider_manifest(
    manifest: crate::GithubProviderManifest,
    expected_repository_id: crate::RepositoryId,
    expected_digest: Sha256Digest,
) -> Result<crate::GithubProviderManifest, crate::GithubProviderManifestValueError> {
    crate::GithubProviderManifest::from_durable_parts(
        manifest,
        expected_repository_id,
        expected_digest,
    )
}

/// Validates durable timing while rehydrating one manifest record.
pub fn github_provider_manifest_record(
    manifest: crate::GithubProviderManifest,
    registered_at: UnixMillis,
    activated_at: Option<UnixMillis>,
) -> Result<crate::GithubProviderManifestRecord, crate::GithubProviderManifestValueError> {
    crate::GithubProviderManifestRecord::new(manifest, registered_at, activated_at)
}

/// Rechecks that runtime-policy and manifest bootstrap receipts are identical
/// in tenant, repository, revision, and digest.
pub fn github_provider_repository_bootstrap_receipt(
    runtime_policy: crate::WorkflowRuntimePolicyReceipt,
    manifest: crate::GithubProviderManifestBootstrapReceipt,
) -> Result<crate::GithubProviderRepositoryBootstrapReceipt, crate::GithubProviderManifestValueError>
{
    crate::GithubProviderRepositoryBootstrapReceipt::new(runtime_policy, manifest)
}

/// Rechecks that a bootstrap receipt points at a current manifest record.
pub fn github_provider_manifest_bootstrap_receipt(
    current: crate::GithubProviderManifestRecord,
    replay: bool,
) -> Result<crate::GithubProviderManifestBootstrapReceipt, crate::GithubProviderManifestValueError>
{
    crate::GithubProviderManifestBootstrapReceipt::new(current, replay)
}

/// Rechecks that a mint receipt is the exact minting transition requested.
pub fn github_server_service_mint_start(
    request: &crate::BeginGithubServerServiceMint,
    receipt: crate::GithubServerServiceIssuanceReceipt,
) -> Result<crate::GithubServerServiceMintStart, crate::GithubServerServiceValueError> {
    crate::GithubServerServiceMintStart::from_request(request, receipt)
}

/// Rehydrates one activated instance while enforcing matrix, object-kind, and
/// workspace invariants.
#[allow(clippy::too_many_arguments)]
pub fn activated_logical_instance_descriptor(
    id: crate::LogicalWorkflowInstanceId,
    run_id: RunId,
    invocation_id: crate::LogicalWorkflowInvocationId,
    logical_job_id: crate::LogicalWorkflowJobId,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: Sha256Digest,
    workspace: String,
    job_ir: crate::LogicalActivationObject,
    runtime_context: crate::LogicalActivationObject,
    environment_gate: Option<crate::JobEnvironmentActivationEvidence>,
) -> Result<crate::ActivatedLogicalInstanceDescriptor, crate::LogicalActivationValueError> {
    crate::ActivatedLogicalInstanceDescriptor::from_durable(
        id,
        run_id,
        invocation_id,
        logical_job_id,
        matrix_index,
        matrix_total,
        matrix_digest,
        workspace,
        job_ir,
        runtime_context,
        environment_gate,
    )
}

/// Rehydrates an instance output while enforcing its name, sensitivity, and
/// value-presence matrix.
pub fn logical_instance_result_output(
    name: String,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
) -> Result<crate::LogicalInstanceResultOutput, crate::LogicalInstanceResultValueError> {
    crate::LogicalInstanceResultOutput::from_durable(name, sensitivity, public_value)
}

/// Rehydrates a logical-job output while enforcing its sensitivity/value matrix.
pub fn logical_job_result_output(
    name: WorkflowOutputKey,
    sensitivity: OutputSensitivity,
    public_value: Option<String>,
) -> Result<crate::LogicalJobResultOutput, crate::LogicalJobResultValueError> {
    crate::LogicalJobResultOutput::from_durable(name, sensitivity, public_value)
}

/// Joins a repository-proven renewed orchestration lineage to its selection.
pub fn repository_verified_logical_job_orchestration(
    selected: crate::SelectedLogicalJobOrchestration,
    authority: crate::ConsumedLogicalJobOrchestrationAuthority,
    validated_at: UnixMillis,
) -> Result<crate::ConsumedSelectedLogicalJobOrchestration, crate::LogicalWorkSelectionValueError> {
    crate::ConsumedSelectedLogicalJobOrchestration::new_repository_verified(
        selected,
        authority,
        validated_at,
    )
}

/// Joins a repository-proven renewed materialization lineage to its selection.
pub fn repository_verified_logical_instance_materialization(
    selected: crate::SelectedLogicalInstanceMaterialization,
    authority: crate::ClaimedLogicalInstanceMaterialization,
    validated_at: UnixMillis,
) -> Result<
    crate::ConsumedSelectedLogicalInstanceMaterialization,
    crate::LogicalWorkSelectionValueError,
> {
    crate::ConsumedSelectedLogicalInstanceMaterialization::new_repository_verified(
        selected,
        authority,
        validated_at,
    )
}

/// Rehydrates server-derived tenant/repository execution scope.
#[must_use]
pub const fn managed_secret_execution_scope(
    tenant: crate::TenantScope,
    repository_id: crate::RepositoryId,
) -> crate::ManagedSecretExecutionScope {
    crate::ManagedSecretExecutionScope::from_durable(tenant, repository_id)
}

/// Constructs one binding only after the adapter has proved the exact current
/// grant/provider/version row and canonical name under lock.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn repository_verified_managed_secret_authority_binding(
    grant_id: crate::SecretWorkloadGrantId,
    provider_id: crate::ManagedSecretProviderId,
    secret_id: crate::RepositorySecretId,
    version_id: crate::RepositorySecretVersionId,
    version_number: u64,
    canonical_name: String,
    scope: crate::ManagedSecretScope,
    mode: crate::ManagedSecretGrantMode,
    provider_supports_dynamic_leases: bool,
) -> crate::ManagedSecretAuthorityBinding {
    crate::ManagedSecretAuthorityBinding::from_verified_parts(
        crate::managed_secret_authority::ManagedSecretAuthorityBindingParts {
            grant_id,
            provider_id,
            secret_id,
            version_id,
            version_number,
            canonical_name,
            scope,
            mode,
            provider_supports_dynamic_leases,
        },
    )
}

/// Constructs a value-free receipt only after the adapter has proved the
/// request's current lease/session fence and every exact-version binding.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn repository_verified_managed_secret_authority_receipt(
    operation_id: crate::ManagedSecretDeliveryOperationId,
    credential_key_id: String,
    credential_sha256: Sha256Digest,
    request: &crate::ResolveManagedSecretAuthority,
    bindings: Vec<crate::ManagedSecretAuthorityBinding>,
    evidence_digest: Sha256Digest,
    usable_until: UnixMillis,
) -> crate::ManagedSecretAuthorityReceipt {
    crate::ManagedSecretAuthorityReceipt::from_verified_parts(
        operation_id,
        credential_key_id,
        credential_sha256,
        request,
        bindings,
        evidence_digest,
        usable_until,
    )
}

/// Rehydrates one committed delivery acknowledgement.
#[must_use]
pub const fn managed_secret_delivery_acknowledgement(
    operation_id: crate::ManagedSecretDeliveryOperationId,
    acknowledged_at: UnixMillis,
) -> crate::ManagedSecretDeliveryAcknowledgement {
    crate::ManagedSecretDeliveryAcknowledgement::from_durable(operation_id, acknowledged_at)
}

/// Rehydrates one value-free leased secret binding after its durable binding
/// and canonical name have been verified.
#[must_use]
pub fn issued_leased_job_secret_binding(
    canonical_name: String,
    binding: automata_ci_core::SecretBinding,
) -> crate::IssuedLeasedJobSecretBinding {
    crate::IssuedLeasedJobSecretBinding::new(canonical_name, binding)
}

/// Rehydrates a sanitized runtime-authority inspection from one coherent,
/// repository-locked snapshot.
///
/// The adapter must first validate the receipt and prove that the attempt
/// count, next-action time, commit disposition, provider-expiry presence,
/// safe-erasure horizon, and corruption class all describe that same durable
/// lifecycle row. This mirrors the former in-crate adapter construction path;
/// the domain currently has no independent constructor that can re-prove those
/// relational predicates without the locked row.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub const fn github_runtime_authority_inspection(
    receipt: crate::GithubRuntimeAuthorityReceipt,
    mint_attempts: u16,
    next_action_at: Option<UnixMillis>,
    commit_disposition: Option<crate::GithubRuntimeAuthorityCommitDisposition>,
    provider_expiry_known: bool,
    safe_erase_after: Option<UnixMillis>,
    corruption: Option<crate::GithubRuntimeAuthorityCorruptionKind>,
) -> crate::GithubRuntimeAuthorityInspection {
    crate::GithubRuntimeAuthorityInspection {
        receipt,
        mint_attempts,
        next_action_at,
        commit_disposition,
        provider_expiry_known,
        safe_erase_after,
        corruption,
    }
}

/// Resolves an authenticated rerun route to its internal repository identity.
pub fn resolve_workflow_rerun(
    request: crate::RerunWorkflowByName,
    repository_id: crate::RepositoryId,
) -> Result<crate::RerunWorkflow, crate::WorkflowRerunValueError> {
    request.into_resolved(repository_id)
}

/// Returns whether a repository-authoritative rerun age exceeds the Store-owned horizon.
#[must_use]
pub const fn workflow_rerun_age_is_rejected(observed_age_millis: i64) -> bool {
    matches!(
        crate::workflow_rerun::workflow_rerun_age_rejection(observed_age_millis),
        Some(crate::workflow_rerun::WorkflowRerunLimitRejection::AgeMillis)
    )
}

/// Rehydrates requirements while preserving the closed state ordering and
/// sorted/unique bounded required-key validation.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub fn secret_custody_requirements(
    active_provider: bool,
    encrypted_envelopes: bool,
    open_mutations: bool,
    open_leases: bool,
    open_cleanup: bool,
    open_recovery: bool,
    open_rotation: bool,
    required_key_ids: Vec<KeyId>,
) -> Result<crate::SecretCustodyRequirements, crate::SecretCustodyValueError> {
    crate::SecretCustodyRequirements::from_durable_parts(
        [
            active_provider,
            encrypted_envelopes,
            open_mutations,
            open_leases,
            open_cleanup,
            open_recovery,
            open_rotation,
        ],
        required_key_ids,
    )
}

/// Rehydrates the only supported immutable canary generation.
pub fn secret_custody_canary_generation(
    value: u64,
) -> Result<crate::SecretCustodyCanaryGeneration, crate::SecretCustodyValueError> {
    crate::SecretCustodyCanaryGeneration::new(value)
}

/// Returns the canonical durable schema for an encrypted custody-key canary.
#[must_use]
pub const fn secret_custody_canary_schema_version() -> u16 {
    crate::secret_custody::SECRET_CUSTODY_CANARY_SCHEMA_VERSION
}

/// Joins a verified key identity to its validated canary generation.
#[must_use]
pub const fn secret_custody_canary_binding(
    key_id: KeyId,
    generation: crate::SecretCustodyCanaryGeneration,
) -> crate::SecretCustodyCanaryBinding {
    crate::SecretCustodyCanaryBinding::new(key_id, generation)
}

/// Constructs custody proof only after validating canary ordering, configured
/// membership, active-key coverage, and every durably required key.
pub fn verified_secret_custody(
    configured_keys: &crate::SecretCustodyKeySet,
    requirements: &crate::SecretCustodyRequirements,
    canaries: Vec<crate::SecretCustodyCanaryBinding>,
) -> Result<crate::VerifiedSecretCustody, crate::SecretCustodyValueError> {
    crate::VerifiedSecretCustody::from_verified_parts(configured_keys, requirements, canaries)
}

/// Tests complete immutable connection identity equality.
#[must_use]
pub fn github_provider_manifest_same_connection_identity(
    left: &crate::GithubProviderManifest,
    right: &crate::GithubProviderManifest,
) -> bool {
    left.same_connection_identity(right)
}

/// Validates the complete contiguous manifest-successor relationship.
#[must_use]
pub fn github_provider_manifest_valid_successor(
    candidate: &crate::GithubProviderManifest,
    prior: &crate::GithubProviderManifest,
) -> bool {
    candidate.valid_successor_of(prior)
}

/// Tests a server-service selector against a complete immutable identity.
#[must_use]
pub fn github_server_service_authority_matches(
    selector: &crate::GithubServerServiceAuthoritySelector,
    identity: &crate::GithubServerServiceAuthorityIdentity,
) -> bool {
    selector.matches(identity)
}

/// Enforces the admitted maximum secret-exposure boundary at terminal commit.
#[must_use]
pub const fn logical_instance_accepts_terminal_secret_exposure(
    descriptor: &crate::LogicalInstanceResultDescriptor,
    observed: JobSecretExposure,
) -> bool {
    descriptor.accepts_terminal_secret_exposure(observed)
}

/// Returns the canonical JSON retained beside typed materialization requirements.
#[must_use]
pub const fn logical_materialization_requirements_json(
    commit: &crate::CommitLogicalInstanceMaterialization,
) -> &serde_json::Value {
    commit.requirements_json()
}

/// Returns the configured key set requested for custody verification.
#[must_use]
pub fn configured_secret_custody_keys(
    request: &crate::VerifySecretCustody,
) -> Option<&crate::SecretCustodyKeySet> {
    request.configured_keys()
}

/// Tests membership in the validated, sorted configured custody key set.
#[must_use]
pub fn secret_custody_key_set_contains(
    configured_keys: &crate::SecretCustodyKeySet,
    key_id: &KeyId,
) -> bool {
    configured_keys.contains(key_id)
}

/// Re-derives the canonical OIDC claim-evidence root.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn workload_oidc_claim_evidence_digest(
    permission_evidence_sha256: Sha256Digest,
    subject_policy_mode: crate::WorkloadOidcSubjectPolicyMode,
    subject_policy_revision: crate::WorkloadOidcSubjectPolicyRevision,
    subject_policy_sha256: Sha256Digest,
    github_run_subject_evidence_sha256: Sha256Digest,
    github_owner_id: u64,
    subject: &OidcSubject,
    default_audience: &OidcAudience,
    additional_claims: &OidcClaimSet,
    configuration_sha256: Sha256Digest,
    request_bearer_verification_skew_seconds: u64,
    id_token_verifier_skew_seconds: u64,
) -> Sha256Digest {
    crate::workload_oidc::workload_oidc_claim_evidence_digest(
        permission_evidence_sha256,
        subject_policy_mode,
        subject_policy_revision,
        subject_policy_sha256,
        github_run_subject_evidence_sha256,
        github_owner_id,
        subject,
        default_audience,
        additional_claims,
        configuration_sha256,
        request_bearer_verification_skew_seconds,
        id_token_verifier_skew_seconds,
    )
}

/// Re-derives the canonical logical-activation publication root.
#[must_use]
pub fn logical_activation_publication_digest(
    run_id: RunId,
    invocation_id: crate::LogicalWorkflowInvocationId,
    logical_job_id: crate::LogicalWorkflowJobId,
    input_digest: Sha256Digest,
    condition_matched: bool,
    instances: &[crate::ActivatedLogicalInstanceDescriptor],
    scheduling_policy: &crate::ResolvedLogicalJobSchedulingPolicy,
) -> Sha256Digest {
    crate::logical_activation::rederive_publication_digest(
        run_id,
        invocation_id,
        logical_job_id,
        input_digest,
        condition_matched,
        instances,
        scheduling_policy,
    )
}

/// Re-derives the canonical instance-output set root.
#[must_use]
pub fn logical_instance_output_set_digest(
    outputs: &[crate::LogicalInstanceResultOutput],
) -> Sha256Digest {
    crate::logical_instance_result::output_set_digest(outputs)
}

/// Re-derives the canonical instance-result commit root.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn logical_instance_result_commit_digest(
    instance_id: crate::LogicalWorkflowInstanceId,
    job_id: JobId,
    attempt_id: AttemptId,
    terminal_ordinal: crate::LogicalInstanceTerminalOrdinal,
    owner: crate::LogicalInstanceResultWorkerId,
    generation: crate::LogicalInstanceResultGeneration,
    descriptor_digest: Sha256Digest,
    raw_conclusion: JobConclusion,
    effective_conclusion: JobConclusion,
    continue_on_error: bool,
    secret_exposure: JobSecretExposure,
    outputs_digest: Sha256Digest,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    crate::logical_instance_result::rederive_commit_digest(
        instance_id,
        job_id,
        attempt_id,
        terminal_ordinal,
        owner,
        generation,
        descriptor_digest,
        raw_conclusion,
        effective_conclusion,
        continue_on_error,
        secret_exposure,
        outputs_digest,
        finalized_at,
    )
}

/// Re-derives the canonical logical-job output set root.
#[must_use]
pub fn logical_job_outputs_digest(outputs: &[crate::LogicalJobResultOutput]) -> Sha256Digest {
    crate::logical_job_result::outputs_digest(outputs)
}

/// Re-derives the canonical logical-job result commit root.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn logical_job_result_commit_digest(
    target: &crate::LogicalJobResultTarget,
    owner: crate::LogicalJobResultWorkerId,
    generation: crate::LogicalJobResultGeneration,
    descriptor_digest: Sha256Digest,
    instances_digest: Sha256Digest,
    prerequisites_digest: Sha256Digest,
    effective_conclusion: JobConclusion,
    closure_has_failure: bool,
    closure_has_cancelled: bool,
    closure_has_skipped: bool,
    outputs_digest: Sha256Digest,
    finalized_at: UnixMillis,
) -> Sha256Digest {
    crate::logical_job_result::rederive_commit_digest(
        target,
        owner,
        generation,
        descriptor_digest,
        instances_digest,
        prerequisites_digest,
        effective_conclusion,
        closure_has_failure,
        closure_has_cancelled,
        closure_has_skipped,
        outputs_digest,
        finalized_at,
    )
}

/// Read-only view of a prepared environment request.
#[derive(Clone, Copy, Debug)]
pub struct PrepareJobEnvironmentView<'a>(&'a crate::PrepareJobEnvironment);

impl std::ops::Deref for PrepareJobEnvironmentView<'_> {
    type Target = crate::PrepareJobEnvironment;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// Inspects a prepared environment request without exposing mutable state.
#[must_use]
pub const fn prepare_job_environment(
    request: &crate::PrepareJobEnvironment,
) -> PrepareJobEnvironmentView<'_> {
    PrepareJobEnvironmentView(request)
}

impl<'a> PrepareJobEnvironmentView<'a> {
    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(self) -> &'a crate::TenantScope {
        self.0.tenant()
    }
    /// Returns the attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.0.attempt_id()
    }
    /// Returns the optional deployment environment.
    #[must_use]
    pub const fn environment(self) -> Option<&'a crate::DeploymentEnvironmentName> {
        self.0.environment()
    }
    /// Returns the activation-context digest.
    #[must_use]
    pub const fn activation_context_digest(self) -> Sha256Digest {
        self.0.activation_context_digest()
    }
    /// Returns the event trust classification.
    #[must_use]
    pub const fn event_trust(self) -> crate::JobEventTrust {
        self.0.event_trust()
    }
    /// Returns the source kind.
    #[must_use]
    pub const fn source_kind(self) -> crate::JobSourceKind {
        self.0.source_kind()
    }
    /// Returns reusable-secret permission.
    #[must_use]
    pub const fn reusable_secret_permission(self) -> crate::ReusableSecretPermission {
        self.0.reusable_secret_permission()
    }
    /// Returns the approval request identity.
    #[must_use]
    pub const fn approval_request_id(self) -> uuid::Uuid {
        self.0.approval_request_id()
    }
    /// Returns the request time.
    #[must_use]
    pub const fn requested_at(self) -> UnixMillis {
        self.0.requested_at()
    }
    /// Returns the approval deadline.
    #[must_use]
    pub const fn approval_expires_at(self) -> UnixMillis {
        self.0.approval_expires_at()
    }
}

/// Read-only view of an environment review.
#[derive(Clone, Copy, Debug)]
pub struct ReviewJobEnvironmentView<'a>(&'a crate::ReviewJobEnvironment);

impl std::ops::Deref for ReviewJobEnvironmentView<'_> {
    type Target = crate::ReviewJobEnvironment;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// Inspects an environment review without exposing mutable state.
#[must_use]
pub const fn review_job_environment(
    request: &crate::ReviewJobEnvironment,
) -> ReviewJobEnvironmentView<'_> {
    ReviewJobEnvironmentView(request)
}

impl<'a> ReviewJobEnvironmentView<'a> {
    /// Returns the authenticated management actor.
    #[must_use]
    pub const fn actor(self) -> &'a ManagementActor {
        self.0.actor()
    }
    /// Returns the repository identity.
    #[must_use]
    pub const fn repository_id(self) -> crate::RepositoryId {
        self.0.repository_id()
    }
    /// Returns the attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.0.attempt_id()
    }
    /// Returns the review decision.
    #[must_use]
    pub const fn decision(self) -> crate::EnvironmentReviewDecision {
        self.0.decision()
    }
}

/// Read-only view of a leased-secret binding request.
#[derive(Clone, Copy, Debug)]
pub struct BindLeasedJobSecretsView<'a>(&'a crate::BindLeasedJobSecrets);

impl std::ops::Deref for BindLeasedJobSecretsView<'_> {
    type Target = crate::BindLeasedJobSecrets;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// Inspects a leased-secret binding request without exposing mutable state.
#[must_use]
pub const fn bind_leased_job_secrets(
    request: &crate::BindLeasedJobSecrets,
) -> BindLeasedJobSecretsView<'_> {
    BindLeasedJobSecretsView(request)
}

impl<'a> BindLeasedJobSecretsView<'a> {
    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(self) -> &'a crate::TenantScope {
        self.0.tenant()
    }
    /// Returns the attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.0.attempt_id()
    }
    /// Returns the lease identity.
    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.0.lease_id()
    }
    /// Returns the fencing token.
    #[must_use]
    pub const fn fencing_token(self) -> FencingToken {
        self.0.fencing_token()
    }
    /// Returns the exact selected authorities.
    #[must_use]
    pub fn authorities(self) -> &'a [crate::SecretLeaseAuthority] {
        self.0.authorities()
    }
    /// Returns the issue time.
    #[must_use]
    pub const fn issued_at(self) -> UnixMillis {
        self.0.issued_at()
    }
    /// Returns the expiry time.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.0.expires_at()
    }
}

/// Read-only view of a leased-secret grant issuance request.
#[derive(Clone, Copy, Debug)]
pub struct IssueLeasedJobSecretGrantsView<'a>(&'a crate::IssueLeasedJobSecretGrants);

impl std::ops::Deref for IssueLeasedJobSecretGrantsView<'_> {
    type Target = crate::IssueLeasedJobSecretGrants;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// Inspects a grant issuance request without exposing mutable state.
#[must_use]
pub const fn issue_leased_job_secret_grants(
    request: &crate::IssueLeasedJobSecretGrants,
) -> IssueLeasedJobSecretGrantsView<'_> {
    IssueLeasedJobSecretGrantsView(request)
}

impl<'a> IssueLeasedJobSecretGrantsView<'a> {
    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(self) -> &'a crate::TenantScope {
        self.0.tenant()
    }
    /// Returns the attempt identity.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.0.attempt_id()
    }
    /// Returns the lease identity.
    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.0.lease_id()
    }
    /// Returns the fencing token.
    #[must_use]
    pub const fn fencing_token(self) -> FencingToken {
        self.0.fencing_token()
    }
    /// Returns the issue time.
    #[must_use]
    pub const fn issued_at(self) -> UnixMillis {
        self.0.issued_at()
    }
    /// Returns the expiry time.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.0.expires_at()
    }
}

/// Read-only view of a leased-secret binding inspection request.
#[derive(Clone, Copy, Debug)]
pub struct InspectLeasedJobSecretBindingsView<'a>(&'a crate::InspectLeasedJobSecretBindings);

impl std::ops::Deref for InspectLeasedJobSecretBindingsView<'_> {
    type Target = crate::InspectLeasedJobSecretBindings;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// Inspects a binding lookup request without exposing mutable state.
#[must_use]
pub const fn inspect_leased_job_secret_bindings(
    request: &crate::InspectLeasedJobSecretBindings,
) -> InspectLeasedJobSecretBindingsView<'_> {
    InspectLeasedJobSecretBindingsView(request)
}

impl<'a> InspectLeasedJobSecretBindingsView<'a> {
    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(self) -> &'a crate::TenantScope {
        self.0.tenant()
    }
    /// Returns the complete validated lease.
    #[must_use]
    pub const fn lease(self) -> &'a Lease {
        self.0.lease()
    }
}

/// Returns a deployment name's canonical normalized spelling.
#[must_use]
pub fn deployment_environment_name(name: &crate::DeploymentEnvironmentName) -> &str {
    name.normalized()
}

/// Read-only projection of a validated secret lease authority.
#[derive(Clone, Copy, Debug)]
pub struct SecretLeaseAuthorityView<'a>(&'a crate::SecretLeaseAuthority);

/// Inspects one value-free lease authority without exposing its fields.
#[must_use]
pub const fn secret_lease_authority(
    authority: &crate::SecretLeaseAuthority,
) -> SecretLeaseAuthorityView<'_> {
    SecretLeaseAuthorityView(authority)
}

impl<'a> SecretLeaseAuthorityView<'a> {
    /// Returns the canonical selected secret name.
    #[must_use]
    pub fn canonical_name(self) -> &'a str {
        self.0.canonical_name()
    }
    /// Returns the exact workload grant identity.
    #[must_use]
    pub const fn grant_id(self) -> uuid::Uuid {
        self.0.grant_id()
    }
    /// Returns the authority evidence digest.
    #[must_use]
    pub const fn authority_digest(self) -> Sha256Digest {
        self.0.authority_digest()
    }
    /// Returns the authority digest key identity.
    #[must_use]
    pub fn authority_digest_key_id(self) -> &'a str {
        self.0.authority_digest_key_id()
    }
}

/// One state reduction counted by a runtime-authority reconciliation batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRuntimeAuthorityReconciliationReduction {
    /// An issuance was revoked before mint.
    RevokedBeforeMint,
    /// A definitive mint retry was rejected.
    MintRetryRejected,
    /// An abandoned mint was marked indeterminate.
    MintingMarkedIndeterminate,
    /// A ready authority moved to revoke-pending.
    ReadyMarkedRevokePending,
    /// Indeterminate authority custody expired.
    IndeterminateAuthorityExpired,
    /// An ordinary expired envelope was erased.
    ExpiredEnvelopeErased,
    /// A quarantined envelope was erased.
    QuarantinedEnvelopeErased,
}

/// Records one bounded reconciliation reduction, returning `false` only if a
/// corrupted caller attempts to overflow a report counter.
pub fn record_github_runtime_authority_reconciliation_reduction(
    report: &mut crate::GithubRuntimeAuthorityReconciliationReport,
    reduction: GithubRuntimeAuthorityReconciliationReduction,
) -> bool {
    let counter = match reduction {
        GithubRuntimeAuthorityReconciliationReduction::RevokedBeforeMint => {
            &mut report.revoked_before_mint
        }
        GithubRuntimeAuthorityReconciliationReduction::MintRetryRejected => {
            &mut report.mint_retries_rejected
        }
        GithubRuntimeAuthorityReconciliationReduction::MintingMarkedIndeterminate => {
            &mut report.minting_marked_indeterminate
        }
        GithubRuntimeAuthorityReconciliationReduction::ReadyMarkedRevokePending => {
            &mut report.ready_marked_revoke_pending
        }
        GithubRuntimeAuthorityReconciliationReduction::IndeterminateAuthorityExpired => {
            &mut report.indeterminate_authorities_expired
        }
        GithubRuntimeAuthorityReconciliationReduction::ExpiredEnvelopeErased => {
            &mut report.expired_envelopes_erased
        }
        GithubRuntimeAuthorityReconciliationReduction::QuarantinedEnvelopeErased => {
            &mut report.quarantined_envelopes_erased
        }
    };
    let Some(incremented) = counter.checked_add(1) else {
        return false;
    };
    *counter = incremented;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_rehydration_preserves_sensitivity_validation() {
        assert!(
            logical_instance_result_output(
                "token".to_owned(),
                OutputSensitivity::SecretDerived,
                Some("must-not-survive".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn custody_requirements_preserve_strict_key_ordering() {
        let later = KeyId::new("key-b").expect("valid test key");
        let earlier = KeyId::new("key-a").expect("valid test key");
        assert!(
            secret_custody_requirements(
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                vec![later, earlier],
            )
            .is_err()
        );
    }

    #[test]
    fn custody_canary_schema_accessor_tracks_the_domain_format() {
        assert_eq!(
            secret_custody_canary_schema_version(),
            crate::secret_custody::SECRET_CUSTODY_CANARY_SCHEMA_VERSION
        );
    }

    #[test]
    fn reconciliation_reductions_use_controlled_counters() {
        let mut report = crate::GithubRuntimeAuthorityReconciliationReport::default();
        assert!(record_github_runtime_authority_reconciliation_reduction(
            &mut report,
            GithubRuntimeAuthorityReconciliationReduction::RevokedBeforeMint,
        ));
        assert_eq!(report.revoked_before_mint(), 1);
        assert_eq!(report.total(), 1);
    }
}
