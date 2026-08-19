#![forbid(unsafe_code)]
//! Backend-neutral durable control-plane values and repository ports.

mod admission;
mod assignment;
mod conformance;
mod error;
mod event_subject;
mod github_check_rerun;
mod github_checks;
mod github_job_runtime_authority;
mod github_provider_manifest;
mod github_schedule;
mod github_service_authority;
mod github_workflow_permissions;
mod live_log_ticket;
mod logical_activation;
mod logical_activation_preparation;
mod logical_instance_result;
mod logical_job_result;
mod logical_materialization;
mod logical_orchestration;
mod logical_run_finalization;
mod logical_work_selection;
mod managed_secret_authority;
mod outbox;
mod plan;
mod protected_environment;
mod provider_admission;
mod provider_delivery;
mod publication;
mod receipt;
mod reconciliation;
mod reusable_workflow_admission;
mod reusable_workflow_runtime;
mod runner_payload;
mod runtime_authority;
mod secret_custody;
mod secret_management;
mod session;
mod store_error;
mod tenant;
mod value;
mod web;
mod workflow_enable_state;
mod workflow_rerun;
mod workflow_runtime_policy;
mod workload_oidc;

/// Unstable construction and inspection hooks for Automata's first-party
/// durable adapters.
///
/// This module is not a supported public API. It is feature-gated so that
/// ordinary Store consumers cannot accidentally depend on adapter trust-boundary
/// operations, and it may change without notice alongside first-party adapters.
#[cfg(feature = "adapter-spi")]
#[doc(hidden)]
pub mod adapter_spi;

pub use admission::{
    AdmissionObject, AdmissionRepository, AdmitWorkflowRun, AdmitWorkflowRunBuilder,
    AdmittedWorkflowJob, MAX_ADMISSION_EVENT_BYTES, MAX_ADMISSION_OBJECT_BYTES, RepositoryId,
    WORKFLOW_ADMISSION_EPOCH, WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionIdempotency,
    WorkflowAdmissionReceipt, WorkflowAdmissionRepository, WorkflowAdmissionStoreError,
    WorkflowAdmissionValueError, WorkflowConcurrency, WorkflowSnapshotId,
};
pub use assignment::{AttemptAssignment, AttemptAssignmentError};
pub use automata_ci_core::Sha256Digest;
pub use automata_ci_provider::{
    ProviderDeliveryId, ProviderProcessingClaimFence, ProviderProcessingClaimSource,
    ProviderProcessingInvocationId, ProviderProcessingReceipt, ProviderProcessingState,
    ProviderProcessingWorkerId,
};
pub use conformance::{
    ConformanceDelivery, ConformanceDeliveryQuery, ConformanceDeliveryState,
    ConformanceReadRepository, ConformanceReadValueError, ConformanceWorkflowOutcome,
    ConformanceWorkflowResult, MAX_CONFORMANCE_DELIVERY_ID_BYTES,
};
pub use error::{
    AttemptCommandError, AttemptSnapshotError, AttemptStoreError, RepositoryOperationError,
};
pub use event_subject::{
    EVENT_CONTROL_SUBJECT_SCHEMA, EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
    EVENT_SUBJECT_PROGRESS_SCHEMA, EVENT_SUBJECT_SELECTION_SCHEMA, EventControlSubject,
    EventControlSubjectId, EventSubjectId, EventSubjectOrigin, EventSubjectOriginKind,
    EventSubjectOriginRegistration, EventSubjectOriginRegistry, EventSubjectProgress,
    EventSubjectProgressReceipt, EventSubjectRegistrationReceipt, EventSubjectRepository,
    EventSubjectSelection, EventSubjectStoreError, EventSubjectTerminalKind,
    EventSubjectTerminalOutcome, EventSubjectValueError, MAX_EVENT_SUBJECT_EVENT_NAME_BYTES,
    MAX_EVENT_SUBJECT_REASON_BYTES, MAX_EVENT_SUBJECT_WORKFLOW_PATH_BYTES, RegisterEventSubject,
};
pub use github_check_rerun::{
    GithubCheckRerunAction, GithubCheckRerunRepository, GithubCheckRerunRequest,
    GithubCheckRerunStoreError, GithubCheckRerunTarget, GithubCheckRerunValueError,
};
pub use github_checks::{
    AdvanceGithubCheckAnnotations, BeginGithubCheckAnnotationBatch, BeginGithubCheckRunCreate,
    BindGithubCheckRun, BindGithubCheckSuite, BlockGithubCheckAnnotationMismatch,
    BlockGithubCheckProjectionForCredentialRejection, ClaimGithubCheckProjection,
    ClaimedGithubCheckProjection, ClearGithubCheckAnnotationUncertainty,
    CompleteGithubCheckProjection, GithubCheckAnnotationProgress, GithubCheckAppId,
    GithubCheckConclusion, GithubCheckCreateReconciliation, GithubCheckDesiredProjection,
    GithubCheckDetailsTarget, GithubCheckName, GithubCheckProjectionAction,
    GithubCheckProjectionClaimFence, GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId,
    GithubCheckRunBindingFence, GithubCheckRunCreateFence, GithubCheckRunId, GithubCheckStoreError,
    GithubCheckSubjectId, GithubCheckSubjectIdentity, GithubCheckSubjectKey,
    GithubCheckSubjectOrigin, GithubCheckSubjectReceipt, GithubCheckSuiteId,
    GithubCheckTerminalCause, GithubCheckValueError, InitializeGithubCheckPresentation,
    MAX_GITHUB_CHECK_CREATE_RECONCILE_GRACE_MILLIS, MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS,
    MAX_GITHUB_CHECK_PROJECTION_CLAIM_MILLIS, MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS,
    ReleaseUnissuedGithubCheckAnnotationBatch, ReleaseUnissuedGithubCheckRunCreate,
    ResolveGithubCheckRunCreate, RetryGithubCheckProjection, RetryUncertainGithubCheckAnnotations,
};
pub use github_job_runtime_authority::{
    GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityExecution,
    GithubJobRuntimeAuthorityRepository, GithubJobRuntimeAuthorityResolution,
    GithubJobRuntimeAuthorityStoreError, GithubJobRuntimeAuthorityValueError,
};
pub use github_provider_manifest::{
    BootstrapGithubProviderManifest, BootstrapGithubProviderRepository,
    GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY, GITHUB_PROVIDER_API_ORIGIN,
    GITHUB_PROVIDER_ARCHIVE_ACCEPT, GITHUB_PROVIDER_ARCHIVE_FORMAT,
    GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES, GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES,
    GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES, GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES,
    GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES, GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS,
    GITHUB_PROVIDER_ARCHIVE_ORIGIN, GITHUB_PROVIDER_EVENT, GITHUB_PROVIDER_GIT_REF,
    GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES, GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS,
    GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION, GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
    GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS, GITHUB_PROVIDER_REST_ACCEPT,
    GITHUB_PROVIDER_REST_API_VERSION, GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, GITHUB_PROVIDER_SOURCE_REVISION,
    GITHUB_PROVIDER_WEB_ORIGIN, GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS,
    GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES, GITHUB_PROVIDER_WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN,
    GITHUB_PROVIDER_WORKFLOW_MAX_BYTES, GithubInstallationBindingGeneration, GithubProviderGitRef,
    GithubProviderManifest, GithubProviderManifestBootstrapReceipt, GithubProviderManifestLimits,
    GithubProviderManifestRecord, GithubProviderManifestRepository, GithubProviderManifestRevision,
    GithubProviderManifestStoreError, GithubProviderManifestValueError, GithubProviderOrigins,
    GithubProviderRepositoryBootstrapReceipt, GithubProviderRunnerPolicyObject,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    github_provider_repository_id,
};
pub use github_schedule::{
    ClaimDueGithubScheduleFire, ClaimGithubScheduleDiscovery, ClaimedGithubScheduleFire,
    CompleteGithubScheduleFire, GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE,
    GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE, GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE,
    GITHUB_SCHEDULE_SERVICE_ACTOR, GithubScheduleArchive, GithubScheduleClaimFence,
    GithubScheduleDiscoveryClaim, GithubScheduleFireClaim, GithubScheduleFireConclusion,
    GithubScheduleFireId, GithubScheduleFireReceipt, GithubScheduleRegistryEntry,
    GithubScheduleRegistryId, GithubScheduleRegistryReceipt, GithubScheduleRepository,
    GithubScheduleSourceAuthority, GithubScheduleStoreError, GithubScheduleValueError,
    GithubScheduleWorkerId, MAX_GITHUB_REGISTERED_SCHEDULES, MAX_GITHUB_SCHEDULE_CLAIM_MILLIS,
    MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS, MAX_GITHUB_SCHEDULE_RETRY_MILLIS,
    RegisterGithubScheduleRegistry, RegisterGithubScheduledCheckSubject, RetryGithubScheduleFire,
};
pub use github_service_authority::{
    AcquireGithubServerServiceHandoff, BeginGithubServerServiceMint,
    BeginGithubServerServiceMintOutcome, ClaimNextGithubServerServiceMaintenance,
    ClaimedGithubServerServiceMint, ClaimedGithubServerServiceRevocation,
    EnsureGithubServerServiceAuthority, FinishGithubServerServiceMint,
    FinishGithubServerServiceRevocation, GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS,
    GITHUB_SERVICE_GENERATION_FAILURE_BACKOFF_MILLIS, GITHUB_SERVICE_PROVIDER_CLOCK_SKEW_MILLIS,
    GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS, GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS,
    GithubServerServiceAction, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityDescriptor, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceClaim, GithubServerServiceClaimFence, GithubServerServiceConsumerClaim,
    GithubServerServiceConsumerId, GithubServerServiceCredentialHandoff,
    GithubServerServiceEnvelopeMetadata, GithubServerServiceFailureKind,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceReceipt, GithubServerServiceIssuanceState,
    GithubServerServiceJwtIssuer, GithubServerServiceMaintenanceOutcome,
    GithubServerServiceMintStart, GithubServerServiceRevision, GithubServerServiceScope,
    GithubServerServiceStoreError, GithubServerServiceValueError, GithubServerServiceWorkerId,
    MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES, MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS,
    MAX_GITHUB_SERVICE_HANDOFF_MILLIS, MAX_GITHUB_SERVICE_MINT_ATTEMPTS,
    MAX_GITHUB_SERVICE_MINT_CLAIM_MILLIS, MAX_GITHUB_SERVICE_MINT_RETRY_MILLIS,
    MAX_GITHUB_SERVICE_PLAINTEXT_BYTES, MAX_GITHUB_SERVICE_REQUEST_MILLIS,
    MAX_GITHUB_SERVICE_REVOKE_ATTEMPTS, MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS,
    MAX_GITHUB_SERVICE_REVOKE_RETRY_MILLIS, MIN_GITHUB_SERVICE_READY_USE_MILLIS,
    ProtectedGithubServerServiceCredential, QuarantineGithubServerServiceCredential,
    ReleaseGithubServerServiceHandoff, RetireGithubServerServiceAuthority,
};
pub use github_workflow_permissions::{
    FinalizeGithubWorkflowPermissionObservation,
    GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS,
    GithubWorkflowPermissionDefaultsObservation, GithubWorkflowPermissionDefaultsObservationError,
    GithubWorkflowPermissionDefaultsObservationRepository,
    GithubWorkflowPermissionHandoffReconciliation, GithubWorkflowPermissionObservationCandidate,
    ReconcileGithubWorkflowPermissionHandoff,
};
pub use live_log_ticket::{
    HUMAN_LIVE_LOG_PROTOCOL_VERSION, HumanLiveLogBrowserOrigin, HumanLiveLogScope,
    HumanLiveLogTicketRepository, HumanLiveLogTicketValueError, IssueHumanLiveLogTicket,
    IssueHumanLiveLogTicketOutcome, IssuedHumanLiveLogTicket, MAX_HUMAN_LIVE_LOG_TICKET_LIFETIME,
    RedeemHumanLiveLogTicket, RedeemedHumanLiveLogTicket,
};
pub use logical_activation::{
    ActivatedLogicalInstanceDescriptor, ClaimLogicalJobActivation, ClaimedLogicalJobActivation,
    LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE, LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    LOGICAL_JOB_SCHEDULING_POLICY_SCHEMA, LogicalActivationClaimFence,
    LogicalActivationExecutionContext, LogicalActivationGeneration, LogicalActivationObject,
    LogicalActivationPublicationReceipt, LogicalActivationRepository, LogicalActivationStoreError,
    LogicalActivationValueError, LogicalActivationWorkerId, LogicalJobSchedulingPolicyScope,
    LogicalWorkflowInstanceId, MAX_LOGICAL_ACTIVATED_INSTANCES,
    MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS, PublishLogicalJobActivation, RenewLogicalJobActivation,
    RenewedLogicalJobActivation, ResolvedLogicalJobSchedulingPolicy,
};
pub use logical_activation_preparation::{
    BindLogicalActivationPreparation, ClaimLogicalActivationPreparation,
    ClaimedLogicalActivationPreparation, LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE,
    LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE, LogicalActivationAggregateStatus,
    LogicalActivationBaseContextKind, LogicalActivationPreparationClaimFence,
    LogicalActivationPreparationClaimOutcome, LogicalActivationPreparationDescriptor,
    LogicalActivationPreparationGeneration, LogicalActivationPreparationReceipt,
    LogicalActivationPreparationStore, LogicalActivationPreparationStoreError,
    LogicalActivationPreparationTarget, LogicalActivationPreparationValueError,
    LogicalActivationPreparationWorkspace, LogicalActivationPrerequisiteEvidence,
    LogicalActivationPrerequisiteOutput, MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS,
    RenewLogicalActivationPreparation, RenewedLogicalActivationPreparation,
};
pub use logical_instance_result::{
    ClaimLogicalInstanceResult, ClaimNextLogicalInstanceResult, ClaimedLogicalInstanceResult,
    CommitLogicalInstanceResult, LOGICAL_INSTANCE_RESULT_MEDIA_TYPE,
    LogicalInstanceResultClaimFence, LogicalInstanceResultClaimNextOutcome,
    LogicalInstanceResultClaimOutcome, LogicalInstanceResultDescriptor,
    LogicalInstanceResultGeneration, LogicalInstanceResultOutput,
    LogicalInstanceResultQuarantineKind, LogicalInstanceResultQuarantineOutcome,
    LogicalInstanceResultReceipt, LogicalInstanceResultRepository,
    LogicalInstanceResultSelectionId, LogicalInstanceResultStoreError, LogicalInstanceResultTarget,
    LogicalInstanceResultValueError, LogicalInstanceResultWorkerId,
    LogicalInstanceTerminalAuthority, LogicalInstanceTerminalOrdinal,
    LogicalServerCancellationTerminal, LogicalTerminalResultObject,
    MAX_LOGICAL_INSTANCE_RESULT_CLAIM_MILLIS, QuarantineLogicalInstanceResult,
};
pub use logical_job_result::{
    ClaimLogicalJobResult, ClaimNextLogicalJobResult, ClaimedLogicalJobResult,
    CommitLogicalJobResult, LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE, LogicalJobInstanceOutput,
    LogicalJobInstanceResultEvidence, LogicalJobPrerequisiteEvidence, LogicalJobResultClaimFence,
    LogicalJobResultClaimNextOutcome, LogicalJobResultClaimOutcome, LogicalJobResultDescriptor,
    LogicalJobResultGeneration, LogicalJobResultOutput, LogicalJobResultQuarantineKind,
    LogicalJobResultQuarantineOutcome, LogicalJobResultReceipt, LogicalJobResultRepository,
    LogicalJobResultSelectionId, LogicalJobResultStoreError, LogicalJobResultTarget,
    LogicalJobResultValueError, LogicalJobResultWorkerId, MAX_LOGICAL_JOB_RESULT_CLAIM_MILLIS,
    QuarantineLogicalJobResult,
};
pub use logical_materialization::{
    ClaimLogicalInstanceMaterialization, ClaimedLogicalInstanceMaterialization,
    CommitLogicalInstanceMaterialization, LogicalInstanceMaterializationClaimOutcome,
    LogicalInstanceMaterializationDescriptor, LogicalInstanceMaterializationTarget,
    LogicalMaterializationClaimFence, LogicalMaterializationGeneration,
    LogicalMaterializationReceipt, LogicalMaterializationRepository,
    LogicalMaterializationStoreError, LogicalMaterializationValueError,
    LogicalMaterializationWorkerId, MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS,
    RenewLogicalInstanceMaterialization, RenewedLogicalInstanceMaterialization,
};
pub use logical_orchestration::{
    AdmitLogicalWorkflowRun, AdmitLogicalWorkflowRunBuilder, AdmittedLogicalWorkflowJob,
    AuthenticatedWorkflowDispatchClaim, AuthenticatedWorkflowDispatchSource,
    BeginWorkflowDispatchSourceResolution, CompleteWorkflowDispatchSourceResolution,
    LOGICAL_ORCHESTRATION_SCHEMA, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    LogicalWorkflowAdmissionValueError, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, MAX_WORKFLOW_DISPATCH_SOURCE_CLAIM_MILLIS,
    ResolveAuthenticatedWorkflowDispatchSource, WorkflowDispatchSourceClaim,
    WorkflowDispatchSourceResolutionOutcome, WorkflowDispatchSourceResolutionRepository,
    WorkflowDispatchSourceResolutionStoreError,
};
pub use logical_run_finalization::{
    ClaimLogicalRunFinalization, ClaimedLogicalRunFinalization, CommitLogicalRunFinalization,
    LogicalRunFinalizationClaimFence, LogicalRunFinalizationDescriptor,
    LogicalRunFinalizationGeneration, LogicalRunFinalizationOpenState,
    LogicalRunFinalizationReceipt, LogicalRunFinalizationRepository,
    LogicalRunFinalizationStoreError, LogicalRunFinalizationTarget,
    LogicalRunFinalizationValueError, LogicalRunFinalizationWorkerId,
    LogicalRunFinalizationWorkflowStatus, LogicalRunJobResultEvidence,
    MAX_LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
};
pub use logical_work_selection::{
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, ConsumedSelectedLogicalInstanceMaterialization,
    ConsumedSelectedLogicalJobOrchestration, LogicalInstanceMaterializationSelectionOutcome,
    LogicalJobOrchestrationAuthorityKind, LogicalJobOrchestrationSelectionOutcome,
    LogicalWorkQuarantineKind, LogicalWorkQuarantineOutcome, LogicalWorkSelectionGeneration,
    LogicalWorkSelectionId, LogicalWorkSelectionRepository, LogicalWorkSelectionStoreError,
    LogicalWorkSelectionValueError, MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES,
    MAX_LOGICAL_WORK_SELECTION_MILLIS, MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS,
    MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS, MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
    QuarantineLogicalInstanceMaterialization, QuarantineLogicalJobOrchestration,
    SelectedLogicalInstanceMaterialization, SelectedLogicalJobOrchestration,
};
pub use managed_secret_authority::{
    AcknowledgeManagedSecretDelivery, MANAGED_SECRET_AUTHORITY_SCHEMA, MAX_MANAGED_SECRET_BINDINGS,
    ManagedSecretAuthorityBinding, ManagedSecretAuthorityReceipt, ManagedSecretAuthorityRepository,
    ManagedSecretAuthorityStoreError, ManagedSecretAuthorityValueError, ManagedSecretBinding,
    ManagedSecretBindingSet, ManagedSecretDeliveryAcknowledgement, ManagedSecretDeliveryMachine,
    ManagedSecretDeliveryOperationId, ManagedSecretDeliveryProposal, ManagedSecretExecutionScope,
    ManagedSecretGrantMode, ManagedSecretScope, ResolveManagedSecretAuthority,
    ResolveManagedSecretDeliverySession, ResolveManagedSecretExecutionScope, SecretWorkloadGrantId,
};
pub use outbox::{
    AcknowledgeRunnerCommands, CommandCursor, CommandReplayDisposition, CommandReplayLimit,
    CommandReplayPage, CommandSequence, CommandValueError, DurableRunnerCommand,
    EnqueueRunnerCommand, LeaseOfferCommandIdentity, MAX_COMMAND_REPLAY_BYTES,
    MAX_COMMAND_REPLAY_LIMIT, RunnerCommandPayload,
};
pub use plan::{
    JobDependency, JobDependencyError, JobIrMetadata, JobIrMetadataError, WorkflowPlanRepository,
};
pub use protected_environment::{
    BindLeasedJobSecrets, DeploymentEnvironmentName, EnvironmentReviewDecision,
    InspectLeasedJobSecretBindings, IssueLeasedJobSecretGrants, IssuedLeasedJobSecretBinding,
    JobCredentialRequirements, JobEnvironmentActivationEvidence, JobEnvironmentGatePhase,
    JobEnvironmentGateSnapshot, JobEnvironmentGateState, JobEnvironmentRequirement, JobEventTrust,
    JobSourceKind, MAX_DEPLOYMENT_ENVIRONMENT_NAME_BYTES, MAX_JOB_CREDENTIAL_REFERENCES,
    PrepareJobEnvironment, ProtectedEnvironmentRepository, ProtectedEnvironmentStoreError,
    ProtectedEnvironmentValueError, ReusableSecretPermission, ReviewJobEnvironment,
    SecretLeaseAuthority,
};
pub use provider_admission::{
    AuthenticatedProviderDeliveryClaim, AuthenticatedProviderDeliveryClaimError,
};
pub use provider_delivery::{
    AcceptProviderDelivery, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, MAX_PROVIDER_DELIVERY_ATTEMPTS, MAX_PROVIDER_DELIVERY_CLAIM_MILLIS,
    MAX_PROVIDER_DELIVERY_EVENT_ENVELOPE_BYTES, MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS,
    MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, MAX_PROVIDER_DELIVERY_WORKFLOW_OUTCOMES,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimRenewalRepository,
    ProviderDeliveryEventEnvelope, ProviderDeliveryFailureKind, ProviderDeliveryIdentity,
    ProviderDeliveryReceipt, ProviderDeliveryRenewalTiming, ProviderDeliveryRepository,
    ProviderDeliveryState, ProviderDeliveryStoreError, ProviderDeliveryValueError,
    ProviderDeliveryWorkflowConclusion, ProviderDeliveryWorkflowInventory,
    ProviderDeliveryWorkflowInventoryEntry, ProviderDeliveryWorkflowInventoryReceipt,
    ProviderDeliveryWorkflowOutcome, ProviderDeliveryWorkflowSourceState, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RecordProviderDeliveryWorkflowProgress,
    RegisterProviderDeliveryWorkflowInventory, RejectProviderDelivery, RenewProviderDeliveryClaim,
    RenewedProviderDeliveryClaim, RetryProviderDelivery,
};
pub use publication::{
    PublicationRepositoryError, RepositoryPublicationRepository, RepositoryPublicationSettings,
    UpdateRepositoryPublication, UpdateRepositoryPublicationOutcome,
};
pub use receipt::{
    RunnerOperationKind, RunnerOperationReceipt, RunnerOperationRequest, RunnerOperationResponse,
    RunnerReceiptValueError,
};
pub use reconciliation::{RunReconciliation, RunReconciliationRepository, WorkflowRunStatus};
pub use reusable_workflow_admission::{
    AdmittedReusableInput, AdmittedReusableInputKind, AdmittedReusableInvocation,
    AdmittedReusableJob, AdmittedReusableOutput, AdmittedReusablePermissions,
    AdmittedReusableSecret, AdmittedReusableWorkflowCatalogEntry,
    AdmittedReusableWorkflowExpansion,
};
pub use reusable_workflow_runtime::{
    CompleteReusableWorkflowCall, EvaluatedReusableWorkflowOutput, MAX_REUSABLE_CALL_OUTPUTS,
    PublishReusableWorkflowCall, ReadyReusableWorkflowCall, ReadyReusableWorkflowCompletion,
    ReusableCallOutputMapping, ReusableWorkflowCompletionReceipt,
    ReusableWorkflowInputBindingEvidence, ReusableWorkflowOperationId,
    ReusableWorkflowPermissionSnapshot, ReusableWorkflowPublicationReceipt,
    ReusableWorkflowResultOutput, ReusableWorkflowRuntimeRepository,
    ReusableWorkflowRuntimeStoreError, ReusableWorkflowRuntimeValueError,
    ReusableWorkflowSecretBindingEvidence,
};
pub use runner_payload::{RunnerPayloadTombstone, RunnerPayloadTombstoneReason};
pub use runtime_authority::{
    AuthenticateGithubRuntimeAuthorityUnprotectedErasure, BeginGithubRuntimeAuthorityMint,
    BeginGithubRuntimeAuthorityMintOutcome, ClaimGithubRuntimeAuthorityMint,
    ClaimGithubRuntimeAuthorityRevocation, ClaimedGithubRuntimeAuthorityMint,
    ClaimedGithubRuntimeAuthorityRevocation, CommitGithubRuntimeAuthority,
    ConfirmGithubRuntimeAuthorityRevocation, DeferGithubRuntimeAuthorityRevocation,
    GITHUB_AUTHORITY_EXPIRY_SKEW_MILLIS, GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS,
    GITHUB_AUTHORITY_TOKEN_LIFETIME_MILLIS, GithubRepositoryId, GithubRepositoryName,
    GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityClaimFence,
    GithubRuntimeAuthorityCommitDisposition, GithubRuntimeAuthorityCorruptionKind,
    GithubRuntimeAuthorityEnvelopeMetadata, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityInspection, GithubRuntimeAuthorityKey,
    GithubRuntimeAuthorityMaterializationSelectionTail, GithubRuntimeAuthorityMintFailure,
    GithubRuntimeAuthorityNamespace, GithubRuntimeAuthorityPreparationSelectionTail,
    GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityReconciliationReport,
    GithubRuntimeAuthorityRepository, GithubRuntimeAuthorityRevocationFailure,
    GithubRuntimeAuthorityState, GithubRuntimeAuthorityStoreError,
    GithubRuntimeAuthorityTerminalReason, GithubRuntimeAuthorityValueError,
    GithubRuntimeAuthorityWorkerId, InspectGithubRuntimeAuthority, LoadGithubRuntimeAuthority,
    MAX_ACTIONS_RUNTIME_AUTHORITY_PLAINTEXT_BYTES, MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS,
    MAX_GITHUB_AUTHORITY_MINT_CLAIM_MILLIS, MAX_GITHUB_AUTHORITY_MINT_RETRY_BACKOFF_MILLIS,
    MAX_GITHUB_AUTHORITY_RECONCILE_BATCH, MAX_GITHUB_AUTHORITY_REQUEST_MILLIS,
    MAX_GITHUB_AUTHORITY_REVOKE_ATTEMPTS, MAX_GITHUB_AUTHORITY_REVOKE_BACKOFF_MILLIS,
    MAX_GITHUB_AUTHORITY_REVOKE_CLAIM_MILLIS, MarkGithubRuntimeAuthorityIndeterminate,
    ProtectedGithubRuntimeAuthority, QuarantineGithubRuntimeAuthority, ReadyGithubRuntimeAuthority,
    ReconcileGithubRuntimeAuthorities, RejectGithubRuntimeAuthorityMint,
    RetryGithubRuntimeAuthorityMint, RetryGithubRuntimeAuthorityRevocation,
    RevalidateGithubRuntimeAuthorityRevocation, RevalidatedGithubRuntimeAuthorityRevocation,
};
pub use secret_custody::{
    MAX_SECRET_CUSTODY_CONFIGURED_KEYS, SECRET_CUSTODY_CANARY_GENERATION,
    SecretCustodyCanaryBinding, SecretCustodyCanaryGeneration, SecretCustodyKeySet,
    SecretCustodyRepository, SecretCustodyRepositoryError, SecretCustodyRequirements,
    SecretCustodyValueError, VerifiedSecretCustody, VerifySecretCustody,
    VerifySecretCustodyOutcome,
};
pub use secret_management::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome,
    BUILTIN_SECRET_PROVIDER_ID, BuiltinRepositorySecretVersion, BuiltinSecretCleanupRepository,
    BuiltinSecretCleanupTask, BuiltinSecretProviderActivationEvidence, BuiltinSecretProviderHealth,
    BuiltinSecretProviderInspection, BuiltinSecretProviderMetadata, BuiltinSecretProviderState,
    ClaimBuiltinSecretCleanup, ClaimBuiltinSecretCleanupOutcome, ClaimSecretMutationRecovery,
    ClaimSecretMutationRecoveryOutcome, CompleteBuiltinSecretCleanup,
    CompleteBuiltinSecretCleanupOutcome, ConfirmRepositorySecretVersionMutation,
    ConfirmRepositorySecretVersionMutationOutcome, DeleteRepositorySecret,
    DeleteRepositorySecretOutcome, GetRepositorySecretMetadata, GetRepositorySecretMetadataOutcome,
    InspectBuiltinSecretProvider, InspectBuiltinSecretProviderOutcome, ListRepositorySecrets,
    ListRepositorySecretsOutcome, MAX_SECRET_CLEANUP_ATTEMPTS, MAX_SECRET_CLEANUP_CLAIM_MILLIS,
    MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS, MAX_SECRET_METADATA_PAGE_SIZE,
    MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS, ManagedSecretProviderId,
    RecoverSecretMutationReservation, RecoverSecretMutationReservationOutcome,
    RepositorySecretDeletionReceipt, RepositorySecretId, RepositorySecretManagementReadRepository,
    RepositorySecretManagementRepository, RepositorySecretMetadata, RepositorySecretMetadataPage,
    RepositorySecretMutationId, RepositorySecretMutationKind, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretState, RepositorySecretVersionId,
    RepositorySecretVersionMutationReceipt, RepositorySecretVersionMutationReservation,
    ReserveRepositorySecretVersionMutation, ReserveRepositorySecretVersionMutationOutcome,
    ResolveGithubRepositorySecretMetadata, ResolveGithubRepositorySecretMetadataOutcome,
    RetryBuiltinSecretCleanup, RetryBuiltinSecretCleanupOutcome,
    SECRET_MUTATION_CONFIRMATION_TTL_MILLIS, SecretCleanupFailureKind, SecretCleanupFence,
    SecretCleanupWorkerId, SecretManagementRepositoryError, SecretManagementValueError,
    SecretMetadataPageSize, SecretMutationRecoveryFence, SecretMutationRecoveryReconciliation,
    SecretMutationRecoveryRepository, SecretMutationRecoveryTask,
};
pub use session::{
    CloseRunnerSession, HeartbeatRunnerSession, OpenRunnerSession, ResumeRunnerSession,
    RunnerSessionFence, RunnerSessionSnapshot, RunnerSessionSnapshotError,
};
pub use store_error::StoreError;
pub use tenant::{TenantScope, TenantScopeError};
pub use value::{
    DocumentSchema, DurabilityValueError, MAX_JOB_IR_BYTES, MAX_LOG_SEGMENT_BYTES,
    MAX_ROUTING_DOCUMENT_BYTES, MAX_TERMINAL_RESULT_BYTES, ObjectKey, RoutingDocument,
    RoutingLabel, RunnerGeneration, RunnerProtocolVersion, RunnerSlotCount, SessionEpoch,
    StableRunnerSlot,
};
pub use web::{
    DEFAULT_HUMAN_LOG_SEGMENT_PAGE_SIZE, DEFAULT_HUMAN_PAGE_SIZE, HUMAN_JOB_RESULT_MEDIA_TYPE,
    HUMAN_LOG_SEGMENT_MEDIA_TYPE, HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA, HumanArtifactBlock,
    HumanArtifactDownload, HumanArtifactId, HumanArtifactScope, HumanArtifactSummary,
    HumanAuthorizationTarget, HumanGitRef, HumanJob, HumanJobAttempt, HumanJobDetail,
    HumanJobNavigation, HumanJobScope, HumanLogCommitHint, HumanLogCommitNotificationHub,
    HumanLogCommitNotificationSource, HumanLogCommitSubscription, HumanLogSegment,
    HumanLogSegmentCursor, HumanLogSegmentPage, HumanLogSegmentPageDirection,
    HumanLogSegmentPageSize, HumanLogSegmentQuery, HumanLogStream, HumanLogTailWake,
    HumanOutputPublication, HumanPageSize, HumanRawLogDisposition, HumanReadValueError,
    HumanRepository, HumanRepositoryCursor, HumanRepositoryListQuery, HumanRepositoryPage,
    HumanRun, HumanRunConclusion, HumanRunCursor, HumanRunDetail, HumanRunListQuery, HumanRunPage,
    HumanRunPageDirection, HumanRunPublication, HumanRunScope, HumanRunStatusFilter, HumanRunner,
    HumanTerminalResult, HumanWorkflow, HumanWorkflowCursor, HumanWorkflowListQuery,
    HumanWorkflowPage, HumanWorkflowProjectedName, HumanWorkflowReadRepository,
    MAX_HUMAN_LOG_SEGMENT_PAGE_SIZE, MAX_HUMAN_PAGE_SIZE, RepositoryCoordinate,
    forward_human_log_commit_notifications, human_output_publication_safety_schema_is_current,
};
pub use workflow_enable_state::{
    SetWorkflowEnableState, WorkflowEnableState, WorkflowEnableStateReceipt,
    WorkflowEnableStateRecord, WorkflowEnableStateRepository, WorkflowEnableStateRevision,
    WorkflowEnableStateStoreError, WorkflowEnableStateValueError,
};
pub use workflow_rerun::{
    MAX_WORKFLOW_RERUN_AGE_MILLIS, MAX_WORKFLOW_RERUN_ATTEMPTS, RerunWorkflow, RerunWorkflowByName,
    WorkflowRerunReceipt, WorkflowRerunRepository, WorkflowRerunSelection, WorkflowRerunStoreError,
    WorkflowRerunValueError, next_workflow_rerun_attempt,
};
pub use workflow_runtime_policy::{
    MAX_WORKFLOW_RUNTIME_POLICY_BYTES, MAX_WORKFLOW_RUNTIME_POLICY_FEATURES,
    MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS, MAX_WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURES,
    PinnedWorkflowRuntimePolicy, RegisterWorkflowRuntimePolicy, WORKFLOW_RUNTIME_POLICY_MEDIA_TYPE,
    WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURE_SCHEMA, WORKFLOW_RUNTIME_POLICY_SCHEMA,
    WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT, WORKFLOW_RUNTIME_POLICY_WORKSPACE_SCHEMA,
    WORKFLOW_WORKSPACE_DERIVATION_VERSION, WorkflowPermissionPolicy, WorkflowRunnerFeaturePolicy,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyMapping, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyReceipt, WorkflowRuntimePolicyRepository, WorkflowRuntimePolicyRevision,
    WorkflowRuntimePolicyStoreError, WorkflowRuntimePolicyValueError,
};
pub use workload_oidc::{
    MAX_WORKLOAD_OIDC_ISSUANCE_SLOTS, MAXIMUM_OIDC_KEYS_PER_KEYRING,
    MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS, OIDC_JWKS_CACHE_SECONDS,
    ReserveWorkloadOidcAuthority, ReservedWorkloadOidcAuthority, RetainWorkloadOidcKey,
    WORKLOAD_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN,
    WORKLOAD_OIDC_RS256_PUBLIC_KEY_FINGERPRINT_DOMAIN, WorkloadOidcAuthorityProposal,
    WorkloadOidcAuthorityRepository, WorkloadOidcCurrentPolicy, WorkloadOidcCurrentnessClock,
    WorkloadOidcCurrentnessClockError, WorkloadOidcExecutionIdentity, WorkloadOidcKeyDeadline,
    WorkloadOidcKeyRetentionRepository, WorkloadOidcKeyUse, WorkloadOidcLoadedKey,
    WorkloadOidcStoreError, WorkloadOidcSubjectPolicyMode, WorkloadOidcSubjectPolicyRevision,
    WorkloadOidcValueError, workload_oidc_rs256_public_key_fingerprint,
};
