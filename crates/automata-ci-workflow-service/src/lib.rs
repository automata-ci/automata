#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Provider-neutral, blob-first workflow admission.
//!
//! Dialect adapters recompile exact source and verify the supplied
//! [`automata_ci_core::WorkflowPlan`]. This crate publishes immutable source,
//! event, and plan evidence first, then atomically commits the logical run DAG
//! for later fenced activation.

mod activation;
mod activation_preparation;
mod autonomous_workflow;
mod credential_requirements;
mod github;
mod github_activation;
mod github_autonomous;
mod github_dispatch;
mod github_schedule;
mod id;
mod logical_projection;
mod materialization;
mod model;
mod observer;
mod orchestration;
mod port;
mod result_projection;
mod reusable_runtime;
mod reusable_workflow;
mod run_finalization;
mod runner_policy;
mod service;
mod workflow_rerun;

pub use activation::{
    ActivateLogicalJobRequest, ActivatedDeploymentEnvironment, ActivatedJobInstance,
    ActivatedJobResources, ActivatedResourceVector, ActivatedRunnerSelection,
    ActivationEvaluationContext, ActivationEvaluationSite, ActivationStatus, ActivationValue,
    LogicalActivationError, LogicalActivationEvaluator, LogicalActivationRequestError,
    LogicalActivationSession, LogicalJobActivation, LogicalJobActivator,
    MAX_ACTIVATION_OUTPUT_BYTES, MAX_MATRIX_CANDIDATE_COMBINATIONS, MAX_MATRIX_EXPANSION_WORK,
    ValidatedLogicalJob, ValidatedLogicalPlan,
};
pub use automata_ci_workflow_github::{
    GithubWorkflowDispatchInputValue, GithubWorkflowDispatchInputsV1,
};
pub use autonomous_workflow::{
    AUTONOMOUS_WORKFLOW_AUTHORITY_SAFETY_MILLIS, AutonomousActivationLease,
    AutonomousMaterializationLease, AutonomousPreparationLease, AutonomousWorkflowDeadline,
    AutonomousWorkflowError, AutonomousWorkflowExecutionFuture, AutonomousWorkflowExecutionOutcome,
    AutonomousWorkflowLeaseError, AutonomousWorkflowOutcome, AutonomousWorkflowPhase,
    AutonomousWorkflowPhaseExecutor, AutonomousWorkflowQueue, AutonomousWorkflowRenewalOutcome,
    AutonomousWorkflowService,
};
pub use credential_requirements::{CredentialDiscoveryError, discover_job_credential_requirements};
pub use github::GithubWorkflowPlanVerifier;
pub use github_activation::{
    GithubActivationContext, GithubActivationEvaluationError, GithubActivationSession,
    GithubLogicalActivationEvaluator,
};
pub use github_autonomous::GithubAutonomousWorkflowPhaseExecutor;
pub use github_dispatch::{
    AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE, DurableGithubWorkflowDispatchRequest,
    GithubWorkflowDispatchError, GithubWorkflowDispatchEvidenceError,
    GithubWorkflowDispatchEvidenceV1, GithubWorkflowDispatchRequest,
    GithubWorkflowDispatchRequestError, GithubWorkflowDispatchService,
    WorkflowDispatchAuthorization,
};
pub use github_schedule::{
    AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE, GithubScheduleEvidenceError,
    GithubScheduleEvidenceV1,
};
pub use id::{Sha256AdmissionIdGenerator, SystemAdmissionClock};
pub use logical_projection::{
    GithubLogicalJobProjector, JOB_RUNTIME_CONTEXT_MEDIA_TYPE, LogicalJobProjectionError,
    ProjectGithubLogicalJobRequest, ProjectedGithubLogicalJob, UnsupportedLogicalJobSemantics,
};
pub use model::{
    AdmissionRepositoryCoordinates, WorkflowAdmissionRequest, WorkflowAdmissionRequestBuilder,
    WorkflowAdmissionRequestError, WorkflowAdmissionResult, WorkflowPlanVerificationError,
};
pub use observer::{
    NoopWorkflowAdmissionObserver, WorkflowAdmissionFailure, WorkflowAdmissionObservation,
    WorkflowAdmissionObserver, WorkflowAdmissionStage, WorkflowAdmissionStageOutcome,
};
pub use port::{AdmissionClock, AdmissionIdGenerator, WorkflowPlanVerifier};
pub use result_projection::{
    LOGICAL_RESULT_PROJECTION_CLAIM_MILLIS, LogicalResultProjectionError,
    LogicalResultProjectionOutcome, LogicalResultProjectionService,
};
pub use reusable_runtime::{
    ReusableWorkflowRuntimeError, ReusableWorkflowRuntimeOutcome, ReusableWorkflowRuntimeService,
};
pub use reusable_workflow::{
    CatalogedReusableWorkflow, ExpandReusableWorkflowRequest, ExpandedReusableInput,
    ExpandedReusableJob, ExpandedReusableOutput, ExpandedReusableOutputMapping,
    ExpandedReusableSecret, GithubReusableWorkflowCatalog, MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES,
    MAX_REUSABLE_WORKFLOW_DEPTH, MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS,
    MAX_REUSABLE_WORKFLOW_INVOCATIONS, RepositoryWorkflowSource, ReusableInputBindingSource,
    ReusableWorkflowExpander, ReusableWorkflowExpansion, ReusableWorkflowExpansionError,
    ReusableWorkflowInvocationExpansion, ReusableWorkflowLimits, ReusableWorkflowPermissions,
};
pub use run_finalization::{
    LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS, LogicalRunFinalizationError,
    LogicalRunFinalizationOutcome, LogicalRunFinalizationService,
    PendingLogicalRunFinalizationCommit,
};
pub use runner_policy::{
    GITHUB_RUNNER_POLICY_MEDIA_TYPE, GithubRunnerPolicy, GithubRunnerPolicyError,
    MAX_GITHUB_RUNNER_POLICY_BYTES, MAX_GITHUB_RUNNER_POLICY_CONTAINER_FEATURES,
    MAX_GITHUB_RUNNER_POLICY_MAPPINGS,
};
pub use service::{WorkflowAdmissionError, WorkflowAdmissionService};
pub use workflow_rerun::WorkflowRerunService;

/// Immutable media type used for exact GitHub workflow source.
pub const GITHUB_WORKFLOW_MEDIA_TYPE: &str = "application/vnd.github-actions.workflow+yaml";
/// Immutable media type used for the exact provider event body.
pub const WORKFLOW_EVENT_MEDIA_TYPE: &str = "application/json";
/// Immutable media type used for canonical workflow-plan JSON.
pub const WORKFLOW_PLAN_MEDIA_TYPE: &str = "application/vnd.automata.workflow-plan+json";
