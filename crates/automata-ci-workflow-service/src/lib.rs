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
mod github;
mod github_activation;
mod github_autonomous;
mod id;
mod logical_projection;
mod materialization;
mod model;
mod observer;
mod orchestration;
mod port;
mod result_projection;
mod run_finalization;
mod runner_policy;
mod service;

pub use activation::{
    ActivateLogicalJobRequest, ActivatedJobInstance, ActivatedRunnerSelection,
    ActivationEvaluationContext, ActivationEvaluationSite, ActivationStatus, ActivationValue,
    LogicalActivationError, LogicalActivationEvaluator, LogicalActivationRequestError,
    LogicalActivationSession, LogicalJobActivation, LogicalJobActivator,
    MAX_ACTIVATION_OUTPUT_BYTES, MAX_MATRIX_CANDIDATE_COMBINATIONS, MAX_MATRIX_EXPANSION_WORK,
    ValidatedLogicalJob, ValidatedLogicalPlan,
};
pub use autonomous_workflow::{
    AUTONOMOUS_WORKFLOW_AUTHORITY_SAFETY_MILLIS, AutonomousActivationLease,
    AutonomousMaterializationLease, AutonomousPreparationLease, AutonomousWorkflowDeadline,
    AutonomousWorkflowError, AutonomousWorkflowExecutionFuture, AutonomousWorkflowExecutionOutcome,
    AutonomousWorkflowLeaseError, AutonomousWorkflowOutcome, AutonomousWorkflowPhase,
    AutonomousWorkflowPhaseExecutor, AutonomousWorkflowQueue, AutonomousWorkflowRenewalOutcome,
    AutonomousWorkflowService,
};
pub use github::GithubWorkflowPlanVerifier;
pub use github_activation::{
    GithubActivationContext, GithubActivationEvaluationError, GithubActivationSession,
    GithubLogicalActivationEvaluator,
};
pub use github_autonomous::GithubAutonomousWorkflowPhaseExecutor;
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

/// Immutable media type used for exact GitHub workflow source.
pub const GITHUB_WORKFLOW_MEDIA_TYPE: &str = "application/vnd.github-actions.workflow+yaml";
/// Immutable media type used for the exact provider event body.
pub const WORKFLOW_EVENT_MEDIA_TYPE: &str = "application/json";
/// Immutable media type used for canonical workflow-plan JSON.
pub const WORKFLOW_PLAN_MEDIA_TYPE: &str = "application/vnd.automata.workflow-plan+json";
