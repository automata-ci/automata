#![forbid(unsafe_code)]
//! Provider-neutral, blob-first workflow admission.
//!
//! Dialect adapters materialize a validated [`automata_core::WorkflowPlan`]
//! into executable jobs. This crate publishes all immutable evidence first,
//! then commits the run, jobs, attempts, dependency graph, concurrency state,
//! and idempotency receipt through one atomic repository operation.

mod github;
mod id;
mod model;
mod port;
mod service;

pub use github::{GithubWorkflowMaterializer, github_hosted_ubuntu_24_04_catalog};
pub use id::{Sha256AdmissionIdGenerator, SystemAdmissionClock};
pub use model::{
    AdmissionRepositoryCoordinates, MaterializeWorkflowRequest, MaterializedWorkflow,
    MaterializedWorkflowJob, WorkflowAdmissionRequest, WorkflowAdmissionRequestBuilder,
    WorkflowAdmissionRequestError, WorkflowAdmissionResult, WorkflowJobIdentity,
    WorkflowMaterializationError,
};
pub use port::{AdmissionClock, AdmissionIdGenerator, WorkflowMaterializer};
pub use service::{WorkflowAdmissionError, WorkflowAdmissionService};

/// Immutable media type used for exact GitHub workflow source.
pub const GITHUB_WORKFLOW_MEDIA_TYPE: &str = "application/vnd.github-actions.workflow+yaml";
/// Immutable media type used for the exact provider event body.
pub const WORKFLOW_EVENT_MEDIA_TYPE: &str = "application/json";
/// Immutable media type used for canonical workflow-plan JSON.
pub const WORKFLOW_PLAN_MEDIA_TYPE: &str = "application/vnd.automata.workflow-plan+json";
/// Immutable media type expected by the runner control-plane `JobIR` reader.
pub const JOB_IR_MEDIA_TYPE: &str = "application/vnd.automata.job-ir.protobuf";
