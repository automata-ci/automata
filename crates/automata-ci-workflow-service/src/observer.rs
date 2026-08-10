use std::{fmt, time::Duration};

/// Closed stages in one blob-first workflow admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowAdmissionStage {
    /// Validate the request and derive its immutable server-owned identities.
    Prepare,
    /// Convert the supplied plan into the durable logical workflow graph.
    Materialize,
    /// Canonically encode the immutable admission objects.
    Encode,
    /// Publish the immutable objects to blob storage.
    Publish,
    /// Atomically commit the logical workflow admission receipt.
    Commit,
}

/// Closed result of one admission stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowAdmissionStageOutcome {
    /// The stage completed successfully.
    Success,
    /// The stage stopped the admission attempt.
    Failure,
}

/// Privacy-safe failure categories for a physical admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowAdmissionFailure {
    /// The supplied plan could not be converted into a durable logical graph.
    Materialization,
    /// Immutable-object publication or verification failed.
    BlobStore,
    /// The logical admission transaction failed.
    DurableStore,
    /// The request or a replayed durable state violated an invariant.
    InvalidState,
}

/// Final physical and durable disposition of one admission request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowAdmissionObservation {
    /// A new durable workflow run and this many jobs committed.
    New {
        /// The number of logical jobs committed with the run.
        jobs: usize,
    },
    /// An identical prior durable admission receipt was replayed.
    Replay,
    /// The physical admission attempt failed without a new durable transition.
    Failed(WorkflowAdmissionFailure),
}

/// Provider-neutral observation seam for workflow admission.
///
/// Inputs contain only closed enums, durations, and bounded aggregate counts.
/// Request identities and provider-controlled strings never cross this seam.
pub trait WorkflowAdmissionObserver: fmt::Debug + Send + Sync {
    /// Records completion of one fixed admission stage.
    fn observe_stage(
        &self,
        _stage: WorkflowAdmissionStage,
        _outcome: WorkflowAdmissionStageOutcome,
        _duration: Duration,
    ) {
    }

    /// Records the final outcome of one physical admission attempt.
    fn observe_admission(&self, _outcome: WorkflowAdmissionObservation, _duration: Duration) {}
}

/// Observer used when metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopWorkflowAdmissionObserver;

impl WorkflowAdmissionObserver for NoopWorkflowAdmissionObserver {}
