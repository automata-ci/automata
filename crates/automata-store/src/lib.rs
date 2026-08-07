#![forbid(unsafe_code)]
//! Durable control-plane storage ports and their `PostgreSQL` adapter.

mod admission;
mod assignment;
mod attempt;
mod blocked;
mod cancellation;
mod error;
mod log_metadata;
mod maintenance;
mod migration;
mod operation;
mod outbox;
mod plan;
mod postgres;
mod receipt;
mod reconciliation;
mod routing;
mod runnable;
mod runner_control;
mod session;
mod snapshot;
mod store_error;
mod tenant;
mod terminal;
mod value;

pub use admission::{
    AdmissionObject, AdmissionRepository, AdmitWorkflowRun, AdmitWorkflowRunBuilder,
    AdmittedWorkflowJob, MAX_ADMISSION_OBJECT_BYTES, RepositoryId, WORKFLOW_ADMISSION_EPOCH,
    WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionIdempotency, WorkflowAdmissionReceipt,
    WorkflowAdmissionRepository, WorkflowAdmissionStoreError, WorkflowAdmissionValueError,
    WorkflowConcurrency, WorkflowSnapshotId,
};
pub use assignment::{AttemptAssignment, AttemptAssignmentError};
pub use attempt::{
    AcquireLease, ConcludeQueuedAttempt, InternalAttemptRepository, QueuedAttempt, RenewLease,
    TenantAttemptQuery, TransitionAttempt,
};
pub use automata_core::Sha256Digest;
pub use blocked::{
    BlockedAttempt, BlockedAttemptRepository, BlockedConclusion, ConcludeBlockedAttempt,
};
pub use cancellation::{
    CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload, CancellationActor,
    CancellationIntent, CancellationIntentError, CancellationReason, CancellationRepository,
    CancellationValueError, DEFAULT_CANCELLATION_REASON, RequestCancellation,
};
pub use error::{
    AttemptCommandError, AttemptSnapshotError, AttemptStoreError, RepositoryOperationError,
};
pub use log_metadata::{
    LogMetadataReceipt, LogMetadataRepository, LogSegmentMetadata, LogSegmentMetadataError,
    LogStreamMetadata,
};
pub use maintenance::{
    ControlPlaneMaintenanceReport, ControlPlaneMaintenanceRepository,
    ControlPlaneMaintenanceRequest, ExpiredAttemptDisposition, ExpiredAttemptMaintenance,
    LeaseFailureLimit, MAX_MAINTENANCE_BATCH_SIZE, MaintenanceBatchSize, MaintenanceValueError,
    StaleSessionTimeoutMillis,
};
pub use operation::{
    BeginLeaseRequest, BegunLeaseRequest, ClaimCommandError, ClaimRejection, ClaimedAttempt,
    CompleteLeaseRequest, LeaseRequestKey, LeaseRequestKeyError, NoWorkLeaseRequest,
    RunnerClaimRepository, RunnerLeaseRequestRepository, TryClaimAttempt, TryClaimOutcome,
    TryClaimReceipt,
};
pub use outbox::{
    AcknowledgeRunnerCommands, CommandCursor, CommandReplayLimit, CommandSequence,
    CommandValueError, DurableRunnerCommand, EnqueueRunnerCommand, MAX_COMMAND_REPLAY_BYTES,
    MAX_COMMAND_REPLAY_LIMIT, RunnerCommandOutbox, RunnerCommandPayload,
};
pub use plan::{
    JobDependency, JobDependencyError, JobIrMetadata, JobIrMetadataError, WorkflowPlanRepository,
};
pub use postgres::{PostgresStore, PostgresStoreError};
pub use receipt::{
    RunnerOperationKind, RunnerOperationReceipt, RunnerOperationReceiptRepository,
    RunnerOperationRequest, RunnerOperationResponse, RunnerReceiptValueError,
};
pub use reconciliation::{RunReconciliation, RunReconciliationRepository, WorkflowRunStatus};
pub use routing::{
    RoutingSnapshotError, RunnerGroupId, RunnerRoutingRepository, RunnerRoutingSnapshot,
    RunnerSlotAvailability, RunnerSlotAvailabilityRepository,
};
pub use runnable::{
    MAX_RUNNABLE_SCAN_LIMIT, RunnableAttempt, RunnableAttemptError, RunnableAttemptRepository,
    RunnableCursorAdvance, RunnableQueueKey, RunnableScanError, RunnableScanLimit,
    RunnableScanPage, RunnableScanRequest,
};
pub use runner_control::{
    CommitCommandAcknowledgement, CommitLeaseHeartbeat, CommitLeaseResponse,
    CommitRunnerLogSegment, CommitRunnerTerminalResult, CurrentRunnerSession,
    CurrentRunnerSessionRepository, LeaseOfferClaim, LeaseOfferClaimStatus,
    LeaseOfferCommandIdentity, LeaseResponseAction, PublishLeaseOffer, PublishedLeaseOffer,
    RunnerControlTransactionRepository, RunnerControlValueError, RunnerLeaseOfferRepository,
};
pub use session::{
    CloseRunnerSession, HeartbeatRunnerSession, OpenRunnerSession, ResumeRunnerSession,
    RunnerSessionFence, RunnerSessionRepository, RunnerSessionSnapshot, RunnerSessionSnapshotError,
};
pub use snapshot::{AttemptSnapshot, AttemptSnapshotBuilder};
pub use store_error::StoreError;
pub use tenant::{TenantScope, TenantScopeError};
pub use terminal::{
    TerminalResultMetadata, TerminalResultMetadataError, TerminalResultReceipt,
    TerminalResultRepository,
};
pub use value::{
    DocumentSchema, DurabilityValueError, MAX_JOB_IR_BYTES, MAX_LOG_SEGMENT_BYTES,
    MAX_ROUTING_DOCUMENT_BYTES, MAX_TERMINAL_RESULT_BYTES, ObjectKey, RoutingDocument,
    RoutingLabel, RunnerGeneration, RunnerProtocolVersion, RunnerSlotCount, SessionEpoch,
    StableRunnerSlot,
};
