#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Provider-neutral, crash-recoverable Automata runner supervision.
//!
//! This crate owns control-session and delivery semantics, but deliberately
//! does not know how a sandbox is implemented.  A [`JobExecutor`] adapter may
//! target rootless Podman today and Firecracker, Kubernetes, Windows, or macOS
//! later without changing the durable runner protocol.

mod config;
mod content;
mod control;
mod endpoint_replay;
mod endpoint_result;
mod error;
mod events;
mod observer;
mod orphan;
mod outbox;
mod port;
mod retry;
mod supervisor;
mod watchdog;

pub use config::{RetryPolicy, RunnerRuntimeConfig, RunnerRuntimeConfigError, RunnerRuntimeLimits};
pub use control::{
    RunnerRuntimeControlClient, RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture,
    RuntimeControlReply, RuntimeControlReplyError, RuntimeControlRetry,
    TransportControlClientAdapter,
};
pub use error::{RemotePhase, RunnerRuntimeError};
pub use observer::{
    NoopRunnerRuntimeObserver, RunnerRuntimeEvent, RunnerRuntimeObserver,
    RuntimeCancellationReason, RuntimeCommandKind, RuntimeCommandOutcome, RuntimeExchangeKind,
    RuntimeInfrastructureFailure, RuntimeJobConclusion, RuntimeJobStartMode,
    RuntimeLeaseDisposition, RuntimeLeasePollOutcome, RuntimeOperationOutcome,
    RuntimeReconnectReason, RuntimeRemoteErrorDisposition, RuntimeRemoteErrorKind,
    RuntimeRetryCause, RuntimeSessionMode, RuntimeSessionOutcome, RuntimeTerminalResultStage,
};
pub use port::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionCancellationReason, ExecutionEventError, ExecutionEvents, ExecutionRequest,
    ExecutorError, ExecutorErrorKind, ExecutorFuture, JobExecutor, LogEvent, RuntimeClock,
    RuntimeIdSource, RuntimeSleeper, SleepFuture, StableIdDomain, SystemRuntimeClock,
    SystemRuntimeIds, TokioRuntimeSleeper,
};
pub use supervisor::{RunnerRuntimePorts, RunnerSessionSupervisor};
pub use watchdog::{LeaseWatchdog, MonotonicMillis};
