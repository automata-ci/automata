use std::{fmt, time::Duration};

use automata_ci_execution::{ExecutionStage, ProviderStage};

/// Closed command stage spanning provider lifecycle and returned endpoints.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PodmanCommandStage {
    /// A command issued while creating, inspecting, or cleaning a sandbox.
    Provider(ProviderStage),
    /// A command issued through an endpoint returned to the executor.
    Endpoint(ExecutionStage),
}

/// Bounded process result that never exposes argv, output, or backend text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PodmanCommandOutcome {
    /// The command returned numeric exit status zero within its bounds.
    Success,
    /// The command returned a nonzero numeric exit status.
    NonzeroExit,
    /// The process exited without a numeric status, normally due to a signal.
    Signalled,
    /// A per-command or aggregate operation deadline expired.
    TimedOut,
    /// Caller cancellation stopped the command.
    Cancelled,
    /// The command could not be spawned or safely reaped.
    FailedToStart,
    /// Captured output exhausted its bounded aggregate byte budget.
    OutputTruncated,
    /// Expected anonymous input did not reach the child in full.
    InputIncomplete,
}

/// Finite Docker-compatible proxy route surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DockerProxyRoute {
    /// The Docker-compatible daemon liveness endpoint.
    Ping,
    /// The bounded daemon version endpoint.
    Version,
    /// A policy-filtered image build request.
    Build,
    /// Inspection of one attempt-owned image.
    ImageInspect,
    /// Deletion of one attempt-owned image.
    ImageDelete,
    /// Creation of one attempt-owned workload container.
    ContainerCreate,
    /// Inspection of one attempt-owned workload container.
    ContainerInspect,
    /// Another allowlisted operation on an attempt-owned container.
    ContainerOperation,
}

/// Terminal proxy handling result independent of backend HTTP status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DockerProxyOutcome {
    /// The request was admitted and a bounded backend response was relayed.
    Forwarded,
    /// The proxy rejected the request at its local policy boundary.
    Rejected,
    /// Bounded local transport failed before a complete response was relayed.
    IoError,
}

/// Closed rejection reason at the Docker-compatible policy boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DockerProxyRejection {
    /// The attempt already has the maximum number of concurrent connections.
    ConnectionLimit,
    /// The bounded HTTP request head was invalid or incomplete.
    MalformedHead,
    /// The request used an unsupported streaming or transfer encoding.
    UnsupportedTransfer,
    /// The request head or body exceeded its configured byte limit.
    RequestTooLarge,
    /// The route, method, parameters, or ownership evidence violated policy.
    Policy,
    /// No bounded proxy worker was available for the connection.
    WorkerUnavailable,
}

/// One identifier-free Podman adapter observation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PodmanEvent {
    /// A bounded Podman process was about to be executed.
    CommandStarted {
        /// The closed lifecycle stage, without sandbox or command identifiers.
        stage: PodmanCommandStage,
    },
    /// A bounded Podman process reached a terminal outcome.
    CommandCompleted {
        /// The closed lifecycle stage, without sandbox or command identifiers.
        stage: PodmanCommandStage,
        /// The sanitized terminal classification.
        outcome: PodmanCommandOutcome,
        /// Wall-clock time spent in the bounded execution boundary.
        duration: Duration,
        /// Number of retained standard-output bytes, never their contents.
        stdout_bytes: u64,
        /// Number of retained standard-error bytes, never their contents.
        stderr_bytes: u64,
    },
    /// An admitted Docker-compatible request began proxy handling.
    DockerRequestStarted {
        /// The closed route class, without path parameters or identifiers.
        route: DockerProxyRoute,
    },
    /// A Docker-compatible request reached a terminal proxy outcome.
    DockerRequestCompleted {
        /// The closed route class, without path parameters or identifiers.
        route: DockerProxyRoute,
        /// The sanitized proxy result, independent of backend response text.
        outcome: DockerProxyOutcome,
        /// Wall-clock time spent handling the request.
        duration: Duration,
        /// Complete request bytes observed, never their contents.
        request_bytes: u64,
        /// Complete response bytes relayed, never their contents.
        response_bytes: u64,
    },
    /// A connection or request was rejected before backend forwarding.
    DockerRejected {
        /// The closed local rejection class without request details.
        reason: DockerProxyRejection,
    },
}

/// Infallible adapter observer. Implementations must remain non-blocking.
pub trait PodmanObserver: fmt::Debug + Send + Sync {
    /// Records one bounded, identifier-free event without affecting execution.
    ///
    /// Implementations must not block or panic, and must not attach identifiers
    /// or unbounded command, path, payload, or backend values.
    fn observe(&self, event: PodmanEvent);
}

/// Production default when runner metrics are disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopPodmanObserver;

impl PodmanObserver for NoopPodmanObserver {
    fn observe(&self, _event: PodmanEvent) {}
}
