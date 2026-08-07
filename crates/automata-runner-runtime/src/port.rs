use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use automata_core::{
    AttemptId, JobIrEnvelope, JobLifecycle, JobResult, Lease, LeaseGuard, LogChannel, OperationId,
    RunnerSessionId, UnixMillis,
};
use automata_execution::SandboxEnvironment;
use automata_protocol::JobRuntimeAuthorities;
use automata_protocol::{LeaseRejectionReason, RunnerSlotOrdinal};
use automata_runner_journal::{
    DurableContentRef, ProviderFailureOutcome, ProviderOperationKind, SandboxIdentity,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::content::CapacityReclaimError;
use uuid::Uuid;

use crate::MonotonicMillis;

/// Admission failure mapped to a stable lease-rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRejection {
    /// Local capacity changed after the poll.
    CapacityChanged,
    /// Required execution capability or attestation is unavailable.
    CapabilityChanged,
    /// The runner is draining.
    ShuttingDown,
    /// The decoded job is not executable by this adapter.
    InvalidJob,
}

impl AdmissionRejection {
    pub(crate) const fn protocol_reason(self) -> LeaseRejectionReason {
        match self {
            Self::CapacityChanged => LeaseRejectionReason::CapacityChanged,
            Self::CapabilityChanged => LeaseRejectionReason::CapabilityChanged,
            Self::ShuttingDown => LeaseRejectionReason::ShuttingDown,
            Self::InvalidJob => LeaseRejectionReason::InvalidJob,
        }
    }
}

/// Successful executor admission bound to exact attested launch material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionAdmission {
    environment: SandboxEnvironment,
}

impl ExecutionAdmission {
    /// Records the executor-selected launch material and its exact attestation.
    #[must_use]
    pub const fn new(environment: SandboxEnvironment) -> Self {
        Self { environment }
    }

    /// Returns the exact executor-selected sandbox environment.
    #[must_use]
    pub const fn environment(&self) -> &SandboxEnvironment {
        &self.environment
    }
}

/// Immutable input to one fresh or recovered job execution.
#[derive(Clone)]
pub struct ExecutionRequest {
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    lease: Lease,
    job: JobIrEnvelope,
    runtime_authorities: JobRuntimeAuthorities,
    job_content: DurableContentRef,
    environment: SandboxEnvironment,
    recovery_lifecycle: JobLifecycle,
    recovered_sandbox: Option<SandboxIdentity>,
}

impl ExecutionRequest {
    /// Constructs a request after a supervisor has durably accepted and fenced
    /// the exact lease, validated `JobIR`, protected its content, and admitted
    /// the exact environment attestation.
    ///
    /// Alternate supervisors must preserve those trust-boundary invariants;
    /// the executor independently validates correlations it can observe.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        lease: Lease,
        job: JobIrEnvelope,
        runtime_authorities: JobRuntimeAuthorities,
        job_content: DurableContentRef,
        environment: SandboxEnvironment,
        recovery_lifecycle: JobLifecycle,
        recovered_sandbox: Option<SandboxIdentity>,
    ) -> Self {
        Self {
            session_id,
            slot,
            lease,
            job,
            runtime_authorities,
            job_content,
            environment,
            recovery_lifecycle,
            recovered_sandbox,
        }
    }

    /// Returns the durable runner session.
    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    /// Returns the stable runner slot.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    /// Returns the exact fenced lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the validated `JobIR`.
    #[must_use]
    pub const fn job(&self) -> &JobIrEnvelope {
        &self.job
    }

    /// Returns exact server-issued authority protected before lease acceptance.
    #[must_use]
    pub const fn runtime_authorities(&self) -> &JobRuntimeAuthorities {
        &self.runtime_authorities
    }

    /// Returns the durable protected `JobIR` content identity.
    #[must_use]
    pub const fn job_content(&self) -> &DurableContentRef {
        &self.job_content
    }

    /// Returns exact launch material whose attestation matched the requirement.
    #[must_use]
    pub const fn environment(&self) -> &SandboxEnvironment {
        &self.environment
    }

    /// Returns the durable lifecycle from which this invocation is recovering.
    #[must_use]
    pub const fn recovery_lifecycle(&self) -> JobLifecycle {
        self.recovery_lifecycle
    }

    /// Returns the provider and opaque sandbox handle retained across restart.
    #[must_use]
    pub const fn recovered_sandbox(&self) -> Option<&SandboxIdentity> {
        self.recovered_sandbox.as_ref()
    }
}

impl fmt::Debug for ExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionRequest")
            .field("session_id", &self.session_id)
            .field("slot", &self.slot)
            .field("attempt_id", &self.lease.attempt_id())
            .field("guard", &self.lease.guard())
            .field("job_content", &self.job_content)
            .field("environment", &self.environment)
            .field("recovery_lifecycle", &self.recovery_lifecycle)
            .field("recovered_sandbox", &self.recovered_sandbox)
            .finish_non_exhaustive()
    }
}

/// Immutable input for post-terminal sandbox reconciliation.
#[derive(Clone, Debug)]
pub struct CleanupRequest {
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    attempt_id: AttemptId,
    guard: LeaseGuard,
    sandbox: SandboxIdentity,
}

impl CleanupRequest {
    /// Constructs post-terminal cleanup work for a sandbox identity retained
    /// by the durable journal. The caller must supply the same session, slot,
    /// attempt, and lease guard that own the identity.
    #[must_use]
    pub const fn new(
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        attempt_id: AttemptId,
        guard: LeaseGuard,
        sandbox: SandboxIdentity,
    ) -> Self {
        Self {
            session_id,
            slot,
            attempt_id,
            guard,
            sandbox,
        }
    }

    /// Returns the durable session.
    #[must_use]
    pub const fn session_id(&self) -> RunnerSessionId {
        self.session_id
    }

    /// Returns the stable slot.
    #[must_use]
    pub const fn slot(&self) -> RunnerSlotOrdinal {
        self.slot
    }

    /// Returns the attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the lease fence.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    /// Returns the provider and opaque sandbox handle.
    #[must_use]
    pub const fn sandbox(&self) -> &SandboxIdentity {
        &self.sandbox
    }
}

/// Reason communicated to an executor through a monotonic cancellation signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionCancellationReason {
    /// A durable server cancellation command was applied.
    ServerRequest,
    /// The local monotonic lease deadline elapsed.
    LeaseExpired,
    /// The negotiated session became stale.
    SessionLost,
    /// The runner process is shutting down.
    Shutdown,
}

#[derive(Debug)]
struct CancellationState {
    token: CancellationToken,
    reason: Mutex<Option<ExecutionCancellationReason>>,
}

/// Cloneable cancellation handle passed across the executor boundary.
#[derive(Clone, Debug)]
pub struct ExecutionCancellation(Arc<CancellationState>);

impl ExecutionCancellation {
    /// Creates an unsignalled cancellation source for one executor invocation.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(CancellationState {
            token: CancellationToken::new(),
            reason: Mutex::new(None),
        }))
    }

    /// Signals cancellation exactly once. Later reasons cannot replace the
    /// first cause observed by the executor and supervisor.
    pub fn signal(&self, reason: ExecutionCancellationReason) {
        let mut stored = self.0.reason.lock().unwrap_or_else(PoisonError::into_inner);
        if stored.is_none() {
            *stored = Some(reason);
            self.0.token.cancel();
        }
    }

    /// Returns a cancellation token for async provider operations.
    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.0.token.clone()
    }

    /// Returns the first durable/local reason that fired the signal.
    #[must_use]
    pub fn reason(&self) -> Option<ExecutionCancellationReason> {
        *self.0.reason.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns whether cancellation has fired.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.token.is_cancelled()
    }
}

impl Default for ExecutionCancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// One executor-produced log payload.
///
/// The runtime owns stream identity, sequence identity, and the terminal
/// end-of-stream marker. Executors can publish payloads only; returning a
/// [`JobResult`] (or an executor error) transfers terminal-log ownership back
/// to the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEvent {
    channel: LogChannel,
    payload: Vec<u8>,
}

impl LogEvent {
    /// Constructs a non-terminal payload event.
    ///
    /// Protocol payload validation is applied before commit. The runtime emits
    /// the terminal end-of-stream frame after the executor finishes.
    #[must_use]
    pub fn new(channel: LogChannel, payload: Vec<u8>) -> Self {
        Self { channel, payload }
    }

    /// Returns the logical output channel.
    #[must_use]
    pub const fn channel(&self) -> LogChannel {
        self.channel
    }

    /// Returns raw log bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Sanitized durable execution-event failure.
#[derive(Debug, Error)]
pub enum ExecutionEventError {
    /// The journal rejected or could not commit the event.
    #[error("execution event journal commit failed")]
    Journal(#[source] automata_runner_journal::JournalError),
    /// Protected content could not be committed or opened.
    #[error("execution event content commit failed")]
    Spool(#[source] automata_runner_spool::SpoolError),
    /// The event violated sequencing, lifecycle, or correlation invariants.
    #[error("execution event violates its durable contract")]
    InvalidEvent,
}

impl CapacityReclaimError for ExecutionEventError {
    fn is_capacity_exhausted(&self) -> bool {
        matches!(
            self,
            Self::Spool(automata_runner_spool::SpoolError::CapacityExhausted)
        )
    }

    fn from_spool(error: automata_runner_spool::SpoolError) -> Self {
        Self::Spool(error)
    }
}

/// Narrow callback surface for durable executor progress and provider sagas.
pub trait ExecutionEvents: fmt::Debug + Send + Sync {
    /// Commits a non-terminal lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionEventError`] if the transition is invalid or cannot
    /// be committed durably.
    fn transition(&self, next: JobLifecycle) -> Result<(), ExecutionEventError>;

    /// Publishes one payload-first ordered non-terminal log event.
    ///
    /// Executors never publish end-of-stream markers. After execution returns,
    /// the runtime durably appends and acknowledges EOS before delivering the
    /// terminal [`JobResult`].
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionEventError`] for invalid sequencing, payload limits,
    /// or a failed protected-content/journal commit.
    fn emit_log(&self, event: LogEvent) -> Result<(), ExecutionEventError>;

    /// Records or exactly resumes one provider mutation intention.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionEventError`] for invalid saga ordering or a failed
    /// durable commit.
    fn begin_provider_operation(
        &self,
        kind: ProviderOperationKind,
    ) -> Result<OperationId, ExecutionEventError>;

    /// Records the exact provider and sandbox handle immediately after create.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionEventError`] if the identity conflicts with the
    /// pending create operation or cannot be committed.
    fn sandbox_created(
        &self,
        operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<(), ExecutionEventError>;

    /// Marks a non-create provider mutation durably applied.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionEventError`] if no exact pending operation exists or
    /// its completion cannot be committed.
    fn provider_operation_completed(
        &self,
        operation_id: OperationId,
    ) -> Result<(), ExecutionEventError>;

    /// Classifies a provider failure without retaining raw diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionEventError`] if the failure conflicts with durable
    /// saga state or cannot be committed.
    fn provider_operation_failed(
        &self,
        operation_id: OperationId,
        failure: ProviderFailureOutcome,
    ) -> Result<(), ExecutionEventError>;
}

/// Secret-free executor failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorErrorKind {
    /// The admitted `JobIR` cannot be executed.
    InvalidJob,
    /// The selected provider cannot implement the requested semantics.
    Unsupported,
    /// A provider resource limit was reached.
    ResourceExhausted,
    /// Provider access was denied.
    PermissionDenied,
    /// A transient provider dependency failed.
    Unavailable,
    /// Provider work exceeded its deadline.
    TimedOut,
    /// Execution stopped in response to cancellation.
    Cancelled,
    /// An internal adapter invariant failed.
    Internal,
}

/// Sanitized executor error without raw command output or credentials.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("job executor failed with {kind:?}")]
pub struct ExecutorError {
    kind: ExecutorErrorKind,
}

impl ExecutorError {
    /// Creates a typed secret-free executor failure.
    #[must_use]
    pub const fn new(kind: ExecutorErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable category.
    #[must_use]
    pub const fn kind(self) -> ExecutorErrorKind {
        self.kind
    }
}

/// Boxed future returned by [`JobExecutor`].
pub type ExecutorFuture<'a> =
    Pin<Box<dyn Future<Output = Result<JobResult, ExecutorError>> + Send + 'a>>;

/// Boxed future returned by [`JobExecutor::cleanup`].
pub type CleanupFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + 'a>>;

/// Provider-neutral whole-job executor.
pub trait JobExecutor: fmt::Debug + Send + Sync {
    /// Selects a concrete exact environment before lease acceptance.
    ///
    /// The runtime independently requires this attestation to equal the `JobIR`
    /// requirement (ID and manifest digest) and the advertised inventory.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRejection`] before lease acceptance when the job or
    /// selected environment cannot be supported exactly.
    fn admit(&self, job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection>;

    /// Starts or reattaches to one admitted attempt.
    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_>;

    /// Reconciles a retained sandbox after a terminal result already exists.
    fn cleanup(
        &self,
        request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_>;
}

/// Wall and monotonic time source used by the supervisor.
pub trait RuntimeClock: fmt::Debug + Send + Sync {
    /// Returns wall time used only in protocol timestamps.
    fn wall_now(&self) -> UnixMillis;
    /// Returns process-local monotonic time used for leases and deadlines.
    fn monotonic_now(&self) -> MonotonicMillis;
}

/// Production runtime clock.
#[derive(Debug)]
pub struct SystemRuntimeClock {
    origin: Instant,
}

impl SystemRuntimeClock {
    /// Captures a process-local monotonic origin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemRuntimeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeClock for SystemRuntimeClock {
    fn wall_now(&self) -> UnixMillis {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| {
                i64::try_from(value.as_millis()).unwrap_or(i64::MAX)
            });
        UnixMillis::new(millis)
    }

    fn monotonic_now(&self) -> MonotonicMillis {
        MonotonicMillis::new(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// Boxed future returned by [`RuntimeSleeper`].
pub type SleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Injectable async delay boundary.
pub trait RuntimeSleeper: fmt::Debug + Send + Sync {
    /// Waits for a bounded delay or returns early when cancelled.
    fn sleep(&self, duration: Duration, cancellation: CancellationToken) -> SleepFuture<'_>;
}

/// Tokio-backed production sleeper.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioRuntimeSleeper;

impl RuntimeSleeper for TokioRuntimeSleeper {
    fn sleep(&self, duration: Duration, cancellation: CancellationToken) -> SleepFuture<'_> {
        Box::pin(async move {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {}
                () = tokio::time::sleep(duration) => {}
            }
        })
    }
}

/// Domain separator for deterministically reconstructed operation identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableIdDomain {
    /// Accepted lease response.
    LeaseAcceptance,
    /// Rejected lease response.
    LeaseRejection,
    /// Durable server-command cursor acknowledgement.
    CommandAcknowledgement,
    /// One ordered log frame request.
    LogFrame,
    /// One deterministic contiguous log delivery batch.
    LogBatch,
    /// Deterministic stream identity represented as an operation ID seed.
    LogStream,
    /// Provider mutation invoked through execution events.
    ProviderOperation,
}

impl StableIdDomain {
    const fn separator(self) -> &'static [u8] {
        match self {
            Self::LeaseAcceptance => b"automata.runtime.lease-acceptance.v1",
            Self::LeaseRejection => b"automata.runtime.lease-rejection.v1",
            Self::CommandAcknowledgement => b"automata.runtime.command-ack.v1",
            Self::LogFrame => b"automata.runtime.log-frame.v1",
            Self::LogBatch => b"automata.runtime.log-batch.v1",
            Self::LogStream => b"automata.runtime.log-stream.v1",
            Self::ProviderOperation => b"automata.runtime.provider-operation.v1",
        }
    }
}

/// Fresh and deterministic operation-ID source.
pub trait RuntimeIdSource: fmt::Debug + Send + Sync {
    /// Produces a fresh ID for an operation constructed and retained in memory
    /// or durably stored before it can be retried.
    fn fresh_operation_id(&self) -> OperationId;

    /// Deterministically derives an ID from non-secret stable identity bytes.
    /// Implementations must return the same result across process restarts.
    fn stable_operation_id(&self, domain: StableIdDomain, stable_identity: &[u8]) -> OperationId;
}

/// SHA-256 domain-separated production ID source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRuntimeIds;

impl RuntimeIdSource for SystemRuntimeIds {
    fn fresh_operation_id(&self) -> OperationId {
        OperationId::new()
    }

    fn stable_operation_id(&self, domain: StableIdDomain, stable_identity: &[u8]) -> OperationId {
        let mut digest = Sha256::new();
        digest.update(domain.separator());
        digest.update([0]);
        digest.update(stable_identity);
        let output: [u8; 32] = digest.finalize().into();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&output[..16]);
        // RFC 9562 variant and a name-derived version marker.
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        OperationId::from_uuid(Uuid::from_bytes(bytes))
    }
}
