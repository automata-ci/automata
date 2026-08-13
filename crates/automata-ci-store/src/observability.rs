use std::{collections::BTreeSet, fmt, time::Duration};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, JobId, JobLifecycle, RunnerCapabilities, RunnerRequirements, UnixMillis,
};
use thiserror::Error;

use crate::{
    RoutingLabel, RunnerSessionFence, RunnerSlotCount, StableRunnerSlot, StoreError,
    WorkflowRunStatus,
};

/// Default horizon used to distinguish leases that require prompt attention.
pub const LEASE_NEAR_EXPIRY_WINDOW: Duration = Duration::from_mins(1);

/// Maximum exact runnable prefix retained for one capacity observation.
///
/// The sampler fails closed instead of publishing partial compatibility
/// aggregates when the exact eligible queue exceeds this bound.
pub const MAX_CONTROL_PLANE_CAPACITY_CANDIDATES: usize = 1_000;

/// Maximum effective runner records retained for one capacity observation.
pub const MAX_CONTROL_PLANE_CAPACITY_RUNNERS: usize = 64;

/// Maximum registered slots accepted in one capacity observation.
pub const MAX_CONTROL_PLANE_CAPACITY_SLOTS_PER_RUNNER: u16 = 256;

/// One trusted-time request for a consistent durable control-plane snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneStateSnapshotRequest {
    observed_at: UnixMillis,
    near_expiry_at: UnixMillis,
}

impl ControlPlaneStateSnapshotRequest {
    /// Creates a request with a positive, signed-millisecond expiry horizon.
    ///
    /// # Errors
    ///
    /// Rejects a zero, sub-millisecond, too-large, or overflowing horizon.
    pub fn new(
        observed_at: UnixMillis,
        near_expiry_window: Duration,
    ) -> Result<Self, ControlPlaneStateValueError> {
        let millis = i64::try_from(near_expiry_window.as_millis())
            .map_err(|_| ControlPlaneStateValueError::InvalidNearExpiryWindow)?;
        if millis == 0 || !near_expiry_window.subsec_nanos().is_multiple_of(1_000_000) {
            return Err(ControlPlaneStateValueError::InvalidNearExpiryWindow);
        }
        let near_expiry_at = observed_at
            .get()
            .checked_add(millis)
            .map(UnixMillis::new)
            .ok_or(ControlPlaneStateValueError::NearExpiryCutoffOutOfRange)?;
        Ok(Self {
            observed_at,
            near_expiry_at,
        })
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn near_expiry_at(self) -> UnixMillis {
        self.near_expiry_at
    }
}

/// Closed observed connectivity state persisted for a runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerObservedState {
    Offline,
    Online,
}

impl RunnerObservedState {
    pub const ALL: [Self; 2] = [Self::Offline, Self::Online];

    const fn index(self) -> usize {
        match self {
            Self::Offline => 0,
            Self::Online => 1,
        }
    }
}

/// Closed operator intent persisted for a runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerDesiredState {
    Active,
    Draining,
    Disabled,
}

impl RunnerDesiredState {
    pub const ALL: [Self; 3] = [Self::Active, Self::Draining, Self::Disabled];

    const fn index(self) -> usize {
        match self {
            Self::Active => 0,
            Self::Draining => 1,
            Self::Disabled => 2,
        }
    }
}

/// Closed durable runner-session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerSessionState {
    Live,
    Disconnected,
}

impl RunnerSessionState {
    pub const ALL: [Self; 2] = [Self::Live, Self::Disconnected];

    const fn index(self) -> usize {
        match self {
            Self::Live => 0,
            Self::Disconnected => 1,
        }
    }
}

/// Closed lease-expiration band relative to one trusted observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Active,
    NearExpiry,
    Expired,
}

impl LeaseState {
    pub const ALL: [Self; 3] = [Self::Active, Self::NearExpiry, Self::Expired];

    const fn index(self) -> usize {
        match self {
            Self::Active => 0,
            Self::NearExpiry => 1,
            Self::Expired => 2,
        }
    }
}

/// Closed durable artifact publication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactState {
    /// Upload metadata exists but no immutable manifest has been reserved.
    PendingUpload,
    /// The immutable manifest descriptor is reserved but not yet published.
    PublicationReserved,
    /// The manifest and artifact publication are finalized.
    Finalized,
}

impl ArtifactState {
    pub const ALL: [Self; 3] = [
        Self::PendingUpload,
        Self::PublicationReserved,
        Self::Finalized,
    ];

    const fn index(self) -> usize {
        match self {
            Self::PendingUpload => 0,
            Self::PublicationReserved => 1,
            Self::Finalized => 2,
        }
    }
}

/// Closed immutable artifact-reservation kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactReservationKind {
    Block,
    Manifest,
}

impl ArtifactReservationKind {
    pub const ALL: [Self; 2] = [Self::Block, Self::Manifest];

    const fn index(self) -> usize {
        match self {
            Self::Block => 0,
            Self::Manifest => 1,
        }
    }
}

/// Closed durable status of a built-in secret-version cleanup operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinSecretCleanupStatus {
    Pending,
    InProgress,
    DeadLetter,
}

impl BuiltinSecretCleanupStatus {
    pub const ALL: [Self; 3] = [Self::Pending, Self::InProgress, Self::DeadLetter];

    const fn index(self) -> usize {
        match self {
            Self::Pending => 0,
            Self::InProgress => 1,
            Self::DeadLetter => 2,
        }
    }
}

/// Counts for every closed workflow-run status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkflowRunCounts([u64; 4]);

impl WorkflowRunCounts {
    pub const ALL: [WorkflowRunStatus; 4] = [
        WorkflowRunStatus::Queued,
        WorkflowRunStatus::InProgress,
        WorkflowRunStatus::Completed,
        WorkflowRunStatus::Cancelled,
    ];

    pub fn set(&mut self, status: WorkflowRunStatus, count: u64) {
        self.0[workflow_run_status_index(status)] = count;
    }

    #[must_use]
    pub const fn get(self, status: WorkflowRunStatus) -> u64 {
        self.0[workflow_run_status_index(status)]
    }
}

/// Closed durable state of a current `WorkflowPlan`-v2 orchestration marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalWorkflowRunState {
    Pending,
    Active,
    Completed,
    Cancelled,
    Failed,
}

impl LogicalWorkflowRunState {
    pub const ALL: [Self; 5] = [
        Self::Pending,
        Self::Active,
        Self::Completed,
        Self::Cancelled,
        Self::Failed,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Pending => 0,
            Self::Active => 1,
            Self::Completed => 2,
            Self::Cancelled => 3,
            Self::Failed => 4,
        }
    }
}

/// Counts for every closed `WorkflowPlan`-v2 orchestration-marker state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogicalWorkflowRunCounts([u64; 5]);

impl LogicalWorkflowRunCounts {
    pub fn set(&mut self, state: LogicalWorkflowRunState, count: u64) {
        self.0[state.index()] = count;
    }

    #[must_use]
    pub const fn get(self, state: LogicalWorkflowRunState) -> u64 {
        self.0[state.index()]
    }
}

/// Closed durable state of one current logical workflow job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalJobState {
    Pending,
    Activating,
    Activated,
    Completed,
    Skipped,
    Cancelled,
    Failed,
}

impl LogicalJobState {
    pub const ALL: [Self; 7] = [
        Self::Pending,
        Self::Activating,
        Self::Activated,
        Self::Completed,
        Self::Skipped,
        Self::Cancelled,
        Self::Failed,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Pending => 0,
            Self::Activating => 1,
            Self::Activated => 2,
            Self::Completed => 3,
            Self::Skipped => 4,
            Self::Cancelled => 5,
            Self::Failed => 6,
        }
    }
}

/// Counts for every closed current logical-job state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogicalJobCounts([u64; 7]);

impl LogicalJobCounts {
    pub fn set(&mut self, state: LogicalJobState, count: u64) {
        self.0[state.index()] = count;
    }

    #[must_use]
    pub const fn get(self, state: LogicalJobState) -> u64 {
        self.0[state.index()]
    }
}

/// Closed activation backlog/claim band at one trusted observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalActivationState {
    Pending,
    Activating,
    Expired,
}

impl LogicalActivationState {
    pub const ALL: [Self; 3] = [Self::Pending, Self::Activating, Self::Expired];

    const fn index(self) -> usize {
        match self {
            Self::Pending => 0,
            Self::Activating => 1,
            Self::Expired => 2,
        }
    }
}

/// Counts and oldest timestamps for activation backlog/claim bands.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogicalActivationCounts {
    counts: [u64; 3],
    oldest_at: [Option<UnixMillis>; 3],
}

impl LogicalActivationCounts {
    /// Sets one closed activation aggregate.
    ///
    /// # Errors
    ///
    /// Rejects a count/timestamp presence mismatch.
    pub fn set(
        &mut self,
        state: LogicalActivationState,
        count: u64,
        oldest_at: Option<UnixMillis>,
    ) -> Result<(), ControlPlaneStateValueError> {
        validate_oldest_timestamp(count, oldest_at)?;
        self.counts[state.index()] = count;
        self.oldest_at[state.index()] = oldest_at;
        Ok(())
    }

    #[must_use]
    pub const fn get(self, state: LogicalActivationState) -> u64 {
        self.counts[state.index()]
    }

    #[must_use]
    pub const fn oldest_at(self, state: LogicalActivationState) -> Option<UnixMillis> {
        self.oldest_at[state.index()]
    }
}

/// Counts for every closed job-attempt lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobAttemptCounts([u64; 12]);

impl JobAttemptCounts {
    pub const ALL: [JobLifecycle; 12] = [
        JobLifecycle::Queued,
        JobLifecycle::Leased,
        JobLifecycle::Preparing,
        JobLifecycle::Running,
        JobLifecycle::Cancelling,
        JobLifecycle::Finalizing,
        JobLifecycle::Succeeded,
        JobLifecycle::Failed,
        JobLifecycle::Cancelled,
        JobLifecycle::TimedOut,
        JobLifecycle::Skipped,
        JobLifecycle::Lost,
    ];

    pub fn set(&mut self, lifecycle: JobLifecycle, count: u64) {
        self.0[job_lifecycle_index(lifecycle)] = count;
    }

    #[must_use]
    pub const fn get(self, lifecycle: JobLifecycle) -> u64 {
        self.0[job_lifecycle_index(lifecycle)]
    }
}

/// Counts for every closed observed/desired runner-state pair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerCounts([[u64; 3]; 2]);

impl RunnerCounts {
    pub fn set(&mut self, observed: RunnerObservedState, desired: RunnerDesiredState, count: u64) {
        self.0[observed.index()][desired.index()] = count;
    }

    #[must_use]
    pub const fn get(self, observed: RunnerObservedState, desired: RunnerDesiredState) -> u64 {
        self.0[observed.index()][desired.index()]
    }
}

/// Counts for every closed runner-session state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerSessionCounts([u64; 2]);

impl RunnerSessionCounts {
    pub fn set(&mut self, state: RunnerSessionState, count: u64) {
        self.0[state.index()] = count;
    }

    #[must_use]
    pub const fn get(self, state: RunnerSessionState) -> u64 {
        self.0[state.index()]
    }
}

/// Counts for every closed active-lease expiry band.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LeaseCounts([u64; 3]);

impl LeaseCounts {
    pub fn set(&mut self, state: LeaseState, count: u64) {
        self.0[state.index()] = count;
    }

    #[must_use]
    pub const fn get(self, state: LeaseState) -> u64 {
        self.0[state.index()]
    }
}

/// Counts for every closed artifact publication state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArtifactCounts([u64; 3]);

impl ArtifactCounts {
    pub fn set(&mut self, state: ArtifactState, count: u64) {
        self.0[state.index()] = count;
    }

    #[must_use]
    pub const fn get(self, state: ArtifactState) -> u64 {
        self.0[state.index()]
    }
}

/// Counts and oldest timestamps for every outstanding reservation kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArtifactReservations {
    counts: [u64; 2],
    oldest_at: [Option<UnixMillis>; 2],
}

impl ArtifactReservations {
    /// Sets one closed reservation aggregate.
    ///
    /// # Errors
    ///
    /// Rejects an oldest timestamp without a reservation, or reservations
    /// without an oldest timestamp.
    pub fn set(
        &mut self,
        kind: ArtifactReservationKind,
        count: u64,
        oldest_at: Option<UnixMillis>,
    ) -> Result<(), ControlPlaneStateValueError> {
        validate_oldest_timestamp(count, oldest_at)?;
        self.counts[kind.index()] = count;
        self.oldest_at[kind.index()] = oldest_at;
        Ok(())
    }

    #[must_use]
    pub const fn get(self, kind: ArtifactReservationKind) -> u64 {
        self.counts[kind.index()]
    }

    #[must_use]
    pub const fn oldest_at(self, kind: ArtifactReservationKind) -> Option<UnixMillis> {
        self.oldest_at[kind.index()]
    }
}

/// Counts and oldest creation timestamps for built-in secret-version cleanup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuiltinSecretCleanupCounts {
    counts: [u64; 3],
    oldest_created_at: [Option<UnixMillis>; 3],
}

impl BuiltinSecretCleanupCounts {
    /// Sets one closed cleanup-status aggregate.
    ///
    /// # Errors
    ///
    /// Rejects an oldest timestamp without an operation, or operations without
    /// an oldest timestamp.
    pub fn set(
        &mut self,
        status: BuiltinSecretCleanupStatus,
        count: u64,
        oldest_created_at: Option<UnixMillis>,
    ) -> Result<(), ControlPlaneStateValueError> {
        validate_oldest_timestamp(count, oldest_created_at)?;
        self.counts[status.index()] = count;
        self.oldest_created_at[status.index()] = oldest_created_at;
        Ok(())
    }

    #[must_use]
    pub const fn get(self, status: BuiltinSecretCleanupStatus) -> u64 {
        self.counts[status.index()]
    }

    #[must_use]
    pub const fn oldest_created_at(self, status: BuiltinSecretCleanupStatus) -> Option<UnixMillis> {
        self.oldest_created_at[status.index()]
    }
}

/// One exact, already-runnable candidate retained only for capacity analysis.
#[derive(Clone, Eq, PartialEq)]
pub struct ControlPlaneCapacityCandidate {
    tenant_id: String,
    attempt_id: AttemptId,
    job_id: JobId,
    queued_at: UnixMillis,
    requirements: RunnerRequirements,
}

impl fmt::Debug for ControlPlaneCapacityCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneCapacityCandidate")
            .field("queued_at", &self.queued_at)
            .finish_non_exhaustive()
    }
}

impl ControlPlaneCapacityCandidate {
    /// Retains one exact eligible candidate for off-scrape capacity analysis.
    #[must_use]
    pub fn new(
        tenant_id: String,
        attempt_id: AttemptId,
        job_id: JobId,
        queued_at: UnixMillis,
        requirements: RunnerRequirements,
    ) -> Self {
        Self {
            tenant_id,
            attempt_id,
            job_id,
            queued_at,
            requirements,
        }
    }

    /// Returns the internal tenant scope used only to select authorized runners.
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Returns the durable attempt identity used by the pure scheduler input.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the durable job identity used by the pure scheduler input.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns when the candidate became queued.
    #[must_use]
    pub const fn queued_at(&self) -> UnixMillis {
        self.queued_at
    }

    /// Returns the candidate's validated core and administrative requirements.
    #[must_use]
    pub const fn requirements(&self) -> &RunnerRequirements {
        &self.requirements
    }
}

/// One exact effective-runner input retained only for capacity analysis.
#[derive(Clone, Eq, PartialEq)]
pub struct ControlPlaneCapacityRunner {
    tenant_id: String,
    session: RunnerSessionFence,
    group_name: Option<String>,
    labels: BTreeSet<RoutingLabel>,
    registered_capabilities: RunnerCapabilities,
    observed_capabilities: RunnerCapabilities,
    slots: RunnerSlotCount,
    occupied_slots: BTreeSet<StableRunnerSlot>,
}

impl fmt::Debug for ControlPlaneCapacityRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneCapacityRunner")
            .field("slots", &self.slots)
            .field("occupied_slots", &self.occupied_slots.len())
            .finish_non_exhaustive()
    }
}

impl ControlPlaneCapacityRunner {
    /// Builds one bounded current runner input.
    ///
    /// # Errors
    ///
    /// Rejects capability identity mismatch, excessive capacity, or occupied
    /// slots outside the registered range.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        tenant_id: String,
        session: RunnerSessionFence,
        group_name: Option<String>,
        labels: impl IntoIterator<Item = RoutingLabel>,
        registered_capabilities: RunnerCapabilities,
        observed_capabilities: RunnerCapabilities,
        slots: RunnerSlotCount,
        occupied_slots: impl IntoIterator<Item = StableRunnerSlot>,
    ) -> Result<Self, ControlPlaneStateValueError> {
        registered_capabilities
            .validate()
            .map_err(|_| ControlPlaneStateValueError::InvalidCapacityRunner)?;
        observed_capabilities
            .validate()
            .map_err(|_| ControlPlaneStateValueError::InvalidCapacityRunner)?;
        if registered_capabilities.runner_id() != session.runner_id()
            || observed_capabilities.runner_id() != session.runner_id()
            || slots.get() > MAX_CONTROL_PLANE_CAPACITY_SLOTS_PER_RUNNER
        {
            return Err(ControlPlaneStateValueError::InvalidCapacityRunner);
        }
        let labels = labels.into_iter().collect::<BTreeSet<_>>();
        let occupied_slots = occupied_slots.into_iter().collect::<BTreeSet<_>>();
        if occupied_slots.iter().any(|slot| !slots.contains(*slot)) {
            return Err(ControlPlaneStateValueError::InvalidCapacityRunner);
        }
        Ok(Self {
            tenant_id,
            session,
            group_name,
            labels,
            registered_capabilities,
            observed_capabilities,
            slots,
            occupied_slots,
        })
    }

    /// Returns the internal tenant scope used only to select candidates.
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Returns the current durable session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the server-authorized normalized runner group, when present.
    #[must_use]
    pub fn group_name(&self) -> Option<&str> {
        self.group_name.as_deref()
    }

    /// Returns the server-authorized routing labels.
    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RoutingLabel> {
        &self.labels
    }

    /// Returns the registered execution capabilities.
    #[must_use]
    pub const fn registered_capabilities(&self) -> &RunnerCapabilities {
        &self.registered_capabilities
    }

    /// Returns the capabilities observed from the current live session.
    #[must_use]
    pub const fn observed_capabilities(&self) -> &RunnerCapabilities {
        &self.observed_capabilities
    }

    /// Returns the registered stable-slot count.
    #[must_use]
    pub const fn slots(&self) -> RunnerSlotCount {
        self.slots
    }

    /// Returns slots occupied by a durable lease at snapshot time.
    #[must_use]
    pub const fn occupied_slots(&self) -> &BTreeSet<StableRunnerSlot> {
        &self.occupied_slots
    }
}

/// Bounded exact inputs for pure scheduler-capacity classification.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ControlPlaneCapacitySnapshot {
    candidates: Vec<ControlPlaneCapacityCandidate>,
    runners: Vec<ControlPlaneCapacityRunner>,
}

impl fmt::Debug for ControlPlaneCapacitySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneCapacitySnapshot")
            .field("candidates", &self.candidates.len())
            .field("runners", &self.runners.len())
            .finish()
    }
}

impl ControlPlaneCapacitySnapshot {
    /// Builds a complete bounded compatibility input.
    ///
    /// # Errors
    ///
    /// Rejects partial candidate coverage or excessive runner state.
    pub fn try_new(
        eligible_depth: u64,
        candidates: Vec<ControlPlaneCapacityCandidate>,
        runners: Vec<ControlPlaneCapacityRunner>,
    ) -> Result<Self, ControlPlaneStateValueError> {
        if candidates.len() > MAX_CONTROL_PLANE_CAPACITY_CANDIDATES
            || runners.len() > MAX_CONTROL_PLANE_CAPACITY_RUNNERS
            || u64::try_from(candidates.len()).ok() != Some(eligible_depth)
        {
            return Err(ControlPlaneStateValueError::CapacitySnapshotTooLarge);
        }
        Ok(Self {
            candidates,
            runners,
        })
    }

    /// Returns the complete eligible candidate set.
    #[must_use]
    pub fn candidates(&self) -> &[ControlPlaneCapacityCandidate] {
        &self.candidates
    }

    /// Returns every current effective-runner input.
    #[must_use]
    pub fn runners(&self) -> &[ControlPlaneCapacityRunner] {
        &self.runners
    }
}

/// One consistent aggregate snapshot with bounded capacity-evaluation inputs.
///
/// Capacity inputs carry identities only for in-memory scheduler evaluation;
/// their diagnostics are redacted and exposition remains identifier-free.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlPlaneStateSnapshot {
    workflow_runs: WorkflowRunCounts,
    logical_workflow_runs: LogicalWorkflowRunCounts,
    logical_jobs: LogicalJobCounts,
    logical_activations: LogicalActivationCounts,
    activation_publications: u64,
    materialized_instances: u64,
    job_attempts: JobAttemptCounts,
    runners: RunnerCounts,
    runner_sessions: RunnerSessionCounts,
    queue_depth: u64,
    queue_oldest_at: Option<UnixMillis>,
    eligible_queue_depth: u64,
    eligible_queue_oldest_at: Option<UnixMillis>,
    capacity: ControlPlaneCapacitySnapshot,
    leases: LeaseCounts,
    pending_commands: u64,
    pending_commands_oldest_at: Option<UnixMillis>,
    pending_cancellation_intents: u64,
    pending_cancellation_intents_oldest_at: Option<UnixMillis>,
    builtin_secret_cleanup: BuiltinSecretCleanupCounts,
    artifacts: ArtifactCounts,
    artifact_reservations: ArtifactReservations,
}

impl ControlPlaneStateSnapshot {
    /// Builds a snapshot while enforcing count/timestamp consistency.
    ///
    /// # Errors
    ///
    /// Rejects an oldest timestamp without work, or non-empty work without an
    /// oldest timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_runs: WorkflowRunCounts,
        job_attempts: JobAttemptCounts,
        runners: RunnerCounts,
        runner_sessions: RunnerSessionCounts,
        queue_depth: u64,
        queue_oldest_at: Option<UnixMillis>,
        leases: LeaseCounts,
        pending_commands: u64,
        pending_commands_oldest_at: Option<UnixMillis>,
        pending_cancellation_intents: u64,
        pending_cancellation_intents_oldest_at: Option<UnixMillis>,
        artifacts: ArtifactCounts,
        artifact_reservations: ArtifactReservations,
    ) -> Result<Self, ControlPlaneStateValueError> {
        validate_oldest_timestamp(queue_depth, queue_oldest_at)?;
        validate_oldest_timestamp(pending_commands, pending_commands_oldest_at)?;
        validate_oldest_timestamp(
            pending_cancellation_intents,
            pending_cancellation_intents_oldest_at,
        )?;
        Ok(Self {
            workflow_runs,
            logical_workflow_runs: LogicalWorkflowRunCounts::default(),
            logical_jobs: LogicalJobCounts::default(),
            logical_activations: LogicalActivationCounts::default(),
            activation_publications: 0,
            materialized_instances: 0,
            job_attempts,
            runners,
            runner_sessions,
            queue_depth,
            queue_oldest_at,
            eligible_queue_depth: 0,
            eligible_queue_oldest_at: None,
            capacity: ControlPlaneCapacitySnapshot::default(),
            leases,
            pending_commands,
            pending_commands_oldest_at,
            pending_cancellation_intents,
            pending_cancellation_intents_oldest_at,
            builtin_secret_cleanup: BuiltinSecretCleanupCounts::default(),
            artifacts,
            artifact_reservations,
        })
    }

    /// Adds current logical-orchestration and exact capacity state.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent eligible depth/timestamp state or a partial
    /// capacity input.
    #[allow(clippy::too_many_arguments)]
    pub fn with_logical_orchestration(
        mut self,
        logical_workflow_runs: LogicalWorkflowRunCounts,
        logical_jobs: LogicalJobCounts,
        logical_activations: LogicalActivationCounts,
        activation_publications: u64,
        materialized_instances: u64,
        eligible_queue_depth: u64,
        eligible_queue_oldest_at: Option<UnixMillis>,
        capacity_candidates: Vec<ControlPlaneCapacityCandidate>,
        capacity_runners: Vec<ControlPlaneCapacityRunner>,
    ) -> Result<Self, ControlPlaneStateValueError> {
        validate_oldest_timestamp(eligible_queue_depth, eligible_queue_oldest_at)?;
        let capacity = ControlPlaneCapacitySnapshot::try_new(
            eligible_queue_depth,
            capacity_candidates,
            capacity_runners,
        )?;
        self.logical_workflow_runs = logical_workflow_runs;
        self.logical_jobs = logical_jobs;
        self.logical_activations = logical_activations;
        self.activation_publications = activation_publications;
        self.materialized_instances = materialized_instances;
        self.eligible_queue_depth = eligible_queue_depth;
        self.eligible_queue_oldest_at = eligible_queue_oldest_at;
        self.capacity = capacity;
        Ok(self)
    }

    /// Adds the built-in secret-version cleanup backlog observed in the same
    /// durable snapshot.
    #[must_use]
    pub const fn with_builtin_secret_cleanup(
        mut self,
        builtin_secret_cleanup: BuiltinSecretCleanupCounts,
    ) -> Self {
        self.builtin_secret_cleanup = builtin_secret_cleanup;
        self
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self {
            workflow_runs: WorkflowRunCounts([0; 4]),
            logical_workflow_runs: LogicalWorkflowRunCounts([0; 5]),
            logical_jobs: LogicalJobCounts([0; 7]),
            logical_activations: LogicalActivationCounts {
                counts: [0; 3],
                oldest_at: [None; 3],
            },
            activation_publications: 0,
            materialized_instances: 0,
            job_attempts: JobAttemptCounts([0; 12]),
            runners: RunnerCounts([[0; 3]; 2]),
            runner_sessions: RunnerSessionCounts([0; 2]),
            queue_depth: 0,
            queue_oldest_at: None,
            eligible_queue_depth: 0,
            eligible_queue_oldest_at: None,
            capacity: ControlPlaneCapacitySnapshot {
                candidates: Vec::new(),
                runners: Vec::new(),
            },
            leases: LeaseCounts([0; 3]),
            pending_commands: 0,
            pending_commands_oldest_at: None,
            pending_cancellation_intents: 0,
            pending_cancellation_intents_oldest_at: None,
            builtin_secret_cleanup: BuiltinSecretCleanupCounts {
                counts: [0; 3],
                oldest_created_at: [None; 3],
            },
            artifacts: ArtifactCounts([0; 3]),
            artifact_reservations: ArtifactReservations {
                counts: [0; 2],
                oldest_at: [None; 2],
            },
        }
    }

    #[must_use]
    pub const fn workflow_runs(&self) -> WorkflowRunCounts {
        self.workflow_runs
    }

    #[must_use]
    pub const fn logical_workflow_runs(&self) -> LogicalWorkflowRunCounts {
        self.logical_workflow_runs
    }

    #[must_use]
    pub const fn logical_jobs(&self) -> LogicalJobCounts {
        self.logical_jobs
    }

    #[must_use]
    pub const fn logical_activations(&self) -> LogicalActivationCounts {
        self.logical_activations
    }

    #[must_use]
    pub const fn activation_publications(&self) -> u64 {
        self.activation_publications
    }

    #[must_use]
    pub const fn materialized_instances(&self) -> u64 {
        self.materialized_instances
    }

    #[must_use]
    pub const fn job_attempts(&self) -> JobAttemptCounts {
        self.job_attempts
    }

    #[must_use]
    pub const fn runners(&self) -> RunnerCounts {
        self.runners
    }

    #[must_use]
    pub const fn runner_sessions(&self) -> RunnerSessionCounts {
        self.runner_sessions
    }

    #[must_use]
    pub const fn queue_depth(&self) -> u64 {
        self.queue_depth
    }

    #[must_use]
    pub const fn queue_oldest_at(&self) -> Option<UnixMillis> {
        self.queue_oldest_at
    }

    #[must_use]
    pub const fn eligible_queue_depth(&self) -> u64 {
        self.eligible_queue_depth
    }

    #[must_use]
    pub const fn eligible_queue_oldest_at(&self) -> Option<UnixMillis> {
        self.eligible_queue_oldest_at
    }

    #[must_use]
    pub const fn capacity(&self) -> &ControlPlaneCapacitySnapshot {
        &self.capacity
    }

    #[must_use]
    pub const fn leases(&self) -> LeaseCounts {
        self.leases
    }

    #[must_use]
    pub const fn pending_commands(&self) -> u64 {
        self.pending_commands
    }

    #[must_use]
    pub const fn pending_commands_oldest_at(&self) -> Option<UnixMillis> {
        self.pending_commands_oldest_at
    }

    #[must_use]
    pub const fn pending_cancellation_intents(&self) -> u64 {
        self.pending_cancellation_intents
    }

    #[must_use]
    pub const fn pending_cancellation_intents_oldest_at(&self) -> Option<UnixMillis> {
        self.pending_cancellation_intents_oldest_at
    }

    #[must_use]
    pub const fn builtin_secret_cleanup(&self) -> BuiltinSecretCleanupCounts {
        self.builtin_secret_cleanup
    }

    #[must_use]
    pub const fn artifacts(&self) -> ArtifactCounts {
        self.artifacts
    }

    #[must_use]
    pub const fn artifact_reservations(&self) -> ArtifactReservations {
        self.artifact_reservations
    }
}

impl Default for ControlPlaneStateSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

/// Cached connection-pool occupancy captured beside one durable snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatabasePoolSnapshot {
    maximum: u32,
    open: u32,
    idle: u32,
    in_use: u32,
}

impl DatabasePoolSnapshot {
    /// Validates pool occupancy and derives the in-use count exactly.
    ///
    /// # Errors
    ///
    /// Rejects idle connections above open connections or open connections
    /// above the configured maximum.
    pub fn new(maximum: u32, open: u32, idle: u32) -> Result<Self, ControlPlaneStateValueError> {
        if idle > open || open > maximum {
            return Err(ControlPlaneStateValueError::InvalidPoolOccupancy);
        }
        Ok(Self {
            maximum,
            open,
            idle,
            in_use: open - idle,
        })
    }

    #[must_use]
    pub const fn maximum(self) -> u32 {
        self.maximum
    }

    #[must_use]
    pub const fn open(self) -> u32 {
        self.open
    }

    #[must_use]
    pub const fn idle(self) -> u32 {
        self.idle
    }

    #[must_use]
    pub const fn in_use(self) -> u32 {
        self.in_use
    }
}

/// Invalid input or durable aggregate shape.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ControlPlaneStateValueError {
    #[error("lease near-expiry window must be a positive whole-millisecond duration")]
    InvalidNearExpiryWindow,
    #[error("lease near-expiry cutoff is outside the durable timestamp range")]
    NearExpiryCutoffOutOfRange,
    #[error("oldest timestamp presence does not match aggregate work count")]
    InconsistentOldestTimestamp,
    #[error("database pool occupancy is inconsistent")]
    InvalidPoolOccupancy,
    #[error("capacity runner state is invalid or outside the bounded product contract")]
    InvalidCapacityRunner,
    #[error("exact capacity snapshot exceeds its bounded in-memory contract")]
    CapacitySnapshotTooLarge,
}

/// Provider-neutral source for one cached durable metrics snapshot.
#[async_trait]
pub trait ControlPlaneStateRepository: std::fmt::Debug + Send + Sync {
    /// Reads one consistent durable aggregate snapshot.
    ///
    /// # Errors
    ///
    /// Returns a sanitized backend failure or corrupt-data error.
    async fn control_plane_state_snapshot(
        &self,
        request: ControlPlaneStateSnapshotRequest,
    ) -> Result<ControlPlaneStateSnapshot, StoreError>;

    /// Reads cached connection-pool occupancy without acquiring a connection.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-data error if the provider reports inconsistent
    /// occupancy.
    fn database_pool_snapshot(&self) -> Result<DatabasePoolSnapshot, StoreError>;
}

const fn workflow_run_status_index(status: WorkflowRunStatus) -> usize {
    match status {
        WorkflowRunStatus::Queued => 0,
        WorkflowRunStatus::InProgress => 1,
        WorkflowRunStatus::Completed => 2,
        WorkflowRunStatus::Cancelled => 3,
    }
}

const fn job_lifecycle_index(lifecycle: JobLifecycle) -> usize {
    match lifecycle {
        JobLifecycle::Queued => 0,
        JobLifecycle::Leased => 1,
        JobLifecycle::Preparing => 2,
        JobLifecycle::Running => 3,
        JobLifecycle::Cancelling => 4,
        JobLifecycle::Finalizing => 5,
        JobLifecycle::Succeeded => 6,
        JobLifecycle::Failed => 7,
        JobLifecycle::Cancelled => 8,
        JobLifecycle::TimedOut => 9,
        JobLifecycle::Skipped => 10,
        JobLifecycle::Lost => 11,
    }
}

fn validate_oldest_timestamp(
    count: u64,
    oldest_at: Option<UnixMillis>,
) -> Result<(), ControlPlaneStateValueError> {
    if (count == 0) != oldest_at.is_none() {
        return Err(ControlPlaneStateValueError::InconsistentOldestTimestamp);
    }
    Ok(())
}
