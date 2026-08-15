//! Durable control-plane snapshots used for bounded, identifier-free metrics.

use std::{collections::BTreeSet, fmt, time::Duration};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, JobId, JobLifecycle, RunnerCapabilities, RunnerRequirements, UnixMillis,
};
use thiserror::Error;

use automata_ci_store::{
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

    /// Returns the trusted time at which the snapshot is observed.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the inclusive upper bound for near-expiry leases.
    #[must_use]
    pub const fn near_expiry_at(self) -> UnixMillis {
        self.near_expiry_at
    }
}

/// Closed observed connectivity state persisted for a runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerObservedState {
    /// The runner has no live observed connection.
    Offline,
    /// The runner has a live observed connection.
    Online,
}

impl RunnerObservedState {
    /// Every observed runner state in stable metric order.
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
    /// The runner may accept work.
    Active,
    /// The runner is draining existing work without accepting more.
    Draining,
    /// The runner is administratively disabled.
    Disabled,
}

impl RunnerDesiredState {
    /// Every desired runner state in stable metric order.
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
    /// The session is live.
    Live,
    /// The session is durably disconnected.
    Disconnected,
}

impl RunnerSessionState {
    /// Every durable runner-session state in stable metric order.
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
    /// The lease remains outside the near-expiry window.
    Active,
    /// The lease remains valid but falls within the near-expiry window.
    NearExpiry,
    /// The lease has expired at the observation time.
    Expired,
}

impl LeaseState {
    /// Every lease-expiration band in stable metric order.
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
    /// Every artifact publication state in stable metric order.
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
    /// An immutable artifact block reservation.
    Block,
    /// An immutable artifact manifest reservation.
    Manifest,
}

impl ArtifactReservationKind {
    /// Every artifact reservation kind in stable metric order.
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
    /// Cleanup is waiting to start.
    Pending,
    /// Cleanup is currently being processed.
    InProgress,
    /// Cleanup exhausted its retry policy.
    DeadLetter,
}

impl BuiltinSecretCleanupStatus {
    /// Every built-in cleanup status in stable metric order.
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
    /// Every workflow-run status in stable metric order.
    pub const ALL: [WorkflowRunStatus; 4] = [
        WorkflowRunStatus::Queued,
        WorkflowRunStatus::InProgress,
        WorkflowRunStatus::Completed,
        WorkflowRunStatus::Cancelled,
    ];

    /// Sets the count for one workflow-run status.
    pub fn set(&mut self, status: WorkflowRunStatus, count: u64) {
        self.0[workflow_run_status_index(status)] = count;
    }

    /// Returns the count for one workflow-run status.
    #[must_use]
    pub const fn get(self, status: WorkflowRunStatus) -> u64 {
        self.0[workflow_run_status_index(status)]
    }
}

/// Closed durable state of a current `WorkflowPlan`-v1 orchestration marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalWorkflowRunState {
    /// The orchestration marker is waiting for activation.
    Pending,
    /// The logical workflow run is active.
    Active,
    /// The logical workflow run completed successfully.
    Completed,
    /// The logical workflow run was cancelled.
    Cancelled,
    /// The logical workflow run failed.
    Failed,
}

impl LogicalWorkflowRunState {
    /// Every logical workflow-run state in stable metric order.
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

/// Counts for every closed `WorkflowPlan`-v1 orchestration-marker state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogicalWorkflowRunCounts([u64; 5]);

impl LogicalWorkflowRunCounts {
    /// Sets the count for one logical workflow-run state.
    pub fn set(&mut self, state: LogicalWorkflowRunState, count: u64) {
        self.0[state.index()] = count;
    }

    /// Returns the count for one logical workflow-run state.
    #[must_use]
    pub const fn get(self, state: LogicalWorkflowRunState) -> u64 {
        self.0[state.index()]
    }
}

/// Closed durable state of one current logical workflow job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalJobState {
    /// The logical job is waiting for activation.
    Pending,
    /// Activation of the logical job is in progress.
    Activating,
    /// The logical job has produced its current physical job.
    Activated,
    /// The logical job completed successfully.
    Completed,
    /// The logical job was skipped.
    Skipped,
    /// The logical job was cancelled.
    Cancelled,
    /// The logical job failed.
    Failed,
}

impl LogicalJobState {
    /// Every logical-job state in stable metric order.
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
    /// Sets the count for one logical-job state.
    pub fn set(&mut self, state: LogicalJobState, count: u64) {
        self.0[state.index()] = count;
    }

    /// Returns the count for one logical-job state.
    #[must_use]
    pub const fn get(self, state: LogicalJobState) -> u64 {
        self.0[state.index()]
    }
}

/// Closed activation backlog/claim band at one trusted observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalActivationState {
    /// Activation work is waiting to be claimed.
    Pending,
    /// Activation work has a live claim.
    Activating,
    /// Activation work has an expired claim.
    Expired,
}

impl LogicalActivationState {
    /// Every logical-activation state in stable metric order.
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

    /// Returns the count for one logical-activation state.
    #[must_use]
    pub const fn get(self, state: LogicalActivationState) -> u64 {
        self.counts[state.index()]
    }

    /// Returns the oldest timestamp for one logical-activation state.
    #[must_use]
    pub const fn oldest_at(self, state: LogicalActivationState) -> Option<UnixMillis> {
        self.oldest_at[state.index()]
    }
}

/// Counts for every closed job-attempt lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobAttemptCounts([u64; 12]);

impl JobAttemptCounts {
    /// Every job-attempt lifecycle in stable metric order.
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

    /// Sets the count for one job-attempt lifecycle.
    pub fn set(&mut self, lifecycle: JobLifecycle, count: u64) {
        self.0[job_lifecycle_index(lifecycle)] = count;
    }

    /// Returns the count for one job-attempt lifecycle.
    #[must_use]
    pub const fn get(self, lifecycle: JobLifecycle) -> u64 {
        self.0[job_lifecycle_index(lifecycle)]
    }
}

/// Counts for every closed observed/desired runner-state pair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerCounts([[u64; 3]; 2]);

impl RunnerCounts {
    /// Sets the count for one observed/desired runner-state pair.
    pub fn set(&mut self, observed: RunnerObservedState, desired: RunnerDesiredState, count: u64) {
        self.0[observed.index()][desired.index()] = count;
    }

    /// Returns the count for one observed/desired runner-state pair.
    #[must_use]
    pub const fn get(self, observed: RunnerObservedState, desired: RunnerDesiredState) -> u64 {
        self.0[observed.index()][desired.index()]
    }
}

/// Counts for every closed runner-session state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerSessionCounts([u64; 2]);

impl RunnerSessionCounts {
    /// Sets the count for one runner-session state.
    pub fn set(&mut self, state: RunnerSessionState, count: u64) {
        self.0[state.index()] = count;
    }

    /// Returns the count for one runner-session state.
    #[must_use]
    pub const fn get(self, state: RunnerSessionState) -> u64 {
        self.0[state.index()]
    }
}

/// Counts for every closed active-lease expiry band.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LeaseCounts([u64; 3]);

impl LeaseCounts {
    /// Sets the count for one lease-expiration band.
    pub fn set(&mut self, state: LeaseState, count: u64) {
        self.0[state.index()] = count;
    }

    /// Returns the count for one lease-expiration band.
    #[must_use]
    pub const fn get(self, state: LeaseState) -> u64 {
        self.0[state.index()]
    }
}

/// Counts for every closed artifact publication state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArtifactCounts([u64; 3]);

impl ArtifactCounts {
    /// Sets the count for one artifact publication state.
    pub fn set(&mut self, state: ArtifactState, count: u64) {
        self.0[state.index()] = count;
    }

    /// Returns the count for one artifact publication state.
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

    /// Returns the outstanding reservation count for one kind.
    #[must_use]
    pub const fn get(self, kind: ArtifactReservationKind) -> u64 {
        self.counts[kind.index()]
    }

    /// Returns the oldest outstanding reservation time for one kind.
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

    /// Returns the operation count for one cleanup status.
    #[must_use]
    pub const fn get(self, status: BuiltinSecretCleanupStatus) -> u64 {
        self.counts[status.index()]
    }

    /// Returns the oldest creation time for one cleanup status.
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

    /// Returns an identifier-free snapshot with every aggregate empty.
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

    /// Returns workflow-run counts.
    #[must_use]
    pub const fn workflow_runs(&self) -> WorkflowRunCounts {
        self.workflow_runs
    }

    /// Returns logical workflow-run counts.
    #[must_use]
    pub const fn logical_workflow_runs(&self) -> LogicalWorkflowRunCounts {
        self.logical_workflow_runs
    }

    /// Returns current logical-job counts.
    #[must_use]
    pub const fn logical_jobs(&self) -> LogicalJobCounts {
        self.logical_jobs
    }

    /// Returns logical-activation counts and oldest timestamps.
    #[must_use]
    pub const fn logical_activations(&self) -> LogicalActivationCounts {
        self.logical_activations
    }

    /// Returns the current activation-publication count.
    #[must_use]
    pub const fn activation_publications(&self) -> u64 {
        self.activation_publications
    }

    /// Returns the current materialized-instance count.
    #[must_use]
    pub const fn materialized_instances(&self) -> u64 {
        self.materialized_instances
    }

    /// Returns job-attempt lifecycle counts.
    #[must_use]
    pub const fn job_attempts(&self) -> JobAttemptCounts {
        self.job_attempts
    }

    /// Returns runner counts by observed and desired state.
    #[must_use]
    pub const fn runners(&self) -> RunnerCounts {
        self.runners
    }

    /// Returns durable runner-session counts.
    #[must_use]
    pub const fn runner_sessions(&self) -> RunnerSessionCounts {
        self.runner_sessions
    }

    /// Returns the total queued-attempt depth.
    #[must_use]
    pub const fn queue_depth(&self) -> u64 {
        self.queue_depth
    }

    /// Returns the oldest queued-attempt timestamp, when the queue is non-empty.
    #[must_use]
    pub const fn queue_oldest_at(&self) -> Option<UnixMillis> {
        self.queue_oldest_at
    }

    /// Returns the exact scheduler-eligible queue depth.
    #[must_use]
    pub const fn eligible_queue_depth(&self) -> u64 {
        self.eligible_queue_depth
    }

    /// Returns the oldest eligible queued-attempt timestamp, when present.
    #[must_use]
    pub const fn eligible_queue_oldest_at(&self) -> Option<UnixMillis> {
        self.eligible_queue_oldest_at
    }

    /// Returns bounded inputs for scheduler-capacity classification.
    #[must_use]
    pub const fn capacity(&self) -> &ControlPlaneCapacitySnapshot {
        &self.capacity
    }

    /// Returns active-lease counts by expiry band.
    #[must_use]
    pub const fn leases(&self) -> LeaseCounts {
        self.leases
    }

    /// Returns the pending runner-command count.
    #[must_use]
    pub const fn pending_commands(&self) -> u64 {
        self.pending_commands
    }

    /// Returns the oldest pending runner-command timestamp, when present.
    #[must_use]
    pub const fn pending_commands_oldest_at(&self) -> Option<UnixMillis> {
        self.pending_commands_oldest_at
    }

    /// Returns the pending cancellation-intent count.
    #[must_use]
    pub const fn pending_cancellation_intents(&self) -> u64 {
        self.pending_cancellation_intents
    }

    /// Returns the oldest pending cancellation-intent timestamp, when present.
    #[must_use]
    pub const fn pending_cancellation_intents_oldest_at(&self) -> Option<UnixMillis> {
        self.pending_cancellation_intents_oldest_at
    }

    /// Returns built-in secret-version cleanup counts and oldest timestamps.
    #[must_use]
    pub const fn builtin_secret_cleanup(&self) -> BuiltinSecretCleanupCounts {
        self.builtin_secret_cleanup
    }

    /// Returns artifact publication counts.
    #[must_use]
    pub const fn artifacts(&self) -> ArtifactCounts {
        self.artifacts
    }

    /// Returns artifact-reservation counts and oldest timestamps.
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

    /// Returns the configured maximum pool size.
    #[must_use]
    pub const fn maximum(self) -> u32 {
        self.maximum
    }

    /// Returns the number of open pool connections.
    #[must_use]
    pub const fn open(self) -> u32 {
        self.open
    }

    /// Returns the number of idle pool connections.
    #[must_use]
    pub const fn idle(self) -> u32 {
        self.idle
    }

    /// Returns the number of checked-out pool connections.
    #[must_use]
    pub const fn in_use(self) -> u32 {
        self.in_use
    }
}

/// Invalid input or durable aggregate shape.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ControlPlaneStateValueError {
    /// The lease near-expiry window was not a positive whole-millisecond duration.
    #[error("lease near-expiry window must be a positive whole-millisecond duration")]
    InvalidNearExpiryWindow,
    /// Adding the near-expiry window overflowed the durable timestamp range.
    #[error("lease near-expiry cutoff is outside the durable timestamp range")]
    NearExpiryCutoffOutOfRange,
    /// An aggregate count and its optional oldest timestamp disagreed.
    #[error("oldest timestamp presence does not match aggregate work count")]
    InconsistentOldestTimestamp,
    /// Pool occupancy exceeded its configured or open-connection bounds.
    #[error("database pool occupancy is inconsistent")]
    InvalidPoolOccupancy,
    /// Effective runner capacity state was invalid or outside its bounded contract.
    #[error("capacity runner state is invalid or outside the bounded product contract")]
    InvalidCapacityRunner,
    /// Exact capacity inputs exceeded their bounded in-memory contract.
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
