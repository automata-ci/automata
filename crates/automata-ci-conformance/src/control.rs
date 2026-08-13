use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::catalog::hex_digest;

/// Maximum parallel shards admitted by one fixture plan.
// foundation-governance: operational-limit
pub const MAX_CONFORMANCE_SHARDS: u16 = 256;
// foundation-governance: operational-limit
const MAX_FAULTS: usize = 1_024;

/// Clock used by product conformance composition.
pub trait ConformanceClock: fmt::Debug + Send + Sync {
    fn now_millis(&self) -> i64;
}

/// Thread-safe monotonic clock advanced explicitly by the fixture driver.
#[derive(Debug)]
pub struct ManualConformanceClock(AtomicI64);

impl ManualConformanceClock {
    #[must_use]
    pub const fn new(initial_millis: i64) -> Self {
        Self(AtomicI64::new(initial_millis))
    }

    /// Advances the clock by a strictly positive duration.
    ///
    /// # Errors
    ///
    /// Rejects zero, negative, or overflowing advances.
    pub fn advance(&self, millis: i64) -> Result<i64, FixtureControlError> {
        if millis <= 0 {
            return Err(FixtureControlError::InvalidClockAdvance);
        }
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(millis)
            })
            .map(|previous| previous + millis)
            .map_err(|_| FixtureControlError::ClockOverflow)
    }
}

impl ConformanceClock for ManualConformanceClock {
    fn now_millis(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Independently injectable external failure boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultTarget {
    Source,
    Token,
    Results,
    Checks,
    Runner,
    ObjectStorage,
}

/// Exact product operation at which a conformance fault may be injected.
///
/// Operations are deliberately more precise than [`FaultTarget`]. A script can
/// therefore fail a Results mutation without being consumed by an earlier
/// Results read, or fail an object write without intercepting an object read.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultOperation {
    /// Fetch immutable repository source.
    SourceFetch,
    /// Issue a repository-scoped credential.
    TokenIssue,
    /// Handle a runner's pre-session handshake.
    RunnerHandshake,
    /// Handle a runner's fenced session operation.
    RunnerSync,
    /// Read and verify an immutable object.
    ObjectRead,
    /// Publish an immutable object.
    ObjectWrite,
    /// Mutate Results metadata before finalization.
    ResultsMutation,
    /// Claim, verify, or complete Results finalization.
    ResultsFinalization,
    /// Read published Results metadata.
    ResultsRead,
    /// Acquire the credential for a GitHub Checks publication.
    ChecksCredential,
}

impl FaultOperation {
    /// Returns the independently configurable external boundary containing the operation.
    #[must_use]
    pub const fn target(self) -> FaultTarget {
        match self {
            Self::SourceFetch => FaultTarget::Source,
            Self::TokenIssue => FaultTarget::Token,
            Self::RunnerHandshake | Self::RunnerSync => FaultTarget::Runner,
            Self::ObjectRead | Self::ObjectWrite => FaultTarget::ObjectStorage,
            Self::ResultsMutation | Self::ResultsFinalization | Self::ResultsRead => {
                FaultTarget::Results
            }
            Self::ChecksCredential => FaultTarget::Checks,
        }
    }

    const fn accepts_mode(self, mode: &FaultMode) -> bool {
        match mode {
            FaultMode::Unavailable | FaultMode::CorruptResponse => true,
            FaultMode::CredentialRejected => matches!(
                self,
                Self::SourceFetch
                    | Self::TokenIssue
                    | Self::ObjectRead
                    | Self::ObjectWrite
                    | Self::ResultsMutation
                    | Self::ResultsFinalization
                    | Self::ResultsRead
                    | Self::ChecksCredential
            ),
            FaultMode::RateLimited { .. } => {
                matches!(self, Self::SourceFetch | Self::TokenIssue)
            }
            FaultMode::IndeterminateMutation => matches!(
                self,
                Self::ObjectWrite | Self::ResultsMutation | Self::ResultsFinalization
            ),
        }
    }
}

/// Closed behavior of one injected fault.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FaultMode {
    Unavailable,
    CredentialRejected,
    RateLimited { retry_after_millis: u64 },
    IndeterminateMutation,
    CorruptResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScheduledFault {
    transition: DurableTransition,
    mode: FaultMode,
}

/// A pending fault was invoked at a checkpoint other than the one scripted.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("fault is armed for {expected:?}, not the current {actual:?} transition")]
pub struct FaultNotDue {
    expected: DurableTransition,
    actual: DurableTransition,
}

impl FaultNotDue {
    /// Returns the exact checkpoint named by the next operation-specific entry.
    #[must_use]
    pub const fn expected(self) -> DurableTransition {
        self.expected
    }

    /// Returns the checkpoint at which the operation was attempted.
    #[must_use]
    pub const fn actual(self) -> DurableTransition {
        self.actual
    }
}

/// Ordered operation- and checkpoint-specific one-shot fault script.
///
/// Ordinary product construction uses an empty plan. Entries for different
/// operations never consume one another, even when they share a broad target.
#[derive(Debug, Default)]
pub struct FaultPlan(Mutex<BTreeMap<FaultOperation, VecDeque<ScheduledFault>>>);

impl FaultPlan {
    /// Builds a bounded deterministic plan.
    ///
    /// # Errors
    ///
    /// Rejects an unbounded script or zero rate-limit duration.
    pub fn new(
        faults: impl IntoIterator<Item = (FaultOperation, DurableTransition, FaultMode)>,
    ) -> Result<Self, FixtureControlError> {
        let mut plan = BTreeMap::<FaultOperation, VecDeque<ScheduledFault>>::new();
        let mut count = 0_usize;
        for (operation, transition, mode) in faults {
            count = count
                .checked_add(1)
                .ok_or(FixtureControlError::TooManyFaults)?;
            if count > MAX_FAULTS {
                return Err(FixtureControlError::TooManyFaults);
            }
            if !operation.accepts_mode(&mode)
                || matches!(
                    mode,
                    FaultMode::RateLimited {
                        retry_after_millis: 0
                    }
                )
            {
                return Err(FixtureControlError::InvalidFault);
            }
            plan.entry(operation)
                .or_default()
                .push_back(ScheduledFault { transition, mode });
        }
        Ok(Self(Mutex::new(plan)))
    }

    /// Consumes the next fault only for the exact operation and checkpoint.
    ///
    /// An operation with no pending entry delegates normally at every
    /// checkpoint. An entry attempted at the wrong checkpoint remains armed so
    /// a fixture cannot silently consume it at an unintended durable boundary.
    ///
    /// # Errors
    ///
    /// Returns the expected and actual checkpoints when this operation has a
    /// pending entry that is not due yet.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the private plan lock.
    pub fn take_due(
        &self,
        operation: FaultOperation,
        actual: DurableTransition,
    ) -> Result<Option<FaultMode>, FaultNotDue> {
        let mut plan = self
            .0
            .lock()
            .expect("fault plan lock is not exposed to callbacks");
        let Some(faults) = plan.get_mut(&operation) else {
            return Ok(None);
        };
        let Some(next) = faults.front() else {
            return Ok(None);
        };
        if next.transition != actual {
            return Err(FaultNotDue {
                expected: next.transition,
                actual,
            });
        }
        Ok(faults.pop_front().map(|fault| fault.mode))
    }

    #[must_use]
    /// Returns the number of unconsumed scripted faults.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the private plan lock.
    pub fn remaining(&self) -> usize {
        self.0
            .lock()
            .expect("fault plan lock is not exposed to callbacks")
            .values()
            .map(VecDeque::len)
            .sum()
    }
}

/// Service boundary that can be restarted between durable transitions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductService {
    Ingress,
    DeliveryWorker,
    WorkflowService,
    Scheduler,
    ControlPlane,
    Runner,
    Results,
    ChecksPublisher,
    ObjectStorage,
}

/// Ordered durable product checkpoints exercised by a complete push fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableTransition {
    Provisioned,
    WebhookAccepted,
    DeliverySelected,
    WorkflowAdmitted,
    JobQueued,
    LeaseCommitted,
    JobResultCommitted,
    RunFinalized,
    ResultsPublished,
    CheckPublished,
    CleanupVerified,
}

impl DurableTransition {
    const ORDER: [Self; 11] = [
        Self::Provisioned,
        Self::WebhookAccepted,
        Self::DeliverySelected,
        Self::WorkflowAdmitted,
        Self::JobQueued,
        Self::LeaseCommitted,
        Self::JobResultCommitted,
        Self::RunFinalized,
        Self::ResultsPublished,
        Self::CheckPublished,
        Self::CleanupVerified,
    ];

    fn ordinal(self) -> usize {
        Self::ORDER
            .iter()
            .position(|value| *value == self)
            .expect("closed transition")
    }

    /// Returns the exact service restarts required after this checkpoint.
    ///
    /// The schedule covers every boundary in the canonical push lifecycle.
    /// `CleanupVerified` is terminal and therefore has no following restart.
    #[must_use]
    pub const fn required_restart_services(self) -> &'static [ProductService] {
        match self {
            Self::Provisioned => &[ProductService::Ingress],
            Self::WebhookAccepted => &[ProductService::DeliveryWorker],
            Self::DeliverySelected => &[ProductService::WorkflowService],
            Self::WorkflowAdmitted => &[ProductService::Scheduler],
            Self::JobQueued | Self::JobResultCommitted => &[ProductService::ControlPlane],
            Self::LeaseCommitted => &[ProductService::Runner],
            Self::RunFinalized => &[ProductService::Results],
            Self::ResultsPublished => &[ProductService::ChecksPublisher],
            Self::CheckPublished => &[ProductService::ObjectStorage],
            Self::CleanupVerified => &[],
        }
    }
}

/// One exact restart retained in fixture evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RestartRecord {
    after: DurableTransition,
    service: ProductService,
    at_millis: i64,
    stopped_generation: u64,
    started_generation: u64,
    stopped_instance: String,
    started_instance: String,
}

impl RestartRecord {
    #[must_use]
    pub const fn after(&self) -> DurableTransition {
        self.after
    }

    #[must_use]
    pub const fn service(&self) -> ProductService {
        self.service
    }

    #[must_use]
    pub const fn at_millis(&self) -> i64 {
        self.at_millis
    }

    #[must_use]
    pub const fn stopped_generation(&self) -> u64 {
        self.stopped_generation
    }

    #[must_use]
    pub const fn started_generation(&self) -> u64 {
        self.started_generation
    }

    #[must_use]
    pub fn stopped_instance(&self) -> &str {
        &self.stopped_instance
    }

    #[must_use]
    pub fn started_instance(&self) -> &str {
        &self.started_instance
    }
}

/// Observed lifecycle state returned by a product service probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    Running,
    Stopped,
}

/// Independently observed service generation and process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceObservation {
    state: ServiceState,
    generation: u64,
    instance: String,
}

impl ServiceObservation {
    /// Constructs a bounded observation returned by a process adapter.
    ///
    /// # Errors
    ///
    /// Rejects generation zero and unsafe or empty instance identities.
    pub fn new(
        state: ServiceState,
        generation: u64,
        instance: impl Into<String>,
    ) -> Result<Self, FixtureControlError> {
        let instance = instance.into();
        if generation == 0
            || instance.is_empty()
            || instance.len() > 256
            || instance.trim() != instance
            || instance.chars().any(char::is_control)
        {
            return Err(FixtureControlError::InvalidServiceObservation);
        }
        Ok(Self {
            state,
            generation,
            instance,
        })
    }
}

/// Adapter boundary used to prove a real stop/start cycle.
pub trait ServiceRestartProbe: fmt::Debug + Send + Sync {
    /// Observes the service without mutating it.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureControlError::ProbeFailed`] when the adapter cannot
    /// obtain an authoritative lifecycle observation.
    fn observe(&self, service: ProductService) -> Result<ServiceObservation, FixtureControlError>;
    /// Requests and waits for the service to stop.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureControlError::ProbeFailed`] when stop or its wait fails.
    fn stop(&self, service: ProductService) -> Result<(), FixtureControlError>;
    /// Requests and waits for the service to start in its next generation.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureControlError::ProbeFailed`] when start or its wait fails.
    fn start(&self, service: ProductService) -> Result<(), FixtureControlError>;
}

/// Stable identities assigned to one parallel shard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShardIdentity {
    id: String,
    postgres_schema: String,
    object_prefix: String,
    credential_scope: String,
    port_reservation_key: String,
}

impl ShardIdentity {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn postgres_schema(&self) -> &str {
        &self.postgres_schema
    }

    #[must_use]
    pub fn object_prefix(&self) -> &str {
        &self.object_prefix
    }

    #[must_use]
    pub fn credential_scope(&self) -> &str {
        &self.credential_scope
    }

    #[must_use]
    pub fn port_reservation_key(&self) -> &str {
        &self.port_reservation_key
    }
}

/// Complete isolated shard plan for one run identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardPlan(Vec<ShardIdentity>);

impl ShardPlan {
    /// Deterministically derives disjoint rows, object prefixes, credentials,
    /// and port-reservation keys for every shard.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or unsafe run identity.
    pub fn derive(run_identity: &str, count: u16) -> Result<Self, FixtureControlError> {
        if count == 0 || count > MAX_CONFORMANCE_SHARDS {
            return Err(FixtureControlError::InvalidShardCount);
        }
        if run_identity.is_empty()
            || run_identity.len() > 256
            || run_identity.trim() != run_identity
            || run_identity.chars().any(char::is_control)
        {
            return Err(FixtureControlError::InvalidRunIdentity);
        }
        let run_digest = domain_digest(
            b"automata.conformance.shard-run.v1\0",
            run_identity.as_bytes(),
        );
        let mut shards = Vec::with_capacity(usize::from(count));
        let mut identities = BTreeSet::new();
        for ordinal in 0..count {
            let mut material = Vec::with_capacity(run_digest.len() + 2);
            material.extend_from_slice(run_digest.as_bytes());
            material.extend_from_slice(&ordinal.to_be_bytes());
            let digest = domain_digest(b"automata.conformance.shard.v1\0", &material);
            let short = &digest[..20];
            let id = format!("shard-{ordinal:03}-{short}");
            if !identities.insert(id.clone()) {
                return Err(FixtureControlError::ShardCollision);
            }
            shards.push(ShardIdentity {
                postgres_schema: format!("cf_{short}"),
                object_prefix: format!("conformance/v1/{run_digest}/{ordinal:03}/"),
                credential_scope: format!("conformance:{run_digest}:{ordinal:03}"),
                port_reservation_key: format!("{run_digest}-{ordinal:03}"),
                id,
            });
        }
        Ok(Self(shards))
    }

    #[must_use]
    pub fn shards(&self) -> &[ShardIdentity] {
        &self.0
    }

    /// Returns one identity only from this derived plan.
    ///
    /// # Errors
    ///
    /// Rejects an ordinal outside the derived shard count.
    pub fn shard(&self, ordinal: u16) -> Result<&ShardIdentity, FixtureControlError> {
        self.0
            .get(usize::from(ordinal))
            .ok_or(FixtureControlError::UnknownShard)
    }
}

fn domain_digest(domain: &[u8], material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(material);
    hex_digest(&hasher.finalize())
}

/// Deterministic controls owned by one reusable product fixture.
#[derive(Debug)]
pub struct FixtureControl {
    clock: Arc<dyn ConformanceClock>,
    faults: Arc<FaultPlan>,
    shard: ShardIdentity,
    state: Mutex<FixtureState>,
}

#[derive(Debug)]
struct FixtureState {
    transition: DurableTransition,
    restarted_after_current: BTreeSet<ProductService>,
    restart_in_progress: Option<RestartReservation>,
    restarts: Vec<RestartRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RestartReservation {
    after: DurableTransition,
    service: ProductService,
}

#[derive(Debug)]
struct RestartCycle {
    stopped: ServiceObservation,
    started: ServiceObservation,
}

impl FixtureControl {
    /// Creates controls for an identity selected from a derived shard plan.
    ///
    /// # Errors
    ///
    /// Rejects an ordinal not present in the plan.
    pub fn for_shard(
        clock: Arc<dyn ConformanceClock>,
        faults: Arc<FaultPlan>,
        plan: &ShardPlan,
        ordinal: u16,
    ) -> Result<Self, FixtureControlError> {
        let shard = plan.shard(ordinal)?.clone();
        Ok(Self {
            clock,
            faults,
            shard,
            state: Mutex::new(FixtureState {
                transition: DurableTransition::Provisioned,
                restarted_after_current: BTreeSet::new(),
                restart_in_progress: None,
                restarts: Vec::new(),
            }),
        })
    }

    #[must_use]
    pub const fn shard(&self) -> &ShardIdentity {
        &self.shard
    }

    #[must_use]
    pub fn faults(&self) -> &Arc<FaultPlan> {
        &self.faults
    }

    /// Executes and verifies a stop/start cycle after the current checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects duplicate restarts, probe failures, observations that do not prove
    /// a stopped old generation and running next generation, or poisoned state.
    pub fn restart_with(
        &self,
        service: ProductService,
        probe: &dyn ServiceRestartProbe,
    ) -> Result<(), FixtureControlError> {
        let reservation = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| FixtureControlError::Poisoned)?;
            if !state
                .transition
                .required_restart_services()
                .contains(&service)
            {
                return Err(FixtureControlError::UnexpectedRestartService);
            }
            if state.restarted_after_current.contains(&service) {
                return Err(FixtureControlError::DuplicateRestart);
            }
            if state.restart_in_progress.is_some() {
                return Err(FixtureControlError::RestartInProgress);
            }
            let reservation = RestartReservation {
                after: state.transition,
                service,
            };
            state.restart_in_progress = Some(reservation);
            reservation
        };

        // Probe implementations are external process adapters. Never invoke
        // them while the fixture state is locked: they may safely inspect this
        // control while carrying out a slow stop/start cycle.
        let outcome = Self::perform_restart(service, probe);
        let at_millis = self.clock.now_millis();

        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::Poisoned)?;
        if state.restart_in_progress != Some(reservation) || state.transition != reservation.after {
            return Err(FixtureControlError::RestartReservationChanged);
        }
        state.restart_in_progress = None;
        let cycle = outcome?;
        state.restarted_after_current.insert(service);
        state.restarts.push(RestartRecord {
            after: reservation.after,
            service,
            at_millis,
            stopped_generation: cycle.stopped.generation,
            started_generation: cycle.started.generation,
            stopped_instance: cycle.stopped.instance,
            started_instance: cycle.started.instance,
        });
        Ok(())
    }

    fn perform_restart(
        service: ProductService,
        probe: &dyn ServiceRestartProbe,
    ) -> Result<RestartCycle, FixtureControlError> {
        let before = probe.observe(service)?;
        if before.state != ServiceState::Running {
            return Err(FixtureControlError::ServiceNotRunning);
        }
        probe.stop(service)?;
        let stopped = probe.observe(service)?;
        if stopped.state != ServiceState::Stopped
            || stopped.generation != before.generation
            || stopped.instance != before.instance
        {
            return Err(FixtureControlError::RestartDidNotStop);
        }
        probe.start(service)?;
        let started = probe.observe(service)?;
        let expected_generation = before
            .generation
            .checked_add(1)
            .ok_or(FixtureControlError::ServiceGenerationOverflow)?;
        if started.state != ServiceState::Running
            || started.generation != expected_generation
            || started.instance == before.instance
        {
            return Err(FixtureControlError::RestartDidNotAdvance);
        }
        Ok(RestartCycle { stopped, started })
    }

    /// Advances exactly one durable checkpoint after its scheduled service restarts.
    ///
    /// Requiring a restart at every boundary makes restart determinism a fixture
    /// invariant instead of an optional scenario convention.
    ///
    /// # Errors
    ///
    /// Rejects noncontiguous transitions, in-progress or missing scheduled
    /// restarts, and poisoned state.
    pub fn transition(&self, next: DurableTransition) -> Result<(), FixtureControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::Poisoned)?;
        if next.ordinal() != state.transition.ordinal() + 1 {
            return Err(FixtureControlError::NonContiguousTransition);
        }
        if state.restart_in_progress.is_some() {
            return Err(FixtureControlError::RestartInProgress);
        }
        if !state
            .transition
            .required_restart_services()
            .iter()
            .all(|service| state.restarted_after_current.contains(service))
        {
            return Err(FixtureControlError::RestartRequired);
        }
        state.transition = next;
        state.restarted_after_current.clear();
        Ok(())
    }

    #[must_use]
    /// Returns the last completed durable checkpoint.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the private state lock.
    pub fn current_transition(&self) -> DurableTransition {
        self.state
            .lock()
            .expect("fixture state lock is not exposed to callbacks")
            .transition
    }

    #[must_use]
    /// Returns a stable copy of all recorded restart cycles.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the private state lock.
    pub fn restart_records(&self) -> Vec<RestartRecord> {
        self.state
            .lock()
            .expect("fixture state lock is not exposed to callbacks")
            .restarts
            .clone()
    }
}

/// Invalid deterministic fixture control operation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FixtureControlError {
    #[error("manual clock advance must be positive")]
    InvalidClockAdvance,
    #[error("manual clock overflowed")]
    ClockOverflow,
    #[error("fault plan is too large")]
    TooManyFaults,
    #[error("fault mode is invalid")]
    InvalidFault,
    #[error("shard count is outside the supported bound")]
    InvalidShardCount,
    #[error("shard run identity is invalid")]
    InvalidRunIdentity,
    #[error("derived shard identity collided")]
    ShardCollision,
    #[error("shard ordinal does not exist in the derived plan")]
    UnknownShard,
    #[error("fixture control lock was poisoned")]
    Poisoned,
    #[error("service was restarted twice at one checkpoint")]
    DuplicateRestart,
    #[error("service is not scheduled for restart at the current checkpoint")]
    UnexpectedRestartService,
    #[error("a service restart is already in progress")]
    RestartInProgress,
    #[error("the reserved restart checkpoint changed unexpectedly")]
    RestartReservationChanged,
    #[error("durable fixture transition is not contiguous")]
    NonContiguousTransition,
    #[error("a service restart is required before the next durable transition")]
    RestartRequired,
    #[error("service restart probe returned an invalid observation")]
    InvalidServiceObservation,
    #[error("service was not running before restart")]
    ServiceNotRunning,
    #[error("service restart probe did not observe the old generation stop")]
    RestartDidNotStop,
    #[error("service restart probe did not observe exactly the next running generation")]
    RestartDidNotAdvance,
    #[error("service generation overflowed")]
    ServiceGenerationOverflow,
    #[error("service restart probe operation failed")]
    ProbeFailed,
}
