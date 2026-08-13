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
pub const MAX_CONFORMANCE_SHARDS: u16 = 256;
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

/// Ordered one-shot fault script. Ordinary product construction uses an empty plan.
#[derive(Debug, Default)]
pub struct FaultPlan(Mutex<BTreeMap<FaultTarget, VecDeque<FaultMode>>>);

impl FaultPlan {
    /// Builds a bounded deterministic plan.
    ///
    /// # Errors
    ///
    /// Rejects an unbounded script or zero rate-limit duration.
    pub fn new(
        faults: impl IntoIterator<Item = (FaultTarget, FaultMode)>,
    ) -> Result<Self, FixtureControlError> {
        let mut plan = BTreeMap::<FaultTarget, VecDeque<FaultMode>>::new();
        let mut count = 0_usize;
        for (target, mode) in faults {
            count = count
                .checked_add(1)
                .ok_or(FixtureControlError::TooManyFaults)?;
            if count > MAX_FAULTS {
                return Err(FixtureControlError::TooManyFaults);
            }
            if matches!(
                mode,
                FaultMode::RateLimited {
                    retry_after_millis: 0
                }
            ) {
                return Err(FixtureControlError::InvalidFault);
            }
            plan.entry(target).or_default().push_back(mode);
        }
        Ok(Self(Mutex::new(plan)))
    }

    /// Consumes exactly the next fault for one boundary.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the private plan lock.
    #[must_use]
    pub fn take(&self, target: FaultTarget) -> Option<FaultMode> {
        self.0
            .lock()
            .expect("fault plan lock is not exposed to callbacks")
            .get_mut(&target)
            .and_then(VecDeque::pop_front)
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
}

/// One exact restart retained in fixture evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RestartRecord {
    pub after: DurableTransition,
    pub service: ProductService,
    pub at_millis: i64,
}

/// Stable identities assigned to one parallel shard.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShardIdentity {
    pub id: String,
    pub postgres_schema: String,
    pub object_prefix: String,
    pub credential_scope: String,
    pub port_reservation_key: String,
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
    clock: Arc<ManualConformanceClock>,
    faults: Arc<FaultPlan>,
    shard: ShardIdentity,
    state: Mutex<FixtureState>,
}

#[derive(Debug)]
struct FixtureState {
    transition: DurableTransition,
    restarted_after_current: BTreeSet<ProductService>,
    restarts: Vec<RestartRecord>,
}

impl FixtureControl {
    #[must_use]
    pub fn new(
        clock: Arc<ManualConformanceClock>,
        faults: Arc<FaultPlan>,
        shard: ShardIdentity,
    ) -> Self {
        Self {
            clock,
            faults,
            shard,
            state: Mutex::new(FixtureState {
                transition: DurableTransition::Provisioned,
                restarted_after_current: BTreeSet::new(),
                restarts: Vec::new(),
            }),
        }
    }

    #[must_use]
    pub const fn shard(&self) -> &ShardIdentity {
        &self.shard
    }

    #[must_use]
    pub fn faults(&self) -> &Arc<FaultPlan> {
        &self.faults
    }

    /// Records a completed stop/start cycle after the current durable checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects a duplicate restart or a poisoned fixture-state lock.
    pub fn restarted(&self, service: ProductService) -> Result<(), FixtureControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::Poisoned)?;
        if !state.restarted_after_current.insert(service) {
            return Err(FixtureControlError::DuplicateRestart);
        }
        let after = state.transition;
        state.restarts.push(RestartRecord {
            after,
            service,
            at_millis: self.clock.now_millis(),
        });
        Ok(())
    }

    /// Advances exactly one durable checkpoint after at least one service restart.
    ///
    /// Requiring a restart at every boundary makes restart determinism a fixture
    /// invariant instead of an optional scenario convention.
    ///
    /// # Errors
    ///
    /// Rejects noncontiguous transitions, missing restarts, and poisoned state.
    pub fn transition(&self, next: DurableTransition) -> Result<(), FixtureControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FixtureControlError::Poisoned)?;
        if next.ordinal() != state.transition.ordinal() + 1 {
            return Err(FixtureControlError::NonContiguousTransition);
        }
        if state.restarted_after_current.is_empty() {
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
    #[error("fixture control lock was poisoned")]
    Poisoned,
    #[error("service was restarted twice at one checkpoint")]
    DuplicateRestart,
    #[error("durable fixture transition is not contiguous")]
    NonContiguousTransition,
    #[error("a service restart is required before the next durable transition")]
    RestartRequired,
}
