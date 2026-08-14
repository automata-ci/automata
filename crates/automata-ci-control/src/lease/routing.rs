use std::collections::BTreeSet;

use async_trait::async_trait;
use uuid::Uuid;

use automata_ci_core::{AttemptId, JobIrVersion, UnixMillis};

use automata_ci_store::{
    RoutingDocument, RoutingLabel, RunnerSessionFence, RunnerSlotCount, StableRunnerSlot,
    StoreError,
};

/// Identifies an administrative runner group without exposing a backend key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerGroupId(Uuid);

impl RunnerGroupId {
    /// Wraps the durable runner-group UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the durable runner-group UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Routing facts loaded by the server from durable runner registration state.
///
/// Runner RPC requests deliberately carry only a [`RunnerSessionFence`]; they
/// cannot supply labels, group membership, slot capacity, or capabilities to
/// an individual claim operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerRoutingSnapshot {
    fence: RunnerSessionFence,
    group_id: Option<RunnerGroupId>,
    group_name: Option<String>,
    labels: BTreeSet<RoutingLabel>,
    registered_capabilities: RoutingDocument,
    negotiated_capabilities: RoutingDocument,
    slots: RunnerSlotCount,
    job_ir_version: JobIrVersion,
}

impl RunnerRoutingSnapshot {
    /// Constructs routing evidence decoded by an adapter.
    ///
    /// # Errors
    ///
    /// Rejects partial group identity or duplicate labels.
    pub fn try_new(
        fence: RunnerSessionFence,
        group: Option<(RunnerGroupId, String)>,
        labels: impl IntoIterator<Item = RoutingLabel>,
        registered_capabilities: RoutingDocument,
        negotiated_capabilities: RoutingDocument,
        slots: RunnerSlotCount,
        job_ir_version: JobIrVersion,
    ) -> Result<Self, RoutingSnapshotError> {
        let labels = labels.into_iter().collect::<Vec<_>>();
        let unique = labels.iter().cloned().collect::<BTreeSet<_>>();
        if labels.len() != unique.len() {
            return Err(RoutingSnapshotError::DuplicateLabel);
        }
        let (group_id, group_name) =
            group.map_or((None, None), |(id, name)| (Some(id), Some(name)));
        if group_name.as_deref().is_some_and(str::is_empty) {
            return Err(RoutingSnapshotError::EmptyGroupName);
        }
        Ok(Self {
            fence,
            group_id,
            group_name,
            labels: unique,
            registered_capabilities,
            negotiated_capabilities,
            slots,
            job_ir_version,
        })
    }

    /// Returns the exact live runner-session fence.
    #[must_use]
    pub const fn fence(&self) -> RunnerSessionFence {
        self.fence
    }

    /// Returns the optional administrative runner-group ID.
    #[must_use]
    pub const fn group_id(&self) -> Option<RunnerGroupId> {
        self.group_id
    }

    /// Returns the optional administrative runner-group name.
    #[must_use]
    pub fn group_name(&self) -> Option<&str> {
        self.group_name.as_deref()
    }

    /// Returns the runner's authoritative routing labels.
    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<RoutingLabel> {
        &self.labels
    }

    /// Returns the administratively registered capabilities.
    #[must_use]
    pub const fn registered_capabilities(&self) -> &RoutingDocument {
        &self.registered_capabilities
    }

    /// Returns the session-negotiated capabilities.
    #[must_use]
    pub const fn negotiated_capabilities(&self) -> &RoutingDocument {
        &self.negotiated_capabilities
    }

    /// Returns the registered slot capacity.
    #[must_use]
    pub const fn slots(&self) -> RunnerSlotCount {
        self.slots
    }

    /// Returns the exact `JobIR` version selected for this durable session.
    #[must_use]
    pub const fn job_ir_version(&self) -> JobIrVersion {
        self.job_ir_version
    }
}

/// Invalid routing evidence returned by a storage adapter.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum RoutingSnapshotError {
    /// The routing snapshot repeats a label.
    #[error("runner routing snapshot contains a duplicate label")]
    DuplicateLabel,
    /// A runner group is present with an empty name.
    #[error("runner routing snapshot contains an empty group name")]
    EmptyGroupName,
}

/// Server-side access to authoritative routing state.
#[async_trait]
pub trait RunnerRoutingRepository: Send + Sync {
    /// Loads authoritative routing state for an exact live session.
    async fn routing_for_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerRoutingSnapshot, StoreError>;
}

/// Authoritative state of one exact stable runner slot at an observation time.
///
/// This is a scheduling hint only. A claim adapter must re-check the slot in
/// the same transaction that issues a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerSlotAvailability {
    /// No live assignment currently owns the slot.
    Available,
    /// A live assignment currently owns the slot.
    Occupied {
        /// The attempt currently assigned to the slot.
        attempt_id: AttemptId,
    },
    /// The slot is outside the durable registration's configured capacity.
    OutOfRange,
    /// The durable runner registration is not currently online for new work.
    RunnerUnavailable,
}

/// Read port for deriving capacity from durable state rather than trusting a
/// runner's poll or assuming every configured slot is free.
#[async_trait]
pub trait RunnerSlotAvailabilityRepository: Send + Sync {
    /// Loads the state of exactly one slot for the exact live session fence.
    ///
    /// Stale, closed, or mismatched fences fail with [`StoreError`]. The
    /// trusted `observed_at` is included so adapters can retain a consistent
    /// observation boundary as this query evolves.
    async fn slot_availability(
        &self,
        fence: RunnerSessionFence,
        slot: StableRunnerSlot,
        observed_at: UnixMillis,
    ) -> Result<RunnerSlotAvailability, StoreError>;
}
