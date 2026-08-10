//! Database-time, replay-bounded selection for autonomous logical workers.

use std::{fmt, num::NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{Sha256Digest, UnixMillis};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ClaimedLogicalActivationPreparation, ClaimedLogicalInstanceMaterialization,
    ClaimedLogicalJobActivation, LogicalActivationPreparationTarget, LogicalActivationWorkerId,
    LogicalInstanceMaterializationTarget, LogicalMaterializationWorkerId, StoreError,
};

/// Maximum database-issued selection lease.
pub const MAX_LOGICAL_WORK_SELECTION_MILLIS: i64 = 5 * 60 * 1_000;
/// Minimum requested selection lease, leaving bounded work before handoff.
pub const MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS: i64 = 2_000;
/// Minimum authority remaining when a selected claim is handed to a worker.
pub const MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS: i64 = 1_000;
/// Minimum database-issued real-claim renewal request.
///
/// This is intentionally greater than the handoff minimum so a renewal at
/// the exact request boundary can still be returned with useful authority.
pub const MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS: i64 = 2_000;
/// Maximum candidates examined by one bounded selector transaction.
pub const MAX_LOGICAL_WORK_DISCOVERY_CANDIDATES: usize = 1_024;

/// Non-nil idempotency identity for one autonomous selector call.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalWorkSelectionId(Uuid);

impl LogicalWorkSelectionId {
    /// Constructs one stable non-nil selection identity.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID sentinel.
    pub fn from_uuid(value: Uuid) -> Result<Self, LogicalWorkSelectionValueError> {
        if value.is_nil() {
            Err(LogicalWorkSelectionValueError::NilSelectionId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Positive persistent takeover generation for one selected target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalWorkSelectionGeneration(NonZeroU64);

impl LogicalWorkSelectionGeneration {
    /// Constructs a positive generation representable by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero or values greater than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, LogicalWorkSelectionValueError> {
        NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .map(Self)
            .ok_or(LogicalWorkSelectionValueError::InvalidGeneration)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.get()).expect("validated work-selection generation fits BIGINT")
    }
}

/// Request to select at most one globally ready logical job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimNextLogicalJobOrchestration {
    selection_id: LogicalWorkSelectionId,
    owner: LogicalActivationWorkerId,
    observed_at: UnixMillis,
    duration_ms: i64,
}

impl ClaimNextLogicalJobOrchestration {
    /// Constructs a bounded selection request.
    ///
    /// # Errors
    ///
    /// Rejects negative caller time or a zero/excessive duration.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        owner: LogicalActivationWorkerId,
        observed_at: UnixMillis,
        duration_ms: i64,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        validate_request(observed_at, duration_ms)?;
        Ok(Self {
            selection_id,
            owner,
            observed_at,
            duration_ms,
        })
    }

    /// Returns the stable selection identity.
    #[must_use]
    pub const fn selection_id(&self) -> LogicalWorkSelectionId {
        self.selection_id
    }

    /// Returns the process-lifetime worker identity.
    #[must_use]
    pub const fn owner(&self) -> LogicalActivationWorkerId {
        self.owner
    }

    /// Returns caller time used only for bounded database-skew admission.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the requested database-issued lease duration.
    #[must_use]
    pub const fn duration_ms(&self) -> i64 {
        self.duration_ms
    }
}

/// Kind of inert orchestration discovery evidence recorded by the selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalJobOrchestrationAuthorityKind {
    /// The selector atomically acquired the first preparation claim.
    Preparation,
    /// Preparation was already durable and the selector acquired activation.
    Activation,
}

/// Inert orchestration discovery evidence; it never authorizes provider or blob work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedLogicalJobOrchestration {
    selection_id: LogicalWorkSelectionId,
    target: LogicalActivationPreparationTarget,
    owner: LogicalActivationWorkerId,
    generation: LogicalWorkSelectionGeneration,
    authority_kind: LogicalJobOrchestrationAuthorityKind,
    authority_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl SelectedLogicalJobOrchestration {
    /// Rehydrates one exact selection receipt.
    ///
    /// # Errors
    ///
    /// Rejects an empty or overlong interval.
    #[allow(clippy::too_many_arguments)] // The immutable receipt tuple is validated as one unit.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        target: LogicalActivationPreparationTarget,
        owner: LogicalActivationWorkerId,
        generation: LogicalWorkSelectionGeneration,
        authority_kind: LogicalJobOrchestrationAuthorityKind,
        authority_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        validate_interval(claimed_at, expires_at)?;
        Ok(Self {
            selection_id,
            target,
            owner,
            generation,
            authority_kind,
            authority_digest,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the request identity.
    #[must_use]
    pub const fn selection_id(&self) -> LogicalWorkSelectionId {
        self.selection_id
    }

    /// Returns the exact selected target.
    #[must_use]
    pub const fn target(&self) -> &LogicalActivationPreparationTarget {
        &self.target
    }

    /// Returns the worker named by the discovery receipt.
    #[must_use]
    pub const fn owner(&self) -> LogicalActivationWorkerId {
        self.owner
    }

    /// Returns the positive target generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalWorkSelectionGeneration {
        self.generation
    }

    /// Returns which sole durable claim carries this orchestration authority.
    #[must_use]
    pub const fn authority_kind(&self) -> LogicalJobOrchestrationAuthorityKind {
        self.authority_kind
    }

    /// Returns the preparation descriptor or activation input digest.
    #[must_use]
    pub const fn authority_digest(&self) -> Sha256Digest {
        self.authority_digest
    }

    /// Returns the database-issued start.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the exclusive database-issued expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Result of one global orchestration selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalJobOrchestrationSelectionOutcome {
    /// No unlocked ready target exists.
    Idle,
    /// One exact target was discovered; it must be consumed before any work.
    Selected(SelectedLogicalJobOrchestration),
    /// The exact previously selected lineage is now durably quarantined.
    Quarantined,
    /// The bounded scan found contention but did not prove the queue idle.
    Contended,
}

/// Request to select at most one globally published unmaterialized instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimNextLogicalInstanceMaterialization {
    selection_id: LogicalWorkSelectionId,
    owner: LogicalMaterializationWorkerId,
    observed_at: UnixMillis,
    duration_ms: i64,
}

impl ClaimNextLogicalInstanceMaterialization {
    /// Constructs a bounded selection request.
    ///
    /// # Errors
    ///
    /// Rejects negative caller time or a zero/excessive duration.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        owner: LogicalMaterializationWorkerId,
        observed_at: UnixMillis,
        duration_ms: i64,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        validate_request(observed_at, duration_ms)?;
        Ok(Self {
            selection_id,
            owner,
            observed_at,
            duration_ms,
        })
    }

    /// Returns the stable selection identity.
    #[must_use]
    pub const fn selection_id(&self) -> LogicalWorkSelectionId {
        self.selection_id
    }

    /// Returns the process-lifetime worker identity.
    #[must_use]
    pub const fn owner(&self) -> LogicalMaterializationWorkerId {
        self.owner
    }

    /// Returns caller time used only for bounded database-skew admission.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the requested database-issued lease duration.
    #[must_use]
    pub const fn duration_ms(&self) -> i64 {
        self.duration_ms
    }
}

/// Inert materialization discovery evidence; it never authorizes provider or blob work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedLogicalInstanceMaterialization {
    selection_id: LogicalWorkSelectionId,
    target: LogicalInstanceMaterializationTarget,
    owner: LogicalMaterializationWorkerId,
    generation: LogicalWorkSelectionGeneration,
    authority_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl SelectedLogicalInstanceMaterialization {
    /// Rehydrates one exact selection receipt.
    ///
    /// # Errors
    ///
    /// Rejects an empty or overlong interval.
    pub fn new(
        selection_id: LogicalWorkSelectionId,
        target: LogicalInstanceMaterializationTarget,
        owner: LogicalMaterializationWorkerId,
        generation: LogicalWorkSelectionGeneration,
        authority_digest: Sha256Digest,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        validate_interval(claimed_at, expires_at)?;
        Ok(Self {
            selection_id,
            target,
            owner,
            generation,
            authority_digest,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the request identity.
    #[must_use]
    pub const fn selection_id(&self) -> LogicalWorkSelectionId {
        self.selection_id
    }

    /// Returns the exact selected target.
    #[must_use]
    pub const fn target(&self) -> &LogicalInstanceMaterializationTarget {
        &self.target
    }

    /// Returns the worker named by the discovery receipt.
    #[must_use]
    pub const fn owner(&self) -> LogicalMaterializationWorkerId {
        self.owner
    }

    /// Returns the positive target generation.
    #[must_use]
    pub const fn generation(&self) -> LogicalWorkSelectionGeneration {
        self.generation
    }

    /// Returns the descriptor digest bound by the sole durable materialization claim.
    #[must_use]
    pub const fn authority_digest(&self) -> Sha256Digest {
        self.authority_digest
    }

    /// Returns the database-issued start.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the exclusive database-issued expiration.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Result of one global materialization selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalInstanceMaterializationSelectionOutcome {
    /// No unlocked published instance exists.
    Idle,
    /// One exact target was discovered; it must be consumed before any work.
    Selected(SelectedLogicalInstanceMaterialization),
    /// The exact previously selected lineage is now durably quarantined.
    Quarantined,
    /// The bounded scan found contention but did not prove the queue idle.
    Contended,
}

/// Request to consume the exact current claim lineage selected for orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeSelectedLogicalJobOrchestration {
    selected: SelectedLogicalJobOrchestration,
}

impl ConsumeSelectedLogicalJobOrchestration {
    /// Constructs a consume request from non-authorizing discovery evidence.
    #[must_use]
    pub const fn new(selected: SelectedLogicalJobOrchestration) -> Self {
        Self { selected }
    }

    /// Returns the selected discovery evidence.
    #[must_use]
    pub const fn selected(&self) -> &SelectedLogicalJobOrchestration {
        &self.selected
    }
}

/// Exact rich authority recovered immediately before orchestration work.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Rich authenticated phase evidence stays owned and exact.
pub enum ConsumedLogicalJobOrchestrationAuthority {
    /// The existing preparation claim is live and current.
    Preparation(ClaimedLogicalActivationPreparation),
    /// The existing activation claim is live and current.
    Activation(ClaimedLogicalJobActivation),
}

/// Selection evidence joined to the exact current orchestration claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedSelectedLogicalJobOrchestration {
    selected: SelectedLogicalJobOrchestration,
    authority: ConsumedLogicalJobOrchestrationAuthority,
    validated_at: UnixMillis,
}

impl ConsumedSelectedLogicalJobOrchestration {
    /// Joins exact base-generation authority to inert selection evidence.
    ///
    /// This public constructor is intentionally limited to the generation and
    /// interval stored in the selection receipt. A later renewed generation can
    /// only be joined by the repository after it proves every immutable renewal
    /// edge under lock.
    ///
    /// # Errors
    ///
    /// Rejects a target, owner, origin, generation, digest, or authority-kind
    /// mismatch.
    pub fn new(
        selected: SelectedLogicalJobOrchestration,
        authority: ConsumedLogicalJobOrchestrationAuthority,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        Self::new_inner(selected, authority, validated_at, false)
    }

    pub(crate) fn new_repository_verified(
        selected: SelectedLogicalJobOrchestration,
        authority: ConsumedLogicalJobOrchestrationAuthority,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        Self::new_inner(selected, authority, validated_at, true)
    }

    fn new_inner(
        selected: SelectedLogicalJobOrchestration,
        authority: ConsumedLogicalJobOrchestrationAuthority,
        validated_at: UnixMillis,
        repository_verified_later: bool,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        if !orchestration_authority_matches(&selected, &authority, repository_verified_later)
            || !orchestration_handoff_is_live(&authority, validated_at)
        {
            return Err(LogicalWorkSelectionValueError::AuthorityMismatch);
        }
        Ok(Self {
            selected,
            authority,
            validated_at,
        })
    }

    /// Returns the immutable selection receipt that led to this consume.
    #[must_use]
    pub const fn selected(&self) -> &SelectedLogicalJobOrchestration {
        &self.selected
    }

    /// Returns the exact current claim loaded under the selection lineage.
    #[must_use]
    pub const fn authority(&self) -> &ConsumedLogicalJobOrchestrationAuthority {
        &self.authority
    }

    /// Returns the authoritative database observation immediately preceding handoff.
    #[must_use]
    pub const fn validated_at(&self) -> UnixMillis {
        self.validated_at
    }
}

/// Request to consume the exact current materialization claim lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeSelectedLogicalInstanceMaterialization {
    selected: SelectedLogicalInstanceMaterialization,
}

/// Selection evidence joined to the exact current materialization claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedSelectedLogicalInstanceMaterialization {
    selected: SelectedLogicalInstanceMaterialization,
    authority: ClaimedLogicalInstanceMaterialization,
    validated_at: UnixMillis,
}

impl ConsumedSelectedLogicalInstanceMaterialization {
    /// Joins repository-authenticated current authority to inert selection evidence.
    ///
    /// This public constructor accepts only the exact generation and interval
    /// stored in the selection receipt. A repository may join a later renewed
    /// generation only after proving its complete immutable renewal chain.
    ///
    /// # Errors
    ///
    /// Rejects a target, owner, origin, generation, digest, or interval mismatch.
    pub fn new(
        selected: SelectedLogicalInstanceMaterialization,
        authority: ClaimedLogicalInstanceMaterialization,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        Self::new_inner(selected, authority, validated_at, false)
    }

    pub(crate) fn new_repository_verified(
        selected: SelectedLogicalInstanceMaterialization,
        authority: ClaimedLogicalInstanceMaterialization,
        validated_at: UnixMillis,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        Self::new_inner(selected, authority, validated_at, true)
    }

    fn new_inner(
        selected: SelectedLogicalInstanceMaterialization,
        authority: ClaimedLogicalInstanceMaterialization,
        validated_at: UnixMillis,
        repository_verified_later: bool,
    ) -> Result<Self, LogicalWorkSelectionValueError> {
        if !materialization_authority_matches(&selected, &authority, repository_verified_later)
            || !handoff_is_live(
                authority.claim().claimed_at(),
                authority.claim().expires_at(),
                validated_at,
            )
        {
            return Err(LogicalWorkSelectionValueError::AuthorityMismatch);
        }
        Ok(Self {
            selected,
            authority,
            validated_at,
        })
    }

    /// Returns the immutable selection receipt that led to this consume.
    #[must_use]
    pub const fn selected(&self) -> &SelectedLogicalInstanceMaterialization {
        &self.selected
    }

    /// Returns the exact current claim loaded under the selection lineage.
    #[must_use]
    pub const fn authority(&self) -> &ClaimedLogicalInstanceMaterialization {
        &self.authority
    }

    /// Returns the authoritative database observation immediately preceding handoff.
    #[must_use]
    pub const fn validated_at(&self) -> UnixMillis {
        self.validated_at
    }
}

impl ConsumeSelectedLogicalInstanceMaterialization {
    /// Constructs a consume request from non-authorizing discovery evidence.
    #[must_use]
    pub const fn new(selected: SelectedLogicalInstanceMaterialization) -> Self {
        Self { selected }
    }

    /// Returns the selected discovery evidence.
    #[must_use]
    pub const fn selected(&self) -> &SelectedLogicalInstanceMaterialization {
        &self.selected
    }
}

/// Closed, value-free reason for isolating selected work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogicalWorkQuarantineKind {
    /// Durable relational evidence was internally inconsistent.
    RelationalEvidence,
    /// An immutable object was unavailable under its exact descriptor.
    ObjectEvidence,
    /// Loaded bytes were malformed or disagreed with current semantics.
    PayloadEvidence,
}

/// Exact selected orchestration fence to isolate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineLogicalJobOrchestration {
    consumed: ConsumedSelectedLogicalJobOrchestration,
    kind: LogicalWorkQuarantineKind,
}

impl QuarantineLogicalJobOrchestration {
    /// Binds a closed failure kind to an exact consumed selection authority.
    #[must_use]
    pub const fn new(
        consumed: ConsumedSelectedLogicalJobOrchestration,
        kind: LogicalWorkQuarantineKind,
    ) -> Self {
        Self { consumed, kind }
    }

    /// Returns the exact consumed selection authority.
    #[must_use]
    pub const fn consumed(&self) -> &ConsumedSelectedLogicalJobOrchestration {
        &self.consumed
    }

    /// Returns the immutable selection receipt.
    #[must_use]
    pub const fn selected(&self) -> &SelectedLogicalJobOrchestration {
        self.consumed.selected()
    }

    /// Returns the closed failure kind.
    #[must_use]
    pub const fn kind(&self) -> LogicalWorkQuarantineKind {
        self.kind
    }
}

/// Exact selected materialization fence to isolate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineLogicalInstanceMaterialization {
    consumed: ConsumedSelectedLogicalInstanceMaterialization,
    kind: LogicalWorkQuarantineKind,
}

impl QuarantineLogicalInstanceMaterialization {
    /// Binds a closed failure kind to an exact consumed selection authority.
    #[must_use]
    pub const fn new(
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        kind: LogicalWorkQuarantineKind,
    ) -> Self {
        Self { consumed, kind }
    }

    /// Returns the exact consumed selection authority.
    #[must_use]
    pub const fn consumed(&self) -> &ConsumedSelectedLogicalInstanceMaterialization {
        &self.consumed
    }

    /// Returns the immutable selection receipt.
    #[must_use]
    pub const fn selected(&self) -> &SelectedLogicalInstanceMaterialization {
        self.consumed.selected()
    }

    /// Returns the closed failure kind.
    #[must_use]
    pub const fn kind(&self) -> LogicalWorkQuarantineKind {
        self.kind
    }
}

/// Result of idempotently isolating selected work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalWorkQuarantineOutcome {
    /// The exact live selection was isolated.
    Quarantined,
    /// The same target was already isolated.
    AlreadyQuarantined,
    /// The submitted selection no longer owns the current live fence.
    FenceRejected,
}

/// Invalid autonomous selection value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LogicalWorkSelectionValueError {
    /// The selection identity used the nil sentinel.
    #[error("logical work selection ID must not be nil")]
    NilSelectionId,
    /// A generation was zero or outside `PostgreSQL` `BIGINT`.
    #[error("logical work selection generation is invalid")]
    InvalidGeneration,
    /// Caller time or the requested duration was invalid.
    #[error("logical work selection request is invalid")]
    InvalidRequest,
    /// A rehydrated database interval was empty or excessive.
    #[error("logical work selection interval is invalid")]
    InvalidInterval,
    /// Consumed authority disagreed with its inert selection evidence.
    #[error("logical work selection authority is inconsistent")]
    AuthorityMismatch,
}

/// Durable selector failure.
#[derive(Debug, Error)]
pub enum LogicalWorkSelectionStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// One selection identity was replayed with different authority or bounds.
    #[error("logical work selection identity was reused inconsistently")]
    SelectionConflict,
    /// The exact replay horizon has closed.
    #[error("logical work selection replay horizon has closed")]
    SelectionExpired,
    /// Caller time was not corroborated by authoritative database time.
    #[error("logical work selection time exceeds database clock skew")]
    SelectionClockSkew,
    /// A target's positive takeover generation is exhausted.
    #[error("logical work selection generation is exhausted")]
    GenerationExhausted,
    /// The exact selected lineage was durably quarantined.
    #[error("logical work selection is quarantined")]
    SelectionQuarantined,
}

/// Persistence boundary for both autonomous pre-execution queues.
#[async_trait]
pub trait LogicalWorkSelectionRepository: fmt::Debug + Send + Sync {
    /// Selects at most one oldest-ready logical job without waiting on peers.
    async fn claim_next_logical_job_orchestration(
        &self,
        request: ClaimNextLogicalJobOrchestration,
    ) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError>;

    /// Selects at most one oldest-published unmaterialized instance.
    async fn claim_next_logical_instance_materialization(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
    ) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError>;

    /// Locks and returns the existing exact live orchestration claim.
    async fn consume_selected_logical_job_orchestration(
        &self,
        request: ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError>;

    /// Locks and returns the existing exact live materialization claim.
    async fn consume_selected_logical_instance_materialization(
        &self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError>;

    /// Isolates one exact selected logical-job lineage.
    async fn quarantine_logical_job_orchestration(
        &self,
        request: QuarantineLogicalJobOrchestration,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError>;

    /// Isolates one exact selected instance lineage.
    async fn quarantine_logical_instance_materialization(
        &self,
        request: QuarantineLogicalInstanceMaterialization,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError>;
}

fn orchestration_authority_matches(
    selected: &SelectedLogicalJobOrchestration,
    authority: &ConsumedLogicalJobOrchestrationAuthority,
    repository_verified_later: bool,
) -> bool {
    match authority {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => {
            let claim = claimed.claim();
            selected.authority_kind() == LogicalJobOrchestrationAuthorityKind::Preparation
                && claim.target() == selected.target()
                && claim.owner() == selected.owner()
                && claim.selection_origin() == selected.selection_id()
                && claim.descriptor_digest() == selected.authority_digest()
                && renewed_lineage_matches(
                    selected,
                    claim.generation().get(),
                    claim.claimed_at(),
                    claim.expires_at(),
                    repository_verified_later,
                )
        }
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            let claim = claimed.claim();
            let target = selected.target();
            selected.authority_kind() == LogicalJobOrchestrationAuthorityKind::Activation
                && claim.tenant() == target.tenant()
                && claim.run_id() == target.run_id()
                && claim.invocation_id() == target.invocation_id()
                && claim.logical_job_id() == target.logical_job_id()
                && claim.owner() == selected.owner()
                && claim.selection_origin() == selected.selection_id()
                && claim.input_digest() == selected.authority_digest()
                && renewed_lineage_matches(
                    selected,
                    claim.generation().get(),
                    claim.claimed_at(),
                    claim.expires_at(),
                    repository_verified_later,
                )
        }
    }
}

fn orchestration_handoff_is_live(
    authority: &ConsumedLogicalJobOrchestrationAuthority,
    validated_at: UnixMillis,
) -> bool {
    match authority {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => handoff_is_live(
            claimed.claim().claimed_at(),
            claimed.claim().expires_at(),
            validated_at,
        ),
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => handoff_is_live(
            claimed.claim().claimed_at(),
            claimed.claim().expires_at(),
            validated_at,
        ),
    }
}

fn handoff_is_live(
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    validated_at: UnixMillis,
) -> bool {
    validated_at >= claimed_at
        && expires_at.get().saturating_sub(validated_at.get())
            >= MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS
}

fn renewed_lineage_matches(
    selected: &SelectedLogicalJobOrchestration,
    generation: u64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    repository_verified_later: bool,
) -> bool {
    let selected_generation = selected.generation().get();
    generation == selected_generation
        && claimed_at == selected.claimed_at()
        && expires_at == selected.expires_at()
        || repository_verified_later
            && generation > selected_generation
            && claimed_at >= selected.claimed_at()
            && expires_at > selected.expires_at()
}

fn materialization_authority_matches(
    selected: &SelectedLogicalInstanceMaterialization,
    authority: &ClaimedLogicalInstanceMaterialization,
    repository_verified_later: bool,
) -> bool {
    let claim = authority.claim();
    claim.target() == selected.target()
        && claim.owner() == selected.owner()
        && claim.selection_origin() == selected.selection_id()
        && claim.descriptor_digest() == selected.authority_digest()
        && materialization_lineage_matches(
            selected,
            claim.generation().get(),
            claim.claimed_at(),
            claim.expires_at(),
            repository_verified_later,
        )
}

fn materialization_lineage_matches(
    selected: &SelectedLogicalInstanceMaterialization,
    generation: u64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    repository_verified_later: bool,
) -> bool {
    let selected_generation = selected.generation().get();
    generation == selected_generation
        && claimed_at == selected.claimed_at()
        && expires_at == selected.expires_at()
        || repository_verified_later
            && generation > selected_generation
            && claimed_at >= selected.claimed_at()
            && expires_at > selected.expires_at()
}

fn validate_request(
    observed_at: UnixMillis,
    duration_ms: i64,
) -> Result<(), LogicalWorkSelectionValueError> {
    if observed_at.get() < 0
        || !(MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS..=MAX_LOGICAL_WORK_SELECTION_MILLIS)
            .contains(&duration_ms)
    {
        Err(LogicalWorkSelectionValueError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_interval(
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), LogicalWorkSelectionValueError> {
    let duration = expires_at.get().checked_sub(claimed_at.get());
    if claimed_at.get() < 0
        || !matches!(
            duration,
            Some(value)
                if (MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS
                    ..=MAX_LOGICAL_WORK_SELECTION_MILLIS)
                    .contains(&value)
        )
    {
        Err(LogicalWorkSelectionValueError::InvalidInterval)
    } else {
        Ok(())
    }
}
