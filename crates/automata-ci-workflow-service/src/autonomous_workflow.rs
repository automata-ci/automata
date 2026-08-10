//! Autonomous, selection-bound preparation, activation, and materialization.
//!
//! A selector receipt is deliberately inert. This worker consumes it into the
//! exact current phase claim before handing any capability to an executor.
//! Executors never receive a target/worker pair or the selector receipt; they
//! receive a worker-owned lease that exposes only the current rich authority
//! and exact renewal. Product readiness must remain false until a real
//! implementation of [`AutonomousWorkflowPhaseExecutor`] is composed for all
//! three phases.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_core::UnixMillis;
use automata_ci_store::{
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimedLogicalActivationPreparation, ClaimedLogicalInstanceMaterialization,
    ClaimedLogicalJobActivation, ConsumeSelectedLogicalInstanceMaterialization,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    ConsumedSelectedLogicalInstanceMaterialization, ConsumedSelectedLogicalJobOrchestration,
    LogicalActivationPreparationStore, LogicalActivationPreparationStoreError,
    LogicalActivationRepository, LogicalActivationStoreError, LogicalActivationWorkerId,
    LogicalInstanceMaterializationSelectionOutcome, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationRepository, LogicalMaterializationStoreError,
    LogicalMaterializationWorkerId, LogicalWorkQuarantineKind, LogicalWorkQuarantineOutcome,
    LogicalWorkSelectionRepository, MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS,
    MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS, MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS,
    MAX_LOGICAL_WORK_SELECTION_MILLIS, MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS,
    QuarantineLogicalInstanceMaterialization, QuarantineLogicalJobOrchestration,
    RenewLogicalActivationPreparation, RenewLogicalInstanceMaterialization,
    RenewLogicalJobActivation, StoreError,
};
use thiserror::Error;
use tokio::{
    sync::{Mutex, watch},
    time::{Instant, sleep, sleep_until},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    AdmissionClock, activation_preparation::ReadyLogicalActivationPreparation,
    materialization::ReadyLogicalInstanceMaterialization, orchestration::ReadyLogicalJobActivation,
};

/// Safety subtracted from every database-issued authority interval.
///
/// The deadline is anchored before the consume/renew round trip, so transport
/// and scheduling time also consume the usable interval.
pub const AUTONOMOUS_WORKFLOW_AUTHORITY_SAFETY_MILLIS: i64 = 250;

const IDLE_POLL_MILLIS: u64 = 250;
const CUSTODY_OPERATION_TIMEOUT_MILLIS: u64 = 30_000;
const CUSTODY_RETRY_MILLIS: u64 = 250;

/// Queue polled by one autonomous worker pass.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AutonomousWorkflowQueue {
    /// Logical-job preparation or activation.
    Orchestration,
    /// Activated-instance materialization.
    Materialization,
}

/// Exact phase completed by one autonomous worker pass.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AutonomousWorkflowPhase {
    /// Immutable activation inputs were prepared and bound.
    Preparation,
    /// A prepared logical job was activated and published.
    Activation,
    /// One published logical instance became a runnable concrete job.
    Materialization,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExpectedRenewalSuccessor {
    phase: AutonomousWorkflowPhase,
    generation: u64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ExpectedRenewalSuccessor {
    const fn new(
        phase: AutonomousWorkflowPhase,
        generation: u64,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Self {
        Self {
            phase,
            generation,
            claimed_at,
            expires_at,
        }
    }

    const fn matches_orchestration(
        self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
    ) -> bool {
        match (self.phase, consumed.authority()) {
            (
                AutonomousWorkflowPhase::Preparation,
                ConsumedLogicalJobOrchestrationAuthority::Preparation(authority),
            ) => self.accepts_claim(
                authority.claim().generation().get(),
                authority.claim().claimed_at(),
                authority.claim().expires_at(),
            ),
            (
                AutonomousWorkflowPhase::Activation,
                ConsumedLogicalJobOrchestrationAuthority::Activation(authority),
            ) => self.accepts_claim(
                authority.claim().generation().get(),
                authority.claim().claimed_at(),
                authority.claim().expires_at(),
            ),
            _ => false,
        }
    }

    fn matches_materialization(
        self,
        consumed: &ConsumedSelectedLogicalInstanceMaterialization,
    ) -> bool {
        self.phase == AutonomousWorkflowPhase::Materialization
            && self.accepts_claim(
                consumed.authority().claim().generation().get(),
                consumed.authority().claim().claimed_at(),
                consumed.authority().claim().expires_at(),
            )
    }

    const fn accepts_claim(
        self,
        generation: u64,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> bool {
        // Public consumed-value construction is exact-base-only. Therefore a
        // later tuple can only cross this boundary after the Store proves its
        // complete immutable renewal lineage under lock.
        if self.generation == generation {
            self.claimed_at.get() == claimed_at.get() && self.expires_at.get() == expires_at.get()
        } else {
            self.generation < generation
                && self.claimed_at.get() <= claimed_at.get()
                && self.expires_at.get() <= expires_at.get()
        }
    }
}

/// Result of one bounded autonomous workflow pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutonomousWorkflowOutcome {
    /// Both queues proved that no unlocked ready work existed.
    Idle,
    /// A bounded selector could not prove its queue idle because of contention.
    Contended(AutonomousWorkflowQueue),
    /// One corrupt selected lineage was isolated, newly or by exact replay.
    Quarantined(AutonomousWorkflowQueue),
    /// The selected queue or its phase dependency was temporarily unavailable.
    Unavailable(AutonomousWorkflowQueue),
    /// Exactly one selected phase completed.
    Completed(AutonomousWorkflowPhase),
}

/// Closed executor result that never transfers authority custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutonomousWorkflowExecutionOutcome {
    /// The selected phase completed its exact durable mutation.
    Completed,
    /// Exact evidence was malformed and the latest authority must be isolated.
    EvidenceFailure(LogicalWorkQuarantineKind),
    /// A genuine dependency failure may be retried after the claim expires.
    Retryable,
    /// The executor atomically retained an unpolled final request in worker custody.
    FinalRequestReady,
    /// One exact final-request submission had an ambiguous repository outcome.
    FinalRequestOperation,
}

/// Result of exact renewal through a worker-owned phase lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutonomousWorkflowRenewalOutcome {
    /// The phase repository returned the exact next claim generation.
    Renewed,
    /// The current claim already covered the fixed deadline and was revalidated by exact consume.
    Revalidated,
    /// A typed repository-operation failure was reconciled by exact consume.
    Reconciled,
}

/// Failure available to a phase executor while using its bounded lease.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AutonomousWorkflowLeaseError {
    /// Local shutdown won before another operation could begin.
    #[error("autonomous workflow worker is shutting down")]
    Shutdown,
    /// The conservative cumulative monotonic deadline elapsed.
    #[error("autonomous workflow phase deadline elapsed")]
    DeadlineElapsed,
    /// Exact renewal could not be reconciled to current selected authority.
    #[error("autonomous workflow phase authority is unavailable")]
    Unavailable,
    /// Durable state rejected the selected lineage as inconsistent.
    #[error("autonomous workflow phase authority was rejected")]
    AuthorityRejected,
}

/// Sanitized worker failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AutonomousWorkflowError {
    /// Local shutdown won before another operation could begin.
    #[error("autonomous workflow worker is shutting down")]
    Shutdown,
    /// The admission clock returned an invalid caller observation.
    #[error("autonomous workflow caller time is invalid")]
    InvalidTimestamp,
    /// A supposedly live consumed claim could not establish a safe deadline.
    #[error("autonomous workflow authority interval is invalid")]
    InvalidAuthorityInterval,
    /// A closed executor failure could not quarantine the exact latest fence.
    #[error("autonomous workflow quarantine fence was rejected")]
    QuarantineFenceRejected,
    /// Durable state rejected an internally selected lineage as inconsistent.
    #[error("autonomous workflow selected authority was rejected")]
    AuthorityRejected,
}

/// Shared conservative deadline for one selected phase.
///
/// Renewal and reconciliation may only tighten this value. They never reset or
/// extend the phase's original cumulative budget.
#[derive(Clone)]
pub struct AutonomousWorkflowDeadline {
    deadline: watch::Sender<Instant>,
}

impl fmt::Debug for AutonomousWorkflowDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AutonomousWorkflowDeadline")
    }
}

impl AutonomousWorkflowDeadline {
    fn new(
        operation_started: Instant,
        validated_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, AutonomousWorkflowError> {
        let deadline = authority_deadline(operation_started, validated_at, expires_at)?;
        let (deadline, _) = watch::channel(deadline);
        Ok(Self { deadline })
    }

    /// Returns the current absolute monotonic deadline.
    #[must_use]
    pub fn instant(&self) -> Instant {
        *self.deadline.borrow()
    }

    /// Returns the remaining conservative local budget.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.instant().saturating_duration_since(Instant::now())
    }

    /// Fails if cancellation or the cumulative deadline already won.
    ///
    /// # Errors
    ///
    /// Returns the winning shutdown or deadline classification.
    pub fn checkpoint(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        if shutdown.is_cancelled() {
            Err(AutonomousWorkflowLeaseError::Shutdown)
        } else if Instant::now() >= self.instant() {
            Err(AutonomousWorkflowLeaseError::DeadlineElapsed)
        } else {
            Ok(())
        }
    }

    fn tighten(
        &self,
        operation_started: Instant,
        validated_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let candidate = authority_deadline(operation_started, validated_at, expires_at)
            .map_err(|_| AutonomousWorkflowLeaseError::DeadlineElapsed)?;
        self.deadline.send_if_modified(|current| {
            if candidate < *current {
                *current = candidate;
                true
            } else {
                false
            }
        });
        if Instant::now() >= self.instant() {
            Err(AutonomousWorkflowLeaseError::DeadlineElapsed)
        } else {
            Ok(())
        }
    }

    async fn elapsed(&self) {
        let mut receiver = self.deadline.subscribe();
        loop {
            let deadline = *receiver.borrow_and_update();
            tokio::select! {
                () = sleep_until(deadline) => return,
                notification = receiver.changed() => {
                    if notification.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Boxed operation returned by an autonomous phase executor.
pub type AutonomousWorkflowExecutionFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
            > + Send
            + 'a,
    >,
>;

/// Actual preparation, activation, and materialization operations.
///
/// Calling an executor method must be side-effect free; I/O begins only when
/// the returned future is polled. This lets the worker establish cancellation
/// and deadline races before any executor work can start.
///
/// Implementations must call the lease's `before_io` method immediately before
/// every blob/provider operation and durable mutation. Long operations call
/// `renew` between bounded I/O units. They must branch on durable profile and
/// policy evidence exposed by `authority`, never repository visibility.
pub trait AutonomousWorkflowPhaseExecutor: fmt::Debug + Send + Sync {
    /// Executes one already-consumed preparation phase.
    fn execute_preparation<'a>(
        &'a self,
        lease: &'a mut AutonomousPreparationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a>;

    /// Executes one already-consumed activation phase.
    fn execute_activation<'a>(
        &'a self,
        lease: &'a mut AutonomousActivationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a>;

    /// Executes one already-consumed materialization phase.
    fn execute_materialization<'a>(
        &'a self,
        lease: &'a mut AutonomousMaterializationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a>;

    /// Submits one worker-retained preparation binding exactly once.
    ///
    /// The request is obtained from the read-only lease's exact pending
    /// custody. Implementations must not perform blob I/O, renew authority,
    /// select work, consult a clock, or enforce the expired phase deadline.
    /// Only a typed repository-operation ambiguity returns
    /// [`AutonomousWorkflowExecutionOutcome::FinalRequestOperation`].
    fn submit_preparation_final<'a>(
        &'a self,
        _lease: &'a AutonomousPreparationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async { Err(AutonomousWorkflowLeaseError::AuthorityRejected) })
    }

    /// Submits one worker-retained activation publication exactly once.
    ///
    /// This has the same one-attempt, Store-only contract as
    /// [`Self::submit_preparation_final`].
    fn submit_activation_final<'a>(
        &'a self,
        _lease: &'a AutonomousActivationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async { Err(AutonomousWorkflowLeaseError::AuthorityRejected) })
    }

    /// Submits one worker-retained materialization commit exactly once.
    ///
    /// This has the same one-attempt, Store-only contract as
    /// [`Self::submit_preparation_final`].
    fn submit_materialization_final<'a>(
        &'a self,
        _lease: &'a AutonomousMaterializationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async { Err(AutonomousWorkflowLeaseError::AuthorityRejected) })
    }
}

#[derive(Clone, Default)]
enum OrchestrationCustody {
    #[default]
    Idle,
    Select {
        request: Box<ClaimNextLogicalJobOrchestration>,
        submitted: bool,
    },
    Selected {
        request: Box<ConsumeSelectedLogicalJobOrchestration>,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    },
    PendingConsume {
        request: Box<ConsumeSelectedLogicalJobOrchestration>,
        operation_started: Option<Instant>,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        submitted: bool,
    },
    Active {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
    },
    ReadyPreparationFinal {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<ReadyLogicalActivationPreparation>,
    },
    PendingPreparationFinal {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<ReadyLogicalActivationPreparation>,
    },
    ReadyActivationFinal {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<ReadyLogicalJobActivation>,
    },
    PendingActivationFinal {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<ReadyLogicalJobActivation>,
    },
    PendingPreparationRenew {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<RenewLogicalActivationPreparation>,
        submitted: bool,
    },
    PendingActivationRenew {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<RenewLogicalJobActivation>,
        submitted: bool,
    },
    SettledFinalEvidence {
        consumed: Box<ConsumedSelectedLogicalJobOrchestration>,
        kind: LogicalWorkQuarantineKind,
    },
    Quarantine {
        request: Box<QuarantineLogicalJobOrchestration>,
        submitted: bool,
    },
}

impl fmt::Debug for OrchestrationCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Idle => "Idle",
            Self::Select { submitted, .. } => {
                if *submitted {
                    "PendingSelect([REDACTED])"
                } else {
                    "ReadySelect([REDACTED])"
                }
            }
            Self::Selected { .. } => "Selected([REDACTED])",
            Self::PendingConsume { submitted, .. } => {
                if *submitted {
                    "PendingConsume([REDACTED])"
                } else {
                    "ReadyConsume([REDACTED])"
                }
            }
            Self::Active { .. } => "Active([REDACTED])",
            Self::ReadyPreparationFinal { .. } => "ReadyPreparationFinal([REDACTED])",
            Self::PendingPreparationFinal { .. } => "PendingPreparationFinal([REDACTED])",
            Self::ReadyActivationFinal { .. } => "ReadyActivationFinal([REDACTED])",
            Self::PendingActivationFinal { .. } => "PendingActivationFinal([REDACTED])",
            Self::PendingPreparationRenew { submitted, .. }
            | Self::PendingActivationRenew { submitted, .. } => {
                if *submitted {
                    "PendingRenew([REDACTED])"
                } else {
                    "ReadyRenew([REDACTED])"
                }
            }
            Self::SettledFinalEvidence { .. } => "SettledFinalEvidence([REDACTED])",
            Self::Quarantine { submitted, .. } => {
                if *submitted {
                    "PendingQuarantine([REDACTED])"
                } else {
                    "ReadyQuarantine([REDACTED])"
                }
            }
        })
    }
}

#[derive(Clone, Default)]
enum MaterializationCustody {
    #[default]
    Idle,
    Select {
        request: Box<ClaimNextLogicalInstanceMaterialization>,
        submitted: bool,
    },
    Selected {
        request: Box<ConsumeSelectedLogicalInstanceMaterialization>,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    },
    PendingConsume {
        request: Box<ConsumeSelectedLogicalInstanceMaterialization>,
        operation_started: Option<Instant>,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        submitted: bool,
    },
    Active {
        consumed: Box<ConsumedSelectedLogicalInstanceMaterialization>,
        deadline: AutonomousWorkflowDeadline,
    },
    ReadyFinal {
        consumed: Box<ConsumedSelectedLogicalInstanceMaterialization>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<ReadyLogicalInstanceMaterialization>,
    },
    PendingFinal {
        consumed: Box<ConsumedSelectedLogicalInstanceMaterialization>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<ReadyLogicalInstanceMaterialization>,
    },
    PendingRenew {
        consumed: Box<ConsumedSelectedLogicalInstanceMaterialization>,
        deadline: AutonomousWorkflowDeadline,
        request: Box<RenewLogicalInstanceMaterialization>,
        submitted: bool,
    },
    SettledFinalEvidence {
        consumed: Box<ConsumedSelectedLogicalInstanceMaterialization>,
        kind: LogicalWorkQuarantineKind,
    },
    Quarantine {
        request: Box<QuarantineLogicalInstanceMaterialization>,
        submitted: bool,
    },
}

impl fmt::Debug for MaterializationCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Idle => "Idle",
            Self::Select { submitted, .. } => {
                if *submitted {
                    "PendingSelect([REDACTED])"
                } else {
                    "ReadySelect([REDACTED])"
                }
            }
            Self::Selected { .. } => "Selected([REDACTED])",
            Self::PendingConsume { submitted, .. } => {
                if *submitted {
                    "PendingConsume([REDACTED])"
                } else {
                    "ReadyConsume([REDACTED])"
                }
            }
            Self::Active { .. } => "Active([REDACTED])",
            Self::ReadyFinal { .. } => "ReadyFinal([REDACTED])",
            Self::PendingFinal { .. } => "PendingFinal([REDACTED])",
            Self::PendingRenew { submitted, .. } => {
                if *submitted {
                    "PendingRenew([REDACTED])"
                } else {
                    "ReadyRenew([REDACTED])"
                }
            }
            Self::SettledFinalEvidence { .. } => "SettledFinalEvidence([REDACTED])",
            Self::Quarantine { submitted, .. } => {
                if *submitted {
                    "PendingQuarantine([REDACTED])"
                } else {
                    "ReadyQuarantine([REDACTED])"
                }
            }
        })
    }
}

#[derive(Default)]
struct AutonomousWorkflowCustody {
    orchestration: StdMutex<OrchestrationCustody>,
    materialization: StdMutex<MaterializationCustody>,
}

impl fmt::Debug for AutonomousWorkflowCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let orchestration = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        let materialization = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        formatter
            .debug_struct("AutonomousWorkflowCustody")
            .field("orchestration", &*orchestration)
            .field("materialization", &*materialization)
            .finish()
    }
}

impl AutonomousWorkflowCustody {
    fn orchestration(&self) -> OrchestrationCustody {
        self.orchestration
            .lock()
            .expect("custody lock is not poisoned")
            .clone()
    }

    fn materialization(&self) -> MaterializationCustody {
        self.materialization
            .lock()
            .expect("custody lock is not poisoned")
            .clone()
    }

    fn set_orchestration(&self, state: OrchestrationCustody) {
        *self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned") = state;
    }

    fn set_materialization(&self, state: MaterializationCustody) {
        *self
            .materialization
            .lock()
            .expect("custody lock is not poisoned") = state;
    }

    fn orchestration_is_active(&self, expected: &ConsumedSelectedLogicalJobOrchestration) -> bool {
        matches!(
            self.orchestration(),
            OrchestrationCustody::Active { consumed, .. } if consumed.as_ref() == expected
        )
    }

    fn materialization_is_active(
        &self,
        expected: &ConsumedSelectedLogicalInstanceMaterialization,
    ) -> bool {
        matches!(
            self.materialization(),
            MaterializationCustody::Active { consumed, .. } if consumed.as_ref() == expected
        )
    }

    fn clear_orchestration_if_active(&self) {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if matches!(*state, OrchestrationCustody::Active { .. }) {
            *state = OrchestrationCustody::Idle;
        }
    }

    fn clear_materialization_if_active(&self) {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if matches!(*state, MaterializationCustody::Active { .. }) {
            *state = MaterializationCustody::Idle;
        }
    }

    fn begin_orchestration_selection(
        &self,
        request: ClaimNextLogicalJobOrchestration,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(*state, OrchestrationCustody::Idle) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::Select {
            request: Box::new(request),
            submitted: false,
        };
        Ok(())
    }

    fn begin_materialization_selection(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(*state, MaterializationCustody::Idle) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = MaterializationCustody::Select {
            request: Box::new(request),
            submitted: false,
        };
        Ok(())
    }

    fn mark_orchestration_selection_submitted(
        &self,
        expected: &ClaimNextLogicalJobOrchestration,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            OrchestrationCustody::Select { request, submitted }
                if request.as_ref() == expected && !*submitted =>
            {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn mark_materialization_selection_submitted(
        &self,
        expected: &ClaimNextLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            MaterializationCustody::Select { request, submitted }
                if request.as_ref() == expected && !*submitted =>
            {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn retain_ready_orchestration_consume(
        &self,
        request: ConsumeSelectedLogicalJobOrchestration,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::Selected { request: selected, .. }
                if selected.as_ref() == &request
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::PendingConsume {
            request: Box::new(request),
            operation_started: None,
            deadline,
            expected_successor,
            submitted: false,
        };
        Ok(())
    }

    fn retain_ready_materialization_consume(
        &self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            MaterializationCustody::Selected { request: selected, .. }
                if selected.as_ref() == &request
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = MaterializationCustody::PendingConsume {
            request: Box::new(request),
            operation_started: None,
            deadline,
            expected_successor,
            submitted: false,
        };
        Ok(())
    }

    fn begin_orchestration_revalidation(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::Active { consumed: active, .. }
                if active.as_ref() == consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::Selected {
            request: Box::new(request),
            deadline: Some(deadline),
            expected_successor: None,
        };
        Ok(())
    }

    fn begin_materialization_revalidation(
        &self,
        consumed: &ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            MaterializationCustody::Active { consumed: active, .. }
                if active.as_ref() == consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = MaterializationCustody::Selected {
            request: Box::new(request),
            deadline: Some(deadline),
            expected_successor: None,
        };
        Ok(())
    }

    fn mark_orchestration_consume_submitted(
        &self,
        expected: &ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<Instant, AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            OrchestrationCustody::PendingConsume {
                request,
                operation_started,
                submitted,
                ..
            } if request.as_ref() == expected && !*submitted => {
                let started = Instant::now();
                *operation_started = Some(started);
                *submitted = true;
                Ok(started)
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn mark_materialization_consume_submitted(
        &self,
        expected: &ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<Instant, AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            MaterializationCustody::PendingConsume {
                request,
                operation_started,
                submitted,
                ..
            } if request.as_ref() == expected && !*submitted => {
                let started = Instant::now();
                *operation_started = Some(started);
                *submitted = true;
                Ok(started)
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn begin_preparation_renewal(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: RenewLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::Active { consumed: active, .. } if active.as_ref() == &consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::PendingPreparationRenew {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
            submitted: false,
        };
        Ok(())
    }

    fn begin_activation_renewal(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: RenewLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::Active { consumed: active, .. } if active.as_ref() == &consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::PendingActivationRenew {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
            submitted: false,
        };
        Ok(())
    }

    fn begin_materialization_renewal(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: RenewLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            MaterializationCustody::Active { consumed: active, .. } if active.as_ref() == &consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = MaterializationCustody::PendingRenew {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
            submitted: false,
        };
        Ok(())
    }

    fn mark_preparation_renewal_submitted(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
        expected: &RenewLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            OrchestrationCustody::PendingPreparationRenew {
                consumed: active,
                request,
                submitted,
                ..
            } if active.as_ref() == consumed && request.as_ref() == expected && !*submitted => {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn mark_activation_renewal_submitted(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
        expected: &RenewLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            OrchestrationCustody::PendingActivationRenew {
                consumed: active,
                request,
                submitted,
                ..
            } if active.as_ref() == consumed && request.as_ref() == expected && !*submitted => {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn mark_materialization_renewal_submitted(
        &self,
        consumed: &ConsumedSelectedLogicalInstanceMaterialization,
        expected: &RenewLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            MaterializationCustody::PendingRenew {
                consumed: active,
                request,
                submitted,
                ..
            } if active.as_ref() == consumed && request.as_ref() == expected && !*submitted => {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn clear_expired_unsubmitted_preparation_renewal(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
        expected: &RenewLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &*state {
            OrchestrationCustody::PendingPreparationRenew {
                consumed: active,
                request,
                submitted,
                ..
            } if active.as_ref() == consumed && request.as_ref() == expected => {
                if !submitted {
                    *state = OrchestrationCustody::Idle;
                }
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn clear_expired_unsubmitted_activation_renewal(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
        expected: &RenewLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &*state {
            OrchestrationCustody::PendingActivationRenew {
                consumed: active,
                request,
                submitted,
                ..
            } if active.as_ref() == consumed && request.as_ref() == expected => {
                if !submitted {
                    *state = OrchestrationCustody::Idle;
                }
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn clear_expired_unsubmitted_materialization_renewal(
        &self,
        consumed: &ConsumedSelectedLogicalInstanceMaterialization,
        expected: &RenewLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        match &*state {
            MaterializationCustody::PendingRenew {
                consumed: active,
                request,
                submitted,
                ..
            } if active.as_ref() == consumed && request.as_ref() == expected => {
                if !submitted {
                    *state = MaterializationCustody::Idle;
                }
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn mark_orchestration_quarantine_submitted(
        &self,
        expected: &QuarantineLogicalJobOrchestration,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            OrchestrationCustody::Quarantine { request, submitted }
                if request.as_ref() == expected && !*submitted =>
            {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn mark_materialization_quarantine_submitted(
        &self,
        expected: &QuarantineLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        match &mut *state {
            MaterializationCustody::Quarantine { request, submitted }
                if request.as_ref() == expected && !*submitted =>
            {
                *submitted = true;
                Ok(())
            }
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn retain_ready_preparation_final(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::Active { consumed: active, .. } if active.as_ref() == &consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::ReadyPreparationFinal {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
        };
        Ok(())
    }

    fn retain_ready_activation_final(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::Active { consumed: active, .. } if active.as_ref() == &consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::ReadyActivationFinal {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
        };
        Ok(())
    }

    fn retain_ready_materialization_final(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            MaterializationCustody::Active { consumed: active, .. } if active.as_ref() == &consumed
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = MaterializationCustody::ReadyFinal {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
        };
        Ok(())
    }

    fn ready_preparation_final(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
    ) -> Option<(
        AutonomousWorkflowDeadline,
        ReadyLogicalActivationPreparation,
    )> {
        match self.orchestration() {
            OrchestrationCustody::ReadyPreparationFinal {
                consumed: active,
                deadline,
                request,
            } if active.as_ref() == consumed => Some((deadline, *request)),
            _ => None,
        }
    }

    fn ready_activation_final(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
    ) -> Option<(AutonomousWorkflowDeadline, ReadyLogicalJobActivation)> {
        match self.orchestration() {
            OrchestrationCustody::ReadyActivationFinal {
                consumed: active,
                deadline,
                request,
            } if active.as_ref() == consumed => Some((deadline, *request)),
            _ => None,
        }
    }

    fn ready_materialization_final(
        &self,
        consumed: &ConsumedSelectedLogicalInstanceMaterialization,
    ) -> Option<(
        AutonomousWorkflowDeadline,
        ReadyLogicalInstanceMaterialization,
    )> {
        match self.materialization() {
            MaterializationCustody::ReadyFinal {
                consumed: active,
                deadline,
                request,
            } if active.as_ref() == consumed => Some((deadline, *request)),
            _ => None,
        }
    }

    fn begin_preparation_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::ReadyPreparationFinal {
                consumed: active,
                request: ready,
                ..
            } if active.as_ref() == &consumed && ready.as_ref() == &request
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::PendingPreparationFinal {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
        };
        Ok(())
    }

    fn begin_activation_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .orchestration
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            OrchestrationCustody::ReadyActivationFinal {
                consumed: active,
                request: ready,
                ..
            } if active.as_ref() == &consumed && ready.as_ref() == &request
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = OrchestrationCustody::PendingActivationFinal {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
        };
        Ok(())
    }

    fn begin_materialization_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let mut state = self
            .materialization
            .lock()
            .expect("custody lock is not poisoned");
        if !matches!(
            &*state,
            MaterializationCustody::ReadyFinal {
                consumed: active,
                request: ready,
                ..
            } if active.as_ref() == &consumed && ready.as_ref() == &request
        ) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        *state = MaterializationCustody::PendingFinal {
            consumed: Box::new(consumed),
            deadline,
            request: Box::new(request),
        };
        Ok(())
    }

    fn pending_preparation_final(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
    ) -> Result<ReadyLogicalActivationPreparation, AutonomousWorkflowLeaseError> {
        match self.orchestration() {
            OrchestrationCustody::PendingPreparationFinal {
                consumed: active,
                request,
                ..
            } if active.as_ref() == consumed => Ok(*request),
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn pending_activation_final(
        &self,
        consumed: &ConsumedSelectedLogicalJobOrchestration,
    ) -> Result<ReadyLogicalJobActivation, AutonomousWorkflowLeaseError> {
        match self.orchestration() {
            OrchestrationCustody::PendingActivationFinal {
                consumed: active,
                request,
                ..
            } if active.as_ref() == consumed => Ok(*request),
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn pending_materialization_final(
        &self,
        consumed: &ConsumedSelectedLogicalInstanceMaterialization,
    ) -> Result<ReadyLogicalInstanceMaterialization, AutonomousWorkflowLeaseError> {
        match self.materialization() {
            MaterializationCustody::PendingFinal {
                consumed: active,
                request,
                ..
            } if active.as_ref() == consumed => Ok(*request),
            _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
        }
    }

    fn has_pending_queue(&self, queue: AutonomousWorkflowQueue) -> bool {
        match queue {
            AutonomousWorkflowQueue::Orchestration => matches!(
                self.orchestration(),
                OrchestrationCustody::Select {
                    submitted: true,
                    ..
                } | OrchestrationCustody::PendingConsume {
                    submitted: true,
                    ..
                } | OrchestrationCustody::PendingPreparationFinal { .. }
                    | OrchestrationCustody::PendingActivationFinal { .. }
                    | OrchestrationCustody::PendingPreparationRenew {
                        submitted: true,
                        ..
                    }
                    | OrchestrationCustody::PendingActivationRenew {
                        submitted: true,
                        ..
                    }
                    | OrchestrationCustody::Quarantine {
                        submitted: true,
                        ..
                    }
            ),
            AutonomousWorkflowQueue::Materialization => matches!(
                self.materialization(),
                MaterializationCustody::Select {
                    submitted: true,
                    ..
                } | MaterializationCustody::PendingConsume {
                    submitted: true,
                    ..
                } | MaterializationCustody::PendingFinal { .. }
                    | MaterializationCustody::PendingRenew {
                        submitted: true,
                        ..
                    }
                    | MaterializationCustody::Quarantine {
                        submitted: true,
                        ..
                    }
            ),
        }
    }

    fn has_pending(&self) -> bool {
        self.has_pending_queue(AutonomousWorkflowQueue::Orchestration)
            || self.has_pending_queue(AutonomousWorkflowQueue::Materialization)
    }
}

/// Worker-owned capability for one consumed preparation claim.
pub struct AutonomousPreparationLease {
    selections: Arc<dyn LogicalWorkSelectionRepository>,
    preparations: Arc<dyn LogicalActivationPreparationStore>,
    consumed: ConsumedSelectedLogicalJobOrchestration,
    deadline: AutonomousWorkflowDeadline,
    custody: Arc<AutonomousWorkflowCustody>,
}

impl fmt::Debug for AutonomousPreparationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AutonomousPreparationLease")
    }
}

impl AutonomousPreparationLease {
    /// Returns the current exact rich preparation authority.
    #[must_use]
    pub fn authority(&self) -> &ClaimedLogicalActivationPreparation {
        let ConsumedLogicalJobOrchestrationAuthority::Preparation(authority) =
            self.consumed.authority()
        else {
            unreachable!("lease construction fixes the authority phase")
        };
        authority
    }

    pub(crate) fn retain_ready_final(
        &self,
        request: ReadyLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        if !request.matches_authority(self.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.custody.retain_ready_preparation_final(
            self.consumed.clone(),
            self.deadline.clone(),
            request,
        )
    }

    pub(crate) fn pending_final_request(
        &self,
    ) -> Result<ReadyLogicalActivationPreparation, AutonomousWorkflowLeaseError> {
        let request = self.custody.pending_preparation_final(&self.consumed)?;
        if request.matches_authority(self.authority()) {
            Ok(request)
        } else {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
    }

    /// Returns the cumulative monotonic phase deadline.
    #[must_use]
    pub const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        &self.deadline
    }

    /// Must be called immediately before each blob/provider I/O or mutation.
    ///
    /// # Errors
    ///
    /// Returns the winning shutdown or deadline classification.
    pub fn before_io(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        self.deadline.checkpoint(shutdown)
    }

    /// Renews exact preparation authority when it extends custody, otherwise revalidates it.
    ///
    /// # Errors
    ///
    /// Returns shutdown, deadline expiry, or a failure to recover the exact
    /// current selected authority.
    pub async fn renew(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        self.before_io(shutdown)?;
        let Some(duration_ms) = extending_renewal_duration(
            &self.deadline,
            MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS,
            self.authority().claim().claimed_at(),
            self.authority().claim().expires_at(),
        )?
        else {
            return self.revalidate(shutdown).await;
        };
        let request =
            RenewLogicalActivationPreparation::new(self.authority().claim().clone(), duration_ms)
                .map_err(|_| AutonomousWorkflowLeaseError::Unavailable)?;
        self.custody.begin_preparation_renewal(
            self.consumed.clone(),
            self.deadline.clone(),
            request.clone(),
        )?;
        let submission = async {
            self.custody
                .mark_preparation_renewal_submitted(&self.consumed, &request)?;
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.preparations
                    .renew_logical_activation_preparation(request.clone())
                    .await,
            )
        };
        let result = await_bounded(shutdown, &self.deadline, submission).await??;
        let (outcome, expected_successor) = match result {
            Ok(acknowledgement) if acknowledgement.request() == &request => (
                AutonomousWorkflowRenewalOutcome::Renewed,
                Some(ExpectedRenewalSuccessor::new(
                    AutonomousWorkflowPhase::Preparation,
                    acknowledgement.successor_generation().get(),
                    acknowledgement.successor_claimed_at(),
                    acknowledgement.successor_expires_at(),
                )),
            ),
            Err(LogicalActivationPreparationStoreError::Store(StoreError::Operation(_))) => {
                (AutonomousWorkflowRenewalOutcome::Reconciled, None)
            }
            Ok(_) | Err(_) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
            }
        };
        let reconcile =
            ConsumeSelectedLogicalJobOrchestration::new(self.consumed.selected().clone());
        self.custody
            .set_orchestration(OrchestrationCustody::Selected {
                request: Box::new(reconcile.clone()),
                deadline: Some(self.deadline.clone()),
                expected_successor,
            });
        self.reconcile(reconcile, expected_successor, shutdown)
            .await?;
        Ok(outcome)
    }

    async fn revalidate(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        let request = ConsumeSelectedLogicalJobOrchestration::new(self.consumed.selected().clone());
        self.custody.begin_orchestration_revalidation(
            &self.consumed,
            self.deadline.clone(),
            request.clone(),
        )?;
        self.reconcile(request, None, shutdown).await?;
        Ok(AutonomousWorkflowRenewalOutcome::Revalidated)
    }

    async fn reconcile(
        &mut self,
        request: ConsumeSelectedLogicalJobOrchestration,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let expected_selected = request.selected().clone();
        if let Err(error) = self.deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
            }
            return Err(error);
        }
        self.custody.retain_ready_orchestration_consume(
            request.clone(),
            Some(self.deadline.clone()),
            expected_successor,
        )?;
        let submission = async {
            let operation_started = self
                .custody
                .mark_orchestration_consume_submitted(&request)?;
            let result = self
                .selections
                .consume_selected_logical_job_orchestration(request)
                .await;
            Ok::<_, AutonomousWorkflowLeaseError>((operation_started, result))
        };
        let (operation_started, consumed) =
            await_bounded(shutdown, &self.deadline, submission).await??;
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) if is_repository_unavailable(&error) => {
                return Err(AutonomousWorkflowLeaseError::Unavailable);
            }
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Err(map_reconcile_error(&error));
            }
        };
        if consumed.selected() != &expected_selected {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        if !matches!(
            consumed.authority(),
            ConsumedLogicalJobOrchestrationAuthority::Preparation(_)
        ) || expected_successor
            .is_some_and(|expected| !expected.matches_orchestration(&consumed))
        {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.replace(consumed, operation_started)
    }

    fn replace(
        &mut self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        operation_started: Instant,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let (validated_at, expires_at) = orchestration_interval(&consumed);
        if let Err(error) = self
            .deadline
            .tighten(operation_started, validated_at, expires_at)
        {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(error);
        }
        self.consumed = consumed.clone();
        self.custody
            .set_orchestration(OrchestrationCustody::Active {
                consumed: Box::new(consumed),
                deadline: self.deadline.clone(),
            });
        Ok(())
    }
}

/// Worker-owned capability for one consumed activation claim.
pub struct AutonomousActivationLease {
    selections: Arc<dyn LogicalWorkSelectionRepository>,
    activations: Arc<dyn LogicalActivationRepository>,
    consumed: ConsumedSelectedLogicalJobOrchestration,
    deadline: AutonomousWorkflowDeadline,
    custody: Arc<AutonomousWorkflowCustody>,
}

impl fmt::Debug for AutonomousActivationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AutonomousActivationLease")
    }
}

impl AutonomousActivationLease {
    /// Returns the current exact rich activation authority.
    #[must_use]
    pub fn authority(&self) -> &ClaimedLogicalJobActivation {
        let ConsumedLogicalJobOrchestrationAuthority::Activation(authority) =
            self.consumed.authority()
        else {
            unreachable!("lease construction fixes the authority phase")
        };
        authority
    }

    pub(crate) fn retain_ready_final(
        &self,
        request: ReadyLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        if !request.matches_authority(self.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.custody.retain_ready_activation_final(
            self.consumed.clone(),
            self.deadline.clone(),
            request,
        )
    }

    pub(crate) fn pending_final_request(
        &self,
    ) -> Result<ReadyLogicalJobActivation, AutonomousWorkflowLeaseError> {
        let request = self.custody.pending_activation_final(&self.consumed)?;
        if request.matches_authority(self.authority()) {
            Ok(request)
        } else {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
    }

    /// Returns the cumulative monotonic phase deadline.
    #[must_use]
    pub const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        &self.deadline
    }

    /// Must be called immediately before each blob/provider I/O or mutation.
    ///
    /// # Errors
    ///
    /// Returns the winning shutdown or deadline classification.
    pub fn before_io(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        self.deadline.checkpoint(shutdown)
    }

    /// Renews exact activation authority when it extends custody, otherwise revalidates it.
    ///
    /// # Errors
    ///
    /// Returns shutdown, deadline expiry, or a failure to recover the exact
    /// current selected authority.
    pub async fn renew(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        self.before_io(shutdown)?;
        let Some(duration_ms) = extending_renewal_duration(
            &self.deadline,
            MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS,
            self.authority().claim().claimed_at(),
            self.authority().claim().expires_at(),
        )?
        else {
            return self.revalidate(shutdown).await;
        };
        let request = RenewLogicalJobActivation::new(self.authority().claim().clone(), duration_ms)
            .map_err(|_| AutonomousWorkflowLeaseError::Unavailable)?;
        self.custody.begin_activation_renewal(
            self.consumed.clone(),
            self.deadline.clone(),
            request.clone(),
        )?;
        let submission = async {
            self.custody
                .mark_activation_renewal_submitted(&self.consumed, &request)?;
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.activations
                    .renew_logical_job_activation(request.clone())
                    .await,
            )
        };
        let result = await_bounded(shutdown, &self.deadline, submission).await??;
        let (outcome, expected_successor) = match result {
            Ok(acknowledgement) if acknowledgement.request() == &request => (
                AutonomousWorkflowRenewalOutcome::Renewed,
                Some(ExpectedRenewalSuccessor::new(
                    AutonomousWorkflowPhase::Activation,
                    acknowledgement.successor_generation().get(),
                    acknowledgement.successor_claimed_at(),
                    acknowledgement.successor_expires_at(),
                )),
            ),
            Err(LogicalActivationStoreError::Store(StoreError::Operation(_))) => {
                (AutonomousWorkflowRenewalOutcome::Reconciled, None)
            }
            Ok(_) | Err(_) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
            }
        };
        let reconcile =
            ConsumeSelectedLogicalJobOrchestration::new(self.consumed.selected().clone());
        self.custody
            .set_orchestration(OrchestrationCustody::Selected {
                request: Box::new(reconcile.clone()),
                deadline: Some(self.deadline.clone()),
                expected_successor,
            });
        self.reconcile(reconcile, expected_successor, shutdown)
            .await?;
        Ok(outcome)
    }

    async fn revalidate(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        let request = ConsumeSelectedLogicalJobOrchestration::new(self.consumed.selected().clone());
        self.custody.begin_orchestration_revalidation(
            &self.consumed,
            self.deadline.clone(),
            request.clone(),
        )?;
        self.reconcile(request, None, shutdown).await?;
        Ok(AutonomousWorkflowRenewalOutcome::Revalidated)
    }

    async fn reconcile(
        &mut self,
        request: ConsumeSelectedLogicalJobOrchestration,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let expected_selected = request.selected().clone();
        if let Err(error) = self.deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
            }
            return Err(error);
        }
        self.custody.retain_ready_orchestration_consume(
            request.clone(),
            Some(self.deadline.clone()),
            expected_successor,
        )?;
        let submission = async {
            let operation_started = self
                .custody
                .mark_orchestration_consume_submitted(&request)?;
            let result = self
                .selections
                .consume_selected_logical_job_orchestration(request)
                .await;
            Ok::<_, AutonomousWorkflowLeaseError>((operation_started, result))
        };
        let (operation_started, consumed) =
            await_bounded(shutdown, &self.deadline, submission).await??;
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) if is_repository_unavailable(&error) => {
                return Err(AutonomousWorkflowLeaseError::Unavailable);
            }
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Err(map_reconcile_error(&error));
            }
        };
        if consumed.selected() != &expected_selected {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        if !matches!(
            consumed.authority(),
            ConsumedLogicalJobOrchestrationAuthority::Activation(_)
        ) || expected_successor
            .is_some_and(|expected| !expected.matches_orchestration(&consumed))
        {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.replace(consumed, operation_started)
    }

    fn replace(
        &mut self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        operation_started: Instant,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let (validated_at, expires_at) = orchestration_interval(&consumed);
        if let Err(error) = self
            .deadline
            .tighten(operation_started, validated_at, expires_at)
        {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(error);
        }
        self.consumed = consumed.clone();
        self.custody
            .set_orchestration(OrchestrationCustody::Active {
                consumed: Box::new(consumed),
                deadline: self.deadline.clone(),
            });
        Ok(())
    }
}

/// Worker-owned capability for one consumed materialization claim.
pub struct AutonomousMaterializationLease {
    selections: Arc<dyn LogicalWorkSelectionRepository>,
    materializations: Arc<dyn LogicalMaterializationRepository>,
    consumed: ConsumedSelectedLogicalInstanceMaterialization,
    deadline: AutonomousWorkflowDeadline,
    custody: Arc<AutonomousWorkflowCustody>,
}

impl fmt::Debug for AutonomousMaterializationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AutonomousMaterializationLease")
    }
}

impl AutonomousMaterializationLease {
    /// Returns the current exact rich materialization authority.
    #[must_use]
    pub const fn authority(&self) -> &ClaimedLogicalInstanceMaterialization {
        self.consumed.authority()
    }

    pub(crate) fn retain_ready_final(
        &self,
        request: ReadyLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        if !request.matches_authority(self.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.custody.retain_ready_materialization_final(
            self.consumed.clone(),
            self.deadline.clone(),
            request,
        )
    }

    pub(crate) fn pending_final_request(
        &self,
    ) -> Result<ReadyLogicalInstanceMaterialization, AutonomousWorkflowLeaseError> {
        let request = self.custody.pending_materialization_final(&self.consumed)?;
        if request.matches_authority(self.authority()) {
            Ok(request)
        } else {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
    }

    /// Returns the cumulative monotonic phase deadline.
    #[must_use]
    pub const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        &self.deadline
    }

    /// Must be called immediately before each blob/provider I/O or mutation.
    ///
    /// # Errors
    ///
    /// Returns the winning shutdown or deadline classification.
    pub fn before_io(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        self.deadline.checkpoint(shutdown)
    }

    /// Renews exact materialization authority when it extends custody, otherwise revalidates it.
    ///
    /// # Errors
    ///
    /// Returns shutdown, deadline expiry, or a failure to recover the exact
    /// current selected authority.
    pub async fn renew(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        self.before_io(shutdown)?;
        let Some(duration_ms) = extending_renewal_duration(
            &self.deadline,
            MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS,
            self.authority().claim().claimed_at(),
            self.authority().claim().expires_at(),
        )?
        else {
            return self.revalidate(shutdown).await;
        };
        let request =
            RenewLogicalInstanceMaterialization::new(self.authority().claim().clone(), duration_ms)
                .map_err(|_| AutonomousWorkflowLeaseError::Unavailable)?;
        self.custody.begin_materialization_renewal(
            self.consumed.clone(),
            self.deadline.clone(),
            request.clone(),
        )?;
        let submission = async {
            self.custody
                .mark_materialization_renewal_submitted(&self.consumed, &request)?;
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.materializations
                    .renew_logical_instance_materialization(request.clone())
                    .await,
            )
        };
        let result = await_bounded(shutdown, &self.deadline, submission).await??;
        let (outcome, expected_successor) = match result {
            Ok(acknowledgement) if acknowledgement.request() == &request => (
                AutonomousWorkflowRenewalOutcome::Renewed,
                Some(ExpectedRenewalSuccessor::new(
                    AutonomousWorkflowPhase::Materialization,
                    acknowledgement.successor_generation().get(),
                    acknowledgement.successor_claimed_at(),
                    acknowledgement.successor_expires_at(),
                )),
            ),
            Err(LogicalMaterializationStoreError::Store(StoreError::Operation(_))) => {
                (AutonomousWorkflowRenewalOutcome::Reconciled, None)
            }
            Ok(_) | Err(_) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
            }
        };
        let reconcile =
            ConsumeSelectedLogicalInstanceMaterialization::new(self.consumed.selected().clone());
        self.custody
            .set_materialization(MaterializationCustody::Selected {
                request: Box::new(reconcile.clone()),
                deadline: Some(self.deadline.clone()),
                expected_successor,
            });
        self.reconcile(reconcile, expected_successor, shutdown)
            .await?;
        Ok(outcome)
    }

    async fn revalidate(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        let request =
            ConsumeSelectedLogicalInstanceMaterialization::new(self.consumed.selected().clone());
        self.custody.begin_materialization_revalidation(
            &self.consumed,
            self.deadline.clone(),
            request.clone(),
        )?;
        self.reconcile(request, None, shutdown).await?;
        Ok(AutonomousWorkflowRenewalOutcome::Revalidated)
    }

    async fn reconcile(
        &mut self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let expected_selected = request.selected().clone();
        if let Err(error) = self.deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
            }
            return Err(error);
        }
        self.custody.retain_ready_materialization_consume(
            request.clone(),
            Some(self.deadline.clone()),
            expected_successor,
        )?;
        let submission = async {
            let operation_started = self
                .custody
                .mark_materialization_consume_submitted(&request)?;
            let result = self
                .selections
                .consume_selected_logical_instance_materialization(request)
                .await;
            Ok::<_, AutonomousWorkflowLeaseError>((operation_started, result))
        };
        let (operation_started, consumed) =
            await_bounded(shutdown, &self.deadline, submission).await??;
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) if is_repository_unavailable(&error) => {
                return Err(AutonomousWorkflowLeaseError::Unavailable);
            }
            Err(error) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return Err(map_reconcile_error(&error));
            }
        };
        if consumed.selected() != &expected_selected
            || expected_successor
                .is_some_and(|expected| !expected.matches_materialization(&consumed))
        {
            self.custody
                .set_materialization(MaterializationCustody::Idle);
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.replace(consumed, operation_started)
    }

    fn replace(
        &mut self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        operation_started: Instant,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let validated_at = consumed.validated_at();
        let expires_at = consumed.authority().claim().expires_at();
        if let Err(error) = self
            .deadline
            .tighten(operation_started, validated_at, expires_at)
        {
            self.custody
                .set_materialization(MaterializationCustody::Idle);
            return Err(error);
        }
        self.consumed = consumed.clone();
        self.custody
            .set_materialization(MaterializationCustody::Active {
                consumed: Box::new(consumed),
                deadline: self.deadline.clone(),
            });
        Ok(())
    }
}

/// Cancellation-aware autonomous worker for all pre-execution phases.
pub struct AutonomousWorkflowService {
    selections: Arc<dyn LogicalWorkSelectionRepository>,
    preparations: Arc<dyn LogicalActivationPreparationStore>,
    activations: Arc<dyn LogicalActivationRepository>,
    materializations: Arc<dyn LogicalMaterializationRepository>,
    executor: Arc<dyn AutonomousWorkflowPhaseExecutor>,
    clock: Arc<dyn AdmissionClock>,
    orchestration_worker: LogicalActivationWorkerId,
    materialization_worker: LogicalMaterializationWorkerId,
    prefer_materialization: AtomicBool,
    run_gate: Mutex<()>,
    custody: Arc<AutonomousWorkflowCustody>,
}

impl fmt::Debug for AutonomousWorkflowService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AutonomousWorkflowService")
    }
}

impl AutonomousWorkflowService {
    /// Composes one worker over exact selection, phase, and executor ports.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        selections: Arc<dyn LogicalWorkSelectionRepository>,
        preparations: Arc<dyn LogicalActivationPreparationStore>,
        activations: Arc<dyn LogicalActivationRepository>,
        materializations: Arc<dyn LogicalMaterializationRepository>,
        executor: Arc<dyn AutonomousWorkflowPhaseExecutor>,
        clock: Arc<dyn AdmissionClock>,
        orchestration_worker: LogicalActivationWorkerId,
        materialization_worker: LogicalMaterializationWorkerId,
    ) -> Self {
        Self {
            selections,
            preparations,
            activations,
            materializations,
            executor,
            clock,
            orchestration_worker,
            materialization_worker,
            prefer_materialization: AtomicBool::new(false),
            run_gate: Mutex::new(()),
            custody: Arc::new(AutonomousWorkflowCustody::default()),
        }
    }

    /// Selects, consumes, and executes at most one exact phase.
    ///
    /// The first queue alternates on every call. An idle first queue permits
    /// one probe of the other queue; any other classification returns without
    /// selecting more work.
    ///
    /// # Errors
    ///
    /// Returns a sanitized cancellation, clock, authority-interval, or exact
    /// quarantine-fence failure.
    pub async fn run_once(
        &self,
        shutdown: CancellationToken,
    ) -> Result<AutonomousWorkflowOutcome, AutonomousWorkflowError> {
        let _run = self.run_gate.lock().await;
        let result = Box::pin(self.run_once_serial(&shutdown)).await;
        if matches!(result, Err(AutonomousWorkflowError::Shutdown)) {
            Box::pin(self.drain_pending_custody()).await;
        }
        result
    }

    async fn run_once_serial(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowOutcome, AutonomousWorkflowError> {
        if shutdown.is_cancelled() {
            return Err(AutonomousWorkflowError::Shutdown);
        }
        if let Some(poll) = Box::pin(self.resume_custody(shutdown, false, None)).await? {
            return Ok(outcome_from_poll(&poll));
        }
        let materialization_first = self
            .prefer_materialization
            .fetch_xor(true, Ordering::Relaxed);
        let first = if materialization_first {
            AutonomousWorkflowQueue::Materialization
        } else {
            AutonomousWorkflowQueue::Orchestration
        };
        let second = if materialization_first {
            AutonomousWorkflowQueue::Orchestration
        } else {
            AutonomousWorkflowQueue::Materialization
        };
        match Box::pin(self.try_queue(first, shutdown)).await? {
            QueuePoll::Outcome(outcome) => Ok(outcome),
            QueuePoll::Idle => match Box::pin(self.try_queue(second, shutdown)).await? {
                QueuePoll::Outcome(outcome) => Ok(outcome),
                QueuePoll::Idle => Ok(AutonomousWorkflowOutcome::Idle),
            },
        }
    }

    /// Continuously polls without busy-spinning on idle, contention, or outage.
    ///
    /// # Errors
    ///
    /// Returns the first non-shutdown worker failure. Cancellation completes
    /// normally and prevents another selection from starting.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), AutonomousWorkflowError> {
        loop {
            if shutdown.is_cancelled() {
                let _run = self.run_gate.lock().await;
                Box::pin(self.drain_pending_custody()).await;
                return Ok(());
            }
            let outcome = match Box::pin(self.run_once(shutdown.child_token())).await {
                Err(AutonomousWorkflowError::Shutdown) if shutdown.is_cancelled() => return Ok(()),
                other => other?,
            };
            match outcome {
                AutonomousWorkflowOutcome::Completed(_)
                | AutonomousWorkflowOutcome::Quarantined(_) => tokio::task::yield_now().await,
                AutonomousWorkflowOutcome::Idle
                | AutonomousWorkflowOutcome::Contended(_)
                | AutonomousWorkflowOutcome::Unavailable(_) => {
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => {
                            let _run = self.run_gate.lock().await;
                            Box::pin(self.drain_pending_custody()).await;
                            return Ok(());
                        },
                        () = sleep(Duration::from_millis(IDLE_POLL_MILLIS)) => {}
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Each redacted custody state has one explicit recovery edge.
    async fn resume_custody(
        &self,
        shutdown: &CancellationToken,
        drain_only: bool,
        queue: Option<AutonomousWorkflowQueue>,
    ) -> Result<Option<QueuePoll>, AutonomousWorkflowError> {
        let orchestration = if queue == Some(AutonomousWorkflowQueue::Materialization) {
            None
        } else {
            match self.custody.orchestration() {
                OrchestrationCustody::Idle => None,
                OrchestrationCustody::Select { request, submitted } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.submit_orchestration_selection(
                                *request,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::Selected {
                    request,
                    deadline,
                    expected_successor,
                } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(self.start_orchestration_consume(
                                *request,
                                deadline,
                                expected_successor,
                                shutdown,
                                true,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::PendingConsume {
                    request,
                    operation_started,
                    deadline,
                    expected_successor,
                    submitted,
                } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.resolve_orchestration_consume(
                                *request,
                                operation_started,
                                deadline,
                                expected_successor,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::Active { consumed, deadline } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(
                                self.execute_orchestration_active(*consumed, deadline, shutdown),
                            )
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::ReadyPreparationFinal {
                    consumed,
                    deadline,
                    request,
                } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(self.start_preparation_final_submission(
                                *consumed, deadline, *request, shutdown,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::PendingPreparationFinal {
                    consumed,
                    deadline,
                    request,
                } => Some(
                    Box::pin(self.resolve_preparation_final_submission(
                        *consumed,
                        deadline,
                        *request,
                        shutdown,
                        false,
                        !drain_only,
                    ))
                    .await?,
                ),
                OrchestrationCustody::ReadyActivationFinal {
                    consumed,
                    deadline,
                    request,
                } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(self.start_activation_final_submission(
                                *consumed, deadline, *request, shutdown,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::PendingActivationFinal {
                    consumed,
                    deadline,
                    request,
                } => Some(
                    Box::pin(self.resolve_activation_final_submission(
                        *consumed,
                        deadline,
                        *request,
                        shutdown,
                        false,
                        !drain_only,
                    ))
                    .await?,
                ),
                OrchestrationCustody::PendingPreparationRenew {
                    consumed,
                    deadline,
                    request,
                    submitted,
                } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.resume_preparation_renewal(
                                *consumed,
                                deadline,
                                *request,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::PendingActivationRenew {
                    consumed,
                    deadline,
                    request,
                    submitted,
                } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.resume_activation_renewal(
                                *consumed,
                                deadline,
                                *request,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::SettledFinalEvidence { consumed, kind } => {
                    if drain_only {
                        None
                    } else {
                        let request = QuarantineLogicalJobOrchestration::new(*consumed, kind);
                        self.custody
                            .set_orchestration(OrchestrationCustody::Quarantine {
                                request: Box::new(request.clone()),
                                submitted: false,
                            });
                        Some(
                            Box::pin(
                                self.submit_orchestration_quarantine(request, shutdown, false),
                            )
                            .await?,
                        )
                    }
                }
                OrchestrationCustody::Quarantine { request, submitted } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(
                                self.submit_orchestration_quarantine(*request, shutdown, submitted),
                            )
                            .await?,
                        )
                    }
                }
            }
        };
        if orchestration.is_some() {
            return Ok(orchestration);
        }

        let materialization = if queue == Some(AutonomousWorkflowQueue::Orchestration) {
            None
        } else {
            match self.custody.materialization() {
                MaterializationCustody::Idle => None,
                MaterializationCustody::Select { request, submitted } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.submit_materialization_selection(
                                *request,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                MaterializationCustody::Selected {
                    request,
                    deadline,
                    expected_successor,
                } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(self.start_materialization_consume(
                                *request,
                                deadline,
                                expected_successor,
                                shutdown,
                                true,
                            ))
                            .await?,
                        )
                    }
                }
                MaterializationCustody::PendingConsume {
                    request,
                    operation_started,
                    deadline,
                    expected_successor,
                    submitted,
                } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.resolve_materialization_consume(
                                *request,
                                operation_started,
                                deadline,
                                expected_successor,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                MaterializationCustody::Active { consumed, deadline } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(
                                self.execute_materialization_active(*consumed, deadline, shutdown),
                            )
                            .await?,
                        )
                    }
                }
                MaterializationCustody::ReadyFinal {
                    consumed,
                    deadline,
                    request,
                } => {
                    if drain_only {
                        None
                    } else {
                        Some(
                            Box::pin(self.start_materialization_final_submission(
                                *consumed, deadline, *request, shutdown,
                            ))
                            .await?,
                        )
                    }
                }
                MaterializationCustody::PendingFinal {
                    consumed,
                    deadline,
                    request,
                } => Some(
                    Box::pin(self.resolve_materialization_final_submission(
                        *consumed,
                        deadline,
                        *request,
                        shutdown,
                        false,
                        !drain_only,
                    ))
                    .await?,
                ),
                MaterializationCustody::PendingRenew {
                    consumed,
                    deadline,
                    request,
                    submitted,
                } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(self.resume_materialization_renewal(
                                *consumed,
                                deadline,
                                *request,
                                shutdown,
                                !drain_only,
                                submitted,
                            ))
                            .await?,
                        )
                    }
                }
                MaterializationCustody::SettledFinalEvidence { consumed, kind } => {
                    if drain_only {
                        None
                    } else {
                        let request =
                            QuarantineLogicalInstanceMaterialization::new(*consumed, kind);
                        self.custody
                            .set_materialization(MaterializationCustody::Quarantine {
                                request: Box::new(request.clone()),
                                submitted: false,
                            });
                        Some(
                            Box::pin(
                                self.submit_materialization_quarantine(request, shutdown, false),
                            )
                            .await?,
                        )
                    }
                }
                MaterializationCustody::Quarantine { request, submitted } => {
                    if drain_only && !submitted {
                        None
                    } else {
                        Some(
                            Box::pin(
                                self.submit_materialization_quarantine(
                                    *request, shutdown, submitted,
                                ),
                            )
                            .await?,
                        )
                    }
                }
            }
        };
        Ok(materialization)
    }

    async fn resume_preparation_renewal(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: RenewLogicalActivationPreparation,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_preparation_renewal_submitted(&consumed, &request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.preparations
                    .renew_logical_activation_preparation(request.clone())
                    .await,
            )
        };
        let result =
            match await_renewal_submission(submitted, shutdown, &deadline, submission).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
                Err(error) => {
                    if !submitted
                        && error == AutonomousWorkflowLeaseError::DeadlineElapsed
                        && self
                            .custody
                            .clear_expired_unsubmitted_preparation_renewal(&consumed, &request)
                            .is_err()
                    {
                        return Err(AutonomousWorkflowError::AuthorityRejected);
                    }
                    return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
                }
            };
        let expected_successor = match result {
            Ok(acknowledgement) if acknowledgement.request() == &request => {
                Some(ExpectedRenewalSuccessor::new(
                    AutonomousWorkflowPhase::Preparation,
                    acknowledgement.successor_generation().get(),
                    acknowledgement.successor_claimed_at(),
                    acknowledgement.successor_expires_at(),
                ))
            }
            Err(LogicalActivationPreparationStoreError::Store(StoreError::Operation(_))) => {
                let reconcile =
                    ConsumeSelectedLogicalJobOrchestration::new(consumed.selected().clone());
                self.custody
                    .set_orchestration(OrchestrationCustody::Selected {
                        request: Box::new(reconcile),
                        deadline: Some(deadline),
                        expected_successor: None,
                    });
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
            }
            Ok(_) | Err(_) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Err(AutonomousWorkflowError::AuthorityRejected);
            }
        };
        let reconcile = ConsumeSelectedLogicalJobOrchestration::new(consumed.selected().clone());
        self.custody
            .set_orchestration(OrchestrationCustody::Selected {
                request: Box::new(reconcile.clone()),
                deadline: Some(deadline.clone()),
                expected_successor,
            });
        if continue_after {
            Box::pin(self.start_orchestration_consume(
                reconcile,
                Some(deadline),
                expected_successor,
                shutdown,
                true,
            ))
            .await
        } else {
            Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
        }
    }

    async fn resume_activation_renewal(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: RenewLogicalJobActivation,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_activation_renewal_submitted(&consumed, &request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.activations
                    .renew_logical_job_activation(request.clone())
                    .await,
            )
        };
        let result =
            match await_renewal_submission(submitted, shutdown, &deadline, submission).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
                Err(error) => {
                    if !submitted
                        && error == AutonomousWorkflowLeaseError::DeadlineElapsed
                        && self
                            .custody
                            .clear_expired_unsubmitted_activation_renewal(&consumed, &request)
                            .is_err()
                    {
                        return Err(AutonomousWorkflowError::AuthorityRejected);
                    }
                    return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
                }
            };
        let expected_successor = match result {
            Ok(acknowledgement) if acknowledgement.request() == &request => {
                Some(ExpectedRenewalSuccessor::new(
                    AutonomousWorkflowPhase::Activation,
                    acknowledgement.successor_generation().get(),
                    acknowledgement.successor_claimed_at(),
                    acknowledgement.successor_expires_at(),
                ))
            }
            Err(LogicalActivationStoreError::Store(StoreError::Operation(_))) => {
                let reconcile =
                    ConsumeSelectedLogicalJobOrchestration::new(consumed.selected().clone());
                self.custody
                    .set_orchestration(OrchestrationCustody::Selected {
                        request: Box::new(reconcile),
                        deadline: Some(deadline),
                        expected_successor: None,
                    });
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
            }
            Ok(_) | Err(_) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Err(AutonomousWorkflowError::AuthorityRejected);
            }
        };
        let reconcile = ConsumeSelectedLogicalJobOrchestration::new(consumed.selected().clone());
        self.custody
            .set_orchestration(OrchestrationCustody::Selected {
                request: Box::new(reconcile.clone()),
                deadline: Some(deadline.clone()),
                expected_successor,
            });
        if continue_after {
            Box::pin(self.start_orchestration_consume(
                reconcile,
                Some(deadline),
                expected_successor,
                shutdown,
                true,
            ))
            .await
        } else {
            Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
        }
    }

    async fn resume_materialization_renewal(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: RenewLogicalInstanceMaterialization,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_materialization_renewal_submitted(&consumed, &request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.materializations
                    .renew_logical_instance_materialization(request.clone())
                    .await,
            )
        };
        let result = match await_renewal_submission(submitted, shutdown, &deadline, submission)
            .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                if !submitted
                    && error == AutonomousWorkflowLeaseError::DeadlineElapsed
                    && self
                        .custody
                        .clear_expired_unsubmitted_materialization_renewal(&consumed, &request)
                        .is_err()
                {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
            }
        };
        let expected_successor = match result {
            Ok(acknowledgement) if acknowledgement.request() == &request => {
                Some(ExpectedRenewalSuccessor::new(
                    AutonomousWorkflowPhase::Materialization,
                    acknowledgement.successor_generation().get(),
                    acknowledgement.successor_claimed_at(),
                    acknowledgement.successor_expires_at(),
                ))
            }
            Err(LogicalMaterializationStoreError::Store(StoreError::Operation(_))) => {
                let reconcile =
                    ConsumeSelectedLogicalInstanceMaterialization::new(consumed.selected().clone());
                self.custody
                    .set_materialization(MaterializationCustody::Selected {
                        request: Box::new(reconcile),
                        deadline: Some(deadline),
                        expected_successor: None,
                    });
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
            }
            Ok(_) | Err(_) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return Err(AutonomousWorkflowError::AuthorityRejected);
            }
        };
        let reconcile =
            ConsumeSelectedLogicalInstanceMaterialization::new(consumed.selected().clone());
        self.custody
            .set_materialization(MaterializationCustody::Selected {
                request: Box::new(reconcile.clone()),
                deadline: Some(deadline.clone()),
                expected_successor,
            });
        if continue_after {
            Box::pin(self.start_materialization_consume(
                reconcile,
                Some(deadline),
                expected_successor,
                shutdown,
                true,
            ))
            .await
        } else {
            Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization))
        }
    }

    async fn start_preparation_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalActivationPreparation,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
        }
        Box::pin(self.resolve_preparation_final_submission(
            consumed, deadline, request, shutdown, true, true,
        ))
        .await
    }

    async fn resolve_preparation_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalActivationPreparation,
        shutdown: &CancellationToken,
        first_submission: bool,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission_deadline = deadline.clone();
        let lease = AutonomousPreparationLease {
            selections: Arc::clone(&self.selections),
            preparations: Arc::clone(&self.preparations),
            consumed: consumed.clone(),
            deadline,
            custody: Arc::clone(&self.custody),
        };
        let submission = async {
            if first_submission {
                self.custody.begin_preparation_final_submission(
                    consumed.clone(),
                    submission_deadline.clone(),
                    request.clone(),
                )?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.executor.submit_preparation_final(&lease).await,
            )
        };
        let outcome = match if first_submission {
            await_bounded(shutdown, &submission_deadline, submission).await
        } else {
            await_custody(shutdown, submission).await
        } {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
            }
        };
        if !self
            .custody
            .pending_preparation_final(&consumed)
            .is_ok_and(|pending| pending == request)
        {
            return Err(AutonomousWorkflowError::AuthorityRejected);
        }
        self.finish_preparation_final(consumed, outcome, shutdown, continue_after)
            .await
    }

    async fn finish_preparation_final(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        outcome: Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
        shutdown: &CancellationToken,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        match outcome {
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation) => {
                Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
            }
            Ok(AutonomousWorkflowExecutionOutcome::Completed) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    AutonomousWorkflowPhase::Preparation,
                )))
            }
            Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind)) => {
                if !continue_after {
                    self.custody
                        .set_orchestration(OrchestrationCustody::SettledFinalEvidence {
                            consumed: Box::new(consumed),
                            kind,
                        });
                    return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
                }
                let request = QuarantineLogicalJobOrchestration::new(consumed, kind);
                self.custody
                    .set_orchestration(OrchestrationCustody::Quarantine {
                        request: Box::new(request.clone()),
                        submitted: false,
                    });
                self.submit_orchestration_quarantine(request, shutdown, false)
                    .await
            }
            Ok(AutonomousWorkflowExecutionOutcome::Retryable) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
            }
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
            Err(AutonomousWorkflowLeaseError::Shutdown) => Err(AutonomousWorkflowError::Shutdown),
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration)
            }
        }
    }

    async fn start_activation_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalJobActivation,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
        }
        Box::pin(
            self.resolve_activation_final_submission(
                consumed, deadline, request, shutdown, true, true,
            ),
        )
        .await
    }

    async fn resolve_activation_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalJobActivation,
        shutdown: &CancellationToken,
        first_submission: bool,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission_deadline = deadline.clone();
        let lease = AutonomousActivationLease {
            selections: Arc::clone(&self.selections),
            activations: Arc::clone(&self.activations),
            consumed: consumed.clone(),
            deadline,
            custody: Arc::clone(&self.custody),
        };
        let submission = async {
            if first_submission {
                self.custody.begin_activation_final_submission(
                    consumed.clone(),
                    submission_deadline.clone(),
                    request.clone(),
                )?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.executor.submit_activation_final(&lease).await,
            )
        };
        let outcome = match if first_submission {
            await_bounded(shutdown, &submission_deadline, submission).await
        } else {
            await_custody(shutdown, submission).await
        } {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
            }
        };
        if !self
            .custody
            .pending_activation_final(&consumed)
            .is_ok_and(|pending| pending == request)
        {
            return Err(AutonomousWorkflowError::AuthorityRejected);
        }
        self.finish_activation_final(consumed, outcome, shutdown, continue_after)
            .await
    }

    async fn finish_activation_final(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        outcome: Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
        shutdown: &CancellationToken,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        match outcome {
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation) => {
                Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
            }
            Ok(AutonomousWorkflowExecutionOutcome::Completed) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    AutonomousWorkflowPhase::Activation,
                )))
            }
            Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind)) => {
                if !continue_after {
                    self.custody
                        .set_orchestration(OrchestrationCustody::SettledFinalEvidence {
                            consumed: Box::new(consumed),
                            kind,
                        });
                    return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
                }
                let request = QuarantineLogicalJobOrchestration::new(consumed, kind);
                self.custody
                    .set_orchestration(OrchestrationCustody::Quarantine {
                        request: Box::new(request.clone()),
                        submitted: false,
                    });
                self.submit_orchestration_quarantine(request, shutdown, false)
                    .await
            }
            Ok(AutonomousWorkflowExecutionOutcome::Retryable) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
            }
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
            Err(AutonomousWorkflowLeaseError::Shutdown) => Err(AutonomousWorkflowError::Shutdown),
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration)
            }
        }
    }

    async fn start_materialization_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalInstanceMaterialization,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
        }
        Box::pin(self.resolve_materialization_final_submission(
            consumed, deadline, request, shutdown, true, true,
        ))
        .await
    }

    async fn resolve_materialization_final_submission(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        request: ReadyLogicalInstanceMaterialization,
        shutdown: &CancellationToken,
        first_submission: bool,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission_deadline = deadline.clone();
        let lease = AutonomousMaterializationLease {
            selections: Arc::clone(&self.selections),
            materializations: Arc::clone(&self.materializations),
            consumed: consumed.clone(),
            deadline,
            custody: Arc::clone(&self.custody),
        };
        let submission = async {
            if first_submission {
                self.custody.begin_materialization_final_submission(
                    consumed.clone(),
                    submission_deadline.clone(),
                    request.clone(),
                )?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.executor.submit_materialization_final(&lease).await,
            )
        };
        let outcome = match if first_submission {
            await_bounded(shutdown, &submission_deadline, submission).await
        } else {
            await_custody(shutdown, submission).await
        } {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
            }
        };
        if !self
            .custody
            .pending_materialization_final(&consumed)
            .is_ok_and(|pending| pending == request)
        {
            return Err(AutonomousWorkflowError::AuthorityRejected);
        }
        self.finish_materialization_final(consumed, outcome, shutdown, continue_after)
            .await
    }

    async fn finish_materialization_final(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        outcome: Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
        shutdown: &CancellationToken,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        match outcome {
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation) => {
                Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization))
            }
            Ok(AutonomousWorkflowExecutionOutcome::Completed) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    AutonomousWorkflowPhase::Materialization,
                )))
            }
            Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind)) => {
                if !continue_after {
                    self.custody.set_materialization(
                        MaterializationCustody::SettledFinalEvidence {
                            consumed: Box::new(consumed),
                            kind,
                        },
                    );
                    return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
                }
                let request = QuarantineLogicalInstanceMaterialization::new(consumed, kind);
                self.custody
                    .set_materialization(MaterializationCustody::Quarantine {
                        request: Box::new(request.clone()),
                        submitted: false,
                    });
                self.submit_materialization_quarantine(request, shutdown, false)
                    .await
            }
            Ok(AutonomousWorkflowExecutionOutcome::Retryable) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization))
            }
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
            Err(AutonomousWorkflowLeaseError::Shutdown) => Err(AutonomousWorkflowError::Shutdown),
            Err(error) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization)
            }
        }
    }

    async fn drain_pending_custody(&self) {
        if !self.custody.has_pending() {
            return;
        }
        let recovery = CancellationToken::new();
        let Some(deadline) =
            Instant::now().checked_add(Duration::from_millis(CUSTODY_OPERATION_TIMEOUT_MILLIS))
        else {
            return;
        };
        while self.custody.has_pending() {
            let round_deadline = Instant::now()
                .checked_add(Duration::from_millis(CUSTODY_RETRY_MILLIS))
                .map_or(deadline, |candidate| candidate.min(deadline));
            // One round gives each pending queue at most one exact attempt.
            // Each attempt also owns at most one cadence slice, so a hanging
            // operation in either direction cannot starve the other queue for
            // the entire drain interval.
            for queue in [
                AutonomousWorkflowQueue::Orchestration,
                AutonomousWorkflowQueue::Materialization,
            ] {
                if !self.custody.has_pending_queue(queue) {
                    continue;
                }
                let attempt_deadline = Instant::now()
                    .checked_add(Duration::from_millis(CUSTODY_RETRY_MILLIS))
                    .map_or(deadline, |candidate| candidate.min(deadline));
                tokio::select! {
                    biased;
                    () = sleep_until(deadline) => return,
                    () = sleep_until(attempt_deadline) => {}
                    _ = Box::pin(self.resume_custody(&recovery, true, Some(queue))) => {}
                }
            }
            if !self.custody.has_pending() {
                return;
            }
            // Retry exact, still-pending Store operations at a bounded cadence.
            // The absolute deadline is biased so equality never starts another
            // operation and no per-attempt timeout can extend the drain bound.
            tokio::select! {
                biased;
                () = sleep_until(deadline) => return,
                () = sleep_until(round_deadline) => {}
            }
        }
    }

    async fn try_queue(
        &self,
        queue: AutonomousWorkflowQueue,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        match queue {
            AutonomousWorkflowQueue::Orchestration => {
                Box::pin(self.try_orchestration(shutdown)).await
            }
            AutonomousWorkflowQueue::Materialization => {
                Box::pin(self.try_materialization(shutdown)).await
            }
        }
    }

    async fn try_orchestration(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let request = ClaimNextLogicalJobOrchestration::new(
            automata_ci_store::LogicalWorkSelectionId::from_uuid(Uuid::new_v4())
                .map_err(|_| AutonomousWorkflowError::InvalidTimestamp)?,
            self.orchestration_worker,
            trusted_now(self.clock.as_ref())?,
            MAX_LOGICAL_WORK_SELECTION_MILLIS,
        )
        .map_err(|_| AutonomousWorkflowError::InvalidTimestamp)?;
        self.custody
            .begin_orchestration_selection(request.clone())
            .map_err(|_| AutonomousWorkflowError::AuthorityRejected)?;
        Box::pin(self.submit_orchestration_selection(request, shutdown, true, false)).await
    }

    async fn submit_orchestration_selection(
        &self,
        request: ClaimNextLogicalJobOrchestration,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_orchestration_selection_submitted(&request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.selections
                    .claim_next_logical_job_orchestration(request.clone())
                    .await,
            )
        };
        let outcome = match await_custody(shutdown, submission).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
            }
        };
        let selected = match outcome {
            Err(error) if is_repository_unavailable(&error) => {
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
            }
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return selection_failure(&error, AutonomousWorkflowQueue::Orchestration);
            }
            Ok(LogicalJobOrchestrationSelectionOutcome::Idle) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Ok(QueuePoll::Idle);
            }
            Ok(LogicalJobOrchestrationSelectionOutcome::Contended) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Contended(
                    AutonomousWorkflowQueue::Orchestration,
                )));
            }
            Ok(LogicalJobOrchestrationSelectionOutcome::Quarantined) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Quarantined(
                    AutonomousWorkflowQueue::Orchestration,
                )));
            }
            Ok(LogicalJobOrchestrationSelectionOutcome::Selected(selected)) => selected,
        };

        let consume = ConsumeSelectedLogicalJobOrchestration::new(selected);
        self.custody
            .set_orchestration(OrchestrationCustody::Selected {
                request: Box::new(consume.clone()),
                deadline: None,
                expected_successor: None,
            });
        if continue_after {
            Box::pin(self.start_orchestration_consume(consume, None, None, shutdown, true)).await
        } else {
            Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration))
        }
    }

    async fn start_orchestration_consume(
        &self,
        consume: ConsumeSelectedLogicalJobOrchestration,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if shutdown.is_cancelled() {
            return unavailable_or_shutdown(
                AutonomousWorkflowLeaseError::Shutdown,
                AutonomousWorkflowQueue::Orchestration,
            );
        }
        if let Some(deadline) = deadline.as_ref()
            && let Err(error) = deadline.checkpoint(shutdown)
        {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
        }
        self.custody
            .retain_ready_orchestration_consume(
                consume.clone(),
                deadline.clone(),
                expected_successor,
            )
            .map_err(|_| AutonomousWorkflowError::AuthorityRejected)?;
        Box::pin(self.resolve_orchestration_consume(
            consume,
            None,
            deadline,
            expected_successor,
            shutdown,
            continue_after,
            false,
        ))
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_orchestration_consume(
        &self,
        consume: ConsumeSelectedLogicalJobOrchestration,
        operation_started: Option<Instant>,
        prior_deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let request = consume.clone();
        let submission = async {
            let started = if submitted {
                operation_started.ok_or(AutonomousWorkflowLeaseError::AuthorityRejected)?
            } else {
                self.custody
                    .mark_orchestration_consume_submitted(&request)?
            };
            let result = self
                .selections
                .consume_selected_logical_job_orchestration(consume)
                .await;
            Ok::<_, AutonomousWorkflowLeaseError>((started, result))
        };
        let consumed = match if submitted {
            await_custody(shutdown, submission).await
        } else if let Some(deadline) = prior_deadline.as_ref() {
            await_bounded(shutdown, deadline, submission).await
        } else {
            await_custody(shutdown, submission).await
        } {
            Ok(Ok(consumed)) => consumed,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
            }
        };
        let (operation_started, consumed) = consumed;
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) if is_repository_unavailable(&error) => {
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
            }
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return consume_failure(error, AutonomousWorkflowQueue::Orchestration);
            }
        };
        if consumed.selected() != request.selected()
            || expected_successor.is_some_and(|expected| !expected.matches_orchestration(&consumed))
        {
            self.custody.set_orchestration(OrchestrationCustody::Idle);
            return Err(AutonomousWorkflowError::AuthorityRejected);
        }
        let (validated_at, expires_at) = orchestration_interval(&consumed);
        let deadline = match prior_deadline {
            Some(deadline) => {
                if deadline
                    .tighten(operation_started, validated_at, expires_at)
                    .is_err()
                {
                    self.custody.set_orchestration(OrchestrationCustody::Idle);
                    return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
                }
                deadline
            }
            None => {
                match AutonomousWorkflowDeadline::new(operation_started, validated_at, expires_at) {
                    Ok(deadline) => deadline,
                    Err(AutonomousWorkflowError::InvalidAuthorityInterval) => {
                        self.custody.set_orchestration(OrchestrationCustody::Idle);
                        return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        self.custody
            .set_orchestration(OrchestrationCustody::Active {
                consumed: Box::new(consumed.clone()),
                deadline: deadline.clone(),
            });
        if !continue_after {
            return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
        }
        Box::pin(self.execute_orchestration_active(consumed, deadline, shutdown)).await
    }

    async fn execute_orchestration_active(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
        }
        match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                let mut lease = AutonomousPreparationLease {
                    selections: Arc::clone(&self.selections),
                    preparations: Arc::clone(&self.preparations),
                    consumed,
                    deadline: deadline.clone(),
                    custody: Arc::clone(&self.custody),
                };
                let execution = self.executor.execute_preparation(
                    &mut lease,
                    shutdown.clone(),
                    deadline.clone(),
                );
                let disposition = await_bounded(shutdown, &deadline, execution).await;
                Box::pin(self.finish_orchestration(
                    AutonomousWorkflowPhase::Preparation,
                    lease.consumed,
                    disposition,
                    shutdown,
                ))
                .await
            }
            ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                let mut lease = AutonomousActivationLease {
                    selections: Arc::clone(&self.selections),
                    activations: Arc::clone(&self.activations),
                    consumed,
                    deadline: deadline.clone(),
                    custody: Arc::clone(&self.custody),
                };
                let execution = self.executor.execute_activation(
                    &mut lease,
                    shutdown.clone(),
                    deadline.clone(),
                );
                let disposition = await_bounded(shutdown, &deadline, execution).await;
                Box::pin(self.finish_orchestration(
                    AutonomousWorkflowPhase::Activation,
                    lease.consumed,
                    disposition,
                    shutdown,
                ))
                .await
            }
        }
    }

    async fn finish_orchestration(
        &self,
        phase: AutonomousWorkflowPhase,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        disposition: Result<
            Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
            AutonomousWorkflowLeaseError,
        >,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let disposition = match disposition {
            Err(AutonomousWorkflowLeaseError::Shutdown)
            | Ok(Err(AutonomousWorkflowLeaseError::Shutdown)) => {
                return Err(AutonomousWorkflowError::Shutdown);
            }
            Err(
                AutonomousWorkflowLeaseError::DeadlineElapsed
                | AutonomousWorkflowLeaseError::Unavailable,
            )
            | Ok(Err(
                AutonomousWorkflowLeaseError::DeadlineElapsed
                | AutonomousWorkflowLeaseError::Unavailable,
            )) => {
                self.custody.clear_orchestration_if_active();
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
                    AutonomousWorkflowQueue::Orchestration,
                )));
            }
            Ok(Ok(AutonomousWorkflowExecutionOutcome::Retryable)) => {
                if !self.custody.orchestration_is_active(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                self.custody.clear_orchestration_if_active();
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
                    AutonomousWorkflowQueue::Orchestration,
                )));
            }
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
            | Ok(Err(AutonomousWorkflowLeaseError::AuthorityRejected)) => {
                self.custody.clear_orchestration_if_active();
                return Err(AutonomousWorkflowError::AuthorityRejected);
            }
            Ok(Ok(outcome)) => outcome,
        };
        match disposition {
            AutonomousWorkflowExecutionOutcome::Completed => {
                if !self.custody.orchestration_is_active(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    phase,
                )))
            }
            AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind) => {
                if !self.custody.orchestration_is_active(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                if shutdown.is_cancelled() {
                    return Err(AutonomousWorkflowError::Shutdown);
                }
                let request = QuarantineLogicalJobOrchestration::new(consumed, kind);
                self.custody
                    .set_orchestration(OrchestrationCustody::Quarantine {
                        request: Box::new(request.clone()),
                        submitted: false,
                    });
                self.submit_orchestration_quarantine(request, shutdown, false)
                    .await
            }
            AutonomousWorkflowExecutionOutcome::Retryable => unreachable!("handled above"),
            AutonomousWorkflowExecutionOutcome::FinalRequestReady => {
                match phase {
                    AutonomousWorkflowPhase::Preparation => {
                        let Some((deadline, request)) =
                            self.custody.ready_preparation_final(&consumed)
                        else {
                            return Err(AutonomousWorkflowError::AuthorityRejected);
                        };
                        Box::pin(self.start_preparation_final_submission(
                            consumed, deadline, request, shutdown,
                        ))
                        .await
                    }
                    AutonomousWorkflowPhase::Activation => {
                        let Some((deadline, request)) =
                            self.custody.ready_activation_final(&consumed)
                        else {
                            return Err(AutonomousWorkflowError::AuthorityRejected);
                        };
                        Box::pin(self.start_activation_final_submission(
                            consumed, deadline, request, shutdown,
                        ))
                        .await
                    }
                    AutonomousWorkflowPhase::Materialization => {
                        Err(AutonomousWorkflowError::AuthorityRejected)
                    }
                }
            }
            AutonomousWorkflowExecutionOutcome::FinalRequestOperation => {
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
        }
    }

    async fn submit_orchestration_quarantine(
        &self,
        request: QuarantineLogicalJobOrchestration,
        shutdown: &CancellationToken,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_orchestration_quarantine_submitted(&request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.selections
                    .quarantine_logical_job_orchestration(request.clone())
                    .await,
            )
        };
        let outcome = match await_custody(shutdown, submission).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Orchestration);
            }
        };
        match outcome {
            Ok(
                LogicalWorkQuarantineOutcome::Quarantined
                | LogicalWorkQuarantineOutcome::AlreadyQuarantined,
            ) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Quarantined(
                    AutonomousWorkflowQueue::Orchestration,
                )))
            }
            Ok(LogicalWorkQuarantineOutcome::FenceRejected) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                Err(AutonomousWorkflowError::QuarantineFenceRejected)
            }
            Err(error) if is_repository_unavailable(&error) => Ok(QueuePoll::Outcome(
                AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration),
            )),
            Err(error) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                quarantine_failure(&error, AutonomousWorkflowQueue::Orchestration)
            }
        }
    }

    async fn try_materialization(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let request = ClaimNextLogicalInstanceMaterialization::new(
            automata_ci_store::LogicalWorkSelectionId::from_uuid(Uuid::new_v4())
                .map_err(|_| AutonomousWorkflowError::InvalidTimestamp)?,
            self.materialization_worker,
            trusted_now(self.clock.as_ref())?,
            MAX_LOGICAL_WORK_SELECTION_MILLIS,
        )
        .map_err(|_| AutonomousWorkflowError::InvalidTimestamp)?;
        self.custody
            .begin_materialization_selection(request.clone())
            .map_err(|_| AutonomousWorkflowError::AuthorityRejected)?;
        self.submit_materialization_selection(request, shutdown, true, false)
            .await
    }

    async fn submit_materialization_selection(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_materialization_selection_submitted(&request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.selections
                    .claim_next_logical_instance_materialization(request.clone())
                    .await,
            )
        };
        let outcome = match await_custody(shutdown, submission).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
            }
        };
        let selected = match outcome {
            Err(error) if is_repository_unavailable(&error) => {
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
            }
            Err(error) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return selection_failure(&error, AutonomousWorkflowQueue::Materialization);
            }
            Ok(LogicalInstanceMaterializationSelectionOutcome::Idle) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return Ok(QueuePoll::Idle);
            }
            Ok(LogicalInstanceMaterializationSelectionOutcome::Contended) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Contended(
                    AutonomousWorkflowQueue::Materialization,
                )));
            }
            Ok(LogicalInstanceMaterializationSelectionOutcome::Quarantined) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Quarantined(
                    AutonomousWorkflowQueue::Materialization,
                )));
            }
            Ok(LogicalInstanceMaterializationSelectionOutcome::Selected(selected)) => selected,
        };

        let consume = ConsumeSelectedLogicalInstanceMaterialization::new(selected);
        self.custody
            .set_materialization(MaterializationCustody::Selected {
                request: Box::new(consume.clone()),
                deadline: None,
                expected_successor: None,
            });
        if continue_after {
            Box::pin(self.start_materialization_consume(consume, None, None, shutdown, true)).await
        } else {
            Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization))
        }
    }

    async fn start_materialization_consume(
        &self,
        consume: ConsumeSelectedLogicalInstanceMaterialization,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if shutdown.is_cancelled() {
            return unavailable_or_shutdown(
                AutonomousWorkflowLeaseError::Shutdown,
                AutonomousWorkflowQueue::Materialization,
            );
        }
        if let Some(deadline) = deadline.as_ref()
            && let Err(error) = deadline.checkpoint(shutdown)
        {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
        }
        self.custody
            .retain_ready_materialization_consume(
                consume.clone(),
                deadline.clone(),
                expected_successor,
            )
            .map_err(|_| AutonomousWorkflowError::AuthorityRejected)?;
        Box::pin(self.resolve_materialization_consume(
            consume,
            None,
            deadline,
            expected_successor,
            shutdown,
            continue_after,
            false,
        ))
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_materialization_consume(
        &self,
        consume: ConsumeSelectedLogicalInstanceMaterialization,
        operation_started: Option<Instant>,
        prior_deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let request = consume.clone();
        let submission = async {
            let started = if submitted {
                operation_started.ok_or(AutonomousWorkflowLeaseError::AuthorityRejected)?
            } else {
                self.custody
                    .mark_materialization_consume_submitted(&request)?
            };
            let result = self
                .selections
                .consume_selected_logical_instance_materialization(consume)
                .await;
            Ok::<_, AutonomousWorkflowLeaseError>((started, result))
        };
        let consumed = match if submitted {
            await_custody(shutdown, submission).await
        } else if let Some(deadline) = prior_deadline.as_ref() {
            await_bounded(shutdown, deadline, submission).await
        } else {
            await_custody(shutdown, submission).await
        } {
            Ok(Ok(consumed)) => consumed,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
            }
        };
        let (operation_started, consumed) = consumed;
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) if is_repository_unavailable(&error) => {
                return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
            }
            Err(error) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return consume_failure(error, AutonomousWorkflowQueue::Materialization);
            }
        };
        if consumed.selected() != request.selected()
            || expected_successor
                .is_some_and(|expected| !expected.matches_materialization(&consumed))
        {
            self.custody
                .set_materialization(MaterializationCustody::Idle);
            return Err(AutonomousWorkflowError::AuthorityRejected);
        }
        let deadline = match prior_deadline {
            Some(deadline) => {
                if deadline
                    .tighten(
                        operation_started,
                        consumed.validated_at(),
                        consumed.authority().claim().expires_at(),
                    )
                    .is_err()
                {
                    self.custody
                        .set_materialization(MaterializationCustody::Idle);
                    return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
                }
                deadline
            }
            None => match AutonomousWorkflowDeadline::new(
                operation_started,
                consumed.validated_at(),
                consumed.authority().claim().expires_at(),
            ) {
                Ok(deadline) => deadline,
                Err(AutonomousWorkflowError::InvalidAuthorityInterval) => {
                    self.custody
                        .set_materialization(MaterializationCustody::Idle);
                    return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
                }
                Err(error) => return Err(error),
            },
        };
        self.custody
            .set_materialization(MaterializationCustody::Active {
                consumed: Box::new(consumed.clone()),
                deadline: deadline.clone(),
            });
        if !continue_after {
            return Ok(unavailable_poll(AutonomousWorkflowQueue::Materialization));
        }
        Box::pin(self.execute_materialization_active(consumed, deadline, shutdown)).await
    }

    async fn execute_materialization_active(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        deadline: AutonomousWorkflowDeadline,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
            }
            return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
        }
        let mut lease = AutonomousMaterializationLease {
            selections: Arc::clone(&self.selections),
            materializations: Arc::clone(&self.materializations),
            consumed,
            deadline: deadline.clone(),
            custody: Arc::clone(&self.custody),
        };
        let execution =
            self.executor
                .execute_materialization(&mut lease, shutdown.clone(), deadline.clone());
        let disposition = await_bounded(shutdown, &deadline, execution).await;
        Box::pin(self.finish_materialization(lease.consumed, disposition, shutdown)).await
    }

    async fn finish_materialization(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
        disposition: Result<
            Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
            AutonomousWorkflowLeaseError,
        >,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let disposition = match disposition {
            Err(AutonomousWorkflowLeaseError::Shutdown)
            | Ok(Err(AutonomousWorkflowLeaseError::Shutdown)) => {
                return Err(AutonomousWorkflowError::Shutdown);
            }
            Err(
                AutonomousWorkflowLeaseError::DeadlineElapsed
                | AutonomousWorkflowLeaseError::Unavailable,
            )
            | Ok(Err(
                AutonomousWorkflowLeaseError::DeadlineElapsed
                | AutonomousWorkflowLeaseError::Unavailable,
            )) => {
                self.custody.clear_materialization_if_active();
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
                    AutonomousWorkflowQueue::Materialization,
                )));
            }
            Ok(Ok(AutonomousWorkflowExecutionOutcome::Retryable)) => {
                if !self.custody.materialization_is_active(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                self.custody.clear_materialization_if_active();
                return Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
                    AutonomousWorkflowQueue::Materialization,
                )));
            }
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
            | Ok(Err(AutonomousWorkflowLeaseError::AuthorityRejected)) => {
                self.custody.clear_materialization_if_active();
                return Err(AutonomousWorkflowError::AuthorityRejected);
            }
            Ok(Ok(outcome)) => outcome,
        };
        match disposition {
            AutonomousWorkflowExecutionOutcome::Completed => {
                if !self.custody.materialization_is_active(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    AutonomousWorkflowPhase::Materialization,
                )))
            }
            AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind) => {
                if !self.custody.materialization_is_active(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                if shutdown.is_cancelled() {
                    return Err(AutonomousWorkflowError::Shutdown);
                }
                let request = QuarantineLogicalInstanceMaterialization::new(consumed, kind);
                self.custody
                    .set_materialization(MaterializationCustody::Quarantine {
                        request: Box::new(request.clone()),
                        submitted: false,
                    });
                self.submit_materialization_quarantine(request, shutdown, false)
                    .await
            }
            AutonomousWorkflowExecutionOutcome::Retryable => unreachable!("handled above"),
            AutonomousWorkflowExecutionOutcome::FinalRequestReady => {
                let Some((deadline, request)) = self.custody.ready_materialization_final(&consumed)
                else {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                };
                Box::pin(
                    self.start_materialization_final_submission(
                        consumed, deadline, request, shutdown,
                    ),
                )
                .await
            }
            AutonomousWorkflowExecutionOutcome::FinalRequestOperation => {
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
        }
    }

    async fn submit_materialization_quarantine(
        &self,
        request: QuarantineLogicalInstanceMaterialization,
        shutdown: &CancellationToken,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission = async {
            if !submitted {
                self.custody
                    .mark_materialization_quarantine_submitted(&request)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                self.selections
                    .quarantine_logical_instance_materialization(request.clone())
                    .await,
            )
        };
        let outcome = match await_custody(shutdown, submission).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                return unavailable_or_shutdown(error, AutonomousWorkflowQueue::Materialization);
            }
        };
        match outcome {
            Ok(
                LogicalWorkQuarantineOutcome::Quarantined
                | LogicalWorkQuarantineOutcome::AlreadyQuarantined,
            ) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Quarantined(
                    AutonomousWorkflowQueue::Materialization,
                )))
            }
            Ok(LogicalWorkQuarantineOutcome::FenceRejected) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                Err(AutonomousWorkflowError::QuarantineFenceRejected)
            }
            Err(error) if is_repository_unavailable(&error) => Ok(QueuePoll::Outcome(
                AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization),
            )),
            Err(error) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                quarantine_failure(&error, AutonomousWorkflowQueue::Materialization)
            }
        }
    }
}

enum QueuePoll {
    Idle,
    Outcome(AutonomousWorkflowOutcome),
}

fn outcome_from_poll(poll: &QueuePoll) -> AutonomousWorkflowOutcome {
    match poll {
        QueuePoll::Idle => AutonomousWorkflowOutcome::Idle,
        QueuePoll::Outcome(outcome) => *outcome,
    }
}

const fn unavailable_poll(queue: AutonomousWorkflowQueue) -> QueuePoll {
    QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(queue))
}

async fn await_bounded<T, F>(
    shutdown: &CancellationToken,
    deadline: &AutonomousWorkflowDeadline,
    future: F,
) -> Result<T, AutonomousWorkflowLeaseError>
where
    F: Future<Output = T>,
{
    deadline.checkpoint(shutdown)?;
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Err(AutonomousWorkflowLeaseError::Shutdown),
        () = deadline.elapsed() => Err(AutonomousWorkflowLeaseError::DeadlineElapsed),
        value = future => Ok(value),
    }
}

async fn await_custody<T, F>(
    shutdown: &CancellationToken,
    future: F,
) -> Result<T, AutonomousWorkflowLeaseError>
where
    F: Future<Output = T>,
{
    if shutdown.is_cancelled() {
        return Err(AutonomousWorkflowLeaseError::Shutdown);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(CUSTODY_OPERATION_TIMEOUT_MILLIS))
        .ok_or(AutonomousWorkflowLeaseError::Unavailable)?;
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Err(AutonomousWorkflowLeaseError::Shutdown),
        () = sleep_until(deadline) => Err(AutonomousWorkflowLeaseError::Unavailable),
        value = future => Ok(value),
    }
}

async fn await_renewal_submission<T, F>(
    submitted: bool,
    shutdown: &CancellationToken,
    deadline: &AutonomousWorkflowDeadline,
    future: F,
) -> Result<T, AutonomousWorkflowLeaseError>
where
    F: Future<Output = T>,
{
    if submitted {
        await_custody(shutdown, future).await
    } else {
        await_bounded(shutdown, deadline, future).await
    }
}

fn authority_deadline(
    operation_started: Instant,
    validated_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<Instant, AutonomousWorkflowError> {
    let usable_millis = expires_at
        .get()
        .checked_sub(validated_at.get())
        .and_then(|remaining| remaining.checked_sub(AUTONOMOUS_WORKFLOW_AUTHORITY_SAFETY_MILLIS))
        .filter(|remaining| *remaining > 0)
        .and_then(|remaining| u64::try_from(remaining).ok())
        .ok_or(AutonomousWorkflowError::InvalidAuthorityInterval)?;
    operation_started
        .checked_add(Duration::from_millis(usable_millis))
        .filter(|deadline| *deadline > Instant::now())
        .ok_or(AutonomousWorkflowError::InvalidAuthorityInterval)
}

fn renewal_duration(deadline: &AutonomousWorkflowDeadline, maximum_millis: i64) -> i64 {
    renewal_duration_for_remaining(deadline.remaining(), maximum_millis)
}

fn extending_renewal_duration(
    deadline: &AutonomousWorkflowDeadline,
    maximum_millis: i64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<Option<i64>, AutonomousWorkflowLeaseError> {
    strictly_extending_duration(
        renewal_duration(deadline, maximum_millis),
        claimed_at,
        expires_at,
    )
}

fn strictly_extending_duration(
    proposed: i64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<Option<i64>, AutonomousWorkflowLeaseError> {
    let durable_interval = expires_at
        .get()
        .checked_sub(claimed_at.get())
        .filter(|interval| *interval > 0)
        .ok_or(AutonomousWorkflowLeaseError::AuthorityRejected)?;
    Ok((proposed > durable_interval).then_some(proposed))
}

fn renewal_duration_for_remaining(remaining: Duration, maximum_millis: i64) -> i64 {
    const STORE_HANDOFF_MILLIS: u128 = 1_000;

    let whole_millis = remaining.as_millis();
    let fractional_millis = !remaining.subsec_nanos().is_multiple_of(1_000_000);
    let ceiling_millis = whole_millis.saturating_add(u128::from(fractional_millis));
    let safety_millis =
        u128::try_from(AUTONOMOUS_WORKFLOW_AUTHORITY_SAFETY_MILLIS).unwrap_or(u128::MAX);
    let requested = ceiling_millis
        .saturating_add(safety_millis)
        .saturating_add(STORE_HANDOFF_MILLIS);
    let minimum = u128::try_from(MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS).unwrap_or(u128::MAX);
    let maximum = u128::try_from(maximum_millis).unwrap_or_default();
    i64::try_from(requested.clamp(minimum, maximum)).unwrap_or(maximum_millis)
}

fn orchestration_interval(
    consumed: &ConsumedSelectedLogicalJobOrchestration,
) -> (UnixMillis, UnixMillis) {
    let expires_at = match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(authority) => {
            authority.claim().expires_at()
        }
        ConsumedLogicalJobOrchestrationAuthority::Activation(authority) => {
            authority.claim().expires_at()
        }
    };
    (consumed.validated_at(), expires_at)
}

fn trusted_now(clock: &dyn AdmissionClock) -> Result<UnixMillis, AutonomousWorkflowError> {
    let now = clock.now();
    if now.get() < 0 {
        Err(AutonomousWorkflowError::InvalidTimestamp)
    } else {
        Ok(now)
    }
}

fn unavailable_or_shutdown(
    error: AutonomousWorkflowLeaseError,
    queue: AutonomousWorkflowQueue,
) -> Result<QueuePoll, AutonomousWorkflowError> {
    match error {
        AutonomousWorkflowLeaseError::Shutdown => Err(AutonomousWorkflowError::Shutdown),
        AutonomousWorkflowLeaseError::DeadlineElapsed
        | AutonomousWorkflowLeaseError::Unavailable => Ok(QueuePoll::Outcome(
            AutonomousWorkflowOutcome::Unavailable(queue),
        )),
        AutonomousWorkflowLeaseError::AuthorityRejected => {
            Err(AutonomousWorkflowError::AuthorityRejected)
        }
    }
}

fn selection_failure(
    error: &automata_ci_store::LogicalWorkSelectionStoreError,
    queue: AutonomousWorkflowQueue,
) -> Result<QueuePoll, AutonomousWorkflowError> {
    if is_repository_unavailable(error) {
        Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
            queue,
        )))
    } else {
        Err(AutonomousWorkflowError::AuthorityRejected)
    }
}

fn consume_failure(
    error: automata_ci_store::LogicalWorkSelectionStoreError,
    queue: AutonomousWorkflowQueue,
) -> Result<QueuePoll, AutonomousWorkflowError> {
    match error {
        automata_ci_store::LogicalWorkSelectionStoreError::SelectionQuarantined => Ok(
            QueuePoll::Outcome(AutonomousWorkflowOutcome::Quarantined(queue)),
        ),
        automata_ci_store::LogicalWorkSelectionStoreError::SelectionExpired => Ok(
            QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(queue)),
        ),
        error if is_repository_unavailable(&error) => Ok(QueuePoll::Outcome(
            AutonomousWorkflowOutcome::Unavailable(queue),
        )),
        _ => Err(AutonomousWorkflowError::AuthorityRejected),
    }
}

fn quarantine_failure(
    error: &automata_ci_store::LogicalWorkSelectionStoreError,
    queue: AutonomousWorkflowQueue,
) -> Result<QueuePoll, AutonomousWorkflowError> {
    if is_repository_unavailable(error) {
        Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
            queue,
        )))
    } else {
        Err(AutonomousWorkflowError::AuthorityRejected)
    }
}

fn map_reconcile_error(
    error: &automata_ci_store::LogicalWorkSelectionStoreError,
) -> AutonomousWorkflowLeaseError {
    if matches!(
        error,
        automata_ci_store::LogicalWorkSelectionStoreError::SelectionExpired
            | automata_ci_store::LogicalWorkSelectionStoreError::SelectionQuarantined
    ) || is_repository_unavailable(error)
    {
        AutonomousWorkflowLeaseError::Unavailable
    } else {
        AutonomousWorkflowLeaseError::AuthorityRejected
    }
}

fn is_repository_unavailable(error: &automata_ci_store::LogicalWorkSelectionStoreError) -> bool {
    matches!(
        error,
        automata_ci_store::LogicalWorkSelectionStoreError::Store(StoreError::Operation(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use async_trait::async_trait;
    use automata_ci_store::{
        BindLogicalActivationPreparation, CommitLogicalInstanceMaterialization,
        LogicalActivationPreparationReceipt, LogicalActivationPublicationReceipt,
        LogicalMaterializationReceipt, LogicalWorkSelectionId, LogicalWorkSelectionStoreError,
        PublishLogicalJobActivation, RenewedLogicalActivationPreparation,
        RenewedLogicalInstanceMaterialization, RenewedLogicalJobActivation,
    };

    #[derive(Debug)]
    struct DrainRepository {
        orchestration_requests: StdMutex<Vec<ClaimNextLogicalJobOrchestration>>,
        materialization_requests: StdMutex<Vec<ClaimNextLogicalInstanceMaterialization>>,
        hang_orchestration: bool,
        hang_materialization: bool,
    }

    impl DrainRepository {
        fn new(hang_orchestration: bool, hang_materialization: bool) -> Self {
            Self {
                orchestration_requests: StdMutex::new(Vec::new()),
                materialization_requests: StdMutex::new(Vec::new()),
                hang_orchestration,
                hang_materialization,
            }
        }

        fn orchestration_requests(&self) -> Vec<ClaimNextLogicalJobOrchestration> {
            self.orchestration_requests
                .lock()
                .expect("attempt lock is not poisoned")
                .clone()
        }

        fn materialization_requests(&self) -> Vec<ClaimNextLogicalInstanceMaterialization> {
            self.materialization_requests
                .lock()
                .expect("attempt lock is not poisoned")
                .clone()
        }
    }

    #[async_trait]
    impl LogicalWorkSelectionRepository for DrainRepository {
        async fn claim_next_logical_job_orchestration(
            &self,
            request: ClaimNextLogicalJobOrchestration,
        ) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError>
        {
            self.orchestration_requests
                .lock()
                .expect("attempt lock is not poisoned")
                .push(request);
            if self.hang_orchestration {
                return std::future::pending().await;
            }
            Err(drain_operation_error())
        }

        async fn claim_next_logical_instance_materialization(
            &self,
            request: ClaimNextLogicalInstanceMaterialization,
        ) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError>
        {
            self.materialization_requests
                .lock()
                .expect("attempt lock is not poisoned")
                .push(request);
            if self.hang_materialization {
                return std::future::pending().await;
            }
            Err(drain_operation_error())
        }

        async fn consume_selected_logical_job_orchestration(
            &self,
            _request: ConsumeSelectedLogicalJobOrchestration,
        ) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError>
        {
            panic!("drain must not consume orchestration")
        }

        async fn consume_selected_logical_instance_materialization(
            &self,
            _request: ConsumeSelectedLogicalInstanceMaterialization,
        ) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError>
        {
            panic!("drain must not consume materialization")
        }

        async fn quarantine_logical_job_orchestration(
            &self,
            _request: QuarantineLogicalJobOrchestration,
        ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
            panic!("drain fixture contains no quarantine")
        }

        async fn quarantine_logical_instance_materialization(
            &self,
            _request: QuarantineLogicalInstanceMaterialization,
        ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
            panic!("drain fixture contains no quarantine")
        }
    }

    #[async_trait]
    impl LogicalActivationPreparationStore for DrainRepository {
        async fn renew_logical_activation_preparation(
            &self,
            _request: RenewLogicalActivationPreparation,
        ) -> Result<RenewedLogicalActivationPreparation, LogicalActivationPreparationStoreError>
        {
            panic!("drain fixture contains no preparation renewal")
        }

        async fn bind_logical_activation_preparation(
            &self,
            _request: BindLogicalActivationPreparation,
        ) -> Result<LogicalActivationPreparationReceipt, LogicalActivationPreparationStoreError>
        {
            panic!("drain fixture contains no preparation final")
        }
    }

    #[async_trait]
    impl LogicalActivationRepository for DrainRepository {
        async fn renew_logical_job_activation(
            &self,
            _request: RenewLogicalJobActivation,
        ) -> Result<RenewedLogicalJobActivation, LogicalActivationStoreError> {
            panic!("drain fixture contains no activation renewal")
        }

        async fn publish_logical_job_activation(
            &self,
            _request: PublishLogicalJobActivation,
        ) -> Result<LogicalActivationPublicationReceipt, LogicalActivationStoreError> {
            panic!("drain fixture contains no activation final")
        }
    }

    #[async_trait]
    impl LogicalMaterializationRepository for DrainRepository {
        async fn renew_logical_instance_materialization(
            &self,
            _request: RenewLogicalInstanceMaterialization,
        ) -> Result<RenewedLogicalInstanceMaterialization, LogicalMaterializationStoreError>
        {
            panic!("drain fixture contains no materialization renewal")
        }

        async fn commit_logical_instance_materialization(
            &self,
            _request: CommitLogicalInstanceMaterialization,
        ) -> Result<LogicalMaterializationReceipt, LogicalMaterializationStoreError> {
            panic!("drain fixture contains no materialization final")
        }
    }

    #[derive(Debug)]
    struct DrainExecutor;

    impl AutonomousWorkflowPhaseExecutor for DrainExecutor {
        fn execute_preparation<'a>(
            &'a self,
            _lease: &'a mut AutonomousPreparationLease,
            _shutdown: CancellationToken,
            _deadline: AutonomousWorkflowDeadline,
        ) -> AutonomousWorkflowExecutionFuture<'a> {
            Box::pin(async { panic!("drain must not execute preparation") })
        }

        fn execute_activation<'a>(
            &'a self,
            _lease: &'a mut AutonomousActivationLease,
            _shutdown: CancellationToken,
            _deadline: AutonomousWorkflowDeadline,
        ) -> AutonomousWorkflowExecutionFuture<'a> {
            Box::pin(async { panic!("drain must not execute activation") })
        }

        fn execute_materialization<'a>(
            &'a self,
            _lease: &'a mut AutonomousMaterializationLease,
            _shutdown: CancellationToken,
            _deadline: AutonomousWorkflowDeadline,
        ) -> AutonomousWorkflowExecutionFuture<'a> {
            Box::pin(async { panic!("drain must not execute materialization") })
        }
    }

    #[derive(Debug)]
    struct DrainClock;

    impl AdmissionClock for DrainClock {
        fn now(&self) -> UnixMillis {
            UnixMillis::new(1_000)
        }
    }

    fn drain_operation_error() -> LogicalWorkSelectionStoreError {
        LogicalWorkSelectionStoreError::Store(StoreError::operation(std::io::Error::other(
            "synthetic drain ambiguity",
        )))
    }

    fn drain_service(repository: Arc<DrainRepository>) -> Arc<AutonomousWorkflowService> {
        let selections: Arc<dyn LogicalWorkSelectionRepository> = repository.clone();
        let preparations: Arc<dyn LogicalActivationPreparationStore> = repository.clone();
        let activations: Arc<dyn LogicalActivationRepository> = repository.clone();
        let materializations: Arc<dyn LogicalMaterializationRepository> = repository;
        Arc::new(AutonomousWorkflowService::new(
            selections,
            preparations,
            activations,
            materializations,
            Arc::new(DrainExecutor),
            Arc::new(DrainClock),
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(1)).expect("worker ID"),
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(2)).expect("worker ID"),
        ))
    }

    fn retain_submitted_selections(service: &AutonomousWorkflowService) {
        let orchestration = ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(3)).expect("selection ID"),
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(1)).expect("worker ID"),
            UnixMillis::new(1_000),
            MAX_LOGICAL_WORK_SELECTION_MILLIS,
        )
        .expect("orchestration selection request");
        let materialization = ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(4)).expect("selection ID"),
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(2)).expect("worker ID"),
            UnixMillis::new(1_000),
            MAX_LOGICAL_WORK_SELECTION_MILLIS,
        )
        .expect("materialization selection request");
        service
            .custody
            .set_orchestration(OrchestrationCustody::Select {
                request: Box::new(orchestration),
                submitted: true,
            });
        service
            .custody
            .set_materialization(MaterializationCustody::Select {
                request: Box::new(materialization),
                submitted: true,
            });
    }

    async fn wait_for_attempts(
        repository: &DrainRepository,
        orchestration: usize,
        materialization: usize,
    ) {
        for _ in 0..100 {
            if repository.orchestration_requests().len() >= orchestration
                && repository.materialization_requests().len() >= materialization
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("drain did not reach {orchestration}/{materialization} attempts")
    }

    #[tokio::test(start_paused = true)]
    async fn simultaneous_pending_queues_share_one_attempt_cap_without_starvation() {
        const ATTEMPT_CAP: usize = 120;

        let repository = Arc::new(DrainRepository::new(false, false));
        let service = drain_service(Arc::clone(&repository));
        retain_submitted_selections(&service);
        let draining = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.drain_pending_custody().await })
        };

        wait_for_attempts(&repository, 1, 1).await;
        for expected in 2..=ATTEMPT_CAP {
            tokio::time::advance(Duration::from_millis(CUSTODY_RETRY_MILLIS)).await;
            wait_for_attempts(&repository, expected, expected).await;
        }
        tokio::time::advance(Duration::from_millis(CUSTODY_RETRY_MILLIS - 1)).await;
        tokio::task::yield_now().await;
        assert_eq!(repository.orchestration_requests().len(), ATTEMPT_CAP);
        assert_eq!(repository.materialization_requests().len(), ATTEMPT_CAP);
        assert!(!draining.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        draining.await.expect("bounded drain joins");

        let orchestration = repository.orchestration_requests();
        let materialization = repository.materialization_requests();
        assert!(orchestration.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(materialization.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(service.custody.has_pending(), "timeout preserves custody");
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_pending_queue_cannot_starve_the_other_direction() {
        for (hang_orchestration, hang_materialization, expected) in
            [(true, false, (2, 1)), (false, true, (2, 2))]
        {
            let repository = Arc::new(DrainRepository::new(
                hang_orchestration,
                hang_materialization,
            ));
            let service = drain_service(Arc::clone(&repository));
            retain_submitted_selections(&service);
            let draining = {
                let service = Arc::clone(&service);
                tokio::spawn(async move { service.drain_pending_custody().await })
            };

            wait_for_attempts(&repository, 1, usize::from(!hang_orchestration)).await;
            tokio::time::advance(Duration::from_millis(CUSTODY_RETRY_MILLIS)).await;
            wait_for_attempts(&repository, expected.0, expected.1).await;
            assert!(
                repository.orchestration_requests().len() >= expected.0
                    && repository.materialization_requests().len() >= expected.1,
                "each direction receives a bounded first attempt",
            );
            draining.abort();
            assert!(
                draining
                    .await
                    .expect_err("drain was aborted")
                    .is_cancelled()
            );
        }
    }

    #[tokio::test]
    async fn all_three_ready_renewals_expire_unpolled_but_submitted_replays_continue() {
        for phase in [
            AutonomousWorkflowPhase::Preparation,
            AutonomousWorkflowPhase::Activation,
            AutonomousWorkflowPhase::Materialization,
        ] {
            let (deadline, _) = watch::channel(Instant::now());
            let deadline = AutonomousWorkflowDeadline { deadline };
            let polls = AtomicUsize::new(0);
            let submission = std::future::poll_fn(|_| {
                polls.fetch_add(1, AtomicOrdering::SeqCst);
                std::task::Poll::Ready(phase)
            });

            assert_eq!(
                await_renewal_submission(false, &CancellationToken::new(), &deadline, submission,)
                    .await,
                Err(AutonomousWorkflowLeaseError::DeadlineElapsed),
            );
            assert_eq!(
                polls.load(AtomicOrdering::SeqCst),
                0,
                "an expired unsubmitted {phase:?} renewal must not be polled",
            );

            let submission = std::future::poll_fn(|_| {
                polls.fetch_add(1, AtomicOrdering::SeqCst);
                std::task::Poll::Ready(phase)
            });
            assert_eq!(
                await_renewal_submission(true, &CancellationToken::new(), &deadline, submission,)
                    .await,
                Ok(phase),
            );
            assert_eq!(
                polls.load(AtomicOrdering::SeqCst),
                1,
                "submitted {phase:?} renewal reconciliation ignores phase expiry",
            );
        }
    }

    #[test]
    fn renewal_duration_rounds_fractional_milliseconds_up_at_the_minimum_boundary() {
        let maximum = MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS;

        assert_eq!(
            renewal_duration_for_remaining(Duration::ZERO, maximum),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS
        );
        assert_eq!(
            renewal_duration_for_remaining(Duration::from_millis(749), maximum),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS
        );
        assert_eq!(
            renewal_duration_for_remaining(
                Duration::from_millis(749) + Duration::from_nanos(999_999),
                maximum,
            ),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS
        );
        assert_eq!(
            renewal_duration_for_remaining(Duration::from_millis(750), maximum),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS
        );
        assert_eq!(
            renewal_duration_for_remaining(
                Duration::from_millis(750) + Duration::from_nanos(1),
                maximum,
            ),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS + 1
        );
        assert_eq!(
            renewal_duration_for_remaining(Duration::from_millis(751), maximum),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS + 1
        );
    }

    #[test]
    fn renewal_duration_clamps_at_the_phase_maximum_without_overflow() {
        for maximum in [
            MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS,
            MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS,
            MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS,
        ] {
            let maximum_boundary =
                u64::try_from(maximum - AUTONOMOUS_WORKFLOW_AUTHORITY_SAFETY_MILLIS - 1_000)
                    .expect("phase maximum boundary is non-negative");

            assert_eq!(
                renewal_duration_for_remaining(
                    Duration::from_millis(maximum_boundary - 1),
                    maximum,
                ),
                maximum - 1
            );
            assert_eq!(
                renewal_duration_for_remaining(
                    Duration::from_millis(maximum_boundary - 1) + Duration::from_nanos(1),
                    maximum,
                ),
                maximum
            );
            assert_eq!(
                renewal_duration_for_remaining(Duration::from_millis(maximum_boundary), maximum),
                maximum
            );
            assert_eq!(
                renewal_duration_for_remaining(
                    Duration::from_millis(maximum_boundary + 1),
                    maximum,
                ),
                maximum
            );
            assert_eq!(
                renewal_duration_for_remaining(Duration::MAX, maximum),
                maximum
            );
        }
    }

    #[test]
    fn renewal_submission_requires_a_strict_durable_interval_extension() {
        let claimed_at = UnixMillis::new(10_000);
        let expires_at = UnixMillis::new(12_000);

        assert_eq!(
            strictly_extending_duration(2_001, claimed_at, expires_at),
            Ok(Some(2_001))
        );
        assert_eq!(
            strictly_extending_duration(2_000, claimed_at, expires_at),
            Ok(None)
        );
        assert_eq!(
            strictly_extending_duration(1_999, claimed_at, expires_at),
            Ok(None)
        );
        assert_eq!(
            strictly_extending_duration(2_000, claimed_at, claimed_at),
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        );
        assert_eq!(
            strictly_extending_duration(
                i64::MAX,
                UnixMillis::new(i64::MIN),
                UnixMillis::new(i64::MAX),
            ),
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        );
    }
}
