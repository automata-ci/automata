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
    Preparation(Box<PhaseCustodySnapshot<PreparationPhase>>),
    Activation(Box<PhaseCustodySnapshot<ActivationPhase>>),
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
            Self::Preparation(state) => match state.as_ref() {
                PhaseCustodySnapshot::Idle => "Idle",
                PhaseCustodySnapshot::Selected { .. } => "Selected([REDACTED])",
                PhaseCustodySnapshot::PendingConsume { submitted, .. } => {
                    if *submitted {
                        "PendingConsume([REDACTED])"
                    } else {
                        "ReadyConsume([REDACTED])"
                    }
                }
                PhaseCustodySnapshot::Active { .. } => "Active([REDACTED])",
                PhaseCustodySnapshot::ReadyFinal { .. } => "ReadyPreparationFinal([REDACTED])",
                PhaseCustodySnapshot::PendingFinal { .. } => "PendingPreparationFinal([REDACTED])",
                PhaseCustodySnapshot::PendingRenew { submitted, .. } => {
                    if *submitted {
                        "PendingRenew([REDACTED])"
                    } else {
                        "ReadyRenew([REDACTED])"
                    }
                }
                PhaseCustodySnapshot::SettledFinalEvidence { .. } => {
                    "SettledFinalEvidence([REDACTED])"
                }
                PhaseCustodySnapshot::Quarantine { submitted, .. } => {
                    if *submitted {
                        "PendingQuarantine([REDACTED])"
                    } else {
                        "ReadyQuarantine([REDACTED])"
                    }
                }
            },
            Self::Activation(state) => match state.as_ref() {
                PhaseCustodySnapshot::Idle => "Idle",
                PhaseCustodySnapshot::Selected { .. } => "Selected([REDACTED])",
                PhaseCustodySnapshot::PendingConsume { submitted, .. } => {
                    if *submitted {
                        "PendingConsume([REDACTED])"
                    } else {
                        "ReadyConsume([REDACTED])"
                    }
                }
                PhaseCustodySnapshot::Active { .. } => "Active([REDACTED])",
                PhaseCustodySnapshot::ReadyFinal { .. } => "ReadyActivationFinal([REDACTED])",
                PhaseCustodySnapshot::PendingFinal { .. } => "PendingActivationFinal([REDACTED])",
                PhaseCustodySnapshot::PendingRenew { submitted, .. } => {
                    if *submitted {
                        "PendingRenew([REDACTED])"
                    } else {
                        "ReadyRenew([REDACTED])"
                    }
                }
                PhaseCustodySnapshot::SettledFinalEvidence { .. } => {
                    "SettledFinalEvidence([REDACTED])"
                }
                PhaseCustodySnapshot::Quarantine { submitted, .. } => {
                    if *submitted {
                        "PendingQuarantine([REDACTED])"
                    } else {
                        "ReadyQuarantine([REDACTED])"
                    }
                }
            },
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
    Phase(Box<PhaseCustodySnapshot<MaterializationPhase>>),
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
            Self::Phase(state) => match state.as_ref() {
                PhaseCustodySnapshot::Idle => "Idle",
                PhaseCustodySnapshot::Selected { .. } => "Selected([REDACTED])",
                PhaseCustodySnapshot::PendingConsume { submitted, .. } => {
                    if *submitted {
                        "PendingConsume([REDACTED])"
                    } else {
                        "ReadyConsume([REDACTED])"
                    }
                }
                PhaseCustodySnapshot::Active { .. } => "Active([REDACTED])",
                PhaseCustodySnapshot::ReadyFinal { .. } => "ReadyFinal([REDACTED])",
                PhaseCustodySnapshot::PendingFinal { .. } => "PendingFinal([REDACTED])",
                PhaseCustodySnapshot::PendingRenew { submitted, .. } => {
                    if *submitted {
                        "PendingRenew([REDACTED])"
                    } else {
                        "ReadyRenew([REDACTED])"
                    }
                }
                PhaseCustodySnapshot::SettledFinalEvidence { .. } => {
                    "SettledFinalEvidence([REDACTED])"
                }
                PhaseCustodySnapshot::Quarantine { submitted, .. } => {
                    if *submitted {
                        "PendingQuarantine([REDACTED])"
                    } else {
                        "ReadyQuarantine([REDACTED])"
                    }
                }
            },
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

    fn has_pending_queue(&self, queue: AutonomousWorkflowQueue) -> bool {
        match queue {
            AutonomousWorkflowQueue::Orchestration => match self.orchestration() {
                OrchestrationCustody::Select {
                    submitted: true, ..
                }
                | OrchestrationCustody::PendingConsume {
                    submitted: true, ..
                }
                | OrchestrationCustody::Quarantine {
                    submitted: true, ..
                } => true,
                OrchestrationCustody::Preparation(state) => matches!(
                    state.as_ref(),
                    PhaseCustodySnapshot::PendingFinal { .. }
                        | PhaseCustodySnapshot::PendingRenew {
                            submitted: true,
                            ..
                        }
                ),
                OrchestrationCustody::Activation(state) => matches!(
                    state.as_ref(),
                    PhaseCustodySnapshot::PendingFinal { .. }
                        | PhaseCustodySnapshot::PendingRenew {
                            submitted: true,
                            ..
                        }
                ),
                _ => false,
            },
            AutonomousWorkflowQueue::Materialization => match self.materialization() {
                MaterializationCustody::Select {
                    submitted: true, ..
                }
                | MaterializationCustody::PendingConsume {
                    submitted: true, ..
                }
                | MaterializationCustody::Quarantine {
                    submitted: true, ..
                } => true,
                MaterializationCustody::Phase(state) => matches!(
                    state.as_ref(),
                    PhaseCustodySnapshot::PendingFinal { .. }
                        | PhaseCustodySnapshot::PendingRenew {
                            submitted: true,
                            ..
                        }
                ),
                _ => false,
            },
        }
    }

    fn has_pending(&self) -> bool {
        self.has_pending_queue(AutonomousWorkflowQueue::Orchestration)
            || self.has_pending_queue(AutonomousWorkflowQueue::Materialization)
    }
}

type PhaseFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type PhaseExecutionDisposition = Result<
    Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
    AutonomousWorkflowLeaseError,
>;

#[derive(Clone, Copy)]
struct PreparationPhase;

#[derive(Clone, Copy)]
struct ActivationPhase;

#[derive(Clone, Copy)]
struct MaterializationPhase;

#[derive(Clone, Copy)]
enum RenewalSubmission {
    Acknowledged(ExpectedRenewalSuccessor),
    Operation,
}

enum PhaseCustodyTransition<P: AutonomousPhaseAdapter> {
    BeginRevalidation {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::Consume,
    },
    RetainReadyConsume {
        request: P::Consume,
        deadline: AutonomousWorkflowDeadline,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    },
    MarkConsumeSubmitted {
        request: P::Consume,
    },
    ReplaceActive {
        request: P::Consume,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
    },
    BeginRenewal {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::Renewal,
    },
    MarkRenewalSubmitted {
        consumed: P::Consumed,
        request: P::Renewal,
    },
    ClearExpiredUnsubmittedRenewal {
        consumed: P::Consumed,
        request: P::Renewal,
    },
    SelectAfterRenewal {
        consumed: P::Consumed,
        renewal: P::Renewal,
        request: P::Consume,
        deadline: AutonomousWorkflowDeadline,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    },
    RetainReadyFinal {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::ReadyFinal,
    },
    BeginFinalSubmission {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::ReadyFinal,
    },
    BeginFinalQuarantine {
        consumed: P::Consumed,
        request: P::ReadyFinal,
        quarantine: P::Quarantine,
    },
    BeginActiveQuarantine {
        consumed: P::Consumed,
        quarantine: P::Quarantine,
    },
    ResumeSettledFinalQuarantine {
        consumed: P::Consumed,
        quarantine: P::Quarantine,
    },
    SettleFinalEvidence {
        consumed: P::Consumed,
        request: P::ReadyFinal,
        kind: LogicalWorkQuarantineKind,
    },
    ClearSelected {
        request: P::Consume,
    },
    ClearConsume {
        request: P::Consume,
    },
    ClearRenewal {
        consumed: P::Consumed,
        request: P::Renewal,
    },
    ClearActive {
        consumed: P::Consumed,
    },
    ClearReadyFinal {
        consumed: P::Consumed,
        request: P::ReadyFinal,
    },
    ClearFinal {
        consumed: P::Consumed,
        request: P::ReadyFinal,
    },
}

enum PhaseCustodyTransitionOutcome {
    Applied,
    ConsumeSubmitted(Instant),
}

#[derive(Clone)]
enum PhaseCustodySnapshot<P: AutonomousPhaseAdapter> {
    Idle,
    Selected {
        request: P::Consume,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    },
    PendingConsume {
        request: P::Consume,
        operation_started: Option<Instant>,
        deadline: Option<AutonomousWorkflowDeadline>,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        submitted: bool,
    },
    Active {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
    },
    ReadyFinal {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::ReadyFinal,
    },
    PendingFinal {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::ReadyFinal,
    },
    PendingRenew {
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::Renewal,
        submitted: bool,
    },
    SettledFinalEvidence {
        consumed: P::Consumed,
        kind: LogicalWorkQuarantineKind,
    },
    Quarantine {
        request: P::Quarantine,
        submitted: bool,
    },
}

#[allow(clippy::too_many_lines)] // The typed state machine keeps every exact custody edge visible.
fn transition_phase_custody<P: AutonomousPhaseAdapter>(
    state: PhaseCustodySnapshot<P>,
    transition: PhaseCustodyTransition<P>,
) -> Result<(PhaseCustodySnapshot<P>, PhaseCustodyTransitionOutcome), AutonomousWorkflowLeaseError>
{
    let applied = PhaseCustodyTransitionOutcome::Applied;
    match (state, transition) {
        (
            PhaseCustodySnapshot::Active {
                consumed: active, ..
            },
            PhaseCustodyTransition::BeginRevalidation {
                consumed,
                deadline,
                request,
            },
        ) if active == consumed && P::authority(&consumed).is_some() => Ok((
            PhaseCustodySnapshot::Selected {
                request,
                deadline: Some(deadline),
                expected_successor: None,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::Selected {
                request: selected, ..
            },
            PhaseCustodyTransition::RetainReadyConsume {
                request,
                deadline,
                expected_successor,
            },
        ) if selected == request => Ok((
            PhaseCustodySnapshot::PendingConsume {
                request,
                operation_started: None,
                deadline: Some(deadline),
                expected_successor,
                submitted: false,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::PendingConsume {
                request: pending,
                operation_started: _,
                deadline,
                expected_successor,
                submitted: false,
            },
            PhaseCustodyTransition::MarkConsumeSubmitted { request },
        ) if pending == request => {
            let operation_started = Instant::now();
            Ok((
                PhaseCustodySnapshot::PendingConsume {
                    request,
                    operation_started: Some(operation_started),
                    deadline,
                    expected_successor,
                    submitted: true,
                },
                PhaseCustodyTransitionOutcome::ConsumeSubmitted(operation_started),
            ))
        }
        (
            PhaseCustodySnapshot::PendingConsume {
                request: pending,
                submitted: true,
                ..
            },
            PhaseCustodyTransition::ReplaceActive {
                request,
                consumed,
                deadline,
            },
        ) if pending == request && P::authority(&consumed).is_some() => {
            Ok((PhaseCustodySnapshot::Active { consumed, deadline }, applied))
        }
        (
            PhaseCustodySnapshot::Active {
                consumed: active, ..
            },
            PhaseCustodyTransition::BeginRenewal {
                consumed,
                deadline,
                request,
            },
        ) if active == consumed && P::authority(&consumed).is_some() => Ok((
            PhaseCustodySnapshot::PendingRenew {
                consumed,
                deadline,
                request,
                submitted: false,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::PendingRenew {
                consumed: active,
                deadline,
                request: pending,
                submitted: false,
            },
            PhaseCustodyTransition::MarkRenewalSubmitted { consumed, request },
        ) if active == consumed && pending == request => Ok((
            PhaseCustodySnapshot::PendingRenew {
                consumed,
                deadline,
                request,
                submitted: true,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::PendingRenew {
                consumed: active,
                deadline,
                request: pending,
                submitted,
            },
            PhaseCustodyTransition::ClearExpiredUnsubmittedRenewal { consumed, request },
        ) if active == consumed && pending == request => {
            let state = if submitted {
                PhaseCustodySnapshot::PendingRenew {
                    consumed,
                    deadline,
                    request,
                    submitted,
                }
            } else {
                PhaseCustodySnapshot::Idle
            };
            Ok((state, applied))
        }
        (
            PhaseCustodySnapshot::PendingRenew {
                consumed: active,
                request: pending,
                submitted: true,
                ..
            },
            PhaseCustodyTransition::SelectAfterRenewal {
                consumed,
                renewal,
                request,
                deadline,
                expected_successor,
            },
        ) if active == consumed && pending == renewal => Ok((
            PhaseCustodySnapshot::Selected {
                request,
                deadline: Some(deadline),
                expected_successor,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::Active {
                consumed: active, ..
            },
            PhaseCustodyTransition::RetainReadyFinal {
                consumed,
                deadline,
                request,
            },
        ) if active == consumed
            && P::authority(&consumed)
                .is_some_and(|authority| P::ready_matches_authority(&request, authority)) =>
        {
            Ok((
                PhaseCustodySnapshot::ReadyFinal {
                    consumed,
                    deadline,
                    request,
                },
                applied,
            ))
        }
        (
            PhaseCustodySnapshot::ReadyFinal {
                consumed: active,
                request: ready,
                ..
            },
            PhaseCustodyTransition::BeginFinalSubmission {
                consumed,
                deadline,
                request,
            },
        ) if active == consumed && ready == request => Ok((
            PhaseCustodySnapshot::PendingFinal {
                consumed,
                deadline,
                request,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::PendingFinal {
                consumed: active,
                request: pending,
                ..
            },
            PhaseCustodyTransition::BeginFinalQuarantine {
                consumed,
                request,
                quarantine,
            },
        ) if active == consumed && pending == request => Ok((
            PhaseCustodySnapshot::Quarantine {
                request: quarantine,
                submitted: false,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::Active {
                consumed: active, ..
            },
            PhaseCustodyTransition::BeginActiveQuarantine {
                consumed,
                quarantine,
            },
        ) if active == consumed => Ok((
            PhaseCustodySnapshot::Quarantine {
                request: quarantine,
                submitted: false,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::SettledFinalEvidence {
                consumed: settled, ..
            },
            PhaseCustodyTransition::ResumeSettledFinalQuarantine {
                consumed,
                quarantine,
            },
        ) if settled == consumed => Ok((
            PhaseCustodySnapshot::Quarantine {
                request: quarantine,
                submitted: false,
            },
            applied,
        )),
        (
            PhaseCustodySnapshot::PendingFinal {
                consumed: active,
                request: pending,
                ..
            },
            PhaseCustodyTransition::SettleFinalEvidence {
                consumed,
                request,
                kind,
            },
        ) if active == consumed && pending == request => Ok((
            PhaseCustodySnapshot::SettledFinalEvidence { consumed, kind },
            applied,
        )),
        (
            PhaseCustodySnapshot::Selected {
                request: selected, ..
            },
            PhaseCustodyTransition::ClearSelected { request },
        ) if selected == request => Ok((PhaseCustodySnapshot::Idle, applied)),
        (
            PhaseCustodySnapshot::PendingConsume {
                request: pending, ..
            },
            PhaseCustodyTransition::ClearConsume { request },
        ) if pending == request => Ok((PhaseCustodySnapshot::Idle, applied)),
        (
            PhaseCustodySnapshot::PendingRenew {
                consumed: active,
                request: pending,
                ..
            },
            PhaseCustodyTransition::ClearRenewal { consumed, request },
        ) if active == consumed && pending == request => Ok((PhaseCustodySnapshot::Idle, applied)),
        (
            PhaseCustodySnapshot::Active {
                consumed: active, ..
            },
            PhaseCustodyTransition::ClearActive { consumed },
        ) if active == consumed => Ok((PhaseCustodySnapshot::Idle, applied)),
        (
            PhaseCustodySnapshot::ReadyFinal {
                consumed: active,
                request: ready,
                ..
            },
            PhaseCustodyTransition::ClearReadyFinal { consumed, request },
        ) if active == consumed && ready == request => Ok((PhaseCustodySnapshot::Idle, applied)),
        (
            PhaseCustodySnapshot::PendingFinal {
                consumed: active,
                request: pending,
                ..
            },
            PhaseCustodyTransition::ClearFinal { consumed, request },
        ) if active == consumed && pending == request => Ok((PhaseCustodySnapshot::Idle, applied)),
        _ => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
    }
}

trait AutonomousPhaseAdapter: Clone + Copy + Send + Sync + 'static {
    type Consumed: Clone + Eq + Send + 'static;
    type Authority: Sync;
    type Consume: Clone + Eq + Send + 'static;
    type Renewal: Clone + Eq + Send + 'static;
    type ReadyFinal: Clone + Eq + Send + 'static;
    type Quarantine: Clone + Eq + Send + 'static;
    type Repository: ?Sized + fmt::Debug + Send + Sync + 'static;
    type Lease: Send;

    const PHASE: AutonomousWorkflowPhase;
    const QUEUE: AutonomousWorkflowQueue;
    const MAX_RENEWAL_MILLIS: i64;

    fn authority(consumed: &Self::Consumed) -> Option<&Self::Authority>;
    fn claim_interval(authority: &Self::Authority) -> (UnixMillis, UnixMillis);
    fn validated_interval(consumed: &Self::Consumed) -> (UnixMillis, UnixMillis);
    fn consume_request(consumed: &Self::Consumed) -> Self::Consume;
    fn consumed_matches(
        consumed: &Self::Consumed,
        request: &Self::Consume,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    ) -> bool;
    fn make_renewal(
        authority: &Self::Authority,
        duration_ms: i64,
    ) -> Result<Self::Renewal, AutonomousWorkflowLeaseError>;
    fn submit_renewal(
        repository: &Self::Repository,
        request: Self::Renewal,
    ) -> PhaseFuture<'_, Result<RenewalSubmission, AutonomousWorkflowLeaseError>>;
    fn consume_selected(
        selections: &dyn LogicalWorkSelectionRepository,
        request: Self::Consume,
    ) -> PhaseFuture<'_, Result<Self::Consumed, automata_ci_store::LogicalWorkSelectionStoreError>>;
    fn ready_matches_authority(request: &Self::ReadyFinal, authority: &Self::Authority) -> bool;
    fn quarantine_request(
        consumed: Self::Consumed,
        kind: LogicalWorkQuarantineKind,
    ) -> Self::Quarantine;

    fn transition(
        custody: &AutonomousWorkflowCustody,
        transition: PhaseCustodyTransition<Self>,
    ) -> Result<PhaseCustodyTransitionOutcome, AutonomousWorkflowLeaseError>;
    fn snapshot(custody: &AutonomousWorkflowCustody) -> Option<PhaseCustodySnapshot<Self>>;

    fn repository(service: &AutonomousWorkflowService) -> Arc<Self::Repository>;
    fn continue_consume<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Consume,
        deadline: AutonomousWorkflowDeadline,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>>;
    fn submit_quarantine<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Quarantine,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>>;

    fn lease_from_core(core: PhaseLeaseCore<Self>) -> Self::Lease;
    fn into_core(lease: Self::Lease) -> PhaseLeaseCore<Self>;
    fn execute<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a mut Self::Lease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a>;
    fn submit_final<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a Self::Lease,
    ) -> AutonomousWorkflowExecutionFuture<'a>;
}

fn expect_applied(
    outcome: &PhaseCustodyTransitionOutcome,
) -> Result<(), AutonomousWorkflowLeaseError> {
    match outcome {
        PhaseCustodyTransitionOutcome::Applied => Ok(()),
        PhaseCustodyTransitionOutcome::ConsumeSubmitted(_) => {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
    }
}

fn apply_service_transition<P: AutonomousPhaseAdapter>(
    custody: &AutonomousWorkflowCustody,
    transition: PhaseCustodyTransition<P>,
) -> Result<(), AutonomousWorkflowError> {
    let outcome = P::transition(custody, transition)
        .map_err(|_| AutonomousWorkflowError::AuthorityRejected)?;
    expect_applied(&outcome).map_err(|_| AutonomousWorkflowError::AuthorityRejected)
}

struct PhaseLeaseCore<P: AutonomousPhaseAdapter> {
    selections: Arc<dyn LogicalWorkSelectionRepository>,
    repository: Arc<P::Repository>,
    consumed: P::Consumed,
    deadline: AutonomousWorkflowDeadline,
    custody: Arc<AutonomousWorkflowCustody>,
}

impl<P: AutonomousPhaseAdapter> PhaseLeaseCore<P> {
    fn new(
        selections: Arc<dyn LogicalWorkSelectionRepository>,
        repository: Arc<P::Repository>,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        custody: Arc<AutonomousWorkflowCustody>,
    ) -> Self {
        Self {
            selections,
            repository,
            consumed,
            deadline,
            custody,
        }
    }

    fn authority(&self) -> &P::Authority {
        P::authority(&self.consumed)
            .unwrap_or_else(|| unreachable!("lease construction fixes the authority phase"))
    }

    const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        &self.deadline
    }

    fn before_io(&self, shutdown: &CancellationToken) -> Result<(), AutonomousWorkflowLeaseError> {
        self.deadline.checkpoint(shutdown)
    }

    fn retain_ready_final(
        &self,
        request: P::ReadyFinal,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        if !P::ready_matches_authority(&request, self.authority()) {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        expect_applied(&P::transition(
            &self.custody,
            PhaseCustodyTransition::RetainReadyFinal {
                consumed: self.consumed.clone(),
                deadline: self.deadline.clone(),
                request,
            },
        )?)
    }

    fn pending_final_request(&self) -> Result<P::ReadyFinal, AutonomousWorkflowLeaseError> {
        let Some(PhaseCustodySnapshot::PendingFinal {
            consumed, request, ..
        }) = P::snapshot(&self.custody)
        else {
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        };
        if consumed == self.consumed && P::ready_matches_authority(&request, self.authority()) {
            Ok(request)
        } else {
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
        }
    }

    async fn renew(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        self.before_io(shutdown)?;
        let (claimed_at, expires_at) = P::claim_interval(self.authority());
        let Some(duration_ms) = extending_renewal_duration(
            &self.deadline,
            P::MAX_RENEWAL_MILLIS,
            claimed_at,
            expires_at,
        )?
        else {
            return self.revalidate(shutdown).await;
        };
        let request = P::make_renewal(self.authority(), duration_ms)?;
        expect_applied(&P::transition(
            &self.custody,
            PhaseCustodyTransition::BeginRenewal {
                consumed: self.consumed.clone(),
                deadline: self.deadline.clone(),
                request: request.clone(),
            },
        )?)?;
        let submission = async {
            expect_applied(&P::transition(
                &self.custody,
                PhaseCustodyTransition::MarkRenewalSubmitted {
                    consumed: self.consumed.clone(),
                    request: request.clone(),
                },
            )?)?;
            Ok::<_, AutonomousWorkflowLeaseError>(
                P::submit_renewal(self.repository.as_ref(), request.clone()).await,
            )
        };
        let result = match await_bounded(shutdown, &self.deadline, submission).await {
            Ok(Ok(result)) => match result {
                Ok(result) => result,
                Err(error) => {
                    expect_applied(&P::transition(
                        &self.custody,
                        PhaseCustodyTransition::ClearRenewal {
                            consumed: self.consumed.clone(),
                            request,
                        },
                    )?)?;
                    return Err(error);
                }
            },
            Ok(Err(error)) | Err(error) => return Err(error),
        };
        let (outcome, expected_successor) = match result {
            RenewalSubmission::Acknowledged(successor) => {
                (AutonomousWorkflowRenewalOutcome::Renewed, Some(successor))
            }
            RenewalSubmission::Operation => (AutonomousWorkflowRenewalOutcome::Reconciled, None),
        };
        let reconcile = P::consume_request(&self.consumed);
        expect_applied(&P::transition(
            &self.custody,
            PhaseCustodyTransition::SelectAfterRenewal {
                consumed: self.consumed.clone(),
                renewal: request,
                request: reconcile.clone(),
                deadline: self.deadline.clone(),
                expected_successor,
            },
        )?)?;
        self.reconcile(reconcile, expected_successor, shutdown)
            .await?;
        Ok(outcome)
    }

    async fn revalidate(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<AutonomousWorkflowRenewalOutcome, AutonomousWorkflowLeaseError> {
        let request = P::consume_request(&self.consumed);
        expect_applied(&P::transition(
            &self.custody,
            PhaseCustodyTransition::BeginRevalidation {
                consumed: self.consumed.clone(),
                deadline: self.deadline.clone(),
                request: request.clone(),
            },
        )?)?;
        self.reconcile(request, None, shutdown).await?;
        Ok(AutonomousWorkflowRenewalOutcome::Revalidated)
    }

    async fn reconcile(
        &mut self,
        request: P::Consume,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &CancellationToken,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        if let Err(error) = self.deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                expect_applied(&P::transition(
                    &self.custody,
                    PhaseCustodyTransition::ClearSelected {
                        request: request.clone(),
                    },
                )?)?;
            }
            return Err(error);
        }
        expect_applied(&P::transition(
            &self.custody,
            PhaseCustodyTransition::RetainReadyConsume {
                request: request.clone(),
                deadline: self.deadline.clone(),
                expected_successor,
            },
        )?)?;
        let submitted_request = request.clone();
        let submission = async {
            let operation_started = match P::transition(
                &self.custody,
                PhaseCustodyTransition::MarkConsumeSubmitted {
                    request: submitted_request.clone(),
                },
            )? {
                PhaseCustodyTransitionOutcome::ConsumeSubmitted(started) => started,
                PhaseCustodyTransitionOutcome::Applied => {
                    return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
                }
            };
            let result = P::consume_selected(self.selections.as_ref(), submitted_request).await;
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
                expect_applied(&P::transition(
                    &self.custody,
                    PhaseCustodyTransition::ClearConsume {
                        request: request.clone(),
                    },
                )?)?;
                return Err(map_reconcile_error(&error));
            }
        };
        if !P::consumed_matches(&consumed, &request, expected_successor) {
            expect_applied(&P::transition(
                &self.custody,
                PhaseCustodyTransition::ClearConsume {
                    request: request.clone(),
                },
            )?)?;
            return Err(AutonomousWorkflowLeaseError::AuthorityRejected);
        }
        self.replace(request, consumed, operation_started)
    }

    fn replace(
        &mut self,
        request: P::Consume,
        consumed: P::Consumed,
        operation_started: Instant,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        let (validated_at, expires_at) = P::validated_interval(&consumed);
        if let Err(error) = self
            .deadline
            .tighten(operation_started, validated_at, expires_at)
        {
            expect_applied(&P::transition(
                &self.custody,
                PhaseCustodyTransition::ClearConsume { request },
            )?)?;
            return Err(error);
        }
        expect_applied(&P::transition(
            &self.custody,
            PhaseCustodyTransition::ReplaceActive {
                request,
                consumed: consumed.clone(),
                deadline: self.deadline.clone(),
            },
        )?)?;
        self.consumed = consumed;
        Ok(())
    }
}

fn ready_phase_final<P: AutonomousPhaseAdapter>(
    custody: &AutonomousWorkflowCustody,
    consumed: &P::Consumed,
) -> Option<(AutonomousWorkflowDeadline, P::ReadyFinal)> {
    match P::snapshot(custody) {
        Some(PhaseCustodySnapshot::ReadyFinal {
            consumed: active,
            deadline,
            request,
        }) if &active == consumed => Some((deadline, request)),
        _ => None,
    }
}

/// Worker-owned capability for one consumed preparation claim.
pub struct AutonomousPreparationLease {
    core: PhaseLeaseCore<PreparationPhase>,
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
        self.core.authority()
    }

    pub(crate) fn retain_ready_final(
        &self,
        request: ReadyLogicalActivationPreparation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        self.core.retain_ready_final(request)
    }

    pub(crate) fn pending_final_request(
        &self,
    ) -> Result<ReadyLogicalActivationPreparation, AutonomousWorkflowLeaseError> {
        self.core.pending_final_request()
    }

    /// Returns the cumulative monotonic phase deadline.
    #[must_use]
    pub const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        self.core.deadline()
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
        self.core.before_io(shutdown)
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
        self.core.renew(shutdown).await
    }
}

/// Worker-owned capability for one consumed activation claim.
pub struct AutonomousActivationLease {
    core: PhaseLeaseCore<ActivationPhase>,
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
        self.core.authority()
    }

    pub(crate) fn retain_ready_final(
        &self,
        request: ReadyLogicalJobActivation,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        self.core.retain_ready_final(request)
    }

    pub(crate) fn pending_final_request(
        &self,
    ) -> Result<ReadyLogicalJobActivation, AutonomousWorkflowLeaseError> {
        self.core.pending_final_request()
    }

    /// Returns the cumulative monotonic phase deadline.
    #[must_use]
    pub const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        self.core.deadline()
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
        self.core.before_io(shutdown)
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
        self.core.renew(shutdown).await
    }
}

/// Worker-owned capability for one consumed materialization claim.
pub struct AutonomousMaterializationLease {
    core: PhaseLeaseCore<MaterializationPhase>,
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
        self.core.consumed.authority()
    }

    pub(crate) fn retain_ready_final(
        &self,
        request: ReadyLogicalInstanceMaterialization,
    ) -> Result<(), AutonomousWorkflowLeaseError> {
        self.core.retain_ready_final(request)
    }

    pub(crate) fn pending_final_request(
        &self,
    ) -> Result<ReadyLogicalInstanceMaterialization, AutonomousWorkflowLeaseError> {
        self.core.pending_final_request()
    }

    /// Returns the cumulative monotonic phase deadline.
    #[must_use]
    pub const fn deadline(&self) -> &AutonomousWorkflowDeadline {
        self.core.deadline()
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
        self.core.before_io(shutdown)
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
        self.core.renew(shutdown).await
    }
}

trait OrchestrationPhaseAdapter:
    AutonomousPhaseAdapter<
        Consumed = ConsumedSelectedLogicalJobOrchestration,
        Consume = ConsumeSelectedLogicalJobOrchestration,
        Quarantine = QuarantineLogicalJobOrchestration,
    >
{
    fn decode_specific(state: OrchestrationCustody) -> Option<PhaseCustodySnapshot<Self>>;
    fn encode_specific(state: PhaseCustodySnapshot<Self>) -> OrchestrationCustody;
}

fn decode_orchestration_phase<P: OrchestrationPhaseAdapter>(
    state: OrchestrationCustody,
) -> Option<PhaseCustodySnapshot<P>> {
    match state {
        OrchestrationCustody::Idle => Some(PhaseCustodySnapshot::Idle),
        OrchestrationCustody::Selected {
            request,
            deadline,
            expected_successor,
        } => Some(PhaseCustodySnapshot::Selected {
            request: *request,
            deadline,
            expected_successor,
        }),
        OrchestrationCustody::PendingConsume {
            request,
            operation_started,
            deadline,
            expected_successor,
            submitted,
        } => Some(PhaseCustodySnapshot::PendingConsume {
            request: *request,
            operation_started,
            deadline,
            expected_successor,
            submitted,
        }),
        OrchestrationCustody::Quarantine { request, submitted } => {
            Some(PhaseCustodySnapshot::Quarantine {
                request: *request,
                submitted,
            })
        }
        specific => P::decode_specific(specific),
    }
}

fn encode_orchestration_phase<P: OrchestrationPhaseAdapter>(
    state: PhaseCustodySnapshot<P>,
) -> OrchestrationCustody {
    match state {
        PhaseCustodySnapshot::Idle => OrchestrationCustody::Idle,
        PhaseCustodySnapshot::Selected {
            request,
            deadline,
            expected_successor,
        } => OrchestrationCustody::Selected {
            request: Box::new(request),
            deadline,
            expected_successor,
        },
        PhaseCustodySnapshot::PendingConsume {
            request,
            operation_started,
            deadline,
            expected_successor,
            submitted,
        } => OrchestrationCustody::PendingConsume {
            request: Box::new(request),
            operation_started,
            deadline,
            expected_successor,
            submitted,
        },
        PhaseCustodySnapshot::Quarantine { request, submitted } => {
            OrchestrationCustody::Quarantine {
                request: Box::new(request),
                submitted,
            }
        }
        specific => P::encode_specific(specific),
    }
}

fn transition_orchestration_phase<P: OrchestrationPhaseAdapter>(
    custody: &AutonomousWorkflowCustody,
    transition: PhaseCustodyTransition<P>,
) -> Result<PhaseCustodyTransitionOutcome, AutonomousWorkflowLeaseError> {
    let mut state = custody
        .orchestration
        .lock()
        .expect("custody lock is not poisoned");
    let current = decode_orchestration_phase::<P>(state.clone())
        .ok_or(AutonomousWorkflowLeaseError::AuthorityRejected)?;
    let (next, outcome) = transition_phase_custody(current, transition)?;
    *state = encode_orchestration_phase::<P>(next);
    Ok(outcome)
}

impl OrchestrationPhaseAdapter for PreparationPhase {
    fn decode_specific(state: OrchestrationCustody) -> Option<PhaseCustodySnapshot<Self>> {
        match state {
            OrchestrationCustody::Preparation(state) => Some(*state),
            _ => None,
        }
    }

    fn encode_specific(state: PhaseCustodySnapshot<Self>) -> OrchestrationCustody {
        OrchestrationCustody::Preparation(Box::new(state))
    }
}
impl OrchestrationPhaseAdapter for ActivationPhase {
    fn decode_specific(state: OrchestrationCustody) -> Option<PhaseCustodySnapshot<Self>> {
        match state {
            OrchestrationCustody::Activation(state) => Some(*state),
            _ => None,
        }
    }

    fn encode_specific(state: PhaseCustodySnapshot<Self>) -> OrchestrationCustody {
        OrchestrationCustody::Activation(Box::new(state))
    }
}
fn decode_materialization_phase(
    state: MaterializationCustody,
) -> Option<PhaseCustodySnapshot<MaterializationPhase>> {
    match state {
        MaterializationCustody::Idle => Some(PhaseCustodySnapshot::Idle),
        MaterializationCustody::Selected {
            request,
            deadline,
            expected_successor,
        } => Some(PhaseCustodySnapshot::Selected {
            request: *request,
            deadline,
            expected_successor,
        }),
        MaterializationCustody::PendingConsume {
            request,
            operation_started,
            deadline,
            expected_successor,
            submitted,
        } => Some(PhaseCustodySnapshot::PendingConsume {
            request: *request,
            operation_started,
            deadline,
            expected_successor,
            submitted,
        }),
        MaterializationCustody::Phase(state) => Some(*state),
        MaterializationCustody::Quarantine { request, submitted } => {
            Some(PhaseCustodySnapshot::Quarantine {
                request: *request,
                submitted,
            })
        }
        MaterializationCustody::Select { .. } => None,
    }
}

fn encode_materialization_phase(
    state: PhaseCustodySnapshot<MaterializationPhase>,
) -> MaterializationCustody {
    match state {
        PhaseCustodySnapshot::Idle => MaterializationCustody::Idle,
        PhaseCustodySnapshot::Selected {
            request,
            deadline,
            expected_successor,
        } => MaterializationCustody::Selected {
            request: Box::new(request),
            deadline,
            expected_successor,
        },
        PhaseCustodySnapshot::PendingConsume {
            request,
            operation_started,
            deadline,
            expected_successor,
            submitted,
        } => MaterializationCustody::PendingConsume {
            request: Box::new(request),
            operation_started,
            deadline,
            expected_successor,
            submitted,
        },
        PhaseCustodySnapshot::Quarantine { request, submitted } => {
            MaterializationCustody::Quarantine {
                request: Box::new(request),
                submitted,
            }
        }
        phase => MaterializationCustody::Phase(Box::new(phase)),
    }
}
fn transition_materialization_phase(
    custody: &AutonomousWorkflowCustody,
    transition: PhaseCustodyTransition<MaterializationPhase>,
) -> Result<PhaseCustodyTransitionOutcome, AutonomousWorkflowLeaseError> {
    let mut state = custody
        .materialization
        .lock()
        .expect("custody lock is not poisoned");
    let current = decode_materialization_phase(state.clone())
        .ok_or(AutonomousWorkflowLeaseError::AuthorityRejected)?;
    let (next, outcome) = transition_phase_custody(current, transition)?;
    *state = encode_materialization_phase(next);
    Ok(outcome)
}

impl AutonomousPhaseAdapter for PreparationPhase {
    type Consumed = ConsumedSelectedLogicalJobOrchestration;
    type Authority = ClaimedLogicalActivationPreparation;
    type Consume = ConsumeSelectedLogicalJobOrchestration;
    type Renewal = RenewLogicalActivationPreparation;
    type ReadyFinal = ReadyLogicalActivationPreparation;
    type Quarantine = QuarantineLogicalJobOrchestration;
    type Repository = dyn LogicalActivationPreparationStore;
    type Lease = AutonomousPreparationLease;

    const PHASE: AutonomousWorkflowPhase = AutonomousWorkflowPhase::Preparation;
    const QUEUE: AutonomousWorkflowQueue = AutonomousWorkflowQueue::Orchestration;
    const MAX_RENEWAL_MILLIS: i64 = MAX_LOGICAL_ACTIVATION_PREPARATION_CLAIM_MILLIS;

    fn authority(consumed: &Self::Consumed) -> Option<&Self::Authority> {
        match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(authority) => Some(authority),
            ConsumedLogicalJobOrchestrationAuthority::Activation(_) => None,
        }
    }

    fn claim_interval(authority: &Self::Authority) -> (UnixMillis, UnixMillis) {
        (
            authority.claim().claimed_at(),
            authority.claim().expires_at(),
        )
    }

    fn validated_interval(consumed: &Self::Consumed) -> (UnixMillis, UnixMillis) {
        orchestration_interval(consumed)
    }

    fn consume_request(consumed: &Self::Consumed) -> Self::Consume {
        ConsumeSelectedLogicalJobOrchestration::new(consumed.selected().clone())
    }

    fn consumed_matches(
        consumed: &Self::Consumed,
        request: &Self::Consume,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    ) -> bool {
        consumed.selected() == request.selected()
            && matches!(
                consumed.authority(),
                ConsumedLogicalJobOrchestrationAuthority::Preparation(_)
            )
            && expected_successor.is_none_or(|expected| expected.matches_orchestration(consumed))
    }

    fn make_renewal(
        authority: &Self::Authority,
        duration_ms: i64,
    ) -> Result<Self::Renewal, AutonomousWorkflowLeaseError> {
        RenewLogicalActivationPreparation::new(authority.claim().clone(), duration_ms)
            .map_err(|_| AutonomousWorkflowLeaseError::Unavailable)
    }

    fn submit_renewal(
        repository: &Self::Repository,
        request: Self::Renewal,
    ) -> PhaseFuture<'_, Result<RenewalSubmission, AutonomousWorkflowLeaseError>> {
        Box::pin(async move {
            match repository
                .renew_logical_activation_preparation(request.clone())
                .await
            {
                Ok(acknowledgement) if acknowledgement.request() == &request => Ok(
                    RenewalSubmission::Acknowledged(ExpectedRenewalSuccessor::new(
                        Self::PHASE,
                        acknowledgement.successor_generation().get(),
                        acknowledgement.successor_claimed_at(),
                        acknowledgement.successor_expires_at(),
                    )),
                ),
                Err(LogicalActivationPreparationStoreError::Store(StoreError::Operation(_))) => {
                    Ok(RenewalSubmission::Operation)
                }
                Ok(_) | Err(_) => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
            }
        })
    }

    fn consume_selected(
        selections: &dyn LogicalWorkSelectionRepository,
        request: Self::Consume,
    ) -> PhaseFuture<'_, Result<Self::Consumed, automata_ci_store::LogicalWorkSelectionStoreError>>
    {
        Box::pin(async move {
            selections
                .consume_selected_logical_job_orchestration(request)
                .await
        })
    }

    fn ready_matches_authority(request: &Self::ReadyFinal, authority: &Self::Authority) -> bool {
        request.matches_authority(authority)
    }

    fn quarantine_request(
        consumed: Self::Consumed,
        kind: LogicalWorkQuarantineKind,
    ) -> Self::Quarantine {
        QuarantineLogicalJobOrchestration::new(consumed, kind)
    }

    fn transition(
        custody: &AutonomousWorkflowCustody,
        transition: PhaseCustodyTransition<Self>,
    ) -> Result<PhaseCustodyTransitionOutcome, AutonomousWorkflowLeaseError> {
        transition_orchestration_phase::<Self>(custody, transition)
    }

    fn snapshot(custody: &AutonomousWorkflowCustody) -> Option<PhaseCustodySnapshot<Self>> {
        decode_orchestration_phase::<Self>(custody.orchestration())
    }
    fn repository(service: &AutonomousWorkflowService) -> Arc<Self::Repository> {
        Arc::clone(&service.preparations)
    }

    fn continue_consume<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Consume,
        deadline: AutonomousWorkflowDeadline,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>> {
        Box::pin(service.start_orchestration_consume(
            request,
            Some(deadline),
            expected_successor,
            shutdown,
            true,
        ))
    }

    fn submit_quarantine<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Quarantine,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>> {
        Box::pin(service.submit_orchestration_quarantine(request, shutdown, false))
    }

    fn lease_from_core(core: PhaseLeaseCore<Self>) -> Self::Lease {
        AutonomousPreparationLease { core }
    }

    fn into_core(lease: Self::Lease) -> PhaseLeaseCore<Self> {
        lease.core
    }

    fn execute<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a mut Self::Lease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        executor.execute_preparation(lease, shutdown, deadline)
    }

    fn submit_final<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a Self::Lease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        executor.submit_preparation_final(lease)
    }
}

impl AutonomousPhaseAdapter for ActivationPhase {
    type Consumed = ConsumedSelectedLogicalJobOrchestration;
    type Authority = ClaimedLogicalJobActivation;
    type Consume = ConsumeSelectedLogicalJobOrchestration;
    type Renewal = RenewLogicalJobActivation;
    type ReadyFinal = ReadyLogicalJobActivation;
    type Quarantine = QuarantineLogicalJobOrchestration;
    type Repository = dyn LogicalActivationRepository;
    type Lease = AutonomousActivationLease;

    const PHASE: AutonomousWorkflowPhase = AutonomousWorkflowPhase::Activation;
    const QUEUE: AutonomousWorkflowQueue = AutonomousWorkflowQueue::Orchestration;
    const MAX_RENEWAL_MILLIS: i64 = MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS;

    fn authority(consumed: &Self::Consumed) -> Option<&Self::Authority> {
        match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => None,
            ConsumedLogicalJobOrchestrationAuthority::Activation(authority) => Some(authority),
        }
    }

    fn claim_interval(authority: &Self::Authority) -> (UnixMillis, UnixMillis) {
        (
            authority.claim().claimed_at(),
            authority.claim().expires_at(),
        )
    }

    fn validated_interval(consumed: &Self::Consumed) -> (UnixMillis, UnixMillis) {
        orchestration_interval(consumed)
    }

    fn consume_request(consumed: &Self::Consumed) -> Self::Consume {
        ConsumeSelectedLogicalJobOrchestration::new(consumed.selected().clone())
    }

    fn consumed_matches(
        consumed: &Self::Consumed,
        request: &Self::Consume,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    ) -> bool {
        consumed.selected() == request.selected()
            && matches!(
                consumed.authority(),
                ConsumedLogicalJobOrchestrationAuthority::Activation(_)
            )
            && expected_successor.is_none_or(|expected| expected.matches_orchestration(consumed))
    }

    fn make_renewal(
        authority: &Self::Authority,
        duration_ms: i64,
    ) -> Result<Self::Renewal, AutonomousWorkflowLeaseError> {
        RenewLogicalJobActivation::new(authority.claim().clone(), duration_ms)
            .map_err(|_| AutonomousWorkflowLeaseError::Unavailable)
    }

    fn submit_renewal(
        repository: &Self::Repository,
        request: Self::Renewal,
    ) -> PhaseFuture<'_, Result<RenewalSubmission, AutonomousWorkflowLeaseError>> {
        Box::pin(async move {
            match repository
                .renew_logical_job_activation(request.clone())
                .await
            {
                Ok(acknowledgement) if acknowledgement.request() == &request => Ok(
                    RenewalSubmission::Acknowledged(ExpectedRenewalSuccessor::new(
                        Self::PHASE,
                        acknowledgement.successor_generation().get(),
                        acknowledgement.successor_claimed_at(),
                        acknowledgement.successor_expires_at(),
                    )),
                ),
                Err(LogicalActivationStoreError::Store(StoreError::Operation(_))) => {
                    Ok(RenewalSubmission::Operation)
                }
                Ok(_) | Err(_) => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
            }
        })
    }

    fn consume_selected(
        selections: &dyn LogicalWorkSelectionRepository,
        request: Self::Consume,
    ) -> PhaseFuture<'_, Result<Self::Consumed, automata_ci_store::LogicalWorkSelectionStoreError>>
    {
        Box::pin(async move {
            selections
                .consume_selected_logical_job_orchestration(request)
                .await
        })
    }

    fn ready_matches_authority(request: &Self::ReadyFinal, authority: &Self::Authority) -> bool {
        request.matches_authority(authority)
    }

    fn quarantine_request(
        consumed: Self::Consumed,
        kind: LogicalWorkQuarantineKind,
    ) -> Self::Quarantine {
        QuarantineLogicalJobOrchestration::new(consumed, kind)
    }

    fn transition(
        custody: &AutonomousWorkflowCustody,
        transition: PhaseCustodyTransition<Self>,
    ) -> Result<PhaseCustodyTransitionOutcome, AutonomousWorkflowLeaseError> {
        transition_orchestration_phase::<Self>(custody, transition)
    }

    fn snapshot(custody: &AutonomousWorkflowCustody) -> Option<PhaseCustodySnapshot<Self>> {
        decode_orchestration_phase::<Self>(custody.orchestration())
    }
    fn repository(service: &AutonomousWorkflowService) -> Arc<Self::Repository> {
        Arc::clone(&service.activations)
    }

    fn continue_consume<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Consume,
        deadline: AutonomousWorkflowDeadline,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>> {
        Box::pin(service.start_orchestration_consume(
            request,
            Some(deadline),
            expected_successor,
            shutdown,
            true,
        ))
    }

    fn submit_quarantine<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Quarantine,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>> {
        Box::pin(service.submit_orchestration_quarantine(request, shutdown, false))
    }

    fn lease_from_core(core: PhaseLeaseCore<Self>) -> Self::Lease {
        AutonomousActivationLease { core }
    }

    fn into_core(lease: Self::Lease) -> PhaseLeaseCore<Self> {
        lease.core
    }

    fn execute<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a mut Self::Lease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        executor.execute_activation(lease, shutdown, deadline)
    }

    fn submit_final<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a Self::Lease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        executor.submit_activation_final(lease)
    }
}

impl AutonomousPhaseAdapter for MaterializationPhase {
    type Consumed = ConsumedSelectedLogicalInstanceMaterialization;
    type Authority = ClaimedLogicalInstanceMaterialization;
    type Consume = ConsumeSelectedLogicalInstanceMaterialization;
    type Renewal = RenewLogicalInstanceMaterialization;
    type ReadyFinal = ReadyLogicalInstanceMaterialization;
    type Quarantine = QuarantineLogicalInstanceMaterialization;
    type Repository = dyn LogicalMaterializationRepository;
    type Lease = AutonomousMaterializationLease;

    const PHASE: AutonomousWorkflowPhase = AutonomousWorkflowPhase::Materialization;
    const QUEUE: AutonomousWorkflowQueue = AutonomousWorkflowQueue::Materialization;
    const MAX_RENEWAL_MILLIS: i64 = MAX_LOGICAL_MATERIALIZATION_CLAIM_MILLIS;

    fn authority(consumed: &Self::Consumed) -> Option<&Self::Authority> {
        Some(consumed.authority())
    }

    fn claim_interval(authority: &Self::Authority) -> (UnixMillis, UnixMillis) {
        (
            authority.claim().claimed_at(),
            authority.claim().expires_at(),
        )
    }

    fn validated_interval(consumed: &Self::Consumed) -> (UnixMillis, UnixMillis) {
        (
            consumed.validated_at(),
            consumed.authority().claim().expires_at(),
        )
    }

    fn consume_request(consumed: &Self::Consumed) -> Self::Consume {
        ConsumeSelectedLogicalInstanceMaterialization::new(consumed.selected().clone())
    }

    fn consumed_matches(
        consumed: &Self::Consumed,
        request: &Self::Consume,
        expected_successor: Option<ExpectedRenewalSuccessor>,
    ) -> bool {
        consumed.selected() == request.selected()
            && expected_successor.is_none_or(|expected| expected.matches_materialization(consumed))
    }

    fn make_renewal(
        authority: &Self::Authority,
        duration_ms: i64,
    ) -> Result<Self::Renewal, AutonomousWorkflowLeaseError> {
        RenewLogicalInstanceMaterialization::new(authority.claim().clone(), duration_ms)
            .map_err(|_| AutonomousWorkflowLeaseError::Unavailable)
    }

    fn submit_renewal(
        repository: &Self::Repository,
        request: Self::Renewal,
    ) -> PhaseFuture<'_, Result<RenewalSubmission, AutonomousWorkflowLeaseError>> {
        Box::pin(async move {
            match repository
                .renew_logical_instance_materialization(request.clone())
                .await
            {
                Ok(acknowledgement) if acknowledgement.request() == &request => Ok(
                    RenewalSubmission::Acknowledged(ExpectedRenewalSuccessor::new(
                        Self::PHASE,
                        acknowledgement.successor_generation().get(),
                        acknowledgement.successor_claimed_at(),
                        acknowledgement.successor_expires_at(),
                    )),
                ),
                Err(LogicalMaterializationStoreError::Store(StoreError::Operation(_))) => {
                    Ok(RenewalSubmission::Operation)
                }
                Ok(_) | Err(_) => Err(AutonomousWorkflowLeaseError::AuthorityRejected),
            }
        })
    }

    fn consume_selected(
        selections: &dyn LogicalWorkSelectionRepository,
        request: Self::Consume,
    ) -> PhaseFuture<'_, Result<Self::Consumed, automata_ci_store::LogicalWorkSelectionStoreError>>
    {
        Box::pin(async move {
            selections
                .consume_selected_logical_instance_materialization(request)
                .await
        })
    }

    fn ready_matches_authority(request: &Self::ReadyFinal, authority: &Self::Authority) -> bool {
        request.matches_authority(authority)
    }

    fn quarantine_request(
        consumed: Self::Consumed,
        kind: LogicalWorkQuarantineKind,
    ) -> Self::Quarantine {
        QuarantineLogicalInstanceMaterialization::new(consumed, kind)
    }

    fn transition(
        custody: &AutonomousWorkflowCustody,
        transition: PhaseCustodyTransition<Self>,
    ) -> Result<PhaseCustodyTransitionOutcome, AutonomousWorkflowLeaseError> {
        transition_materialization_phase(custody, transition)
    }

    fn snapshot(custody: &AutonomousWorkflowCustody) -> Option<PhaseCustodySnapshot<Self>> {
        decode_materialization_phase(custody.materialization())
    }
    fn repository(service: &AutonomousWorkflowService) -> Arc<Self::Repository> {
        Arc::clone(&service.materializations)
    }

    fn continue_consume<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Consume,
        deadline: AutonomousWorkflowDeadline,
        expected_successor: Option<ExpectedRenewalSuccessor>,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>> {
        Box::pin(service.start_materialization_consume(
            request,
            Some(deadline),
            expected_successor,
            shutdown,
            true,
        ))
    }

    fn submit_quarantine<'a>(
        service: &'a AutonomousWorkflowService,
        request: Self::Quarantine,
        shutdown: &'a CancellationToken,
    ) -> PhaseFuture<'a, Result<QueuePoll, AutonomousWorkflowError>> {
        Box::pin(service.submit_materialization_quarantine(request, shutdown, false))
    }

    fn lease_from_core(core: PhaseLeaseCore<Self>) -> Self::Lease {
        AutonomousMaterializationLease { core }
    }

    fn into_core(lease: Self::Lease) -> PhaseLeaseCore<Self> {
        lease.core
    }

    fn execute<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a mut Self::Lease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        executor.execute_materialization(lease, shutdown, deadline)
    }

    fn submit_final<'a>(
        executor: &'a dyn AutonomousWorkflowPhaseExecutor,
        lease: &'a Self::Lease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        executor.submit_materialization_final(lease)
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
                OrchestrationCustody::Preparation(state) => {
                    Box::pin(
                        self.resume_phase_custody::<PreparationPhase>(*state, shutdown, drain_only),
                    )
                    .await?
                }
                OrchestrationCustody::Activation(state) => {
                    Box::pin(
                        self.resume_phase_custody::<ActivationPhase>(*state, shutdown, drain_only),
                    )
                    .await?
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

        let materialization =
            if queue == Some(AutonomousWorkflowQueue::Orchestration) {
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
                    MaterializationCustody::Phase(state) => {
                        Box::pin(self.resume_phase_custody::<MaterializationPhase>(
                            *state, shutdown, drain_only,
                        ))
                        .await?
                    }
                    MaterializationCustody::Quarantine { request, submitted } => {
                        if drain_only && !submitted {
                            None
                        } else {
                            Some(
                                Box::pin(self.submit_materialization_quarantine(
                                    *request, shutdown, submitted,
                                ))
                                .await?,
                            )
                        }
                    }
                }
            };
        Ok(materialization)
    }

    async fn resume_phase_custody<P: AutonomousPhaseAdapter>(
        &self,
        state: PhaseCustodySnapshot<P>,
        shutdown: &CancellationToken,
        drain_only: bool,
    ) -> Result<Option<QueuePoll>, AutonomousWorkflowError> {
        match state {
            PhaseCustodySnapshot::Active { consumed, deadline } => {
                if drain_only {
                    Ok(None)
                } else {
                    Ok(Some(
                        Box::pin(self.execute_phase_active::<P>(consumed, deadline, shutdown))
                            .await?,
                    ))
                }
            }
            PhaseCustodySnapshot::ReadyFinal {
                consumed,
                deadline,
                request,
            } => {
                if drain_only {
                    Ok(None)
                } else {
                    Ok(Some(
                        Box::pin(self.start_phase_final_submission::<P>(
                            consumed, deadline, request, shutdown,
                        ))
                        .await?,
                    ))
                }
            }
            PhaseCustodySnapshot::PendingFinal {
                consumed,
                deadline,
                request,
            } => Ok(Some(
                Box::pin(self.resolve_phase_final_submission::<P>(
                    consumed,
                    deadline,
                    request,
                    shutdown,
                    false,
                    !drain_only,
                ))
                .await?,
            )),
            PhaseCustodySnapshot::PendingRenew {
                consumed,
                deadline,
                request,
                submitted,
            } => {
                if drain_only && !submitted {
                    Ok(None)
                } else {
                    Ok(Some(
                        Box::pin(self.resume_phase_renewal::<P>(
                            consumed,
                            deadline,
                            request,
                            shutdown,
                            !drain_only,
                            submitted,
                        ))
                        .await?,
                    ))
                }
            }
            PhaseCustodySnapshot::SettledFinalEvidence { consumed, kind } => {
                if drain_only {
                    return Ok(None);
                }
                let request = P::quarantine_request(consumed.clone(), kind);
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ResumeSettledFinalQuarantine {
                        consumed,
                        quarantine: request.clone(),
                    },
                )?;
                Ok(Some(
                    Box::pin(P::submit_quarantine(self, request, shutdown)).await?,
                ))
            }
            PhaseCustodySnapshot::Idle
            | PhaseCustodySnapshot::Selected { .. }
            | PhaseCustodySnapshot::PendingConsume { .. }
            | PhaseCustodySnapshot::Quarantine { .. } => {
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
        }
    }

    async fn resume_phase_renewal<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::Renewal,
        shutdown: &CancellationToken,
        continue_after: bool,
        submitted: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let repository = P::repository(self);
        let submission = async {
            if !submitted {
                expect_applied(&P::transition(
                    &self.custody,
                    PhaseCustodyTransition::MarkRenewalSubmitted {
                        consumed: consumed.clone(),
                        request: request.clone(),
                    },
                )?)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                P::submit_renewal(repository.as_ref(), request.clone()).await,
            )
        };
        let result = match await_renewal_submission(submitted, shutdown, &deadline, submission)
            .await
        {
            Ok(Ok(result)) => match result {
                Ok(result) => result,
                Err(error) => {
                    apply_service_transition::<P>(
                        &self.custody,
                        PhaseCustodyTransition::ClearRenewal { consumed, request },
                    )?;
                    return Err(match error {
                        AutonomousWorkflowLeaseError::Shutdown => AutonomousWorkflowError::Shutdown,
                        AutonomousWorkflowLeaseError::DeadlineElapsed
                        | AutonomousWorkflowLeaseError::Unavailable
                        | AutonomousWorkflowLeaseError::AuthorityRejected => {
                            AutonomousWorkflowError::AuthorityRejected
                        }
                    });
                }
            },
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => {
                if !submitted && error == AutonomousWorkflowLeaseError::DeadlineElapsed {
                    apply_service_transition::<P>(
                        &self.custody,
                        PhaseCustodyTransition::ClearExpiredUnsubmittedRenewal {
                            consumed,
                            request,
                        },
                    )?;
                }
                return unavailable_or_shutdown(error, P::QUEUE);
            }
        };
        let (expected_successor, operation) = match result {
            RenewalSubmission::Acknowledged(successor) => (Some(successor), false),
            RenewalSubmission::Operation => (None, true),
        };
        let reconcile = P::consume_request(&consumed);
        apply_service_transition::<P>(
            &self.custody,
            PhaseCustodyTransition::SelectAfterRenewal {
                consumed,
                renewal: request,
                request: reconcile.clone(),
                deadline: deadline.clone(),
                expected_successor,
            },
        )?;
        if operation || !continue_after {
            return Ok(unavailable_poll(P::QUEUE));
        }
        P::continue_consume(self, reconcile, deadline, expected_successor, shutdown).await
    }

    async fn start_phase_final_submission<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::ReadyFinal,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearReadyFinal { consumed, request },
                )?;
            }
            return unavailable_or_shutdown(error, P::QUEUE);
        }
        Box::pin(
            self.resolve_phase_final_submission::<P>(
                consumed, deadline, request, shutdown, true, true,
            ),
        )
        .await
    }

    async fn resolve_phase_final_submission<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        request: P::ReadyFinal,
        shutdown: &CancellationToken,
        first_submission: bool,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let submission_deadline = deadline.clone();
        let lease = P::lease_from_core(PhaseLeaseCore::new(
            Arc::clone(&self.selections),
            P::repository(self),
            consumed.clone(),
            deadline,
            Arc::clone(&self.custody),
        ));
        let submission = async {
            if first_submission {
                expect_applied(&P::transition(
                    &self.custody,
                    PhaseCustodyTransition::BeginFinalSubmission {
                        consumed: consumed.clone(),
                        deadline: submission_deadline.clone(),
                        request: request.clone(),
                    },
                )?)?;
            }
            Ok::<_, AutonomousWorkflowLeaseError>(
                P::submit_final(self.executor.as_ref(), &lease).await,
            )
        };
        let outcome = match if first_submission {
            await_bounded(shutdown, &submission_deadline, submission).await
        } else {
            await_custody(shutdown, submission).await
        } {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => return Err(AutonomousWorkflowError::AuthorityRejected),
            Err(error) => return unavailable_or_shutdown(error, P::QUEUE),
        };
        if !matches!(
            P::snapshot(&self.custody),
            Some(PhaseCustodySnapshot::PendingFinal {
                consumed: pending_consumed,
                request: pending_request,
                ..
            }) if pending_consumed == consumed && pending_request == request
        ) {
            return Err(AutonomousWorkflowError::AuthorityRejected);
        }
        self.finish_phase_final::<P>(consumed, request, outcome, shutdown, continue_after)
            .await
    }

    async fn finish_phase_final<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        request: P::ReadyFinal,
        outcome: Result<AutonomousWorkflowExecutionOutcome, AutonomousWorkflowLeaseError>,
        shutdown: &CancellationToken,
        continue_after: bool,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        match outcome {
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestOperation) => {
                Ok(unavailable_poll(P::QUEUE))
            }
            Ok(AutonomousWorkflowExecutionOutcome::Completed) => {
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearFinal { consumed, request },
                )?;
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    P::PHASE,
                )))
            }
            Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind)) => {
                if !continue_after {
                    apply_service_transition::<P>(
                        &self.custody,
                        PhaseCustodyTransition::SettleFinalEvidence {
                            consumed,
                            request,
                            kind,
                        },
                    )?;
                    return Ok(unavailable_poll(P::QUEUE));
                }
                let quarantine = P::quarantine_request(consumed.clone(), kind);
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::BeginFinalQuarantine {
                        consumed,
                        request,
                        quarantine: quarantine.clone(),
                    },
                )?;
                P::submit_quarantine(self, quarantine, shutdown).await
            }
            Ok(AutonomousWorkflowExecutionOutcome::Retryable) => {
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearFinal { consumed, request },
                )?;
                Ok(unavailable_poll(P::QUEUE))
            }
            Ok(AutonomousWorkflowExecutionOutcome::FinalRequestReady) => {
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearFinal { consumed, request },
                )?;
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
            Err(AutonomousWorkflowLeaseError::Shutdown) => Err(AutonomousWorkflowError::Shutdown),
            Err(error) => {
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearFinal { consumed, request },
                )?;
                unavailable_or_shutdown(error, P::QUEUE)
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
            Ok(Err(error)) => {
                self.custody.set_orchestration(OrchestrationCustody::Idle);
                return selection_submission_failure(error, AutonomousWorkflowQueue::Orchestration);
            }
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
        self.custody.set_orchestration(match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                OrchestrationCustody::Preparation(Box::new(PhaseCustodySnapshot::Active {
                    consumed: consumed.clone(),
                    deadline: deadline.clone(),
                }))
            }
            ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                OrchestrationCustody::Activation(Box::new(PhaseCustodySnapshot::Active {
                    consumed: consumed.clone(),
                    deadline: deadline.clone(),
                }))
            }
        });
        if !continue_after {
            return Ok(unavailable_poll(AutonomousWorkflowQueue::Orchestration));
        }
        Box::pin(self.execute_orchestration_active(consumed, deadline, shutdown)).await
    }

    async fn execute_phase<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        shutdown: &CancellationToken,
    ) -> (P::Consumed, PhaseExecutionDisposition) {
        let mut lease = P::lease_from_core(PhaseLeaseCore::new(
            Arc::clone(&self.selections),
            P::repository(self),
            consumed,
            deadline.clone(),
            Arc::clone(&self.custody),
        ));
        let execution = P::execute(
            self.executor.as_ref(),
            &mut lease,
            shutdown.clone(),
            deadline.clone(),
        );
        let disposition = await_bounded(shutdown, &deadline, execution).await;
        let core = P::into_core(lease);
        (core.consumed, disposition)
    }

    fn phase_active_matches<P: AutonomousPhaseAdapter>(&self, consumed: &P::Consumed) -> bool {
        matches!(
            P::snapshot(&self.custody),
            Some(PhaseCustodySnapshot::Active { consumed: active, .. }) if &active == consumed
        )
    }

    fn clear_phase_if_active<P: AutonomousPhaseAdapter>(
        &self,
    ) -> Result<(), AutonomousWorkflowError> {
        let Some(PhaseCustodySnapshot::Active { consumed, .. }) = P::snapshot(&self.custody) else {
            return Ok(());
        };
        apply_service_transition::<P>(
            &self.custody,
            PhaseCustodyTransition::ClearActive { consumed },
        )
    }

    async fn finish_phase_execution<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        disposition: PhaseExecutionDisposition,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        let outcome = match disposition {
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
                self.clear_phase_if_active::<P>()?;
                return Ok(unavailable_poll(P::QUEUE));
            }
            Ok(Ok(AutonomousWorkflowExecutionOutcome::Retryable)) => {
                if !self.phase_active_matches::<P>(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearActive {
                        consumed: consumed.clone(),
                    },
                )?;
                return Ok(unavailable_poll(P::QUEUE));
            }
            Err(AutonomousWorkflowLeaseError::AuthorityRejected)
            | Ok(Err(AutonomousWorkflowLeaseError::AuthorityRejected)) => {
                self.clear_phase_if_active::<P>()?;
                return Err(AutonomousWorkflowError::AuthorityRejected);
            }
            Ok(Ok(outcome)) => outcome,
        };
        match outcome {
            AutonomousWorkflowExecutionOutcome::Completed => {
                if !self.phase_active_matches::<P>(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearActive { consumed },
                )?;
                Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Completed(
                    P::PHASE,
                )))
            }
            AutonomousWorkflowExecutionOutcome::EvidenceFailure(kind) => {
                if !self.phase_active_matches::<P>(&consumed) {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                }
                if shutdown.is_cancelled() {
                    return Err(AutonomousWorkflowError::Shutdown);
                }
                let quarantine = P::quarantine_request(consumed.clone(), kind);
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::BeginActiveQuarantine {
                        consumed,
                        quarantine: quarantine.clone(),
                    },
                )?;
                P::submit_quarantine(self, quarantine, shutdown).await
            }
            AutonomousWorkflowExecutionOutcome::Retryable => unreachable!("handled above"),
            AutonomousWorkflowExecutionOutcome::FinalRequestReady => {
                let Some((deadline, request)) = ready_phase_final::<P>(&self.custody, &consumed)
                else {
                    return Err(AutonomousWorkflowError::AuthorityRejected);
                };
                Box::pin(
                    self.start_phase_final_submission::<P>(consumed, deadline, request, shutdown),
                )
                .await
            }
            AutonomousWorkflowExecutionOutcome::FinalRequestOperation => {
                Err(AutonomousWorkflowError::AuthorityRejected)
            }
        }
    }

    async fn execute_phase_active<P: AutonomousPhaseAdapter>(
        &self,
        consumed: P::Consumed,
        deadline: AutonomousWorkflowDeadline,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        if let Err(error) = deadline.checkpoint(shutdown) {
            if error != AutonomousWorkflowLeaseError::Shutdown {
                apply_service_transition::<P>(
                    &self.custody,
                    PhaseCustodyTransition::ClearActive { consumed },
                )?;
            }
            return unavailable_or_shutdown(error, P::QUEUE);
        }
        let (consumed, disposition) = self.execute_phase::<P>(consumed, deadline, shutdown).await;
        Box::pin(self.finish_phase_execution::<P>(consumed, disposition, shutdown)).await
    }

    async fn execute_orchestration_active(
        &self,
        consumed: ConsumedSelectedLogicalJobOrchestration,
        deadline: AutonomousWorkflowDeadline,
        shutdown: &CancellationToken,
    ) -> Result<QueuePoll, AutonomousWorkflowError> {
        match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                Box::pin(
                    self.execute_phase_active::<PreparationPhase>(consumed, deadline, shutdown),
                )
                .await
            }
            ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                Box::pin(self.execute_phase_active::<ActivationPhase>(consumed, deadline, shutdown))
                    .await
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
            Ok(Err(error)) => {
                self.custody
                    .set_materialization(MaterializationCustody::Idle);
                return selection_submission_failure(
                    error,
                    AutonomousWorkflowQueue::Materialization,
                );
            }
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
            .set_materialization(MaterializationCustody::Phase(Box::new(
                PhaseCustodySnapshot::Active {
                    consumed: consumed.clone(),
                    deadline: deadline.clone(),
                },
            )));
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
        Box::pin(self.execute_phase_active::<MaterializationPhase>(consumed, deadline, shutdown))
            .await
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
    _error: &automata_ci_store::LogicalWorkSelectionStoreError,
    queue: AutonomousWorkflowQueue,
) -> Result<QueuePoll, AutonomousWorkflowError> {
    // Selection is a read/claim poll.  A rejected or malformed candidate must
    // not terminate the control plane: the transaction has rolled back and the
    // next bounded poll can re-read the authoritative graph after maintenance
    // or a concurrent worker has advanced it.  Fatal authority errors remain
    // enforced at consume/finalization boundaries, after a durable claim exists.
    Ok(QueuePoll::Outcome(AutonomousWorkflowOutcome::Unavailable(
        queue,
    )))
}

fn selection_submission_failure(
    error: AutonomousWorkflowLeaseError,
    queue: AutonomousWorkflowQueue,
) -> Result<QueuePoll, AutonomousWorkflowError> {
    match error {
        AutonomousWorkflowLeaseError::Shutdown => Err(AutonomousWorkflowError::Shutdown),
        AutonomousWorkflowLeaseError::DeadlineElapsed
        | AutonomousWorkflowLeaseError::Unavailable
        | AutonomousWorkflowLeaseError::AuthorityRejected => Ok(unavailable_poll(queue)),
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
