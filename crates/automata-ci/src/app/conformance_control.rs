//! Deterministic product clock and failure adapters for conformance fixtures.

use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use automata_ci_auth::time::{Clock as AuthClock, UnixTimestamp};
pub use automata_ci_conformance::FaultOperation as ProductFaultOperation;
use automata_ci_conformance::{
    ConformanceClock, DurableTransition, FaultMode, FaultPlan, FaultTarget, FixtureControl,
    FixtureControlError, ManualConformanceClock, ShardPlan,
};
use automata_ci_control::LeaseClock;
use automata_ci_core::UnixMillis;
use automata_ci_credential_github::{
    GithubRuntimeAuthorityCoordinatorClock, GithubServerServiceCoordinatorClock,
};
use automata_ci_github_delivery::{
    GithubDeliveryClock, GithubScheduleClock, GithubScheduleServiceError,
};
use automata_ci_results_github::ResultsClock;
use automata_ci_workflow_service::AdmissionClock;
use thiserror::Error;

use crate::server::MaintenanceClock;

use super::conformance_shard::ProductConformanceShard;

/// One shared deterministic clock implementing product-owned time ports.
#[derive(Clone, Debug)]
pub struct ProductConformanceClock {
    inner: Arc<ManualConformanceClock>,
}

impl ProductConformanceClock {
    /// Creates a nonnegative fixture clock.
    ///
    /// # Errors
    ///
    /// Rejects an instant before the Unix epoch.
    pub fn new(initial_millis: i64) -> Result<Self, ProductConformanceAdapterError> {
        if initial_millis < 0 {
            return Err(ProductConformanceAdapterError::InvalidInitialTime);
        }
        Ok(Self {
            inner: Arc::new(ManualConformanceClock::new(initial_millis)),
        })
    }

    /// Advances every attached product clock port together.
    ///
    /// # Errors
    ///
    /// Rejects zero, negative, or overflowing advances.
    pub fn advance(&self, millis: i64) -> Result<i64, FixtureControlError> {
        self.inner.advance(millis)
    }

    /// Returns this clock through the provider-neutral fixture contract.
    #[must_use]
    pub fn fixture_clock(&self) -> Arc<dyn ConformanceClock> {
        self.inner.clone()
    }

    fn now_millis(&self) -> i64 {
        self.inner.now_millis()
    }

    fn now_unix_millis(&self) -> UnixMillis {
        UnixMillis::new(self.now_millis())
    }

    fn now_seconds(&self) -> u64 {
        u64::try_from(self.now_millis()).expect("constructor and advance keep time nonnegative")
            / 1_000
    }
}

impl AuthClock for ProductConformanceClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(self.now_seconds())
    }
}

impl AdmissionClock for ProductConformanceClock {
    fn now(&self) -> UnixMillis {
        self.now_unix_millis()
    }
}

impl GithubDeliveryClock for ProductConformanceClock {
    fn now(&self) -> UnixMillis {
        self.now_unix_millis()
    }
}

impl GithubScheduleClock for ProductConformanceClock {
    fn now(&self) -> Result<UnixMillis, GithubScheduleServiceError> {
        Ok(self.now_unix_millis())
    }
}

impl GithubRuntimeAuthorityCoordinatorClock for ProductConformanceClock {
    fn now(&self) -> UnixMillis {
        self.now_unix_millis()
    }
}

impl GithubServerServiceCoordinatorClock for ProductConformanceClock {
    fn now(&self) -> UnixMillis {
        self.now_unix_millis()
    }
}

impl ResultsClock for ProductConformanceClock {
    fn now_seconds(&self) -> u64 {
        self.now_seconds()
    }
}

impl LeaseClock for ProductConformanceClock {
    fn now(&self) -> UnixMillis {
        self.now_unix_millis()
    }
}

impl MaintenanceClock for ProductConformanceClock {
    fn now(&self) -> UnixMillis {
        self.now_unix_millis()
    }
}

/// Concrete deterministic adapters selected for one isolated fixture shard.
#[derive(Debug)]
pub struct ProductConformanceAdapters {
    clock: ProductConformanceClock,
    control: Arc<FixtureControl>,
    faults: Arc<ProductFaultGate>,
    shard: ProductConformanceShard,
}

impl ProductConformanceAdapters {
    /// Creates one clock/control/fault composition with no wall-time seam.
    ///
    /// # Errors
    ///
    /// Rejects invalid time or an unknown shard ordinal.
    pub fn for_shard(
        initial_millis: i64,
        fault_plan: Arc<FaultPlan>,
        shard_plan: &ShardPlan,
        ordinal: u16,
    ) -> Result<Self, ProductConformanceAdapterError> {
        let clock = ProductConformanceClock::new(initial_millis)?;
        let control = Arc::new(FixtureControl::for_shard(
            clock.fixture_clock(),
            fault_plan,
            shard_plan,
            ordinal,
        )?);
        let shard = ProductConformanceShard::from_identity(control.shard());
        let faults = Arc::new(ProductFaultGate {
            clock: clock.clone(),
            control: Arc::clone(&control),
            events: Mutex::new(Vec::new()),
        });
        Ok(Self {
            clock,
            control,
            faults,
            shard,
        })
    }

    /// Returns the shared clock for injection into every product clock port.
    #[must_use]
    pub const fn clock(&self) -> &ProductConformanceClock {
        &self.clock
    }

    /// Returns the durable transition/restart control using the same clock.
    #[must_use]
    pub fn control(&self) -> &Arc<FixtureControl> {
        &self.control
    }

    /// Returns the operation-scoped fixture fault gate.
    #[must_use]
    pub const fn faults(&self) -> &Arc<ProductFaultGate> {
        &self.faults
    }

    /// Returns product provisioning adapters bound to the control's exact shard identity.
    #[must_use]
    pub const fn shard(&self) -> &ProductConformanceShard {
        &self.shard
    }
}

/// One typed failure consumed by an operation-scoped fixture adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectedProductFault {
    transition: DurableTransition,
    operation: ProductFaultOperation,
    target: FaultTarget,
    mode: FaultMode,
    at_millis: i64,
}

impl InjectedProductFault {
    #[must_use]
    pub const fn transition(&self) -> DurableTransition {
        self.transition
    }

    #[must_use]
    pub const fn operation(&self) -> ProductFaultOperation {
        self.operation
    }

    #[must_use]
    pub const fn target(&self) -> FaultTarget {
        self.target
    }

    #[must_use]
    pub const fn mode(&self) -> &FaultMode {
        &self.mode
    }

    #[must_use]
    pub const fn at_millis(&self) -> i64 {
        self.at_millis
    }
}

/// Operation-scoped gate that consumes the fixture's one-shot fault plan.
#[derive(Debug)]
pub struct ProductFaultGate {
    clock: ProductConformanceClock,
    control: Arc<FixtureControl>,
    events: Mutex<Vec<InjectedProductFault>>,
}

impl ProductFaultGate {
    /// Runs one synchronous adapter operation unless its exact fault is due.
    ///
    /// The gate verifies the operation's valid durable checkpoints before consuming a
    /// fault. A wrong-stage call neither invokes the operation nor consumes the
    /// script.
    ///
    /// # Errors
    ///
    /// Returns an injected fixture fault, an adapter invariant failure, or the
    /// wrapped adapter operation's error as separate variants.
    pub fn call<T, E>(
        &self,
        operation: ProductFaultOperation,
        delegate: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, ProductBoundaryCallError<E>> {
        if let Some(fault) = self.take_due(operation)? {
            return Err(ProductBoundaryCallError::Injected(fault));
        }
        delegate().map_err(ProductBoundaryCallError::Operation)
    }

    /// Runs one asynchronous adapter operation unless its exact fault is due.
    ///
    /// # Errors
    ///
    /// Returns an injected fixture fault, an adapter invariant failure, or the
    /// wrapped adapter operation's error as separate variants.
    pub async fn call_async<T, E, F, Fut>(
        &self,
        operation: ProductFaultOperation,
        delegate: F,
    ) -> Result<T, ProductBoundaryCallError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if let Some(fault) = self.take_due(operation)? {
            return Err(ProductBoundaryCallError::Injected(fault));
        }
        delegate()
            .await
            .map_err(ProductBoundaryCallError::Operation)
    }

    /// Returns immutable evidence for every fault consumed so far.
    ///
    /// # Errors
    ///
    /// Returns an error if another thread poisoned the private evidence lock.
    pub fn events(&self) -> Result<Vec<InjectedProductFault>, ProductConformanceAdapterError> {
        self.events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| ProductConformanceAdapterError::EventLedgerPoisoned)
    }

    /// Consumes a fault only when its typed operation is valid at the current checkpoint.
    ///
    /// Concrete product-port wrappers use this method immediately before their
    /// delegated operation.
    ///
    /// # Errors
    ///
    /// Rejects an armed operation attempted outside its exact scripted
    /// checkpoint or a poisoned evidence ledger without consuming the fault.
    /// Operations with no armed entry delegate normally at every checkpoint.
    pub fn take_due(
        &self,
        operation: ProductFaultOperation,
    ) -> Result<Option<InjectedProductFault>, ProductConformanceAdapterError> {
        let actual = self.control.current_transition();
        let target = operation.target();
        let mode = self
            .control
            .faults()
            .take_due(operation, actual)
            .map_err(
                |not_due| ProductConformanceAdapterError::WrongFaultTransition {
                    operation,
                    expected: not_due.expected(),
                    actual: not_due.actual(),
                },
            )?;
        let Some(mode) = mode else {
            return Ok(None);
        };
        let fault = InjectedProductFault {
            transition: actual,
            operation,
            target,
            mode,
            at_millis: self.clock.now_millis(),
        };
        self.events
            .lock()
            .map_err(|_| ProductConformanceAdapterError::EventLedgerPoisoned)?
            .push(fault.clone());
        Ok(Some(fault))
    }
}

/// Result of executing an operation through the fixture fault gate.
#[derive(Debug, Eq, PartialEq)]
pub enum ProductBoundaryCallError<E> {
    /// The fixture consumed a typed fault instead of invoking the operation.
    Injected(InjectedProductFault),
    /// The adapter itself rejected unsafe use.
    Adapter(ProductConformanceAdapterError),
    /// The wrapped adapter operation ran and returned its own failure.
    Operation(E),
}

impl<E> From<ProductConformanceAdapterError> for ProductBoundaryCallError<E> {
    fn from(error: ProductConformanceAdapterError) -> Self {
        Self::Adapter(error)
    }
}

/// Failure to construct or safely use deterministic product adapters.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProductConformanceAdapterError {
    #[error("the product conformance clock cannot start before the Unix epoch")]
    InvalidInitialTime,
    #[error("the product conformance fixture control is invalid")]
    FixtureControl(#[from] FixtureControlError),
    #[error(
        "the {operation:?} fault operation is armed for {expected:?}, not the current {actual:?} transition"
    )]
    WrongFaultTransition {
        operation: ProductFaultOperation,
        expected: DurableTransition,
        actual: DurableTransition,
    },
    #[error("the product conformance fault evidence ledger was poisoned")]
    EventLedgerPoisoned,
}
