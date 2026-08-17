use std::{
    sync::{Condvar, Mutex, PoisonError},
    time::Duration,
};

use automata_ci_runner_journal::{JournalContentRetainSet, RunnerJournal};
use automata_ci_runner_spool::{
    DurableContentStore, EndpointResultCapacityReservation, SpoolError,
};

use crate::ExecutionCancellation;

const LOG_DELIVERY_WAIT_POLL: Duration = Duration::from_millis(100);

pub(crate) trait CapacityReclaimError: Sized {
    fn is_capacity_exhausted(&self) -> bool;

    fn from_spool(error: SpoolError) -> Self;
}

/// Serializes payload-first publication transactions with reconciliation.
///
/// The spool retains its own publication fence as the crash-safety authority.
/// This coordinator prevents normal concurrent runner slots from colliding
/// with that fence: each critical section either publishes bytes and adopts
/// their exact identity in the journal, or snapshots the journal and prunes
/// everything else. No network or provider await belongs inside this gate.
#[derive(Debug, Default)]
pub(crate) struct ContentOperationCoordinator {
    exclusive: Mutex<()>,
    log_delivery_generation: Mutex<u64>,
    log_delivery_changed: Condvar,
}

impl ContentOperationCoordinator {
    pub(crate) fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _exclusive = self
            .exclusive
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        operation()
    }

    pub(crate) fn log_delivery_generation(&self) -> u64 {
        *self
            .log_delivery_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn notify_log_delivery_progress(&self) {
        let mut generation = self
            .log_delivery_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *generation = generation.wrapping_add(1);
        self.log_delivery_changed.notify_all();
    }

    pub(crate) fn wait_for_log_delivery_progress(
        &self,
        observed: u64,
        cancellation: &ExecutionCancellation,
    ) -> bool {
        let mut generation = self
            .log_delivery_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while *generation == observed && !cancellation.is_cancelled() {
            let waited = self
                .log_delivery_changed
                .wait_timeout(generation, LOG_DELIVERY_WAIT_POLL);
            generation = match waited {
                Ok((generation, _)) => generation,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        *generation != observed
    }

    /// Publishes one complete payload-first transaction, reclaiming only
    /// journal-unreferenced content before one exact retry when local capacity
    /// is exhausted.
    ///
    /// `publish` must resolve or abort every nested publication receipt before
    /// returning an error. Reconciliation therefore begins only after the
    /// whole transaction has unwound and the journal remains the sole retain
    /// authority for every runner slot.
    pub(crate) fn publish_reclaiming_capacity<T, E>(
        &self,
        journal: &dyn RunnerJournal,
        spool: &dyn DurableContentStore,
        publish: impl Fn() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: CapacityReclaimError,
    {
        self.run(|| match publish() {
            Err(error) if error.is_capacity_exhausted() => {
                spool
                    .reconcile(&JournalContentRetainSet::new(journal))
                    .map_err(E::from_spool)?;
                publish()
            }
            outcome => outcome,
        })
    }

    /// Reserves shared protected capacity for an endpoint result before any
    /// backend invocation, reconciling journal-unreferenced payloads before one
    /// exact retry on exhaustion.
    pub(crate) fn reserve_endpoint_result<'store>(
        &self,
        journal: &dyn RunnerJournal,
        spool: &'store dyn DurableContentStore,
        maximum_plaintext_bytes: u64,
    ) -> Result<Box<dyn EndpointResultCapacityReservation<'store> + 'store>, SpoolError> {
        self.run(
            || match spool.reserve_endpoint_result(maximum_plaintext_bytes) {
                Err(SpoolError::CapacityExhausted) => {
                    spool.reconcile(&JournalContentRetainSet::new(journal))?;
                    spool.reserve_endpoint_result(maximum_plaintext_bytes)
                }
                outcome => outcome,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Instant};

    use super::{ContentOperationCoordinator, LOG_DELIVERY_WAIT_POLL};
    use crate::ExecutionCancellation;

    #[test]
    fn log_delivery_notification_releases_all_capacity_waiters() {
        let coordinator = Arc::new(ContentOperationCoordinator::default());
        let cancellation = ExecutionCancellation::new();
        let observed = coordinator.log_delivery_generation();
        let waiter = {
            let coordinator = Arc::clone(&coordinator);
            let cancellation = cancellation.clone();
            std::thread::spawn(move || {
                coordinator.wait_for_log_delivery_progress(observed, &cancellation)
            })
        };

        coordinator.notify_log_delivery_progress();

        assert!(waiter.join().expect("capacity waiter"));
    }

    #[test]
    fn cancellation_bounds_a_capacity_wait_without_delivery_progress() {
        let coordinator = ContentOperationCoordinator::default();
        let cancellation = ExecutionCancellation::new();
        let observed = coordinator.log_delivery_generation();
        cancellation.signal(crate::ExecutionCancellationReason::ServerRequest);
        let started = Instant::now();

        assert!(!coordinator.wait_for_log_delivery_progress(observed, &cancellation));
        assert!(started.elapsed() < LOG_DELIVERY_WAIT_POLL);
    }
}
