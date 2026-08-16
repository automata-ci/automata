use std::sync::{Mutex, PoisonError};

use automata_ci_runner_journal::{JournalContentRetainSet, RunnerJournal};
use automata_ci_runner_spool::{
    DurableContentStore, EndpointResultCapacityReservation, SpoolError,
};

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
}

impl ContentOperationCoordinator {
    pub(crate) fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _exclusive = self
            .exclusive
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        operation()
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
