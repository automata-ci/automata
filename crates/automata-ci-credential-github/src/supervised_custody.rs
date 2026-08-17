use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use tokio::{
    runtime::Handle,
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::AbortHandle,
};

pub(crate) struct SupervisedCustody<T> {
    shared: Arc<Shared>,
    retained: Arc<Mutex<Vec<Arc<Entry<T>>>>>,
}

impl<T> SupervisedCustody<T> {
    pub(crate) fn new(runtime: Handle, capacity: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                runtime,
                permits: Arc::new(Semaphore::new(capacity)),
                outstanding: AtomicUsize::new(0),
                pending: AtomicUsize::new(0),
                drained: Arc::new(Notify::new()),
            }),
            retained: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        }
    }

    pub(crate) fn linked<U>(&self, capacity: usize) -> SupervisedCustody<U> {
        SupervisedCustody {
            shared: Arc::clone(&self.shared),
            retained: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        }
    }

    pub(crate) fn try_reserve(&self) -> Option<Reservation> {
        self.shared.outstanding.fetch_add(1, Ordering::AcqRel);
        let Ok(permit) = Arc::clone(&self.shared.permits).try_acquire_owned() else {
            self.shared.outstanding.fetch_sub(1, Ordering::AcqRel);
            self.shared.drained.notify_waiters();
            return None;
        };
        Some(Reservation {
            _permit: permit,
            shared: Arc::clone(&self.shared),
        })
    }

    pub(crate) fn retain(&self, reservation: Reservation, value: T) -> Arc<Entry<T>> {
        assert!(
            Arc::ptr_eq(&self.shared, &reservation.shared),
            "reservation belongs to the supervised custody core"
        );
        let entry = Arc::new(Entry {
            reservation,
            _pending: PendingObservation::new(Arc::clone(&self.shared)),
            value,
            task_abort: Mutex::new(None),
            driver_active: Arc::new(AtomicBool::new(false)),
            removed: AtomicBool::new(false),
        });
        self.retained
            .lock()
            .expect("supervised custody lock")
            .push(Arc::clone(&entry));
        entry
    }

    pub(crate) fn start_driver<R, Drive, DriveFuture, Complete>(
        &self,
        entry: &Arc<Entry<T>>,
        drive: Drive,
        complete: Complete,
    ) -> bool
    where
        T: Send + Sync + 'static,
        R: Send + 'static,
        Drive: FnOnce(Arc<Entry<T>>) -> DriveFuture + Send + 'static,
        DriveFuture: Future<Output = R> + Send + 'static,
        Complete: FnOnce(R) + Send + 'static,
    {
        assert!(
            Arc::ptr_eq(&self.shared, &entry.reservation.shared),
            "entry belongs to the supervised custody core"
        );
        if entry.removed.load(Ordering::Acquire) {
            return false;
        }
        if entry
            .driver_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if entry.removed.load(Ordering::Acquire) {
            entry.driver_active.store(false, Ordering::Release);
            self.shared.drained.notify_waiters();
            return false;
        }

        let retained = Arc::clone(&self.retained);
        let task_entry = Arc::clone(entry);
        let driver_active = DriverObservation {
            active: Arc::clone(&entry.driver_active),
            drained: Arc::clone(&self.shared.drained),
        };
        let task = self.shared.runtime.spawn(async move {
            let _driver_active = driver_active;
            let result = drive(Arc::clone(&task_entry)).await;
            task_entry.removed.store(true, Ordering::Release);
            drop(take_retained(&retained, &task_entry));
            drop(task_entry);
            complete(result);
        });
        *entry.task_abort.lock().expect("supervised driver lock") = Some(task.abort_handle());
        true
    }

    pub(crate) fn retained(&self) -> Vec<Arc<Entry<T>>> {
        self.retained
            .lock()
            .expect("supervised custody lock")
            .clone()
    }

    pub(crate) fn retained_count(&self) -> usize {
        self.retained.lock().expect("supervised custody lock").len()
    }

    pub(crate) fn pending(&self) -> usize {
        self.shared.pending.load(Ordering::Acquire)
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.shared.outstanding.load(Ordering::Acquire)
    }

    pub(crate) fn available(&self) -> usize {
        self.shared.permits.available_permits()
    }

    pub(crate) fn close(&self) {
        self.shared.permits.close();
    }

    pub(crate) async fn wait_for_idle(&self, mut redrive: impl FnMut()) {
        loop {
            let notified = self.shared.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            redrive();
            if self.outstanding() == 0 {
                return;
            }
            notified.await;
        }
    }
}

pub(crate) struct Entry<T> {
    reservation: Reservation,
    _pending: PendingObservation,
    value: T,
    task_abort: Mutex<Option<AbortHandle>>,
    driver_active: Arc<AtomicBool>,
    removed: AtomicBool,
}

impl<T> Entry<T> {
    pub(crate) const fn value(&self) -> &T {
        &self.value
    }

    #[cfg(test)]
    pub(crate) fn abort_driver(&self) -> bool {
        let task = self
            .task_abort
            .lock()
            .expect("supervised driver lock")
            .clone();
        task.is_some_and(|task| {
            task.abort();
            true
        })
    }

    #[cfg(test)]
    pub(crate) fn is_removed(&self) -> bool {
        self.removed.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn is_driver_active(&self) -> bool {
        self.driver_active.load(Ordering::Acquire)
    }
}

pub(crate) struct Reservation {
    _permit: OwnedSemaphorePermit,
    shared: Arc<Shared>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.shared.outstanding.fetch_sub(1, Ordering::AcqRel);
        self.shared.drained.notify_waiters();
    }
}

struct Shared {
    runtime: Handle,
    permits: Arc<Semaphore>,
    outstanding: AtomicUsize,
    pending: AtomicUsize,
    drained: Arc<Notify>,
}

struct PendingObservation {
    shared: Arc<Shared>,
}

impl PendingObservation {
    fn new(shared: Arc<Shared>) -> Self {
        shared.pending.fetch_add(1, Ordering::AcqRel);
        Self { shared }
    }
}

impl Drop for PendingObservation {
    fn drop(&mut self) {
        self.shared.pending.fetch_sub(1, Ordering::AcqRel);
        self.shared.drained.notify_waiters();
    }
}

struct DriverObservation {
    active: Arc<AtomicBool>,
    drained: Arc<Notify>,
}

impl Drop for DriverObservation {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.drained.notify_waiters();
    }
}

fn take_retained<T>(
    retained: &Mutex<Vec<Arc<Entry<T>>>>,
    target: &Arc<Entry<T>>,
) -> Option<Arc<Entry<T>>> {
    let mut retained = retained.lock().expect("supervised custody lock");
    let position = retained
        .iter()
        .position(|entry| Arc::ptr_eq(entry, target))?;
    Some(retained.swap_remove(position))
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    async fn wait_for_driver(entry: &Entry<()>, active: bool) {
        for _ in 0..100 {
            if entry.is_driver_active() == active {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("driver activity did not converge");
    }

    #[tokio::test]
    async fn aborted_driver_retains_custody_for_redrive() {
        let custody = SupervisedCustody::new(Handle::current(), 1);
        let entry = custody.retain(custody.try_reserve().expect("reservation"), ());
        assert!(custody.start_driver(&entry, |_| std::future::pending(), |()| {}));
        wait_for_driver(&entry, true).await;
        assert!(entry.abort_driver());
        wait_for_driver(&entry, false).await;
        assert_eq!((custody.pending(), custody.outstanding()), (1, 1));
        assert_eq!(custody.retained_count(), 1);

        assert!(custody.start_driver(&entry, |_| async {}, |()| {}));
        drop(entry);
        custody.wait_for_idle(|| {}).await;
        assert_eq!((custody.pending(), custody.outstanding()), (0, 0));
        assert_eq!(custody.retained_count(), 0);
    }

    #[tokio::test]
    async fn linked_typed_ledgers_share_one_bounded_core() {
        let left = SupervisedCustody::<u8>::new(Handle::current(), 1);
        let right = left.linked::<u16>(1);
        let reservation = left.try_reserve().expect("shared reservation");
        assert!(right.try_reserve().is_none());
        let _entry = right.retain(reservation, 7);
        assert_eq!((left.outstanding(), right.outstanding()), (1, 1));
        assert_eq!((left.pending(), right.pending()), (1, 1));
        assert_eq!((left.available(), right.available()), (0, 0));
        assert_eq!((left.retained_count(), right.retained_count()), (0, 1));
    }

    #[tokio::test]
    async fn foreign_reservation_is_rejected_without_counter_drift() {
        let local = SupervisedCustody::<()>::new(Handle::current(), 1);
        let foreign = SupervisedCustody::<()>::new(Handle::current(), 1);
        let reservation = foreign.try_reserve().expect("foreign reservation");
        let rejected = catch_unwind(AssertUnwindSafe(|| local.retain(reservation, ())));
        assert!(rejected.is_err());
        assert_eq!((local.pending(), local.outstanding()), (0, 0));
        assert_eq!((foreign.pending(), foreign.outstanding()), (0, 0));
        assert_eq!((local.available(), foreign.available()), (1, 1));
        assert_eq!((local.retained_count(), foreign.retained_count()), (0, 0));
    }
}
