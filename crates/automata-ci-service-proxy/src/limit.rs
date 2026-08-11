use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct SlotLimiter {
    limit: usize,
    in_use: AtomicUsize,
}

impl SlotLimiter {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            limit,
            in_use: AtomicUsize::new(0),
        }
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<SlotPermit> {
        let mut current = self.in_use.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                return None;
            }
            match self.in_use.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(SlotPermit {
                        limiter: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(crate) struct SlotPermit {
    limiter: Arc<SlotLimiter>,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        let previous = self.limiter.in_use.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn never_issues_more_than_the_fixed_limit() {
        let limiter = Arc::new(SlotLimiter::new(2));
        let first = limiter.try_acquire().expect("first slot");
        let second = limiter.try_acquire().expect("second slot");
        assert!(limiter.try_acquire().is_none());
        assert_eq!(limiter.in_use(), 2);

        drop(first);
        let replacement = limiter.try_acquire().expect("released slot");
        assert_eq!(limiter.in_use(), 2);
        drop((second, replacement));
        assert_eq!(limiter.in_use(), 0);
    }

    #[test]
    fn concurrent_contenders_never_overcommit_and_every_permit_is_reclaimed() {
        const LIMIT: usize = 4;
        const CONTENDERS: usize = 32;

        let limiter = Arc::new(SlotLimiter::new(LIMIT));
        let start = Arc::new(Barrier::new(CONTENDERS + 1));
        let (reported, reports) = mpsc::channel();
        let contenders = (0..CONTENDERS)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let start = Arc::clone(&start);
                let reported = reported.clone();
                thread::spawn(move || {
                    start.wait();
                    reported
                        .send(limiter.try_acquire())
                        .expect("report acquisition outcome");
                })
            })
            .collect::<Vec<_>>();
        drop(reported);

        start.wait();
        let acquisitions = (0..CONTENDERS)
            .map(|_| {
                reports
                    .recv_timeout(Duration::from_secs(2))
                    .expect("contender reports without deadlock")
            })
            .collect::<Vec<_>>();
        for contender in contenders {
            contender.join().expect("contender thread");
        }
        assert_eq!(
            acquisitions
                .iter()
                .filter(|permit| permit.is_some())
                .count(),
            LIMIT
        );
        assert_eq!(limiter.in_use(), LIMIT);
        drop(acquisitions);
        assert_eq!(limiter.in_use(), 0);

        let replacements = (0..LIMIT)
            .map(|_| limiter.try_acquire().expect("replacement permit"))
            .collect::<Vec<_>>();
        assert!(limiter.try_acquire().is_none());
        drop(replacements);
        assert_eq!(limiter.in_use(), 0);
    }
}
