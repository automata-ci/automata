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
}
