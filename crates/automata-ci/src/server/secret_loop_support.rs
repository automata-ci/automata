//! Shared cancellation and exact-timing primitives for durable secret loops.

use std::{future::Future, time::Duration};

use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LoopAction {
    Stop,
    Drain,
    Poll,
}

pub(super) enum OperationWait<T> {
    Completed(T),
    Cancelled,
    TimedOut,
}

pub(super) async fn wait_for_operation<T>(
    cancellation: &CancellationToken,
    timeout: Duration,
    operation: impl Future<Output = T>,
) -> OperationWait<T> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => OperationWait::Cancelled,
        outcome = tokio::time::timeout(timeout, operation) => match outcome {
            Ok(value) => OperationWait::Completed(value),
            Err(_) => OperationWait::TimedOut,
        },
    }
}

pub(super) fn exact_millis(duration: Duration) -> Option<u64> {
    let millis = u64::try_from(duration.as_millis()).ok()?;
    (millis != 0 && Duration::from_millis(millis) == duration).then_some(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pre_cancelled_token_wins_over_immediately_ready_operation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let outcome = wait_for_operation(&cancellation, Duration::from_secs(1), async { 17 }).await;

        assert!(matches!(outcome, OperationWait::Cancelled));
    }

    #[tokio::test]
    async fn immediately_ready_operation_completes_without_cancellation() {
        let cancellation = CancellationToken::new();

        let outcome = wait_for_operation(&cancellation, Duration::from_secs(1), async { 17 }).await;

        assert!(matches!(outcome, OperationWait::Completed(17)));
    }

    #[test]
    fn exact_millis_accepts_only_positive_exact_representable_values() {
        assert_eq!(exact_millis(Duration::from_millis(1)), Some(1));
        assert_eq!(
            exact_millis(Duration::from_millis(u64::MAX)),
            Some(u64::MAX)
        );
        assert_eq!(exact_millis(Duration::ZERO), None);
        assert_eq!(exact_millis(Duration::from_nanos(999_999)), None);
        assert_eq!(
            exact_millis(Duration::from_millis(1) + Duration::from_nanos(1)),
            None
        );
        assert_eq!(exact_millis(Duration::MAX), None);
    }
}
