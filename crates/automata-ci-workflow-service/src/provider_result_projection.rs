//! Autonomous reconciliation of durable workflow lifecycle into provider results.

use std::{sync::Arc, time::Duration};

use automata_ci_provider::{
    ProviderResultRepositoryError, ProviderResultSaveOutcome, ProviderWorkflowResultSource,
};
use thiserror::Error;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::{ProviderWorkflowResultService, ProviderWorkflowResultServiceError};

const IDLE_POLL_MILLIS: u64 = 250;

/// Result of one provider workflow-result reconciliation poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWorkflowResultProjectionOutcome {
    /// No durable lifecycle is newer than its desired result.
    Idle,
    /// Initial subject production has not committed yet; the observation stays due.
    Deferred,
    /// One lifecycle was reconciled into the common desired-result outbox.
    Projected(ProviderResultSaveOutcome),
}

/// Lock-free worker over durable CI state and the common result outbox.
#[derive(Clone, Debug)]
pub struct ProviderWorkflowResultProjectionService {
    source: Arc<dyn ProviderWorkflowResultSource>,
    results: ProviderWorkflowResultService,
}

impl ProviderWorkflowResultProjectionService {
    /// Composes lifecycle discovery with provider-neutral desired-result production.
    #[must_use]
    pub const fn new(
        source: Arc<dyn ProviderWorkflowResultSource>,
        results: ProviderWorkflowResultService,
    ) -> Self {
        Self { source, results }
    }

    /// Reconciles at most one stale workflow result.
    ///
    /// Exclusive custody is unnecessary: concurrent observations converge
    /// through monotonic, idempotent desired-result reconciliation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized source, result, or cancellation failure.
    pub async fn run_once(
        &self,
        shutdown: CancellationToken,
    ) -> Result<ProviderWorkflowResultProjectionOutcome, ProviderWorkflowResultProjectionError>
    {
        if shutdown.is_cancelled() {
            return Err(ProviderWorkflowResultProjectionError::Shutdown);
        }
        let observation = tokio::select! {
            () = shutdown.cancelled() => {
                return Err(ProviderWorkflowResultProjectionError::Shutdown);
            }
            result = self.source.next_workflow_result() => {
                result.map_err(source_error)?
            }
        };
        let Some(observation) = observation else {
            return Ok(ProviderWorkflowResultProjectionOutcome::Idle);
        };
        let projected = tokio::select! {
            () = shutdown.cancelled() => {
                return Err(ProviderWorkflowResultProjectionError::Shutdown);
            }
            result = self.results.reconcile_workflow_run(
                observation.run_id(),
                observation.state(),
                observation.updated_at(),
            ) => result,
        };
        match projected {
            Ok(outcome) => Ok(ProviderWorkflowResultProjectionOutcome::Projected(outcome)),
            Err(ProviderWorkflowResultServiceError::SubjectNotReady) => {
                Ok(ProviderWorkflowResultProjectionOutcome::Deferred)
            }
            Err(error) => Err(result_error(error)),
        }
    }

    /// Reconciles until cancellation or the first non-retryable failure.
    ///
    /// # Errors
    ///
    /// Returns the first sanitized source or result failure. Cancellation
    /// stops normally without starting further work.
    pub async fn run(
        &self,
        shutdown: CancellationToken,
    ) -> Result<(), ProviderWorkflowResultProjectionError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            let delay = match self.run_once(shutdown.child_token()).await {
                Ok(ProviderWorkflowResultProjectionOutcome::Projected(_)) => {
                    tokio::task::yield_now().await;
                    None
                }
                Ok(
                    ProviderWorkflowResultProjectionOutcome::Idle
                    | ProviderWorkflowResultProjectionOutcome::Deferred,
                ) => Some(Duration::from_millis(IDLE_POLL_MILLIS)),
                Err(ProviderWorkflowResultProjectionError::Shutdown) if shutdown.is_cancelled() => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if let Some(delay) = delay {
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = sleep(delay) => {}
                }
            }
        }
    }
}

const fn source_error(
    error: ProviderResultRepositoryError,
) -> ProviderWorkflowResultProjectionError {
    match error {
        ProviderResultRepositoryError::Unavailable => {
            ProviderWorkflowResultProjectionError::Unavailable
        }
        ProviderResultRepositoryError::Conflict
        | ProviderResultRepositoryError::StaleClaim
        | ProviderResultRepositoryError::NotFound
        | ProviderResultRepositoryError::Corrupt => {
            ProviderWorkflowResultProjectionError::Inconsistent
        }
    }
}

const fn result_error(
    error: ProviderWorkflowResultServiceError,
) -> ProviderWorkflowResultProjectionError {
    match error {
        ProviderWorkflowResultServiceError::Unavailable => {
            ProviderWorkflowResultProjectionError::Unavailable
        }
        ProviderWorkflowResultServiceError::InvalidConfiguration
        | ProviderWorkflowResultServiceError::InvalidEvidence
        | ProviderWorkflowResultServiceError::SubjectNotReady
        | ProviderWorkflowResultServiceError::Inconsistent => {
            ProviderWorkflowResultProjectionError::Inconsistent
        }
    }
}

/// Sanitized autonomous provider workflow-result projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderWorkflowResultProjectionError {
    /// The worker was cancelled before its current operation completed.
    #[error("provider workflow result projection was cancelled")]
    Shutdown,
    /// Durable source or result storage is temporarily unavailable.
    #[error("provider workflow result projection storage is unavailable")]
    Unavailable,
    /// Durable lifecycle and result state contradict each other.
    #[error("provider workflow result projection state is inconsistent")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use automata_ci_core::{RunId, UnixMillis};
    use automata_ci_provider::{
        ClaimProviderResult, ClaimedProviderResult, CompleteProviderResult, FailProviderResult,
        ProviderResultFuture, ProviderResultRepository, ProviderResultRepositoryError,
        ProviderResultSaveOutcome, ProviderWorkflowResultObservation, ProviderWorkflowResultSource,
        ProviderWorkflowRunState, RetryProviderResult, SaveDesiredProviderResult,
    };
    use tokio_util::sync::CancellationToken;
    use url::Url;
    use uuid::Uuid;

    use super::{
        ProviderWorkflowResultProjectionError, ProviderWorkflowResultProjectionOutcome,
        ProviderWorkflowResultProjectionService,
    };
    use crate::ProviderWorkflowResultService;

    #[derive(Debug)]
    struct FixedSource(Option<ProviderWorkflowResultObservation>);

    impl ProviderWorkflowResultSource for FixedSource {
        fn next_workflow_result(
            &self,
        ) -> ProviderResultFuture<'_, Option<ProviderWorkflowResultObservation>> {
            Box::pin(async move { Ok(self.0) })
        }
    }

    #[derive(Debug)]
    struct MissingResults;

    impl ProviderResultRepository for MissingResults {
        fn load_workflow_subject(
            &self,
            _run_id: RunId,
        ) -> ProviderResultFuture<'_, Option<automata_ci_provider::ProviderResultSubject>> {
            Box::pin(async { Ok(None) })
        }

        fn save_desired(
            &self,
            _request: SaveDesiredProviderResult,
        ) -> ProviderResultFuture<'_, ProviderResultSaveOutcome> {
            Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
        }

        fn claim_result(
            &self,
            _request: ClaimProviderResult,
        ) -> ProviderResultFuture<'_, Option<ClaimedProviderResult>> {
            Box::pin(async { Ok(None) })
        }

        fn complete_result(
            &self,
            _request: CompleteProviderResult,
        ) -> ProviderResultFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn retry_result(&self, _request: RetryProviderResult) -> ProviderResultFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn fail_result(&self, _request: FailProviderResult) -> ProviderResultFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    fn service(
        observation: Option<ProviderWorkflowResultObservation>,
    ) -> ProviderWorkflowResultProjectionService {
        ProviderWorkflowResultProjectionService::new(
            Arc::new(FixedSource(observation)),
            ProviderWorkflowResultService::new(
                Arc::new(MissingResults),
                Url::parse("https://ci.example/").unwrap(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn idle_and_missing_subject_observations_remain_distinct() {
        assert_eq!(
            service(None)
                .run_once(CancellationToken::new())
                .await
                .unwrap(),
            ProviderWorkflowResultProjectionOutcome::Idle
        );
        let observation = ProviderWorkflowResultObservation::new(
            RunId::from_uuid(Uuid::from_u128(42)),
            ProviderWorkflowRunState::Running,
            UnixMillis::new(42),
        )
        .unwrap();
        assert_eq!(
            service(Some(observation))
                .run_once(CancellationToken::new())
                .await
                .unwrap(),
            ProviderWorkflowResultProjectionOutcome::Deferred
        );
    }

    #[tokio::test]
    async fn cancellation_prevents_source_work() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        assert_eq!(
            service(None).run_once(shutdown).await,
            Err(ProviderWorkflowResultProjectionError::Shutdown)
        );
    }
}
