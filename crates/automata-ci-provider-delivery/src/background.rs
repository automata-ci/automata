//! Provider-neutral ownership and supervision of common background workers.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    ProviderProcessingWorker, ProviderProcessingWorkerError, ProviderResultWorker,
    ProviderResultWorkerError,
};

/// Process-lifetime common processing and connection-scoped result workers.
///
/// Provider-specific behavior remains behind the registries injected into the
/// workers. This aggregate owns only lifecycle: every worker starts together,
/// the first fatal exit stops new work everywhere, and in-flight fenced work is
/// allowed to reach the worker's bounded outcome before the aggregate returns.
pub struct ProviderBackgroundRuntime {
    processing: Vec<ProviderProcessingWorker>,
    results: Vec<ProviderResultWorker>,
}

impl ProviderBackgroundRuntime {
    /// Builds a runtime from explicitly provisioned common worker identities.
    ///
    /// An empty result-worker set is valid for providers that do not publish
    /// native status. Multiple result workers may serve one busy connection,
    /// but every process-lifetime worker identity must remain unique so durable
    /// claim ownership is unambiguous.
    ///
    /// # Errors
    ///
    /// Returns an error when no processing worker exists or a worker identity is
    /// reused within either durable queue family.
    pub fn new(
        processing: impl IntoIterator<Item = ProviderProcessingWorker>,
        results: impl IntoIterator<Item = ProviderResultWorker>,
    ) -> Result<Self, ProviderBackgroundRuntimeError> {
        let processing = processing.into_iter().collect::<Vec<_>>();
        let results = results.into_iter().collect::<Vec<_>>();
        if processing.is_empty() {
            return Err(ProviderBackgroundRuntimeError::MissingProcessingWorker);
        }
        let mut processing_ids = BTreeSet::new();
        if processing
            .iter()
            .any(|worker| !processing_ids.insert(worker.worker_id()))
        {
            return Err(ProviderBackgroundRuntimeError::DuplicateProcessingWorker);
        }
        let mut result_ids = BTreeSet::new();
        if results
            .iter()
            .any(|worker| !result_ids.insert(worker.worker_id()))
        {
            return Err(ProviderBackgroundRuntimeError::DuplicateResultWorker);
        }
        Ok(Self {
            processing,
            results,
        })
    }

    /// Runs all common provider workers as one fail-fast shutdown unit.
    ///
    /// Once shutdown or a fatal worker exit is observed, the shared stop token
    /// prevents new claims. Worker implementations finish their current fenced
    /// operation before returning, so this method drains every spawned task and
    /// never relies on task abortion for normal control flow.
    ///
    /// # Errors
    ///
    /// Returns the first fatal worker error, an unexpected successful worker
    /// exit, or a sanitized task failure after all remaining workers drain.
    pub async fn run(
        self,
        shutdown: CancellationToken,
    ) -> Result<(), ProviderBackgroundRuntimeError> {
        let stop = CancellationToken::new();
        let mut workers = JoinSet::new();

        for processing in self.processing {
            let processing_stop = stop.clone();
            workers.spawn(
                async move { WorkerExit::Processing(processing.run(processing_stop).await) },
            );
        }

        for result in self.results {
            let result_stop = stop.clone();
            workers.spawn(async move { WorkerExit::Result(result.run(result_stop).await) });
        }

        supervise_workers(workers, stop, shutdown).await
    }

    /// Returns the number of common processing workers.
    #[must_use]
    pub const fn processing_worker_count(&self) -> usize {
        self.processing.len()
    }

    /// Returns the number of connection-scoped result workers.
    #[must_use]
    pub const fn result_worker_count(&self) -> usize {
        self.results.len()
    }
}

async fn supervise_workers(
    mut workers: JoinSet<WorkerExit>,
    stop: CancellationToken,
    shutdown: CancellationToken,
) -> Result<(), ProviderBackgroundRuntimeError> {
    let mut failure = tokio::select! {
        () = shutdown.cancelled() => None,
        completed = workers.join_next() => Some(completed_worker(completed)),
    };

    stop.cancel();
    while let Some(completed) = workers.join_next().await {
        let error = completed_worker(Some(completed));
        if failure.is_none() && !matches!(error, ProviderBackgroundRuntimeError::UnexpectedStop) {
            failure = Some(error);
        }
    }

    failure.map_or(Ok(()), Err)
}

impl fmt::Debug for ProviderBackgroundRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBackgroundRuntime")
            .field(
                "processing_worker_ids",
                &self
                    .processing
                    .iter()
                    .map(ProviderProcessingWorker::worker_id)
                    .collect::<Vec<_>>(),
            )
            .field(
                "result_connections",
                &self
                    .results
                    .iter()
                    .map(ProviderResultWorker::connection_id)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

enum WorkerExit {
    Processing(Result<(), ProviderProcessingWorkerError>),
    Result(Result<(), ProviderResultWorkerError>),
}

fn completed_worker(
    completed: Option<Result<WorkerExit, JoinError>>,
) -> ProviderBackgroundRuntimeError {
    let Some(Ok(completed)) = completed else {
        return ProviderBackgroundRuntimeError::WorkerTask;
    };
    match completed {
        WorkerExit::Processing(Ok(())) | WorkerExit::Result(Ok(())) => {
            ProviderBackgroundRuntimeError::UnexpectedStop
        }
        WorkerExit::Processing(Err(error)) => ProviderBackgroundRuntimeError::Processing(error),
        WorkerExit::Result(Err(error)) => ProviderBackgroundRuntimeError::Result(error),
    }
}

/// Sanitized common background-runtime construction or supervision failure.
#[derive(Debug, Error)]
pub enum ProviderBackgroundRuntimeError {
    /// A runtime cannot service delivery or control work without a consumer.
    #[error("the provider background runtime has no processing worker")]
    MissingProcessingWorker,
    /// A durable processing worker identity was assigned to more than one loop.
    #[error("a provider processing worker identity is duplicated")]
    DuplicateProcessingWorker,
    /// A durable result worker identity was assigned to more than one loop.
    #[error("a provider result worker identity is duplicated")]
    DuplicateResultWorker,
    /// Common delivery or control processing failed terminally.
    #[error(transparent)]
    Processing(#[from] ProviderProcessingWorkerError),
    /// Common result publication failed terminally.
    #[error(transparent)]
    Result(#[from] ProviderResultWorkerError),
    /// A worker stopped successfully before aggregate shutdown.
    #[error("a provider background worker stopped unexpectedly")]
    UnexpectedStop,
    /// A spawned worker task could not be joined safely.
    #[error("a provider background worker task failed")]
    WorkerTask,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    #[tokio::test]
    async fn fatal_worker_stops_and_drains_siblings() {
        let stop = CancellationToken::new();
        let drained = Arc::new(AtomicBool::new(false));
        let mut workers = JoinSet::new();
        workers.spawn(async {
            WorkerExit::Processing(Err(ProviderProcessingWorkerError::Repository))
        });
        let sibling_stop = stop.clone();
        let sibling_drained = drained.clone();
        workers.spawn(async move {
            sibling_stop.cancelled().await;
            sibling_drained.store(true, Ordering::SeqCst);
            WorkerExit::Result(Ok(()))
        });

        let error = supervise_workers(workers, stop, CancellationToken::new())
            .await
            .expect_err("fatal worker");

        assert!(matches!(
            error,
            ProviderBackgroundRuntimeError::Processing(ProviderProcessingWorkerError::Repository)
        ));
        assert!(drained.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_stops_and_drains_all_workers_cleanly() {
        let stop = CancellationToken::new();
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let drained = Arc::new(AtomicBool::new(false));
        let mut workers = JoinSet::new();
        let worker_stop = stop.clone();
        let worker_drained = drained.clone();
        workers.spawn(async move {
            worker_stop.cancelled().await;
            worker_drained.store(true, Ordering::SeqCst);
            WorkerExit::Processing(Ok(()))
        });

        supervise_workers(workers, stop, shutdown)
            .await
            .expect("clean shutdown");

        assert!(drained.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn successful_worker_exit_before_shutdown_is_fatal() {
        let mut workers = JoinSet::new();
        workers.spawn(async { WorkerExit::Result(Ok(())) });

        let error = supervise_workers(workers, CancellationToken::new(), CancellationToken::new())
            .await
            .expect_err("unexpected stop");

        assert!(matches!(
            error,
            ProviderBackgroundRuntimeError::UnexpectedStop
        ));
    }
}
