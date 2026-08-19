//! Provider-neutral production ingress and background supervision.

use std::{collections::BTreeSet, fmt, future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use automata_ci_provider::ProviderTypeId;
use automata_ci_provider_delivery::{
    ProviderBackgroundRuntime, ProviderBackgroundRuntimeError, ProviderDeliveryIngress,
};
use automata_ci_workflow_service::{
    ProviderWorkflowResultProjectionError, ProviderWorkflowResultProjectionService,
};
use futures::{StreamExt as _, stream::FuturesUnordered};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::GithubProviderRuntime;

/// Immediate fail-fast notification emitted before provider services drain.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProviderFatalNotification;

#[async_trait]
pub trait ProviderAuxiliaryRuntime: fmt::Debug + Send {
    /// Returns the exact provider type owning this auxiliary runtime.
    fn provider_type(&self) -> ProviderTypeId;

    /// Runs provider-specific background services until common shutdown.
    ///
    /// The `fatal` signal must be raised as soon as a terminal failure is
    /// observed, before bounded provider-specific drain completes.
    async fn run(
        self: Box<Self>,
        shutdown: CancellationToken,
        fatal: CancellationToken,
    ) -> Result<(), ProviderAuxiliaryRuntimeError>;
}

#[async_trait]
impl ProviderAuxiliaryRuntime for GithubProviderRuntime {
    fn provider_type(&self) -> ProviderTypeId {
        self.runtime_adapter().provider_type().clone()
    }

    async fn run(
        self: Box<Self>,
        shutdown: CancellationToken,
        fatal: CancellationToken,
    ) -> Result<(), ProviderAuxiliaryRuntimeError> {
        (*self)
            .run_with_fatal_signal(shutdown, fatal)
            .await
            .map_err(|error| {
                tracing::error!(%error, provider = "github", "provider auxiliary runtime failed");
                ProviderAuxiliaryRuntimeError
            })
    }
}

/// One provider-neutral HTTP ingress and statically registered runtime set.
pub struct ProviderRuntime {
    ingress: Arc<ProviderDeliveryIngress>,
    background: ProviderBackgroundRuntime,
    workflow_results: ProviderWorkflowResultProjectionService,
    auxiliaries: Vec<Box<dyn ProviderAuxiliaryRuntime>>,
}

impl ProviderRuntime {
    /// Composes common durable workers with optional provider-specific auxiliaries.
    ///
    /// # Errors
    ///
    /// Rejects duplicate auxiliary runtimes for the same provider type.
    pub fn new(
        ingress: Arc<ProviderDeliveryIngress>,
        background: ProviderBackgroundRuntime,
        workflow_results: ProviderWorkflowResultProjectionService,
        auxiliaries: impl IntoIterator<Item = Box<dyn ProviderAuxiliaryRuntime>>,
    ) -> Result<Self, ProviderRuntimeBuildError> {
        let auxiliaries = auxiliaries.into_iter().collect::<Vec<_>>();
        let mut provider_types = BTreeSet::new();
        if auxiliaries
            .iter()
            .any(|runtime| !provider_types.insert(runtime.provider_type()))
        {
            return Err(ProviderRuntimeBuildError::DuplicateAuxiliary);
        }
        Ok(Self {
            ingress,
            background,
            workflow_results,
            auxiliaries,
        })
    }

    /// Returns the sole provider-neutral webhook ingress.
    #[must_use]
    pub fn ingress(&self) -> Arc<ProviderDeliveryIngress> {
        Arc::clone(&self.ingress)
    }

    pub(super) async fn run_with_fatal_notification(
        self,
        shutdown: CancellationToken,
        fatal_notification: oneshot::Sender<ProviderFatalNotification>,
    ) -> Result<(), ProviderRuntimeError> {
        let Self {
            ingress: _,
            background,
            workflow_results,
            auxiliaries,
        } = self;
        let stop = CancellationToken::new();
        let auxiliary_fatal = CancellationToken::new();
        let loops = FuturesUnordered::new();
        let background_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::Background(background.run(background_stop).await)
        }));
        let projection_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::WorkflowResults(workflow_results.run(projection_stop).await)
        }));
        for auxiliary in auxiliaries {
            let auxiliary_stop = stop.clone();
            let auxiliary_fatal = auxiliary_fatal.clone();
            loops.push(runtime_loop(async move {
                RuntimeLoopExit::Auxiliary(auxiliary.run(auxiliary_stop, auxiliary_fatal).await)
            }));
        }
        supervise_runtime(loops, stop, shutdown, auxiliary_fatal, fatal_notification).await
    }
}

impl fmt::Debug for ProviderRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRuntime")
            .field("ingress", &self.ingress)
            .field("background", &self.background)
            .field("workflow_results", &self.workflow_results)
            .field(
                "auxiliary_provider_types",
                &self
                    .auxiliaries
                    .iter()
                    .map(|runtime| runtime.provider_type())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

enum RuntimeLoopExit {
    Background(Result<(), ProviderBackgroundRuntimeError>),
    WorkflowResults(Result<(), ProviderWorkflowResultProjectionError>),
    Auxiliary(Result<(), ProviderAuxiliaryRuntimeError>),
}

type RuntimeLoopFuture = Pin<Box<dyn Future<Output = RuntimeLoopExit> + Send>>;

fn runtime_loop(
    future: impl Future<Output = RuntimeLoopExit> + Send + 'static,
) -> RuntimeLoopFuture {
    Box::pin(future)
}

async fn supervise_runtime(
    mut loops: FuturesUnordered<RuntimeLoopFuture>,
    stop: CancellationToken,
    shutdown: CancellationToken,
    auxiliary_fatal: CancellationToken,
    fatal_notification: oneshot::Sender<ProviderFatalNotification>,
) -> Result<(), ProviderRuntimeError> {
    let shutdown_requested;
    let first = tokio::select! {
        () = shutdown.cancelled() => {
            shutdown_requested = true;
            None
        }
        exit = loops.next() => {
            shutdown_requested = shutdown.is_cancelled();
            exit
        }
        () = auxiliary_fatal.cancelled() => {
            shutdown_requested = false;
            None
        }
    };
    let mut failure = match first {
        Some(exit) => runtime_error(exit),
        None => None,
    };
    if !shutdown_requested {
        let _ = fatal_notification.send(ProviderFatalNotification);
    }
    stop.cancel();
    while let Some(exit) = loops.next().await {
        if failure.is_none() {
            failure = runtime_error(exit);
        }
    }
    if !shutdown_requested && failure.is_none() {
        failure = Some(ProviderRuntimeError::UnexpectedStop);
    }
    failure.map_or(Ok(()), Err)
}

fn runtime_error(exit: RuntimeLoopExit) -> Option<ProviderRuntimeError> {
    match exit {
        RuntimeLoopExit::Background(Ok(()))
        | RuntimeLoopExit::WorkflowResults(Ok(()))
        | RuntimeLoopExit::Auxiliary(Ok(())) => None,
        RuntimeLoopExit::Background(Err(error)) => Some(error.into()),
        RuntimeLoopExit::WorkflowResults(Err(error)) => Some(error.into()),
        RuntimeLoopExit::Auxiliary(Err(error)) => Some(error.into()),
    }
}

/// Sanitized provider-specific auxiliary failure.
#[derive(Debug, Error)]
#[error("provider auxiliary runtime failed")]
pub struct ProviderAuxiliaryRuntimeError;

/// Invalid provider runtime topology.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderRuntimeBuildError {
    /// A provider registered more than one auxiliary runtime.
    #[error("a provider auxiliary runtime is duplicated")]
    DuplicateAuxiliary,
}

/// Sanitized provider runtime failure.
#[derive(Debug, Error)]
pub enum ProviderRuntimeError {
    /// Common delivery processing or result publication failed.
    #[error(transparent)]
    Background(#[from] ProviderBackgroundRuntimeError),
    /// Durable workflow lifecycle projection failed.
    #[error(transparent)]
    WorkflowResults(#[from] ProviderWorkflowResultProjectionError),
    /// A provider-specific auxiliary service failed.
    #[error(transparent)]
    Auxiliary(#[from] ProviderAuxiliaryRuntimeError),
    /// A provider runtime loop returned before shutdown.
    #[error("a provider runtime loop stopped unexpectedly")]
    UnexpectedStop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fatal_exit_notifies_before_common_siblings_finish_draining() {
        let stop = CancellationToken::new();
        let release = CancellationToken::new();
        let loops = FuturesUnordered::new();
        loops.push(runtime_loop(async {
            RuntimeLoopExit::Auxiliary(Err(ProviderAuxiliaryRuntimeError))
        }));
        let sibling_stop = stop.clone();
        let sibling_release = release.clone();
        loops.push(runtime_loop(async move {
            sibling_stop.cancelled().await;
            sibling_release.cancelled().await;
            RuntimeLoopExit::WorkflowResults(Ok(()))
        }));
        let (fatal_sender, fatal_receiver) = oneshot::channel();
        let runtime = tokio::spawn(supervise_runtime(
            loops,
            stop,
            CancellationToken::new(),
            CancellationToken::new(),
            fatal_sender,
        ));

        tokio::time::timeout(std::time::Duration::from_secs(1), fatal_receiver)
            .await
            .expect("fatal notification")
            .expect("fatal sender remains owned");
        assert!(
            !runtime.is_finished(),
            "common siblings remain owned while draining"
        );
        release.cancel();
        assert!(matches!(
            runtime.await.expect("runtime task"),
            Err(ProviderRuntimeError::Auxiliary(_))
        ));
    }

    #[tokio::test]
    async fn requested_shutdown_drains_without_a_fatal_notification() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let stop = CancellationToken::new();
        let worker_stop = stop.clone();
        let loops = FuturesUnordered::new();
        loops.push(runtime_loop(async move {
            worker_stop.cancelled().await;
            RuntimeLoopExit::Background(Ok(()))
        }));
        let (fatal_sender, fatal_receiver) = oneshot::channel();

        supervise_runtime(
            loops,
            stop,
            shutdown,
            CancellationToken::new(),
            fatal_sender,
        )
        .await
        .expect("ordered shutdown");
        assert!(fatal_receiver.await.is_err());
    }
}
