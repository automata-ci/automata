use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use automata::server::{ManagedServiceError, supervise_services};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

async fn fake_service(
    cancellation: CancellationToken,
    entered: Arc<AtomicUsize>,
    drained: Arc<AtomicUsize>,
) -> Result<(), ManagedServiceError> {
    entered.fetch_add(1, Ordering::AcqRel);
    cancellation.cancelled().await;
    drained.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

#[tokio::test]
async fn one_shutdown_signal_drains_every_managed_service() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let supervisor = supervise_services(
        (
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
        ),
        async move {
            let _ = shutdown_rx.await;
        },
        cancellation,
    );
    let task = tokio::spawn(supervisor);

    while entered.load(Ordering::Acquire) != 5 {
        tokio::task::yield_now().await;
    }
    shutdown_tx
        .send(())
        .expect("supervisor must await shutdown");

    task.await
        .expect("supervisor task must join")
        .expect("graceful shutdown must succeed");
    assert_eq!(drained.load(Ordering::Acquire), 5);
}
