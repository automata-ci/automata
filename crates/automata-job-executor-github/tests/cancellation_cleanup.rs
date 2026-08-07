mod support;

use std::sync::Arc;

use automata_core::JobConclusion;
use automata_runner_runtime::{
    CleanupRequest, ExecutionCancellation, ExecutionEvents, JobExecutor,
};

use support::{Fixture, PhaseResponse, journal_identity, run_job};

#[tokio::test]
async fn cancelled_phase_returns_cancelled_and_cleanup_destroys_the_exact_fenced_sandbox() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success().cancelled()]);
    let request = fixture.request(run_job("exit 0\n"));
    let session_id = request.session_id();
    let slot = request.slot();
    let attempt_id = request.lease().attempt_id();
    let guard = request.lease().guard();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events.clone(), ExecutionCancellation::new())
        .await
        .expect("cancelled process is a terminal job result");

    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(fixture.events.sandbox(), Some(journal_identity()));
    let cleanup = CleanupRequest::new(session_id, slot, attempt_id, guard, journal_identity());
    fixture
        .executor
        .cleanup(cleanup, events, ExecutionCancellation::new())
        .await
        .expect("cleanup succeeds");
    assert_eq!(fixture.provider.counts(), (1, 1, 1));
    assert_eq!(fixture.events.sandbox(), None);
}
