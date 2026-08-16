mod support;

use std::sync::Arc;

use automata_ci_core::JobConclusion;
use automata_ci_execution::{ProviderId, SandboxGeneration, SandboxHandle};
use automata_ci_runner_runtime::{
    CleanupRequest, ExecutionCancellation, ExecutionEvents, JobExecutor,
};

use support::{Fixture, PhaseResponse, journal_identity, run_job};

#[tokio::test]
async fn cancelled_phase_returns_cancelled_and_cleanup_destroys_the_exact_fenced_sandbox() {
    let cancellation = ExecutionCancellation::new();
    let fixture = Fixture::new(
        Vec::new(),
        vec![
            PhaseResponse::success()
                .cancelled()
                .signal(cancellation.clone()),
        ],
    );
    let request = fixture.request(run_job("exit 0\n"));
    let session_id = request.session_id();
    let slot = request.slot();
    let runner_id = request.lease().runner_id();
    let attempt_id = request.lease().attempt_id();
    let guard = request.lease().guard();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events.clone(), cancellation.clone())
        .await
        .expect("cancelled process is a terminal job result");

    assert!(cancellation.is_cancelled());
    assert_eq!(result.conclusion(), JobConclusion::Cancelled);
    assert_eq!(fixture.events.sandbox(), Some(journal_identity()));
    let cleanup = CleanupRequest::new(
        runner_id,
        session_id,
        slot,
        attempt_id,
        guard,
        journal_identity(),
    );
    let expected_custody = cleanup.sandbox_custody();
    fixture
        .executor
        .cleanup(cleanup, events, ExecutionCancellation::new())
        .await
        .expect("cleanup succeeds");
    assert_eq!(fixture.provider.counts(), (1, 1, 1));
    let destroy_requests = fixture.provider.destroy_requests();
    assert_eq!(destroy_requests.len(), 1);
    let destroy_request = &destroy_requests[0];
    let expected_identity = journal_identity();
    let expected_handle = SandboxHandle::new(
        ProviderId::new(expected_identity.provider().as_str()).expect("valid provider"),
        expected_identity.handle().as_str(),
    )
    .expect("valid sandbox handle");
    assert_eq!(destroy_request.handle(), &expected_handle);
    assert_eq!(destroy_request.custody(), expected_custody);
    assert_eq!(
        destroy_request.generation(),
        SandboxGeneration::new(guard.fencing_token().get()).expect("valid generation")
    );
    assert_eq!(fixture.events.sandbox(), None);
}
