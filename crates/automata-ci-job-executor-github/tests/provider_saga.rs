mod support;

use std::sync::Arc;

use automata_ci_core::JobConclusion;
use automata_ci_execution::{OperationOutcome, ProviderErrorKind};
use automata_ci_runner_journal::{
    ProviderFailureKind, ProviderFailureOutcome, ProviderOperationKind,
};
use automata_ci_runner_runtime::{
    CleanupRequest, ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};

use support::{Fixture, PhaseResponse, journal_identity, run_job};

const PROVIDER_FAILURE_CASES: &[(ProviderErrorKind, ExecutorErrorKind, ProviderFailureKind)] = &[
    (
        ProviderErrorKind::UnsupportedPlatform,
        ExecutorErrorKind::Unsupported,
        ProviderFailureKind::Unsupported,
    ),
    (
        ProviderErrorKind::UnsupportedCapability,
        ExecutorErrorKind::Unsupported,
        ProviderFailureKind::Unsupported,
    ),
    (
        ProviderErrorKind::Cancelled,
        ExecutorErrorKind::Cancelled,
        ProviderFailureKind::Internal,
    ),
    (
        ProviderErrorKind::TimedOut,
        ExecutorErrorKind::TimedOut,
        ProviderFailureKind::TimedOut,
    ),
    (
        ProviderErrorKind::AdapterUnavailable,
        ExecutorErrorKind::Unavailable,
        ProviderFailureKind::Unavailable,
    ),
    (
        ProviderErrorKind::InvalidConfiguration,
        ExecutorErrorKind::Internal,
        ProviderFailureKind::InvalidRequest,
    ),
    (
        ProviderErrorKind::NotFound,
        ExecutorErrorKind::Internal,
        ProviderFailureKind::NotFound,
    ),
    (
        ProviderErrorKind::Conflict,
        ExecutorErrorKind::Internal,
        ProviderFailureKind::Conflict,
    ),
    (
        ProviderErrorKind::OwnershipMismatch,
        ExecutorErrorKind::Internal,
        ProviderFailureKind::Conflict,
    ),
    (
        ProviderErrorKind::InvalidState,
        ExecutorErrorKind::Internal,
        ProviderFailureKind::Internal,
    ),
    (
        ProviderErrorKind::OutputLimitExceeded,
        ExecutorErrorKind::ResourceExhausted,
        ProviderFailureKind::ResourceExhausted,
    ),
    (
        ProviderErrorKind::BackendRejected,
        ExecutorErrorKind::Internal,
        ProviderFailureKind::Internal,
    ),
    (
        ProviderErrorKind::LocalStorage,
        ExecutorErrorKind::Unavailable,
        ProviderFailureKind::Unavailable,
    ),
];

#[tokio::test]
async fn provider_intent_commit_failure_prevents_every_provider_call() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    fixture.events.fail_next_begin_provider_operation();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(
            fixture.request(run_job("true\n")),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("a missing durable create intent must stop execution");

    assert_eq!(error.kind(), ExecutorErrorKind::Internal);
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert_eq!(fixture.provider.unique_create_operation_count(), 0);
    assert!(fixture.provider.specs().is_empty());
    assert!(fixture.events.provider_operation_begins().is_empty());
    assert_eq!(fixture.events.pending_provider_operation(), None);
    assert_eq!(fixture.events.sandbox(), None);
}

#[tokio::test]
async fn sandbox_identity_commit_failure_replays_the_exact_create_intent() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success()]);
    fixture.events.fail_next_sandbox_created();
    let request = fixture.request(run_job("true\n"));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(
            request.clone(),
            events.clone(),
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("the sandbox identity must be durable before execution continues");

    assert_eq!(error.kind(), ExecutorErrorKind::Internal);
    assert_eq!(fixture.provider.counts(), (1, 0, 0));
    assert_eq!(fixture.provider.unique_create_operation_count(), 1);
    assert_eq!(fixture.events.sandbox(), None);
    let pending = fixture
        .events
        .pending_provider_operation()
        .expect("the committed create intent remains recoverable");
    assert_eq!(pending.1, ProviderOperationKind::CreateSandbox);
    let first_specs = fixture.provider.specs();
    assert_eq!(first_specs.len(), 1);
    assert_eq!(first_specs[0].operation_id(), pending.0);

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("retrying the exact create intent succeeds");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(fixture.provider.counts(), (2, 1, 0));
    assert_eq!(
        fixture.provider.unique_create_operation_count(),
        1,
        "provider create replay must not identify a second resource"
    );
    let specs = fixture.provider.specs();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].operation_id(), specs[1].operation_id());
    assert_eq!(specs[0].operation_id(), pending.0);
    assert_eq!(
        fixture.events.provider_operation_begins(),
        vec![pending, pending],
        "both begin calls must resolve to the same durable operation"
    );
    assert_eq!(fixture.events.pending_provider_operation(), None);
    assert_eq!(fixture.events.sandbox(), Some(journal_identity()));
}

#[tokio::test]
async fn provider_failure_commit_failure_retains_the_exact_create_intent() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success()]);
    fixture.provider.fail_next_create(
        ProviderErrorKind::AdapterUnavailable,
        OperationOutcome::KnownNoEffect,
    );
    fixture.events.fail_next_provider_operation_failed();
    let request = fixture.request(run_job("true\n"));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(
            request.clone(),
            events.clone(),
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("a provider failure remains an execution failure");

    assert_eq!(error.kind(), ExecutorErrorKind::Unavailable);
    assert_eq!(fixture.provider.counts(), (1, 0, 0));
    let pending = fixture
        .events
        .pending_provider_operation()
        .expect("failed failure-event commit retains the create intent");
    assert_eq!(pending.1, ProviderOperationKind::CreateSandbox);
    assert_eq!(fixture.events.provider_operation_begins(), vec![pending]);
    assert_eq!(fixture.events.sandbox(), None);

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("the retained create intent can be retried");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(fixture.provider.counts(), (2, 1, 0));
    assert_eq!(fixture.provider.unique_create_operation_count(), 1);
    let specs = fixture.provider.specs();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].operation_id(), pending.0);
    assert_eq!(specs[1].operation_id(), pending.0);
    assert_eq!(
        fixture.events.provider_operation_begins(),
        vec![pending, pending]
    );
    assert_eq!(fixture.events.pending_provider_operation(), None);
    assert_eq!(fixture.events.sandbox(), Some(journal_identity()));
}

#[tokio::test]
async fn provider_failures_map_to_exact_executor_and_durable_domains() {
    for &(provider_kind, executor_kind, failure_kind) in PROVIDER_FAILURE_CASES {
        for outcome in [OperationOutcome::KnownNoEffect, OperationOutcome::Uncertain] {
            let fixture = Fixture::new(Vec::new(), Vec::new());
            fixture.provider.fail_next_create(provider_kind, outcome);
            let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

            let error = fixture
                .executor
                .execute(
                    fixture.request(run_job("true\n")),
                    events,
                    ExecutionCancellation::new(),
                )
                .await
                .expect_err("injected provider creation failure");

            assert_eq!(
                error.kind(),
                executor_kind,
                "wrong executor mapping for {provider_kind:?} with {outcome:?}"
            );
            let operation_begins = fixture.events.provider_operation_begins();
            let [(operation_id, operation_kind)] = operation_begins.as_slice() else {
                panic!("one durable create intent for {provider_kind:?} with {outcome:?}");
            };
            assert_eq!(*operation_kind, ProviderOperationKind::CreateSandbox);
            let expected_failure = match outcome {
                OperationOutcome::KnownNoEffect => {
                    ProviderFailureOutcome::KnownNoEffect(failure_kind)
                }
                OperationOutcome::Uncertain => ProviderFailureOutcome::Uncertain(failure_kind),
            };
            assert_eq!(
                fixture.events.provider_operation_failures(),
                vec![(*operation_id, expected_failure)],
                "wrong journal mapping for {provider_kind:?} with {outcome:?}"
            );
            assert_eq!(
                fixture.events.pending_provider_operation(),
                (outcome == OperationOutcome::Uncertain)
                    .then_some((*operation_id, ProviderOperationKind::CreateSandbox)),
                "wrong replay state for {provider_kind:?} with {outcome:?}"
            );
            assert_eq!(fixture.provider.counts(), (1, 0, 0));
            assert_eq!(fixture.events.sandbox(), None);
        }
    }
}

#[tokio::test]
async fn destroy_completion_commit_failure_retains_and_replays_exact_custody() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success()]);
    let request = fixture.request(run_job("true\n"));
    let session_id = request.session_id();
    let slot = request.slot();
    let attempt_id = request.lease().attempt_id();
    let guard = request.lease().guard();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events.clone(), ExecutionCancellation::new())
        .await
        .expect("sandbox creation succeeds before cleanup fault injection");
    assert_eq!(result.conclusion(), JobConclusion::Success);
    let retained = fixture
        .events
        .sandbox()
        .expect("successful creation records exact sandbox custody");
    assert_eq!(retained, journal_identity());
    let cleanup = CleanupRequest::new(session_id, slot, attempt_id, guard, retained.clone());

    fixture.events.fail_next_provider_operation_completed();
    let error = fixture
        .executor
        .cleanup(
            cleanup.clone(),
            events.clone(),
            ExecutionCancellation::new(),
        )
        .await
        .expect_err("destroy is not complete until its durable completion commits");

    assert_eq!(error.kind(), ExecutorErrorKind::Internal);
    assert_eq!(fixture.provider.counts(), (1, 1, 1));
    assert_eq!(fixture.events.sandbox(), Some(retained.clone()));
    let pending = fixture
        .events
        .pending_provider_operation()
        .expect("failed completion retains the destroy intent");
    assert_eq!(pending.1, ProviderOperationKind::DestroySandbox);
    let first_destroy = fixture.provider.destroy_requests();
    assert_eq!(first_destroy.len(), 1);
    assert_eq!(first_destroy[0].operation_id(), pending.0);

    fixture
        .executor
        .cleanup(cleanup, events, ExecutionCancellation::new())
        .await
        .expect("the exact retained destroy intent can be retried");

    assert_eq!(fixture.provider.counts(), (1, 1, 2));
    let destroy_requests = fixture.provider.destroy_requests();
    assert_eq!(destroy_requests.len(), 2);
    assert_eq!(destroy_requests[0], destroy_requests[1]);
    assert_eq!(destroy_requests[0].operation_id(), pending.0);
    let operations = fixture.events.provider_operation_begins();
    assert_eq!(operations.len(), 3);
    assert_eq!(operations[1], pending);
    assert_eq!(operations[2], pending);
    assert_eq!(fixture.events.pending_provider_operation(), None);
    assert_eq!(fixture.events.sandbox(), None);
}
