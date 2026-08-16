mod support;

use std::sync::Arc;

use automata_ci_runner_runtime::{
    AdmissionRejection, ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};

use support::{Fixture, action_step, local_action_step, windows_envelope};

#[test]
fn windows_repository_action_is_rejected_before_provider_mutation() {
    let fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    let job = windows_envelope(vec![action_step("checkout", "actions/example")]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .is_empty()
    );
}

#[tokio::test]
async fn direct_execute_cannot_bypass_windows_action_admission() {
    let fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    let job = windows_envelope(vec![action_step("checkout", "actions/example")]);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect_err("Windows action execution must fail closed");

    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .is_empty()
    );
}

#[tokio::test]
async fn direct_execute_trusts_the_windows_toolchain_over_request_environment() {
    let posix_environment = Fixture::new(Vec::new(), Vec::new()).environment;
    let mut fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    fixture.environment = posix_environment;
    let job = windows_envelope(vec![action_step("checkout", "actions/example")]);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect_err("the request environment must not weaken the Windows executor gate");

    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .commands
            .is_empty()
    );
}

#[test]
fn windows_local_javascript_action_is_rejected_before_provider_mutation() {
    let fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    let job = windows_envelope(vec![local_action_step("local", "./local-action")]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}

#[test]
fn windows_local_composite_action_is_rejected_before_provider_mutation() {
    let fixture = Fixture::windows_actions(Vec::new(), Vec::new());
    let job = windows_envelope(vec![local_action_step(
        "local-composite",
        "./local-composite",
    )]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}
