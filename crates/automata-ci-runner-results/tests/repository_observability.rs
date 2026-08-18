mod observability_support;

use std::sync::Arc;

use automata_ci_core::{AttemptId, FencingToken, JobId, RunId};
use automata_ci_runner_results::{
    ArtifactName, ArtifactRepository, ArtifactRepositoryErrorKind, ExecutionAuthority,
    ListArtifacts, ObservedResultsArtifactRepository, ResultsRepositoryOperation,
    ResultsRepositoryOperationOutcome,
};
use observability_support::{
    observer::RecordingObserver,
    repository::{ListArtifactsBehavior, TestArtifactRepository},
};
use tokio::sync::Notify;

fn list_request(name: &str) -> ListArtifacts {
    ListArtifacts {
        authority: ExecutionAuthority::new(
            RunId::new(),
            JobId::new(),
            AttemptId::new(),
            FencingToken::new(3).expect("fencing token"),
        ),
        name: Some(ArtifactName::new(name, 255).expect("artifact name")),
        artifact_id: None,
        observed_at_seconds: 10,
        maximum_results: 5,
    }
}

#[tokio::test]
async fn repository_success_and_error_map_to_closed_identifier_free_outcomes() {
    for (behavior, expected) in [
        (
            ListArtifactsBehavior::Success,
            ResultsRepositoryOperationOutcome::Success,
        ),
        (
            ListArtifactsBehavior::Conflict,
            ResultsRepositoryOperationOutcome::Conflict,
        ),
    ] {
        let recorder = RecordingObserver::default();
        let inner: Arc<dyn ArtifactRepository> = Arc::new(TestArtifactRepository {
            list_artifacts: behavior,
            ..TestArtifactRepository::default()
        });
        let repository = ObservedResultsArtifactRepository::new(inner, Arc::new(recorder.clone()));
        let result = repository
            .list(list_request("private-artifact-marker"))
            .await;
        if expected == ResultsRepositoryOperationOutcome::Success {
            assert_eq!(result.expect("successful list"), Vec::new());
        } else {
            assert_eq!(
                result.expect_err("conflicting list").kind(),
                ArtifactRepositoryErrorKind::Conflict
            );
        }
        let observations = recorder.snapshot();
        let observations = &observations.repository_operations;
        assert_eq!(observations.len(), 1);
        assert_eq!(
            (observations[0].0, observations[0].1),
            (ResultsRepositoryOperation::List, expected)
        );
        assert!(!format!("{observations:?}").contains("private-artifact-marker"));
    }
}

#[tokio::test]
async fn adversarial_artifact_names_never_cross_the_typed_observer_boundary() {
    let recorder = RecordingObserver::default();
    let inner: Arc<dyn ArtifactRepository> = Arc::new(TestArtifactRepository {
        list_artifacts: ListArtifactsBehavior::Success,
        ..TestArtifactRepository::default()
    });
    let repository = ObservedResultsArtifactRepository::new(inner, Arc::new(recorder.clone()));
    let mut forbidden = Vec::new();

    for index in 0..128 {
        let name = format!("artifact-{index}-tenant-url-path-image-error-payload-secret-marker");
        assert_eq!(
            repository
                .list(list_request(&name))
                .await
                .expect("successful adversarial list"),
            Vec::new()
        );
        forbidden.push(name);
    }

    let observations = recorder.snapshot();
    let observations = &observations.repository_operations;
    assert_eq!(observations.len(), forbidden.len());
    assert!(observations.iter().all(|(operation, outcome, _)| {
        *operation == ResultsRepositoryOperation::List
            && *outcome == ResultsRepositoryOperationOutcome::Success
    }));
    let rendered = format!("{observations:?}");
    for forbidden in forbidden {
        assert!(
            !rendered.contains(&forbidden),
            "artifact input crossed the typed observer boundary: {forbidden}"
        );
    }
}

#[tokio::test]
async fn dropped_repository_future_records_exactly_one_cancellation() {
    let recorder = RecordingObserver::default();
    let entered = Arc::new(Notify::new());
    let inner: Arc<dyn ArtifactRepository> = Arc::new(TestArtifactRepository {
        list_artifacts: ListArtifactsBehavior::Pending {
            entered: Arc::clone(&entered),
            release: Arc::new(Notify::new()),
        },
        ..TestArtifactRepository::default()
    });
    let repository = ObservedResultsArtifactRepository::new(inner, Arc::new(recorder.clone()));
    let task = tokio::spawn(async move {
        repository
            .list(list_request("private-artifact-marker"))
            .await
    });
    entered.notified().await;
    task.abort();
    assert!(
        task.await
            .expect_err("repository task must be cancelled")
            .is_cancelled()
    );

    let observations = recorder.snapshot();
    let observations = &observations.repository_operations;
    assert_eq!(observations.len(), 1);
    assert_eq!(
        (observations[0].0, observations[0].1),
        (
            ResultsRepositoryOperation::List,
            ResultsRepositoryOperationOutcome::Cancelled,
        )
    );
}
