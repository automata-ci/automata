use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_core::{AttemptId, FencingToken, JobId, RunId};
use automata_ci_results_github::{
    ArtifactBlockReservation, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    ArtifactName, ArtifactRepository, ArtifactRepositoryError, ArtifactRepositoryErrorKind,
    BeginArtifactFinalization, CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock,
    CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome, ExecutionAuthority,
    FinalizeArtifactOutcome, ListArtifacts, LoadArtifactFinalization,
    ObservedResultsArtifactRepository, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload, ResultsObserver,
    ResultsRepositoryOperation, ResultsRepositoryOperationOutcome,
};
use tokio::sync::Notify;

#[derive(Clone, Debug, Default)]
struct RecordingObserver {
    operations: Arc<
        Mutex<
            Vec<(
                ResultsRepositoryOperation,
                ResultsRepositoryOperationOutcome,
                Duration,
            )>,
        >,
    >,
}

impl ResultsObserver for RecordingObserver {
    fn observe_repository_operation(
        &self,
        operation: ResultsRepositoryOperation,
        outcome: ResultsRepositoryOperationOutcome,
        duration: Duration,
    ) {
        self.operations
            .lock()
            .expect("repository observations lock")
            .push((operation, outcome, duration));
    }
}

#[derive(Debug)]
enum ListBehavior {
    Success,
    Conflict,
    Pending {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    },
}

#[derive(Debug)]
struct ListRepository {
    behavior: ListBehavior,
}

fn unavailable() -> ArtifactRepositoryError {
    ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::Unavailable)
}

#[async_trait]
impl ArtifactRepository for ListRepository {
    async fn create(
        &self,
        _request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn reserve_block(
        &self,
        _request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn complete_block(
        &self,
        _request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn commit_blocks(
        &self,
        _request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn begin_finalization(
        &self,
        _request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn load_finalization(
        &self,
        _request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn renew_finalization(
        &self,
        _request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn record_verification(
        &self,
        _request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn complete_finalization(
        &self,
        _request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn list(
        &self,
        _request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        match &self.behavior {
            ListBehavior::Success => Ok(Vec::new()),
            ListBehavior::Conflict => Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::Conflict,
            )),
            ListBehavior::Pending { entered, release } => {
                entered.notify_one();
                release.notified().await;
                Err(unavailable())
            }
        }
    }

    async fn resolve_download(
        &self,
        _request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        Err(unavailable())
    }
}

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
            ListBehavior::Success,
            ResultsRepositoryOperationOutcome::Success,
        ),
        (
            ListBehavior::Conflict,
            ResultsRepositoryOperationOutcome::Conflict,
        ),
    ] {
        let recorder = RecordingObserver::default();
        let inner: Arc<dyn ArtifactRepository> = Arc::new(ListRepository { behavior });
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
        let observations = recorder
            .operations
            .lock()
            .expect("repository observations lock");
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
    let inner: Arc<dyn ArtifactRepository> = Arc::new(ListRepository {
        behavior: ListBehavior::Success,
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

    let observations = recorder
        .operations
        .lock()
        .expect("repository observations lock");
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
    let inner: Arc<dyn ArtifactRepository> = Arc::new(ListRepository {
        behavior: ListBehavior::Pending {
            entered: Arc::clone(&entered),
            release: Arc::new(Notify::new()),
        },
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

    let observations = recorder
        .operations
        .lock()
        .expect("repository observations lock");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        (observations[0].0, observations[0].1),
        (
            ResultsRepositoryOperation::List,
            ResultsRepositoryOperationOutcome::Cancelled,
        )
    );
}
