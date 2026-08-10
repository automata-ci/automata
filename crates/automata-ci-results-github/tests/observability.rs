use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_results_github::{
    NoopResultsObserver, ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsHttpMethod,
    ResultsHttpRoute, ResultsHttpStatusClass, ResultsObserver, ResultsOperation,
    ResultsOperationOutcome, ResultsRepositoryOperation, ResultsRepositoryOperationOutcome,
    ResultsTransferDirection,
};

#[derive(Clone, Debug, Default)]
struct RecordingObserver {
    operations: Arc<Mutex<Vec<(ResultsOperation, ResultsOperationOutcome, Duration)>>>,
    transfers: Arc<Mutex<Vec<(ResultsTransferDirection, u64)>>>,
}

impl ResultsObserver for RecordingObserver {
    fn observe_operation(
        &self,
        operation: ResultsOperation,
        outcome: ResultsOperationOutcome,
        duration: Duration,
    ) {
        self.operations
            .lock()
            .expect("operation observations lock")
            .push((operation, outcome, duration));
    }

    fn observe_transfer_bytes(&self, direction: ResultsTransferDirection, bytes: u64) {
        self.transfers
            .lock()
            .expect("transfer observations lock")
            .push((direction, bytes));
    }
}

#[test]
fn observer_contract_is_object_safe_infallible_and_identifier_free() {
    let recorder = RecordingObserver::default();
    let observer: Arc<dyn ResultsObserver> = Arc::new(recorder.clone());

    observer.observe_operation(
        ResultsOperation::Finalize,
        ResultsOperationOutcome::Unavailable,
        Duration::from_millis(17),
    );
    observer.observe_transfer_bytes(ResultsTransferDirection::Download, 4_096);

    assert_eq!(
        *recorder
            .operations
            .lock()
            .expect("operation observations lock"),
        vec![(
            ResultsOperation::Finalize,
            ResultsOperationOutcome::Unavailable,
            Duration::from_millis(17),
        )]
    );
    assert_eq!(
        *recorder
            .transfers
            .lock()
            .expect("transfer observations lock"),
        vec![(ResultsTransferDirection::Download, 4_096)]
    );

    let rendered = format!("{observer:?}");
    assert!(!rendered.contains("artifact"));
    assert!(!rendered.contains("sha256"));
    assert!(!rendered.contains("endpoint"));
}

#[test]
fn noop_accepts_every_closed_operation_and_outcome() {
    let observer: &dyn ResultsObserver = &NoopResultsObserver;
    let operations = [
        ResultsOperation::Create,
        ResultsOperation::StageBlock,
        ResultsOperation::Commit,
        ResultsOperation::Finalize,
        ResultsOperation::List,
        ResultsOperation::PrepareDownload,
        ResultsOperation::ReadBlock,
    ];
    let outcomes = [
        ResultsOperationOutcome::Success,
        ResultsOperationOutcome::Cancelled,
        ResultsOperationOutcome::InvalidArgument,
        ResultsOperationOutcome::PermissionDenied,
        ResultsOperationOutcome::NotFound,
        ResultsOperationOutcome::Conflict,
        ResultsOperationOutcome::FailedPrecondition,
        ResultsOperationOutcome::ResourceExhausted,
        ResultsOperationOutcome::Unavailable,
        ResultsOperationOutcome::Internal,
    ];

    for operation in operations {
        for outcome in outcomes {
            observer.observe_operation(operation, outcome, Duration::ZERO);
        }
    }
    observer.observe_transfer_bytes(ResultsTransferDirection::Upload, 0);
    observer.observe_transfer_bytes(ResultsTransferDirection::Download, u64::MAX);
    observer
        .results_http_request_started(ResultsHttpMethod::Post, ResultsHttpRoute::CreateArtifact);
    observer.observe_results_http_request(
        ResultsHttpMethod::Post,
        ResultsHttpRoute::CreateArtifact,
        ResultsHttpStatusClass::ClientError,
        Duration::ZERO,
    );
    observer
        .results_http_request_finished(ResultsHttpMethod::Post, ResultsHttpRoute::CreateArtifact);
    observer.observe_blob_operation(
        ResultsBlobOperation::Put,
        ResultsBlobOperationOutcome::AlreadyPresent,
        Duration::ZERO,
    );
    observer.observe_blob_bytes(ResultsBlobOperation::Get, u64::MAX);
    observer.observe_repository_operation(
        ResultsRepositoryOperation::RecordVerification,
        ResultsRepositoryOperationOutcome::CorruptData,
        Duration::ZERO,
    );
}
