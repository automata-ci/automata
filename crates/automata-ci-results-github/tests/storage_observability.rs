use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType, MemoryBlobStore, PutBlobOutcome, VerifiedBlob,
};
use automata_ci_results_github::{
    ObservedResultsBlobStore, ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsObserver,
};
use tokio::sync::Notify;

#[derive(Clone, Debug, Default)]
struct RecordingObserver {
    operations: Arc<Mutex<Vec<(ResultsBlobOperation, ResultsBlobOperationOutcome, Duration)>>>,
    bytes: Arc<Mutex<Vec<(ResultsBlobOperation, u64)>>>,
}

impl ResultsObserver for RecordingObserver {
    fn observe_blob_operation(
        &self,
        operation: ResultsBlobOperation,
        outcome: ResultsBlobOperationOutcome,
        duration: Duration,
    ) {
        self.operations
            .lock()
            .expect("blob operation observations lock")
            .push((operation, outcome, duration));
    }

    fn observe_blob_bytes(&self, operation: ResultsBlobOperation, bytes: u64) {
        self.bytes
            .lock()
            .expect("blob byte observations lock")
            .push((operation, bytes));
    }
}

fn payload(key: &str, bytes: &'static [u8]) -> BlobPayload {
    BlobPayload::from_bytes(
        BlobKey::new(key).expect("blob key"),
        MediaType::new("application/octet-stream").expect("media type"),
        bytes::Bytes::from_static(bytes),
    )
}

#[tokio::test]
async fn successful_put_and_get_record_only_closed_labels_and_actual_bytes() {
    let recorder = RecordingObserver::default();
    let inner: Arc<dyn ImmutableBlobStore> = Arc::new(MemoryBlobStore::default());
    let store = ObservedResultsBlobStore::new(inner, Arc::new(recorder.clone()));
    let private_key = "private/tenant-91/artifact-secret-digest";
    let payload = payload(private_key, b"immutable payload");
    let descriptor = payload.descriptor().clone();

    assert_eq!(
        store.put_if_absent(payload).await.expect("put blob"),
        PutBlobOutcome::Created
    );
    let verified = store
        .get_verified(&descriptor, descriptor.size())
        .await
        .expect("get blob");
    assert_eq!(verified.bytes().as_ref(), b"immutable payload");

    let operations = recorder
        .operations
        .lock()
        .expect("blob operation observations lock");
    assert_eq!(operations.len(), 2);
    assert_eq!(
        (operations[0].0, operations[0].1),
        (
            ResultsBlobOperation::Put,
            ResultsBlobOperationOutcome::Created,
        )
    );
    assert_eq!(
        (operations[1].0, operations[1].1),
        (
            ResultsBlobOperation::Get,
            ResultsBlobOperationOutcome::Success,
        )
    );
    assert!(!format!("{operations:?}").contains(private_key));
    assert_eq!(
        *recorder.bytes.lock().expect("blob byte observations lock"),
        vec![
            (ResultsBlobOperation::Put, descriptor.size()),
            (ResultsBlobOperation::Get, descriptor.size()),
        ]
    );
}

#[derive(Debug)]
struct FailingBlobStore;

#[async_trait]
impl ImmutableBlobStore for FailingBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::Conflict))
    }

    async fn get_verified(
        &self,
        _descriptor: &BlobDescriptor,
        _maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable))
    }
}

#[tokio::test]
async fn provider_errors_are_sanitized_and_never_emit_bytes() {
    let recorder = RecordingObserver::default();
    let inner: Arc<dyn ImmutableBlobStore> = Arc::new(FailingBlobStore);
    let store = ObservedResultsBlobStore::new(inner, Arc::new(recorder.clone()));
    let payload = payload("private/error-key", b"not accepted");
    let descriptor = payload.descriptor().clone();

    assert_eq!(
        store
            .put_if_absent(payload)
            .await
            .expect_err("put fails")
            .kind(),
        BlobStoreErrorKind::Conflict
    );
    assert_eq!(
        store
            .get_verified(&descriptor, descriptor.size())
            .await
            .expect_err("get fails")
            .kind(),
        BlobStoreErrorKind::Unavailable
    );

    let operations = recorder
        .operations
        .lock()
        .expect("blob operation observations lock");
    assert_eq!(
        operations
            .iter()
            .map(|(operation, outcome, _)| (*operation, *outcome))
            .collect::<Vec<_>>(),
        vec![
            (
                ResultsBlobOperation::Put,
                ResultsBlobOperationOutcome::Conflict,
            ),
            (
                ResultsBlobOperation::Get,
                ResultsBlobOperationOutcome::Unavailable,
            ),
        ]
    );
    assert!(
        recorder
            .bytes
            .lock()
            .expect("blob byte observations lock")
            .is_empty()
    );
}

#[derive(Debug)]
struct PendingBlobStore {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl ImmutableBlobStore for PendingBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        self.entered.notify_one();
        self.release.notified().await;
        Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable))
    }

    async fn get_verified(
        &self,
        _descriptor: &BlobDescriptor,
        _maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable))
    }
}

#[tokio::test]
async fn dropped_provider_future_records_one_cancellation_without_bytes() {
    let recorder = RecordingObserver::default();
    let entered = Arc::new(Notify::new());
    let inner: Arc<dyn ImmutableBlobStore> = Arc::new(PendingBlobStore {
        entered: Arc::clone(&entered),
        release: Arc::new(Notify::new()),
    });
    let store = ObservedResultsBlobStore::new(inner, Arc::new(recorder.clone()));
    let task = tokio::spawn(async move {
        store
            .put_if_absent(payload("private/cancelled-key", b"not accepted"))
            .await
    });
    entered.notified().await;
    task.abort();
    assert!(
        task.await
            .expect_err("blob task must be cancelled")
            .is_cancelled()
    );

    let operations = recorder
        .operations
        .lock()
        .expect("blob operation observations lock");
    assert_eq!(operations.len(), 1);
    assert_eq!(
        (operations[0].0, operations[0].1),
        (
            ResultsBlobOperation::Put,
            ResultsBlobOperationOutcome::Cancelled,
        )
    );
    assert!(
        recorder
            .bytes
            .lock()
            .expect("blob byte observations lock")
            .is_empty()
    );
}
