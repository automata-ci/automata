use std::{fmt, future::Future, sync::Arc, time::Instant};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, ReclaimableBlobStore, VerifiedBlob,
};

use crate::{
    ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsObserver, ResultsRepositoryOperation,
    ResultsRepositoryOperationOutcome,
    model::{
        ArtifactBlockReservation, ArtifactFinalizationReservation, ArtifactFinalizationWork,
        BeginArtifactFinalization, CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock,
        CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome,
        FinalizeArtifactOutcome, ListArtifacts, LoadArtifactFinalization,
        PublishedArtifactMetadata, RecordArtifactVerification, RenewArtifactFinalization,
        ReserveArtifactBlock, ResolveArtifactDownload,
    },
    port::{ArtifactRepository, ArtifactRepositoryError, ArtifactRepositoryErrorKind},
};

/// Identifier-free metrics decorator for the provider-neutral immutable-blob port.
#[derive(Clone)]
pub struct ObservedResultsBlobStore {
    inner: Arc<dyn ReclaimableBlobStore>,
    observer: Arc<dyn ResultsObserver>,
}

impl ObservedResultsBlobStore {
    /// Wraps one immutable-blob provider without changing its behavior.
    #[must_use]
    pub fn new(inner: Arc<dyn ReclaimableBlobStore>, observer: Arc<dyn ResultsObserver>) -> Self {
        Self { inner, observer }
    }
}

#[async_trait]
impl ReclaimableBlobStore for ObservedResultsBlobStore {
    async fn delete_if_present(&self, descriptor: &BlobDescriptor) -> Result<(), BlobStoreError> {
        self.inner.delete_if_present(descriptor).await
    }
}

#[async_trait]
impl ImmutableBlobStore for ObservedResultsBlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let bytes = payload.descriptor().size();
        let observation =
            BlobOperationObservation::new(Arc::clone(&self.observer), ResultsBlobOperation::Put);
        let result = self.inner.put_if_absent(payload).await;
        let outcome = match &result {
            Ok(PutBlobOutcome::Created) => ResultsBlobOperationOutcome::Created,
            Ok(PutBlobOutcome::AlreadyPresent) => ResultsBlobOperationOutcome::AlreadyPresent,
            Err(error) => blob_error_outcome(*error),
        };
        if result.is_ok() {
            self.observer
                .observe_blob_bytes(ResultsBlobOperation::Put, bytes);
        }
        observation.finish(outcome);
        result
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let observation =
            BlobOperationObservation::new(Arc::clone(&self.observer), ResultsBlobOperation::Get);
        let result = self.inner.get_verified(descriptor, maximum_bytes).await;
        let outcome = match &result {
            Ok(_) => ResultsBlobOperationOutcome::Success,
            Err(error) => blob_error_outcome(*error),
        };
        if let Ok(blob) = &result {
            self.observer.observe_blob_bytes(
                ResultsBlobOperation::Get,
                u64::try_from(blob.bytes().len()).unwrap_or(u64::MAX),
            );
        }
        observation.finish(outcome);
        result
    }
}

impl fmt::Debug for ObservedResultsBlobStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedResultsBlobStore")
            .finish_non_exhaustive()
    }
}

/// Identifier-free metrics decorator for the provider-neutral artifact repository.
#[derive(Clone)]
pub struct ObservedResultsArtifactRepository {
    inner: Arc<dyn ArtifactRepository>,
    observer: Arc<dyn ResultsObserver>,
}

impl ObservedResultsArtifactRepository {
    /// Wraps one artifact repository without changing its behavior.
    #[must_use]
    pub fn new(inner: Arc<dyn ArtifactRepository>, observer: Arc<dyn ResultsObserver>) -> Self {
        Self { inner, observer }
    }
}

#[async_trait]
impl ArtifactRepository for ObservedResultsArtifactRepository {
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::Create,
            self.inner.create(request),
        )
        .await
    }

    async fn reserve_block(
        &self,
        request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::ReserveBlock,
            self.inner.reserve_block(request),
        )
        .await
    }

    async fn complete_block(
        &self,
        request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::CompleteBlock,
            self.inner.complete_block(request),
        )
        .await
    }

    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::CommitBlocks,
            self.inner.commit_blocks(request),
        )
        .await
    }

    async fn begin_finalization(
        &self,
        request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::BeginFinalization,
            self.inner.begin_finalization(request),
        )
        .await
    }

    async fn load_finalization(
        &self,
        request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::LoadFinalization,
            self.inner.load_finalization(request),
        )
        .await
    }

    async fn renew_finalization(
        &self,
        request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::RenewFinalization,
            self.inner.renew_finalization(request),
        )
        .await
    }

    async fn record_verification(
        &self,
        request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::RecordVerification,
            self.inner.record_verification(request),
        )
        .await
    }

    async fn complete_finalization(
        &self,
        request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::CompleteFinalization,
            self.inner.complete_finalization(request),
        )
        .await
    }

    async fn list(
        &self,
        request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::List,
            self.inner.list(request),
        )
        .await
    }

    async fn resolve_download(
        &self,
        request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        observe_repository(
            Arc::clone(&self.observer),
            ResultsRepositoryOperation::ResolveDownload,
            self.inner.resolve_download(request),
        )
        .await
    }
}

impl fmt::Debug for ObservedResultsArtifactRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedResultsArtifactRepository")
            .finish_non_exhaustive()
    }
}

async fn observe_repository<T>(
    observer: Arc<dyn ResultsObserver>,
    operation: ResultsRepositoryOperation,
    future: impl Future<Output = Result<T, ArtifactRepositoryError>>,
) -> Result<T, ArtifactRepositoryError> {
    let observation = RepositoryOperationObservation::new(observer, operation);
    let result = future.await;
    let outcome = match &result {
        Ok(_) => ResultsRepositoryOperationOutcome::Success,
        Err(error) => repository_error_outcome(*error),
    };
    observation.finish(outcome);
    result
}

struct BlobOperationObservation {
    observer: Arc<dyn ResultsObserver>,
    operation: ResultsBlobOperation,
    started: Instant,
    completed: bool,
}

impl BlobOperationObservation {
    fn new(observer: Arc<dyn ResultsObserver>, operation: ResultsBlobOperation) -> Self {
        Self {
            observer,
            operation,
            started: Instant::now(),
            completed: false,
        }
    }

    fn finish(mut self, outcome: ResultsBlobOperationOutcome) {
        self.observer
            .observe_blob_operation(self.operation, outcome, self.started.elapsed());
        self.completed = true;
    }
}

impl Drop for BlobOperationObservation {
    fn drop(&mut self) {
        if !self.completed {
            self.observer.observe_blob_operation(
                self.operation,
                ResultsBlobOperationOutcome::Cancelled,
                self.started.elapsed(),
            );
        }
    }
}

struct RepositoryOperationObservation {
    observer: Arc<dyn ResultsObserver>,
    operation: ResultsRepositoryOperation,
    started: Instant,
    completed: bool,
}

impl RepositoryOperationObservation {
    fn new(observer: Arc<dyn ResultsObserver>, operation: ResultsRepositoryOperation) -> Self {
        Self {
            observer,
            operation,
            started: Instant::now(),
            completed: false,
        }
    }

    fn finish(mut self, outcome: ResultsRepositoryOperationOutcome) {
        self.observer
            .observe_repository_operation(self.operation, outcome, self.started.elapsed());
        self.completed = true;
    }
}

impl Drop for RepositoryOperationObservation {
    fn drop(&mut self) {
        if !self.completed {
            self.observer.observe_repository_operation(
                self.operation,
                ResultsRepositoryOperationOutcome::Cancelled,
                self.started.elapsed(),
            );
        }
    }
}

const fn blob_error_outcome(error: BlobStoreError) -> ResultsBlobOperationOutcome {
    match error.kind() {
        BlobStoreErrorKind::NotFound => ResultsBlobOperationOutcome::NotFound,
        BlobStoreErrorKind::Conflict => ResultsBlobOperationOutcome::Conflict,
        BlobStoreErrorKind::Integrity => ResultsBlobOperationOutcome::Integrity,
        BlobStoreErrorKind::TooLarge => ResultsBlobOperationOutcome::TooLarge,
        BlobStoreErrorKind::Unauthorized => ResultsBlobOperationOutcome::Unauthorized,
        BlobStoreErrorKind::Unavailable => ResultsBlobOperationOutcome::Unavailable,
        BlobStoreErrorKind::InvalidResponse => ResultsBlobOperationOutcome::InvalidResponse,
    }
}

const fn repository_error_outcome(
    error: ArtifactRepositoryError,
) -> ResultsRepositoryOperationOutcome {
    match error.kind() {
        ArtifactRepositoryErrorKind::NotFound => ResultsRepositoryOperationOutcome::NotFound,
        ArtifactRepositoryErrorKind::Unauthorized => {
            ResultsRepositoryOperationOutcome::Unauthorized
        }
        ArtifactRepositoryErrorKind::Conflict => ResultsRepositoryOperationOutcome::Conflict,
        ArtifactRepositoryErrorKind::InvalidState => {
            ResultsRepositoryOperationOutcome::InvalidState
        }
        ArtifactRepositoryErrorKind::ResourceExhausted => {
            ResultsRepositoryOperationOutcome::ResourceExhausted
        }
        ArtifactRepositoryErrorKind::CorruptData => ResultsRepositoryOperationOutcome::CorruptData,
        ArtifactRepositoryErrorKind::Unavailable => ResultsRepositoryOperationOutcome::Unavailable,
    }
}
