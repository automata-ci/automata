mod fixture_support;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_ci_core::Sha256Digest;
use automata_ci_runner_results::{
    ArtifactBlock, ArtifactBlockReservation, ArtifactFinalizationClaim,
    ArtifactFinalizationReservation, ArtifactFinalizationWork, ArtifactId, ArtifactRepository,
    ArtifactRepositoryError, ArtifactRepositoryErrorKind, ArtifactService,
    BeginArtifactFinalization, CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock,
    CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome, ExecutionAuthority,
    FinalizeArtifactOutcome, ListArtifacts, LoadArtifactFinalization, PublishedArtifactMetadata,
    RecordArtifactVerification, RenewArtifactFinalization, ReserveArtifactBlock,
    ResolveArtifactDownload, ResultsLimits, ResultsServiceErrorKind, UploadId,
    VerifiedArtifactFinalization,
};
use bytes::Bytes;
use fixture_support::{FixedIds, MutableClock as TestClock, fresh_execution_authority};
use uuid::Uuid;

#[derive(Debug, Default)]
struct ObservedBlobStore {
    state: Mutex<BlobState>,
}

#[derive(Debug, Default)]
struct BlobState {
    objects: BTreeMap<String, BlobPayload>,
    put_calls: usize,
    get_calls: usize,
    failures_remaining: usize,
}

impl ObservedBlobStore {
    fn fail_next_put(&self) {
        self.state
            .lock()
            .expect("blob state lock")
            .failures_remaining += 1;
    }

    fn put_calls(&self) -> usize {
        self.state.lock().expect("blob state lock").put_calls
    }

    fn object_count(&self) -> usize {
        self.state.lock().expect("blob state lock").objects.len()
    }

    fn get_calls(&self) -> usize {
        self.state.lock().expect("blob state lock").get_calls
    }
}

#[async_trait]
impl ImmutableBlobStore for ObservedBlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let mut state = self.state.lock().expect("blob state lock");
        state.put_calls += 1;
        if state.failures_remaining > 0 {
            state.failures_remaining -= 1;
            return Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable));
        }
        let key = payload.descriptor().key().as_str().to_owned();
        match state.objects.get(&key) {
            Some(existing) if existing == &payload => Ok(PutBlobOutcome::AlreadyPresent),
            Some(_) => Err(BlobStoreError::new(BlobStoreErrorKind::Conflict)),
            None => {
                state.objects.insert(key, payload);
                Ok(PutBlobOutcome::Created)
            }
        }
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        if descriptor.size() > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
        }
        let mut state = self.state.lock().expect("blob state lock");
        state.get_calls += 1;
        let payload = state
            .objects
            .get(descriptor.key().as_str())
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::NotFound))?;
        if payload.descriptor() != descriptor {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        Ok(VerifiedBlob::from_payload(payload.clone()))
    }
}

#[derive(Debug)]
struct AdmissionRepository {
    artifact_id: ArtifactId,
    upload_id: UploadId,
    state: Mutex<RepositoryState>,
}

#[derive(Debug, Default)]
struct RepositoryState {
    create: Option<CreateArtifact>,
    blocks: BTreeMap<String, ReservedBlock>,
    committed: Option<CommittedArtifact>,
    finalization: Option<FakeFinalization>,
    published: Option<FinalizeArtifactOutcome>,
    reject_manifest: Option<ArtifactRepositoryErrorKind>,
    complete_failures_remaining: usize,
}

#[derive(Clone, Debug)]
struct FakeFinalization {
    claim: ArtifactFinalizationClaim,
    claimed_size: u64,
    claimed_digest: Option<Sha256Digest>,
    expires_at_seconds: u64,
    verified: Option<VerifiedArtifactFinalization>,
}

#[derive(Clone, Debug)]
struct ReservedBlock {
    block: ArtifactBlock,
    ready: bool,
}

impl AdmissionRepository {
    fn reject_manifest(&self, kind: ArtifactRepositoryErrorKind) {
        self.state
            .lock()
            .expect("repository state lock")
            .reject_manifest = Some(kind);
    }

    fn block_ready(&self, block_id: &str) -> bool {
        self.state
            .lock()
            .expect("repository state lock")
            .blocks
            .get(block_id)
            .is_some_and(|block| block.ready)
    }

    fn fail_next_completion(&self) {
        self.state
            .lock()
            .expect("repository state lock")
            .complete_failures_remaining += 1;
    }

    fn manifest_reserved(&self) -> bool {
        self.state
            .lock()
            .expect("repository state lock")
            .finalization
            .as_ref()
            .is_some_and(|finalization| finalization.verified.is_some())
    }

    fn published(&self) -> bool {
        self.state
            .lock()
            .expect("repository state lock")
            .published
            .is_some()
    }

    fn claim_generation(&self) -> u64 {
        self.state
            .lock()
            .expect("repository state lock")
            .finalization
            .as_ref()
            .map_or(0, |finalization| finalization.claim.generation())
    }
}

#[async_trait]
impl ArtifactRepository for AdmissionRepository {
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        if let Some(existing) = &state.create {
            if existing.authority != request.authority
                || existing.name != request.name
                || existing.version != request.version
                || existing.mime_type != request.mime_type
                || existing.expires_at_seconds != request.expires_at_seconds
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
        } else {
            state.create = Some(request);
        }
        Ok(CreateArtifactOutcome {
            artifact_id: self.artifact_id,
            upload_id: self.upload_id,
        })
    }

    async fn reserve_block(
        &self,
        request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        if request.upload_id != self.upload_id {
            return Err(repository_error(ArtifactRepositoryErrorKind::NotFound));
        }
        let mut state = self.state.lock().expect("repository state lock");
        if let Some(existing) = state.blocks.get(request.block.block_id()) {
            if existing.block != request.block {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            return Ok(if existing.ready {
                ArtifactBlockReservation::Ready
            } else {
                ArtifactBlockReservation::UploadRequired
            });
        }
        let next_count = state.blocks.len().saturating_add(1);
        let staged_bytes = state
            .blocks
            .values()
            .map(|block| block.block.descriptor().size())
            .sum::<u64>();
        let next_bytes = staged_bytes
            .checked_add(request.block.descriptor().size())
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::ResourceExhausted))?;
        if next_count > request.maximum_blocks
            || next_bytes > request.maximum_staged_bytes
            || next_count > request.maximum_run_blocks
            || next_bytes > request.maximum_run_staged_bytes
        {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }
        state.blocks.insert(
            request.block.block_id().to_owned(),
            ReservedBlock {
                block: request.block,
                ready: false,
            },
        );
        Ok(ArtifactBlockReservation::UploadRequired)
    }

    async fn complete_block(
        &self,
        request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        let block = state
            .blocks
            .get_mut(request.block.block_id())
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
        if block.block != request.block {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        block.ready = true;
        Ok(())
    }

    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        let create = state
            .create
            .as_ref()
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
        let blocks = request
            .block_ids
            .iter()
            .map(|block_id| {
                state
                    .blocks
                    .get(block_id)
                    .filter(|block| block.ready)
                    .map(|block| block.block.clone())
                    .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let size = blocks.iter().map(|block| block.descriptor().size()).sum();
        if size > request.maximum_artifact_bytes {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }
        let committed = CommittedArtifact {
            artifact_id: self.artifact_id,
            upload_id: self.upload_id,
            authority: create.authority,
            name: create.name.clone(),
            mime_type: create.mime_type.clone(),
            blocks,
            size,
        };
        state.committed = Some(committed.clone());
        Ok(committed)
    }

    async fn begin_finalization(
        &self,
        request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        let committed = state
            .committed
            .as_ref()
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::InvalidState))?;
        if committed.authority != request.authority
            || committed.name != request.name
            || committed.size != request.claimed_size
        {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        if let Some(published) = state.published {
            if published.size != request.claimed_size
                || request
                    .claimed_digest
                    .is_some_and(|digest| digest != published.content_digest)
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            return Ok(ArtifactFinalizationReservation::Published(published));
        }
        if let Some(existing) = state.finalization.as_ref()
            && existing.expires_at_seconds > request.observed_at_seconds
        {
            if existing.claimed_size != request.claimed_size
                || existing.claimed_digest != request.claimed_digest
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            return Ok(ArtifactFinalizationReservation::InProgress {
                retry_at_seconds: existing.expires_at_seconds,
            });
        }
        let generation = state
            .finalization
            .as_ref()
            .map_or(1, |existing| existing.claim.generation() + 1);
        if let Some(verified) = state
            .finalization
            .as_ref()
            .and_then(|existing| existing.verified.as_ref())
            && request
                .claimed_digest
                .is_some_and(|digest| digest != verified.content_digest)
        {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        let claim = ArtifactFinalizationClaim::new(
            self.artifact_id,
            request.authority,
            request.name,
            generation,
        );
        let verified = state
            .finalization
            .as_ref()
            .and_then(|existing| existing.verified.clone());
        state.finalization = Some(FakeFinalization {
            claim: claim.clone(),
            claimed_size: request.claimed_size,
            claimed_digest: request.claimed_digest,
            expires_at_seconds: request.observed_at_seconds + request.lease_seconds,
            verified,
        });
        Ok(ArtifactFinalizationReservation::Claimed(claim))
    }

    async fn load_finalization(
        &self,
        request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        let state = self.state.lock().expect("repository state lock");
        let finalization = live_finalization(&state, &request.claim, request.observed_at_seconds)?;
        Ok(finalization.verified.clone().map_or_else(
            || {
                ArtifactFinalizationWork::Verify(
                    state.committed.clone().expect("committed finalization"),
                )
            },
            ArtifactFinalizationWork::Publish,
        ))
    }

    async fn renew_finalization(
        &self,
        request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        let finalization =
            live_finalization_mut(&mut state, &request.claim, request.observed_at_seconds)?;
        finalization.expires_at_seconds = finalization
            .expires_at_seconds
            .max(request.observed_at_seconds + request.lease_seconds);
        Ok(())
    }

    async fn record_verification(
        &self,
        request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        if let Some(kind) = state.reject_manifest {
            return Err(repository_error(kind));
        }
        let size = state
            .committed
            .as_ref()
            .expect("committed finalization")
            .size;
        let finalization =
            live_finalization_mut(&mut state, &request.claim, request.observed_at_seconds)?;
        let verified = VerifiedArtifactFinalization {
            artifact_id: self.artifact_id,
            content_digest: request.content_digest,
            size,
            manifest: request.manifest,
            manifest_bytes: request.manifest_bytes,
        };
        if let Some(existing) = &finalization.verified
            && existing != &verified
        {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        finalization.verified = Some(verified);
        finalization.expires_at_seconds = finalization
            .expires_at_seconds
            .max(request.observed_at_seconds + request.lease_seconds);
        Ok(())
    }

    async fn complete_finalization(
        &self,
        request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("repository state lock");
        if state.complete_failures_remaining > 0 {
            state.complete_failures_remaining -= 1;
            return Err(repository_error(ArtifactRepositoryErrorKind::Unavailable));
        }
        if let Some(published) = state.published {
            if state
                .finalization
                .as_ref()
                .is_none_or(|finalization| finalization.claim != request.claim)
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
            }
            return Ok(published);
        }
        let finalization = live_finalization(&state, &request.claim, request.observed_at_seconds)?;
        let verified = finalization
            .verified
            .as_ref()
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::InvalidState))?;
        let outcome = FinalizeArtifactOutcome {
            artifact_id: self.artifact_id,
            content_digest: verified.content_digest,
            size: verified.size,
        };
        state.published = Some(outcome);
        Ok(outcome)
    }

    async fn list(
        &self,
        _request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        Err(repository_error(ArtifactRepositoryErrorKind::NotFound))
    }

    async fn resolve_download(
        &self,
        _request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        Err(repository_error(ArtifactRepositoryErrorKind::NotFound))
    }
}

fn repository_error(kind: ArtifactRepositoryErrorKind) -> ArtifactRepositoryError {
    ArtifactRepositoryError::new(kind)
}

fn live_finalization<'a>(
    state: &'a RepositoryState,
    claim: &ArtifactFinalizationClaim,
    observed_at_seconds: u64,
) -> Result<&'a FakeFinalization, ArtifactRepositoryError> {
    let finalization = state
        .finalization
        .as_ref()
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::Unauthorized))?;
    if finalization.claim != *claim || finalization.expires_at_seconds <= observed_at_seconds {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(finalization)
}

fn live_finalization_mut<'a>(
    state: &'a mut RepositoryState,
    claim: &ArtifactFinalizationClaim,
    observed_at_seconds: u64,
) -> Result<&'a mut FakeFinalization, ArtifactRepositoryError> {
    let finalization = state
        .finalization
        .as_mut()
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::Unauthorized))?;
    if finalization.claim != *claim || finalization.expires_at_seconds <= observed_at_seconds {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(finalization)
}

struct Fixture {
    service: Arc<ArtifactService>,
    repository: Arc<AdmissionRepository>,
    objects: Arc<ObservedBlobStore>,
    clock: Arc<TestClock>,
    authority: ExecutionAuthority,
    upload_id: UploadId,
}

async fn fixture(limits: ResultsLimits) -> Fixture {
    let authority = fresh_execution_authority(7);
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let repository = Arc::new(AdmissionRepository {
        artifact_id: ArtifactId::new(41).expect("artifact id"),
        upload_id,
        state: Mutex::new(RepositoryState::default()),
    });
    let objects = Arc::new(ObservedBlobStore::default());
    let clock = Arc::new(TestClock::new(1_000));
    let service = Arc::new(ArtifactService::new(
        repository.clone(),
        objects.clone(),
        clock.clone(),
        Arc::new(FixedIds(upload_id)),
        limits,
    ));
    service
        .create(
            authority,
            "dist".to_owned(),
            7,
            "application/zip".to_owned(),
            None,
        )
        .await
        .expect("create artifact");
    Fixture {
        service,
        repository,
        objects,
        clock,
        authority,
        upload_id,
    }
}

#[tokio::test]
async fn conflicting_block_identity_is_rejected_before_object_io() {
    let fixture = fixture(ResultsLimits::default()).await;
    fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"a"),
        )
        .await
        .expect("first block");
    assert_eq!(fixture.objects.put_calls(), 1);

    let error = fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"b"),
        )
        .await
        .expect_err("same block id cannot identify different bytes");
    assert_eq!(error.kind(), ResultsServiceErrorKind::Conflict);
    assert_eq!(fixture.objects.put_calls(), 1);
    assert_eq!(fixture.objects.object_count(), 1);
}

#[test]
fn default_run_block_ceiling_bounds_zero_byte_metadata_growth() {
    let limits = ResultsLimits::default();
    assert_eq!(limits.maximum_run_artifact_blocks(), 16_384);
    assert!(
        limits.maximum_run_artifact_blocks()
            < limits
                .maximum_artifacts_per_run()
                .saturating_mul(limits.maximum_blocks())
    );
}

#[tokio::test]
async fn durable_byte_quota_is_rejected_before_object_io() {
    let limits = ResultsLimits::new(255, 4, 4, 10, 1_024, 86_400)
        .and_then(|limits| limits.with_run_admission(10, 4, 10))
        .expect("bounded test limits");
    let fixture = fixture(limits).await;
    fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"abc"),
        )
        .await
        .expect("first block");

    let error = fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QkJC".to_owned(),
            Bytes::from_static(b"de"),
        )
        .await
        .expect_err("aggregate quota must reject second object");
    assert_eq!(error.kind(), ResultsServiceErrorKind::ResourceExhausted);
    assert_eq!(fixture.objects.put_calls(), 1);
    assert_eq!(fixture.objects.object_count(), 1);
}

#[tokio::test]
async fn exact_concurrent_block_retries_are_safe() {
    let fixture = fixture(ResultsLimits::default()).await;
    let first = fixture.service.clone();
    let second = fixture.service.clone();
    let upload_id = fixture.upload_id;
    let (first, second) = tokio::join!(
        first.stage_block(upload_id, "QUFB".to_owned(), Bytes::from_static(b"same")),
        second.stage_block(upload_id, "QUFB".to_owned(), Bytes::from_static(b"same")),
    );
    first.expect("first retry");
    second.expect("second retry");
    assert!(fixture.repository.block_ready("QUFB"));
    assert_eq!(fixture.objects.object_count(), 1);
}

#[tokio::test]
async fn failed_block_put_leaves_a_retryable_durable_reservation() {
    let fixture = fixture(ResultsLimits::default()).await;
    fixture.objects.fail_next_put();
    let error = fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"retry"),
        )
        .await
        .expect_err("injected object failure");
    assert_eq!(error.kind(), ResultsServiceErrorKind::Unavailable);
    assert!(!fixture.repository.block_ready("QUFB"));

    fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"retry"),
        )
        .await
        .expect("reservation retry");
    assert!(fixture.repository.block_ready("QUFB"));
    assert_eq!(fixture.objects.put_calls(), 2);
    assert_eq!(fixture.objects.object_count(), 1);
}

#[tokio::test]
async fn reserved_block_cannot_be_committed() {
    let fixture = fixture(ResultsLimits::default()).await;
    let block = ArtifactBlock::new(
        "QUFB".to_owned(),
        BlobPayload::from_bytes(
            automata_ci_blob::BlobKey::new("test/reserved").expect("blob key"),
            automata_ci_blob::MediaType::new("application/octet-stream").expect("media type"),
            Bytes::from_static(b"reserved"),
        )
        .descriptor()
        .clone(),
    );
    assert_eq!(
        fixture
            .repository
            .reserve_block(ReserveArtifactBlock {
                upload_id: fixture.upload_id,
                block,
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_staged_bytes: 1_024,
                maximum_run_blocks: 10,
                maximum_run_staged_bytes: 1_024,
            })
            .await
            .expect("reserve block"),
        ArtifactBlockReservation::UploadRequired
    );
    let error = fixture
        .repository
        .commit_blocks(CommitArtifactBlocks {
            upload_id: fixture.upload_id,
            block_ids: vec!["QUFB".to_owned()],
            list_digest: Sha256Digest::from_bytes([1; 32]),
            observed_at_seconds: 1_002,
            maximum_blocks: 10,
            maximum_artifact_bytes: 1_024,
        })
        .await
        .expect_err("reserved block is not commit-visible");
    assert_eq!(error.kind(), ArtifactRepositoryErrorKind::NotFound);
    assert_eq!(fixture.objects.put_calls(), 0);
}

#[tokio::test]
async fn manifest_admission_failure_happens_before_manifest_object_io() {
    let fixture = fixture(ResultsLimits::default()).await;
    fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"manifest"),
        )
        .await
        .expect("stage block");
    fixture
        .service
        .commit_blocks(fixture.upload_id, vec!["QUFB".to_owned()])
        .await
        .expect("commit block list");
    fixture
        .repository
        .reject_manifest(ArtifactRepositoryErrorKind::ResourceExhausted);
    let before = fixture.objects.put_calls();

    let error = fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect_err("manifest descriptor admission must fail");
    assert_eq!(error.kind(), ResultsServiceErrorKind::ResourceExhausted);
    assert_eq!(fixture.objects.put_calls(), before);
    assert!(!fixture.repository.manifest_reserved());
}

#[tokio::test]
async fn failed_manifest_put_leaves_a_retryable_durable_reservation() {
    let fixture = fixture(ResultsLimits::default()).await;
    fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"manifest"),
        )
        .await
        .expect("stage block");
    fixture
        .service
        .commit_blocks(fixture.upload_id, vec!["QUFB".to_owned()])
        .await
        .expect("commit block list");
    fixture.objects.fail_next_put();

    let error = fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect_err("injected manifest put failure");
    assert_eq!(error.kind(), ResultsServiceErrorKind::Unavailable);
    assert!(fixture.repository.manifest_reserved());
    assert!(!fixture.repository.published());
    assert_eq!(fixture.objects.get_calls(), 1);

    let error = fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect_err("an exact follower must not bypass the live verifier");
    assert_eq!(error.kind(), ResultsServiceErrorKind::Unavailable);
    assert_eq!(fixture.objects.get_calls(), 1);

    fixture.clock.set(1_300);
    fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect("retry manifest publication");
    assert!(fixture.repository.published());
    assert_eq!(fixture.objects.object_count(), 2);
    assert_eq!(fixture.objects.get_calls(), 1);
    assert_eq!(fixture.repository.claim_generation(), 2);

    let puts = fixture.objects.put_calls();
    fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect("completed publication replay");
    assert_eq!(fixture.objects.put_calls(), puts);
    assert_eq!(fixture.objects.get_calls(), 1);
}

#[tokio::test]
async fn exact_concurrent_finalization_has_one_claim_and_one_follower() {
    let fixture = fixture(ResultsLimits::default()).await;
    fixture
        .service
        .commit_blocks(fixture.upload_id, Vec::new())
        .await
        .expect("commit empty artifact");
    let request = BeginArtifactFinalization {
        authority: fixture.authority,
        name: automata_ci_runner_results::ArtifactName::new("dist", 255).expect("artifact name"),
        claimed_size: 0,
        claimed_digest: None,
        observed_at_seconds: 1_000,
        lease_seconds: 300,
    };
    let (first, second) = tokio::join!(
        fixture.repository.begin_finalization(request.clone()),
        fixture.repository.begin_finalization(request),
    );
    let outcomes = [first.expect("first begin"), second.expect("second begin")];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ArtifactFinalizationReservation::Claimed(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                ArtifactFinalizationReservation::InProgress {
                    retry_at_seconds: 1_300
                }
            ))
            .count(),
        1
    );
    assert_eq!(fixture.objects.get_calls(), 0);
}

#[tokio::test]
async fn manifest_put_before_completion_is_replayed_without_block_reads() {
    let fixture = fixture(ResultsLimits::default()).await;
    fixture
        .service
        .stage_block(
            fixture.upload_id,
            "QUFB".to_owned(),
            Bytes::from_static(b"manifest"),
        )
        .await
        .expect("stage block");
    fixture
        .service
        .commit_blocks(fixture.upload_id, vec!["QUFB".to_owned()])
        .await
        .expect("commit block list");
    fixture.repository.fail_next_completion();

    let error = fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect_err("injected completion outage");
    assert_eq!(error.kind(), ResultsServiceErrorKind::Unavailable);
    assert!(fixture.repository.manifest_reserved());
    assert!(!fixture.repository.published());
    assert_eq!(fixture.objects.get_calls(), 1);
    assert_eq!(fixture.objects.object_count(), 2);

    fixture.clock.set(1_300);
    fixture
        .service
        .finalize(fixture.authority, "dist".to_owned(), 8, None)
        .await
        .expect("take over persisted publication");
    assert!(fixture.repository.published());
    assert_eq!(fixture.objects.get_calls(), 1);
    assert_eq!(fixture.objects.object_count(), 2);
}
