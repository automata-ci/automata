#[path = "../../automata-store/tests/common/mod.rs"]
mod common;

use automata_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_core::{AttemptId, AttemptNumber, LeaseId, Sha256Digest, UnixMillis};
use automata_results_github::{
    ArtifactBlock, ArtifactName, ArtifactPublicationState, ArtifactRepository as _,
    ArtifactRepositoryErrorKind, CommitArtifactBlocks, CreateArtifact, ExecutionAuthority,
    FinalizeArtifact, PostgresArtifactRepository, StageArtifactBlock, UploadId,
};
use automata_store::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt, StableRunnerSlot,
};
use common::{TestDatabase, TestResult, run_with_database, seed_control_plane};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // A single transaction narrative keeps idempotency assertions ordered.
async fn artifact_transactions_are_idempotent_immutable_and_fenced() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let first_upload = UploadId::from_uuid(Uuid::new_v4());
        let created = repository
            .create(create_request(authority, first_upload))
            .await?;
        let retry = repository
            .create(create_request(
                authority,
                UploadId::from_uuid(Uuid::new_v4()),
            ))
            .await?;
        assert_eq!(retry, created);
        assert_eq!(created.upload_id, first_upload);

        let block_id = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        let block = ArtifactBlock::new(block_id.to_owned(), descriptor("block-a", 3, 7));
        repository
            .record_block(StageArtifactBlock {
                upload_id: first_upload,
                block: block.clone(),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_staged_bytes: 1_024,
            })
            .await?;
        repository
            .record_block(StageArtifactBlock {
                upload_id: first_upload,
                block: block.clone(),
                observed_at_seconds: 1_002,
                maximum_blocks: 10,
                maximum_staged_bytes: 1_024,
            })
            .await?;
        let conflict = repository
            .record_block(StageArtifactBlock {
                upload_id: first_upload,
                block: ArtifactBlock::new(block_id.to_owned(), descriptor("block-b", 3, 9)),
                observed_at_seconds: 1_003,
                maximum_blocks: 10,
                maximum_staged_bytes: 1_024,
            })
            .await
            .expect_err("same block id cannot change bytes");
        assert_eq!(conflict.kind(), ArtifactRepositoryErrorKind::Conflict);

        let ids = vec![block_id.to_owned(), block_id.to_owned()];
        let committed = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id: first_upload,
                list_digest: list_digest(&ids),
                block_ids: ids.clone(),
                observed_at_seconds: 1_004,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        assert_eq!(committed.blocks.len(), 2);
        assert_eq!(committed.size, 6);
        let retry = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id: first_upload,
                list_digest: list_digest(&ids),
                block_ids: ids,
                observed_at_seconds: 1_005,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        assert_eq!(retry, committed);

        let manifest = descriptor("manifest", 123, 11);
        let content_digest = Sha256Digest::from_bytes([42; 32]);
        let finalized = repository
            .finalize(FinalizeArtifact {
                authority,
                name: ArtifactName::new("dist", 255)?,
                content_digest,
                size: 6,
                manifest: manifest.clone(),
                observed_at_seconds: 1_006,
            })
            .await?;
        let retry = repository
            .finalize(FinalizeArtifact {
                authority,
                name: ArtifactName::new("dist", 255)?,
                content_digest,
                size: 6,
                manifest: manifest.clone(),
                observed_at_seconds: 1_007,
            })
            .await?;
        assert_eq!(retry, finalized);
        assert!(matches!(
            repository
                .publication_state(authority, &ArtifactName::new("dist", 255)?)
                .await?,
            ArtifactPublicationState::Published(value)
                if value.manifest == manifest && value.content_digest == content_digest
        ));

        let counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_artifacts),
                (SELECT count(*) FROM workflow_artifact_blocks),
                (SELECT count(*) FROM workflow_artifact_block_commits)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn stale_attempts_and_cross_job_claims_are_rejected() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;

        let wrong = ExecutionAuthority::new(
            authority.run_id(),
            automata_core::JobId::new(),
            authority.attempt_id(),
            authority.fencing_token(),
        );
        let error = repository
            .create(create_request(wrong, UploadId::from_uuid(Uuid::new_v4())))
            .await
            .expect_err("cross-job token must fail");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::Unauthorized);

        let requeued = database
            .store()
            .requeue_expired(UnixMillis::new(100), 3, 10)
            .await?;
        assert_eq!(requeued, vec![authority.attempt_id()]);
        let error = repository
            .authorize_upload(upload_id)
            .await
            .expect_err("stale attempt upload must fail");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        Ok(())
    })
    .await
}

async fn active_attempt(
    database: &TestDatabase,
) -> TestResult<(PostgresArtifactRepository, ExecutionAuthority)> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            seed.job_id,
            AttemptNumber::new(1)?,
            UnixMillis::new(3),
        ))
        .await?;
    let lease = database
        .store()
        .acquire_lease(
            AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                seed.session_fences[0],
                StableRunnerSlot::new(1)?,
                UnixMillis::new(4),
                UnixMillis::new(100),
            )
            .expect("valid lease request"),
        )
        .await?;
    Ok((
        PostgresArtifactRepository::new(database.pool().clone()),
        ExecutionAuthority::new(seed.run_id, seed.job_id, attempt_id, lease.fencing_token()),
    ))
}

fn create_request(authority: ExecutionAuthority, upload_id: UploadId) -> CreateArtifact {
    CreateArtifact {
        authority,
        upload_id,
        name: ArtifactName::new("dist", 255).expect("artifact name"),
        version: 7,
        mime_type: "application/zip".to_owned(),
        expires_at_seconds: None,
        observed_at_seconds: 1_000,
    }
}

fn descriptor(suffix: &str, size: u64, byte: u8) -> BlobDescriptor {
    BlobDescriptor::new(
        BlobKey::new(format!("test/artifacts/{suffix}")).expect("blob key"),
        Sha256Digest::from_bytes([byte; 32]),
        size,
        MediaType::new("application/octet-stream").expect("media type"),
    )
}

fn list_digest(ids: &[String]) -> Sha256Digest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"automata-results-block-list-v1\0");
    hasher.update(u64::try_from(ids.len()).expect("count").to_be_bytes());
    for id in ids {
        hasher.update(u64::try_from(id.len()).expect("length").to_be_bytes());
        hasher.update(id.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}
