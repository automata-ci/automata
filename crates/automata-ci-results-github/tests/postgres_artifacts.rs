mod support;

use std::time::Duration;

use automata_ci_blob::{BlobDescriptor, BlobKey, BlobPayload, MediaType};
use automata_ci_control::adapter_spi::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt,
};
use automata_ci_core::{AttemptId, AttemptNumber, LeaseId, Sha256Digest, UnixMillis};
use automata_ci_postgres::test_support::TestClock;
use automata_ci_results_github::{
    ARTIFACT_MANIFEST_MEDIA_TYPE, ArtifactBlock, ArtifactBlockReservation,
    ArtifactFinalizationReservation, ArtifactFinalizationWork, ArtifactManifest, ArtifactName,
    ArtifactRepository as _, ArtifactRepositoryErrorKind, BeginArtifactFinalization,
    CommitArtifactBlocks, CompleteArtifactBlock, CompleteArtifactFinalization, CreateArtifact,
    ExecutionAuthority, ListArtifacts, LoadArtifactFinalization, PostgresArtifactRepository,
    RecordArtifactVerification, RenewArtifactFinalization, ReserveArtifactBlock,
    ResolveArtifactDownload, UploadId,
};
use automata_ci_store::{HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA, StableRunnerSlot};
use bytes::Bytes;
use sqlx::PgPool;
use support::{
    fixtures::{database_now_millis, database_now_seconds},
    postgres::{TestDatabase, TestResult, run_with_database, seed_control_plane},
};
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
        assert_eq!(
            repository
                .reserve_block(ReserveArtifactBlock {
                    upload_id: first_upload,
                    block: block.clone(),
                    observed_at_seconds: 1_001,
                    maximum_blocks: 10,
                    maximum_staged_bytes: 1_024,
                    maximum_run_blocks: 10,
                    maximum_run_staged_bytes: 4_096,
                })
                .await?,
            ArtifactBlockReservation::UploadRequired
        );
        repository
            .complete_block(CompleteArtifactBlock {
                upload_id: first_upload,
                block: block.clone(),
                observed_at_seconds: 1_002,
            })
            .await?;
        assert_eq!(
            repository
                .reserve_block(ReserveArtifactBlock {
                    upload_id: first_upload,
                    block: block.clone(),
                    observed_at_seconds: 1_003,
                    maximum_blocks: 10,
                    maximum_staged_bytes: 1_024,
                    maximum_run_blocks: 10,
                    maximum_run_staged_bytes: 4_096,
                })
                .await?,
            ArtifactBlockReservation::Ready
        );
        let conflict = repository
            .reserve_block(ReserveArtifactBlock {
                upload_id: first_upload,
                block: ArtifactBlock::new(block_id.to_owned(), descriptor("block-b", 3, 9)),
                observed_at_seconds: 1_004,
                maximum_blocks: 10,
                maximum_staged_bytes: 1_024,
                maximum_run_blocks: 10,
                maximum_run_staged_bytes: 4_096,
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
                observed_at_seconds: 1_005,
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
                observed_at_seconds: 1_006,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        assert_eq!(retry, committed);

        let content_digest = Sha256Digest::from_bytes([42; 32]);
        let finalization_observed_at = database_now_seconds(&database).await?;
        let begin = BeginArtifactFinalization {
            authority,
            name: ArtifactName::new("dist", 255)?,
            claimed_size: 6,
            claimed_digest: None,
            observed_at_seconds: finalization_observed_at,
            lease_seconds: 30,
        };
        let claim = match repository.begin_finalization(begin.clone()).await? {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("first finalizer must own the claim: {outcome:?}"),
        };
        assert_eq!(claim.generation(), 1);
        let retry_at = match repository.begin_finalization(begin.clone()).await? {
            ArtifactFinalizationReservation::InProgress { retry_at_seconds } => retry_at_seconds,
            outcome => panic!("exact live claim must be in progress: {outcome:?}"),
        };
        assert!(retry_at >= finalization_observed_at + 30);
        assert!(retry_at <= database_now_seconds(&database).await? + 30);
        let conflict = repository
            .begin_finalization(BeginArtifactFinalization {
                claimed_digest: Some(Sha256Digest::from_bytes([12; 32])),
                ..begin.clone()
            })
            .await
            .expect_err("a live claim fixes the exact request");
        assert_eq!(conflict.kind(), ArtifactRepositoryErrorKind::Conflict);
        assert_eq!(
            repository
                .load_finalization(LoadArtifactFinalization {
                    claim: claim.clone(),
                    observed_at_seconds: finalization_observed_at,
                })
                .await?,
            ArtifactFinalizationWork::Verify(committed.clone())
        );
        let payload = manifest_payload(&committed, content_digest);
        repository
            .record_verification(RecordArtifactVerification {
                claim: claim.clone(),
                content_digest,
                manifest: payload.descriptor().clone(),
                manifest_bytes: payload.bytes().to_vec(),
                observed_at_seconds: finalization_observed_at,
                lease_seconds: 30,
            })
            .await?;
        assert!(matches!(
            repository
                .load_finalization(LoadArtifactFinalization {
                    claim: claim.clone(),
                    observed_at_seconds: finalization_observed_at,
                })
                .await?,
            ArtifactFinalizationWork::Publish(verified)
                if verified.manifest == *payload.descriptor()
                    && verified.manifest_bytes == payload.bytes().as_ref()
        ));
        let finalized = repository
            .complete_finalization(CompleteArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: finalization_observed_at,
            })
            .await?;
        let retry = repository
            .complete_finalization(CompleteArtifactFinalization {
                claim,
                observed_at_seconds: finalization_observed_at,
            })
            .await?;
        assert_eq!(retry, finalized);
        assert_eq!(
            repository
                .begin_finalization(BeginArtifactFinalization {
                    observed_at_seconds: finalization_observed_at,
                    ..begin
                })
                .await?,
            ArtifactFinalizationReservation::Published(finalized)
        );
        let manifest = payload.descriptor().clone();
        let listed = repository
            .list(ListArtifacts {
                authority,
                name: Some(ArtifactName::new("dist", 255)?),
                artifact_id: Some(finalized.artifact_id),
                observed_at_seconds: 1_010,
                maximum_results: 10,
            })
            .await?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].artifact_id, finalized.artifact_id);
        assert_eq!(listed[0].authority, authority);
        assert_eq!(listed[0].content_digest, content_digest);
        assert_eq!(listed[0].manifest, manifest);
        assert_eq!(listed[0].created_at_seconds, 1_000);
        assert_eq!(listed[0].expires_at_seconds, None);
        let resolved = repository
            .resolve_download(ResolveArtifactDownload {
                artifact_id: finalized.artifact_id,
                content_digest,
                observed_at_seconds: 1_010,
            })
            .await?;
        assert_eq!(resolved, listed[0]);
        let absent = repository
            .list(ListArtifacts {
                authority,
                name: Some(ArtifactName::new("other", 255)?),
                artifact_id: None,
                observed_at_seconds: 1_010,
                maximum_results: 10,
            })
            .await?;
        assert!(absent.is_empty());

        let state: (i64, i64, i64, String, Option<i64>, String, Option<i64>) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_artifacts),
                (SELECT count(*) FROM workflow_artifact_blocks),
                (SELECT count(*) FROM workflow_artifact_block_commits),
                (SELECT state FROM workflow_artifact_blocks LIMIT 1),
                (SELECT ready_at_seconds FROM workflow_artifact_blocks LIMIT 1),
                (SELECT manifest_state FROM workflow_artifacts LIMIT 1),
                (SELECT manifest_reserved_at_seconds FROM workflow_artifacts LIMIT 1)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(state.0, 1);
        assert_eq!(state.1, 1);
        assert_eq!(state.2, 1);
        assert_eq!(state.3, "ready");
        assert_eq!(state.4, Some(1_002));
        assert_eq!(state.5, "ready");
        assert!(state.6.is_some_and(|value| {
            u64::try_from(value).is_ok_and(|value| value >= finalization_observed_at)
        }));
        let finalization_state: (i64, Option<i64>, Option<i32>) = sqlx::query_as(
            r"
            SELECT finalization_generation,
                   finalization_claim_expires_at_seconds,
                   octet_length(manifest_bytes)
            FROM workflow_artifacts
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(finalization_state.0, 1);
        assert!(finalization_state.1.is_some_and(|value| {
            u64::try_from(value).is_ok_and(|value| value >= finalization_observed_at + 30)
        }));
        assert_eq!(
            finalization_state.2,
            Some(i32::try_from(payload.bytes().len())?)
        );
        let mut corrupted_manifest = payload.bytes().to_vec();
        corrupted_manifest[0] ^= 1;
        sqlx::query("UPDATE workflow_artifacts SET manifest_bytes = $1")
            .bind(&corrupted_manifest)
            .execute(database.pool())
            .await?;
        let corrupt_winner = repository
            .begin_finalization(BeginArtifactFinalization {
                authority,
                name: ArtifactName::new("dist", 255)?,
                claimed_size: 6,
                claimed_digest: Some(content_digest),
                observed_at_seconds: database_now_seconds(&database).await?,
                lease_seconds: 30,
            })
            .await
            .expect_err("published recovery must verify the persisted canonical bytes");
        assert_eq!(
            corrupt_winner.kind(),
            ArtifactRepositoryErrorKind::CorruptData
        );
        sqlx::query("UPDATE workflow_artifacts SET manifest_bytes = $1")
            .bind(payload.bytes().as_ref())
            .execute(database.pool())
            .await?;
        let missing_block_readiness = sqlx::query(
            "UPDATE workflow_artifact_blocks SET ready_at_seconds = NULL WHERE state = 'ready'",
        )
        .execute(database.pool())
        .await
        .expect_err("ready blocks require an explicit completion timestamp");
        assert_eq!(
            missing_block_readiness
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_artifact_blocks_readiness")
        );
        let missing_manifest_identity = sqlx::query(
            "UPDATE workflow_artifacts SET manifest_object_key = NULL WHERE state = 'finalized'",
        )
        .execute(database.pool())
        .await
        .expect_err("finalized manifests require every publication field");
        assert_eq!(
            missing_manifest_identity
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_artifacts_publication_shape")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn artifact_creation_inherits_the_locked_attempt_and_run_safety_matrix() -> TestResult {
    run_with_database(|database| async move {
        let visibilities = ["private", "authenticated", "public"];
        let exposures = ["secretless", "capability_only", "readable_secret"];

        for requested_visibility in visibilities {
            for secret_exposure_class in exposures {
                let (repository, authority) = active_attempt_with_safety(
                    &database,
                    requested_visibility,
                    secret_exposure_class,
                )
                .await?;
                let upload_id = UploadId::from_uuid(Uuid::new_v4());
                let created = repository
                    .create(create_request(authority, upload_id))
                    .await?;
                let replay = repository
                    .create(create_request(
                        authority,
                        UploadId::from_uuid(Uuid::new_v4()),
                    ))
                    .await?;
                assert_eq!(replay, created);

                let persisted: (String, String, String, String, i32) = sqlx::query_as(
                    r"
                    SELECT secret_exposure_class, requested_visibility,
                           effective_visibility, publication_safety_reason,
                           publication_safety_schema
                    FROM workflow_artifacts
                    WHERE upload_id = $1
                    ",
                )
                .bind(upload_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
                let narrowed =
                    secret_exposure_class == "readable_secret" && requested_visibility != "private";
                let effective_visibility = if secret_exposure_class == "readable_secret" {
                    "private"
                } else {
                    requested_visibility
                };
                let publication_safety_reason = if narrowed {
                    "secret_exposure"
                } else {
                    "repository_policy"
                };
                assert_eq!(
                    persisted,
                    (
                        secret_exposure_class.to_owned(),
                        requested_visibility.to_owned(),
                        effective_visibility.to_owned(),
                        publication_safety_reason.to_owned(),
                        HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA,
                    )
                );
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn artifact_create_replay_rejects_schema_valid_safety_tampering() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) =
            active_attempt_with_safety(&database, "public", "secretless").await?;
        let (tenant_id, repository_id): (String, Uuid) = sqlx::query_as(
            r"
            SELECT repository.tenant_id, run.repository_id
            FROM workflow_runs AS run
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE run.id = $1
            ",
        )
        .bind(authority.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;

        for (name, effective_visibility, publication_safety_reason) in [
            ("narrowed", "private", "repository_policy"),
            ("false-reason", "public", "secret_exposure"),
        ] {
            sqlx::query(
                r"
                INSERT INTO workflow_artifacts (
                    upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
                    fencing_token, name, protocol_version, mime_type,
                    created_at_seconds, secret_exposure_class,
                    requested_visibility, effective_visibility,
                    publication_safety_reason, publication_safety_schema
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, 7, 'application/zip',
                    1000, 'secretless', 'public', $9, $10, $11
                )
                ",
            )
            .bind(Uuid::new_v4())
            .bind(&tenant_id)
            .bind(repository_id)
            .bind(authority.run_id().as_uuid())
            .bind(authority.job_id().as_uuid())
            .bind(authority.attempt_id().as_uuid())
            .bind(i64::try_from(authority.fencing_token().get())?)
            .bind(name)
            .bind(effective_visibility)
            .bind(publication_safety_reason)
            .bind(HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA)
            .execute(database.pool())
            .await?;

            let error = repository
                .create(create_named_request(
                    authority,
                    UploadId::from_uuid(Uuid::new_v4()),
                    name,
                    10,
                ))
                .await
                .expect_err("server-derived artifact safety must be exact on replay");
            assert_eq!(error.kind(), ArtifactRepositoryErrorKind::CorruptData);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn artifact_create_replay_rejects_noncurrent_publication_safety_schema() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) =
            active_attempt_with_safety(&database, "public", "secretless").await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        sqlx::query(
            "ALTER TABLE workflow_artifacts DROP CONSTRAINT workflow_artifacts_publication_safety_schema",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_artifacts DISABLE TRIGGER workflow_artifacts_output_safety_immutable",
        )
        .execute(database.pool())
        .await?;

        for schema in [0_i32, HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA - 1] {
            sqlx::query(
                "UPDATE workflow_artifacts SET publication_safety_schema = $2 WHERE upload_id = $1",
            )
            .bind(upload_id.as_uuid())
            .bind(schema)
            .execute(database.pool())
            .await?;
            let error = repository
                .create(create_request(
                    authority,
                    UploadId::from_uuid(Uuid::new_v4()),
                ))
                .await
                .expect_err("noncurrent publication-safety schema must fail closed");
            assert_eq!(error.kind(), ArtifactRepositoryErrorKind::CorruptData);
        }
        sqlx::query(
            "ALTER TABLE workflow_artifacts ENABLE TRIGGER workflow_artifacts_output_safety_immutable",
        )
        .execute(database.pool())
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_block_reservations_are_idempotent_and_not_visible_early() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        let block_id = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        let block = ArtifactBlock::new(block_id.to_owned(), descriptor("concurrent", 5, 7));
        let request = ReserveArtifactBlock {
            upload_id,
            block: block.clone(),
            observed_at_seconds: 1_001,
            maximum_blocks: 10,
            maximum_staged_bytes: 1_024,
            maximum_run_blocks: 10,
            maximum_run_staged_bytes: 4_096,
        };
        let (first, second) = tokio::join!(
            repository.reserve_block(request.clone()),
            repository.reserve_block(request),
        );
        assert_eq!(first?, ArtifactBlockReservation::UploadRequired);
        assert_eq!(second?, ArtifactBlockReservation::UploadRequired);

        let error = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids: vec![block_id.to_owned()],
                list_digest: list_digest(&[block_id.to_owned()]),
                observed_at_seconds: 1_002,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await
            .expect_err("reserved block must not be commit-visible");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::NotFound);

        let completion = CompleteArtifactBlock {
            upload_id,
            block: block.clone(),
            // Completion is a liveness timestamp; a wall-clock correction
            // must not violate the durable reservation ordering.
            observed_at_seconds: 999,
        };
        let (first, second) = tokio::join!(
            repository.complete_block(completion.clone()),
            repository.complete_block(completion),
        );
        first?;
        second?;
        assert_eq!(
            repository
                .reserve_block(ReserveArtifactBlock {
                    upload_id,
                    block,
                    observed_at_seconds: 1_004,
                    maximum_blocks: 10,
                    maximum_staged_bytes: 1_024,
                    maximum_run_blocks: 10,
                    maximum_run_staged_bytes: 4_096,
                })
                .await?,
            ArtifactBlockReservation::Ready
        );
        let row: (i64, String, Option<i64>) = sqlx::query_as(
            "SELECT count(*) OVER (), state, ready_at_seconds FROM workflow_artifact_blocks",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(row, (1, "ready".to_owned(), Some(1_001)));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_run_block_admission_never_oversubscribes() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let first_upload = UploadId::from_uuid(Uuid::new_v4());
        let second_upload = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_named_request(authority, first_upload, "first", 10))
            .await?;
        repository
            .create(create_named_request(authority, second_upload, "second", 10))
            .await?;

        let first = ReserveArtifactBlock {
            upload_id: first_upload,
            block: ArtifactBlock::new("QUFB".to_owned(), descriptor("count-a", 0, 1)),
            observed_at_seconds: 1_001,
            maximum_blocks: 1,
            maximum_staged_bytes: 1,
            maximum_run_blocks: 1,
            maximum_run_staged_bytes: 1,
        };
        let second = ReserveArtifactBlock {
            upload_id: second_upload,
            block: ArtifactBlock::new("QkJC".to_owned(), descriptor("count-b", 0, 2)),
            observed_at_seconds: 1_001,
            maximum_blocks: 1,
            maximum_staged_bytes: 1,
            maximum_run_blocks: 1,
            maximum_run_staged_bytes: 1,
        };
        let (first, second) = tokio::join!(
            repository.reserve_block(first),
            repository.reserve_block(second),
        );
        let rejected = match (first, second) {
            (Ok(ArtifactBlockReservation::UploadRequired), Err(error))
            | (Err(error), Ok(ArtifactBlockReservation::UploadRequired)) => error,
            result => panic!("exactly one concurrent block must be admitted: {result:?}"),
        };
        assert_eq!(
            rejected.kind(),
            ArtifactRepositoryErrorKind::ResourceExhausted
        );

        let block_count: i64 = sqlx::query_scalar("SELECT count(*) FROM workflow_artifact_blocks")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(block_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn manifest_reservation_and_publication_use_database_time() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        let committed = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids: Vec::new(),
                list_digest: list_digest(&[]),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;

        let content_digest = Sha256Digest::from_bytes([42; 32]);
        let observed_at = database_now_seconds(&database).await?;
        let claim = match repository
            .begin_finalization(BeginArtifactFinalization {
                authority,
                name: ArtifactName::new("dist", 255)?,
                claimed_size: 0,
                claimed_digest: None,
                observed_at_seconds: observed_at,
                lease_seconds: 10,
            })
            .await?
        {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("expected finalization claim: {outcome:?}"),
        };
        let payload = manifest_payload(&committed, content_digest);
        let reservation_database_before = database_now_seconds(&database).await?;
        let forged_fast_reservation = reservation_database_before + 30;
        repository
            .record_verification(RecordArtifactVerification {
                claim: claim.clone(),
                content_digest,
                manifest: payload.descriptor().clone(),
                manifest_bytes: payload.bytes().to_vec(),
                observed_at_seconds: forged_fast_reservation,
                lease_seconds: 10,
            })
            .await?;
        let reservation_database_after = database_now_seconds(&database).await?;

        let reserved_at: i64 = sqlx::query_scalar(
            "SELECT manifest_reserved_at_seconds FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let reserved_at = u64::try_from(reserved_at)?;
        assert!(
            reservation_database_after < forged_fast_reservation,
            "fixture must retain a future caller observation"
        );
        assert!(
            (reservation_database_before..=reservation_database_after).contains(&reserved_at),
            "manifest reservation must persist database time, not the future caller observation"
        );

        let publication_database_before = database_now_seconds(&database).await?;
        let forged_fast_publication = publication_database_before + 30;
        repository
            .complete_finalization(CompleteArtifactFinalization {
                claim,
                observed_at_seconds: forged_fast_publication,
            })
            .await?;
        let publication_database_after = database_now_seconds(&database).await?;
        let finalized_at: i64 = sqlx::query_scalar(
            "SELECT finalized_at_seconds FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let finalized_at = u64::try_from(finalized_at)?;
        assert!(
            publication_database_after < forged_fast_publication,
            "fixture must retain a future caller observation"
        );
        assert!(
            (publication_database_before..=publication_database_after).contains(&finalized_at),
            "publication must persist database time, not the future caller observation"
        );
        assert!(finalized_at >= reserved_at);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn finalization_rejects_future_and_past_caller_skew() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids: Vec::new(),
                list_digest: list_digest(&[]),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        let content_digest = Sha256Digest::from_bytes([42; 32]);
        let observed_at = database_now_seconds(&database).await?;
        let begin = BeginArtifactFinalization {
            authority,
            name: ArtifactName::new("dist", 255)?,
            claimed_size: 0,
            claimed_digest: Some(content_digest),
            observed_at_seconds: observed_at,
            lease_seconds: 5,
        };

        for skewed_observation in [
            observed_at.saturating_sub(3_600),
            observed_at.saturating_add(3_600),
        ] {
            let error = repository
                .begin_finalization(BeginArtifactFinalization {
                    observed_at_seconds: skewed_observation,
                    ..begin.clone()
                })
                .await
                .expect_err("caller skew must never acquire finalization authority");
            assert_eq!(error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        }
        let generation: i64 = sqlx::query_scalar(
            "SELECT finalization_generation FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(generation, 0);

        let claim = match repository
            .begin_finalization(BeginArtifactFinalization {
                observed_at_seconds: database_now_seconds(&database).await?,
                ..begin
            })
            .await?
        {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("database-time finalization claim expected: {outcome:?}"),
        };
        let expiry_before: i64 = sqlx::query_scalar(
            "SELECT finalization_claim_expires_at_seconds FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        for skewed_observation in [
            observed_at.saturating_sub(3_600),
            observed_at.saturating_add(3_600),
        ] {
            let load_error = repository
                .load_finalization(LoadArtifactFinalization {
                    claim: claim.clone(),
                    observed_at_seconds: skewed_observation,
                })
                .await
                .expect_err("caller skew must not authorize finalization work");
            assert_eq!(load_error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
            let renew_error = repository
                .renew_finalization(RenewArtifactFinalization {
                    claim: claim.clone(),
                    observed_at_seconds: skewed_observation,
                    lease_seconds: 60,
                })
                .await
                .expect_err("caller skew must not renew finalization authority");
            assert_eq!(renew_error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        }
        let expiry_after: i64 = sqlx::query_scalar(
            "SELECT finalization_claim_expires_at_seconds FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(expiry_after, expiry_before);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One exact-boundary narrative covers every claim-bound finalization operation.
async fn bounded_caller_skew_cannot_steal_or_commit_at_exact_expiry() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        let committed = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids: Vec::new(),
                list_digest: list_digest(&[]),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        let content_digest = Sha256Digest::from_bytes([0x52; 32]);
        let begin = BeginArtifactFinalization {
            authority,
            name: ArtifactName::new("dist", 255)?,
            claimed_size: 0,
            claimed_digest: Some(content_digest),
            observed_at_seconds: database_now_seconds(&database).await?,
            lease_seconds: 60,
        };
        let claim = match repository.begin_finalization(begin.clone()).await? {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("database-time finalization claim expected: {outcome:?}"),
        };
        let payload = manifest_payload(&committed, content_digest);
        repository
            .record_verification(RecordArtifactVerification {
                claim: claim.clone(),
                content_digest,
                manifest: payload.descriptor().clone(),
                manifest_bytes: payload.bytes().to_vec(),
                observed_at_seconds: database_now_seconds(&database).await?,
                lease_seconds: 60,
            })
            .await?;
        let expiry_before: i64 = sqlx::query_scalar(
            "SELECT finalization_claim_expires_at_seconds FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let database_now = database_now_seconds(&database).await?;
        let fast_replay = repository
            .begin_finalization(BeginArtifactFinalization {
                observed_at_seconds: database_now + 30,
                ..begin
            })
            .await?;
        assert_eq!(
            fast_replay,
            ArtifactFinalizationReservation::InProgress {
                retry_at_seconds: u64::try_from(expiry_before)?,
            },
            "bounded fast evidence cannot steal a database-live claim",
        );

        expire_finalization_claim(&database, upload_id).await?;
        let slow_observation = database_now_seconds(&database).await?.saturating_sub(30);
        let load_error = repository
            .load_finalization(LoadArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: slow_observation,
            })
            .await
            .expect_err("a slow caller cannot load exactly expired authority");
        assert_eq!(load_error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        let renew_error = repository
            .renew_finalization(RenewArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: slow_observation,
                lease_seconds: 60,
            })
            .await
            .expect_err("a slow caller cannot revive exactly expired authority");
        assert_eq!(renew_error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        let verification_error = repository
            .record_verification(RecordArtifactVerification {
                claim: claim.clone(),
                content_digest,
                manifest: payload.descriptor().clone(),
                manifest_bytes: payload.bytes().to_vec(),
                observed_at_seconds: slow_observation,
                lease_seconds: 60,
            })
            .await
            .expect_err("a slow caller cannot persist with exactly expired authority");
        assert_eq!(
            verification_error.kind(),
            ArtifactRepositoryErrorKind::Unauthorized
        );
        let completion_error = repository
            .complete_finalization(CompleteArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: slow_observation,
            })
            .await
            .expect_err("a slow caller cannot publish with exactly expired authority");
        assert_eq!(
            completion_error.kind(),
            ArtifactRepositoryErrorKind::Unauthorized
        );
        let state: (String, String, i64) = sqlx::query_as(
            r"
            SELECT state, manifest_state, finalization_generation
            FROM workflow_artifacts
            WHERE upload_id = $1
            ",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            state,
            (
                "pending".to_owned(),
                "reserved".to_owned(),
                i64::try_from(claim.generation())?,
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn finalization_rejects_expiry_during_a_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        let committed = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids: Vec::new(),
                list_digest: list_digest(&[]),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        let content_digest = Sha256Digest::from_bytes([42; 32]);
        let begin = BeginArtifactFinalization {
            authority,
            name: ArtifactName::new("dist", 255)?,
            claimed_size: 0,
            claimed_digest: Some(content_digest),
            observed_at_seconds: database_now_seconds(&database).await?,
            lease_seconds: 5,
        };
        let claim = match repository
            .begin_finalization(BeginArtifactFinalization {
                observed_at_seconds: database_now_seconds(&database).await?,
                ..begin
            })
            .await?
        {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("database-time finalization claim expected: {outcome:?}"),
        };
        let payload = manifest_payload(&committed, content_digest);
        repository
            .record_verification(RecordArtifactVerification {
                claim: claim.clone(),
                content_digest,
                manifest: payload.descriptor().clone(),
                manifest_bytes: payload.bytes().to_vec(),
                observed_at_seconds: database_now_seconds(&database).await?,
                lease_seconds: 5,
            })
            .await?;

        let mut blocker = database.pool().begin().await?;
        let blocker_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query(
            r"
            UPDATE workflow_artifacts
            SET finalization_claim_expires_at_seconds =
                floor(extract(epoch FROM clock_timestamp()))::BIGINT + 1
            WHERE upload_id = $1
            ",
        )
        .bind(upload_id.as_uuid())
        .execute(&mut *blocker)
        .await?;
        let completion_repository = repository.clone();
        let completion_observed_at = database_now_seconds(&database).await?;
        let completion = tokio::spawn(async move {
            completion_repository
                .complete_finalization(CompleteArtifactFinalization {
                    claim,
                    observed_at_seconds: completion_observed_at,
                })
                .await
        });
        wait_for_direct_blocker(database.pool(), blocker_pid).await?;
        assert!(!completion.is_finished(), "publication must remain blocked");
        clock.advance(1_000).await?;
        blocker.commit().await?;
        let error = completion
            .await?
            .expect_err("database time sampled after the lock wait must reject expiry");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        let state: (String, String) = sqlx::query_as(
            "SELECT state, manifest_state FROM workflow_artifacts WHERE upload_id = $1",
        )
        .bind(upload_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(state, ("pending".to_owned(), "reserved".to_owned()));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One ordered crash/takeover narrative makes each fence transition explicit.
async fn concurrent_finalizers_take_over_with_generation_fencing_and_publication_replay()
-> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_request(authority, upload_id))
            .await?;
        let committed = repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids: Vec::new(),
                list_digest: list_digest(&[]),
                observed_at_seconds: 1_000,
                maximum_blocks: 10,
                maximum_artifact_bytes: 1_024,
            })
            .await?;
        let content_digest = Sha256Digest::from_bytes([42; 32]);
        let first_observed_at = database_now_seconds(&database).await?;
        let begin = BeginArtifactFinalization {
            authority,
            name: ArtifactName::new("dist", 255)?,
            claimed_size: 0,
            claimed_digest: Some(content_digest),
            observed_at_seconds: first_observed_at,
            lease_seconds: 10,
        };
        let (first, second) = tokio::join!(
            repository.begin_finalization(begin.clone()),
            repository.begin_finalization(begin.clone()),
        );
        let first = first?;
        let second = second?;
        let (first_claim, retry_at_seconds) = match (first, second) {
            (
                ArtifactFinalizationReservation::Claimed(claim),
                ArtifactFinalizationReservation::InProgress { retry_at_seconds },
            )
            | (
                ArtifactFinalizationReservation::InProgress { retry_at_seconds },
                ArtifactFinalizationReservation::Claimed(claim),
            ) => (claim, retry_at_seconds),
            outcomes => panic!("one exact concurrent finalizer must win: {outcomes:?}"),
        };
        assert!(retry_at_seconds >= first_observed_at + 10);
        expire_finalization_claim(&database, upload_id).await?;

        let second_observed_at = database_now_seconds(&database).await?;
        let second_claim = match repository
            .begin_finalization(BeginArtifactFinalization {
                observed_at_seconds: second_observed_at,
                ..begin.clone()
            })
            .await?
        {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("expired pre-verification claim must be taken over: {outcome:?}"),
        };
        assert_eq!(second_claim.generation(), first_claim.generation() + 1);
        let stale = repository
            .renew_finalization(RenewArtifactFinalization {
                claim: first_claim,
                observed_at_seconds: second_observed_at,
                lease_seconds: 10,
            })
            .await
            .expect_err("an expired generation must remain fenced after takeover");
        assert_eq!(stale.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        assert_eq!(
            repository
                .load_finalization(LoadArtifactFinalization {
                    claim: second_claim.clone(),
                    observed_at_seconds: second_observed_at,
                })
                .await?,
            ArtifactFinalizationWork::Verify(committed.clone())
        );

        let payload = manifest_payload(&committed, content_digest);
        let verification_observed_at = database_now_seconds(&database).await?;
        repository
            .record_verification(RecordArtifactVerification {
                claim: second_claim.clone(),
                content_digest,
                manifest: payload.descriptor().clone(),
                manifest_bytes: payload.bytes().to_vec(),
                observed_at_seconds: verification_observed_at,
                lease_seconds: 10,
            })
            .await?;
        expire_finalization_claim(&database, upload_id).await?;
        let third_observed_at = database_now_seconds(&database).await?;
        let third_claim = match repository
            .begin_finalization(BeginArtifactFinalization {
                observed_at_seconds: third_observed_at,
                ..begin.clone()
            })
            .await?
        {
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            outcome => panic!("persisted publication must be recoverable: {outcome:?}"),
        };
        assert_eq!(third_claim.generation(), second_claim.generation() + 1);
        let stale = repository
            .complete_finalization(CompleteArtifactFinalization {
                claim: second_claim,
                observed_at_seconds: third_observed_at,
            })
            .await
            .expect_err("a stale generation cannot publish");
        assert_eq!(stale.kind(), ArtifactRepositoryErrorKind::Unauthorized);
        assert!(matches!(
            repository
                .load_finalization(LoadArtifactFinalization {
                    claim: third_claim.clone(),
                    observed_at_seconds: third_observed_at,
                })
                .await?,
            ArtifactFinalizationWork::Publish(verified)
                if verified.manifest == *payload.descriptor()
                    && verified.manifest_bytes == payload.bytes().as_ref()
        ));
        let finalized = repository
            .complete_finalization(CompleteArtifactFinalization {
                claim: third_claim,
                observed_at_seconds: third_observed_at,
            })
            .await?;
        assert_eq!(
            repository
                .begin_finalization(BeginArtifactFinalization {
                    observed_at_seconds: database_now_seconds(&database).await?,
                    ..begin
                })
                .await?,
            ArtifactFinalizationReservation::Published(finalized)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn artifact_count_and_run_block_and_byte_quotas_are_transactional() -> TestResult {
    run_with_database(|database| async move {
        let (repository, authority) = active_attempt(&database).await?;
        let first_upload = UploadId::from_uuid(Uuid::new_v4());
        let second_upload = UploadId::from_uuid(Uuid::new_v4());
        let first = create_named_request(authority, first_upload, "first", 1);
        let second = create_named_request(authority, second_upload, "second", 1);
        let (first_result, second_result) =
            tokio::join!(repository.create(first), repository.create(second));
        let (admitted_upload, rejected) = match (first_result, second_result) {
            (Ok(_), Err(error)) => (first_upload, error),
            (Err(error), Ok(_)) => (second_upload, error),
            result => panic!("exactly one concurrent create must be admitted: {result:?}"),
        };
        assert_eq!(
            rejected.kind(),
            ArtifactRepositoryErrorKind::ResourceExhausted
        );

        let retry_name = if admitted_upload == first_upload {
            "first"
        } else {
            "second"
        };
        assert_eq!(
            repository
                .create(create_named_request(
                    authority,
                    admitted_upload,
                    retry_name,
                    1
                ))
                .await?
                .upload_id,
            admitted_upload
        );

        let other_upload = UploadId::from_uuid(Uuid::new_v4());
        repository
            .create(create_named_request(authority, other_upload, "other", 10))
            .await?;
        repository
            .reserve_block(ReserveArtifactBlock {
                upload_id: admitted_upload,
                block: ArtifactBlock::new("QUFB".to_owned(), descriptor("quota-a", 3, 1)),
                observed_at_seconds: 1_001,
                maximum_blocks: 1,
                maximum_staged_bytes: 10,
                maximum_run_blocks: 1,
                maximum_run_staged_bytes: 4,
            })
            .await?;
        let error = repository
            .reserve_block(ReserveArtifactBlock {
                upload_id: other_upload,
                block: ArtifactBlock::new("QkJC".to_owned(), descriptor("quota-count", 0, 2)),
                observed_at_seconds: 1_002,
                maximum_blocks: 1,
                maximum_staged_bytes: 10,
                maximum_run_blocks: 1,
                maximum_run_staged_bytes: 4,
            })
            .await
            .expect_err("aggregate run block count must include zero-byte reservations");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::ResourceExhausted);

        let error = repository
            .reserve_block(ReserveArtifactBlock {
                upload_id: other_upload,
                block: ArtifactBlock::new("Q0ND".to_owned(), descriptor("quota-b", 2, 3)),
                observed_at_seconds: 1_003,
                maximum_blocks: 10,
                maximum_staged_bytes: 10,
                maximum_run_blocks: 10,
                maximum_run_staged_bytes: 4,
            })
            .await
            .expect_err("aggregate run bytes must include reservations");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::ResourceExhausted);

        let totals: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_artifacts),
                (SELECT count(*) FROM workflow_artifact_blocks),
                (SELECT coalesce(sum(size_bytes), 0)::bigint FROM workflow_artifact_blocks)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(totals, (2, 1, 3));
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
            automata_ci_core::JobId::new(),
            authority.attempt_id(),
            authority.fencing_token(),
        );
        let error = repository
            .create(create_request(wrong, UploadId::from_uuid(Uuid::new_v4())))
            .await
            .expect_err("cross-job token must fail");
        assert_eq!(error.kind(), ArtifactRepositoryErrorKind::Unauthorized);

        sqlx::query(
            r"
            UPDATE job_attempts
            SET lease_expires_at_ms = lease_issued_at_ms + 1
            WHERE id = $1
            ",
        )
        .bind(authority.attempt_id().as_uuid())
        .execute(database.pool())
        .await?;
        let requeued = database
            .store()
            .requeue_expired(database_now_millis(&database).await?, 3, 10)
            .await?;
        assert_eq!(requeued, vec![authority.attempt_id()]);
        let error = repository
            .reserve_block(ReserveArtifactBlock {
                upload_id,
                block: ArtifactBlock::new("QUFB".to_owned(), descriptor("stale-block", 1, 1)),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_staged_bytes: 1_024,
                maximum_run_blocks: 10,
                maximum_run_staged_bytes: 4_096,
            })
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
    let seed = seed_control_plane(database.pool()).await?;
    let attempt_id = AttemptId::new();
    let queued_at = database_now_millis(database).await?;
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            seed.job_id,
            AttemptNumber::new(1)?,
            queued_at,
        ))
        .await?;
    let lease_observed_at = database_now_millis(database).await?;
    let lease = database
        .store()
        .acquire_lease(
            AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                seed.session_fence,
                StableRunnerSlot::new(1)?,
                lease_observed_at,
                UnixMillis::new(lease_observed_at.get() + 60_000),
            )
            .expect("valid lease request"),
        )
        .await?;
    Ok((
        PostgresArtifactRepository::new(database.pool().clone()),
        ExecutionAuthority::new(seed.run_id, seed.job_id, attempt_id, lease.fencing_token()),
    ))
}

async fn active_attempt_with_safety(
    database: &TestDatabase,
    requested_artifact_visibility: &str,
    secret_exposure_class: &str,
) -> TestResult<(PostgresArtifactRepository, ExecutionAuthority)> {
    let seed = seed_control_plane(database.pool()).await?;
    let run_id = Uuid::new_v4();
    let job_id = automata_ci_core::JobId::new();
    let attempt_id = AttemptId::new();
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number,
            event_name, event_object_key, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, head_sha, status,
            created_at_ms, updated_at_ms, publication_policy_revision,
            requested_dashboard_visibility, effective_dashboard_visibility,
            requested_log_visibility, requested_artifact_visibility,
            publication_safety_reason, publication_safety_schema, runner_requirements_schema
        )
        SELECT
            $1, repository_id, workflow_id, snapshot_id, run_number + 1,
            event_name, 'test/artifact-safety-event', event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, head_sha, status,
            2, 2, 1, 'private', 'private', 'private', $3,
            'repository_policy', $4, runner_requirements_schema
        FROM workflow_runs
        WHERE id = $2
        ",
    )
    .bind(run_id)
    .bind(seed.run_id.as_uuid())
    .bind(requested_artifact_visibility)
    .bind(HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        SELECT
            $1, $2, 'artifact-safety', display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, 2
        FROM jobs
        WHERE id = $3
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id)
    .bind(seed.job_id.as_uuid())
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            queued_at_ms, changed_at_ms, secret_exposure_class,
            raw_log_disposition, requested_log_visibility,
            effective_log_visibility, output_safety_reason, output_safety_schema, classified_at_ms
        ) VALUES (
            $1, $2, 1, 'queued', 0, 3, 3, $3, $4,
            'private', 'private', 'repository_policy', $5, 3
        )
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(job_id.as_uuid())
    .bind(secret_exposure_class)
    .bind("persist")
    .bind(HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA)
    .execute(database.pool())
    .await?;
    let lease_observed_at = database_now_millis(database).await?;
    let lease = database
        .store()
        .acquire_lease(
            AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                seed.session_fence,
                StableRunnerSlot::new(1)?,
                lease_observed_at,
                UnixMillis::new(lease_observed_at.get() + 60_000),
            )
            .expect("valid lease request"),
        )
        .await?;
    Ok((
        PostgresArtifactRepository::new(database.pool().clone()),
        ExecutionAuthority::new(
            automata_ci_core::RunId::from_uuid(run_id),
            job_id,
            attempt_id,
            lease.fencing_token(),
        ),
    ))
}

fn create_request(authority: ExecutionAuthority, upload_id: UploadId) -> CreateArtifact {
    create_named_request(authority, upload_id, "dist", 500)
}

fn create_named_request(
    authority: ExecutionAuthority,
    upload_id: UploadId,
    name: &str,
    maximum_artifacts_per_run: usize,
) -> CreateArtifact {
    CreateArtifact {
        authority,
        upload_id,
        name: ArtifactName::new(name, 255).expect("artifact name"),
        // Keep the PostgreSQL adapter fixture on the exact protocol accepted by
        // the production artifact service. This catches schema/service drift.
        version: 7,
        mime_type: "application/zip".to_owned(),
        expires_at_seconds: None,
        observed_at_seconds: 1_000,
        maximum_artifacts_per_run,
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

fn manifest_payload(
    committed: &automata_ci_results_github::CommittedArtifact,
    content_digest: Sha256Digest,
) -> BlobPayload {
    let bytes = serde_json::to_vec(&ArtifactManifest::from_committed(committed, content_digest))
        .expect("canonical manifest");
    BlobPayload::from_bytes(
        BlobKey::new(format!(
            "artifacts/v1/{content_digest}/{}/manifest.json",
            committed.artifact_id
        ))
        .expect("manifest key"),
        MediaType::new(ARTIFACT_MANIFEST_MEDIA_TYPE).expect("manifest media type"),
        Bytes::from(bytes),
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

async fn expire_finalization_claim(database: &TestDatabase, upload_id: UploadId) -> TestResult {
    sqlx::query(
        r"
        UPDATE workflow_artifacts
        SET finalization_claim_expires_at_seconds =
            floor(extract(epoch FROM clock_timestamp()))::BIGINT
        WHERE upload_id = $1
        ",
    )
    .bind(upload_id.as_uuid())
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn wait_for_direct_blocker(pool: &PgPool, blocking_pid: i32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked = sqlx::query_scalar::<_, bool>(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity AS activity
                    WHERE $1 = ANY(pg_blocking_pids(activity.pid))
                )
                ",
            )
            .bind(blocking_pid)
            .fetch_one(pool)
            .await?;
            if blocked {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "artifact publication did not reach its row-lock gate")??;
    Ok(())
}
