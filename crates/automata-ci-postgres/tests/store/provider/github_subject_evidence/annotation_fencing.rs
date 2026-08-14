use std::time::Duration;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_store::{
    AdvanceGithubCheckAnnotations, BeginGithubCheckAnnotationBatch, BeginGithubCheckRunCreate,
    BindGithubCheckRun, BindGithubCheckSuite, ClaimedGithubCheckProjection,
    ClearGithubCheckAnnotationUncertainty, GithubCheckProjectionAction,
    GithubCheckProjectionClaimFence, GithubCheckProjectionOutbox as _,
    GithubCheckProjectionWorkerId, GithubCheckRunBindingFence, GithubCheckRunId,
    GithubCheckStoreError, GithubCheckSuiteId, GithubSubjectEvidenceRepository as _,
    ProviderDeliveryFailureKind, ProviderDeliveryRepository as _, ProviderRepositoryVisibility,
    RejectProviderDelivery, ReleaseUnissuedGithubCheckAnnotationBatch,
    RetryUncertainGithubCheckAnnotations,
};
use uuid::Uuid;

use super::{
    HEAD_SHA, OWNER_ID, acceptance, bootstrap, checked_add_millis, claim_check_projection,
    claim_delivery, database_now, wait_until_database_at_or_after,
};
use crate::support::{TestDatabase, TestResult, run_with_database};

const PRESENTATION_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0xa7; 32]);
const ANNOTATION_COUNT: u16 = 10;
const BATCH_SIZE: u8 = 10;

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn annotation_append_requires_one_fresh_durable_cutoff() -> TestResult {
    run_with_database(|database| async move {
        let publish = claimed_terminal_publish(&database, "annotation-cutoff", 0xa701).await?;
        seed_annotation_progress(&database, &publish).await?;
        let digest = PRESENTATION_DIGEST;

        let unfenced = AdvanceGithubCheckAnnotations::new(
            publish.claim(),
            digest,
            0,
            ANNOTATION_COUNT,
            publish.claimed_at(),
        )?;
        assert!(matches!(
            database
                .store()
                .advance_github_check_annotations(unfenced)
                .await,
            Err(GithubCheckStoreError::ProjectionMismatch)
        ));

        let started_at = database_now(database.pool()).await?;
        let begin = BeginGithubCheckAnnotationBatch::new(
            publish.claim(),
            digest,
            0,
            BATCH_SIZE,
            started_at,
        )?;
        assert_markerless_requests_are_rejected(&database, &publish, begin).await?;
        let fenced = database
            .store()
            .begin_github_check_annotation_batch(begin)
            .await?;
        assert_eq!(fenced.next(), 0);
        assert_eq!(fenced.uncertain_batch_size(), Some(BATCH_SIZE));
        assert!(matches!(
            database
                .store()
                .begin_github_check_annotation_batch(begin)
                .await,
            Err(GithubCheckStoreError::ProjectionMismatch)
        ));

        let advanced = database
            .store()
            .advance_github_check_annotations(unfenced)
            .await?;
        assert_eq!(advanced.next(), ANNOTATION_COUNT);
        assert_eq!(advanced.uncertain_batch_size(), None);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn unissued_annotation_cutoff_requires_exact_begin_before_bounded_retry() -> TestResult {
    run_with_database(|database| async move {
        let publish = claimed_terminal_publish(&database, "annotation-unissued", 0xa702).await?;
        seed_annotation_progress(&database, &publish).await?;
        let started_at = database_now(database.pool()).await?;
        let begin = BeginGithubCheckAnnotationBatch::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            BATCH_SIZE,
            started_at,
        )?;
        database
            .store()
            .begin_github_check_annotation_batch(begin)
            .await?;

        let next_millisecond = checked_add_millis(started_at, 1)?;
        wait_until_database_at_or_after(database.pool(), next_millisecond.get()).await?;
        let forged_started_at = database_now(database.pool()).await?;
        let forged_begin = BeginGithubCheckAnnotationBatch::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            BATCH_SIZE,
            forged_started_at,
        )?;
        let forged_released_at = database_now(database.pool()).await?;
        let forged_release = ReleaseUnissuedGithubCheckAnnotationBatch::new(
            forged_begin,
            forged_released_at,
            checked_add_millis(forged_released_at, 1)?,
        )?;
        assert!(matches!(
            database
                .store()
                .release_unissued_github_check_annotation_batch(forged_release)
                .await,
            Err(GithubCheckStoreError::ProjectionMismatch)
        ));

        let released_at = database_now(database.pool()).await?;
        let release = ReleaseUnissuedGithubCheckAnnotationBatch::new(
            begin,
            released_at,
            checked_add_millis(released_at, 1)?,
        )?;
        database
            .store()
            .release_unissued_github_check_annotation_batch(release)
            .await?;

        let durable: (String, Option<String>, Option<i16>) = sqlx::query_as(
            r"
            SELECT outbox.state, outbox.last_failure_kind,
                   progress.uncertain_batch_size
            FROM github_check_projection_outbox AS outbox
            JOIN github_check_annotation_progress AS progress
              ON progress.subject_id = outbox.subject_id
            WHERE outbox.subject_id = $1
            ",
        )
        .bind(publish.claim().subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            (
                "retry".to_owned(),
                Some("github_annotation_not_issued".to_owned()),
                None,
            )
        );
        assert!(matches!(
            database
                .store()
                .release_unissued_github_check_annotation_batch(release)
                .await,
            Err(GithubCheckStoreError::ClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One lock race proves stale rejection and successor preservation.
async fn stale_annotation_retry_waiter_cannot_release_successor_claim() -> TestResult {
    run_with_database(|database| async move {
        let publish = claimed_terminal_publish(&database, "annotation-race", 0xa703).await?;
        seed_annotation_progress(&database, &publish).await?;
        let started_at = database_now(database.pool()).await?;
        let begin = BeginGithubCheckAnnotationBatch::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            BATCH_SIZE,
            started_at,
        )?;
        database
            .store()
            .begin_github_check_annotation_batch(begin)
            .await?;
        let stale_failed_at = database_now(database.pool()).await?;

        let successor_owner = GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(0xa7ff))?;
        let successor_fence = publish
            .claim()
            .fence()
            .checked_add(1)
            .ok_or("test claim fence overflow")?;
        let successor_claimed_at = publish.expires_at();
        let successor_expires_at = checked_add_millis(successor_claimed_at, 30_000)?;
        let mut successor = database.pool().begin().await?;
        let blocking_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *successor)
            .await?;
        let successor_updated = sqlx::query(
            r"
            UPDATE github_check_projection_outbox
            SET attempt_count = attempt_count + 1,
                claim_fence = $2,
                claim_owner_id = $3,
                claimed_at_ms = $4,
                claim_expires_at_ms = $5,
                state_updated_at_ms = $4
            WHERE subject_id = $1
              AND state = 'claimed'
              AND claim_owner_id = $6
              AND claim_fence = $7
              AND claim_action = 'publish'
            ",
        )
        .bind(publish.claim().subject_id().as_uuid())
        .bind(i64::try_from(successor_fence)?)
        .bind(successor_owner.as_uuid())
        .bind(successor_claimed_at.get())
        .bind(successor_expires_at.get())
        .bind(publish.claim().owner().as_uuid())
        .bind(i64::try_from(publish.claim().fence())?)
        .execute(&mut *successor)
        .await?;
        assert_eq!(successor_updated.rows_affected(), 1);

        let stale_request = RetryUncertainGithubCheckAnnotations::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            BATCH_SIZE,
            stale_failed_at,
            checked_add_millis(stale_failed_at, 1)?,
        )?;
        let stale_store = database.store().clone();
        let stale = tokio::spawn(async move {
            stale_store
                .retry_uncertain_github_check_annotations(stale_request)
                .await
        });
        wait_for_direct_blocker(database.pool(), blocking_pid).await?;
        successor.commit().await?;
        assert!(matches!(
            stale.await?,
            Err(GithubCheckStoreError::ClaimRejected)
        ));

        let current: (String, Uuid, i64, Option<i16>) = sqlx::query_as(
            r"
            SELECT outbox.state, outbox.claim_owner_id, outbox.claim_fence,
                   progress.uncertain_batch_size
            FROM github_check_projection_outbox AS outbox
            JOIN github_check_annotation_progress AS progress
              ON progress.subject_id = outbox.subject_id
            WHERE outbox.subject_id = $1
            ",
        )
        .bind(publish.claim().subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            current,
            (
                "claimed".to_owned(),
                successor_owner.as_uuid(),
                i64::try_from(successor_fence)?,
                Some(i16::from(BATCH_SIZE)),
            )
        );

        let successor_claim = GithubCheckProjectionClaimFence::from_durable_parts(
            publish.claim().subject_id(),
            successor_owner,
            successor_fence,
        )?;
        database
            .store()
            .retry_uncertain_github_check_annotations(RetryUncertainGithubCheckAnnotations::new(
                successor_claim,
                PRESENTATION_DIGEST,
                0,
                BATCH_SIZE,
                successor_claimed_at,
                checked_add_millis(successor_claimed_at, 1)?,
            )?)
            .await?;
        let retried: (String, Option<Uuid>, Option<String>, Option<i16>) = sqlx::query_as(
            r"
            SELECT outbox.state, outbox.claim_owner_id, outbox.last_failure_kind,
                   progress.uncertain_batch_size
            FROM github_check_projection_outbox AS outbox
            JOIN github_check_annotation_progress AS progress
              ON progress.subject_id = outbox.subject_id
            WHERE outbox.subject_id = $1
            ",
        )
        .bind(publish.claim().subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            retried,
            (
                "retry".to_owned(),
                None,
                Some("github_annotation_ambiguous".to_owned()),
                Some(i16::from(BATCH_SIZE)),
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn stale_annotation_clear_cannot_erase_successor_fresh_batch() -> TestResult {
    run_with_database(|database| async move {
        let publish =
            claimed_fenced_annotation_batch(&database, "annotation-clear-race", 0xa704).await?;
        let stale_observed_at = database_now(database.pool()).await?;

        let mut successor_transaction = database.pool().begin().await?;
        let successor =
            stage_fresh_annotation_successor(&mut successor_transaction, &publish, 0xa7fc).await?;
        let stale_request = ClearGithubCheckAnnotationUncertainty::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            BATCH_SIZE,
            stale_observed_at,
        )?;
        let stale_store = database.store().clone();
        let stale = tokio::spawn(async move {
            stale_store
                .clear_github_check_annotation_uncertainty(stale_request)
                .await
        });
        wait_for_direct_blocker(database.pool(), successor.blocking_pid).await?;
        successor_transaction.commit().await?;
        assert!(matches!(
            stale.await?,
            Err(GithubCheckStoreError::ClaimRejected)
        ));
        assert_fresh_successor_batch(&database, &publish, successor).await?;

        let successor_claim = GithubCheckProjectionClaimFence::from_durable_parts(
            publish.claim().subject_id(),
            successor.owner,
            successor.fence,
        )?;
        let cleared = database
            .store()
            .clear_github_check_annotation_uncertainty(ClearGithubCheckAnnotationUncertainty::new(
                successor_claim,
                PRESENTATION_DIGEST,
                0,
                BATCH_SIZE,
                successor.claimed_at,
            )?)
            .await?;
        assert_eq!(cleared.next(), 0);
        assert_eq!(cleared.uncertain_batch_size(), None);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn stale_annotation_advance_cannot_consume_successor_fresh_batch() -> TestResult {
    run_with_database(|database| async move {
        let publish =
            claimed_fenced_annotation_batch(&database, "annotation-advance-race", 0xa705).await?;
        let stale_observed_at = database_now(database.pool()).await?;

        let mut successor_transaction = database.pool().begin().await?;
        let successor =
            stage_fresh_annotation_successor(&mut successor_transaction, &publish, 0xa7fa).await?;
        let stale_request = AdvanceGithubCheckAnnotations::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            ANNOTATION_COUNT,
            stale_observed_at,
        )?;
        let stale_store = database.store().clone();
        let stale = tokio::spawn(async move {
            stale_store
                .advance_github_check_annotations(stale_request)
                .await
        });
        wait_for_direct_blocker(database.pool(), successor.blocking_pid).await?;
        successor_transaction.commit().await?;
        assert!(matches!(
            stale.await?,
            Err(GithubCheckStoreError::ClaimRejected)
        ));
        assert_fresh_successor_batch(&database, &publish, successor).await?;

        let successor_claim = GithubCheckProjectionClaimFence::from_durable_parts(
            publish.claim().subject_id(),
            successor.owner,
            successor.fence,
        )?;
        let advanced = database
            .store()
            .advance_github_check_annotations(AdvanceGithubCheckAnnotations::new(
                successor_claim,
                PRESENTATION_DIGEST,
                0,
                ANNOTATION_COUNT,
                successor.claimed_at,
            )?)
            .await?;
        assert_eq!(advanced.next(), ANNOTATION_COUNT);
        assert_eq!(advanced.uncertain_batch_size(), None);
        Ok(())
    })
    .await
}

#[derive(Clone, Copy, Debug)]
struct FreshAnnotationSuccessor {
    owner: GithubCheckProjectionWorkerId,
    fence: u64,
    claimed_at: UnixMillis,
    blocking_pid: i32,
}

async fn claimed_fenced_annotation_batch(
    database: &TestDatabase,
    tenant_id: &str,
    connection_seed: u128,
) -> TestResult<ClaimedGithubCheckProjection> {
    let publish = claimed_terminal_publish(database, tenant_id, connection_seed).await?;
    seed_annotation_progress(database, &publish).await?;
    let started_at = database_now(database.pool()).await?;
    database
        .store()
        .begin_github_check_annotation_batch(BeginGithubCheckAnnotationBatch::new(
            publish.claim(),
            PRESENTATION_DIGEST,
            0,
            BATCH_SIZE,
            started_at,
        )?)
        .await?;
    Ok(publish)
}

async fn stage_fresh_annotation_successor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    publish: &ClaimedGithubCheckProjection,
    owner_seed: u128,
) -> TestResult<FreshAnnotationSuccessor> {
    // Commit the successor claim and its same-shaped fresh marker together so
    // a stale joined UPDATE must recheck both durable rows after its lock wait.
    let owner = GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(owner_seed))?;
    let fence = publish
        .claim()
        .fence()
        .checked_add(1)
        .ok_or("test claim fence overflow")?;
    let claimed_at = publish.expires_at();
    let expires_at = checked_add_millis(claimed_at, 30_000)?;
    let blocking_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **transaction)
        .await?;
    let outbox_updated = sqlx::query(
        r"
        UPDATE github_check_projection_outbox
        SET attempt_count = attempt_count + 1,
            claim_fence = $2,
            claim_owner_id = $3,
            claimed_at_ms = $4,
            claim_expires_at_ms = $5,
            state_updated_at_ms = $4
        WHERE subject_id = $1
          AND state = 'claimed'
          AND claim_owner_id = $6
          AND claim_fence = $7
          AND claim_action = 'publish'
        ",
    )
    .bind(publish.claim().subject_id().as_uuid())
    .bind(i64::try_from(fence)?)
    .bind(owner.as_uuid())
    .bind(claimed_at.get())
    .bind(expires_at.get())
    .bind(publish.claim().owner().as_uuid())
    .bind(i64::try_from(publish.claim().fence())?)
    .execute(&mut **transaction)
    .await?;
    assert_eq!(outbox_updated.rows_affected(), 1);

    let marker_updated = sqlx::query(
        r"
        UPDATE github_check_annotation_progress
        SET uncertain_batch_size = $4,
            updated_at_ms = $5
        WHERE subject_id = $1
          AND presentation_digest = $2
          AND annotation_next = $3
          AND uncertain_batch_size = $4
          AND updated_at_ms < $5
        ",
    )
    .bind(publish.claim().subject_id().as_uuid())
    .bind(PRESENTATION_DIGEST.as_bytes().as_slice())
    .bind(0_i32)
    .bind(i16::from(BATCH_SIZE))
    .bind(claimed_at.get())
    .execute(&mut **transaction)
    .await?;
    assert_eq!(marker_updated.rows_affected(), 1);

    Ok(FreshAnnotationSuccessor {
        owner,
        fence,
        claimed_at,
        blocking_pid,
    })
}

async fn assert_fresh_successor_batch(
    database: &TestDatabase,
    publish: &ClaimedGithubCheckProjection,
    successor: FreshAnnotationSuccessor,
) -> TestResult {
    let durable: (String, Uuid, i64, String, i32, Option<i16>, i64) = sqlx::query_as(
        r"
        SELECT outbox.state, outbox.claim_owner_id, outbox.claim_fence,
               outbox.claim_action, progress.annotation_next,
               progress.uncertain_batch_size, progress.updated_at_ms
        FROM github_check_projection_outbox AS outbox
        JOIN github_check_annotation_progress AS progress
          ON progress.subject_id = outbox.subject_id
        WHERE outbox.subject_id = $1
        ",
    )
    .bind(publish.claim().subject_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        durable,
        (
            "claimed".to_owned(),
            successor.owner.as_uuid(),
            i64::try_from(successor.fence)?,
            "publish".to_owned(),
            0,
            Some(i16::from(BATCH_SIZE)),
            successor.claimed_at.get(),
        )
    );
    Ok(())
}

async fn claimed_terminal_publish(
    database: &TestDatabase,
    tenant_id: &str,
    connection_seed: u128,
) -> TestResult<ClaimedGithubCheckProjection> {
    let fixture = bootstrap(
        database,
        tenant_id,
        connection_seed,
        ProviderRepositoryVisibility::Public,
        100,
    )
    .await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(acceptance(
            &fixture,
            "annotation-delivery",
            OWNER_ID,
            OWNER_ID,
            HEAD_SHA,
            fixture.activated_at.get(),
            0xa7,
        ))
        .await?;
    let delivery = claim_delivery(
        database,
        accepted.delivery_id(),
        connection_seed + 1,
        60_000,
    )
    .await?;
    database
        .store()
        .reject_provider_delivery(RejectProviderDelivery::new(
            delivery.claim(),
            ProviderDeliveryFailureKind::new("github.annotation.test")?,
            delivery.claimed_at(),
        )?)
        .await?;

    let ensure_suite = claim_check_projection(database, fixture.connection).await?;
    assert_eq!(
        ensure_suite.action(),
        GithubCheckProjectionAction::EnsureSuite
    );
    let suite_id = GithubCheckSuiteId::new(70_000 + u64::from(BATCH_SIZE))?;
    database
        .store()
        .bind_github_check_suite(BindGithubCheckSuite::new(
            ensure_suite.claim(),
            suite_id,
            ensure_suite.claimed_at(),
        )?)
        .await?;

    let create = claim_check_projection(database, fixture.connection).await?;
    assert_eq!(
        create.action(),
        GithubCheckProjectionAction::PrepareRunCreate
    );
    let cutoff = database
        .store()
        .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
            &create,
            create.claimed_at(),
            checked_add_millis(create.expires_at(), 1)?,
        )?)
        .await?;
    database
        .store()
        .bind_github_check_run(BindGithubCheckRun::new(
            GithubCheckRunBindingFence::Create(cutoff),
            suite_id,
            GithubCheckRunId::new(80_000 + u64::from(BATCH_SIZE))?,
            create.claimed_at(),
        )?)
        .await?;

    let publish = claim_check_projection(database, fixture.connection).await?;
    assert_eq!(publish.action(), GithubCheckProjectionAction::Publish);
    Ok(publish)
}

async fn seed_annotation_progress(
    database: &TestDatabase,
    publish: &ClaimedGithubCheckProjection,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO github_check_annotation_progress (
            subject_id, presentation_digest, annotation_total,
            annotation_next, uncertain_batch_size, updated_at_ms
        ) VALUES ($1, $2, $3, 0, NULL, $4)
        ",
    )
    .bind(publish.claim().subject_id().as_uuid())
    .bind(PRESENTATION_DIGEST.as_bytes().as_slice())
    .bind(i32::from(ANNOTATION_COUNT))
    .bind(publish.claimed_at().get())
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn assert_markerless_requests_are_rejected(
    database: &TestDatabase,
    publish: &ClaimedGithubCheckProjection,
    begin: BeginGithubCheckAnnotationBatch,
) -> TestResult {
    let observed_at = database_now(database.pool()).await?;
    let retry_at = checked_add_millis(observed_at, 1)?;
    assert!(matches!(
        database
            .store()
            .retry_uncertain_github_check_annotations(RetryUncertainGithubCheckAnnotations::new(
                publish.claim(),
                PRESENTATION_DIGEST,
                0,
                BATCH_SIZE,
                observed_at,
                retry_at,
            )?)
            .await,
        Err(GithubCheckStoreError::ProjectionMismatch)
    ));
    assert!(matches!(
        database
            .store()
            .release_unissued_github_check_annotation_batch(
                ReleaseUnissuedGithubCheckAnnotationBatch::new(begin, observed_at, retry_at)?,
            )
            .await,
        Err(GithubCheckStoreError::ProjectionMismatch)
    ));
    Ok(())
}

async fn wait_for_direct_blocker(pool: &sqlx::PgPool, blocking_pid: i32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity AS activity
                    WHERE activity.datname = current_database()
                      AND $1 = ANY(pg_blocking_pids(activity.pid))
                )
                ",
            )
            .bind(blocking_pid)
            .fetch_one(pool)
            .await?;
            if waiting {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "annotation mutation did not reach the expected outbox lock")??;
    Ok(())
}
