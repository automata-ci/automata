mod support;

use std::{io, time::Duration};

use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{
    AttemptId, AttemptNumber, JobLifecycle, LeaseGuard, LeaseId, Sha256Digest, UnixMillis,
};
use automata_ci_postgres::test_support::TestClock;
use automata_ci_results_github::{
    CacheAccessScope, CacheAuthority, CacheBlock, CacheEntryId, CacheFinalizationPreparation,
    CacheKey, CachePermission, CacheRepository as _, CacheRepositoryErrorKind, CacheVersion,
    CommitCacheBlocks, CompleteCacheBlock, CompleteCacheFinalization, CreateCacheEntry,
    ExecutionAuthority, LookupCacheEntry, PostgresCacheRepository, PrepareCacheFinalization,
    ReserveCacheBlock, ResolveCacheDownload,
};
use automata_ci_store::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt, RunnerSessionFence,
    StableRunnerSlot, TransitionAttempt,
};
use sqlx::PgPool;
use support::postgres::{TestDatabase, TestResult, run_with_database, seed_control_plane};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One transaction narrative keeps replay, fencing, and cross-run order explicit.
async fn cache_transactions_are_immutable_fenced_and_cross_run_readable() -> TestResult {
    run_with_database(|database| async move {
        let (repository, execution, session_fence, lease_guard) = active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        let entry_id = CacheEntryId::new(Uuid::new_v4())?;
        let creation_database_before = database_now_seconds(&database).await?;
        let forged_fast_creation = creation_database_before + 30;
        let mut creation = create_request(execution, cache.clone(), entry_id, "cargo-linux");
        creation.observed_at_seconds = forged_fast_creation;
        let created = repository
            .create(creation)
            .await?;
        let creation_database_after = database_now_seconds(&database).await?;
        assert_eq!(created.entry_id, entry_id);
        let replay = repository
            .create(create_request(
                execution,
                cache.clone(),
                CacheEntryId::new(Uuid::new_v4())?,
                "cargo-linux",
            ))
            .await?;
        assert_eq!(replay, created);
        let (created_at, initially_accessed_at): (i64, i64) = sqlx::query_as(
            r"
            SELECT created_at_seconds, last_accessed_at_seconds
            FROM github_actions_cache_entries
            WHERE id = $1
            ",
        )
        .bind(entry_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_database_timestamp_window(
            "cache creation",
            created_at,
            creation_database_before,
            creation_database_after,
            forged_fast_creation,
        )?;
        assert_database_timestamp_window(
            "initial cache access",
            initially_accessed_at,
            creation_database_before,
            creation_database_after,
            forged_fast_creation,
        )?;

        let block = CacheBlock::new(
            "QUFBQUFBQUFBQUFBQUFBQQ==".to_owned(),
            descriptor("block-a", 3, 7),
        );
        let staging_database_before = database_now_seconds(&database).await?;
        let forged_fast_staging = staging_database_before + 30;
        assert!(
            repository
                .reserve_block(ReserveCacheBlock {
                    entry_id,
                    block: block.clone(),
                    observed_at_seconds: forged_fast_staging,
                    maximum_blocks: 10,
                    maximum_entry_bytes: 1_024,
                })
                .await?
        );
        let staging_database_after = database_now_seconds(&database).await?;
        let staged_at: i64 = sqlx::query_scalar(
            "SELECT staged_at_seconds FROM github_actions_cache_blocks WHERE entry_id = $1 AND block_id = $2",
        )
        .bind(entry_id.as_uuid())
        .bind(block.block_id())
        .fetch_one(database.pool())
        .await?;
        assert_database_timestamp_window(
            "cache block staging",
            staged_at,
            staging_database_before,
            staging_database_after,
            forged_fast_staging,
        )?;

        let readiness_database_before = database_now_seconds(&database).await?;
        let forged_fast_readiness = readiness_database_before + 30;
        repository
            .complete_block(CompleteCacheBlock {
                entry_id,
                block: block.clone(),
                observed_at_seconds: forged_fast_readiness,
            })
            .await?;
        let readiness_database_after = database_now_seconds(&database).await?;
        let ready_at: i64 = sqlx::query_scalar(
            "SELECT ready_at_seconds FROM github_actions_cache_blocks WHERE entry_id = $1 AND block_id = $2",
        )
        .bind(entry_id.as_uuid())
        .bind(block.block_id())
        .fetch_one(database.pool())
        .await?;
        assert_database_timestamp_window(
            "cache block readiness",
            ready_at,
            readiness_database_before,
            readiness_database_after,
            forged_fast_readiness,
        )?;
        assert!(ready_at >= staged_at);
        assert!(
            !repository
                .reserve_block(ReserveCacheBlock {
                    entry_id,
                    block: block.clone(),
                    observed_at_seconds: 1_003,
                    maximum_blocks: 10,
                    maximum_entry_bytes: 1_024,
                })
                .await?
        );
        let commit_database_before = database_now_seconds(&database).await?;
        let forged_fast_commit = commit_database_before + 30;
        repository
            .commit_blocks(CommitCacheBlocks {
                entry_id,
                block_ids: vec![block.block_id().to_owned()],
                list_digest: Sha256Digest::from_bytes([0x33; 32]),
                observed_at_seconds: forged_fast_commit,
                maximum_blocks: 10,
                maximum_entry_bytes: 1_024,
            })
            .await?;
        let commit_database_after = database_now_seconds(&database).await?;
        let committed_at: i64 = sqlx::query_scalar(
            "SELECT committed_at_seconds FROM github_actions_cache_block_commits WHERE entry_id = $1",
        )
        .bind(entry_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_database_timestamp_window(
            "cache block-list commit",
            committed_at,
            commit_database_before,
            commit_database_after,
            forged_fast_commit,
        )?;
        let prepared = repository
            .prepare_finalization(PrepareCacheFinalization {
                execution,
                cache: cache.clone(),
                key: CacheKey::new("cargo-linux")?,
                version: CacheVersion::new("version-1")?,
                claimed_size: 3,
            })
            .await?;
        assert!(matches!(prepared, CacheFinalizationPreparation::Verify(_)));
        let digest = Sha256Digest::from_bytes([0x44; 32]);
        let finalized = repository
            .complete_finalization(CompleteCacheFinalization {
                execution,
                cache: cache.clone(),
                entry_id,
                key: CacheKey::new("cargo-linux")?,
                version: CacheVersion::new("version-1")?,
                digest,
                size: 3,
                observed_at_seconds: database_now_seconds(&database).await?,
                repository_quota_bytes: 10 * 1024,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await?;
        assert_eq!(finalized.digest, digest);
        assert_eq!(finalized.blocks, vec![block]);
        assert!(finalized.protocol_entry_id.get() > 0);

        let replay = repository
            .prepare_finalization(PrepareCacheFinalization {
                execution,
                cache: cache.clone(),
                key: CacheKey::new("cargo-linux")?,
                version: CacheVersion::new("version-1")?,
                claimed_size: 3,
            })
            .await?;
        let CacheFinalizationPreparation::Finalized(replay) = replay else {
            panic!("finalization replay must be durable");
        };
        assert_eq!(replay.protocol_entry_id, finalized.protocol_entry_id);

        let abandoned_entry = CacheEntryId::new(Uuid::new_v4())?;
        repository
            .create(create_request(
                execution,
                cache.clone(),
                abandoned_entry,
                "abandoned-pending",
            ))
            .await?;

        for lifecycle in [
            JobLifecycle::Preparing,
            JobLifecycle::Running,
            JobLifecycle::Finalizing,
            JobLifecycle::Succeeded,
        ] {
            database
                .store()
                .transition(TransitionAttempt::new(
                    execution.attempt_id(),
                    session_fence,
                    lease_guard,
                    lifecycle,
                    database_now_millis(&database).await?,
                ))
                .await?;
        }
        let reader = second_run_attempt(&database, execution, session_fence).await?;
        let replacement_entry = CacheEntryId::new(Uuid::new_v4())?;
        let replacement = repository
            .create(create_request(
                reader,
                cache.clone(),
                replacement_entry,
                "abandoned-pending",
            ))
            .await?;
        assert_eq!(replacement.entry_id, replacement_entry);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::BIGINT FROM github_actions_cache_entries WHERE id = $1",
            )
            .bind(abandoned_entry.as_uuid())
            .fetch_one(database.pool())
            .await?,
            0,
        );
        assert_ne!(reader.run_id(), execution.run_id());
        let restored = repository
            .lookup(LookupCacheEntry {
                execution: reader,
                cache: cache.clone(),
                key: CacheKey::new("missing-primary")?,
                restore_keys: vec![CacheKey::new("cargo-")?],
                version: CacheVersion::new("version-1")?,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await?
            .expect("restore-key match");
        assert_eq!(restored.entry_id, entry_id);
        let resolved = repository
            .resolve_download(ResolveCacheDownload {
                entry_id,
                digest,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await?;
        assert_eq!(resolved.entry_id, entry_id);

        let (least_recent_entry, least_recent_digest) = finalize_small_entry(
            &repository,
            reader,
            &cache,
            "cargo-linux-old",
            "QkJCQkJCQkJCQkJCQkJCQg==",
            "block-b",
            0x55,
            1_010,
            6,
        )
        .await?;
        sqlx::query(
            r"
            WITH database_clock AS (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            UPDATE github_actions_cache_entries AS entry
            SET created_at_seconds = CASE
                    WHEN entry.id = $1 THEN database_clock.now_seconds - 20
                    ELSE database_clock.now_seconds - 30
                END,
                finalized_at_seconds = CASE
                    WHEN entry.id = $1 THEN database_clock.now_seconds - 20
                    ELSE database_clock.now_seconds - 30
                END,
                last_accessed_at_seconds = CASE
                    WHEN entry.id = $1 THEN database_clock.now_seconds - 20
                    ELSE database_clock.now_seconds - 30
                END
            FROM database_clock
            WHERE entry.id = ANY($2)
            ",
        )
        .bind(entry_id.as_uuid())
        .bind(vec![entry_id.as_uuid(), least_recent_entry.as_uuid()])
        .execute(database.pool())
        .await?;
        let recently_used = repository
            .lookup(LookupCacheEntry {
                execution: reader,
                cache: cache.clone(),
                key: CacheKey::new("cargo-linux")?,
                restore_keys: Vec::new(),
                version: CacheVersion::new("version-1")?,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await?
            .expect("refresh most recently used entry");
        assert_eq!(recently_used.entry_id, entry_id);
        let (newest_entry, newest_digest) = finalize_small_entry(
            &repository,
            reader,
            &cache,
            "cargo-linux-new",
            "Q0NDQ0NDQ0NDQ0NDQ0NDQw==",
            "block-c",
            0x66,
            1_030,
            6,
        )
        .await?;
        assert_eq!(
            repository
                .resolve_download(ResolveCacheDownload {
                    entry_id,
                    digest,
                    observed_at_seconds: database_now_seconds(&database).await?,
                    inactivity_seconds: 7 * 24 * 60 * 60,
                })
                .await?
                .entry_id,
            entry_id
        );
        let evicted = repository
            .resolve_download(ResolveCacheDownload {
                entry_id: least_recent_entry,
                digest: least_recent_digest,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await
            .expect_err("quota evicts the least recently accessed entry");
        assert_eq!(evicted.kind(), CacheRepositoryErrorKind::NotFound);
        assert_eq!(
            repository
                .resolve_download(ResolveCacheDownload {
                    entry_id: newest_entry,
                    digest: newest_digest,
                    observed_at_seconds: database_now_seconds(&database).await?,
                    inactivity_seconds: 7 * 24 * 60 * 60,
                })
                .await?
                .entry_id,
            newest_entry
        );

        let wrong_repository = repository
            .lookup(LookupCacheEntry {
                execution: reader,
                cache: cache_authority("sibling/repository", "refs/heads/main"),
                key: CacheKey::new("cargo-linux")?,
                restore_keys: Vec::new(),
                version: CacheVersion::new("version-1")?,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await
            .expect_err("authenticated repository claim cannot cross repositories");
        assert_eq!(
            wrong_repository.kind(),
            CacheRepositoryErrorKind::Unauthorized
        );

        let stale = repository
            .lookup(LookupCacheEntry {
                execution: ExecutionAuthority::new(
                    reader.run_id(),
                    reader.job_id(),
                    reader.attempt_id(),
                    automata_ci_core::FencingToken::new(reader.fencing_token().get() + 1)?,
                ),
                cache,
                key: CacheKey::new("cargo-linux")?,
                restore_keys: Vec::new(),
                version: CacheVersion::new("version-1")?,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 7 * 24 * 60 * 60,
            })
            .await
            .expect_err("stale caller fence");
        assert_eq!(stale.kind(), CacheRepositoryErrorKind::Unauthorized);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One clock narrative proves fast, slow, and extreme caller evidence separately.
async fn cache_retention_and_touch_use_database_time_under_caller_skew() -> TestResult {
    run_with_database(|database| async move {
        const INACTIVITY_SECONDS: u64 = 40;
        let (repository, execution, _session_fence, _lease_guard) =
            active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        let (live_id, _live_digest) = finalize_small_entry(
            &repository,
            execution,
            &cache,
            "clock-live",
            "QUFBQUFBQUFBQUFBQUFBQQ==",
            "clock-live",
            0xa1,
            4_000,
            100,
        )
        .await?;
        let (stale_id, _stale_digest) = finalize_small_entry(
            &repository,
            execution,
            &cache,
            "clock-stale",
            "QkJCQkJCQkJCQkJCQkJCQg==",
            "clock-stale",
            0xa2,
            4_010,
            100,
        )
        .await?;
        age_finalized_entries(database.pool(), &[(live_id, 20), (stale_id, 50)]).await?;

        let (fast_incoming, fast_digest) = prepare_small_entry(
            &repository,
            execution,
            &cache,
            "clock-fast-incoming",
            "Q0NDQ0NDQ0NDQ0NDQ0NDQw==",
            "clock-fast-incoming",
            0xa3,
            4_020,
        )
        .await?;
        let database_now = database_now_seconds(&database).await?;
        repository
            .complete_finalization(CompleteCacheFinalization {
                execution,
                cache: cache.clone(),
                entry_id: fast_incoming,
                key: CacheKey::new("clock-fast-incoming")?,
                version: CacheVersion::new("version-1")?,
                digest: fast_digest,
                size: 3,
                observed_at_seconds: database_now + 30,
                repository_quota_bytes: 100,
                inactivity_seconds: INACTIVITY_SECONDS,
            })
            .await?;
        assert!(cache_entry_exists(database.pool(), live_id).await?);
        assert!(!cache_entry_exists(database.pool(), stale_id).await?);

        let (slow_stale_id, _slow_stale_digest) = finalize_small_entry(
            &repository,
            execution,
            &cache,
            "clock-slow-stale",
            "RERERERERERERERERERERA==",
            "clock-slow-stale",
            0xa4,
            4_030,
            100,
        )
        .await?;
        age_finalized_entries(database.pool(), &[(slow_stale_id, 50)]).await?;
        let (slow_incoming, slow_digest) = prepare_small_entry(
            &repository,
            execution,
            &cache,
            "clock-slow-incoming",
            "RUVFRUVFRUVFRUVFRUVFRQ==",
            "clock-slow-incoming",
            0xa5,
            4_040,
        )
        .await?;
        let database_now = database_now_seconds(&database).await?;
        repository
            .complete_finalization(CompleteCacheFinalization {
                execution,
                cache: cache.clone(),
                entry_id: slow_incoming,
                key: CacheKey::new("clock-slow-incoming")?,
                version: CacheVersion::new("version-1")?,
                digest: slow_digest,
                size: 3,
                observed_at_seconds: database_now.saturating_sub(30),
                repository_quota_bytes: 100,
                inactivity_seconds: INACTIVITY_SECONDS,
            })
            .await?;
        assert!(!cache_entry_exists(database.pool(), slow_stale_id).await?);

        let last_accessed_before: i64 = sqlx::query_scalar(
            "SELECT last_accessed_at_seconds FROM github_actions_cache_entries WHERE id = $1",
        )
        .bind(live_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let database_now = database_now_seconds(&database).await?;
        for skewed_observation in [
            database_now.saturating_sub(3_600),
            database_now.saturating_add(3_600),
        ] {
            let error = repository
                .lookup(LookupCacheEntry {
                    execution,
                    cache: cache.clone(),
                    key: CacheKey::new("clock-live")?,
                    restore_keys: Vec::new(),
                    version: CacheVersion::new("version-1")?,
                    observed_at_seconds: skewed_observation,
                    inactivity_seconds: 24 * 60 * 60,
                })
                .await
                .expect_err("extreme caller skew is bounded evidence, never cache authority");
            assert_eq!(error.kind(), CacheRepositoryErrorKind::Unauthorized);
        }
        let last_accessed_after_rejection: i64 = sqlx::query_scalar(
            "SELECT last_accessed_at_seconds FROM github_actions_cache_entries WHERE id = $1",
        )
        .bind(live_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(last_accessed_after_rejection, last_accessed_before);

        let touch_started_at = database_now_seconds(&database).await?;
        repository
            .lookup(LookupCacheEntry {
                execution,
                cache,
                key: CacheKey::new("clock-live")?,
                restore_keys: Vec::new(),
                version: CacheVersion::new("version-1")?,
                observed_at_seconds: touch_started_at + 30,
                inactivity_seconds: 24 * 60 * 60,
            })
            .await?
            .expect("bounded fast evidence must not replace database touch time");
        let touched_at: i64 = sqlx::query_scalar(
            "SELECT last_accessed_at_seconds FROM github_actions_cache_entries WHERE id = $1",
        )
        .bind(live_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(u64::try_from(touched_at)? >= touch_started_at);
        assert!(u64::try_from(touched_at)? < touch_started_at + 30);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One deterministic gate proves both the exact boundary and post-wait resample.
async fn cache_touch_rechecks_exact_expiry_after_the_entry_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let (repository, execution, _session_fence, _lease_guard) =
            active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        let (entry_id, digest) = finalize_small_entry(
            &repository,
            execution,
            &cache,
            "clock-lock-wait",
            "QUFBQUFBQUFBQUFBQUFBQQ==",
            "clock-lock-wait",
            0xb1,
            5_000,
            100,
        )
        .await?;

        age_finalized_entries(database.pool(), &[(entry_id, 5)]).await?;
        let exact_expiry = repository
            .lookup(LookupCacheEntry {
                execution,
                cache: cache.clone(),
                key: CacheKey::new("clock-lock-wait")?,
                restore_keys: Vec::new(),
                version: CacheVersion::new("version-1")?,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 5,
            })
            .await?;
        assert!(
            exact_expiry.is_none(),
            "the inactivity boundary is exclusive"
        );
        let resolve_error = repository
            .resolve_download(ResolveCacheDownload {
                entry_id,
                digest,
                observed_at_seconds: database_now_seconds(&database).await?,
                inactivity_seconds: 5,
            })
            .await
            .expect_err("exact-expiry downloads must fail closed");
        assert_eq!(resolve_error.kind(), CacheRepositoryErrorKind::NotFound);

        sqlx::query(
            r"
            UPDATE github_actions_cache_entries
            SET finalized_at_seconds = floor(extract(epoch FROM clock_timestamp()))::BIGINT,
                last_accessed_at_seconds = floor(extract(epoch FROM clock_timestamp()))::BIGINT
            WHERE id = $1
            ",
        )
        .bind(entry_id.as_uuid())
        .execute(database.pool())
        .await?;
        let last_accessed_before: i64 = sqlx::query_scalar(
            "SELECT last_accessed_at_seconds FROM github_actions_cache_entries WHERE id = $1",
        )
        .bind(entry_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let mut gate = database.pool().begin().await?;
        let gate_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("SELECT id FROM github_actions_cache_entries WHERE id = $1 FOR UPDATE")
            .bind(entry_id.as_uuid())
            .fetch_one(&mut *gate)
            .await?;
        let lookup_repository = repository.clone();
        let lookup_observed_at = database_now_seconds(&database).await?;
        let lookup = tokio::spawn(async move {
            lookup_repository
                .lookup(LookupCacheEntry {
                    execution,
                    cache,
                    key: CacheKey::new("clock-lock-wait").expect("fixed cache key"),
                    restore_keys: Vec::new(),
                    version: CacheVersion::new("version-1").expect("fixed cache version"),
                    observed_at_seconds: lookup_observed_at,
                    // Give the hosted runner enough time to reach the
                    // deliberate row lock before testing expiry during the
                    // wait itself.
                    inactivity_seconds: 10,
                })
                .await
        });
        wait_for_direct_blockers(database.pool(), gate_pid, 1).await?;
        clock.advance(10_000).await?;
        gate.commit().await?;
        assert!(lookup.await??.is_none());
        let last_accessed_after: i64 = sqlx::query_scalar(
            "SELECT last_accessed_at_seconds FROM github_actions_cache_entries WHERE id = $1",
        )
        .bind(entry_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(last_accessed_after, last_accessed_before);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One narrative proves the exact cap, one-over refusal, and bounded eviction.
async fn cache_entry_cardinality_is_bounded_even_for_zero_byte_entries() -> TestResult {
    const ENTRY_LIMIT: i64 = 4_096;

    run_with_database(|database| async move {
        let (repository, execution, _session_fence, _lease_guard) =
            active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        // Keep the target after the injected `1000...` cohort when database-second
        // timestamps tie, so the UUID tiebreak deterministically evicts row two.
        let target = CacheEntryId::new(Uuid::parse_str("f0000000-0000-4000-8000-000000000000")?)?;
        repository
            .create(create_request(execution, cache.clone(), target, "target"))
            .await?;
        repository
            .commit_blocks(CommitCacheBlocks {
                entry_id: target,
                block_ids: Vec::new(),
                list_digest: Sha256Digest::from_bytes([0x71; 32]),
                observed_at_seconds: 1_001,
                maximum_blocks: 10,
                maximum_entry_bytes: 1_024,
            })
            .await?;
        assert!(matches!(
            repository
                .prepare_finalization(PrepareCacheFinalization {
                    execution,
                    cache: cache.clone(),
                    key: CacheKey::new("target")?,
                    version: CacheVersion::new("version-1")?,
                    claimed_size: 0,
                })
                .await?,
            CacheFinalizationPreparation::Verify(_)
        ));

        sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            ), inserted AS (
                INSERT INTO github_actions_cache_entries (
                    id, tenant_id, repository_id, run_id, job_id, attempt_id,
                    fencing_token, cache_ref, cache_key, cache_version, state,
                    content_digest, content_size_bytes, created_at_seconds,
                    finalized_at_seconds, last_accessed_at_seconds
                )
                SELECT
                    (
                        '10000000-0000-4000-8000-'
                        || lpad(to_hex(sequence), 12, '0')
                    )::UUID,
                    target.tenant_id, target.repository_id, target.run_id,
                    target.job_id, target.attempt_id, target.fencing_token,
                    target.cache_ref, 'cardinality-' || sequence::TEXT,
                    target.cache_version, 'finalized', decode(repeat('72', 32), 'hex'),
                    0, database_clock.now_seconds, database_clock.now_seconds,
                    database_clock.now_seconds
                FROM github_actions_cache_entries AS target
                CROSS JOIN generate_series(1, $2::BIGINT) AS sequence
                CROSS JOIN database_clock
                WHERE target.id = $1
                RETURNING id
            )
            INSERT INTO github_actions_cache_block_commits (
                entry_id, list_digest, block_ids, size_bytes, committed_at_seconds
            )
            SELECT id, decode(repeat('73', 32), 'hex'), ARRAY[]::TEXT[], 0,
                   database_clock.now_seconds
            FROM inserted
            CROSS JOIN database_clock
            ",
        )
        .bind(target.as_uuid())
        .bind(ENTRY_LIMIT)
        .execute(database.pool())
        .await?;

        let finalization = CompleteCacheFinalization {
            execution,
            cache: cache.clone(),
            entry_id: target,
            key: CacheKey::new("target")?,
            version: CacheVersion::new("version-1")?,
            digest: Sha256Digest::from_bytes([0x74; 32]),
            size: 0,
            observed_at_seconds: database_now_seconds(&database).await?,
            repository_quota_bytes: 1,
            inactivity_seconds: 100,
        };
        let over_limit = repository
            .complete_finalization(finalization.clone())
            .await
            .expect_err("one-over repository entry census must fail closed");
        assert_eq!(
            over_limit.kind(),
            CacheRepositoryErrorKind::ResourceExhausted
        );

        let first_injected = Uuid::parse_str("10000000-0000-4000-8000-000000000001")?;
        sqlx::query("DELETE FROM github_actions_cache_entries WHERE id = $1")
            .bind(first_injected)
            .execute(database.pool())
            .await?;
        repository.complete_finalization(finalization).await?;

        let new_entry = CacheEntryId::new(Uuid::new_v4())?;
        repository
            .create(create_request(
                execution,
                cache,
                new_entry,
                "after-cardinality-eviction",
            ))
            .await?;
        let second_injected = Uuid::parse_str("10000000-0000-4000-8000-000000000002")?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::BIGINT FROM github_actions_cache_entries WHERE id = $1",
            )
            .bind(second_injected)
            .fetch_one(database.pool())
            .await?,
            0,
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT count(*)::BIGINT
                FROM github_actions_cache_entries AS entry
                JOIN workflow_runs AS run ON run.repository_id = entry.repository_id
                WHERE run.id = $1
                ",
            )
            .bind(execution.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
            ENTRY_LIMIT,
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_creates_respect_the_exact_cap_with_repeatable_read_sessions() -> TestResult {
    const EXISTING_ENTRIES: i64 = 4_095;

    run_with_database(|database| async move {
        let (repository, execution, _session_fence, _lease_guard) =
            active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        let seed = CacheEntryId::new(Uuid::new_v4())?;
        repository
            .create(create_request(execution, cache.clone(), seed, "cap-seed"))
            .await?;
        insert_zero_byte_finalized_entries(database.pool(), seed, EXISTING_ENTRIES - 1).await?;
        set_repeatable_read_session_default(database.pool()).await?;

        let repository_id = execution_repository_id(database.pool(), execution).await?;
        let mut gate = database.pool().begin().await?;
        let gate_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("SELECT id FROM repositories WHERE id = $1 FOR UPDATE")
            .bind(repository_id)
            .fetch_one(&mut *gate)
            .await?;
        let first_id = CacheEntryId::new(Uuid::new_v4())?;
        let first_repository = repository.clone();
        let first_cache = cache.clone();
        let first = tokio::spawn(async move {
            first_repository
                .create(create_request(
                    execution,
                    first_cache,
                    first_id,
                    "cap-concurrent-a",
                ))
                .await
        });
        let second_id = CacheEntryId::new(Uuid::new_v4())?;
        let second_repository = repository.clone();
        let second = tokio::spawn(async move {
            second_repository
                .create(create_request(
                    execution,
                    cache,
                    second_id,
                    "cap-concurrent-b",
                ))
                .await
        });

        wait_for_direct_blockers(database.pool(), gate_pid, 2).await?;
        gate.commit().await?;
        assert_eq!(first.await??.entry_id, first_id);
        assert_eq!(second.await??.entry_id, second_id);

        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::BIGINT FROM github_actions_cache_entries WHERE repository_id = $1",
            )
            .bind(repository_id)
            .fetch_one(database.pool())
            .await?,
            EXISTING_ENTRIES + 1,
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::BIGINT FROM github_actions_cache_entries WHERE id = ANY($1)",
            )
            .bind(vec![first_id.as_uuid(), second_id.as_uuid()])
            .fetch_one(database.pool())
            .await?,
            2,
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_finalizations_include_the_serialized_predecessor_in_quota() -> TestResult {
    run_with_database(|database| async move {
        let (repository, execution, _session_fence, _lease_guard) =
            active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        let (first_id, first_digest) = prepare_small_entry(
            &repository,
            execution,
            &cache,
            "quota-concurrent-a",
            "QUFBQUFBQUFBQUFBQUFBQQ==",
            "quota-concurrent-a",
            0x81,
            2_000,
        )
        .await?;
        let (second_id, second_digest) = prepare_small_entry(
            &repository,
            execution,
            &cache,
            "quota-concurrent-b",
            "QkJCQkJCQkJCQkJCQkJCQg==",
            "quota-concurrent-b",
            0x82,
            2_010,
        )
        .await?;
        set_repeatable_read_session_default(database.pool()).await?;

        let repository_id = execution_repository_id(database.pool(), execution).await?;
        let mut gate = database.pool().begin().await?;
        let gate_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("SELECT id FROM repositories WHERE id = $1 FOR UPDATE")
            .bind(repository_id)
            .fetch_one(&mut *gate)
            .await?;
        let finalization_observed_at = database_now_seconds(&database).await?;

        let first_repository = repository.clone();
        let first_cache = cache.clone();
        let first = tokio::spawn(async move {
            first_repository
                .complete_finalization(complete_small_entry_request(
                    execution,
                    first_cache,
                    first_id,
                    "quota-concurrent-a",
                    first_digest,
                    finalization_observed_at,
                    3,
                ))
                .await
        });
        let second_repository = repository.clone();
        let second = tokio::spawn(async move {
            second_repository
                .complete_finalization(complete_small_entry_request(
                    execution,
                    cache,
                    second_id,
                    "quota-concurrent-b",
                    second_digest,
                    finalization_observed_at,
                    3,
                ))
                .await
        });

        wait_for_direct_blockers(database.pool(), gate_pid, 2).await?;
        gate.commit().await?;
        first.await??;
        second.await??;

        let (count, bytes) = sqlx::query_as::<_, (i64, i64)>(
            r"
            SELECT count(*)::BIGINT, coalesce(sum(content_size_bytes), 0)::BIGINT
            FROM github_actions_cache_entries
            WHERE repository_id = $1 AND state = 'finalized'
            ",
        )
        .bind(repository_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!((count, bytes), (1, 3));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // The trigger makes the row-lock interleaving deterministic.
async fn a_touch_commits_before_eviction_selects_the_current_lru_entry() -> TestResult {
    run_with_database(|database| async move {
        let (repository, execution, _session_fence, _lease_guard) =
            active_attempt(&database).await?;
        let cache = cache_authority("automata/results-test", "refs/heads/main");
        let (oldest_id, _oldest_digest) = finalize_small_entry(
            &repository,
            execution,
            &cache,
            "touch-oldest",
            "QUFBQUFBQUFBQUFBQUFBQQ==",
            "touch-oldest",
            0x91,
            3_000,
            100,
        )
        .await?;
        let (next_id, _next_digest) = finalize_small_entry(
            &repository,
            execution,
            &cache,
            "touch-next",
            "QkJCQkJCQkJCQkJCQkJCQg==",
            "touch-next",
            0x92,
            3_010,
            100,
        )
        .await?;
        sqlx::query(
            r"
            WITH database_clock AS (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            UPDATE github_actions_cache_entries AS entry
            SET created_at_seconds = CASE
                    WHEN entry.id = $1 THEN database_clock.now_seconds - 20
                    ELSE database_clock.now_seconds - 10
                END,
                finalized_at_seconds = CASE
                    WHEN entry.id = $1 THEN database_clock.now_seconds - 20
                    ELSE database_clock.now_seconds - 10
                END,
                last_accessed_at_seconds = CASE
                    WHEN entry.id = $1 THEN database_clock.now_seconds - 20
                    ELSE database_clock.now_seconds - 10
                END
            FROM database_clock
            WHERE entry.id = ANY($2)
            ",
        )
        .bind(oldest_id.as_uuid())
        .bind(vec![oldest_id.as_uuid(), next_id.as_uuid()])
        .execute(database.pool())
        .await?;
        let (incoming_id, incoming_digest) = prepare_small_entry(
            &repository,
            execution,
            &cache,
            "touch-incoming",
            "Q0NDQ0NDQ0NDQ0NDQ0NDQw==",
            "touch-incoming",
            0x93,
            3_020,
        )
        .await?;
        install_touch_gate(database.pool(), oldest_id).await?;

        let mut gate = database.pool().begin().await?;
        let gate_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("SELECT entry_id FROM cache_touch_test_gate WHERE entry_id = $1 FOR UPDATE")
            .bind(oldest_id.as_uuid())
            .fetch_one(&mut *gate)
            .await?;

        let lookup_repository = repository.clone();
        let lookup_cache = cache.clone();
        let lookup_observed_at = database_now_seconds(&database).await?;
        let lookup = tokio::spawn(async move {
            lookup_repository
                .lookup(LookupCacheEntry {
                    execution,
                    cache: lookup_cache,
                    key: CacheKey::new("touch-oldest").expect("fixed cache key"),
                    restore_keys: Vec::new(),
                    version: CacheVersion::new("version-1").expect("fixed cache version"),
                    observed_at_seconds: lookup_observed_at,
                    inactivity_seconds: 7 * 24 * 60 * 60,
                })
                .await
        });
        wait_for_direct_blockers(database.pool(), gate_pid, 1).await?;
        let lookup_pid = direct_blocker_pid(database.pool(), gate_pid).await?;

        let finalization_repository = repository.clone();
        let finalization_observed_at = database_now_seconds(&database).await?;
        let finalization = tokio::spawn(async move {
            finalization_repository
                .complete_finalization(complete_small_entry_request(
                    execution,
                    cache,
                    incoming_id,
                    "touch-incoming",
                    incoming_digest,
                    finalization_observed_at,
                    6,
                ))
                .await
        });
        wait_for_direct_blockers(database.pool(), lookup_pid, 1).await?;
        gate.commit().await?;

        let touched = lookup.await??.expect("oldest entry remains readable");
        assert_eq!(touched.entry_id, oldest_id);
        assert_eq!(finalization.await??.entry_id, incoming_id);
        assert!(
            u64::try_from(sqlx::query_scalar::<_, i64>(
                "SELECT last_accessed_at_seconds FROM github_actions_cache_entries WHERE id = $1",
            )
            .bind(oldest_id.as_uuid())
            .fetch_one(database.pool())
            .await?)? >= lookup_observed_at,
        );
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM github_actions_cache_entries WHERE id = $1)",
            )
            .bind(next_id.as_uuid())
            .fetch_one(database.pool())
            .await?
        );
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM github_actions_cache_entries WHERE id = $1 AND state = 'finalized')",
            )
            .bind(incoming_id.as_uuid())
            .fetch_one(database.pool())
            .await?
        );
        Ok(())
    })
    .await
}

async fn age_finalized_entries(pool: &PgPool, entries: &[(CacheEntryId, i64)]) -> TestResult {
    for (entry_id, age_seconds) in entries {
        sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            UPDATE github_actions_cache_entries AS entry
            SET created_at_seconds = least(
                    entry.created_at_seconds,
                    database_clock.now_seconds - $2
                ),
                finalized_at_seconds = database_clock.now_seconds - $2,
                last_accessed_at_seconds = database_clock.now_seconds - $2
            FROM database_clock
            WHERE entry.id = $1 AND entry.state = 'finalized'
            ",
        )
        .bind(entry_id.as_uuid())
        .bind(age_seconds)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn cache_entry_exists(pool: &PgPool, entry_id: CacheEntryId) -> TestResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM github_actions_cache_entries WHERE id = $1)",
    )
    .bind(entry_id.as_uuid())
    .fetch_one(pool)
    .await?)
}

async fn set_repeatable_read_session_default(pool: &PgPool) -> TestResult {
    let mut connections = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        connections.push(pool.acquire().await?);
    }
    for connection in &mut connections {
        sqlx::query("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut **connection)
            .await?;
    }
    Ok(())
}

async fn execution_repository_id(pool: &PgPool, execution: ExecutionAuthority) -> TestResult<Uuid> {
    Ok(
        sqlx::query_scalar("SELECT repository_id FROM workflow_runs WHERE id = $1")
            .bind(execution.run_id().as_uuid())
            .fetch_one(pool)
            .await?,
    )
}

async fn wait_for_direct_blockers(pool: &PgPool, blocking_pid: i32, expected: i64) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blockers = sqlx::query_scalar::<_, i64>(
                r"
                WITH RECURSIVE blocked(pid) AS (
                    SELECT activity.pid
                    FROM pg_stat_activity AS activity
                    WHERE activity.datname = current_database()
                      AND $1 = ANY(pg_blocking_pids(activity.pid))
                    UNION
                    SELECT activity.pid
                    FROM pg_stat_activity AS activity
                    JOIN blocked
                      ON blocked.pid = ANY(pg_blocking_pids(activity.pid))
                    WHERE activity.datname = current_database()
                )
                SELECT count(*)::BIGINT FROM blocked
                ",
            )
            .bind(blocking_pid)
            .fetch_one(pool)
            .await?;
            if blockers >= expected {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("cache concurrency fixture did not reach its lock gate"))??;
    Ok(())
}

async fn direct_blocker_pid(pool: &PgPool, blocking_pid: i32) -> TestResult<i32> {
    Ok(sqlx::query_scalar(
        r"
        SELECT activity.pid
        FROM pg_stat_activity AS activity
        WHERE activity.datname = current_database()
          AND $1 = ANY(pg_blocking_pids(activity.pid))
        ORDER BY activity.pid
        LIMIT 1
        ",
    )
    .bind(blocking_pid)
    .fetch_one(pool)
    .await?)
}

async fn insert_zero_byte_finalized_entries(
    pool: &PgPool,
    source_entry: CacheEntryId,
    count: i64,
) -> TestResult {
    sqlx::query(
        r"
        WITH inserted AS (
            INSERT INTO github_actions_cache_entries (
                id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, cache_ref, cache_key, cache_version, state,
                content_digest, content_size_bytes, created_at_seconds,
                finalized_at_seconds, last_accessed_at_seconds
            )
            SELECT
                (
                    '20000000-0000-4000-8000-'
                    || lpad(to_hex(sequence), 12, '0')
                )::UUID,
                source.tenant_id, source.repository_id, source.run_id,
                source.job_id, source.attempt_id, source.fencing_token,
                source.cache_ref, 'concurrent-cardinality-' || sequence::TEXT,
                source.cache_version, 'finalized', decode(repeat('a1', 32), 'hex'),
                0, 1000, 1000 + sequence, 1000 + sequence
            FROM github_actions_cache_entries AS source
            CROSS JOIN generate_series(1, $2::BIGINT) AS sequence
            WHERE source.id = $1
            RETURNING id
        )
        INSERT INTO github_actions_cache_block_commits (
            entry_id, list_digest, block_ids, size_bytes, committed_at_seconds
        )
        SELECT id, decode(repeat('a2', 32), 'hex'), ARRAY[]::TEXT[], 0, 1000
        FROM inserted
        ",
    )
    .bind(source_entry.as_uuid())
    .bind(count)
    .execute(pool)
    .await?;
    Ok(())
}

async fn install_touch_gate(pool: &PgPool, entry_id: CacheEntryId) -> TestResult {
    sqlx::query("CREATE TABLE cache_touch_test_gate (entry_id UUID PRIMARY KEY)")
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO cache_touch_test_gate (entry_id) VALUES ($1)")
        .bind(entry_id.as_uuid())
        .execute(pool)
        .await?;
    sqlx::query(
        r"
        CREATE FUNCTION wait_on_cache_touch_test_gate() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.last_accessed_at_seconds > OLD.last_accessed_at_seconds
               AND EXISTS (
                   SELECT 1 FROM cache_touch_test_gate WHERE entry_id = NEW.id
               )
            THEN
                PERFORM 1
                FROM cache_touch_test_gate
                WHERE entry_id = NEW.id
                FOR UPDATE;
            END IF;
            RETURN NEW;
        END
        $$
        ",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        CREATE TRIGGER wait_on_cache_touch_test_gate
        BEFORE UPDATE OF last_accessed_at_seconds
        ON github_actions_cache_entries
        FOR EACH ROW EXECUTE FUNCTION wait_on_cache_touch_test_gate()
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn active_attempt(
    database: &TestDatabase,
) -> TestResult<(
    PostgresCacheRepository,
    ExecutionAuthority,
    RunnerSessionFence,
    LeaseGuard,
)> {
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
        PostgresCacheRepository::new(database.pool().clone()),
        ExecutionAuthority::new(seed.run_id, seed.job_id, attempt_id, lease.fencing_token()),
        seed.session_fence,
        lease.guard(),
    ))
}

async fn second_run_attempt(
    database: &TestDatabase,
    source: ExecutionAuthority,
    session_fence: RunnerSessionFence,
) -> TestResult<ExecutionAuthority> {
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
            publication_safety_reason, publication_safety_schema,
            runner_requirements_schema
        )
        SELECT
            $1, repository_id, workflow_id, snapshot_id, run_number + 1,
            event_name, 'test/cache-reader-event', event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, head_sha, status,
            2, 2, publication_policy_revision,
            requested_dashboard_visibility, effective_dashboard_visibility,
            requested_log_visibility, requested_artifact_visibility,
            publication_safety_reason, publication_safety_schema,
            runner_requirements_schema
        FROM workflow_runs
        WHERE id = $2
        ",
    )
    .bind(run_id)
    .bind(source.run_id().as_uuid())
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
            $1, $2, 'cache-reader', display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, 2
        FROM jobs
        WHERE id = $3
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id)
    .bind(source.job_id().as_uuid())
    .execute(database.pool())
    .await?;
    let queued_at = database_now_millis(database).await?;
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            job_id,
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
                session_fence,
                StableRunnerSlot::new(1)?,
                lease_observed_at,
                UnixMillis::new(lease_observed_at.get() + 60_000),
            )
            .expect("valid reader lease"),
        )
        .await?;
    Ok(ExecutionAuthority::new(
        automata_ci_core::RunId::from_uuid(run_id),
        job_id,
        attempt_id,
        lease.fencing_token(),
    ))
}

fn cache_authority(repository: &str, cache_ref: &str) -> CacheAuthority {
    CacheAuthority::new(
        repository,
        vec![CacheAccessScope::new(cache_ref, CachePermission::ReadWrite).expect("cache scope")],
    )
    .expect("cache authority")
}

fn create_request(
    execution: ExecutionAuthority,
    cache: CacheAuthority,
    entry_id: CacheEntryId,
    key: &str,
) -> CreateCacheEntry {
    CreateCacheEntry {
        execution,
        cache,
        entry_id,
        key: CacheKey::new(key).expect("cache key"),
        version: CacheVersion::new("version-1").expect("cache version"),
        observed_at_seconds: 1_000,
    }
}

fn complete_small_entry_request(
    execution: ExecutionAuthority,
    cache: CacheAuthority,
    entry_id: CacheEntryId,
    key: &str,
    digest: Sha256Digest,
    observed_at_seconds: u64,
    repository_quota_bytes: u64,
) -> CompleteCacheFinalization {
    CompleteCacheFinalization {
        execution,
        cache,
        entry_id,
        key: CacheKey::new(key).expect("fixed cache key"),
        version: CacheVersion::new("version-1").expect("fixed cache version"),
        digest,
        size: 3,
        observed_at_seconds,
        repository_quota_bytes,
        inactivity_seconds: 7 * 24 * 60 * 60,
    }
}

#[allow(clippy::too_many_arguments)] // The helper makes every durable cache field explicit.
async fn finalize_small_entry(
    repository: &PostgresCacheRepository,
    execution: ExecutionAuthority,
    cache: &CacheAuthority,
    key: &str,
    block_id: &str,
    descriptor_suffix: &str,
    descriptor_byte: u8,
    observed_at_seconds: u64,
    repository_quota_bytes: u64,
) -> TestResult<(CacheEntryId, Sha256Digest)> {
    let (entry_id, digest) = prepare_small_entry(
        repository,
        execution,
        cache,
        key,
        block_id,
        descriptor_suffix,
        descriptor_byte,
        observed_at_seconds,
    )
    .await?;
    repository
        .complete_finalization(CompleteCacheFinalization {
            execution,
            cache: cache.clone(),
            entry_id,
            key: CacheKey::new(key)?,
            version: CacheVersion::new("version-1")?,
            digest,
            size: 3,
            observed_at_seconds: database_now_seconds_from_pool(repository.postgres_pool()).await?,
            repository_quota_bytes,
            inactivity_seconds: 7 * 24 * 60 * 60,
        })
        .await?;
    Ok((entry_id, digest))
}

#[allow(clippy::too_many_arguments)] // The helper makes every durable cache field explicit.
async fn prepare_small_entry(
    repository: &PostgresCacheRepository,
    execution: ExecutionAuthority,
    cache: &CacheAuthority,
    key: &str,
    block_id: &str,
    descriptor_suffix: &str,
    descriptor_byte: u8,
    observed_at_seconds: u64,
) -> TestResult<(CacheEntryId, Sha256Digest)> {
    let entry_id = CacheEntryId::new(Uuid::new_v4())?;
    repository
        .create(CreateCacheEntry {
            execution,
            cache: cache.clone(),
            entry_id,
            key: CacheKey::new(key)?,
            version: CacheVersion::new("version-1")?,
            observed_at_seconds,
        })
        .await?;
    let block = CacheBlock::new(
        block_id.to_owned(),
        descriptor(descriptor_suffix, 3, descriptor_byte),
    );
    assert!(
        repository
            .reserve_block(ReserveCacheBlock {
                entry_id,
                block: block.clone(),
                observed_at_seconds: observed_at_seconds + 1,
                maximum_blocks: 10,
                maximum_entry_bytes: 1_024,
            })
            .await?
    );
    repository
        .complete_block(CompleteCacheBlock {
            entry_id,
            block: block.clone(),
            observed_at_seconds: observed_at_seconds + 2,
        })
        .await?;
    repository
        .commit_blocks(CommitCacheBlocks {
            entry_id,
            block_ids: vec![block.block_id().to_owned()],
            list_digest: Sha256Digest::from_bytes([descriptor_byte.wrapping_add(1); 32]),
            observed_at_seconds: observed_at_seconds + 3,
            maximum_blocks: 10,
            maximum_entry_bytes: 1_024,
        })
        .await?;
    let prepared = repository
        .prepare_finalization(PrepareCacheFinalization {
            execution,
            cache: cache.clone(),
            key: CacheKey::new(key)?,
            version: CacheVersion::new("version-1")?,
            claimed_size: 3,
        })
        .await?;
    assert!(matches!(prepared, CacheFinalizationPreparation::Verify(_)));
    let digest = Sha256Digest::from_bytes([descriptor_byte.wrapping_add(2); 32]);
    Ok((entry_id, digest))
}

fn descriptor(suffix: &str, size: u64, byte: u8) -> BlobDescriptor {
    BlobDescriptor::new(
        BlobKey::new(format!("test/cache/{suffix}")).expect("blob key"),
        Sha256Digest::from_bytes([byte; 32]),
        size,
        MediaType::new("application/octet-stream").expect("media type"),
    )
}

fn assert_database_timestamp_window(
    label: &str,
    timestamp: i64,
    database_before: u64,
    database_after: u64,
    forged_fast_observation: u64,
) -> TestResult {
    let timestamp = u64::try_from(timestamp)?;
    assert!(
        database_after < forged_fast_observation,
        "{label} fixture must retain a future caller observation"
    );
    assert!(
        (database_before..=database_after).contains(&timestamp),
        "{label} must persist database time, not the future caller observation"
    );
    Ok(())
}

async fn database_now_seconds(database: &TestDatabase) -> TestResult<u64> {
    database_now_seconds_from_pool(database.pool()).await
}

async fn database_now_seconds_from_pool(pool: &PgPool) -> TestResult<u64> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
            .fetch_one(pool)
            .await?;
    Ok(u64::try_from(database_now)?)
}

async fn database_now_millis(database: &TestDatabase) -> TestResult<UnixMillis> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    Ok(UnixMillis::new(database_now))
}
