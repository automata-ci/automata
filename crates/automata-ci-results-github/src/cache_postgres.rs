use std::collections::HashMap;

use async_trait::async_trait;
use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use sqlx::{PgPool, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use crate::{
    CacheAuthority, CacheBlock, CacheEntryId, CacheFinalizationPreparation, CacheKey,
    CacheProtocolEntryId, CacheRepository, CacheRepositoryError, CacheRepositoryErrorKind,
    CacheVersion, CommitCacheBlocks, CompleteCacheBlock, CompleteCacheFinalization,
    CreateCacheEntry, CreatedCacheEntry, ExecutionAuthority, FinalizedCacheEntry, LookupCacheEntry,
    PrepareCacheFinalization, PreparedCacheFinalization, ReserveCacheBlock, ResolveCacheDownload,
};

const ACTIVE_CACHE_LIFECYCLES: &[&str] =
    &["leased", "preparing", "running", "cancelling", "finalizing"];
const MAX_REPOSITORY_CACHE_ENTRIES: usize = 4_096;
const CACHE_ENTRY_CENSUS_LIMIT: i64 = 4_097;
const MAXIMUM_CACHE_CALLER_CLOCK_SKEW_SECONDS: u64 = 60;

/// `PostgreSQL` coordination adapter for current GitHub Actions cache-v2 entries.
#[derive(Clone, Debug)]
pub struct PostgresCacheRepository {
    pool: PgPool,
}

impl PostgresCacheRepository {
    /// Binds cache coordination to an existing product pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the pool for adapter-level integration tests.
    #[must_use]
    pub const fn postgres_pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl CacheRepository for PostgresCacheRepository {
    async fn create(
        &self,
        request: CreateCacheEntry,
    ) -> Result<CreatedCacheEntry, CacheRepositoryError> {
        let cache_ref = request
            .cache
            .writable_scope()
            .ok_or_else(|| error(CacheRepositoryErrorKind::Unauthorized))?;
        let mut transaction = begin_read_committed(&self.pool).await?;
        let repository = authorize_execution(
            &mut transaction,
            request.execution,
            &request.cache,
            RepositoryLock::Update,
        )
        .await?;
        seconds_i64(request.observed_at_seconds)?;
        delete_inactive_pending_entries(&mut transaction, repository.repository_id).await?;
        let existing = sqlx::query(
            r"
            SELECT id, run_id, job_id, attempt_id, fencing_token, state
            FROM github_actions_cache_entries
            WHERE repository_id = $1 AND cache_ref = $2
              AND cache_key = $3 AND cache_version = $4
            FOR UPDATE
            ",
        )
        .bind(repository.repository_id)
        .bind(cache_ref)
        .bind(request.key.as_str())
        .bind(request.version.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        if let Some(row) = existing {
            if row.try_get::<String, _>("state").map_err(corrupt_error)? != "pending"
                || !row_execution_matches(&row, request.execution)?
            {
                return Err(error(CacheRepositoryErrorKind::Conflict));
            }
            let entry_id = decode_entry_id(&row)?;
            transaction.commit().await.map_err(database_error)?;
            return Ok(CreatedCacheEntry { entry_id });
        }
        reserve_repository_entry_slot(&mut transaction, repository.repository_id).await?;

        sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            INSERT INTO github_actions_cache_entries (
                id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, cache_ref, cache_key, cache_version,
                created_at_seconds, last_accessed_at_seconds
            )
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                   database_clock.now_seconds, database_clock.now_seconds
            FROM database_clock
            ",
        )
        .bind(request.entry_id.as_uuid())
        .bind(&repository.tenant_id)
        .bind(repository.repository_id)
        .bind(request.execution.run_id().as_uuid())
        .bind(request.execution.job_id().as_uuid())
        .bind(request.execution.attempt_id().as_uuid())
        .bind(fence_i64(request.execution.fencing_token())?)
        .bind(cache_ref)
        .bind(request.key.as_str())
        .bind(request.version.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)?;
        Ok(CreatedCacheEntry {
            entry_id: request.entry_id,
        })
    }

    async fn reserve_block(
        &self,
        request: ReserveCacheBlock,
    ) -> Result<bool, CacheRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let entry = lock_entry_by_id(&mut transaction, request.entry_id).await?;
        seconds_i64(request.observed_at_seconds)?;
        require_pending(&entry)?;
        let encoded_length = i32::try_from(request.block.block_id().len())
            .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?;
        match entry.block_id_encoded_length {
            Some(expected) if expected != encoded_length => {
                return Err(error(CacheRepositoryErrorKind::Conflict));
            }
            None => {
                sqlx::query(
                    "UPDATE github_actions_cache_entries SET block_id_encoded_length = $2 WHERE id = $1",
                )
                .bind(request.entry_id.as_uuid())
                .bind(encoded_length)
                .execute(&mut *transaction)
                .await
                .map_err(database_error)?;
            }
            Some(_) => {}
        }

        let existing = sqlx::query(
            r"
            SELECT object_key, digest, size_bytes, media_type, state
            FROM github_actions_cache_blocks
            WHERE entry_id = $1 AND block_id = $2
            FOR UPDATE
            ",
        )
        .bind(request.entry_id.as_uuid())
        .bind(request.block.block_id())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        if let Some(row) = existing {
            if decode_descriptor(&row)? != *request.block.descriptor() {
                return Err(error(CacheRepositoryErrorKind::Conflict));
            }
            let block_state = row.try_get::<String, _>("state").map_err(corrupt_error)?;
            let upload_required = match block_state.as_str() {
                "ready" => false,
                "reserved" => {
                    require_no_commit(&mut transaction, request.entry_id).await?;
                    true
                }
                _ => return Err(error(CacheRepositoryErrorKind::CorruptData)),
            };
            transaction.commit().await.map_err(database_error)?;
            return Ok(upload_required);
        }

        require_no_commit(&mut transaction, request.entry_id).await?;
        ensure_staging_capacity(
            &mut transaction,
            request.entry_id,
            request.block.descriptor().size(),
            request.maximum_blocks,
            request.maximum_entry_bytes,
        )
        .await?;
        sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            INSERT INTO github_actions_cache_blocks (
                entry_id, block_id, object_key, digest, size_bytes, media_type,
                staged_at_seconds
            )
            SELECT $1, $2, $3, $4, $5, $6, database_clock.now_seconds
            FROM database_clock
            ",
        )
        .bind(request.entry_id.as_uuid())
        .bind(request.block.block_id())
        .bind(request.block.descriptor().key().as_str())
        .bind(request.block.descriptor().digest().as_bytes().as_slice())
        .bind(size_i64(request.block.descriptor().size())?)
        .bind(request.block.descriptor().media_type().as_str())
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)?;
        Ok(true)
    }

    async fn complete_block(
        &self,
        request: CompleteCacheBlock,
    ) -> Result<(), CacheRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let entry = lock_entry_by_id(&mut transaction, request.entry_id).await?;
        seconds_i64(request.observed_at_seconds)?;
        require_pending(&entry)?;
        let row = sqlx::query(
            r"
            SELECT object_key, digest, size_bytes, media_type, state
            FROM github_actions_cache_blocks
            WHERE entry_id = $1 AND block_id = $2
            FOR UPDATE
            ",
        )
        .bind(request.entry_id.as_uuid())
        .bind(request.block.block_id())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::NotFound))?;
        if decode_descriptor(&row)? != *request.block.descriptor() {
            return Err(error(CacheRepositoryErrorKind::Conflict));
        }
        match row
            .try_get::<String, _>("state")
            .map_err(corrupt_error)?
            .as_str()
        {
            "ready" => {}
            "reserved" => {
                require_no_commit(&mut transaction, request.entry_id).await?;
                let updated = sqlx::query(
                    r"
                    WITH database_clock AS MATERIALIZED (
                        SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
                    )
                    UPDATE github_actions_cache_blocks AS block
                    SET state = 'ready',
                        ready_at_seconds = greatest(
                            block.staged_at_seconds,
                            database_clock.now_seconds
                        )
                    FROM database_clock
                    WHERE block.entry_id = $1 AND block.block_id = $2
                      AND block.state = 'reserved'
                    ",
                )
                .bind(request.entry_id.as_uuid())
                .bind(request.block.block_id())
                .execute(&mut *transaction)
                .await
                .map_err(database_error)?;
                if updated.rows_affected() != 1 {
                    return Err(error(CacheRepositoryErrorKind::Conflict));
                }
            }
            _ => return Err(error(CacheRepositoryErrorKind::CorruptData)),
        }
        transaction.commit().await.map_err(database_error)
    }

    async fn commit_blocks(&self, request: CommitCacheBlocks) -> Result<(), CacheRepositoryError> {
        if request.block_ids.len() > request.maximum_blocks {
            return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
        }
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let entry = lock_entry_by_id(&mut transaction, request.entry_id).await?;
        seconds_i64(request.observed_at_seconds)?;
        require_pending(&entry)?;
        if let Some(row) = sqlx::query(
            r"
            SELECT list_digest, block_ids, size_bytes
            FROM github_actions_cache_block_commits
            WHERE entry_id = $1
            FOR UPDATE
            ",
        )
        .bind(request.entry_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        {
            let committed_size =
                nonnegative_u64(row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?)?;
            if decode_digest(
                row.try_get::<Vec<u8>, _>("list_digest")
                    .map_err(corrupt_error)?,
            )? != request.list_digest
                || row
                    .try_get::<Vec<String>, _>("block_ids")
                    .map_err(corrupt_error)?
                    != request.block_ids
            {
                return Err(error(CacheRepositoryErrorKind::Conflict));
            }
            let blocks =
                load_ordered_blocks(&mut transaction, request.entry_id, &request.block_ids).await?;
            let verified_size = blocks.iter().try_fold(0_u64, |total, block| {
                total
                    .checked_add(block.descriptor().size())
                    .ok_or_else(|| error(CacheRepositoryErrorKind::CorruptData))
            })?;
            if committed_size != verified_size {
                return Err(error(CacheRepositoryErrorKind::CorruptData));
            }
            transaction.commit().await.map_err(database_error)?;
            return Ok(());
        }
        let blocks =
            load_ordered_blocks(&mut transaction, request.entry_id, &request.block_ids).await?;
        let size = blocks.iter().try_fold(0_u64, |total, block| {
            total
                .checked_add(block.descriptor().size())
                .ok_or_else(|| error(CacheRepositoryErrorKind::ResourceExhausted))
        })?;
        if size > request.maximum_entry_bytes {
            return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
        }
        sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            INSERT INTO github_actions_cache_block_commits (
                entry_id, list_digest, block_ids, size_bytes, committed_at_seconds
            )
            SELECT $1, $2, $3, $4, database_clock.now_seconds
            FROM database_clock
            ",
        )
        .bind(request.entry_id.as_uuid())
        .bind(request.list_digest.as_bytes().as_slice())
        .bind(&request.block_ids)
        .bind(size_i64(size)?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)
    }

    async fn prepare_finalization(
        &self,
        request: PrepareCacheFinalization,
    ) -> Result<CacheFinalizationPreparation, CacheRepositoryError> {
        let cache_ref = request
            .cache
            .writable_scope()
            .ok_or_else(|| error(CacheRepositoryErrorKind::Unauthorized))?;
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let repository = authorize_execution(
            &mut transaction,
            request.execution,
            &request.cache,
            RepositoryLock::None,
        )
        .await?;
        let entry = lock_entry_by_key(
            &mut transaction,
            repository.repository_id,
            cache_ref,
            &request.key,
            &request.version,
        )
        .await?;
        if entry.execution != request.execution {
            return Err(error(CacheRepositoryErrorKind::Unauthorized));
        }
        if entry.state == "finalized" {
            let finalized = load_finalized(&mut transaction, &entry).await?;
            if finalized.size != request.claimed_size {
                return Err(error(CacheRepositoryErrorKind::Conflict));
            }
            transaction.commit().await.map_err(database_error)?;
            return Ok(CacheFinalizationPreparation::Finalized(finalized));
        }
        require_pending(&entry)?;
        let row = sqlx::query(
            "SELECT block_ids, size_bytes FROM github_actions_cache_block_commits WHERE entry_id = $1 FOR UPDATE",
        )
        .bind(entry.entry_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::InvalidState))?;
        let size = nonnegative_u64(row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?)?;
        if size != request.claimed_size {
            return Err(error(CacheRepositoryErrorKind::Conflict));
        }
        let block_ids = row
            .try_get::<Vec<String>, _>("block_ids")
            .map_err(corrupt_error)?;
        let blocks = load_ordered_blocks(&mut transaction, entry.entry_id, &block_ids).await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(CacheFinalizationPreparation::Verify(
            PreparedCacheFinalization {
                entry_id: entry.entry_id,
                blocks,
                size,
            },
        ))
    }

    async fn complete_finalization(
        &self,
        request: CompleteCacheFinalization,
    ) -> Result<FinalizedCacheEntry, CacheRepositoryError> {
        let cache_ref = request
            .cache
            .writable_scope()
            .ok_or_else(|| error(CacheRepositoryErrorKind::Unauthorized))?;
        let mut transaction = begin_read_committed(&self.pool).await?;
        let repository = authorize_execution(
            &mut transaction,
            request.execution,
            &request.cache,
            RepositoryLock::Update,
        )
        .await?;
        delete_inactive_pending_entries(&mut transaction, repository.repository_id).await?;
        let entry = lock_entry_by_id(&mut transaction, request.entry_id).await?;
        let database_now = cache_database_now(&mut transaction).await?;
        validate_cache_caller_clock(request.observed_at_seconds, database_now)?;
        if entry.repository_id != repository.repository_id
            || entry.execution != request.execution
            || entry.cache_ref != cache_ref
            || entry.key != request.key
            || entry.version != request.version
        {
            return Err(error(CacheRepositoryErrorKind::Unauthorized));
        }
        if entry.state == "finalized" {
            let finalized = load_finalized(&mut transaction, &entry).await?;
            if finalized.size != request.size || finalized.digest != request.digest {
                return Err(error(CacheRepositoryErrorKind::Conflict));
            }
            transaction.commit().await.map_err(database_error)?;
            return Ok(finalized);
        }
        require_pending(&entry)?;
        let committed_size = sqlx::query_scalar::<_, i64>(
            "SELECT size_bytes FROM github_actions_cache_block_commits WHERE entry_id = $1 FOR UPDATE",
        )
        .bind(request.entry_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::InvalidState))?;
        if nonnegative_u64(committed_size)? != request.size {
            return Err(error(CacheRepositoryErrorKind::Conflict));
        }
        enforce_repository_entry_ceiling(&mut transaction, repository.repository_id).await?;
        let inactivity_seconds = validated_inactivity_seconds(request.inactivity_seconds)?;
        sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            DELETE FROM github_actions_cache_entries
            USING database_clock
            WHERE repository_id = $1 AND state = 'finalized'
              AND last_accessed_at_seconds <= greatest(
                    0::BIGINT,
                    database_clock.now_seconds - $2
              )
            ",
        )
        .bind(repository.repository_id)
        .bind(seconds_i64(inactivity_seconds)?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        evict_to_fit(
            &mut transaction,
            repository.repository_id,
            request.size,
            request.repository_quota_bytes,
        )
        .await?;
        let updated = sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            UPDATE github_actions_cache_entries AS entry
            SET state = 'finalized', content_digest = $2, content_size_bytes = $3,
                finalized_at_seconds = database_clock.now_seconds,
                last_accessed_at_seconds = database_clock.now_seconds
            FROM database_clock
            WHERE entry.id = $1 AND entry.state = 'pending'
              AND entry.created_at_seconds <= database_clock.now_seconds
            ",
        )
        .bind(request.entry_id.as_uuid())
        .bind(request.digest.as_bytes().as_slice())
        .bind(size_i64(request.size)?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        if updated.rows_affected() != 1 {
            return Err(error(CacheRepositoryErrorKind::Conflict));
        }
        let entry = lock_entry_by_id(&mut transaction, request.entry_id).await?;
        let finalized = load_finalized(&mut transaction, &entry).await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(finalized)
    }

    async fn lookup(
        &self,
        request: LookupCacheEntry,
    ) -> Result<Option<FinalizedCacheEntry>, CacheRepositoryError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let repository = authorize_execution(
            &mut transaction,
            request.execution,
            &request.cache,
            RepositoryLock::Share,
        )
        .await?;
        let database_now = cache_database_now(&mut transaction).await?;
        validate_cache_caller_clock(request.observed_at_seconds, database_now)?;
        let inactivity_seconds = validated_inactivity_seconds(request.inactivity_seconds)?;
        let mut selected = None;
        for candidate in request.candidates() {
            selected = find_match(
                &mut transaction,
                repository.repository_id,
                candidate.cache_ref,
                &request.version,
                candidate.key,
                candidate.exact,
                inactivity_seconds,
            )
            .await?;
            if selected.is_some() {
                break;
            }
        }
        let Some(entry) = selected else {
            transaction.commit().await.map_err(database_error)?;
            return Ok(None);
        };
        let finalized = load_finalized(&mut transaction, &entry).await?;
        if !touch_entry(&mut transaction, entry.entry_id, inactivity_seconds).await? {
            return Ok(None);
        }
        transaction.commit().await.map_err(database_error)?;
        Ok(Some(finalized))
    }

    async fn resolve_download(
        &self,
        request: ResolveCacheDownload,
    ) -> Result<FinalizedCacheEntry, CacheRepositoryError> {
        let mut transaction = begin_read_committed(&self.pool).await?;
        let repository_id = entry_repository_id(&mut transaction, request.entry_id).await?;
        lock_repository(&mut transaction, repository_id, RepositoryLock::Share).await?;
        let entry = lock_entry_by_id_for_read(&mut transaction, request.entry_id).await?;
        let database_now = cache_database_now(&mut transaction).await?;
        validate_cache_caller_clock(request.observed_at_seconds, database_now)?;
        let inactivity_seconds = validated_inactivity_seconds(request.inactivity_seconds)?;
        if entry.repository_id != repository_id
            || entry.state != "finalized"
            || entry.digest()? != request.digest
            || !cache_entry_is_live(&entry, database_now, inactivity_seconds)
        {
            return Err(error(CacheRepositoryErrorKind::NotFound));
        }
        let finalized = load_finalized(&mut transaction, &entry).await?;
        if !touch_entry(&mut transaction, entry.entry_id, inactivity_seconds).await? {
            return Err(error(CacheRepositoryErrorKind::NotFound));
        }
        transaction.commit().await.map_err(database_error)?;
        Ok(finalized)
    }
}

async fn ensure_staging_capacity(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
    block_size: u64,
    maximum_blocks: usize,
    maximum_entry_bytes: u64,
) -> Result<(), CacheRepositoryError> {
    let aggregate = sqlx::query(
        r"
        SELECT count(*) AS block_count,
               coalesce(sum(size_bytes), 0)::text AS staged_bytes
        FROM github_actions_cache_blocks
        WHERE entry_id = $1
        ",
    )
    .bind(entry_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    let block_count = usize::try_from(
        aggregate
            .try_get::<i64, _>("block_count")
            .map_err(corrupt_error)?,
    )
    .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?;
    let staged_bytes = aggregate
        .try_get::<String, _>("staged_bytes")
        .map_err(corrupt_error)?
        .parse::<u64>()
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?;
    if block_count >= maximum_blocks
        || staged_bytes
            .checked_add(block_size)
            .is_none_or(|total| total > maximum_entry_bytes)
    {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    Ok(())
}

#[derive(Debug)]
struct RepositoryScope {
    tenant_id: String,
    repository_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryLock {
    None,
    Share,
    Update,
}

async fn begin_read_committed(
    pool: &PgPool,
) -> Result<Transaction<'_, sqlx::Postgres>, CacheRepositoryError> {
    let mut transaction = pool.begin().await.map_err(database_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    Ok(transaction)
}

async fn lock_repository(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
    lock: RepositoryLock,
) -> Result<(), CacheRepositoryError> {
    let statement = match lock {
        RepositoryLock::None => return Ok(()),
        RepositoryLock::Share => "SELECT id FROM repositories WHERE id = $1 FOR SHARE",
        RepositoryLock::Update => "SELECT id FROM repositories WHERE id = $1 FOR UPDATE",
    };
    let locked = sqlx::query_scalar::<_, Uuid>(statement)
        .bind(repository_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::Unauthorized))?;
    if locked != repository_id {
        return Err(error(CacheRepositoryErrorKind::CorruptData));
    }
    Ok(())
}

async fn authorize_execution(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    execution: ExecutionAuthority,
    cache: &CacheAuthority,
    repository_lock: RepositoryLock,
) -> Result<RepositoryScope, CacheRepositoryError> {
    let row = sqlx::query(
        r"
        SELECT repository.tenant_id, repository.id AS repository_id,
               lower(repository.owner) || '/' || lower(repository.name) AS repository_slug,
               attempt.fencing_token AS current_fencing_token,
               attempt.lifecycle, attempt.lease_id
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE run.id = $1 AND job.id = $2 AND attempt.id = $3
        FOR SHARE OF attempt
        ",
    )
    .bind(execution.run_id().as_uuid())
    .bind(execution.job_id().as_uuid())
    .bind(execution.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| error(CacheRepositoryErrorKind::Unauthorized))?;
    verify_attempt(&row, execution.fencing_token())?;
    if row
        .try_get::<String, _>("repository_slug")
        .map_err(corrupt_error)?
        != cache.repository()
    {
        return Err(error(CacheRepositoryErrorKind::Unauthorized));
    }
    let repository_id = row
        .try_get::<Uuid, _>("repository_id")
        .map_err(corrupt_error)?;
    lock_repository(transaction, repository_id, repository_lock).await?;
    Ok(RepositoryScope {
        tenant_id: row
            .try_get::<String, _>("tenant_id")
            .map_err(corrupt_error)?,
        repository_id,
    })
}

#[derive(Debug)]
struct LockedCacheEntry {
    entry_id: CacheEntryId,
    protocol_entry_id: CacheProtocolEntryId,
    repository_id: Uuid,
    repository_slug: String,
    execution: ExecutionAuthority,
    cache_ref: String,
    key: CacheKey,
    version: CacheVersion,
    block_id_encoded_length: Option<i32>,
    state: String,
    content_digest: Option<Vec<u8>>,
    content_size_bytes: Option<i64>,
    last_accessed_at_seconds: u64,
}

impl LockedCacheEntry {
    fn digest(&self) -> Result<Sha256Digest, CacheRepositoryError> {
        self.content_digest
            .clone()
            .ok_or_else(|| error(CacheRepositoryErrorKind::CorruptData))
            .and_then(decode_digest)
    }
}

async fn lock_entry_by_id(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
) -> Result<LockedCacheEntry, CacheRepositoryError> {
    let execution = lock_active_entry_origin(transaction, entry_id).await?;
    let entry = lock_entry_by_id_for_read(transaction, entry_id).await?;
    if entry.execution != execution {
        return Err(error(CacheRepositoryErrorKind::CorruptData));
    }
    Ok(entry)
}

async fn lock_active_entry_origin(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
) -> Result<ExecutionAuthority, CacheRepositoryError> {
    let row = sqlx::query(
        r"
        SELECT entry.run_id, entry.job_id, entry.attempt_id,
               entry.fencing_token AS entry_fencing_token,
               attempt.fencing_token AS current_fencing_token,
               attempt.lifecycle, attempt.lease_id
        FROM github_actions_cache_entries AS entry
        JOIN job_attempts AS attempt
          ON attempt.id = entry.attempt_id AND attempt.job_id = entry.job_id
        WHERE entry.id = $1
        FOR SHARE OF attempt
        ",
    )
    .bind(entry_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| error(CacheRepositoryErrorKind::NotFound))?;
    let execution = decode_entry_execution(&row)?;
    verify_attempt(&row, execution.fencing_token())?;
    Ok(execution)
}

async fn lock_entry_by_id_for_read(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
) -> Result<LockedCacheEntry, CacheRepositoryError> {
    let statement = format!("{ENTRY_COLUMNS} WHERE entry.id = $1 FOR UPDATE OF entry");
    // The statement consists only of fixed internal SQL fragments above.
    let row = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(entry_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::NotFound))?;
    decode_locked_entry(&row)
}

async fn entry_repository_id(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
) -> Result<Uuid, CacheRepositoryError> {
    sqlx::query_scalar("SELECT repository_id FROM github_actions_cache_entries WHERE id = $1")
        .bind(entry_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::NotFound))
}

async fn lock_entry_by_key(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
    cache_ref: &str,
    key: &CacheKey,
    version: &CacheVersion,
) -> Result<LockedCacheEntry, CacheRepositoryError> {
    let statement = format!(
        "{ENTRY_COLUMNS} WHERE entry.repository_id = $1 AND entry.cache_ref = $2 \
         AND entry.cache_key = $3 AND entry.cache_version = $4 \
         FOR UPDATE OF entry"
    );
    // The statement consists only of fixed internal SQL fragments above.
    let row = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(repository_id)
        .bind(cache_ref)
        .bind(key.as_str())
        .bind(version.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| error(CacheRepositoryErrorKind::NotFound))?;
    decode_locked_entry(&row)
}

const ENTRY_COLUMNS: &str = concat!(
    "SELECT entry.id, entry.protocol_entry_id, entry.repository_id, entry.run_id, entry.job_id, entry.attempt_id, ",
    "entry.fencing_token AS entry_fencing_token, entry.cache_ref, entry.cache_key, ",
    "entry.cache_version, entry.block_id_encoded_length, entry.state, entry.content_digest, ",
    "entry.content_size_bytes, entry.last_accessed_at_seconds, ",
    "lower(repository.owner) || '/' || lower(repository.name) AS repository_slug, ",
    "attempt.fencing_token AS current_fencing_token, attempt.lifecycle, attempt.lease_id ",
    "FROM github_actions_cache_entries AS entry ",
    "JOIN repositories AS repository ON repository.id = entry.repository_id ",
    "JOIN job_attempts AS attempt ON attempt.id = entry.attempt_id "
);
fn decode_entry_execution(row: &PgRow) -> Result<ExecutionAuthority, CacheRepositoryError> {
    let execution = ExecutionAuthority::new(
        RunId::from_uuid(row.try_get::<Uuid, _>("run_id").map_err(corrupt_error)?),
        JobId::from_uuid(row.try_get::<Uuid, _>("job_id").map_err(corrupt_error)?),
        AttemptId::from_uuid(
            row.try_get::<Uuid, _>("attempt_id")
                .map_err(corrupt_error)?,
        ),
        FencingToken::new(
            u64::try_from(
                row.try_get::<i64, _>("entry_fencing_token")
                    .map_err(corrupt_error)?,
            )
            .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?,
        )
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?,
    );
    Ok(execution)
}

fn decode_locked_entry(row: &PgRow) -> Result<LockedCacheEntry, CacheRepositoryError> {
    let execution = decode_entry_execution(row)?;
    Ok(LockedCacheEntry {
        entry_id: decode_entry_id(row)?,
        protocol_entry_id: CacheProtocolEntryId::new(
            row.try_get::<i64, _>("protocol_entry_id")
                .map_err(corrupt_error)?,
        )
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?,
        repository_id: row
            .try_get::<Uuid, _>("repository_id")
            .map_err(corrupt_error)?,
        repository_slug: row
            .try_get::<String, _>("repository_slug")
            .map_err(corrupt_error)?,
        execution,
        cache_ref: row
            .try_get::<String, _>("cache_ref")
            .map_err(corrupt_error)?,
        key: CacheKey::new(
            row.try_get::<String, _>("cache_key")
                .map_err(corrupt_error)?,
        )
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?,
        version: CacheVersion::new(
            row.try_get::<String, _>("cache_version")
                .map_err(corrupt_error)?,
        )
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?,
        block_id_encoded_length: row
            .try_get::<Option<i32>, _>("block_id_encoded_length")
            .map_err(corrupt_error)?,
        state: row.try_get::<String, _>("state").map_err(corrupt_error)?,
        content_digest: row
            .try_get::<Option<Vec<u8>>, _>("content_digest")
            .map_err(corrupt_error)?,
        content_size_bytes: row
            .try_get::<Option<i64>, _>("content_size_bytes")
            .map_err(corrupt_error)?,
        last_accessed_at_seconds: nonnegative_u64(
            row.try_get::<i64, _>("last_accessed_at_seconds")
                .map_err(corrupt_error)?,
        )?,
    })
}

fn verify_attempt(row: &PgRow, fence: FencingToken) -> Result<(), CacheRepositoryError> {
    if row
        .try_get::<i64, _>("current_fencing_token")
        .map_err(corrupt_error)?
        != fence_i64(fence)?
        || !ACTIVE_CACHE_LIFECYCLES.contains(
            &row.try_get::<String, _>("lifecycle")
                .map_err(corrupt_error)?
                .as_str(),
        )
        || row
            .try_get::<Option<Uuid>, _>("lease_id")
            .map_err(corrupt_error)?
            .is_none()
    {
        return Err(error(CacheRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

fn row_execution_matches(
    row: &PgRow,
    execution: ExecutionAuthority,
) -> Result<bool, CacheRepositoryError> {
    Ok(
        row.try_get::<Uuid, _>("run_id").map_err(corrupt_error)? == execution.run_id().as_uuid()
            && row.try_get::<Uuid, _>("job_id").map_err(corrupt_error)?
                == execution.job_id().as_uuid()
            && row
                .try_get::<Uuid, _>("attempt_id")
                .map_err(corrupt_error)?
                == execution.attempt_id().as_uuid()
            && row
                .try_get::<i64, _>("fencing_token")
                .map_err(corrupt_error)?
                == fence_i64(execution.fencing_token())?,
    )
}

async fn require_no_commit(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
) -> Result<(), CacheRepositoryError> {
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM github_actions_cache_block_commits WHERE entry_id = $1)",
    )
    .bind(entry_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?
    {
        return Err(error(CacheRepositoryErrorKind::InvalidState));
    }
    Ok(())
}

fn require_pending(entry: &LockedCacheEntry) -> Result<(), CacheRepositoryError> {
    if entry.state != "pending" {
        return Err(error(CacheRepositoryErrorKind::InvalidState));
    }
    Ok(())
}

async fn load_ordered_blocks(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
    block_ids: &[String],
) -> Result<Vec<CacheBlock>, CacheRepositoryError> {
    if block_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        r"
        SELECT block_id, object_key, digest, size_bytes, media_type, state
        FROM github_actions_cache_blocks
        WHERE entry_id = $1 AND block_id = ANY($2)
        FOR SHARE
        ",
    )
    .bind(entry_id.as_uuid())
    .bind(block_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    let mut blocks = HashMap::with_capacity(rows.len());
    for row in rows {
        if row.try_get::<String, _>("state").map_err(corrupt_error)? != "ready" {
            return Err(error(CacheRepositoryErrorKind::InvalidState));
        }
        let block_id = row
            .try_get::<String, _>("block_id")
            .map_err(corrupt_error)?;
        let block = CacheBlock::new(block_id.clone(), decode_descriptor(&row)?);
        if blocks.insert(block_id, block).is_some() {
            return Err(error(CacheRepositoryErrorKind::CorruptData));
        }
    }
    block_ids
        .iter()
        .map(|block_id| {
            blocks
                .get(block_id)
                .cloned()
                .ok_or_else(|| error(CacheRepositoryErrorKind::NotFound))
        })
        .collect()
}

async fn load_finalized(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry: &LockedCacheEntry,
) -> Result<FinalizedCacheEntry, CacheRepositoryError> {
    if entry.state != "finalized" {
        return Err(error(CacheRepositoryErrorKind::InvalidState));
    }
    let row = sqlx::query(
        "SELECT block_ids, size_bytes FROM github_actions_cache_block_commits WHERE entry_id = $1",
    )
    .bind(entry.entry_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| error(CacheRepositoryErrorKind::CorruptData))?;
    let size = nonnegative_u64(row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?)?;
    if Some(size_i64(size)?) != entry.content_size_bytes {
        return Err(error(CacheRepositoryErrorKind::CorruptData));
    }
    let block_ids = row
        .try_get::<Vec<String>, _>("block_ids")
        .map_err(corrupt_error)?;
    let blocks = load_ordered_blocks(transaction, entry.entry_id, &block_ids).await?;
    Ok(FinalizedCacheEntry {
        entry_id: entry.entry_id,
        protocol_entry_id: entry.protocol_entry_id,
        repository: entry.repository_slug.clone(),
        cache_ref: entry.cache_ref.clone(),
        key: entry.key.clone(),
        version: entry.version.clone(),
        digest: entry.digest()?,
        size,
        blocks,
    })
}

async fn find_match(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
    cache_ref: &str,
    version: &CacheVersion,
    key: &str,
    exact: bool,
    inactivity_seconds: u64,
) -> Result<Option<LockedCacheEntry>, CacheRepositoryError> {
    let predicate = if exact {
        "entry.cache_key = $4"
    } else {
        "left(entry.cache_key, char_length($4)) = $4"
    };
    let statement = format!(
        "{ENTRY_COLUMNS} WHERE entry.repository_id = $1 AND entry.cache_ref = $2 \
         AND entry.cache_version = $3 AND {predicate} AND entry.state = 'finalized' \
         AND entry.last_accessed_at_seconds > $5 \
         AND NOT (entry.id = ANY($6::UUID[])) \
         ORDER BY entry.finalized_at_seconds DESC, entry.id ASC LIMIT 1 FOR UPDATE OF entry"
    );
    // The predicate is selected from the closed `exact` branch above; all data is bound.
    let mut expired_after_lock = Vec::<Uuid>::new();
    loop {
        let database_now = cache_database_now(transaction).await?;
        let cutoff = cache_inactivity_cutoff(database_now, inactivity_seconds)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(repository_id)
            .bind(cache_ref)
            .bind(version.as_str())
            .bind(key)
            .bind(cutoff)
            .bind(&expired_after_lock)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(database_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let entry = decode_locked_entry(&row)?;
        let locked_database_now = cache_database_now(transaction).await?;
        if cache_entry_is_live(&entry, locked_database_now, inactivity_seconds) {
            return Ok(Some(entry));
        }
        expired_after_lock.push(entry.entry_id.as_uuid());
        if expired_after_lock.len() >= MAX_REPOSITORY_CACHE_ENTRIES {
            return Ok(None);
        }
    }
}

async fn touch_entry(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    entry_id: CacheEntryId,
    inactivity_seconds: u64,
) -> Result<bool, CacheRepositoryError> {
    let updated = sqlx::query(
        r"
        WITH database_clock AS MATERIALIZED (
            SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
        )
        UPDATE github_actions_cache_entries AS entry
        SET last_accessed_at_seconds = greatest(
            entry.last_accessed_at_seconds,
            database_clock.now_seconds
        )
        FROM database_clock
        WHERE entry.id = $1 AND entry.state = 'finalized'
          AND entry.last_accessed_at_seconds > greatest(
                0::BIGINT,
                database_clock.now_seconds - $2
          )
        ",
    )
    .bind(entry_id.as_uuid())
    .bind(seconds_i64(inactivity_seconds)?)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(updated.rows_affected() == 1)
}

async fn delete_inactive_pending_entries(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
) -> Result<(), CacheRepositoryError> {
    sqlx::query(
        r"
        DELETE FROM github_actions_cache_entries AS entry
        USING job_attempts AS attempt
        WHERE entry.repository_id = $1
          AND entry.state = 'pending'
          AND attempt.id = entry.attempt_id
          AND attempt.job_id = entry.job_id
          AND NOT (
              attempt.lifecycle = ANY($2::TEXT[])
              AND attempt.lease_id IS NOT NULL
          )
        ",
    )
    .bind(repository_id)
    .bind(ACTIVE_CACHE_LIFECYCLES)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn repository_entry_count(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
) -> Result<usize, CacheRepositoryError> {
    let count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)::BIGINT
        FROM (
            SELECT 1
            FROM github_actions_cache_entries
            WHERE repository_id = $1
            LIMIT $2
        ) AS bounded_entries
        ",
    )
    .bind(repository_id)
    .bind(CACHE_ENTRY_CENSUS_LIMIT)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    usize::try_from(count).map_err(|_| error(CacheRepositoryErrorKind::CorruptData))
}

async fn enforce_repository_entry_ceiling(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
) -> Result<(), CacheRepositoryError> {
    if repository_entry_count(transaction, repository_id).await? > MAX_REPOSITORY_CACHE_ENTRIES {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    Ok(())
}

async fn reserve_repository_entry_slot(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
) -> Result<(), CacheRepositoryError> {
    let count = repository_entry_count(transaction, repository_id).await?;
    if count < MAX_REPOSITORY_CACHE_ENTRIES {
        return Ok(());
    }
    if count > MAX_REPOSITORY_CACHE_ENTRIES {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    let deleted = sqlx::query(
        r"
        DELETE FROM github_actions_cache_entries
        WHERE id = (
            SELECT id
            FROM github_actions_cache_entries
            WHERE repository_id = $1 AND state = 'finalized'
            ORDER BY last_accessed_at_seconds ASC, finalized_at_seconds ASC, id ASC
            LIMIT 1
            FOR UPDATE
        )
        ",
    )
    .bind(repository_id)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    if deleted.rows_affected() != 1 {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    Ok(())
}

async fn evict_to_fit(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
    incoming_size: u64,
    quota: u64,
) -> Result<(), CacheRepositoryError> {
    if incoming_size > quota {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    let rows = sqlx::query(
        r"
        SELECT id, content_size_bytes
        FROM github_actions_cache_entries
        WHERE repository_id = $1 AND state = 'finalized'
        ORDER BY last_accessed_at_seconds ASC, finalized_at_seconds ASC, id ASC
        LIMIT $2
        FOR UPDATE
        ",
    )
    .bind(repository_id)
    .bind(CACHE_ENTRY_CENSUS_LIMIT)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    if rows.len() > MAX_REPOSITORY_CACHE_ENTRIES {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    let mut total = 0_u64;
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let size = nonnegative_u64(
            row.try_get::<i64, _>("content_size_bytes")
                .map_err(corrupt_error)?,
        )?;
        total = total
            .checked_add(size)
            .ok_or_else(|| error(CacheRepositoryErrorKind::CorruptData))?;
        candidates.push((row.try_get::<Uuid, _>("id").map_err(corrupt_error)?, size));
    }
    let mut index = 0_usize;
    while total
        .checked_add(incoming_size)
        .is_none_or(|projected| projected > quota)
    {
        let Some((entry_id, size)) = candidates.get(index).copied() else {
            return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
        };
        let deleted = sqlx::query(
            "DELETE FROM github_actions_cache_entries WHERE id = $1 AND state = 'finalized'",
        )
        .bind(entry_id)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
        if deleted.rows_affected() != 1 {
            return Err(error(CacheRepositoryErrorKind::Conflict));
        }
        total = total
            .checked_sub(size)
            .ok_or_else(|| error(CacheRepositoryErrorKind::CorruptData))?;
        index = index
            .checked_add(1)
            .ok_or_else(|| error(CacheRepositoryErrorKind::CorruptData))?;
    }
    Ok(())
}

fn decode_descriptor(row: &PgRow) -> Result<BlobDescriptor, CacheRepositoryError> {
    let key = BlobKey::new(
        row.try_get::<String, _>("object_key")
            .map_err(corrupt_error)?,
    )
    .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?;
    let digest = decode_digest(row.try_get::<Vec<u8>, _>("digest").map_err(corrupt_error)?)?;
    let size = nonnegative_u64(row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?)?;
    let media_type = MediaType::new(
        row.try_get::<String, _>("media_type")
            .map_err(corrupt_error)?,
    )
    .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?;
    Ok(BlobDescriptor::new(key, digest, size, media_type))
}

fn decode_digest(bytes: Vec<u8>) -> Result<Sha256Digest, CacheRepositoryError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn decode_entry_id(row: &PgRow) -> Result<CacheEntryId, CacheRepositoryError> {
    CacheEntryId::new(row.try_get::<Uuid, _>("id").map_err(corrupt_error)?)
        .map_err(|_| error(CacheRepositoryErrorKind::CorruptData))
}

async fn cache_database_now(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
) -> Result<u64, CacheRepositoryError> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(database_error)?;
    nonnegative_u64(database_now)
}

fn validate_cache_caller_clock(
    observed_at_seconds: u64,
    database_now: u64,
) -> Result<(), CacheRepositoryError> {
    if observed_at_seconds.abs_diff(database_now) > MAXIMUM_CACHE_CALLER_CLOCK_SKEW_SECONDS {
        return Err(error(CacheRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

fn validated_inactivity_seconds(inactivity_seconds: u64) -> Result<u64, CacheRepositoryError> {
    if inactivity_seconds == 0 || inactivity_seconds > i64::MAX as u64 {
        return Err(error(CacheRepositoryErrorKind::ResourceExhausted));
    }
    Ok(inactivity_seconds)
}

fn cache_inactivity_cutoff(
    database_now: u64,
    inactivity_seconds: u64,
) -> Result<i64, CacheRepositoryError> {
    seconds_i64(database_now.saturating_sub(inactivity_seconds))
}

fn cache_entry_is_live(
    entry: &LockedCacheEntry,
    database_now: u64,
    inactivity_seconds: u64,
) -> bool {
    entry.last_accessed_at_seconds > database_now.saturating_sub(inactivity_seconds)
}

fn seconds_i64(value: u64) -> Result<i64, CacheRepositoryError> {
    i64::try_from(value).map_err(|_| error(CacheRepositoryErrorKind::ResourceExhausted))
}

fn size_i64(value: u64) -> Result<i64, CacheRepositoryError> {
    i64::try_from(value).map_err(|_| error(CacheRepositoryErrorKind::ResourceExhausted))
}

fn fence_i64(value: FencingToken) -> Result<i64, CacheRepositoryError> {
    i64::try_from(value.get()).map_err(|_| error(CacheRepositoryErrorKind::CorruptData))
}

fn nonnegative_u64(value: i64) -> Result<u64, CacheRepositoryError> {
    u64::try_from(value).map_err(|_| error(CacheRepositoryErrorKind::CorruptData))
}

const fn error(kind: CacheRepositoryErrorKind) -> CacheRepositoryError {
    CacheRepositoryError::new(kind)
}

fn database_error(error: sqlx::Error) -> CacheRepositoryError {
    match error {
        sqlx::Error::Database(database) if database.is_unique_violation() => {
            CacheRepositoryError::new(CacheRepositoryErrorKind::Conflict)
        }
        _ => CacheRepositoryError::new(CacheRepositoryErrorKind::Unavailable),
    }
}

fn corrupt_error(_error: sqlx::Error) -> CacheRepositoryError {
    CacheRepositoryError::new(CacheRepositoryErrorKind::CorruptData)
}
