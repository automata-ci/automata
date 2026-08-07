use std::collections::HashMap;

use async_trait::async_trait;
use automata_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use sqlx::{PgPool, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    ArtifactBlock, ArtifactId, ArtifactName, ArtifactPublicationState, ArtifactRepository,
    ArtifactRepositoryError, ArtifactRepositoryErrorKind, CommitArtifactBlocks, CommittedArtifact,
    CreateArtifact, CreateArtifactOutcome, ExecutionAuthority, FinalizeArtifact,
    FinalizeArtifactOutcome, PublishedArtifact, StageArtifactBlock, UploadId,
};

const MAXIMUM_DURABLE_NAME_BYTES: usize = 255;
const ACTIVE_ARTIFACT_LIFECYCLES: &[&str] =
    &["leased", "preparing", "running", "cancelling", "finalizing"];

/// `PostgreSQL` coordination adapter for GitHub-compatible artifacts.
#[derive(Clone, Debug)]
pub struct PostgresArtifactRepository {
    pool: PgPool,
}

impl PostgresArtifactRepository {
    /// Binds artifact coordination to an existing product pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the underlying pool for adapter-level integration tests.
    #[must_use]
    pub const fn postgres_pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl ArtifactRepository for PostgresArtifactRepository {
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let scope = authorize_execution(&mut transaction, request.authority).await?;
        let expires_at = request.expires_at_seconds.map(seconds_to_i64).transpose()?;
        let inserted = sqlx::query(
            r"
            INSERT INTO workflow_artifacts (
                upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
                fencing_token, name, protocol_version, mime_type,
                expires_at_seconds, created_at_seconds
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (run_id, name) DO NOTHING
            RETURNING id, upload_id
            ",
        )
        .bind(request.upload_id.as_uuid())
        .bind(&scope.tenant_id)
        .bind(scope.repository_id)
        .bind(request.authority.run_id().as_uuid())
        .bind(request.authority.job_id().as_uuid())
        .bind(request.authority.attempt_id().as_uuid())
        .bind(fencing_to_i64(request.authority.fencing_token())?)
        .bind(request.name.as_str())
        .bind(request.version)
        .bind(&request.mime_type)
        .bind(expires_at)
        .bind(seconds_to_i64(request.observed_at_seconds)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;

        let outcome = if let Some(row) = inserted {
            decode_create_outcome(&row)?
        } else {
            let row = sqlx::query(
                r"
                SELECT id, upload_id, job_id, attempt_id, fencing_token,
                       protocol_version, mime_type, expires_at_seconds, state
                FROM workflow_artifacts
                WHERE run_id = $1 AND name = $2
                FOR UPDATE
                ",
            )
            .bind(request.authority.run_id().as_uuid())
            .bind(request.name.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(database_error)?
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::Unavailable))?;
            if row.try_get::<Uuid, _>("job_id").map_err(corrupt_error)?
                != request.authority.job_id().as_uuid()
                || row
                    .try_get::<Uuid, _>("attempt_id")
                    .map_err(corrupt_error)?
                    != request.authority.attempt_id().as_uuid()
                || row
                    .try_get::<i64, _>("fencing_token")
                    .map_err(corrupt_error)?
                    != fencing_to_i64(request.authority.fencing_token())?
                || row
                    .try_get::<i32, _>("protocol_version")
                    .map_err(corrupt_error)?
                    != request.version
                || row
                    .try_get::<String, _>("mime_type")
                    .map_err(corrupt_error)?
                    != request.mime_type
                || row
                    .try_get::<Option<i64>, _>("expires_at_seconds")
                    .map_err(corrupt_error)?
                    != expires_at
                || row.try_get::<String, _>("state").map_err(corrupt_error)? != "pending"
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            decode_create_outcome(&row)?
        };
        transaction.commit().await.map_err(database_error)?;
        Ok(outcome)
    }

    async fn authorize_upload(&self, upload_id: UploadId) -> Result<(), ArtifactRepositoryError> {
        let row = sqlx::query(
            r"
            SELECT artifact.state, artifact.fencing_token AS artifact_fencing_token,
                   attempt.fencing_token AS current_fencing_token,
                   attempt.lifecycle, attempt.lease_id
            FROM workflow_artifacts AS artifact
            JOIN job_attempts AS attempt ON attempt.id = artifact.attempt_id
            WHERE artifact.upload_id = $1
            ",
        )
        .bind(upload_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
        verify_locked_attempt(&row)?;
        if row.try_get::<String, _>("state").map_err(corrupt_error)? != "pending" {
            return Err(repository_error(ArtifactRepositoryErrorKind::InvalidState));
        }
        Ok(())
    }

    async fn record_block(
        &self,
        request: StageArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_upload(&mut transaction, request.upload_id).await?;
        require_pending(&artifact)?;
        if commit_exists(&mut transaction, artifact.artifact_id).await? {
            return Err(repository_error(ArtifactRepositoryErrorKind::InvalidState));
        }
        let encoded_length = i32::try_from(request.block.block_id().len())
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
        match artifact.block_id_encoded_length {
            Some(expected) if expected != encoded_length => {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            None => {
                sqlx::query(
                    "UPDATE workflow_artifacts SET block_id_encoded_length = $2 WHERE id = $1",
                )
                .bind(artifact.artifact_id.get())
                .bind(encoded_length)
                .execute(&mut *transaction)
                .await
                .map_err(database_error)?;
            }
            Some(_) => {}
        }

        let existing = sqlx::query(
            r"
            SELECT object_key, digest, size_bytes, media_type
            FROM workflow_artifact_blocks
            WHERE artifact_id = $1 AND block_id = $2
            ",
        )
        .bind(artifact.artifact_id.get())
        .bind(request.block.block_id())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        if let Some(row) = existing {
            let descriptor = decode_descriptor(&row)?;
            if descriptor != *request.block.descriptor() {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            transaction.commit().await.map_err(database_error)?;
            return Ok(());
        }

        let aggregate = sqlx::query(
            r"
            SELECT count(*) AS block_count,
                   coalesce(sum(size_bytes), 0)::bigint AS staged_bytes
            FROM workflow_artifact_blocks
            WHERE artifact_id = $1
            ",
        )
        .bind(artifact.artifact_id.get())
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?;
        let block_count = aggregate
            .try_get::<i64, _>("block_count")
            .map_err(corrupt_error)?;
        let staged_bytes = aggregate
            .try_get::<i64, _>("staged_bytes")
            .map_err(corrupt_error)?;
        let next_count = usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
        let next_size = u64::try_from(staged_bytes)
            .ok()
            .and_then(|size| size.checked_add(request.block.descriptor().size()))
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
        if next_count > request.maximum_blocks || next_size > request.maximum_staged_bytes {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }

        sqlx::query(
            r"
            INSERT INTO workflow_artifact_blocks (
                artifact_id, block_id, object_key, digest, size_bytes,
                media_type, staged_at_seconds
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(artifact.artifact_id.get())
        .bind(request.block.block_id())
        .bind(request.block.descriptor().key().as_str())
        .bind(request.block.descriptor().digest().as_bytes().as_slice())
        .bind(size_to_i64(request.block.descriptor().size())?)
        .bind(request.block.descriptor().media_type().as_str())
        .bind(seconds_to_i64(request.observed_at_seconds)?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        if request.block_ids.len() > request.maximum_blocks {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_upload(&mut transaction, request.upload_id).await?;
        require_pending(&artifact)?;

        if let Some(row) = sqlx::query(
            r"
            SELECT list_digest, block_ids, size_bytes
            FROM workflow_artifact_block_commits
            WHERE artifact_id = $1
            FOR UPDATE
            ",
        )
        .bind(artifact.artifact_id.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        {
            let digest = decode_digest(
                row.try_get::<Vec<u8>, _>("list_digest")
                    .map_err(corrupt_error)?,
            )?;
            let block_ids = row
                .try_get::<Vec<String>, _>("block_ids")
                .map_err(corrupt_error)?;
            let size = nonnegative_i64_to_u64(
                row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?,
            )?;
            if digest != request.list_digest || block_ids != request.block_ids {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            let blocks =
                load_ordered_blocks(&mut transaction, artifact.artifact_id, &request.block_ids)
                    .await?;
            transaction.commit().await.map_err(database_error)?;
            return Ok(artifact.committed(blocks, size));
        }

        let blocks =
            load_ordered_blocks(&mut transaction, artifact.artifact_id, &request.block_ids).await?;
        let size = blocks.iter().try_fold(0_u64, |total, block| {
            total
                .checked_add(block.descriptor().size())
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::ResourceExhausted))
        })?;
        if size > request.maximum_artifact_bytes {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }
        sqlx::query(
            r"
            INSERT INTO workflow_artifact_block_commits (
                artifact_id, list_digest, block_ids, size_bytes, committed_at_seconds
            )
            VALUES ($1, $2, $3, $4, $5)
            ",
        )
        .bind(artifact.artifact_id.get())
        .bind(request.list_digest.as_bytes().as_slice())
        .bind(&request.block_ids)
        .bind(size_to_i64(size)?)
        .bind(seconds_to_i64(request.observed_at_seconds)?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        transaction.commit().await.map_err(database_error)?;
        Ok(artifact.committed(blocks, size))
    }

    async fn publication_state(
        &self,
        authority: ExecutionAuthority,
        name: &ArtifactName,
    ) -> Result<ArtifactPublicationState, ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_named_artifact(&mut transaction, authority, name).await?;
        let state = if artifact.state == "finalized" {
            ArtifactPublicationState::Published(artifact.published()?)
        } else if artifact.state == "pending" {
            let row = sqlx::query(
                r"
                SELECT block_ids, size_bytes
                FROM workflow_artifact_block_commits
                WHERE artifact_id = $1
                ",
            )
            .bind(artifact.artifact_id.get())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(database_error)?
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::InvalidState))?;
            let block_ids = row
                .try_get::<Vec<String>, _>("block_ids")
                .map_err(corrupt_error)?;
            let size = nonnegative_i64_to_u64(
                row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?,
            )?;
            let blocks =
                load_ordered_blocks(&mut transaction, artifact.artifact_id, &block_ids).await?;
            ArtifactPublicationState::Committed(artifact.committed(blocks, size))
        } else {
            return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
        };
        transaction.commit().await.map_err(database_error)?;
        Ok(state)
    }

    async fn finalize(
        &self,
        request: FinalizeArtifact,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact =
            lock_named_artifact(&mut transaction, request.authority, &request.name).await?;
        if artifact.state == "finalized" {
            let published = artifact.published()?;
            if published.content_digest != request.content_digest
                || published.size != request.size
                || published.manifest != request.manifest
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            transaction.commit().await.map_err(database_error)?;
            return Ok(FinalizeArtifactOutcome {
                artifact_id: published.artifact_id,
                content_digest: published.content_digest,
                size: published.size,
            });
        }
        require_pending(&artifact)?;
        let commit = sqlx::query(
            r"
            SELECT size_bytes
            FROM workflow_artifact_block_commits
            WHERE artifact_id = $1
            FOR UPDATE
            ",
        )
        .bind(artifact.artifact_id.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::InvalidState))?;
        let committed_size = nonnegative_i64_to_u64(
            commit
                .try_get::<i64, _>("size_bytes")
                .map_err(corrupt_error)?,
        )?;
        if committed_size != request.size {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        let updated = sqlx::query(
            r"
            UPDATE workflow_artifacts
            SET state = 'finalized',
                content_digest = $2,
                content_size_bytes = $3,
                manifest_object_key = $4,
                manifest_digest = $5,
                manifest_size_bytes = $6,
                manifest_media_type = $7,
                finalized_at_seconds = $8
            WHERE id = $1 AND state = 'pending'
            ",
        )
        .bind(artifact.artifact_id.get())
        .bind(request.content_digest.as_bytes().as_slice())
        .bind(size_to_i64(request.size)?)
        .bind(request.manifest.key().as_str())
        .bind(request.manifest.digest().as_bytes().as_slice())
        .bind(size_to_i64(request.manifest.size())?)
        .bind(request.manifest.media_type().as_str())
        .bind(seconds_to_i64(request.observed_at_seconds)?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        if updated.rows_affected() != 1 {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        transaction.commit().await.map_err(database_error)?;
        Ok(FinalizeArtifactOutcome {
            artifact_id: artifact.artifact_id,
            content_digest: request.content_digest,
            size: request.size,
        })
    }
}

#[derive(Debug)]
struct ExecutionScope {
    tenant_id: String,
    repository_id: Uuid,
}

async fn authorize_execution(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    authority: ExecutionAuthority,
) -> Result<ExecutionScope, ArtifactRepositoryError> {
    let row = sqlx::query(
        r"
        SELECT repository.tenant_id, run.repository_id, attempt.lifecycle,
               attempt.lease_id, attempt.fencing_token AS current_fencing_token
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE run.id = $1 AND job.id = $2 AND attempt.id = $3
        FOR SHARE OF attempt
        ",
    )
    .bind(authority.run_id().as_uuid())
    .bind(authority.job_id().as_uuid())
    .bind(authority.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::Unauthorized))?;
    verify_authority_row(&row, authority.fencing_token())?;
    Ok(ExecutionScope {
        tenant_id: row
            .try_get::<String, _>("tenant_id")
            .map_err(corrupt_error)?,
        repository_id: row
            .try_get::<Uuid, _>("repository_id")
            .map_err(corrupt_error)?,
    })
}

#[derive(Debug)]
struct LockedArtifact {
    artifact_id: ArtifactId,
    upload_id: UploadId,
    authority: ExecutionAuthority,
    name: ArtifactName,
    mime_type: String,
    block_id_encoded_length: Option<i32>,
    state: String,
    content_digest: Option<Vec<u8>>,
    content_size_bytes: Option<i64>,
    manifest_object_key: Option<String>,
    manifest_digest: Option<Vec<u8>>,
    manifest_size_bytes: Option<i64>,
    manifest_media_type: Option<String>,
}

impl LockedArtifact {
    fn committed(self, blocks: Vec<ArtifactBlock>, size: u64) -> CommittedArtifact {
        CommittedArtifact {
            artifact_id: self.artifact_id,
            upload_id: self.upload_id,
            authority: self.authority,
            name: self.name,
            mime_type: self.mime_type,
            blocks,
            size,
        }
    }

    fn published(&self) -> Result<PublishedArtifact, ArtifactRepositoryError> {
        let descriptor = decode_descriptor_parts(
            self.manifest_object_key
                .clone()
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
            self.manifest_digest
                .clone()
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
            self.manifest_size_bytes
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
            self.manifest_media_type
                .clone()
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        )?;
        Ok(PublishedArtifact {
            artifact_id: self.artifact_id,
            content_digest: decode_digest(
                self.content_digest
                    .clone()
                    .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
            )?,
            size: nonnegative_i64_to_u64(
                self.content_size_bytes
                    .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
            )?,
            manifest: descriptor,
        })
    }
}

async fn lock_upload(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    upload_id: UploadId,
) -> Result<LockedArtifact, ArtifactRepositoryError> {
    let row = artifact_lock_query("artifact.upload_id = $1")
        .bind(upload_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
    decode_locked_artifact(&row, None)
}

async fn lock_named_artifact(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    authority: ExecutionAuthority,
    name: &ArtifactName,
) -> Result<LockedArtifact, ArtifactRepositoryError> {
    let row = artifact_lock_query("artifact.run_id = $1 AND artifact.name = $2")
        .bind(authority.run_id().as_uuid())
        .bind(name.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
    decode_locked_artifact(&row, Some(authority))
}

fn artifact_lock_query(
    predicate: &str,
) -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments> {
    // The predicate is selected only from the two fixed call sites above.
    let statement = match predicate {
        "artifact.upload_id = $1" => ARTIFACT_BY_UPLOAD_FOR_UPDATE,
        "artifact.run_id = $1 AND artifact.name = $2" => ARTIFACT_BY_NAME_FOR_UPDATE,
        _ => unreachable!("artifact lock query predicate is internal"),
    };
    sqlx::query(statement)
}

const ARTIFACT_BY_UPLOAD_FOR_UPDATE: &str = concat!(
    "SELECT artifact.id, artifact.upload_id, artifact.run_id, artifact.job_id, ",
    "artifact.attempt_id, artifact.fencing_token AS artifact_fencing_token, ",
    "artifact.name, artifact.mime_type, artifact.block_id_encoded_length, ",
    "artifact.state, artifact.content_digest, artifact.content_size_bytes, ",
    "artifact.manifest_object_key, artifact.manifest_digest, ",
    "artifact.manifest_size_bytes, artifact.manifest_media_type, ",
    "attempt.fencing_token AS current_fencing_token, attempt.lifecycle, attempt.lease_id ",
    "FROM workflow_artifacts AS artifact ",
    "JOIN job_attempts AS attempt ON attempt.id = artifact.attempt_id ",
    "WHERE artifact.upload_id = $1 FOR UPDATE OF artifact, attempt"
);

const ARTIFACT_BY_NAME_FOR_UPDATE: &str = concat!(
    "SELECT artifact.id, artifact.upload_id, artifact.run_id, artifact.job_id, ",
    "artifact.attempt_id, artifact.fencing_token AS artifact_fencing_token, ",
    "artifact.name, artifact.mime_type, artifact.block_id_encoded_length, ",
    "artifact.state, artifact.content_digest, artifact.content_size_bytes, ",
    "artifact.manifest_object_key, artifact.manifest_digest, ",
    "artifact.manifest_size_bytes, artifact.manifest_media_type, ",
    "attempt.fencing_token AS current_fencing_token, attempt.lifecycle, attempt.lease_id ",
    "FROM workflow_artifacts AS artifact ",
    "JOIN job_attempts AS attempt ON attempt.id = artifact.attempt_id ",
    "WHERE artifact.run_id = $1 AND artifact.name = $2 FOR UPDATE OF artifact, attempt"
);

fn decode_locked_artifact(
    row: &sqlx::postgres::PgRow,
    required_authority: Option<ExecutionAuthority>,
) -> Result<LockedArtifact, ArtifactRepositoryError> {
    verify_locked_attempt(row)?;
    let authority = ExecutionAuthority::new(
        RunId::from_uuid(row.try_get::<Uuid, _>("run_id").map_err(corrupt_error)?),
        JobId::from_uuid(row.try_get::<Uuid, _>("job_id").map_err(corrupt_error)?),
        AttemptId::from_uuid(
            row.try_get::<Uuid, _>("attempt_id")
                .map_err(corrupt_error)?,
        ),
        FencingToken::new(
            u64::try_from(
                row.try_get::<i64, _>("artifact_fencing_token")
                    .map_err(corrupt_error)?,
            )
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        )
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
    );
    if required_authority.is_some_and(|required| required != authority) {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(LockedArtifact {
        artifact_id: ArtifactId::new(row.try_get::<i64, _>("id").map_err(corrupt_error)?)
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        upload_id: UploadId::from_uuid(row.try_get::<Uuid, _>("upload_id").map_err(corrupt_error)?),
        authority,
        name: ArtifactName::new(
            row.try_get::<String, _>("name").map_err(corrupt_error)?,
            MAXIMUM_DURABLE_NAME_BYTES,
        )
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        mime_type: row
            .try_get::<String, _>("mime_type")
            .map_err(corrupt_error)?,
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
        manifest_object_key: row
            .try_get::<Option<String>, _>("manifest_object_key")
            .map_err(corrupt_error)?,
        manifest_digest: row
            .try_get::<Option<Vec<u8>>, _>("manifest_digest")
            .map_err(corrupt_error)?,
        manifest_size_bytes: row
            .try_get::<Option<i64>, _>("manifest_size_bytes")
            .map_err(corrupt_error)?,
        manifest_media_type: row
            .try_get::<Option<String>, _>("manifest_media_type")
            .map_err(corrupt_error)?,
    })
}

fn verify_locked_attempt(row: &sqlx::postgres::PgRow) -> Result<(), ArtifactRepositoryError> {
    let artifact_fence = row
        .try_get::<i64, _>("artifact_fencing_token")
        .map_err(corrupt_error)?;
    let current_fence = row
        .try_get::<i64, _>("current_fencing_token")
        .map_err(corrupt_error)?;
    let lifecycle = row
        .try_get::<String, _>("lifecycle")
        .map_err(corrupt_error)?;
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(corrupt_error)?;
    if artifact_fence != current_fence
        || !ACTIVE_ARTIFACT_LIFECYCLES.contains(&lifecycle.as_str())
        || lease_id.is_none()
    {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

fn verify_authority_row(
    row: &sqlx::postgres::PgRow,
    expected_fence: FencingToken,
) -> Result<(), ArtifactRepositoryError> {
    let current_fence = row
        .try_get::<i64, _>("current_fencing_token")
        .map_err(corrupt_error)?;
    let lifecycle = row
        .try_get::<String, _>("lifecycle")
        .map_err(corrupt_error)?;
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(corrupt_error)?;
    if current_fence != fencing_to_i64(expected_fence)?
        || !ACTIVE_ARTIFACT_LIFECYCLES.contains(&lifecycle.as_str())
        || lease_id.is_none()
    {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

fn require_pending(artifact: &LockedArtifact) -> Result<(), ArtifactRepositoryError> {
    if artifact.state != "pending" {
        return Err(repository_error(ArtifactRepositoryErrorKind::InvalidState));
    }
    Ok(())
}

async fn commit_exists(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact_id: ArtifactId,
) -> Result<bool, ArtifactRepositoryError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM workflow_artifact_block_commits WHERE artifact_id = $1)",
    )
    .bind(artifact_id.get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)
}

async fn load_ordered_blocks(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact_id: ArtifactId,
    block_ids: &[String],
) -> Result<Vec<ArtifactBlock>, ArtifactRepositoryError> {
    if block_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        r"
        SELECT block_id, object_key, digest, size_bytes, media_type
        FROM workflow_artifact_blocks
        WHERE artifact_id = $1 AND block_id = ANY($2)
        ",
    )
    .bind(artifact_id.get())
    .bind(block_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    let mut by_id = HashMap::with_capacity(rows.len());
    for row in rows {
        let block_id = row
            .try_get::<String, _>("block_id")
            .map_err(corrupt_error)?;
        let descriptor = decode_descriptor(&row)?;
        if by_id
            .insert(block_id.clone(), ArtifactBlock::new(block_id, descriptor))
            .is_some()
        {
            return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
        }
    }
    block_ids
        .iter()
        .map(|block_id| {
            by_id
                .get(block_id)
                .cloned()
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))
        })
        .collect()
}

fn decode_create_outcome(
    row: &sqlx::postgres::PgRow,
) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
    Ok(CreateArtifactOutcome {
        artifact_id: ArtifactId::new(row.try_get::<i64, _>("id").map_err(corrupt_error)?)
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        upload_id: UploadId::from_uuid(row.try_get::<Uuid, _>("upload_id").map_err(corrupt_error)?),
    })
}

fn decode_descriptor(
    row: &sqlx::postgres::PgRow,
) -> Result<BlobDescriptor, ArtifactRepositoryError> {
    decode_descriptor_parts(
        row.try_get::<String, _>("object_key")
            .map_err(corrupt_error)?,
        row.try_get::<Vec<u8>, _>("digest").map_err(corrupt_error)?,
        row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?,
        row.try_get::<String, _>("media_type")
            .map_err(corrupt_error)?,
    )
}

fn decode_descriptor_parts(
    key: String,
    digest: Vec<u8>,
    size: i64,
    media_type: String,
) -> Result<BlobDescriptor, ArtifactRepositoryError> {
    Ok(BlobDescriptor::new(
        BlobKey::new(key)
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        decode_digest(digest)?,
        nonnegative_i64_to_u64(size)?,
        MediaType::new(media_type)
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
    ))
}

fn decode_digest(bytes: Vec<u8>) -> Result<Sha256Digest, ArtifactRepositoryError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn seconds_to_i64(seconds: u64) -> Result<i64, ArtifactRepositoryError> {
    i64::try_from(seconds).map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))
}

fn size_to_i64(size: u64) -> Result<i64, ArtifactRepositoryError> {
    i64::try_from(size)
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::ResourceExhausted))
}

fn nonnegative_i64_to_u64(value: i64) -> Result<u64, ArtifactRepositoryError> {
    u64::try_from(value).map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))
}

fn fencing_to_i64(fencing_token: FencingToken) -> Result<i64, ArtifactRepositoryError> {
    i64::try_from(fencing_token.get())
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))
}

fn repository_error(kind: ArtifactRepositoryErrorKind) -> ArtifactRepositoryError {
    ArtifactRepositoryError::new(kind)
}

fn database_error(_error: sqlx::Error) -> ArtifactRepositoryError {
    repository_error(ArtifactRepositoryErrorKind::Unavailable)
}

fn corrupt_error(_error: sqlx::Error) -> ArtifactRepositoryError {
    repository_error(ArtifactRepositoryErrorKind::CorruptData)
}
