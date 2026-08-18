use std::collections::HashMap;

use async_trait::async_trait;
use automata_ci_blob::{BlobDescriptor, BlobKey, BlobPayload, MediaType};
use automata_ci_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use automata_ci_store::HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA;
use bytes::Bytes;
use sqlx::{PgPool, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    ARTIFACT_MANIFEST_MEDIA_TYPE, ArtifactBlock, ArtifactBlockReservation,
    ArtifactFinalizationClaim, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    ArtifactId, ArtifactManifest, ArtifactName, ArtifactRepository, ArtifactRepositoryError,
    ArtifactRepositoryErrorKind, BeginArtifactFinalization, CommitArtifactBlocks,
    CommittedArtifact, CompleteArtifactBlock, CompleteArtifactFinalization, CreateArtifact,
    CreateArtifactOutcome, ExecutionAuthority, FinalizeArtifactOutcome, ListArtifacts,
    LoadArtifactFinalization, MAXIMUM_ARTIFACT_FINALIZATION_LEASE_SECONDS,
    MAXIMUM_ARTIFACT_MANIFEST_BYTES, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload, UploadId,
    VerifiedArtifactFinalization,
};

const MAXIMUM_DURABLE_NAME_BYTES: usize = 255;
const MAXIMUM_FINALIZATION_CALLER_CLOCK_SKEW_SECONDS: u64 = 60;
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
        let existing = sqlx::query(
            r"
            SELECT id, upload_id, job_id, attempt_id, fencing_token,
                   protocol_version, mime_type, expires_at_seconds, state,
                   secret_exposure_class, requested_visibility,
                   effective_visibility, publication_safety_reason,
                   publication_safety_schema
            FROM workflow_artifacts
            WHERE run_id = $1 AND name = $2
            FOR UPDATE
            ",
        )
        .bind(request.authority.run_id().as_uuid())
        .bind(request.name.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        if let Some(row) = existing {
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
            scope.safety.require_exact_persisted_snapshot(&row)?;
            let outcome = decode_create_outcome(&row)?;
            transaction.commit().await.map_err(database_error)?;
            return Ok(outcome);
        }

        let artifact_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM workflow_artifacts WHERE run_id = $1",
        )
        .bind(request.authority.run_id().as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?;
        if usize::try_from(artifact_count)
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?
            >= request.maximum_artifacts_per_run
        {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }

        let outcome = insert_new_artifact(&mut transaction, &request, &scope, expires_at).await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(outcome)
    }

    async fn reserve_block(
        &self,
        request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
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
            SELECT object_key, digest, size_bytes, media_type, state
            FROM workflow_artifact_blocks
            WHERE artifact_id = $1 AND block_id = $2
            FOR UPDATE
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
            let reservation = match row
                .try_get::<String, _>("state")
                .map_err(corrupt_error)?
                .as_str()
            {
                "ready" => ArtifactBlockReservation::Ready,
                "reserved" => ArtifactBlockReservation::UploadRequired,
                _ => return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData)),
            };
            transaction.commit().await.map_err(database_error)?;
            return Ok(reservation);
        }

        reserve_new_block(&mut transaction, &artifact, &request).await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(ArtifactBlockReservation::UploadRequired)
    }

    async fn complete_block(
        &self,
        request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_upload(&mut transaction, request.upload_id).await?;
        require_pending(&artifact)?;
        if commit_exists(&mut transaction, artifact.artifact_id).await? {
            return Err(repository_error(ArtifactRepositoryErrorKind::InvalidState));
        }
        let row = sqlx::query(
            r"
            SELECT object_key, digest, size_bytes, media_type, state
            FROM workflow_artifact_blocks
            WHERE artifact_id = $1 AND block_id = $2
            FOR UPDATE
            ",
        )
        .bind(artifact.artifact_id.get())
        .bind(request.block.block_id())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
        if decode_descriptor(&row)? != *request.block.descriptor() {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        match row
            .try_get::<String, _>("state")
            .map_err(corrupt_error)?
            .as_str()
        {
            "ready" => {}
            "reserved" => {
                let updated = sqlx::query(
                    r"
                    UPDATE workflow_artifact_blocks
                    SET state = 'ready',
                        ready_at_seconds = greatest($3, staged_at_seconds)
                    WHERE artifact_id = $1 AND block_id = $2 AND state = 'reserved'
                    ",
                )
                .bind(artifact.artifact_id.get())
                .bind(request.block.block_id())
                .bind(seconds_to_i64(request.observed_at_seconds)?)
                .execute(&mut *transaction)
                .await
                .map_err(database_error)?;
                if updated.rows_affected() != 1 {
                    return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
                }
            }
            _ => return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData)),
        }
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

    async fn begin_finalization(
        &self,
        request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        validate_finalization_lease(request.lease_seconds)?;
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact =
            lock_named_artifact(&mut transaction, request.authority, &request.name).await?;
        if artifact.state == "finalized" {
            let verified = load_verified_finalization(&mut transaction, &artifact).await?;
            validate_finalization_caller_clock(
                request.observed_at_seconds,
                finalization_database_now(&mut transaction).await?,
            )?;
            let outcome = FinalizeArtifactOutcome {
                artifact_id: verified.artifact_id,
                content_digest: verified.content_digest,
                size: verified.size,
            };
            if outcome.size != request.claimed_size
                || request
                    .claimed_digest
                    .is_some_and(|digest| digest != outcome.content_digest)
            {
                return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
            }
            transaction.commit().await.map_err(database_error)?;
            return Ok(ArtifactFinalizationReservation::Published(outcome));
        }
        require_pending(&artifact)?;
        let (_, committed_size) = load_commit(&mut transaction, artifact.artifact_id, true).await?;
        let database_now = finalization_database_now(&mut transaction).await?;
        validate_finalization_caller_clock(request.observed_at_seconds, database_now)?;
        if committed_size != request.claimed_size {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }

        if artifact.finalization_generation > 0 {
            let expires_at = artifact.finalization_expiry()?;
            let exact_request = artifact.finalization_claimed_size()? == request.claimed_size
                && artifact.finalization_claimed_digest()? == request.claimed_digest;
            if expires_at > database_now {
                if !exact_request {
                    return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
                }
                transaction.commit().await.map_err(database_error)?;
                return Ok(ArtifactFinalizationReservation::InProgress {
                    retry_at_seconds: expires_at,
                });
            }
            if artifact.manifest_state.as_deref() == Some("reserved") {
                let verified_digest = artifact.content_digest()?;
                if request
                    .claimed_digest
                    .is_some_and(|digest| digest != verified_digest)
                {
                    return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
                }
            }
        }

        let generation = artifact
            .finalization_generation
            .checked_add(1)
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::ResourceExhausted))?;
        replace_expired_finalization_claim(&mut transaction, &artifact, &request, generation)
            .await?;
        let claim = ArtifactFinalizationClaim::new(
            artifact.artifact_id,
            request.authority,
            request.name,
            generation,
        );
        transaction.commit().await.map_err(database_error)?;
        Ok(ArtifactFinalizationReservation::Claimed(claim))
    }

    async fn load_finalization(
        &self,
        request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_claimed_artifact(&mut transaction, &request.claim).await?;
        let database_now = finalization_database_now(&mut transaction).await?;
        validate_finalization_caller_clock(request.observed_at_seconds, database_now)?;
        require_live_claim(&artifact, &request.claim, database_now)?;
        require_pending(&artifact)?;
        let (block_ids, size) = load_commit(&mut transaction, artifact.artifact_id, false).await?;
        let blocks =
            load_ordered_blocks(&mut transaction, artifact.artifact_id, &block_ids).await?;
        let committed = artifact.committed(blocks, size);
        let work = match artifact.manifest_state.as_deref() {
            None => ArtifactFinalizationWork::Verify(committed),
            Some("reserved") => ArtifactFinalizationWork::Publish(artifact.verified(&committed)?),
            Some(_) => return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData)),
        };
        require_live_claim(
            &artifact,
            &request.claim,
            finalization_database_now(&mut transaction).await?,
        )?;
        transaction.commit().await.map_err(database_error)?;
        Ok(work)
    }

    async fn renew_finalization(
        &self,
        request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        validate_finalization_lease(request.lease_seconds)?;
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_claimed_artifact(&mut transaction, &request.claim).await?;
        require_pending(&artifact)?;
        let database_now = finalization_database_now(&mut transaction).await?;
        validate_finalization_caller_clock(request.observed_at_seconds, database_now)?;
        require_live_claim(&artifact, &request.claim, database_now)?;
        update_claim_expiry(
            &mut transaction,
            artifact.artifact_id,
            request.claim.generation(),
            request.lease_seconds,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn record_verification(
        &self,
        request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        validate_finalization_lease(request.lease_seconds)?;
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_claimed_artifact(&mut transaction, &request.claim).await?;
        require_pending(&artifact)?;
        validate_manifest_payload(
            request.claim.artifact_id(),
            request.content_digest,
            &request.manifest,
            &request.manifest_bytes,
        )?;
        let (block_ids, size) = load_commit(&mut transaction, artifact.artifact_id, true).await?;
        let database_now = finalization_database_now(&mut transaction).await?;
        validate_finalization_caller_clock(request.observed_at_seconds, database_now)?;
        require_live_claim(&artifact, &request.claim, database_now)?;
        let blocks =
            load_ordered_blocks(&mut transaction, artifact.artifact_id, &block_ids).await?;
        let committed = artifact.committed(blocks, size);
        if artifact.finalization_claimed_size()? != size
            || artifact
                .finalization_claimed_digest()?
                .is_some_and(|digest| digest != request.content_digest)
        {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }
        let canonical = serde_json::to_vec(&ArtifactManifest::from_committed(
            &committed,
            request.content_digest,
        ))
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
        if canonical != request.manifest_bytes {
            return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
        }

        match artifact.manifest_state.as_deref() {
            None => {
                reserve_verified_manifest(&mut transaction, &artifact, &request, size).await?;
            }
            Some("reserved") => {
                let existing = artifact.verified(&committed)?;
                if existing.content_digest != request.content_digest
                    || existing.manifest != request.manifest
                    || existing.manifest_bytes != request.manifest_bytes
                {
                    return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
                }
                update_claim_expiry(
                    &mut transaction,
                    artifact.artifact_id,
                    request.claim.generation(),
                    request.lease_seconds,
                )
                .await?;
            }
            Some(_) => return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData)),
        }
        transaction.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn complete_finalization(
        &self,
        request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        let artifact = lock_claimed_artifact(&mut transaction, &request.claim).await?;
        if artifact.state == "finalized" {
            if artifact.finalization_generation != request.claim.generation() {
                return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
            }
            let verified = load_verified_finalization(&mut transaction, &artifact).await?;
            validate_finalization_caller_clock(
                request.observed_at_seconds,
                finalization_database_now(&mut transaction).await?,
            )?;
            let outcome = FinalizeArtifactOutcome {
                artifact_id: verified.artifact_id,
                content_digest: verified.content_digest,
                size: verified.size,
            };
            transaction.commit().await.map_err(database_error)?;
            return Ok(outcome);
        }
        require_pending(&artifact)?;
        if artifact.manifest_state.as_deref() != Some("reserved") {
            return Err(repository_error(ArtifactRepositoryErrorKind::InvalidState));
        }
        let verified = load_verified_finalization(&mut transaction, &artifact).await?;
        let database_now = finalization_database_now(&mut transaction).await?;
        validate_finalization_caller_clock(request.observed_at_seconds, database_now)?;
        require_live_claim(&artifact, &request.claim, database_now)?;
        let updated = sqlx::query(
            r"
            WITH database_clock AS MATERIALIZED (
                SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
            )
            UPDATE workflow_artifacts AS artifact
            SET state = 'finalized',
                manifest_state = 'ready',
                finalized_at_seconds = greatest(
                    database_clock.now_seconds,
                    artifact.manifest_reserved_at_seconds
                )
            FROM database_clock
            WHERE artifact.id = $1
              AND artifact.finalization_generation = $2
              AND artifact.state = 'pending'
              AND artifact.manifest_state = 'reserved'
              AND artifact.finalization_claim_expires_at_seconds
                    > database_clock.now_seconds
            ",
        )
        .bind(artifact.artifact_id.get())
        .bind(u64_to_i64(request.claim.generation())?)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        if updated.rows_affected() != 1 {
            return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
        }
        let outcome = FinalizeArtifactOutcome {
            artifact_id: artifact.artifact_id,
            content_digest: verified.content_digest,
            size: verified.size,
        };
        transaction.commit().await.map_err(database_error)?;
        Ok(outcome)
    }

    async fn list(
        &self,
        request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        if request.maximum_results == 0 {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }
        let fetch_limit = request
            .maximum_results
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::ResourceExhausted))?;
        let observed_at = seconds_to_i64(request.observed_at_seconds)?;
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        authorize_execution(&mut transaction, request.authority).await?;
        let rows = sqlx::query(
            r"
            SELECT id, upload_id, run_id, job_id, attempt_id, fencing_token,
                   name, mime_type, content_digest, content_size_bytes,
                   manifest_object_key, manifest_digest, manifest_size_bytes,
                   manifest_media_type, created_at_seconds, expires_at_seconds
            FROM workflow_artifacts
            WHERE run_id = $1
              AND state = 'finalized'
              AND manifest_state = 'ready'
              AND (expires_at_seconds IS NULL OR expires_at_seconds > $2)
              AND ($3::text IS NULL OR name = $3)
              AND ($4::bigint IS NULL OR id = $4)
            ORDER BY id DESC
            LIMIT $5
            ",
        )
        .bind(request.authority.run_id().as_uuid())
        .bind(observed_at)
        .bind(request.name.as_ref().map(ArtifactName::as_str))
        .bind(request.artifact_id.map(ArtifactId::get))
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(database_error)?;
        if rows.len() > request.maximum_results {
            return Err(repository_error(
                ArtifactRepositoryErrorKind::ResourceExhausted,
            ));
        }
        let artifacts = rows
            .iter()
            .map(decode_published_metadata)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await.map_err(database_error)?;
        Ok(artifacts)
    }

    async fn resolve_download(
        &self,
        request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        let row = sqlx::query(
            r"
            SELECT id, upload_id, run_id, job_id, attempt_id, fencing_token,
                   name, mime_type, content_digest, content_size_bytes,
                   manifest_object_key, manifest_digest, manifest_size_bytes,
                   manifest_media_type, created_at_seconds, expires_at_seconds
            FROM workflow_artifacts
            WHERE id = $1
              AND content_digest = $2
              AND state = 'finalized'
              AND manifest_state = 'ready'
              AND (expires_at_seconds IS NULL OR expires_at_seconds > $3)
            ",
        )
        .bind(request.artifact_id.get())
        .bind(request.content_digest.as_bytes().as_slice())
        .bind(seconds_to_i64(request.observed_at_seconds)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
        decode_published_metadata(&row)
    }
}

#[derive(Debug)]
struct ExecutionScope {
    tenant_id: String,
    repository_id: Uuid,
    safety: ArtifactSafetySnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactSecretExposure {
    Secretless,
    CapabilityOnly,
    ReadableSecret,
}

impl ArtifactSecretExposure {
    fn parse(value: &str) -> Result<Self, ArtifactRepositoryError> {
        match value {
            "secretless" => Ok(Self::Secretless),
            "capability_only" => Ok(Self::CapabilityOnly),
            "readable_secret" => Ok(Self::ReadableSecret),
            _ => Err(repository_error(ArtifactRepositoryErrorKind::CorruptData)),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Secretless => "secretless",
            Self::CapabilityOnly => "capability_only",
            Self::ReadableSecret => "readable_secret",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactVisibility {
    Private,
    Authenticated,
    Public,
}

impl ArtifactVisibility {
    fn parse(value: &str) -> Result<Self, ArtifactRepositoryError> {
        match value {
            "private" => Ok(Self::Private),
            "authenticated" => Ok(Self::Authenticated),
            "public" => Ok(Self::Public),
            _ => Err(repository_error(ArtifactRepositoryErrorKind::CorruptData)),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Authenticated => "authenticated",
            Self::Public => "public",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactSafetySnapshot {
    secret_exposure: ArtifactSecretExposure,
    requested_visibility: ArtifactVisibility,
}

impl ArtifactSafetySnapshot {
    fn from_authority_row(row: &sqlx::postgres::PgRow) -> Result<Self, ArtifactRepositoryError> {
        Ok(Self {
            secret_exposure: ArtifactSecretExposure::parse(
                &row.try_get::<String, _>("secret_exposure_class")
                    .map_err(corrupt_error)?,
            )?,
            requested_visibility: ArtifactVisibility::parse(
                &row.try_get::<String, _>("requested_artifact_visibility")
                    .map_err(corrupt_error)?,
            )?,
        })
    }

    const fn secret_exposure_class(self) -> &'static str {
        self.secret_exposure.as_str()
    }

    const fn requested_visibility(self) -> &'static str {
        self.requested_visibility.as_str()
    }

    const fn effective_visibility(self) -> &'static str {
        if matches!(self.secret_exposure, ArtifactSecretExposure::ReadableSecret) {
            ArtifactVisibility::Private.as_str()
        } else {
            self.requested_visibility.as_str()
        }
    }

    const fn publication_safety_reason(self) -> &'static str {
        if matches!(self.secret_exposure, ArtifactSecretExposure::ReadableSecret)
            && !matches!(self.requested_visibility, ArtifactVisibility::Private)
        {
            "secret_exposure"
        } else {
            "repository_policy"
        }
    }

    fn require_exact_persisted_snapshot(
        self,
        row: &sqlx::postgres::PgRow,
    ) -> Result<(), ArtifactRepositoryError> {
        let exact = row
            .try_get::<String, _>("secret_exposure_class")
            .map_err(corrupt_error)?
            == self.secret_exposure_class()
            && row
                .try_get::<String, _>("requested_visibility")
                .map_err(corrupt_error)?
                == self.requested_visibility()
            && row
                .try_get::<String, _>("effective_visibility")
                .map_err(corrupt_error)?
                == self.effective_visibility()
            && row
                .try_get::<String, _>("publication_safety_reason")
                .map_err(corrupt_error)?
                == self.publication_safety_reason()
            && row
                .try_get::<i32, _>("publication_safety_schema")
                .map_err(corrupt_error)?
                == HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA;
        if !exact {
            return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
        }
        Ok(())
    }
}

async fn lock_run(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    run_id: RunId,
    missing: ArtifactRepositoryErrorKind,
) -> Result<(), ArtifactRepositoryError> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM workflow_runs WHERE id = $1 FOR UPDATE")
        .bind(run_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(missing))?;
    Ok(())
}

async fn authorize_execution(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    authority: ExecutionAuthority,
) -> Result<ExecutionScope, ArtifactRepositoryError> {
    lock_run(
        transaction,
        authority.run_id(),
        ArtifactRepositoryErrorKind::Unauthorized,
    )
    .await?;
    let row = sqlx::query(
        r"
        SELECT repository.tenant_id, run.repository_id, attempt.lifecycle,
               attempt.lease_id, attempt.fencing_token AS current_fencing_token,
               attempt.secret_exposure_class,
               run.requested_artifact_visibility
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
    let safety = ArtifactSafetySnapshot::from_authority_row(&row)?;
    Ok(ExecutionScope {
        tenant_id: row
            .try_get::<String, _>("tenant_id")
            .map_err(corrupt_error)?,
        repository_id: row
            .try_get::<Uuid, _>("repository_id")
            .map_err(corrupt_error)?,
        safety,
    })
}

async fn insert_new_artifact(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    request: &CreateArtifact,
    scope: &ExecutionScope,
    expires_at: Option<i64>,
) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
    let row = sqlx::query(
        r"
        INSERT INTO workflow_artifacts (
            upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
            fencing_token, name, protocol_version, mime_type,
            expires_at_seconds, created_at_seconds, secret_exposure_class,
            requested_visibility, effective_visibility,
            publication_safety_reason, publication_safety_schema
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17
        )
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
    .bind(scope.safety.secret_exposure_class())
    .bind(scope.safety.requested_visibility())
    .bind(scope.safety.effective_visibility())
    .bind(scope.safety.publication_safety_reason())
    .bind(HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    decode_create_outcome(&row)
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
    manifest_state: Option<String>,
    finalization_generation: u64,
    finalization_claimed_size_bytes: Option<i64>,
    finalization_claimed_digest: Option<Vec<u8>>,
    finalization_claim_expires_at_seconds: Option<i64>,
    content_digest: Option<Vec<u8>>,
    content_size_bytes: Option<i64>,
    manifest_object_key: Option<String>,
    manifest_digest: Option<Vec<u8>>,
    manifest_size_bytes: Option<i64>,
    manifest_media_type: Option<String>,
    manifest_bytes: Option<Vec<u8>>,
}

impl LockedArtifact {
    fn committed(&self, blocks: Vec<ArtifactBlock>, size: u64) -> CommittedArtifact {
        CommittedArtifact {
            artifact_id: self.artifact_id,
            upload_id: self.upload_id,
            authority: self.authority,
            name: self.name.clone(),
            mime_type: self.mime_type.clone(),
            blocks,
            size,
        }
    }

    fn manifest_descriptor(&self) -> Result<BlobDescriptor, ArtifactRepositoryError> {
        decode_descriptor_parts(
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
        )
    }

    fn content_digest(&self) -> Result<Sha256Digest, ArtifactRepositoryError> {
        decode_digest(
            self.content_digest
                .clone()
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        )
    }

    fn finalization_claimed_size(&self) -> Result<u64, ArtifactRepositoryError> {
        nonnegative_i64_to_u64(
            self.finalization_claimed_size_bytes
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        )
    }

    fn finalization_claimed_digest(&self) -> Result<Option<Sha256Digest>, ArtifactRepositoryError> {
        self.finalization_claimed_digest
            .clone()
            .map(decode_digest)
            .transpose()
    }

    fn finalization_expiry(&self) -> Result<u64, ArtifactRepositoryError> {
        nonnegative_i64_to_u64(
            self.finalization_claim_expires_at_seconds
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        )
    }

    fn verified(
        &self,
        committed: &CommittedArtifact,
    ) -> Result<VerifiedArtifactFinalization, ArtifactRepositoryError> {
        let content_digest = self.content_digest()?;
        let size = nonnegative_i64_to_u64(
            self.content_size_bytes
                .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        )?;
        if size != committed.size
            || self.finalization_claimed_size()? != size
            || self
                .finalization_claimed_digest()?
                .is_some_and(|claimed| claimed != content_digest)
        {
            return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
        }
        let manifest = self.manifest_descriptor()?;
        let manifest_bytes = self
            .manifest_bytes
            .clone()
            .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
        validate_manifest_payload(self.artifact_id, content_digest, &manifest, &manifest_bytes)?;
        let canonical =
            serde_json::to_vec(&ArtifactManifest::from_committed(committed, content_digest))
                .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
        if canonical != manifest_bytes {
            return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
        }
        Ok(VerifiedArtifactFinalization {
            artifact_id: self.artifact_id,
            content_digest,
            size,
            manifest,
            manifest_bytes,
        })
    }
}

async fn lock_upload(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    upload_id: UploadId,
) -> Result<LockedArtifact, ArtifactRepositoryError> {
    let run_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT run.id
        FROM workflow_runs AS run
        JOIN workflow_artifacts AS artifact ON artifact.run_id = run.id
        WHERE artifact.upload_id = $1
        FOR UPDATE OF run
        ",
    )
    .bind(upload_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
    let row = artifact_lock_query("artifact.upload_id = $1")
        .bind(upload_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
    let artifact = decode_locked_artifact(&row, None)?;
    if artifact.authority.run_id().as_uuid() != run_id {
        return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
    }
    Ok(artifact)
}

async fn lock_named_artifact(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    authority: ExecutionAuthority,
    name: &ArtifactName,
) -> Result<LockedArtifact, ArtifactRepositoryError> {
    lock_run(
        transaction,
        authority.run_id(),
        ArtifactRepositoryErrorKind::NotFound,
    )
    .await?;
    let row = artifact_lock_query("artifact.run_id = $1 AND artifact.name = $2")
        .bind(authority.run_id().as_uuid())
        .bind(name.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::NotFound))?;
    decode_locked_artifact(&row, Some(authority))
}

async fn lock_claimed_artifact(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    claim: &ArtifactFinalizationClaim,
) -> Result<LockedArtifact, ArtifactRepositoryError> {
    let artifact = lock_named_artifact(transaction, claim.authority(), claim.name()).await?;
    if artifact.artifact_id != claim.artifact_id() {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(artifact)
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
    "artifact.finalization_generation, ",
    "artifact.finalization_claimed_size_bytes, artifact.finalization_claimed_digest, ",
    "artifact.finalization_claim_expires_at_seconds, ",
    "artifact.state, artifact.manifest_state, artifact.content_digest, artifact.content_size_bytes, ",
    "artifact.manifest_object_key, artifact.manifest_digest, ",
    "artifact.manifest_size_bytes, artifact.manifest_media_type, artifact.manifest_bytes, ",
    "attempt.fencing_token AS current_fencing_token, attempt.lifecycle, attempt.lease_id ",
    "FROM workflow_artifacts AS artifact ",
    "JOIN job_attempts AS attempt ON attempt.id = artifact.attempt_id ",
    "WHERE artifact.upload_id = $1 FOR UPDATE OF artifact, attempt"
);

const ARTIFACT_BY_NAME_FOR_UPDATE: &str = concat!(
    "SELECT artifact.id, artifact.upload_id, artifact.run_id, artifact.job_id, ",
    "artifact.attempt_id, artifact.fencing_token AS artifact_fencing_token, ",
    "artifact.name, artifact.mime_type, artifact.block_id_encoded_length, ",
    "artifact.finalization_generation, ",
    "artifact.finalization_claimed_size_bytes, artifact.finalization_claimed_digest, ",
    "artifact.finalization_claim_expires_at_seconds, ",
    "artifact.state, artifact.manifest_state, artifact.content_digest, artifact.content_size_bytes, ",
    "artifact.manifest_object_key, artifact.manifest_digest, ",
    "artifact.manifest_size_bytes, artifact.manifest_media_type, artifact.manifest_bytes, ",
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
        manifest_state: row
            .try_get::<Option<String>, _>("manifest_state")
            .map_err(corrupt_error)?,
        finalization_generation: nonnegative_i64_to_u64(
            row.try_get::<i64, _>("finalization_generation")
                .map_err(corrupt_error)?,
        )?,
        finalization_claimed_size_bytes: row
            .try_get::<Option<i64>, _>("finalization_claimed_size_bytes")
            .map_err(corrupt_error)?,
        finalization_claimed_digest: row
            .try_get::<Option<Vec<u8>>, _>("finalization_claimed_digest")
            .map_err(corrupt_error)?,
        finalization_claim_expires_at_seconds: row
            .try_get::<Option<i64>, _>("finalization_claim_expires_at_seconds")
            .map_err(corrupt_error)?,
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
        manifest_bytes: row
            .try_get::<Option<Vec<u8>>, _>("manifest_bytes")
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

fn require_live_claim(
    artifact: &LockedArtifact,
    claim: &ArtifactFinalizationClaim,
    database_now_seconds: u64,
) -> Result<(), ArtifactRepositoryError> {
    if artifact.artifact_id != claim.artifact_id()
        || artifact.authority != claim.authority()
        || artifact.name != *claim.name()
        || claim.generation() == 0
        || artifact.finalization_generation != claim.generation()
        || artifact.finalization_expiry()? <= database_now_seconds
    {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

fn validate_finalization_lease(lease_seconds: u64) -> Result<(), ArtifactRepositoryError> {
    if lease_seconds == 0 || lease_seconds > MAXIMUM_ARTIFACT_FINALIZATION_LEASE_SECONDS {
        return Err(repository_error(
            ArtifactRepositoryErrorKind::ResourceExhausted,
        ));
    }
    Ok(())
}

async fn finalization_database_now(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
) -> Result<u64, ArtifactRepositoryError> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(database_error)?;
    nonnegative_i64_to_u64(database_now)
}

fn validate_finalization_caller_clock(
    observed_at_seconds: u64,
    database_now: u64,
) -> Result<(), ArtifactRepositoryError> {
    if observed_at_seconds.abs_diff(database_now) > MAXIMUM_FINALIZATION_CALLER_CLOCK_SKEW_SECONDS {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

async fn load_commit(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact_id: ArtifactId,
    for_update: bool,
) -> Result<(Vec<String>, u64), ArtifactRepositoryError> {
    let statement = if for_update {
        r"
        SELECT block_ids, size_bytes
        FROM workflow_artifact_block_commits
        WHERE artifact_id = $1
        FOR UPDATE
        "
    } else {
        r"
        SELECT block_ids, size_bytes
        FROM workflow_artifact_block_commits
        WHERE artifact_id = $1
        "
    };
    let row = sqlx::query(statement)
        .bind(artifact_id.get())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::InvalidState))?;
    let block_ids = row
        .try_get::<Vec<String>, _>("block_ids")
        .map_err(corrupt_error)?;
    let size = nonnegative_i64_to_u64(row.try_get::<i64, _>("size_bytes").map_err(corrupt_error)?)?;
    Ok((block_ids, size))
}

async fn load_verified_finalization(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact: &LockedArtifact,
) -> Result<VerifiedArtifactFinalization, ArtifactRepositoryError> {
    if !matches!(
        artifact.manifest_state.as_deref(),
        Some("reserved" | "ready")
    ) {
        return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
    }
    let (block_ids, size) = load_commit(transaction, artifact.artifact_id, false)
        .await
        .map_err(|error| {
            if error.kind() == ArtifactRepositoryErrorKind::InvalidState {
                repository_error(ArtifactRepositoryErrorKind::CorruptData)
            } else {
                error
            }
        })?;
    let blocks = load_ordered_blocks(transaction, artifact.artifact_id, &block_ids)
        .await
        .map_err(|error| {
            if error.kind() == ArtifactRepositoryErrorKind::NotFound {
                repository_error(ArtifactRepositoryErrorKind::CorruptData)
            } else {
                error
            }
        })?;
    artifact.verified(&artifact.committed(blocks, size))
}

async fn replace_expired_finalization_claim(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact: &LockedArtifact,
    request: &BeginArtifactFinalization,
    generation: u64,
) -> Result<(), ArtifactRepositoryError> {
    let updated = sqlx::query(
        r"
        WITH database_clock AS MATERIALIZED (
            SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
        )
        UPDATE workflow_artifacts AS artifact
        SET finalization_generation = $2,
            finalization_claimed_size_bytes = $3,
            finalization_claimed_digest = $4,
            finalization_claim_expires_at_seconds = database_clock.now_seconds + $6
        FROM database_clock
        WHERE artifact.id = $1
          AND artifact.finalization_generation = $5
          AND artifact.state = 'pending'
          AND artifact.created_at_seconds <= database_clock.now_seconds + $6
          AND (
                artifact.finalization_generation = 0
                OR artifact.finalization_claim_expires_at_seconds
                    <= database_clock.now_seconds
          )
        ",
    )
    .bind(artifact.artifact_id.get())
    .bind(u64_to_i64(generation)?)
    .bind(size_to_i64(request.claimed_size)?)
    .bind(
        request
            .claimed_digest
            .map(|digest| digest.as_bytes().as_slice().to_vec()),
    )
    .bind(u64_to_i64(artifact.finalization_generation)?)
    .bind(u64_to_i64(request.lease_seconds)?)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        return Err(repository_error(ArtifactRepositoryErrorKind::Conflict));
    }
    Ok(())
}

async fn reserve_verified_manifest(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact: &LockedArtifact,
    request: &RecordArtifactVerification,
    size: u64,
) -> Result<(), ArtifactRepositoryError> {
    let updated = sqlx::query(
        r"
        WITH database_clock AS MATERIALIZED (
            SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
        )
        UPDATE workflow_artifacts AS artifact
        SET manifest_state = 'reserved',
            content_digest = $3,
            content_size_bytes = $4,
            manifest_object_key = $5,
            manifest_digest = $6,
            manifest_size_bytes = $7,
            manifest_media_type = $8,
            manifest_bytes = $9,
            manifest_reserved_at_seconds = greatest(
                database_clock.now_seconds,
                artifact.created_at_seconds
            ),
            finalization_claim_expires_at_seconds = greatest(
                artifact.finalization_claim_expires_at_seconds,
                database_clock.now_seconds + $10
            )
        FROM database_clock
        WHERE artifact.id = $1
          AND artifact.finalization_generation = $2
          AND artifact.state = 'pending'
          AND artifact.manifest_state IS NULL
          AND artifact.finalization_claim_expires_at_seconds
                > database_clock.now_seconds
        ",
    )
    .bind(artifact.artifact_id.get())
    .bind(u64_to_i64(request.claim.generation())?)
    .bind(request.content_digest.as_bytes().as_slice())
    .bind(size_to_i64(size)?)
    .bind(request.manifest.key().as_str())
    .bind(request.manifest.digest().as_bytes().as_slice())
    .bind(size_to_i64(request.manifest.size())?)
    .bind(request.manifest.media_type().as_str())
    .bind(&request.manifest_bytes)
    .bind(u64_to_i64(request.lease_seconds)?)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

async fn update_claim_expiry(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact_id: ArtifactId,
    generation: u64,
    lease_seconds: u64,
) -> Result<(), ArtifactRepositoryError> {
    let updated = sqlx::query(
        r"
        WITH database_clock AS MATERIALIZED (
            SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS now_seconds
        )
        UPDATE workflow_artifacts AS artifact
        SET finalization_claim_expires_at_seconds = greatest(
            artifact.finalization_claim_expires_at_seconds,
            database_clock.now_seconds + $3
        )
        FROM database_clock
        WHERE artifact.id = $1
          AND artifact.finalization_generation = $2
          AND artifact.state = 'pending'
          AND artifact.finalization_claim_expires_at_seconds
                > database_clock.now_seconds
        ",
    )
    .bind(artifact_id.get())
    .bind(u64_to_i64(generation)?)
    .bind(u64_to_i64(lease_seconds)?)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        return Err(repository_error(ArtifactRepositoryErrorKind::Unauthorized));
    }
    Ok(())
}

fn validate_manifest_payload(
    artifact_id: ArtifactId,
    content_digest: Sha256Digest,
    descriptor: &BlobDescriptor,
    bytes: &[u8],
) -> Result<(), ArtifactRepositoryError> {
    let size = u64::try_from(bytes.len())
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
    let expected_key = format!("artifacts/v1/{content_digest}/{artifact_id}/manifest.json");
    if size == 0
        || size > MAXIMUM_ARTIFACT_MANIFEST_BYTES
        || descriptor.key().as_str() != expected_key
        || descriptor.media_type().as_str() != ARTIFACT_MANIFEST_MEDIA_TYPE
    {
        return Err(repository_error(ArtifactRepositoryErrorKind::CorruptData));
    }
    BlobPayload::verify(descriptor.clone(), Bytes::copy_from_slice(bytes))
        .map(|_| ())
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))
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

async fn reserve_new_block(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact: &LockedArtifact,
    request: &ReserveArtifactBlock,
) -> Result<(), ArtifactRepositoryError> {
    enforce_artifact_block_quota(transaction, artifact.artifact_id, request).await?;
    enforce_run_block_quota(transaction, artifact.authority.run_id(), request).await?;
    sqlx::query(
        r"
        INSERT INTO workflow_artifact_blocks (
            artifact_id, block_id, object_key, digest, size_bytes,
            media_type, staged_at_seconds, state
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'reserved')
        ",
    )
    .bind(artifact.artifact_id.get())
    .bind(request.block.block_id())
    .bind(request.block.descriptor().key().as_str())
    .bind(request.block.descriptor().digest().as_bytes().as_slice())
    .bind(size_to_i64(request.block.descriptor().size())?)
    .bind(request.block.descriptor().media_type().as_str())
    .bind(seconds_to_i64(request.observed_at_seconds)?)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn enforce_artifact_block_quota(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    artifact_id: ArtifactId,
    request: &ReserveArtifactBlock,
) -> Result<(), ArtifactRepositoryError> {
    let aggregate = sqlx::query(
        r"
        SELECT count(*) AS block_count,
               coalesce(sum(size_bytes), 0)::bigint AS staged_bytes
        FROM workflow_artifact_blocks
        WHERE artifact_id = $1
        ",
    )
    .bind(artifact_id.get())
    .fetch_one(&mut **transaction)
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
    let next_size = checked_staged_size(staged_bytes, request.block.descriptor().size())?;
    if next_count > request.maximum_blocks || next_size > request.maximum_staged_bytes {
        return Err(repository_error(
            ArtifactRepositoryErrorKind::ResourceExhausted,
        ));
    }
    Ok(())
}

async fn enforce_run_block_quota(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    run_id: RunId,
    request: &ReserveArtifactBlock,
) -> Result<(), ArtifactRepositoryError> {
    let aggregate = sqlx::query(
        r"
        SELECT count(*) AS block_count,
               coalesce(sum(block.size_bytes), 0)::bigint AS staged_bytes
        FROM workflow_artifact_blocks AS block
        JOIN workflow_artifacts AS owner ON owner.id = block.artifact_id
        WHERE owner.run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(&mut **transaction)
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
    let next_size = checked_staged_size(staged_bytes, request.block.descriptor().size())?;
    if next_count > request.maximum_run_blocks || next_size > request.maximum_run_staged_bytes {
        return Err(repository_error(
            ArtifactRepositoryErrorKind::ResourceExhausted,
        ));
    }
    Ok(())
}

fn checked_staged_size(current: i64, added: u64) -> Result<u64, ArtifactRepositoryError> {
    u64::try_from(current)
        .ok()
        .and_then(|size| size.checked_add(added))
        .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))
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
        WHERE artifact_id = $1 AND block_id = ANY($2) AND state = 'ready'
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

fn decode_published_metadata(
    row: &sqlx::postgres::PgRow,
) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
    let fencing_token = u64::try_from(
        row.try_get::<i64, _>("fencing_token")
            .map_err(corrupt_error)?,
    )
    .ok()
    .and_then(|value| FencingToken::new(value).ok())
    .ok_or_else(|| repository_error(ArtifactRepositoryErrorKind::CorruptData))?;
    let expires_at_seconds = row
        .try_get::<Option<i64>, _>("expires_at_seconds")
        .map_err(corrupt_error)?
        .map(nonnegative_i64_to_u64)
        .transpose()?;
    Ok(PublishedArtifactMetadata {
        artifact_id: ArtifactId::new(row.try_get::<i64, _>("id").map_err(corrupt_error)?)
            .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        upload_id: UploadId::from_uuid(row.try_get::<Uuid, _>("upload_id").map_err(corrupt_error)?),
        authority: ExecutionAuthority::new(
            RunId::from_uuid(row.try_get::<Uuid, _>("run_id").map_err(corrupt_error)?),
            JobId::from_uuid(row.try_get::<Uuid, _>("job_id").map_err(corrupt_error)?),
            AttemptId::from_uuid(
                row.try_get::<Uuid, _>("attempt_id")
                    .map_err(corrupt_error)?,
            ),
            fencing_token,
        ),
        name: ArtifactName::new(
            row.try_get::<String, _>("name").map_err(corrupt_error)?,
            MAXIMUM_DURABLE_NAME_BYTES,
        )
        .map_err(|_| repository_error(ArtifactRepositoryErrorKind::CorruptData))?,
        mime_type: row
            .try_get::<String, _>("mime_type")
            .map_err(corrupt_error)?,
        content_digest: decode_digest(
            row.try_get::<Vec<u8>, _>("content_digest")
                .map_err(corrupt_error)?,
        )?,
        size: nonnegative_i64_to_u64(
            row.try_get::<i64, _>("content_size_bytes")
                .map_err(corrupt_error)?,
        )?,
        manifest: decode_descriptor_parts(
            row.try_get::<String, _>("manifest_object_key")
                .map_err(corrupt_error)?,
            row.try_get::<Vec<u8>, _>("manifest_digest")
                .map_err(corrupt_error)?,
            row.try_get::<i64, _>("manifest_size_bytes")
                .map_err(corrupt_error)?,
            row.try_get::<String, _>("manifest_media_type")
                .map_err(corrupt_error)?,
        )?,
        created_at_seconds: nonnegative_i64_to_u64(
            row.try_get::<i64, _>("created_at_seconds")
                .map_err(corrupt_error)?,
        )?,
        expires_at_seconds,
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

fn u64_to_i64(value: u64) -> Result<i64, ArtifactRepositoryError> {
    i64::try_from(value)
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
