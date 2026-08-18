use automata_ci_core::{GitObjectAlgorithm, GitObjectId, JobId, RunId, Sha256Digest, UnixMillis};
use automata_ci_provider::{
    ClaimProviderResult, ClaimedProviderResult, CompleteProviderResult, DesiredProviderResult,
    ExternalResultId, FailProviderResult, ProviderConnectionId, ProviderConnectionRevision,
    ProviderDeliveryId, ProviderRepositoryPath, ProviderResultAnnotation,
    ProviderResultAnnotationLevel, ProviderResultAnnotationMessage, ProviderResultAnnotationTitle,
    ProviderResultBinding, ProviderResultClaimFence, ProviderResultConclusion,
    ProviderResultContinuation, ProviderResultDetailsUrl, ProviderResultFailureKind,
    ProviderResultModelError, ProviderResultName, ProviderResultPhase, ProviderResultProjection,
    ProviderResultPublicationModel, ProviderResultRepositoryError, ProviderResultSaveOutcome,
    ProviderResultSubject, ProviderResultSubjectId, ProviderResultSubjectKind,
    ProviderResultSummary, ProviderResultTitle, ProviderResultWorkerId, ProviderSchemaVersion,
    RenewProviderResult, RetryProviderResult, SaveDesiredProviderResult,
};
use sqlx::{FromRow, Postgres, Transaction};

use crate::{PostgresProviderManifestRepository, RESULT_LOCK_SALT};

#[derive(FromRow)]
struct ResultRow {
    subject_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    connection_revision: i64,
    connection_digest: Vec<u8>,
    object_algorithm: String,
    object_bytes: Vec<u8>,
    result_name: String,
    result_details_url: String,
    subject_kind: String,
    delivery_id: Option<uuid::Uuid>,
    workflow_path: Option<String>,
    run_id: Option<uuid::Uuid>,
    job_id: Option<uuid::Uuid>,
    attempt: i64,
    created_at_ms: i64,
    subject_digest: Vec<u8>,
    generation: i64,
    phase: String,
    conclusion: Option<String>,
    title: String,
    summary: String,
    updated_at_ms: i64,
    projection_digest: Vec<u8>,
    desired_digest: Vec<u8>,
    attempts: i16,
    claim_worker_id: Option<uuid::Uuid>,
    claim_fence: Option<i64>,
    claim_started_at_ms: Option<i64>,
    claim_expires_at_ms: Option<i64>,
    binding_external_result_id: Option<String>,
    continuation_schema: Option<i16>,
    continuation_bytes: Option<Vec<u8>>,
    continuation_digest: Option<Vec<u8>>,
}

#[derive(FromRow)]
struct AnnotationRow {
    path: String,
    start_line: i64,
    end_line: i64,
    level: String,
    title: String,
    message: String,
}

impl PostgresProviderManifestRepository {
    pub(crate) async fn save_desired_result_inner(
        &self,
        request: SaveDesiredProviderResult,
    ) -> Result<ProviderResultSaveOutcome, ProviderResultRepositoryError> {
        let (subject, projection) = request.into_parts();
        let mut transaction = self.pool().begin().await.map_err(unavailable)?;
        result_lock(&mut transaction, subject.subject_id()).await?;
        let current = sqlx::query_as::<_, CurrentResultRow>(
            r"
            SELECT subject.subject_digest, outbox.generation,
                   outbox.projection_digest
            FROM provider_result_subjects AS subject
            JOIN provider_result_outbox AS outbox ON outbox.subject_id = subject.subject_id
            WHERE subject.subject_id = $1
            FOR UPDATE OF subject, outbox
            ",
        )
        .bind(subject.subject_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let outcome = match current {
            None => {
                let desired = DesiredProviderResult::new(1, projection).map_err(model_corrupt)?;
                ensure_subject_connection(&mut transaction, &subject).await?;
                insert_subject(&mut transaction, &subject).await?;
                insert_outbox(&mut transaction, &subject, &desired).await?;
                insert_annotations(&mut transaction, subject.subject_id(), &desired).await?;
                ProviderResultSaveOutcome::Inserted
            }
            Some(current) => {
                let generation = positive_u64(current.generation)?;
                if current.subject_digest != subject.digest().as_bytes() {
                    return Err(ProviderResultRepositoryError::Conflict);
                }
                if current.projection_digest == projection.digest().as_bytes() {
                    transaction.commit().await.map_err(unavailable)?;
                    return Ok(ProviderResultSaveOutcome::Unchanged);
                }
                let next = generation
                    .checked_add(1)
                    .ok_or(ProviderResultRepositoryError::Conflict)?;
                let desired =
                    DesiredProviderResult::new(next, projection).map_err(model_corrupt)?;
                sqlx::query("DELETE FROM provider_result_annotations WHERE subject_id = $1")
                    .bind(subject.subject_id().as_uuid())
                    .execute(&mut *transaction)
                    .await
                    .map_err(unavailable)?;
                update_outbox(&mut transaction, subject.subject_id(), &desired).await?;
                insert_annotations(&mut transaction, subject.subject_id(), &desired).await?;
                ProviderResultSaveOutcome::Superseded
            }
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(outcome)
    }

    pub(crate) async fn claim_result_inner(
        &self,
        request: ClaimProviderResult,
    ) -> Result<Option<ClaimedProviderResult>, ProviderResultRepositoryError> {
        let mut transaction = self.pool().begin().await.map_err(unavailable)?;
        sqlx::query(
            r"
            UPDATE provider_result_outbox AS outbox
            SET state = 'failed', failed_at_ms = $2, failure_kind = 'attempt-limit',
                claim_worker_id = NULL, claim_fence = NULL,
                claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
                publication_model = NULL, external_result_id = NULL,
                provider_state_digest = NULL, publication_observed_at_ms = NULL,
                publication_evidence_digest = NULL,
                continuation_schema = NULL, continuation_bytes = NULL,
                continuation_digest = NULL
            FROM provider_result_subjects AS subject
            WHERE subject.subject_id = outbox.subject_id
              AND subject.connection_id = $1
              AND outbox.state = 'claimed' AND outbox.attempts = 64
              AND outbox.claim_expires_at_ms <= $2
            ",
        )
        .bind(request.connection_id().as_uuid())
        .bind(request.claimed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let candidate = sqlx::query_scalar::<_, uuid::Uuid>(
            r"
            SELECT outbox.subject_id
            FROM provider_result_outbox AS outbox
            JOIN provider_result_subjects AS subject ON subject.subject_id = outbox.subject_id
            WHERE subject.connection_id = $1
              AND outbox.attempts < 64
              AND outbox.available_at_ms <= $2
              AND (
                outbox.state = 'pending'
                OR (outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $2)
              )
            ORDER BY outbox.available_at_ms, outbox.subject_id
            FOR UPDATE OF outbox SKIP LOCKED
            LIMIT 1
            ",
        )
        .bind(request.connection_id().as_uuid())
        .bind(request.claimed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let Some(subject_id) = candidate else {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(None);
        };
        let expires_at = request
            .claimed_at()
            .get()
            .checked_add(
                i64::try_from(request.lease_millis())
                    .map_err(|_| ProviderResultRepositoryError::Corrupt)?,
            )
            .ok_or(ProviderResultRepositoryError::Corrupt)?;
        sqlx::query(
            r"
            UPDATE provider_result_outbox
            SET state = 'claimed', attempts = attempts + 1,
                next_fence = next_fence + 1,
                claim_worker_id = $2, claim_fence = next_fence + 1,
                claim_started_at_ms = $3, claim_expires_at_ms = $4,
                publication_model = NULL, external_result_id = NULL,
                provider_state_digest = NULL, publication_observed_at_ms = NULL,
                publication_evidence_digest = NULL,
                failed_at_ms = NULL, failure_kind = NULL
            WHERE subject_id = $1
            ",
        )
        .bind(subject_id)
        .bind(request.worker_id().as_uuid())
        .bind(request.claimed_at().get())
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        let row = load_result_row(&mut transaction, subject_id).await?;
        let annotations = load_annotations(&mut transaction, subject_id, row.generation).await?;
        transaction.commit().await.map_err(unavailable)?;
        self.decode_claimed(row, annotations).await.map(Some)
    }

    pub(crate) async fn complete_result_inner(
        &self,
        request: CompleteProviderResult,
    ) -> Result<(), ProviderResultRepositoryError> {
        let evidence = request.evidence();
        let claim = request.claim();
        let updated = sqlx::query(
            r"
            UPDATE provider_result_outbox
            SET state = 'completed', claim_worker_id = NULL, claim_fence = NULL,
                claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
                publication_model = $7, external_result_id = $8,
                provider_state_digest = $9, publication_observed_at_ms = $10,
                publication_evidence_digest = $11,
                binding_external_result_id = $12,
                continuation_schema = NULL, continuation_bytes = NULL,
                continuation_digest = NULL,
                failed_at_ms = NULL, failure_kind = NULL
            WHERE subject_id = $1 AND generation = $2 AND state = 'claimed'
              AND claim_worker_id = $3 AND claim_fence = $4
              AND claim_started_at_ms = $5 AND claim_expires_at_ms = $6
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(durable_u64(claim.generation())?)
        .bind(claim.worker_id().as_uuid())
        .bind(durable_u64(claim.fence())?)
        .bind(claim.claimed_at().get())
        .bind(claim.expires_at().get())
        .bind(publication_model_text(evidence.model()))
        .bind(evidence.external_id().map(ExternalResultId::as_str))
        .bind(evidence.provider_state_digest().as_bytes().as_slice())
        .bind(evidence.observed_at().get())
        .bind(evidence.digest().as_bytes().as_slice())
        .bind(evidence.external_id().map(ExternalResultId::as_str))
        .execute(self.pool())
        .await
        .map_err(unavailable)?;
        exact_claim_result(self.pool(), claim.subject_id(), updated.rows_affected()).await
    }

    pub(crate) async fn renew_result_inner(
        &self,
        request: RenewProviderResult,
    ) -> Result<ProviderResultClaimFence, ProviderResultRepositoryError> {
        let claim = request.claim();
        let extension = i64::try_from(request.lease_millis())
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
        let expires_at = request
            .renewed_at()
            .get()
            .checked_add(extension)
            .ok_or(ProviderResultRepositoryError::Corrupt)?;
        let renewed = sqlx::query_scalar::<_, i64>(
            r"
            UPDATE provider_result_outbox
            SET claim_expires_at_ms = $8
            WHERE subject_id = $1 AND generation = $2 AND state = 'claimed'
              AND claim_worker_id = $3 AND claim_fence = $4
              AND claim_started_at_ms = $5 AND claim_expires_at_ms = $6
              AND claim_started_at_ms <= $7 AND claim_expires_at_ms > $7
              AND claim_expires_at_ms < $8
            RETURNING claim_expires_at_ms
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(durable_u64(claim.generation())?)
        .bind(claim.worker_id().as_uuid())
        .bind(durable_u64(claim.fence())?)
        .bind(claim.claimed_at().get())
        .bind(claim.expires_at().get())
        .bind(request.renewed_at().get())
        .bind(expires_at)
        .fetch_optional(self.pool())
        .await
        .map_err(unavailable)?
        .ok_or(ProviderResultRepositoryError::StaleClaim)?;
        ProviderResultClaimFence::new(
            claim.subject_id(),
            claim.generation(),
            claim.worker_id(),
            claim.fence(),
            claim.claimed_at(),
            UnixMillis::new(renewed),
        )
        .map_err(model_corrupt)
    }

    pub(crate) async fn retry_result_inner(
        &self,
        request: RetryProviderResult,
    ) -> Result<(), ProviderResultRepositoryError> {
        let claim = request.claim();
        let updated = sqlx::query(
            r"
            UPDATE provider_result_outbox
            SET state = 'pending', available_at_ms = $7,
                claim_worker_id = NULL, claim_fence = NULL,
                claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
                publication_model = NULL, external_result_id = NULL,
                provider_state_digest = NULL, publication_observed_at_ms = NULL,
                publication_evidence_digest = NULL,
                continuation_schema = $8, continuation_bytes = $9,
                continuation_digest = $10,
                failed_at_ms = NULL, failure_kind = NULL
            WHERE subject_id = $1 AND generation = $2 AND state = 'claimed'
              AND claim_worker_id = $3 AND claim_fence = $4
              AND claim_started_at_ms = $5 AND claim_expires_at_ms = $6
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(durable_u64(claim.generation())?)
        .bind(claim.worker_id().as_uuid())
        .bind(durable_u64(claim.fence())?)
        .bind(claim.claimed_at().get())
        .bind(claim.expires_at().get())
        .bind(request.retry_at().get())
        .bind(
            request
                .continuation()
                .map(|continuation| i16::try_from(continuation.schema_version().get()))
                .transpose()
                .map_err(|_| ProviderResultRepositoryError::Corrupt)?,
        )
        .bind(
            request
                .continuation()
                .map(ProviderResultContinuation::bytes),
        )
        .bind(
            request
                .continuation()
                .map(|continuation| continuation.digest().as_bytes().to_vec()),
        )
        .execute(self.pool())
        .await
        .map_err(unavailable)?;
        exact_claim_result(self.pool(), claim.subject_id(), updated.rows_affected()).await
    }

    pub(crate) async fn fail_result_inner(
        &self,
        request: FailProviderResult,
    ) -> Result<(), ProviderResultRepositoryError> {
        let claim = request.claim();
        let updated = sqlx::query(
            r"
            UPDATE provider_result_outbox
            SET state = 'failed', claim_worker_id = NULL, claim_fence = NULL,
                claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
                publication_model = NULL, external_result_id = NULL,
                provider_state_digest = NULL, publication_observed_at_ms = NULL,
                publication_evidence_digest = NULL,
                continuation_schema = NULL, continuation_bytes = NULL,
                continuation_digest = NULL,
                failed_at_ms = $7, failure_kind = $8
            WHERE subject_id = $1 AND generation = $2 AND state = 'claimed'
              AND claim_worker_id = $3 AND claim_fence = $4
              AND claim_started_at_ms = $5 AND claim_expires_at_ms = $6
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(durable_u64(claim.generation())?)
        .bind(claim.worker_id().as_uuid())
        .bind(durable_u64(claim.fence())?)
        .bind(claim.claimed_at().get())
        .bind(claim.expires_at().get())
        .bind(request.failed_at().get())
        .bind(failure_kind_text(request.kind()))
        .execute(self.pool())
        .await
        .map_err(unavailable)?;
        exact_claim_result(self.pool(), claim.subject_id(), updated.rows_affected()).await
    }

    async fn decode_claimed(
        &self,
        row: ResultRow,
        annotations: Vec<AnnotationRow>,
    ) -> Result<ClaimedProviderResult, ProviderResultRepositoryError> {
        let binding = row
            .binding_external_result_id
            .as_deref()
            .map(|external_id| ExternalResultId::new(external_id.to_owned()))
            .transpose()
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?
            .map(ProviderResultBinding::new);
        let continuation = continuation(&row)?;
        let result_name =
            ProviderResultName::new(row.result_name.clone()).map_err(model_corrupt)?;
        let result_details_url = ProviderResultDetailsUrl::new(
            row.result_details_url
                .parse()
                .map_err(|_| ProviderResultRepositoryError::Corrupt)?,
        )
        .map_err(model_corrupt)?;
        let connection_id = ProviderConnectionId::from_uuid(row.connection_id)
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
        let connection_revision =
            ProviderConnectionRevision::new(positive_u64(row.connection_revision)?)
                .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
        let connection = self
            .load_connection_inner(connection_id, connection_revision)
            .await
            .map_err(map_manifest_error)?
            .ok_or(ProviderResultRepositoryError::Corrupt)?;
        if digest(&row.connection_digest)? != connection.digest() {
            return Err(ProviderResultRepositoryError::Corrupt);
        }
        let subject_id = ProviderResultSubjectId::from_uuid(row.subject_id)
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
        let subject = ProviderResultSubject::new(
            subject_id,
            &connection,
            git_object(&row.object_algorithm, &row.object_bytes)?,
            result_name,
            result_details_url,
            subject_kind(&row)?,
            u32::try_from(row.attempt).map_err(|_| ProviderResultRepositoryError::Corrupt)?,
            UnixMillis::new(row.created_at_ms),
        )
        .map_err(model_corrupt)?;
        if digest(&row.subject_digest)? != subject.digest() {
            return Err(ProviderResultRepositoryError::Corrupt);
        }
        let desired = DesiredProviderResult::new(
            positive_u64(row.generation)?,
            ProviderResultProjection::new(
                phase(&row.phase)?,
                conclusion(row.conclusion.as_deref())?,
                ProviderResultTitle::new(row.title).map_err(model_corrupt)?,
                ProviderResultSummary::new(row.summary).map_err(model_corrupt)?,
                annotations
                    .into_iter()
                    .map(decode_annotation)
                    .collect::<Result<Vec<_>, _>>()?,
                UnixMillis::new(row.updated_at_ms),
            )
            .map_err(model_corrupt)?,
        )
        .map_err(model_corrupt)?;
        if digest(&row.projection_digest)? != desired.projection().digest()
            || digest(&row.desired_digest)? != desired.digest()
        {
            return Err(ProviderResultRepositoryError::Corrupt);
        }
        let worker_id = ProviderResultWorkerId::from_uuid(
            row.claim_worker_id
                .ok_or(ProviderResultRepositoryError::Corrupt)?,
        )
        .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
        let claim = ProviderResultClaimFence::new(
            subject_id,
            desired.generation(),
            worker_id,
            positive_u64(
                row.claim_fence
                    .ok_or(ProviderResultRepositoryError::Corrupt)?,
            )?,
            UnixMillis::new(
                row.claim_started_at_ms
                    .ok_or(ProviderResultRepositoryError::Corrupt)?,
            ),
            UnixMillis::new(
                row.claim_expires_at_ms
                    .ok_or(ProviderResultRepositoryError::Corrupt)?,
            ),
        )
        .map_err(model_corrupt)?;
        ClaimedProviderResult::new(
            subject,
            desired,
            claim,
            u16::try_from(row.attempts).map_err(|_| ProviderResultRepositoryError::Corrupt)?,
            binding,
            continuation,
        )
        .map_err(model_corrupt)
    }
}

#[derive(FromRow)]
struct CurrentResultRow {
    subject_digest: Vec<u8>,
    generation: i64,
    projection_digest: Vec<u8>,
}

async fn result_lock(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: ProviderResultSubjectId,
) -> Result<(), ProviderResultRepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(subject_id.to_string())
        .bind(RESULT_LOCK_SALT)
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn ensure_subject_connection(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &ProviderResultSubject,
) -> Result<(), ProviderResultRepositoryError> {
    let digest = sqlx::query_scalar::<_, Vec<u8>>(
        r"
        SELECT manifest_digest
        FROM provider_connection_revisions
        WHERE connection_id = $1 AND revision = $2
        ",
    )
    .bind(subject.connection_id().as_uuid())
    .bind(durable_u64(subject.connection_revision().get())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(unavailable)?
    .ok_or(ProviderResultRepositoryError::NotFound)?;
    if digest != subject.connection_digest().as_bytes() {
        return Err(ProviderResultRepositoryError::Conflict);
    }
    Ok(())
}

async fn insert_subject(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &ProviderResultSubject,
) -> Result<(), ProviderResultRepositoryError> {
    let kind = SubjectColumns::from(subject.subject());
    sqlx::query(
        r"
        INSERT INTO provider_result_subjects (
            subject_id, connection_id, connection_revision, connection_digest,
            object_algorithm, object_bytes, result_name, result_details_url,
            subject_kind, delivery_id, workflow_path, run_id, job_id, attempt,
            created_at_ms, subject_digest
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ",
    )
    .bind(subject.subject_id().as_uuid())
    .bind(subject.connection_id().as_uuid())
    .bind(durable_u64(subject.connection_revision().get())?)
    .bind(subject.connection_digest().as_bytes().as_slice())
    .bind(object_algorithm_text(subject.object().algorithm()))
    .bind(subject.object().as_bytes())
    .bind(subject.name().as_str())
    .bind(subject.details_url().as_url().as_str())
    .bind(kind.kind)
    .bind(kind.delivery_id)
    .bind(kind.workflow_path)
    .bind(kind.run_id)
    .bind(kind.job_id)
    .bind(i64::from(subject.attempt()))
    .bind(subject.created_at().get())
    .bind(subject.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(())
}

struct SubjectColumns<'a> {
    kind: &'static str,
    delivery_id: Option<uuid::Uuid>,
    workflow_path: Option<&'a str>,
    run_id: Option<uuid::Uuid>,
    job_id: Option<uuid::Uuid>,
}

impl<'a> From<&'a ProviderResultSubjectKind> for SubjectColumns<'a> {
    fn from(value: &'a ProviderResultSubjectKind) -> Self {
        match value {
            ProviderResultSubjectKind::PendingWorkflow {
                delivery_id,
                workflow_path,
            } => Self {
                kind: "pending-workflow",
                delivery_id: Some(delivery_id.as_uuid()),
                workflow_path: Some(workflow_path.as_str()),
                run_id: None,
                job_id: None,
            },
            ProviderResultSubjectKind::WorkflowRun { run_id } => Self {
                kind: "workflow-run",
                delivery_id: None,
                workflow_path: None,
                run_id: Some(run_id.as_uuid()),
                job_id: None,
            },
            ProviderResultSubjectKind::Job { run_id, job_id } => Self {
                kind: "job",
                delivery_id: None,
                workflow_path: None,
                run_id: Some(run_id.as_uuid()),
                job_id: Some(job_id.as_uuid()),
            },
        }
    }
}

async fn insert_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &ProviderResultSubject,
    desired: &DesiredProviderResult,
) -> Result<(), ProviderResultRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO provider_result_outbox (
            subject_id, generation, phase, conclusion, title, summary,
            updated_at_ms, projection_digest, desired_digest, state, available_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$7)
        ",
    )
    .bind(subject.subject_id().as_uuid())
    .bind(durable_u64(desired.generation())?)
    .bind(phase_text(desired.phase()))
    .bind(desired.conclusion().map(conclusion_text))
    .bind(desired.title().as_str())
    .bind(desired.summary().as_str())
    .bind(desired.updated_at().get())
    .bind(desired.projection().digest().as_bytes().as_slice())
    .bind(desired.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(())
}

async fn update_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: ProviderResultSubjectId,
    desired: &DesiredProviderResult,
) -> Result<(), ProviderResultRepositoryError> {
    sqlx::query(
        r"
        UPDATE provider_result_outbox
        SET generation = $2, phase = $3, conclusion = $4, title = $5,
            summary = $6, updated_at_ms = $7,
            projection_digest = $8, desired_digest = $9,
            state = 'pending', available_at_ms = $7,
            attempts = 0, claim_worker_id = NULL, claim_fence = NULL,
            claim_started_at_ms = NULL, claim_expires_at_ms = NULL,
            publication_model = NULL, external_result_id = NULL,
            provider_state_digest = NULL, publication_observed_at_ms = NULL,
            publication_evidence_digest = NULL,
            continuation_schema = NULL, continuation_bytes = NULL,
            continuation_digest = NULL,
            failed_at_ms = NULL, failure_kind = NULL
        WHERE subject_id = $1
        ",
    )
    .bind(subject_id.as_uuid())
    .bind(durable_u64(desired.generation())?)
    .bind(phase_text(desired.phase()))
    .bind(desired.conclusion().map(conclusion_text))
    .bind(desired.title().as_str())
    .bind(desired.summary().as_str())
    .bind(desired.updated_at().get())
    .bind(desired.projection().digest().as_bytes().as_slice())
    .bind(desired.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(unavailable)?;
    Ok(())
}

async fn insert_annotations(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: ProviderResultSubjectId,
    desired: &DesiredProviderResult,
) -> Result<(), ProviderResultRepositoryError> {
    for (ordinal, annotation) in desired.annotations().iter().enumerate() {
        sqlx::query(
            r"
            INSERT INTO provider_result_annotations (
                subject_id, generation, ordinal, path, start_line, end_line,
                level, title, message
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ",
        )
        .bind(subject_id.as_uuid())
        .bind(durable_u64(desired.generation())?)
        .bind(i32::try_from(ordinal).map_err(|_| ProviderResultRepositoryError::Corrupt)?)
        .bind(annotation.path().as_str())
        .bind(i64::from(annotation.start_line()))
        .bind(i64::from(annotation.end_line()))
        .bind(annotation_level_text(annotation.level()))
        .bind(annotation.title().as_str())
        .bind(annotation.message().as_str())
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    }
    Ok(())
}

async fn load_result_row(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: uuid::Uuid,
) -> Result<ResultRow, ProviderResultRepositoryError> {
    sqlx::query_as::<_, ResultRow>(
        r"
        SELECT subject.subject_id, subject.connection_id,
               subject.connection_revision, subject.connection_digest,
               subject.object_algorithm, subject.object_bytes, subject.result_name,
               subject.result_details_url, subject.subject_kind,
               subject.delivery_id, subject.workflow_path,
               subject.run_id, subject.job_id, subject.attempt,
               subject.created_at_ms, subject.subject_digest,
               outbox.generation, outbox.phase, outbox.conclusion,
               outbox.title, outbox.summary,
               outbox.updated_at_ms, outbox.projection_digest,
               outbox.desired_digest, outbox.attempts,
               outbox.claim_worker_id, outbox.claim_fence,
               outbox.claim_started_at_ms, outbox.claim_expires_at_ms,
               outbox.binding_external_result_id,
               outbox.continuation_schema, outbox.continuation_bytes,
               outbox.continuation_digest
        FROM provider_result_subjects AS subject
        JOIN provider_result_outbox AS outbox ON outbox.subject_id = subject.subject_id
        WHERE subject.subject_id = $1 AND outbox.state = 'claimed'
        ",
    )
    .bind(subject_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(unavailable)
}

async fn load_annotations(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: uuid::Uuid,
    generation: i64,
) -> Result<Vec<AnnotationRow>, ProviderResultRepositoryError> {
    sqlx::query_as::<_, AnnotationRow>(
        r"
        SELECT path, start_line, end_line, level, title, message
        FROM provider_result_annotations
        WHERE subject_id = $1 AND generation = $2
        ORDER BY ordinal
        ",
    )
    .bind(subject_id)
    .bind(generation)
    .fetch_all(&mut **transaction)
    .await
    .map_err(unavailable)
}

fn subject_kind(
    row: &ResultRow,
) -> Result<ProviderResultSubjectKind, ProviderResultRepositoryError> {
    match row.subject_kind.as_str() {
        "pending-workflow" => Ok(ProviderResultSubjectKind::PendingWorkflow {
            delivery_id: ProviderDeliveryId::from_uuid(
                row.delivery_id
                    .ok_or(ProviderResultRepositoryError::Corrupt)?,
            )
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?,
            workflow_path: ProviderRepositoryPath::new(
                row.workflow_path
                    .clone()
                    .ok_or(ProviderResultRepositoryError::Corrupt)?,
            )
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?,
        }),
        "workflow-run" => Ok(ProviderResultSubjectKind::WorkflowRun {
            run_id: RunId::from_uuid(row.run_id.ok_or(ProviderResultRepositoryError::Corrupt)?),
        }),
        "job" => Ok(ProviderResultSubjectKind::Job {
            run_id: RunId::from_uuid(row.run_id.ok_or(ProviderResultRepositoryError::Corrupt)?),
            job_id: JobId::from_uuid(row.job_id.ok_or(ProviderResultRepositoryError::Corrupt)?),
        }),
        _ => Err(ProviderResultRepositoryError::Corrupt),
    }
}

fn decode_annotation(
    row: AnnotationRow,
) -> Result<ProviderResultAnnotation, ProviderResultRepositoryError> {
    ProviderResultAnnotation::new(
        ProviderRepositoryPath::new(row.path)
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?,
        u32::try_from(row.start_line).map_err(|_| ProviderResultRepositoryError::Corrupt)?,
        u32::try_from(row.end_line).map_err(|_| ProviderResultRepositoryError::Corrupt)?,
        annotation_level(&row.level)?,
        ProviderResultAnnotationTitle::new(row.title).map_err(model_corrupt)?,
        ProviderResultAnnotationMessage::new(row.message).map_err(model_corrupt)?,
    )
    .map_err(model_corrupt)
}

async fn exact_claim_result(
    pool: &sqlx::PgPool,
    subject_id: ProviderResultSubjectId,
    affected: u64,
) -> Result<(), ProviderResultRepositoryError> {
    if affected == 1 {
        return Ok(());
    }
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM provider_result_subjects WHERE subject_id = $1)",
    )
    .bind(subject_id.as_uuid())
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;
    Err(if exists {
        ProviderResultRepositoryError::StaleClaim
    } else {
        ProviderResultRepositoryError::NotFound
    })
}

fn phase(value: &str) -> Result<ProviderResultPhase, ProviderResultRepositoryError> {
    match value {
        "queued" => Ok(ProviderResultPhase::Queued),
        "running" => Ok(ProviderResultPhase::Running),
        "completed" => Ok(ProviderResultPhase::Completed),
        _ => Err(ProviderResultRepositoryError::Corrupt),
    }
}

fn conclusion(
    value: Option<&str>,
) -> Result<Option<ProviderResultConclusion>, ProviderResultRepositoryError> {
    value
        .map(|value| match value {
            "success" => Ok(ProviderResultConclusion::Success),
            "failure" => Ok(ProviderResultConclusion::Failure),
            "error" => Ok(ProviderResultConclusion::Error),
            "cancelled" => Ok(ProviderResultConclusion::Cancelled),
            "skipped" => Ok(ProviderResultConclusion::Skipped),
            "timed-out" => Ok(ProviderResultConclusion::TimedOut),
            "neutral" => Ok(ProviderResultConclusion::Neutral),
            "action-required" => Ok(ProviderResultConclusion::ActionRequired),
            _ => Err(ProviderResultRepositoryError::Corrupt),
        })
        .transpose()
}

fn annotation_level(
    value: &str,
) -> Result<ProviderResultAnnotationLevel, ProviderResultRepositoryError> {
    match value {
        "notice" => Ok(ProviderResultAnnotationLevel::Notice),
        "warning" => Ok(ProviderResultAnnotationLevel::Warning),
        "failure" => Ok(ProviderResultAnnotationLevel::Failure),
        _ => Err(ProviderResultRepositoryError::Corrupt),
    }
}

fn git_object(algorithm: &str, bytes: &[u8]) -> Result<GitObjectId, ProviderResultRepositoryError> {
    let algorithm = match algorithm {
        "sha1" => GitObjectAlgorithm::Sha1,
        "sha256" => GitObjectAlgorithm::Sha256,
        _ => return Err(ProviderResultRepositoryError::Corrupt),
    };
    GitObjectId::from_bytes(algorithm, bytes).map_err(|_| ProviderResultRepositoryError::Corrupt)
}

const fn object_algorithm_text(value: GitObjectAlgorithm) -> &'static str {
    match value {
        GitObjectAlgorithm::Sha1 => "sha1",
        GitObjectAlgorithm::Sha256 => "sha256",
    }
}

const fn phase_text(value: ProviderResultPhase) -> &'static str {
    match value {
        ProviderResultPhase::Queued => "queued",
        ProviderResultPhase::Running => "running",
        ProviderResultPhase::Completed => "completed",
    }
}

const fn conclusion_text(value: ProviderResultConclusion) -> &'static str {
    match value {
        ProviderResultConclusion::Success => "success",
        ProviderResultConclusion::Failure => "failure",
        ProviderResultConclusion::Error => "error",
        ProviderResultConclusion::Cancelled => "cancelled",
        ProviderResultConclusion::Skipped => "skipped",
        ProviderResultConclusion::TimedOut => "timed-out",
        ProviderResultConclusion::Neutral => "neutral",
        ProviderResultConclusion::ActionRequired => "action-required",
    }
}

const fn annotation_level_text(value: ProviderResultAnnotationLevel) -> &'static str {
    match value {
        ProviderResultAnnotationLevel::Notice => "notice",
        ProviderResultAnnotationLevel::Warning => "warning",
        ProviderResultAnnotationLevel::Failure => "failure",
    }
}

const fn publication_model_text(value: ProviderResultPublicationModel) -> &'static str {
    match value {
        ProviderResultPublicationModel::MutableRichCheck => "mutable-rich-check",
        ProviderResultPublicationModel::AppendOnlyCommitStatus => "append-only-commit-status",
    }
}

const fn failure_kind_text(value: ProviderResultFailureKind) -> &'static str {
    match value {
        ProviderResultFailureKind::Unsupported => "unsupported",
        ProviderResultFailureKind::Unauthorized => "unauthorized",
        ProviderResultFailureKind::Forbidden => "forbidden",
        ProviderResultFailureKind::InvalidResponse => "invalid-response",
        ProviderResultFailureKind::Conflict => "conflict",
        ProviderResultFailureKind::AttemptLimit => "attempt-limit",
    }
}

fn digest(value: &[u8]) -> Result<Sha256Digest, ProviderResultRepositoryError> {
    value
        .try_into()
        .map(Sha256Digest::from_bytes)
        .map_err(|_| ProviderResultRepositoryError::Corrupt)
}

fn continuation(
    row: &ResultRow,
) -> Result<Option<ProviderResultContinuation>, ProviderResultRepositoryError> {
    match (
        row.continuation_schema,
        row.continuation_bytes.as_ref(),
        row.continuation_digest.as_deref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(schema), Some(bytes), Some(stored_digest)) => {
            let schema = u16::try_from(schema)
                .ok()
                .and_then(|schema| ProviderSchemaVersion::new(schema).ok())
                .ok_or(ProviderResultRepositoryError::Corrupt)?;
            let continuation =
                ProviderResultContinuation::new(schema, bytes.clone()).map_err(model_corrupt)?;
            if digest(stored_digest)? != continuation.digest() {
                return Err(ProviderResultRepositoryError::Corrupt);
            }
            Ok(Some(continuation))
        }
        _ => Err(ProviderResultRepositoryError::Corrupt),
    }
}

fn durable_u64(value: u64) -> Result<i64, ProviderResultRepositoryError> {
    i64::try_from(value).map_err(|_| ProviderResultRepositoryError::Corrupt)
}

fn positive_u64(value: i64) -> Result<u64, ProviderResultRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ProviderResultRepositoryError::Corrupt)
}

const fn model_corrupt(_: ProviderResultModelError) -> ProviderResultRepositoryError {
    ProviderResultRepositoryError::Corrupt
}

const fn map_manifest_error(
    error: automata_ci_provider::ProviderRepositoryError,
) -> ProviderResultRepositoryError {
    match error {
        automata_ci_provider::ProviderRepositoryError::Unavailable => {
            ProviderResultRepositoryError::Unavailable
        }
        automata_ci_provider::ProviderRepositoryError::NotFound
        | automata_ci_provider::ProviderRepositoryError::Conflict
        | automata_ci_provider::ProviderRepositoryError::Corrupt
        | automata_ci_provider::ProviderRepositoryError::SecretCustody => {
            ProviderResultRepositoryError::Corrupt
        }
    }
}

fn unavailable(_: sqlx::Error) -> ProviderResultRepositoryError {
    ProviderResultRepositoryError::Unavailable
}
