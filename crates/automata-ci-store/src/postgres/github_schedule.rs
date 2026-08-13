use async_trait::async_trait;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_schedule::CronExpression;
use sqlx::{AssertSqlSafe, PgPool, Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::PostgresStore;
use crate::{
    AdmitLogicalWorkflowRun, ClaimDueGithubScheduleFire, ClaimGithubScheduleDiscovery,
    ClaimedGithubScheduleFire, CompleteGithubScheduleFire, GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE,
    GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE, GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE,
    GithubCheckSubjectKey, GithubCheckSubjectReceipt, GithubScheduleArchive,
    GithubScheduleClaimFence, GithubScheduleDiscoveryClaim, GithubScheduleFireClaim,
    GithubScheduleFireConclusion, GithubScheduleFireId, GithubScheduleFireReceipt,
    GithubScheduleRegistryEntry, GithubScheduleRegistryId, GithubScheduleRegistryReceipt,
    GithubScheduleRepository, GithubScheduleSourceAuthority, GithubScheduleStoreError,
    GithubScheduleWorkerId, LogicalWorkflowAdmissionStoreError, MAX_GITHUB_SCHEDULE_CLAIM_MILLIS,
    MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS, ObjectKey, ProviderConnectionId,
    RegisterGithubScheduleRegistry, RegisterGithubScheduledCheckSubject, RepositoryId,
    RetryGithubScheduleFire, StoreError, TenantScope,
};

#[async_trait]
impl GithubScheduleRepository for PostgresStore {
    async fn claim_github_schedule_discovery(
        &self,
        request: ClaimGithubScheduleDiscovery,
    ) -> Result<GithubScheduleDiscoveryClaim, GithubScheduleStoreError> {
        claim_schedule_discovery(&self.pool, request).await
    }

    async fn register_github_schedule_registry(
        &self,
        request: RegisterGithubScheduleRegistry,
    ) -> Result<GithubScheduleRegistryReceipt, GithubScheduleStoreError> {
        register_schedule_registry(&self.pool, request).await
    }

    async fn claim_due_github_schedule_fire(
        &self,
        request: ClaimDueGithubScheduleFire,
    ) -> Result<Option<ClaimedGithubScheduleFire>, GithubScheduleStoreError> {
        claim_due_schedule_fire(&self.pool, request).await
    }

    async fn renew_github_schedule_fire(
        &self,
        claim: GithubScheduleFireClaim,
        lease_millis: i64,
    ) -> Result<GithubScheduleFireClaim, GithubScheduleStoreError> {
        renew_schedule_fire(&self.pool, claim, lease_millis).await
    }

    async fn register_github_scheduled_check_subject(
        &self,
        request: RegisterGithubScheduledCheckSubject,
    ) -> Result<GithubCheckSubjectReceipt, GithubScheduleStoreError> {
        register_scheduled_check_subject(&self.pool, request).await
    }

    async fn retry_github_schedule_fire(
        &self,
        request: RetryGithubScheduleFire,
    ) -> Result<GithubScheduleFireReceipt, GithubScheduleStoreError> {
        retry_schedule_fire(&self.pool, request).await
    }

    async fn complete_github_schedule_fire(
        &self,
        request: CompleteGithubScheduleFire,
    ) -> Result<GithubScheduleFireReceipt, GithubScheduleStoreError> {
        complete_schedule_fire(&self.pool, request).await
    }
}

async fn claim_schedule_discovery(
    pool: &PgPool,
    request: ClaimGithubScheduleDiscovery,
) -> Result<GithubScheduleDiscoveryClaim, GithubScheduleStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let now = database_now(&mut transaction).await?;
    expire_schedule_discovery_claim(&mut transaction, &request, now).await?;
    lock_and_verify_discovery_manifest(&mut transaction, &request, now).await?;
    if let Some(claim) = exact_discovery_claim_replay(&mut transaction, &request, now).await? {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(claim);
    }
    let claim = insert_schedule_discovery_claim(&mut transaction, &request, now).await?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(claim)
}

async fn expire_schedule_discovery_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimGithubScheduleDiscovery,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    sqlx::query(
        r"
        UPDATE github_schedule_discovery_claims
           SET state = 'expired', updated_at_ms = $4
         WHERE tenant_id = $1
           AND repository_id = $2
           AND provider_connection_id = $3
           AND state = 'claimed'
           AND claim_expires_at_ms <= $4
        ",
    )
    .bind(request.manifest().tenant().as_str())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn lock_and_verify_discovery_manifest(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimGithubScheduleDiscovery,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let manifest = request.manifest();
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
              FROM github_provider_manifest_current AS current
              JOIN github_provider_manifest_revisions AS revision
                ON revision.tenant_id = current.tenant_id
               AND revision.repository_id = current.repository_id
               AND revision.provider_connection_id = current.provider_connection_id
               AND revision.manifest_revision = current.manifest_revision
               AND revision.manifest_digest = current.manifest_digest
             WHERE current.tenant_id = $1
               AND current.repository_id = $2
               AND current.provider_connection_id = $3
               AND current.manifest_revision = $4
               AND current.manifest_digest = $5
               AND revision.git_ref = $6
               AND revision.github_repository_owner_id = $7
             FOR UPDATE OF current
        )
        ",
    )
    .bind(manifest.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(manifest.connection_id().as_uuid())
    .bind(i64_from_u64(manifest.revision().get())?)
    .bind(manifest.digest().as_bytes().as_slice())
    .bind(manifest.git_ref())
    .bind(i64_from_u64(request.repository_owner_id().get())?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if !exact {
        return Err(GithubScheduleStoreError::Conflict);
    }
    verify_discovery_source_authority(transaction, request, now).await
}

async fn verify_discovery_source_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimGithubScheduleDiscovery,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let GithubScheduleSourceAuthority::Private(selector) = request.source_authority() else {
        return Ok(());
    };
    let manifest = request.manifest();
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
              FROM github_server_service_authorities AS authority
             WHERE authority.tenant_id = $1
               AND authority.id = $2
               AND authority.repository_id = $3
               AND authority.provider_connection_id = $4
               AND authority.provider_installation_id = $5
               AND authority.github_app_id = $6
               AND authority.github_repository_id = $7
               AND authority.github_repository_name = $8
               AND authority.service_scope = 'private_repository_source_read'
               AND authority.github_app_client_id = $9
               AND authority.github_app_jwt_issuer_kind = $10
               AND authority.app_key_spki_sha256 = $11
               AND authority.identity_digest = $12
               AND authority.app_configuration_revision = $13
               AND authority.policy_revision = $14
               AND authority.state = 'active'
               AND authority.created_at_ms <= $15
             FOR SHARE
        )
        ",
    )
    .bind(manifest.tenant().as_str())
    .bind(selector.authority_id().as_uuid())
    .bind(manifest.repository_id().as_uuid())
    .bind(manifest.connection_id().as_uuid())
    .bind(i64_from_u64(manifest.installation_id().get())?)
    .bind(i64_from_u64(manifest.github_app_id().get())?)
    .bind(i64_from_u64(manifest.github_repository_id().get())?)
    .bind(manifest.github_repository_name().as_str())
    .bind(manifest.app_client_id().as_str())
    .bind(manifest.jwt_issuer().as_str())
    .bind(manifest.app_key_spki_sha256().as_bytes().as_slice())
    .bind(selector.identity_digest().as_bytes().as_slice())
    .bind(i64_from_u64(selector.app_configuration_revision().get())?)
    .bind(i64_from_u64(selector.policy_revision().get())?)
    .bind(now.get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact {
        Ok(())
    } else {
        Err(GithubScheduleStoreError::Conflict)
    }
}

async fn exact_discovery_claim_replay(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimGithubScheduleDiscovery,
    now: UnixMillis,
) -> Result<Option<GithubScheduleDiscoveryClaim>, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT tenant_id, repository_id, provider_connection_id,
               manifest_revision, manifest_digest, github_repository_owner_id,
               source_authority_kind, private_source_authority_id,
               private_source_authority_identity_digest,
               private_source_authority_app_configuration_revision,
               private_source_authority_policy_revision,
               claim_owner_id, claim_fence, state, claimed_at_ms,
               claim_expires_at_ms, completed_registry_id
          FROM github_schedule_discovery_claims
         WHERE discovery_id = $1
         FOR UPDATE
        ",
    )
    .bind(request.registry_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let manifest = request.manifest();
    let state: String = row.try_get("state").map_err(corrupt)?;
    let expires_at = UnixMillis::new(row.try_get("claim_expires_at_ms").map_err(corrupt)?);
    let completed_registry_id: Option<Uuid> =
        row.try_get("completed_registry_id").map_err(corrupt)?;
    if row.try_get::<String, _>("tenant_id").map_err(corrupt)? != manifest.tenant().as_str()
        || row.try_get::<Uuid, _>("repository_id").map_err(corrupt)?
            != manifest.repository_id().as_uuid()
        || row
            .try_get::<Uuid, _>("provider_connection_id")
            .map_err(corrupt)?
            != manifest.connection_id().as_uuid()
        || row
            .try_get::<i64, _>("manifest_revision")
            .map_err(corrupt)?
            != i64_from_u64(manifest.revision().get())?
        || digest(&row, "manifest_digest")? != manifest.digest()
        || row
            .try_get::<i64, _>("github_repository_owner_id")
            .map_err(corrupt)?
            != i64_from_u64(request.repository_owner_id().get())?
        || row.try_get::<Uuid, _>("claim_owner_id").map_err(corrupt)?
            != request.worker_id().as_uuid()
        || !registry_source_authority_is_exact(&row, request.source_authority())?
        || !(state == "claimed" && now < expires_at && completed_registry_id.is_none()
            || state == "completed" && completed_registry_id.is_some())
    {
        return Err(GithubScheduleStoreError::Conflict);
    }
    let fence = GithubScheduleClaimFence::new(
        u64::try_from(row.try_get::<i64, _>("claim_fence").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    GithubScheduleDiscoveryClaim::from_durable_parts(
        request.registry_id(),
        request.worker_id(),
        fence,
        UnixMillis::new(row.try_get("claimed_at_ms").map_err(corrupt)?),
        expires_at,
    )
    .map(Some)
    .map_err(|_| GithubScheduleStoreError::CorruptData)
}

async fn insert_schedule_discovery_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ClaimGithubScheduleDiscovery,
    now: UnixMillis,
) -> Result<GithubScheduleDiscoveryClaim, GithubScheduleStoreError> {
    let expires_at = UnixMillis::new(checked_add(now.get(), request.lease_millis())?);
    let private = request.source_authority().private_selector();
    let result = sqlx::query(
        r"
        INSERT INTO github_schedule_discovery_claims (
            discovery_id, tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, github_repository_owner_id,
            source_authority_kind, private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision,
            claim_owner_id, claim_fence, state, claimed_at_ms,
            claim_expires_at_ms, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, 1, 'claimed', $14, $15, $14, $14
        )
        ",
    )
    .bind(request.registry_id().as_uuid())
    .bind(request.manifest().tenant().as_str())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .bind(i64_from_u64(request.manifest().revision().get())?)
    .bind(request.manifest().digest().as_bytes().as_slice())
    .bind(i64_from_u64(request.repository_owner_id().get())?)
    .bind(request.source_authority().as_durable_str())
    .bind(private.map(|selector| selector.authority_id().as_uuid()))
    .bind(private.map(|selector| selector.identity_digest().as_bytes().to_vec()))
    .bind(
        private
            .map(|selector| i64_from_u64(selector.app_configuration_revision().get()))
            .transpose()?,
    )
    .bind(
        private
            .map(|selector| i64_from_u64(selector.policy_revision().get()))
            .transpose()?,
    )
    .bind(request.worker_id().as_uuid())
    .bind(now.get())
    .bind(expires_at.get())
    .execute(&mut **transaction)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {
            GithubScheduleDiscoveryClaim::from_durable_parts(
                request.registry_id(),
                request.worker_id(),
                GithubScheduleClaimFence::new(1).expect("one is a valid fence"),
                now,
                expires_at,
            )
            .map_err(|_| GithubScheduleStoreError::CorruptData)
        }
        Ok(_) => Err(GithubScheduleStoreError::CorruptData),
        Err(error) if integrity_violation(&error) => Err(GithubScheduleStoreError::Conflict),
        Err(error) => Err(operation_error(error)),
    }
}

async fn register_schedule_registry(
    pool: &PgPool,
    request: RegisterGithubScheduleRegistry,
) -> Result<GithubScheduleRegistryReceipt, GithubScheduleStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let registered_at = database_now(&mut transaction).await?;
    let completed_registry =
        lock_and_verify_registration_discovery(&mut transaction, &request, registered_at).await?;
    lock_and_verify_current_manifest(&mut transaction, &request, registered_at).await?;
    if let Some(receipt) = exact_registry_replay(&mut transaction, &request).await? {
        if let Some(completed_registry) = completed_registry {
            if receipt.registry_id() != completed_registry {
                return Err(GithubScheduleStoreError::Conflict);
            }
        } else {
            complete_schedule_discovery(
                &mut transaction,
                &request,
                receipt.registry_id(),
                registered_at,
            )
            .await?;
        }
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    if completed_registry.is_some() {
        return Err(GithubScheduleStoreError::Conflict);
    }
    if request
        .entries()
        .iter()
        .any(|entry| entry.next_fire_at() <= registered_at)
    {
        return Err(GithubScheduleStoreError::Conflict);
    }
    supersede_current_registry(&mut transaction, &request, registered_at).await?;
    insert_registry_revision(&mut transaction, &request, registered_at).await?;
    insert_registry_entries(&mut transaction, &request).await?;
    seal_registry(&mut transaction, &request, registered_at).await?;
    activate_registry(&mut transaction, &request, registered_at).await?;
    insert_registry_runtime(&mut transaction, &request, registered_at).await?;
    complete_schedule_discovery(
        &mut transaction,
        &request,
        request.registry_id(),
        registered_at,
    )
    .await?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(GithubScheduleRegistryReceipt::from_durable_parts(
        request.registry_id(),
        registered_at,
        false,
    ))
}

async fn claim_due_schedule_fire(
    pool: &PgPool,
    request: ClaimDueGithubScheduleFire,
) -> Result<Option<ClaimedGithubScheduleFire>, GithubScheduleStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let now = database_now(&mut transaction).await?;
    loop {
        let Some(due) = lock_due_runtime(&mut transaction, now).await? else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        };
        let fire_id = ensure_fire(&mut transaction, &due, now).await?;
        if expire_prior_claim(&mut transaction, fire_id, now).await? {
            continue;
        }
        let claim = claim_fire(&mut transaction, fire_id, request, now).await?;
        let claimed = load_claimed_fire(&mut transaction, claim).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(Some(claimed));
    }
}

async fn renew_schedule_fire(
    pool: &PgPool,
    claim: GithubScheduleFireClaim,
    lease_millis: i64,
) -> Result<GithubScheduleFireClaim, GithubScheduleStoreError> {
    if lease_millis <= 0 || lease_millis > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS {
        return Err(GithubScheduleStoreError::ClaimRejected);
    }
    let row = sqlx::query(
        r"
        WITH stamp AS (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
        )
        UPDATE github_schedule_fires AS fire
           SET claim_expires_at_ms = stamp.now_ms + $7,
               updated_at_ms = stamp.now_ms
          FROM stamp
         WHERE fire.fire_id = $1
           AND fire.state = 'claimed'
           AND fire.claim_owner_id = $2
           AND fire.attempt_count = $3
           AND fire.claim_fence = $4
           AND fire.claimed_at_ms = $5
           AND fire.claim_expires_at_ms = $6
           AND stamp.now_ms < fire.claim_expires_at_ms
           AND stamp.now_ms + $7 > fire.claim_expires_at_ms
        RETURNING fire.claimed_at_ms, fire.claim_expires_at_ms
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::ClaimRejected)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(lease_millis)
    .fetch_optional(pool)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    GithubScheduleFireClaim::from_durable_parts(
        claim.fire_id(),
        claim.worker_id(),
        claim.attempt(),
        claim.fence(),
        UnixMillis::new(row.try_get("claimed_at_ms").map_err(corrupt)?),
        UnixMillis::new(row.try_get("claim_expires_at_ms").map_err(corrupt)?),
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)
}

async fn register_scheduled_check_subject(
    pool: &PgPool,
    request: RegisterGithubScheduledCheckSubject,
) -> Result<GithubCheckSubjectReceipt, GithubScheduleStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let source = lock_scheduled_check_source(&mut transaction, request.claim()).await?;
    let now = database_now(&mut transaction).await?;
    if now < request.claim().claimed_at() || now >= request.claim().expires_at() {
        return Err(GithubScheduleStoreError::ClaimRejected);
    }
    if let Some(receipt) =
        load_exact_scheduled_check(&mut transaction, request.claim().fire_id(), &source).await?
    {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let receipt = insert_scheduled_check(&mut transaction, request.claim(), &source, now).await?;
    transaction.commit().await.map_err(configuration_error)?;
    Ok(receipt)
}

async fn retry_schedule_fire(
    pool: &PgPool,
    request: RetryGithubScheduleFire,
) -> Result<GithubScheduleFireReceipt, GithubScheduleStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let now = database_now(&mut transaction).await?;
    let claim = request.claim();
    if claim.attempt() == MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS {
        terminalize_exhausted_fire(&mut transaction, claim, now).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(GithubScheduleFireReceipt::from_durable_parts(
            claim.fire_id(),
            now,
        ));
    }
    let changed = sqlx::query(
        r"
        UPDATE github_schedule_fires
           SET state = 'pending', claim_owner_id = NULL, claimed_at_ms = NULL,
               claim_expires_at_ms = NULL, next_attempt_at_ms = $7, updated_at_ms = $8
         WHERE fire_id = $1 AND state = 'claimed' AND claim_owner_id = $2
           AND attempt_count = $3 AND claim_fence = $4 AND claimed_at_ms = $5
           AND claim_expires_at_ms = $6 AND claim_expires_at_ms > $8
           AND attempt_count < $9
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::ClaimRejected)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(checked_add(now.get(), request.retry_after_millis())?)
    .bind(now.get())
    .bind(i16::try_from(MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS).expect("fixed bound fits SMALLINT"))
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() != 1 {
        return Err(GithubScheduleStoreError::ClaimRejected);
    }
    insert_attempt(
        &mut transaction,
        claim,
        now,
        "retry",
        Some(request.failure_kind()),
    )
    .await?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(GithubScheduleFireReceipt::from_durable_parts(
        claim.fire_id(),
        now,
    ))
}

struct ScheduleFireOutcome<'a> {
    state: &'static str,
    run_id: Option<Uuid>,
    failure_kind: Option<&'a str>,
    check_terminal: Option<(&'static str, &'static str)>,
}

impl<'a> ScheduleFireOutcome<'a> {
    fn from_conclusion(conclusion: &'a GithubScheduleFireConclusion) -> Self {
        match conclusion {
            GithubScheduleFireConclusion::Admitted(run_id) => Self {
                state: "admitted",
                run_id: Some(run_id.as_uuid()),
                failure_kind: None,
                check_terminal: None,
            },
            GithubScheduleFireConclusion::Skipped(kind) => Self {
                state: "skipped",
                run_id: None,
                failure_kind: Some(kind),
                check_terminal: Some(("skipped", "workflow_skipped")),
            },
            GithubScheduleFireConclusion::Failed(kind) => Self {
                state: "failed",
                run_id: None,
                failure_kind: Some(kind),
                check_terminal: Some(("failure", "workflow_failure")),
            },
        }
    }
}

struct TerminalFireRow {
    tenant_id: String,
    repository_id: Uuid,
    connection_id: Uuid,
    registry_id: Uuid,
    entry_ordinal: i16,
    scheduled_at: i64,
}

async fn complete_schedule_fire(
    pool: &PgPool,
    request: CompleteGithubScheduleFire,
) -> Result<GithubScheduleFireReceipt, GithubScheduleStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let now = database_now(&mut transaction).await?;
    let claim = request.claim();
    let outcome = ScheduleFireOutcome::from_conclusion(request.conclusion());
    let row = transition_terminal_fire(&mut transaction, claim, &outcome, now).await?;
    update_schedule_runtime(
        &mut transaction,
        &row,
        request.next_fire_at(),
        outcome.failure_kind,
        now,
    )
    .await?;
    if let Some((conclusion, cause)) = outcome.check_terminal {
        terminalize_scheduled_check(&mut transaction, claim.fire_id(), now, conclusion, cause)
            .await?;
    }
    insert_attempt(
        &mut transaction,
        claim,
        now,
        outcome.state,
        outcome.failure_kind,
    )
    .await?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(GithubScheduleFireReceipt::from_durable_parts(
        claim.fire_id(),
        now,
    ))
}

async fn transition_terminal_fire(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
    outcome: &ScheduleFireOutcome<'_>,
    now: UnixMillis,
) -> Result<TerminalFireRow, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        UPDATE github_schedule_fires
           SET state = $7, claim_owner_id = NULL, claimed_at_ms = NULL,
               claim_expires_at_ms = NULL, workflow_run_id = $8,
               failure_kind = $9, updated_at_ms = $10
         WHERE fire_id = $1 AND state = 'claimed' AND claim_owner_id = $2
           AND attempt_count = $3 AND claim_fence = $4 AND claimed_at_ms = $5
           AND claim_expires_at_ms = $6 AND claim_expires_at_ms > $10
        RETURNING tenant_id, repository_id, provider_connection_id,
                  registry_id, entry_ordinal, scheduled_at_ms
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::ClaimRejected)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(outcome.state)
    .bind(outcome.run_id)
    .bind(outcome.failure_kind)
    .bind(now.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    Ok(TerminalFireRow {
        tenant_id: row.try_get("tenant_id").map_err(corrupt)?,
        repository_id: row.try_get("repository_id").map_err(corrupt)?,
        connection_id: row.try_get("provider_connection_id").map_err(corrupt)?,
        registry_id: row.try_get("registry_id").map_err(corrupt)?,
        entry_ordinal: row.try_get("entry_ordinal").map_err(corrupt)?,
        scheduled_at: row.try_get("scheduled_at_ms").map_err(corrupt)?,
    })
}

async fn update_schedule_runtime(
    transaction: &mut Transaction<'_, Postgres>,
    row: &TerminalFireRow,
    next_fire_at: Option<UnixMillis>,
    failure_kind: Option<&str>,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let changed = match next_fire_at {
        Some(next) if next.get() > row.scheduled_at => sqlx::query(
            r"
            UPDATE github_schedule_runtime
               SET next_fire_at_ms = $6, updated_at_ms = $7
             WHERE tenant_id = $1 AND repository_id = $2
               AND provider_connection_id = $3 AND registry_id = $4
               AND entry_ordinal = $5 AND next_fire_at_ms = $8
            ",
        )
        .bind(&row.tenant_id)
        .bind(row.repository_id)
        .bind(row.connection_id)
        .bind(row.registry_id)
        .bind(row.entry_ordinal)
        .bind(next.get())
        .bind(now.get())
        .bind(row.scheduled_at)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected(),
        None if failure_kind == Some(GITHUB_SCHEDULE_INVALID_REGISTRY_FAILURE) => sqlx::query(
            r"
            DELETE FROM github_schedule_runtime
             WHERE tenant_id = $1 AND repository_id = $2
               AND provider_connection_id = $3 AND registry_id = $4
               AND entry_ordinal = $5 AND next_fire_at_ms = $6
            ",
        )
        .bind(&row.tenant_id)
        .bind(row.repository_id)
        .bind(row.connection_id)
        .bind(row.registry_id)
        .bind(row.entry_ordinal)
        .bind(row.scheduled_at)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected(),
        Some(_) | None => return Err(GithubScheduleStoreError::ClaimRejected),
    };
    if changed == 1 {
        Ok(())
    } else {
        Err(GithubScheduleStoreError::ClaimRejected)
    }
}

async fn terminalize_scheduled_check(
    transaction: &mut Transaction<'_, Postgres>,
    fire_id: GithubScheduleFireId,
    terminal_at: UnixMillis,
    conclusion: &str,
    cause: &str,
) -> Result<(), GithubScheduleStoreError> {
    let changed = sqlx::query(
        r"
        UPDATE github_check_subjects
           SET desired_state = 'completed',
               desired_conclusion = $2,
               terminal_cause = $3,
               desired_revision = desired_revision + 1,
               desired_updated_at_ms = $4
         WHERE origin_kind = 'scheduled_fire'
           AND provider_delivery_id IS NULL
           AND schedule_fire_id = $1
           AND desired_state IN ('queued', 'in_progress')
           AND desired_updated_at_ms <= $4
           AND desired_revision < 9223372036854775807
        ",
    )
    .bind(fire_id.as_uuid())
    .bind(conclusion)
    .bind(cause)
    .bind(terminal_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if changed > 1 {
        return Err(GithubScheduleStoreError::CorruptData);
    }
    if changed == 0 {
        let occupied: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM github_check_subjects WHERE schedule_fire_id = $1)",
        )
        .bind(fire_id.as_uuid())
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?;
        if occupied {
            return Err(GithubScheduleStoreError::Conflict);
        }
    }
    Ok(())
}

pub(crate) async fn record_github_scheduled_run_evidence_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: GithubScheduleFireClaim,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let source = lock_scheduled_check_source(transaction, claim)
        .await
        .map_err(schedule_admission_error)?;
    let now = database_now(transaction)
        .await
        .map_err(schedule_admission_error)?;
    require_scheduled_command(command, claim, &source, now)?;
    let subject_id = link_scheduled_check_to_run(transaction, command, &source).await?;
    insert_scheduled_run_evidence(transaction, command, claim, subject_id, &source).await
}

pub(crate) async fn validate_github_scheduled_run_evidence_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: GithubScheduleFireClaim,
    admitted_at: UnixMillis,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let source = lock_scheduled_check_source(transaction, claim)
        .await
        .map_err(schedule_admission_error)?;
    let now = database_now(transaction)
        .await
        .map_err(schedule_admission_error)?;
    require_scheduled_command(command, claim, &source, now)?;
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
              FROM github_schedule_workflow_run_subject_evidence AS evidence
              JOIN github_check_subjects AS subject
                ON subject.tenant_id = evidence.tenant_id
               AND subject.id = evidence.github_check_subject_id
              JOIN github_schedule_check_evidence AS schedule_check
                ON schedule_check.schedule_fire_id = evidence.schedule_fire_id
               AND schedule_check.github_check_subject_id = evidence.github_check_subject_id
              JOIN workflow_admission_receipts AS receipt
                ON receipt.tenant_id = evidence.tenant_id
               AND receipt.idempotency_kind = 'operation'
               AND receipt.idempotency_key = evidence.schedule_fire_id::TEXT
             WHERE evidence.schedule_fire_id = $1
               AND evidence.tenant_id = $2
               AND evidence.repository_id = $3
               AND evidence.workflow_id = $4
               AND evidence.snapshot_id = $5
               AND evidence.run_id = $6
               AND evidence.root_invocation_id = $7
               AND evidence.github_repository_owner_id = $17
               AND evidence.github_check_head_sha = $8
               AND evidence.workflow_path = $9
               AND evidence.source_digest = $10
               AND evidence.event_name = 'schedule'
               AND evidence.event_digest = $11
               AND evidence.git_ref = $12
               AND evidence.workflow_plan_schema = 1
               AND evidence.plan_digest = $13
               AND evidence.logical_admission_digest = $14
               AND evidence.admitted_at_ms = $15
               AND subject.origin_kind = 'scheduled_fire'
               AND subject.schedule_fire_id = evidence.schedule_fire_id
               AND subject.workflow_run_id = evidence.run_id
               AND subject.linked_at_ms = evidence.admitted_at_ms
               AND schedule_check.registry_id = $16
               AND schedule_check.github_repository_owner_id = $17
               AND receipt.request_digest = evidence.logical_admission_digest
               AND receipt.repository_id = evidence.repository_id
               AND receipt.run_id = evidence.run_id
               AND receipt.committed_at_ms = evidence.admitted_at_ms
               AND receipt.github_subject_evidence_required
        )
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(command.snapshot_id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(command.root_invocation_id().as_uuid())
    .bind(command.head_sha())
    .bind(command.workflow_path())
    .bind(command.source().digest().as_bytes().as_slice())
    .bind(command.event().digest().as_bytes().as_slice())
    .bind(command.git_ref())
    .bind(command.plan().digest().as_bytes().as_slice())
    .bind(command.request_digest().as_bytes().as_slice())
    .bind(admitted_at.get())
    .bind(source.registry_id)
    .bind(source.github_repository_owner_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(logical_operation_error)?;
    if exact {
        Ok(())
    } else {
        Err(StoreError::corrupt_data("scheduled GitHub admission replay is not exact").into())
    }
}

fn require_scheduled_command(
    command: &AdmitLogicalWorkflowRun,
    claim: GithubScheduleFireClaim,
    source: &ScheduledCheckSource,
    now: UnixMillis,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let exact = now >= claim.claimed_at()
        && now < claim.expires_at()
        && command.tenant().as_str() == source.tenant_id
        && command.repository().id().as_uuid() == source.repository_id
        && command.repository().provider() == "github"
        && command.repository().provider_repository_id() == source.github_repository_id.to_string()
        && format!(
            "{}/{}",
            command.repository().owner(),
            command.repository().name()
        ) == source.github_repository_name
        && command.workflow_path() == source.workflow_path
        && command.git_ref() == source.default_branch_ref
        && command.head_sha() == decode_sha1(&source.source_revision)?
        && command.source().digest().as_bytes().as_slice()
            == source.workflow_source_digest.as_slice()
        && command.event_name() == "schedule"
        && command.admitted_at() >= claim.claimed_at()
        && command.admitted_at() < claim.expires_at();
    if exact {
        Ok(())
    } else {
        Err(StoreError::corrupt_data("scheduled GitHub admission source is not exact").into())
    }
}

async fn link_scheduled_check_to_run(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    source: &ScheduledCheckSource,
) -> Result<Uuid, LogicalWorkflowAdmissionStoreError> {
    sqlx::query_scalar(
        r"
        UPDATE github_check_subjects AS subject
           SET workflow_run_id = $2,
               linked_at_ms = $3,
               desired_state = 'in_progress',
               desired_revision = subject.desired_revision + 1,
               desired_updated_at_ms = $3
          FROM github_schedule_check_evidence AS evidence
         WHERE subject.schedule_fire_id = $1
           AND subject.origin_kind = 'scheduled_fire'
           AND subject.provider_delivery_id IS NULL
           AND subject.workflow_run_id IS NULL
           AND subject.linked_at_ms IS NULL
           AND subject.desired_state = 'queued'
           AND subject.desired_revision = 1
           AND subject.tenant_id = $4
           AND subject.repository_id = $5
           AND subject.provider_connection_id = $6
           AND subject.subject_key = $7
           AND subject.head_sha = $8
           AND evidence.schedule_fire_id = subject.schedule_fire_id
           AND evidence.github_check_subject_id = subject.id
           AND evidence.registry_id = $9
        RETURNING subject.id
        ",
    )
    .bind(source.fire_id)
    .bind(command.run_id().as_uuid())
    .bind(command.admitted_at().get())
    .bind(&source.tenant_id)
    .bind(source.repository_id)
    .bind(source.connection_id)
    .bind(&source.workflow_path)
    .bind(command.head_sha())
    .bind(source.registry_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(logical_operation_error)?
    .ok_or_else(|| {
        StoreError::corrupt_data("scheduled Check could not link to admitted run").into()
    })
}

async fn insert_scheduled_run_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: GithubScheduleFireClaim,
    subject_id: Uuid,
    source: &ScheduledCheckSource,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_schedule_workflow_run_subject_evidence (
            schedule_fire_id, tenant_id, repository_id, workflow_id,
            snapshot_id, run_id, root_invocation_id, github_repository_owner_id,
            admission_claim_owner_id, admission_claim_attempt,
            admission_claim_fence, admission_claimed_at_ms,
            admission_claim_expires_at_ms, github_check_subject_id,
            github_check_head_sha, workflow_path, source_digest,
            event_name, event_digest, git_ref, workflow_plan_schema,
            plan_digest, logical_admission_digest, admitted_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            'schedule',$18,$19,1,$20,$21,$22
        )
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(command.snapshot_id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(command.root_invocation_id().as_uuid())
    .bind(source.github_repository_owner_id)
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| {
        StoreError::corrupt_data("scheduled admission claim attempt is out of range")
    })?)
    .bind(i64_from_u64(claim.fence().get()).map_err(schedule_admission_error)?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(subject_id)
    .bind(command.head_sha())
    .bind(command.workflow_path())
    .bind(command.source().digest().as_bytes().as_slice())
    .bind(command.event().digest().as_bytes().as_slice())
    .bind(command.git_ref())
    .bind(command.plan().digest().as_bytes().as_slice())
    .bind(command.request_digest().as_bytes().as_slice())
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(logical_operation_error)?;
    Ok(())
}

#[derive(Debug)]
struct ScheduledCheckSource {
    tenant_id: String,
    repository_id: Uuid,
    connection_id: Uuid,
    fire_id: Uuid,
    registry_id: Uuid,
    entry_ordinal: i16,
    scheduled_at_ms: i64,
    manifest_revision: i64,
    manifest_digest: Vec<u8>,
    default_branch_ref: String,
    source_revision: String,
    workflow_path: String,
    workflow_source_digest: Vec<u8>,
    provider_installation_id: i64,
    github_repository_id: i64,
    github_repository_owner_id: i64,
    github_repository_name: String,
    github_app_id: i64,
    check_name: String,
    github_app_client_id: String,
    github_app_jwt_issuer_kind: String,
    app_key_spki_sha256: Vec<u8>,
    app_configuration_revision: i64,
    policy_revision: i64,
}

async fn lock_scheduled_check_source(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
) -> Result<ScheduledCheckSource, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT fire.tenant_id, fire.repository_id, fire.provider_connection_id,
               fire.fire_id, fire.registry_id, fire.entry_ordinal,
               fire.scheduled_at_ms,
               registry.manifest_revision, registry.manifest_digest,
               registry.default_branch_ref, registry.source_revision,
               registry.github_repository_owner_id,
               entry.workflow_path, entry.workflow_source_digest,
               manifest.provider_installation_id,
               manifest.github_repository_id,
               manifest.github_repository_name,
               manifest.github_app_id, manifest.check_name,
               manifest.github_app_client_id,
               manifest.github_app_jwt_issuer_kind,
               manifest.app_key_spki_sha256,
               manifest.app_configuration_revision,
               manifest.policy_revision
          FROM github_schedule_fires AS fire
          JOIN github_schedule_registry_revisions AS registry
            ON registry.tenant_id = fire.tenant_id
           AND registry.repository_id = fire.repository_id
           AND registry.provider_connection_id = fire.provider_connection_id
           AND registry.registry_id = fire.registry_id
          JOIN github_schedule_registry_entries AS entry
            ON entry.registry_id = fire.registry_id
           AND entry.ordinal = fire.entry_ordinal
          JOIN github_schedule_registry_seals AS seal
            ON seal.registry_id = registry.registry_id
           AND seal.inventory_digest = registry.inventory_digest
           AND seal.schedule_count = registry.schedule_count
          JOIN github_schedule_registry_current AS current
            ON current.tenant_id = registry.tenant_id
           AND current.repository_id = registry.repository_id
           AND current.provider_connection_id = registry.provider_connection_id
           AND current.registry_id = registry.registry_id
          JOIN github_provider_manifest_revisions AS manifest
            ON manifest.tenant_id = registry.tenant_id
           AND manifest.repository_id = registry.repository_id
           AND manifest.provider_connection_id = registry.provider_connection_id
           AND manifest.manifest_revision = registry.manifest_revision
           AND manifest.manifest_digest = registry.manifest_digest
           AND manifest.git_ref = registry.default_branch_ref
          JOIN github_provider_manifest_current AS manifest_current
            ON manifest_current.tenant_id = manifest.tenant_id
           AND manifest_current.repository_id = manifest.repository_id
           AND manifest_current.provider_connection_id = manifest.provider_connection_id
           AND manifest_current.manifest_revision = manifest.manifest_revision
           AND manifest_current.manifest_digest = manifest.manifest_digest
         WHERE fire.fire_id = $1
           AND fire.state = 'claimed'
           AND fire.claim_owner_id = $2
           AND fire.attempt_count = $3
           AND fire.claim_fence = $4
           AND fire.claimed_at_ms = $5
           AND fire.claim_expires_at_ms = $6
         FOR UPDATE OF fire
         FOR SHARE OF registry, entry, seal, current, manifest, manifest_current
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::ClaimRejected)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    Ok(ScheduledCheckSource {
        tenant_id: row.try_get("tenant_id").map_err(corrupt)?,
        repository_id: row.try_get("repository_id").map_err(corrupt)?,
        connection_id: row.try_get("provider_connection_id").map_err(corrupt)?,
        fire_id: row.try_get("fire_id").map_err(corrupt)?,
        registry_id: row.try_get("registry_id").map_err(corrupt)?,
        entry_ordinal: row.try_get("entry_ordinal").map_err(corrupt)?,
        scheduled_at_ms: row.try_get("scheduled_at_ms").map_err(corrupt)?,
        manifest_revision: row.try_get("manifest_revision").map_err(corrupt)?,
        manifest_digest: row.try_get("manifest_digest").map_err(corrupt)?,
        default_branch_ref: row.try_get("default_branch_ref").map_err(corrupt)?,
        source_revision: row.try_get("source_revision").map_err(corrupt)?,
        workflow_path: row.try_get("workflow_path").map_err(corrupt)?,
        workflow_source_digest: row.try_get("workflow_source_digest").map_err(corrupt)?,
        provider_installation_id: row.try_get("provider_installation_id").map_err(corrupt)?,
        github_repository_id: row.try_get("github_repository_id").map_err(corrupt)?,
        github_repository_owner_id: row.try_get("github_repository_owner_id").map_err(corrupt)?,
        github_repository_name: row.try_get("github_repository_name").map_err(corrupt)?,
        github_app_id: row.try_get("github_app_id").map_err(corrupt)?,
        check_name: row.try_get("check_name").map_err(corrupt)?,
        github_app_client_id: row.try_get("github_app_client_id").map_err(corrupt)?,
        github_app_jwt_issuer_kind: row.try_get("github_app_jwt_issuer_kind").map_err(corrupt)?,
        app_key_spki_sha256: row.try_get("app_key_spki_sha256").map_err(corrupt)?,
        app_configuration_revision: row.try_get("app_configuration_revision").map_err(corrupt)?,
        policy_revision: row.try_get("policy_revision").map_err(corrupt)?,
    })
}

async fn load_exact_scheduled_check(
    transaction: &mut Transaction<'_, Postgres>,
    fire_id: GithubScheduleFireId,
    source: &ScheduledCheckSource,
) -> Result<Option<GithubCheckSubjectReceipt>, GithubScheduleStoreError> {
    let query = format!(
        r"
        SELECT {columns}
          FROM github_check_subjects AS subject
          JOIN github_schedule_check_evidence AS evidence
            ON evidence.tenant_id = subject.tenant_id
           AND evidence.repository_id = subject.repository_id
           AND evidence.provider_connection_id = subject.provider_connection_id
           AND evidence.schedule_fire_id = subject.schedule_fire_id
           AND evidence.github_check_subject_id = subject.id
          JOIN github_check_projection_outbox AS outbox
            ON outbox.subject_id = subject.id
         WHERE subject.origin_kind = 'scheduled_fire'
           AND subject.provider_delivery_id IS NULL
           AND subject.schedule_fire_id = $1
           AND subject.tenant_id = $2
           AND subject.repository_id = $3
           AND subject.provider_connection_id = $4
           AND subject.subject_key = $5
           AND subject.provider_installation_id = $6
           AND subject.github_repository_id = $7
           AND subject.github_repository_name = $8
           AND subject.github_app_id = $9
           AND subject.head_sha = decode($10, 'hex')
           AND subject.check_name = $11
           AND evidence.registry_id = $12
           AND evidence.entry_ordinal = $13
           AND evidence.scheduled_at_ms = $14
           AND evidence.provider_manifest_revision = $15
           AND evidence.provider_manifest_digest = $16
           AND evidence.default_branch_ref = $17
           AND evidence.source_revision = $10
           AND evidence.github_repository_owner_id = $18
           AND evidence.github_check_head_sha = subject.head_sha
           AND evidence.recorded_at_ms = subject.created_at_ms
        ",
        columns = super::github_checks::SUBJECT_COLUMNS,
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(fire_id.as_uuid())
        .bind(&source.tenant_id)
        .bind(source.repository_id)
        .bind(source.connection_id)
        .bind(&source.workflow_path)
        .bind(source.provider_installation_id)
        .bind(source.github_repository_id)
        .bind(&source.github_repository_name)
        .bind(source.github_app_id)
        .bind(&source.source_revision)
        .bind(&source.check_name)
        .bind(source.registry_id)
        .bind(source.entry_ordinal)
        .bind(source.scheduled_at_ms)
        .bind(source.manifest_revision)
        .bind(&source.manifest_digest)
        .bind(&source.default_branch_ref)
        .bind(source.github_repository_owner_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    if let Some(row) = row {
        let decoded = super::github_checks::decode_subject(&row)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?;
        return Ok(Some(decoded.receipt));
    }
    let occupied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM github_check_subjects WHERE schedule_fire_id = $1)",
    )
    .bind(fire_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if occupied {
        Err(GithubScheduleStoreError::Conflict)
    } else {
        Ok(None)
    }
}

async fn insert_scheduled_check(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
    source: &ScheduledCheckSource,
    recorded_at: UnixMillis,
) -> Result<GithubCheckSubjectReceipt, GithubScheduleStoreError> {
    let authority = lock_scheduled_check_authority(transaction, source, recorded_at).await?;
    let subject_id = Uuid::new_v4();
    let external_id = format!("automata-check:{subject_id}");
    let query = format!(
        r"
        INSERT INTO github_check_subjects AS subject (
            id, tenant_id, repository_id, origin_kind, provider_delivery_id,
            schedule_fire_id, subject_key, provider_connection_id,
            provider_installation_id, github_repository_id,
            github_repository_name, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        ) VALUES (
            $1, $2, $3, 'scheduled_fire', NULL, $4, $5, $6,
            $7, $8, $9, $10, decode($11, 'hex'), $12, $13, $14, $14
        )
        RETURNING {columns}
        ",
        columns = super::github_checks::SUBJECT_COLUMNS,
    );
    let subject = sqlx::query(AssertSqlSafe(query))
        .bind(subject_id)
        .bind(&source.tenant_id)
        .bind(source.repository_id)
        .bind(claim.fire_id().as_uuid())
        .bind(&source.workflow_path)
        .bind(source.connection_id)
        .bind(source.provider_installation_id)
        .bind(source.github_repository_id)
        .bind(&source.github_repository_name)
        .bind(source.github_app_id)
        .bind(&source.source_revision)
        .bind(&source.check_name)
        .bind(&external_id)
        .bind(recorded_at.get())
        .fetch_one(&mut **transaction)
        .await
        .map_err(configuration_error)?;
    insert_scheduled_check_evidence(transaction, source, &authority, subject_id, recorded_at)
        .await?;
    let decoded = super::github_checks::decode_subject(&subject)
        .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    Ok(decoded.receipt)
}

struct ScheduledCheckAuthority {
    id: Uuid,
    identity_digest: Vec<u8>,
    app_configuration_revision: i64,
    policy_revision: i64,
}

async fn lock_scheduled_check_authority(
    transaction: &mut Transaction<'_, Postgres>,
    source: &ScheduledCheckSource,
    recorded_at: UnixMillis,
) -> Result<ScheduledCheckAuthority, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT id, identity_digest, app_configuration_revision, policy_revision
          FROM github_server_service_authorities
         WHERE tenant_id = $1 AND repository_id = $2
           AND provider_connection_id = $3 AND provider_installation_id = $4
           AND github_app_id = $5 AND github_repository_id = $6
           AND github_repository_name = $7 AND service_scope = 'checks_write'
           AND github_app_client_id = $8 AND github_app_jwt_issuer_kind = $9
           AND app_key_spki_sha256 = $10 AND app_configuration_revision = $11
           AND policy_revision = $12 AND state = 'active' AND created_at_ms <= $13
         FOR SHARE
        ",
    )
    .bind(&source.tenant_id)
    .bind(source.repository_id)
    .bind(source.connection_id)
    .bind(source.provider_installation_id)
    .bind(source.github_app_id)
    .bind(source.github_repository_id)
    .bind(&source.github_repository_name)
    .bind(&source.github_app_client_id)
    .bind(&source.github_app_jwt_issuer_kind)
    .bind(&source.app_key_spki_sha256)
    .bind(source.app_configuration_revision)
    .bind(source.policy_revision)
    .bind(recorded_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::Conflict)?;
    Ok(ScheduledCheckAuthority {
        id: row.try_get("id").map_err(corrupt)?,
        identity_digest: row.try_get("identity_digest").map_err(corrupt)?,
        app_configuration_revision: row.try_get("app_configuration_revision").map_err(corrupt)?,
        policy_revision: row.try_get("policy_revision").map_err(corrupt)?,
    })
}

async fn insert_scheduled_check_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    source: &ScheduledCheckSource,
    authority: &ScheduledCheckAuthority,
    subject_id: Uuid,
    recorded_at: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_schedule_check_evidence (
            schedule_fire_id, tenant_id, repository_id, provider_connection_id,
            registry_id, entry_ordinal, scheduled_at_ms,
            provider_manifest_revision, provider_manifest_digest,
            default_branch_ref, source_revision, github_repository_owner_id,
            checks_authority_id, checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision, github_check_subject_id,
            github_check_head_sha, recorded_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, decode($11, 'hex'), $18
        )
        ",
    )
    .bind(source.fire_id)
    .bind(&source.tenant_id)
    .bind(source.repository_id)
    .bind(source.connection_id)
    .bind(source.registry_id)
    .bind(source.entry_ordinal)
    .bind(source.scheduled_at_ms)
    .bind(source.manifest_revision)
    .bind(&source.manifest_digest)
    .bind(&source.default_branch_ref)
    .bind(&source.source_revision)
    .bind(source.github_repository_owner_id)
    .bind(authority.id)
    .bind(&authority.identity_digest)
    .bind(authority.app_configuration_revision)
    .bind(authority.policy_revision)
    .bind(subject_id)
    .bind(recorded_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(configuration_error)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct DueRuntime {
    tenant_id: String,
    repository_id: Uuid,
    connection_id: Uuid,
    registry_id: Uuid,
    entry_ordinal: i16,
    scheduled_at: i64,
}

async fn lock_and_verify_registration_discovery(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    now: UnixMillis,
) -> Result<Option<GithubScheduleRegistryId>, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT tenant_id, repository_id, provider_connection_id,
               manifest_revision, manifest_digest, github_repository_owner_id,
               source_authority_kind, private_source_authority_id,
               private_source_authority_identity_digest,
               private_source_authority_app_configuration_revision,
               private_source_authority_policy_revision,
               claim_owner_id, claim_fence, state, claimed_at_ms,
               claim_expires_at_ms, completed_registry_id
          FROM github_schedule_discovery_claims
         WHERE discovery_id = $1
         FOR UPDATE
        ",
    )
    .bind(request.discovery_claim().registry_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    let manifest = request.manifest();
    let claim = request.discovery_claim();
    let state: String = row.try_get("state").map_err(corrupt)?;
    let completed_registry: Option<Uuid> = row.try_get("completed_registry_id").map_err(corrupt)?;
    if row.try_get::<String, _>("tenant_id").map_err(corrupt)? != manifest.tenant().as_str()
        || row.try_get::<Uuid, _>("repository_id").map_err(corrupt)?
            != manifest.repository_id().as_uuid()
        || row
            .try_get::<Uuid, _>("provider_connection_id")
            .map_err(corrupt)?
            != manifest.connection_id().as_uuid()
        || row
            .try_get::<i64, _>("manifest_revision")
            .map_err(corrupt)?
            != i64_from_u64(manifest.revision().get())?
        || digest(&row, "manifest_digest")? != manifest.digest()
        || row
            .try_get::<i64, _>("github_repository_owner_id")
            .map_err(corrupt)?
            != i64_from_u64(request.repository_owner_id().get())?
        || row.try_get::<Uuid, _>("claim_owner_id").map_err(corrupt)? != claim.worker_id().as_uuid()
        || row.try_get::<i64, _>("claim_fence").map_err(corrupt)?
            != i64_from_u64(claim.fence().get())?
        || row.try_get::<i64, _>("claimed_at_ms").map_err(corrupt)? != claim.claimed_at().get()
        || row
            .try_get::<i64, _>("claim_expires_at_ms")
            .map_err(corrupt)?
            != claim.expires_at().get()
        || !registry_source_authority_is_exact(&row, request.source_authority())?
    {
        return Err(GithubScheduleStoreError::Conflict);
    }
    match (state.as_str(), completed_registry) {
        ("claimed", None) if claim.claimed_at() <= now && now < claim.expires_at() => Ok(None),
        ("completed", Some(registry_id)) => GithubScheduleRegistryId::from_uuid(registry_id)
            .map(Some)
            .map_err(|_| GithubScheduleStoreError::CorruptData),
        _ => Err(GithubScheduleStoreError::ClaimRejected),
    }
}

async fn complete_schedule_discovery(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    completed_registry: GithubScheduleRegistryId,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let claim = request.discovery_claim();
    let result = sqlx::query(
        r"
        UPDATE github_schedule_discovery_claims
           SET state = 'completed', completed_registry_id = $6, updated_at_ms = $7
         WHERE discovery_id = $1
           AND state = 'claimed'
           AND claim_owner_id = $2
           AND claim_fence = $3
           AND claimed_at_ms = $4
           AND claim_expires_at_ms = $5
           AND $7 < claim_expires_at_ms
        ",
    )
    .bind(claim.registry_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(completed_registry.as_uuid())
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(GithubScheduleStoreError::ClaimRejected)
    }
}

async fn lock_and_verify_current_manifest(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    registered_at: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT revision.tenant_id, revision.repository_id,
               revision.manifest_revision, revision.manifest_digest,
               revision.git_ref
          FROM github_provider_manifest_current AS current
          JOIN github_provider_manifest_revisions AS revision
            ON revision.tenant_id = current.tenant_id
           AND revision.repository_id = current.repository_id
           AND revision.provider_connection_id = current.provider_connection_id
           AND revision.manifest_revision = current.manifest_revision
           AND revision.manifest_digest = current.manifest_digest
         WHERE current.provider_connection_id = $1
         FOR UPDATE OF current
        ",
    )
    .bind(request.manifest().connection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::Conflict)?;
    let manifest = request.manifest();
    if row.try_get::<String, _>("tenant_id").map_err(corrupt)? != manifest.tenant().as_str()
        || row.try_get::<Uuid, _>("repository_id").map_err(corrupt)?
            != manifest.repository_id().as_uuid()
        || row
            .try_get::<i64, _>("manifest_revision")
            .map_err(corrupt)?
            != i64::try_from(manifest.revision().get())
                .map_err(|_| GithubScheduleStoreError::CorruptData)?
        || digest(&row, "manifest_digest")? != manifest.digest()
        || row.try_get::<String, _>("git_ref").map_err(corrupt)? != manifest.git_ref()
    {
        return Err(GithubScheduleStoreError::Conflict);
    }
    verify_schedule_source_authority(transaction, request, registered_at).await
}

async fn verify_schedule_source_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    registered_at: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let GithubScheduleSourceAuthority::Private(selector) = request.source_authority() else {
        return Ok(());
    };
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
              FROM github_server_service_authorities AS authority
             WHERE authority.tenant_id = $1 AND authority.id = $2
               AND authority.repository_id = $3 AND authority.provider_connection_id = $4
               AND authority.provider_installation_id = $5 AND authority.github_app_id = $6
               AND authority.github_repository_id = $7 AND authority.github_repository_name = $8
               AND authority.service_scope = 'private_repository_source_read'
               AND authority.github_app_client_id = $9
               AND authority.github_app_jwt_issuer_kind = $10
               AND authority.app_key_spki_sha256 = $11
               AND authority.identity_digest = $12
               AND authority.app_configuration_revision = $13
               AND authority.policy_revision = $14
               AND authority.state = 'active' AND authority.created_at_ms <= $15
             FOR SHARE
        )
        ",
    )
    .bind(request.manifest().tenant().as_str())
    .bind(selector.authority_id().as_uuid())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .bind(i64_from_u64(request.manifest().installation_id().get())?)
    .bind(i64_from_u64(request.manifest().github_app_id().get())?)
    .bind(i64_from_u64(
        request.manifest().github_repository_id().get(),
    )?)
    .bind(request.manifest().github_repository_name().as_str())
    .bind(request.manifest().app_client_id().as_str())
    .bind(request.manifest().jwt_issuer().as_str())
    .bind(
        request
            .manifest()
            .app_key_spki_sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(selector.identity_digest().as_bytes().as_slice())
    .bind(i64_from_u64(selector.app_configuration_revision().get())?)
    .bind(i64_from_u64(selector.policy_revision().get())?)
    .bind(registered_at.get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact {
        Ok(())
    } else {
        Err(GithubScheduleStoreError::Conflict)
    }
}

async fn exact_registry_replay(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
) -> Result<Option<GithubScheduleRegistryReceipt>, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT registry.registry_id, registry.archive_digest,
               registry.archive_object_key, registry.archive_size_bytes,
               registry.default_branch_ref, registry.inventory_digest,
               registry.schedule_count, registry.discovered_at_ms,
               registry.github_repository_owner_id,
               registry.source_authority_kind,
               registry.private_source_authority_id,
               registry.private_source_authority_identity_digest,
               registry.private_source_authority_app_configuration_revision,
               registry.private_source_authority_policy_revision,
               current.registry_id AS current_registry_id
          FROM github_schedule_registry_revisions AS registry
          LEFT JOIN github_schedule_registry_current AS current
            ON current.tenant_id = registry.tenant_id
           AND current.repository_id = registry.repository_id
           AND current.provider_connection_id = registry.provider_connection_id
         WHERE registry.tenant_id = $1
           AND registry.repository_id = $2
           AND registry.provider_connection_id = $3
           AND registry.manifest_revision = $4
           AND registry.source_revision = $5
           AND registry.inventory_digest = $6
         FOR KEY SHARE OF registry
        ",
    )
    .bind(request.manifest().tenant().as_str())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .bind(
        i64::try_from(request.manifest().revision().get())
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .bind(request.source_revision())
    .bind(request.inventory_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let registry_id =
        GithubScheduleRegistryId::from_uuid(row.try_get("registry_id").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let current: Option<Uuid> = row.try_get("current_registry_id").map_err(corrupt)?;
    if digest(&row, "archive_digest")? != request.archive().digest()
        || row
            .try_get::<String, _>("archive_object_key")
            .map_err(corrupt)?
            != request.archive().object_key().as_str()
        || row
            .try_get::<i64, _>("archive_size_bytes")
            .map_err(corrupt)?
            != i64::try_from(request.archive().encoded_size())
                .map_err(|_| GithubScheduleStoreError::CorruptData)?
        || row
            .try_get::<String, _>("default_branch_ref")
            .map_err(corrupt)?
            != request.manifest().git_ref()
        || digest(&row, "inventory_digest")? != request.inventory_digest()
        || row.try_get::<i16, _>("schedule_count").map_err(corrupt)?
            != i16::try_from(request.entries().len())
                .map_err(|_| GithubScheduleStoreError::CorruptData)?
        || row
            .try_get::<i64, _>("github_repository_owner_id")
            .map_err(corrupt)?
            != i64_from_u64(request.repository_owner_id().get())?
        || current != Some(registry_id.as_uuid())
        || !registry_source_authority_is_exact(&row, request.source_authority())?
        || !replay_entries_are_exact(transaction, registry_id, request.entries()).await?
    {
        return Err(GithubScheduleStoreError::Conflict);
    }
    Ok(Some(GithubScheduleRegistryReceipt::from_durable_parts(
        registry_id,
        UnixMillis::new(row.try_get("discovered_at_ms").map_err(corrupt)?),
        true,
    )))
}

fn registry_source_authority_is_exact(
    row: &sqlx::postgres::PgRow,
    expected: &GithubScheduleSourceAuthority,
) -> Result<bool, GithubScheduleStoreError> {
    let kind: String = row.try_get("source_authority_kind").map_err(corrupt)?;
    let authority_id: Option<Uuid> = row
        .try_get("private_source_authority_id")
        .map_err(corrupt)?;
    let identity_digest: Option<Vec<u8>> = row
        .try_get("private_source_authority_identity_digest")
        .map_err(corrupt)?;
    let app_revision: Option<i64> = row
        .try_get("private_source_authority_app_configuration_revision")
        .map_err(corrupt)?;
    let policy_revision: Option<i64> = row
        .try_get("private_source_authority_policy_revision")
        .map_err(corrupt)?;
    Ok(match expected {
        GithubScheduleSourceAuthority::PublicAnonymous => {
            kind == expected.as_durable_str()
                && authority_id.is_none()
                && identity_digest.is_none()
                && app_revision.is_none()
                && policy_revision.is_none()
        }
        GithubScheduleSourceAuthority::Private(selector) => {
            kind == expected.as_durable_str()
                && authority_id == Some(selector.authority_id().as_uuid())
                && identity_digest.as_deref() == Some(selector.identity_digest().as_bytes())
                && app_revision == i64::try_from(selector.app_configuration_revision().get()).ok()
                && policy_revision == i64::try_from(selector.policy_revision().get()).ok()
        }
    })
}

async fn replay_entries_are_exact(
    transaction: &mut Transaction<'_, Postgres>,
    registry_id: GithubScheduleRegistryId,
    expected: &[GithubScheduleRegistryEntry],
) -> Result<bool, GithubScheduleStoreError> {
    let rows = sqlx::query(
        r"
        SELECT ordinal, workflow_path, workflow_source_digest,
               schedule_ordinal, cron_expression, timezone, entry_digest
          FROM github_schedule_registry_entries
         WHERE registry_id = $1
         ORDER BY ordinal
        ",
    )
    .bind(registry_id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() != expected.len() {
        return Ok(false);
    }
    for (row, entry) in rows.iter().zip(expected) {
        if row.try_get::<i16, _>("ordinal").map_err(corrupt)?
            != i16::try_from(entry.ordinal()).map_err(|_| GithubScheduleStoreError::CorruptData)?
            || row.try_get::<String, _>("workflow_path").map_err(corrupt)? != entry.workflow_path()
            || digest(row, "workflow_source_digest")? != entry.workflow_source_digest()
            || row.try_get::<i16, _>("schedule_ordinal").map_err(corrupt)?
                != i16::try_from(entry.schedule_ordinal())
                    .map_err(|_| GithubScheduleStoreError::CorruptData)?
            || row
                .try_get::<String, _>("cron_expression")
                .map_err(corrupt)?
                != entry.cron_expression()
            || row.try_get::<String, _>("timezone").map_err(corrupt)? != entry.timezone()
            || digest(row, "entry_digest")? != entry.entry_digest()
        {
            return Ok(false);
        }
    }
    let runtime_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM github_schedule_runtime WHERE registry_id = $1")
            .bind(registry_id.as_uuid())
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    Ok(usize::try_from(runtime_count).ok() == Some(expected.len()))
}

async fn supersede_current_registry(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let old_registry: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT registry_id
          FROM github_schedule_registry_current
         WHERE tenant_id = $1 AND repository_id = $2 AND provider_connection_id = $3
         FOR UPDATE
        ",
    )
    .bind(request.manifest().tenant().as_str())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(old_registry) = old_registry else {
        return Ok(());
    };
    sqlx::query(
        r"
        INSERT INTO github_schedule_fire_attempts (
            fire_id, attempt, claim_fence, claim_owner_id,
            claimed_at_ms, claim_expires_at_ms, concluded_at_ms,
            outcome, failure_kind
        )
        SELECT fire_id, attempt_count, claim_fence, claim_owner_id,
               claimed_at_ms, claim_expires_at_ms, $2,
               'failed', 'registry_superseded'
          FROM github_schedule_fires
         WHERE registry_id = $1 AND state = 'claimed'
        ON CONFLICT (fire_id, attempt) DO NOTHING
        ",
    )
    .bind(old_registry)
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    terminalize_superseded_scheduled_checks(transaction, old_registry, now).await?;
    sqlx::query(
        r"
        UPDATE github_schedule_fires
           SET state = 'failed', claim_owner_id = NULL,
               claimed_at_ms = NULL, claim_expires_at_ms = NULL,
               failure_kind = 'registry_superseded', updated_at_ms = $2
         WHERE registry_id = $1 AND state IN ('pending', 'claimed')
        ",
    )
    .bind(old_registry)
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query("DELETE FROM github_schedule_runtime WHERE registry_id = $1")
        .bind(old_registry)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn terminalize_superseded_scheduled_checks(
    transaction: &mut Transaction<'_, Postgres>,
    registry_id: Uuid,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    sqlx::query(
        r"
        UPDATE github_check_subjects AS subject
           SET desired_state = 'completed',
               desired_conclusion = 'failure',
               terminal_cause = 'system_unknown',
               desired_revision = subject.desired_revision + 1,
               desired_updated_at_ms = $2
          FROM github_schedule_fires AS fire
         WHERE fire.registry_id = $1
           AND subject.origin_kind = 'scheduled_fire'
           AND subject.provider_delivery_id IS NULL
           AND subject.schedule_fire_id = fire.fire_id
           AND subject.desired_state IN ('queued', 'in_progress')
           AND subject.desired_updated_at_ms <= $2
           AND subject.desired_revision < 9223372036854775807
        ",
    )
    .bind(registry_id)
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let nonterminal_remains: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
              FROM github_check_subjects AS subject
              JOIN github_schedule_fires AS fire
                ON fire.fire_id = subject.schedule_fire_id
             WHERE fire.registry_id = $1
               AND subject.origin_kind = 'scheduled_fire'
               AND subject.provider_delivery_id IS NULL
               AND subject.desired_state IN ('queued', 'in_progress')
        )
        ",
    )
    .bind(registry_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if nonterminal_remains {
        Err(GithubScheduleStoreError::Conflict)
    } else {
        Ok(())
    }
}

async fn insert_registry_revision(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    let private = request.source_authority().private_selector();
    let private_identity_digest =
        private.map(|selector| selector.identity_digest().as_bytes().to_vec());
    let private_app_revision = private
        .map(|selector| i64_from_u64(selector.app_configuration_revision().get()))
        .transpose()?;
    let private_policy_revision = private
        .map(|selector| i64_from_u64(selector.policy_revision().get()))
        .transpose()?;
    let result = sqlx::query(
        r"
        INSERT INTO github_schedule_registry_revisions (
            registry_id, discovery_id,
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest, github_repository_owner_id,
            default_branch_ref, source_revision,
            source_authority_kind, private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision,
            archive_digest, archive_object_key, archive_size_bytes, archive_media_type,
            inventory_digest, schedule_count, discovered_at_ms
        ) VALUES (
            $1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21
        )
        ",
    )
    .bind(request.registry_id().as_uuid())
    .bind(request.manifest().tenant().as_str())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .bind(
        i64::try_from(request.manifest().revision().get())
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .bind(request.manifest().digest().as_bytes().as_slice())
    .bind(i64_from_u64(request.repository_owner_id().get())?)
    .bind(request.manifest().git_ref())
    .bind(request.source_revision())
    .bind(request.source_authority().as_durable_str())
    .bind(private.map(|selector| selector.authority_id().as_uuid()))
    .bind(private_identity_digest)
    .bind(private_app_revision)
    .bind(private_policy_revision)
    .bind(request.archive().digest().as_bytes().as_slice())
    .bind(request.archive().object_key().as_str())
    .bind(
        i64::try_from(request.archive().encoded_size())
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .bind(GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE)
    .bind(request.inventory_digest().as_bytes().as_slice())
    .bind(
        i16::try_from(request.entries().len())
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .bind(now.get())
    .execute(&mut **transaction)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => Ok(()),
        Ok(_) => Err(GithubScheduleStoreError::CorruptData),
        Err(error) if integrity_violation(&error) => Err(GithubScheduleStoreError::Conflict),
        Err(error) => Err(operation_error(error)),
    }
}

async fn insert_registry_entries(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
) -> Result<(), GithubScheduleStoreError> {
    for entry in request.entries() {
        let result = sqlx::query(
            r"
            INSERT INTO github_schedule_registry_entries (
                registry_id, ordinal, workflow_path, workflow_source_digest,
                schedule_ordinal, cron_expression, timezone, entry_digest
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ",
        )
        .bind(request.registry_id().as_uuid())
        .bind(i16::try_from(entry.ordinal()).map_err(|_| GithubScheduleStoreError::CorruptData)?)
        .bind(entry.workflow_path())
        .bind(entry.workflow_source_digest().as_bytes().as_slice())
        .bind(
            i16::try_from(entry.schedule_ordinal())
                .map_err(|_| GithubScheduleStoreError::CorruptData)?,
        )
        .bind(entry.cron_expression())
        .bind(entry.timezone())
        .bind(entry.entry_digest().as_bytes().as_slice())
        .execute(&mut **transaction)
        .await;
        match result {
            Ok(result) if result.rows_affected() == 1 => {}
            Ok(_) => return Err(GithubScheduleStoreError::CorruptData),
            Err(error) if integrity_violation(&error) => {
                return Err(GithubScheduleStoreError::Conflict);
            }
            Err(error) => return Err(operation_error(error)),
        }
    }
    Ok(())
}

async fn seal_registry(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_schedule_registry_seals (
            registry_id, inventory_digest, schedule_count, sealed_at_ms
        ) VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(request.registry_id().as_uuid())
    .bind(request.inventory_digest().as_bytes().as_slice())
    .bind(
        i16::try_from(request.entries().len())
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(configuration_error)?;
    Ok(())
}

async fn activate_registry(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_schedule_registry_current (
            tenant_id, repository_id, provider_connection_id, registry_id, activated_at_ms
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (tenant_id, repository_id, provider_connection_id)
        DO UPDATE SET registry_id = EXCLUDED.registry_id,
                      activated_at_ms = EXCLUDED.activated_at_ms
        ",
    )
    .bind(request.manifest().tenant().as_str())
    .bind(request.manifest().repository_id().as_uuid())
    .bind(request.manifest().connection_id().as_uuid())
    .bind(request.registry_id().as_uuid())
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(configuration_error)?;
    Ok(())
}

async fn insert_registry_runtime(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterGithubScheduleRegistry,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    for entry in request.entries() {
        sqlx::query(
            r"
            INSERT INTO github_schedule_runtime (
                tenant_id, repository_id, provider_connection_id,
                registry_id, entry_ordinal, next_fire_at_ms, updated_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(request.manifest().tenant().as_str())
        .bind(request.manifest().repository_id().as_uuid())
        .bind(request.manifest().connection_id().as_uuid())
        .bind(request.registry_id().as_uuid())
        .bind(i16::try_from(entry.ordinal()).map_err(|_| GithubScheduleStoreError::CorruptData)?)
        .bind(entry.next_fire_at().get())
        .bind(now.get())
        .execute(&mut **transaction)
        .await
        .map_err(configuration_error)?;
    }
    Ok(())
}

async fn lock_due_runtime(
    transaction: &mut Transaction<'_, Postgres>,
    now: UnixMillis,
) -> Result<Option<DueRuntime>, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT runtime.tenant_id, runtime.repository_id,
               runtime.provider_connection_id, runtime.registry_id,
               runtime.entry_ordinal, runtime.next_fire_at_ms
          FROM github_schedule_runtime AS runtime
          JOIN github_schedule_registry_revisions AS registry
            ON registry.tenant_id = runtime.tenant_id
           AND registry.repository_id = runtime.repository_id
           AND registry.provider_connection_id = runtime.provider_connection_id
           AND registry.registry_id = runtime.registry_id
          JOIN github_provider_manifest_current AS manifest_current
            ON manifest_current.tenant_id = registry.tenant_id
           AND manifest_current.repository_id = registry.repository_id
           AND manifest_current.provider_connection_id = registry.provider_connection_id
           AND manifest_current.manifest_revision = registry.manifest_revision
           AND manifest_current.manifest_digest = registry.manifest_digest
          LEFT JOIN github_schedule_fires AS fire
            ON fire.registry_id = runtime.registry_id
           AND fire.entry_ordinal = runtime.entry_ordinal
           AND fire.scheduled_at_ms = runtime.next_fire_at_ms
         WHERE runtime.next_fire_at_ms <= $1
           AND (
               fire.fire_id IS NULL
               OR fire.state = 'pending'
                  AND fire.next_attempt_at_ms <= $1
                  AND fire.attempt_count < $2
               OR fire.state = 'claimed'
                  AND fire.claim_expires_at_ms <= $1
                  AND fire.attempt_count <= $2
           )
           AND coalesce(fire.claim_fence, 0) < 9223372036854775807
         ORDER BY runtime.next_fire_at_ms, runtime.provider_connection_id, runtime.entry_ordinal
         LIMIT 1
         FOR UPDATE OF runtime, manifest_current SKIP LOCKED
        ",
    )
    .bind(now.get())
    .bind(i16::try_from(MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS).expect("fixed bound fits SMALLINT"))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.map(|row| {
        Ok(DueRuntime {
            tenant_id: row.try_get("tenant_id").map_err(corrupt)?,
            repository_id: row.try_get("repository_id").map_err(corrupt)?,
            connection_id: row.try_get("provider_connection_id").map_err(corrupt)?,
            registry_id: row.try_get("registry_id").map_err(corrupt)?,
            entry_ordinal: row.try_get("entry_ordinal").map_err(corrupt)?,
            scheduled_at: row.try_get("next_fire_at_ms").map_err(corrupt)?,
        })
    })
    .transpose()
}

async fn ensure_fire(
    transaction: &mut Transaction<'_, Postgres>,
    due: &DueRuntime,
    now: UnixMillis,
) -> Result<GithubScheduleFireId, GithubScheduleStoreError> {
    if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT fire_id FROM github_schedule_fires
         WHERE registry_id = $1 AND entry_ordinal = $2 AND scheduled_at_ms = $3
         FOR UPDATE
        ",
    )
    .bind(due.registry_id)
    .bind(due.entry_ordinal)
    .bind(due.scheduled_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    {
        return GithubScheduleFireId::from_uuid(existing)
            .map_err(|_| GithubScheduleStoreError::CorruptData);
    }
    let fire_id = GithubScheduleFireId::from_uuid(Uuid::new_v4()).expect("random UUID is non-nil");
    sqlx::query(
        r"
        INSERT INTO github_schedule_fires (
            fire_id, tenant_id, repository_id, provider_connection_id,
            registry_id, entry_ordinal, scheduled_at_ms, next_attempt_at_ms,
            created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $8)
        ",
    )
    .bind(fire_id.as_uuid())
    .bind(&due.tenant_id)
    .bind(due.repository_id)
    .bind(due.connection_id)
    .bind(due.registry_id)
    .bind(due.entry_ordinal)
    .bind(due.scheduled_at)
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(configuration_error)?;
    Ok(fire_id)
}

async fn expire_prior_claim(
    transaction: &mut Transaction<'_, Postgres>,
    fire_id: GithubScheduleFireId,
    now: UnixMillis,
) -> Result<bool, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt_count, claim_fence, claim_owner_id,
               claimed_at_ms, claim_expires_at_ms
          FROM github_schedule_fires
         WHERE fire_id = $1 AND state = 'claimed' AND claim_expires_at_ms <= $2
         FOR UPDATE
        ",
    )
    .bind(fire_id.as_uuid())
    .bind(now.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let claim = decode_claim_row(fire_id, &row)?;
    if claim.attempt() == MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS {
        terminalize_exhausted_fire(transaction, claim, now).await?;
        return Ok(true);
    }
    insert_attempt(
        transaction,
        claim,
        now,
        "expired",
        Some("claim_lease_expired"),
    )
    .await?;
    let changed = sqlx::query(
        r"
        UPDATE github_schedule_fires
           SET state = 'pending', claim_owner_id = NULL,
               claimed_at_ms = NULL, claim_expires_at_ms = NULL,
               next_attempt_at_ms = $2, updated_at_ms = $2
         WHERE fire_id = $1 AND state = 'claimed'
        ",
    )
    .bind(fire_id.as_uuid())
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() != 1 {
        return Err(GithubScheduleStoreError::ClaimRejected);
    }
    Ok(false)
}

async fn terminalize_exhausted_fire(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
    now: UnixMillis,
) -> Result<(), GithubScheduleStoreError> {
    if claim.attempt() != MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS {
        return Err(GithubScheduleStoreError::ClaimRejected);
    }
    let (terminal, next_fire_at) = lock_exhausted_fire(transaction, claim).await?;
    update_schedule_runtime(
        transaction,
        &terminal,
        Some(next_fire_at),
        Some(GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE),
        now,
    )
    .await?;
    terminalize_scheduled_check(
        transaction,
        claim.fire_id(),
        now,
        "failure",
        "system_unknown",
    )
    .await?;
    insert_attempt(
        transaction,
        claim,
        now,
        "failed",
        Some(GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE),
    )
    .await?;
    let changed = sqlx::query(
        r"
        UPDATE github_schedule_fires
           SET state = 'failed', claim_owner_id = NULL,
               claimed_at_ms = NULL, claim_expires_at_ms = NULL,
               failure_kind = $7, updated_at_ms = $8
         WHERE fire_id = $1 AND state = 'claimed'
           AND claim_owner_id = $2 AND attempt_count = $3
           AND claim_fence = $4 AND claimed_at_ms = $5
           AND claim_expires_at_ms = $6
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::ClaimRejected)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE)
    .bind(now.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() == 1 {
        Ok(())
    } else {
        Err(GithubScheduleStoreError::ClaimRejected)
    }
}

async fn lock_exhausted_fire(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
) -> Result<(TerminalFireRow, UnixMillis), GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT fire.tenant_id, fire.repository_id,
               fire.provider_connection_id, fire.registry_id,
               fire.entry_ordinal, fire.scheduled_at_ms,
               entry.cron_expression, entry.timezone
          FROM github_schedule_fires AS fire
          JOIN github_schedule_registry_entries AS entry
            ON entry.registry_id = fire.registry_id
           AND entry.ordinal = fire.entry_ordinal
         WHERE fire.fire_id = $1
           AND fire.state = 'claimed'
           AND fire.claim_owner_id = $2
           AND fire.attempt_count = $3
           AND fire.claim_fence = $4
           AND fire.claimed_at_ms = $5
           AND fire.claim_expires_at_ms = $6
         FOR UPDATE OF fire
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::ClaimRejected)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    let terminal = TerminalFireRow {
        tenant_id: row.try_get("tenant_id").map_err(corrupt)?,
        repository_id: row.try_get("repository_id").map_err(corrupt)?,
        connection_id: row.try_get("provider_connection_id").map_err(corrupt)?,
        registry_id: row.try_get("registry_id").map_err(corrupt)?,
        entry_ordinal: row.try_get("entry_ordinal").map_err(corrupt)?,
        scheduled_at: row.try_get("scheduled_at_ms").map_err(corrupt)?,
    };
    let cron = CronExpression::parse(
        row.try_get::<String, _>("cron_expression")
            .map_err(corrupt)?,
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let timezone: String = row.try_get("timezone").map_err(corrupt)?;
    let next_fire_at = cron
        .next_after(UnixMillis::new(terminal.scheduled_at), &timezone)
        .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    Ok((terminal, next_fire_at))
}

async fn claim_fire(
    transaction: &mut Transaction<'_, Postgres>,
    fire_id: GithubScheduleFireId,
    request: ClaimDueGithubScheduleFire,
    now: UnixMillis,
) -> Result<GithubScheduleFireClaim, GithubScheduleStoreError> {
    let expires = checked_add(now.get(), request.lease_millis())?;
    let row = sqlx::query(
        r"
        UPDATE github_schedule_fires
           SET state = 'claimed', attempt_count = attempt_count + 1,
               claim_fence = claim_fence + 1, claim_owner_id = $2,
               claimed_at_ms = $3, claim_expires_at_ms = $4, updated_at_ms = $3
         WHERE fire_id = $1 AND state = 'pending' AND next_attempt_at_ms <= $3
           AND attempt_count < $5 AND claim_fence < 9223372036854775807
        RETURNING attempt_count, claim_fence, claimed_at_ms, claim_expires_at_ms
        ",
    )
    .bind(fire_id.as_uuid())
    .bind(request.worker_id().as_uuid())
    .bind(now.get())
    .bind(expires)
    .bind(i16::try_from(MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS).expect("fixed bound fits SMALLINT"))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    let attempt: i16 = row.try_get("attempt_count").map_err(corrupt)?;
    let fence: i64 = row.try_get("claim_fence").map_err(corrupt)?;
    GithubScheduleFireClaim::from_durable_parts(
        fire_id,
        request.worker_id(),
        u16::try_from(attempt).map_err(|_| GithubScheduleStoreError::CorruptData)?,
        GithubScheduleClaimFence::new(
            u64::try_from(fence).map_err(|_| GithubScheduleStoreError::CorruptData)?,
        )
        .map_err(|_| GithubScheduleStoreError::CorruptData)?,
        UnixMillis::new(row.try_get("claimed_at_ms").map_err(corrupt)?),
        UnixMillis::new(row.try_get("claim_expires_at_ms").map_err(corrupt)?),
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)
}

async fn load_claimed_fire(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
) -> Result<ClaimedGithubScheduleFire, GithubScheduleStoreError> {
    let row = sqlx::query(
        r"
        SELECT fire.tenant_id, fire.repository_id, fire.provider_connection_id,
               fire.registry_id, fire.scheduled_at_ms,
               repository.provider_repository_id, repository.owner, repository.name,
               registry.source_revision, registry.default_branch_ref,
               registry.archive_digest, registry.archive_object_key, registry.archive_size_bytes,
               entry.ordinal, entry.workflow_path, entry.workflow_source_digest,
               entry.schedule_ordinal, entry.cron_expression, entry.timezone
          FROM github_schedule_fires AS fire
          JOIN repositories AS repository ON repository.id = fire.repository_id
          JOIN github_schedule_registry_revisions AS registry
            ON registry.registry_id = fire.registry_id
          JOIN github_schedule_registry_entries AS entry
            ON entry.registry_id = fire.registry_id AND entry.ordinal = fire.entry_ordinal
         WHERE fire.fire_id = $1 AND fire.state = 'claimed'
           AND fire.claim_owner_id = $2 AND fire.attempt_count = $3 AND fire.claim_fence = $4
           AND fire.claimed_at_ms <=
               floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
           AND fire.claim_expires_at_ms >
               floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(claim.worker_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::CorruptData)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubScheduleStoreError::ClaimRejected)?;
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id").map_err(corrupt)?,
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let repository_id = RepositoryId::from_uuid(row.try_get("repository_id").map_err(corrupt)?);
    let connection_id =
        ProviderConnectionId::from_uuid(row.try_get("provider_connection_id").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let registry_id =
        GithubScheduleRegistryId::from_uuid(row.try_get("registry_id").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let archive = GithubScheduleArchive::new(
        digest(&row, "archive_digest")?,
        ObjectKey::new(
            row.try_get::<String, _>("archive_object_key")
                .map_err(corrupt)?,
        )
        .map_err(|_| GithubScheduleStoreError::CorruptData)?,
        u64::try_from(
            row.try_get::<i64, _>("archive_size_bytes")
                .map_err(corrupt)?,
        )
        .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let scheduled_at = UnixMillis::new(row.try_get("scheduled_at_ms").map_err(corrupt)?);
    let entry = GithubScheduleRegistryEntry::new(
        u16::try_from(row.try_get::<i16, _>("ordinal").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
        GithubCheckSubjectKey::new(row.try_get::<String, _>("workflow_path").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
        digest(&row, "workflow_source_digest")?,
        u16::try_from(row.try_get::<i16, _>("schedule_ordinal").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
        row.try_get::<String, _>("cron_expression")
            .map_err(corrupt)?,
        row.try_get::<String, _>("timezone").map_err(corrupt)?,
        scheduled_at,
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    Ok(ClaimedGithubScheduleFire::from_durable_parts(
        claim,
        tenant,
        repository_id,
        row.try_get("provider_repository_id").map_err(corrupt)?,
        row.try_get("owner").map_err(corrupt)?,
        row.try_get("name").map_err(corrupt)?,
        connection_id,
        registry_id,
        row.try_get("source_revision").map_err(corrupt)?,
        row.try_get("default_branch_ref").map_err(corrupt)?,
        archive,
        entry,
        scheduled_at,
    ))
}

async fn insert_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubScheduleFireClaim,
    concluded_at: UnixMillis,
    outcome: &str,
    failure_kind: Option<&str>,
) -> Result<(), GithubScheduleStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_schedule_fire_attempts (
            fire_id, attempt, claim_fence, claim_owner_id,
            claimed_at_ms, claim_expires_at_ms, concluded_at_ms,
            outcome, failure_kind
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(claim.fire_id().as_uuid())
    .bind(i16::try_from(claim.attempt()).map_err(|_| GithubScheduleStoreError::CorruptData)?)
    .bind(i64_from_u64(claim.fence().get())?)
    .bind(claim.worker_id().as_uuid())
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(concluded_at.get())
    .bind(outcome)
    .bind(failure_kind)
    .execute(&mut **transaction)
    .await
    .map_err(configuration_error)?;
    Ok(())
}

fn decode_claim_row(
    fire_id: GithubScheduleFireId,
    row: &sqlx::postgres::PgRow,
) -> Result<GithubScheduleFireClaim, GithubScheduleStoreError> {
    let attempt = u16::try_from(row.try_get::<i16, _>("attempt_count").map_err(corrupt)?)
        .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let fence = GithubScheduleClaimFence::new(
        u64::try_from(row.try_get::<i64, _>("claim_fence").map_err(corrupt)?)
            .map_err(|_| GithubScheduleStoreError::CorruptData)?,
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    let worker = GithubScheduleWorkerId::from_uuid(row.try_get("claim_owner_id").map_err(corrupt)?)
        .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    GithubScheduleFireClaim::from_durable_parts(
        fire_id,
        worker,
        attempt,
        fence,
        UnixMillis::new(row.try_get("claimed_at_ms").map_err(corrupt)?),
        UnixMillis::new(row.try_get("claim_expires_at_ms").map_err(corrupt)?),
    )
    .map_err(|_| GithubScheduleStoreError::CorruptData)
}

async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<UnixMillis, GithubScheduleStoreError> {
    let value: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if value < 0 {
        return Err(GithubScheduleStoreError::CorruptData);
    }
    Ok(UnixMillis::new(value))
}

fn digest(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Sha256Digest, GithubScheduleStoreError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(corrupt)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GithubScheduleStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn checked_add(left: i64, right: i64) -> Result<i64, GithubScheduleStoreError> {
    left.checked_add(right)
        .filter(|value| *value >= 0)
        .ok_or(GithubScheduleStoreError::CorruptData)
}

fn i64_from_u64(value: u64) -> Result<i64, GithubScheduleStoreError> {
    i64::try_from(value).map_err(|_| GithubScheduleStoreError::CorruptData)
}

fn integrity_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code.starts_with("23"))
}

fn configuration_error(error: sqlx::Error) -> GithubScheduleStoreError {
    if integrity_violation(&error) {
        GithubScheduleStoreError::Conflict
    } else {
        operation_error(error)
    }
}

fn corrupt(_: sqlx::Error) -> GithubScheduleStoreError {
    GithubScheduleStoreError::CorruptData
}

fn operation_error(error: sqlx::Error) -> GithubScheduleStoreError {
    GithubScheduleStoreError::Store(StoreError::operation(error))
}

fn logical_operation_error(error: sqlx::Error) -> LogicalWorkflowAdmissionStoreError {
    StoreError::operation(error).into()
}

fn schedule_admission_error(error: GithubScheduleStoreError) -> LogicalWorkflowAdmissionStoreError {
    match error {
        GithubScheduleStoreError::Store(error) => error.into(),
        GithubScheduleStoreError::Conflict
        | GithubScheduleStoreError::ClaimRejected
        | GithubScheduleStoreError::CorruptData => {
            StoreError::corrupt_data("scheduled GitHub claim evidence was rejected").into()
        }
    }
}

fn decode_sha1(value: &str) -> Result<[u8; 20], LogicalWorkflowAdmissionStoreError> {
    if value.len() != 40 {
        return Err(StoreError::corrupt_data("scheduled source SHA is malformed").into());
    }
    let mut decoded = [0_u8; 20];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, LogicalWorkflowAdmissionStoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StoreError::corrupt_data("scheduled source SHA is malformed").into()),
    }
}
