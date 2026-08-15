use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use automata_ci_key_management::{EncryptedEnvelope, KeyId, WrappedDataKey};
use sqlx::{AssertSqlSafe, PgConnection, Row as _, postgres::PgRow};
use uuid::Uuid;

use automata_ci_store::{
    AcquireGithubServerServiceHandoff, BeginGithubServerServiceMint,
    BeginGithubServerServiceMintOutcome, ClaimNextGithubServerServiceMaintenance,
    ClaimedGithubServerServiceMint, ClaimedGithubServerServiceRevocation,
    EnsureGithubServerServiceAuthority, FinishGithubServerServiceMint,
    FinishGithubServerServiceRevocation, GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS,
    GithubRepositoryName, GithubServerServiceAction, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityDescriptor,
    GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository, GithubServerServiceAuthoritySelector,
    GithubServerServiceAuthorityState, GithubServerServiceClaim, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceCredentialHandoff, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceReceipt, GithubServerServiceIssuanceState,
    GithubServerServiceJwtIssuer, GithubServerServiceMaintenanceOutcome,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceStoreError,
    GithubServerServiceWorkerId, MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES,
    MAX_GITHUB_SERVICE_MINT_ATTEMPTS, MAX_GITHUB_SERVICE_REVOKE_ATTEMPTS,
    MIN_GITHUB_SERVICE_READY_USE_MILLIS, ProtectedGithubServerServiceCredential,
    ProviderConnectionId, ProviderInstallationId, ProviderRepositoryId,
    QuarantineGithubServerServiceCredential, ReleaseGithubServerServiceHandoff, RepositoryId,
    RetireGithubServerServiceAuthority, Sha256Digest, TenantScope,
};

use super::{PostgresStore, pg_bigint};

const AUTHORITY_COLUMNS: &str = r"
    id, tenant_id, repository_id, provider_connection_id,
    provider_installation_id, github_app_id, github_app_client_id,
    github_app_jwt_issuer_kind, github_repository_id,
    github_repository_name, service_scope, policy_digest, policy_revision,
    app_key_spki_sha256, app_configuration_revision,
    configuration_fingerprint, identity_digest, state, current_issuance_generation,
    refresh_issuance_generation, next_issuance_generation,
    consecutive_generation_failures, next_mint_not_before_ms, mint_gate_generation,
    failure_budget_rearm_at_ms,
    created_at_ms, state_updated_at_ms
";

const ISSUANCE_COLUMNS: &str = r"
    authority_id, generation, state, mint_attempt_count,
    mint_claim_fence, mint_claim_owner_id, mint_claimed_at_ms,
    mint_claim_expires_at_ms, mint_started_at_ms, mint_started_owner_id,
    mint_started_claim_fence, mint_started_claimed_at_ms,
    mint_started_claim_expires_at_ms, ready_at_ms,
    generation_failure_gate_at_ms, next_mint_at_ms,
    mint_failure_kind, requested_at_ms, request_deadline_at_ms,
    conservative_expiry_at_ms, provider_expires_at_ms,
    safe_erase_after_ms, plaintext_schema, plaintext_size_bytes,
    plaintext_digest, aad_digest, envelope_schema, wrapping_key_id,
    wrapped_data_key, nonce, ciphertext, revoke_attempt_count,
    revoke_claim_fence, revoke_claim_owner_id, revoke_claimed_at_ms,
    revoke_claim_expires_at_ms, revoke_result_owner_id,
    revoke_result_claim_fence, revoke_result_claimed_at_ms,
    revoke_result_claim_expires_at_ms, next_revoke_at_ms, revoke_failure_kind,
    terminal_reason, created_at_ms, state_updated_at_ms
";

// Caller wall time is useful admission evidence, but it must never decide
// whether provider I/O is still live or issue an absolute lease boundary.
// Keep the window closed on both sides so a stuck-forward or slow process is
// rejected before it can mutate durable credential custody.
const MAX_GITHUB_SERVICE_AUTHORITY_CLOCK_SKEW_MILLIS: i64 = 60_000;
const MAX_GITHUB_SERVICE_AUTHORITIES_PER_REPOSITORY: usize = 256;

async fn pin_read_committed(
    connection: &mut PgConnection,
) -> Result<(), GithubServerServiceStoreError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(connection)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn database_now_ms(
    connection: &mut PgConnection,
) -> Result<i64, GithubServerServiceStoreError> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(connection)
            .await
            .map_err(operation_error)?;
    if database_now < 0 {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    Ok(database_now)
}

fn validate_caller_clock(
    observed_at: UnixMillis,
    database_now: i64,
) -> Result<(), GithubServerServiceStoreError> {
    if observed_at.get()
        < database_now.saturating_sub(MAX_GITHUB_SERVICE_AUTHORITY_CLOCK_SKEW_MILLIS)
        || observed_at.get()
            > database_now.saturating_add(MAX_GITHUB_SERVICE_AUTHORITY_CLOCK_SKEW_MILLIS)
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    Ok(())
}

fn requested_duration(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<i64, GithubServerServiceStoreError> {
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| *duration > 0)
        .ok_or(GithubServerServiceStoreError::ClaimRejected)
}

fn issue_deadline(database_now: i64, duration: i64) -> Result<i64, GithubServerServiceStoreError> {
    database_now
        .checked_add(duration)
        .ok_or(GithubServerServiceStoreError::CorruptData)
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl GithubServerServiceAuthorityRepository for PostgresStore {
    async fn ensure_github_server_service_authority(
        &self,
        request: EnsureGithubServerServiceAuthority,
    ) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError> {
        let identity = request.identity();
        let inserted = sqlx::query(
            r"
            INSERT INTO github_server_service_authorities (
                id, tenant_id, repository_id, provider_connection_id,
                provider_installation_id, github_app_id, github_app_client_id,
                github_app_jwt_issuer_kind, github_repository_id,
                github_repository_name, service_scope, permission_policy,
                policy_digest, policy_revision, app_key_spki_sha256,
                app_configuration_revision, configuration_fingerprint, identity_digest,
                state, created_at_ms, state_updated_at_ms
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                $12::JSONB, $13, $14, $15, $16, $17, $18, 'active', $19, $19
            )
            ON CONFLICT DO NOTHING
            RETURNING id
            ",
        )
        .bind(identity.authority_id().as_uuid())
        .bind(identity.tenant().as_str())
        .bind(identity.repository_id().as_uuid())
        .bind(identity.connection_id().as_uuid())
        .bind(i64_from_u64(identity.installation_id().get())?)
        .bind(pg_bigint(identity.github_app_id().get()))
        .bind(identity.app_client_id().as_str())
        .bind(identity.jwt_issuer().as_str())
        .bind(i64_from_u64(identity.github_repository_id().get())?)
        .bind(identity.github_repository_name().as_str())
        .bind(identity.scope().as_str())
        .bind(identity.scope().permissions_json())
        .bind(identity.policy_digest().as_bytes().as_slice())
        .bind(pg_bigint(identity.policy_revision().get()))
        .bind(identity.app_key_spki_sha256().as_bytes().as_slice())
        .bind(pg_bigint(identity.app_configuration_revision().get()))
        .bind(identity.configuration_fingerprint().as_bytes().as_slice())
        .bind(identity.identity_digest().as_bytes().as_slice())
        .bind(request.created_at().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;

        let descriptor =
            match load_authority_from_pool(&self.pool, identity.tenant(), identity.authority_id())
                .await
            {
                Ok(descriptor) => descriptor,
                Err(GithubServerServiceStoreError::NotFound) if inserted.is_none() => {
                    return Err(GithubServerServiceStoreError::IdentityConflict);
                }
                Err(error) => return Err(error),
            };
        if descriptor.identity() != identity || descriptor.created_at() != request.created_at() {
            return Err(GithubServerServiceStoreError::IdentityConflict);
        }
        debug_assert!(inserted.is_some() || descriptor.identity() == identity);
        Ok(descriptor)
    }

    async fn inspect_github_server_service_authority(
        &self,
        tenant: &TenantScope,
        authority_id: GithubServerServiceAuthorityId,
    ) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError> {
        load_authority_from_pool(&self.pool, tenant, authority_id).await
    }

    async fn inspect_current_github_server_service_issuance(
        &self,
        tenant: &TenantScope,
        authority_id: GithubServerServiceAuthorityId,
    ) -> Result<Option<GithubServerServiceIssuanceReceipt>, GithubServerServiceStoreError> {
        let query = format!(
            "SELECT {ISSUANCE_COLUMNS} \
             FROM github_server_service_authority_issuances \
             WHERE authority_id = $2 AND generation = ( \
                 SELECT current_issuance_generation \
                 FROM github_server_service_authorities \
                 WHERE tenant_id = $1 AND id = $2 \
             )"
        );
        sqlx::query(AssertSqlSafe(query))
            .bind(tenant.as_str())
            .bind(authority_id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .map(|row| decode_issuance_receipt(&row))
            .transpose()
    }

    async fn list_github_server_service_authorities_for_repository(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        connection_id: ProviderConnectionId,
    ) -> Result<Vec<GithubServerServiceAuthorityDescriptor>, GithubServerServiceStoreError> {
        let query = format!(
            "SELECT {AUTHORITY_COLUMNS} FROM github_server_service_authorities \
             WHERE tenant_id = $1 AND repository_id = $2 \
               AND provider_connection_id = $3 \
               AND state IN ('active', 'retiring') \
             ORDER BY id LIMIT 257"
        );
        let rows = sqlx::query(AssertSqlSafe(query))
            .bind(tenant.as_str())
            .bind(repository_id.as_uuid())
            .bind(connection_id.as_uuid())
            .fetch_all(&self.pool)
            .await
            .map_err(operation_error)?;
        if rows.len() > MAX_GITHUB_SERVICE_AUTHORITIES_PER_REPOSITORY {
            return Err(GithubServerServiceStoreError::CorruptData);
        }
        rows.iter().map(decode_authority).collect()
    }

    async fn begin_github_server_service_mint(
        &self,
        request: BeginGithubServerServiceMint,
    ) -> Result<BeginGithubServerServiceMintOutcome, GithubServerServiceStoreError> {
        let claim = request.claim();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        select_authority_for_update(&mut transaction, claim.selector())
            .await?
            .ok_or(GithubServerServiceStoreError::NotFound)?;
        let existing = select_issuance_for_update(&mut transaction, claim.key())
            .await?
            .ok_or(GithubServerServiceStoreError::NotFound)?;
        if issuance_state(&existing)? == GithubServerServiceIssuanceState::Minting
            && optional_uuid(&existing, "mint_claim_owner_id")? == Some(claim.worker().as_uuid())
            && positive_u64(&existing, "mint_claim_fence")? == claim.fence().get()
            && optional_i64(&existing, "mint_started_at_ms")? == Some(request.started_at().get())
        {
            require_exact_begin_evidence(&existing, &request)?;
            let receipt = decode_issuance_receipt(&existing)?;
            let start =
                automata_ci_store::adapter_spi::github_server_service_mint_start(&request, receipt)
                    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BeginGithubServerServiceMintOutcome::AlreadyStarted(start));
        }

        let database_now = database_now_ms(&mut transaction).await?;
        validate_caller_clock(request.started_at(), database_now)?;
        let row = sqlx::query(AssertSqlSafe(format!(
            r"
            UPDATE github_server_service_authority_issuances
            SET state = 'minting', mint_started_at_ms = $5,
                mint_started_owner_id = mint_claim_owner_id,
                mint_started_claim_fence = mint_claim_fence,
                mint_started_claimed_at_ms = mint_claimed_at_ms,
                mint_started_claim_expires_at_ms = mint_claim_expires_at_ms,
                state_updated_at_ms = $5
            WHERE authority_id = $1 AND generation = $2
              AND state = 'claimed'
              AND mint_claim_owner_id = $3
              AND mint_claim_fence = $4
              AND mint_claimed_at_ms = $6
              AND mint_claim_expires_at_ms = $7
              AND request_deadline_at_ms = $8
              AND mint_claimed_at_ms <= $9
              AND mint_claim_expires_at_ms > $9
              AND request_deadline_at_ms > $9
            RETURNING {ISSUANCE_COLUMNS}
            "
        )))
        .bind(claim.key().authority_id().as_uuid())
        .bind(pg_bigint(claim.key().generation().get()))
        .bind(claim.worker().as_uuid())
        .bind(pg_bigint(claim.fence().get()))
        .bind(request.started_at().get())
        .bind(request.claimed_at().get())
        .bind(request.claim_expires_at().get())
        .bind(request.request_deadline().get())
        .bind(database_now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if let Some(row) = row {
            require_exact_begin_evidence(&row, &request)?;
            let receipt = decode_issuance_receipt(&row)?;
            let start =
                automata_ci_store::adapter_spi::github_server_service_mint_start(&request, receipt)
                    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BeginGithubServerServiceMintOutcome::Started(start));
        }
        Err(GithubServerServiceStoreError::ClaimRejected)
    }

    async fn finish_github_server_service_mint(
        &self,
        request: &FinishGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        match request {
            FinishGithubServerServiceMint::Ready {
                claim,
                protected,
                committed_at,
            } => finish_ready(self, claim.clone(), protected, *committed_at).await,
            FinishGithubServerServiceMint::RevokeOnly {
                claim,
                protected,
                committed_at,
            } => finish_revoke_only(self, claim.clone(), protected, *committed_at).await,
            FinishGithubServerServiceMint::Retry {
                claim,
                failure,
                observed_at,
                retry_at,
            } => {
                finish_mint_without_credential(
                    self,
                    claim.clone(),
                    "mint_retry",
                    Some(failure.as_str()),
                    *observed_at,
                    Some(*retry_at),
                    None,
                    false,
                )
                .await
            }
            FinishGithubServerServiceMint::Indeterminate {
                claim,
                failure,
                observed_at,
            } => {
                finish_mint_without_credential(
                    self,
                    claim.clone(),
                    "indeterminate",
                    Some(failure.as_str()),
                    *observed_at,
                    None,
                    None,
                    true,
                )
                .await
            }
            FinishGithubServerServiceMint::Rejected {
                claim,
                failure,
                observed_at,
            } => {
                finish_mint_without_credential(
                    self,
                    claim.clone(),
                    "rejected",
                    Some(failure.as_str()),
                    *observed_at,
                    None,
                    Some("provider_rejected"),
                    true,
                )
                .await
            }
        }
    }

    async fn acquire_github_server_service_handoff(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError> {
        acquire_handoff(self, request).await
    }

    async fn release_github_server_service_handoff(
        &self,
        request: ReleaseGithubServerServiceHandoff,
    ) -> Result<(), GithubServerServiceStoreError> {
        release_handoff(self, request).await
    }

    async fn quarantine_github_server_service_credential(
        &self,
        request: QuarantineGithubServerServiceCredential,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        quarantine_current(self, request).await
    }

    async fn retire_github_server_service_authority(
        &self,
        request: RetireGithubServerServiceAuthority,
    ) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError> {
        retire_authority(self, request).await
    }

    async fn finish_github_server_service_revocation(
        &self,
        request: FinishGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        finish_revocation(self, request).await
    }

    async fn claim_next_github_server_service_maintenance(
        &self,
        request: ClaimNextGithubServerServiceMaintenance,
    ) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError> {
        claim_next_maintenance(self, request).await
    }
}

#[allow(clippy::too_many_lines)]
async fn finish_ready(
    store: &PostgresStore,
    claim: GithubServerServiceClaim,
    protected: &ProtectedGithubServerServiceCredential,
    committed_at: UnixMillis,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let metadata = protected.metadata();
    if metadata.identity().authority_id() != claim.key().authority_id()
        || metadata.generation() != claim.key().generation()
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let authority_row = select_authority_for_update(&mut transaction, claim.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&authority_row)?;
    let existing = select_issuance_for_update(&mut transaction, claim.key())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    if issuance_state(&existing)? == GithubServerServiceIssuanceState::Ready {
        let replay = exact_protected_replay(&existing, &claim, protected, committed_at)?
            && descriptor.current_generation() == Some(claim.key().generation())
            && descriptor.refresh_generation().is_none();
        if !replay {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
        let receipt = decode_issuance_receipt(&existing)?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let database_now = database_now_ms(&mut transaction).await?;
    let ready_allowed = validate_caller_clock(committed_at, database_now).is_ok()
        && require_live_mint_claim(&existing, &claim, committed_at, database_now).is_ok()
        && descriptor.state() == GithubServerServiceAuthorityState::Active
        && descriptor.refresh_generation() == Some(claim.key().generation())
        && metadata.identity() == descriptor.identity()
        && metadata.requested_at().get() == i64_column(&existing, "requested_at_ms")?
        && metadata.request_deadline().get() == i64_column(&existing, "request_deadline_at_ms")?
        && database_now
            .checked_add(MIN_GITHUB_SERVICE_READY_USE_MILLIS)
            .is_some_and(|required| {
                metadata
                    .usable_until()
                    .is_some_and(|usable_until| usable_until.get() >= required)
            });
    if !ready_allowed {
        // A known provider bearer must not be discarded merely because the
        // database-authoritative Ready window closed while I/O was in flight.
        // Re-lock and retain the exact protected result only for revocation.
        drop(transaction);
        return finish_revoke_only(store, claim, protected, committed_at).await;
    }
    let envelope = protected.envelope();
    let old_current = descriptor.current_generation();
    if let Some(old_generation) = old_current {
        let old = GithubServerServiceIssuanceKey::new(claim.key().authority_id(), old_generation);
        let changed = sqlx::query(
            r"
            UPDATE github_server_service_authority_issuances
            SET state = 'revoke_pending', state_updated_at_ms = $3
            WHERE authority_id = $1 AND generation = $2
              AND state = 'ready' AND state_updated_at_ms <= $3
            ",
        )
        .bind(old.authority_id().as_uuid())
        .bind(pg_bigint(old.generation().get()))
        .bind(committed_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if changed.rows_affected() != 1 {
            return Err(GithubServerServiceStoreError::CorruptData);
        }
    }
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = 'ready', mint_claim_owner_id = NULL,
            mint_claimed_at_ms = NULL, mint_claim_expires_at_ms = NULL,
            ready_at_ms = $16,
            provider_expires_at_ms = $5, safe_erase_after_ms = $6,
            plaintext_schema = $7, plaintext_size_bytes = $8,
            plaintext_digest = $9, aad_digest = $10,
            envelope_schema = $11, wrapping_key_id = $12,
            wrapped_data_key = $13, nonce = $14, ciphertext = $15,
            state_updated_at_ms = $16
        WHERE authority_id = $1 AND generation = $2
          AND state = 'minting' AND mint_claim_owner_id = $3
          AND mint_claim_fence = $4
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(claim.key().authority_id().as_uuid())
    .bind(pg_bigint(claim.key().generation().get()))
    .bind(claim.worker().as_uuid())
    .bind(pg_bigint(claim.fence().get()))
    .bind(metadata.provider_expires_at().map(UnixMillis::get))
    .bind(metadata.safe_erase_after().get())
    .bind(i32::from(metadata.plaintext_schema()))
    .bind(i64_from_u64(metadata.plaintext_size_bytes())?)
    .bind(metadata.plaintext_digest().as_bytes().as_slice())
    .bind(metadata.aad_digest().as_bytes().as_slice())
    .bind(i32::from(envelope.schema()))
    .bind(envelope.wrapping_key_id().as_str())
    .bind(envelope.wrapped_data_key().ciphertext())
    .bind(envelope.nonce().as_slice())
    .bind(envelope.ciphertext())
    .bind(committed_at.get())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
    let authority_updated = sqlx::query(
        r"
        UPDATE github_server_service_authorities
        SET current_issuance_generation = $2,
            refresh_issuance_generation = NULL,
            consecutive_generation_failures = 0,
            next_mint_not_before_ms = NULL,
            mint_gate_generation = NULL,
            failure_budget_rearm_at_ms = NULL,
            state_updated_at_ms = $3
        WHERE id = $1 AND state = 'active'
          AND refresh_issuance_generation = $2
          AND current_issuance_generation IS NOT DISTINCT FROM $4
          AND state_updated_at_ms <= $3
        ",
    )
    .bind(claim.key().authority_id().as_uuid())
    .bind(pg_bigint(claim.key().generation().get()))
    .bind(committed_at.get())
    .bind(old_current.map(|generation| pg_bigint(generation.get())))
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if authority_updated.rows_affected() != 1 {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let receipt = decode_issuance_receipt(&row)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(receipt)
}

#[allow(clippy::too_many_lines)]
async fn finish_revoke_only(
    store: &PostgresStore,
    claim: GithubServerServiceClaim,
    protected: &ProtectedGithubServerServiceCredential,
    committed_at: UnixMillis,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let metadata = protected.metadata();
    if !automata_ci_store::adapter_spi::github_server_service_authority_matches(
        claim.selector(),
        metadata.identity(),
    ) || metadata.generation() != claim.key().generation()
        || metadata.safe_erase_after() <= committed_at
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let authority_row = select_authority_for_update(&mut transaction, claim.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&authority_row)?;
    let existing = select_issuance_for_update(&mut transaction, claim.key())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    if issuance_state(&existing)? == GithubServerServiceIssuanceState::RevokePending {
        let replay = exact_revoke_only_replay(&existing, &claim, protected, committed_at)?
            && descriptor.current_generation() != Some(claim.key().generation())
            && descriptor.refresh_generation() != Some(claim.key().generation());
        if !replay {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
        let receipt = decode_issuance_receipt(&existing)?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let database_now = database_now_ms(&mut transaction).await?;
    let state = issuance_state(&existing)?;
    let transition_at = database_now
        .max(committed_at.get())
        .max(i64_column(&existing, "state_updated_at_ms")?);
    if !matches!(
        state,
        GithubServerServiceIssuanceState::Minting | GithubServerServiceIssuanceState::Indeterminate
    ) || optional_uuid(&existing, "mint_started_owner_id")? != Some(claim.worker().as_uuid())
        || optional_i64(&existing, "mint_started_claim_fence")?
            != Some(pg_bigint(claim.fence().get()))
        || optional_i64(&existing, "mint_started_at_ms")?
            .is_none_or(|started| started > committed_at.get())
        || metadata.identity() != descriptor.identity()
        || metadata.requested_at().get() != i64_column(&existing, "requested_at_ms")?
        || metadata.request_deadline().get() != i64_column(&existing, "request_deadline_at_ms")?
        || metadata.safe_erase_after().get() <= database_now
        || metadata.safe_erase_after().get() <= transition_at
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }

    let envelope = protected.envelope();
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = 'revoke_pending', mint_claim_owner_id = NULL,
            mint_claimed_at_ms = NULL, mint_claim_expires_at_ms = NULL,
            next_mint_at_ms = NULL,
            generation_failure_gate_at_ms = $6,
            mint_failure_kind = CASE
                WHEN $5::BIGINT IS NULL THEN 'provider_expiry_unknown'
                ELSE NULL
            END,
            provider_expires_at_ms = $5, safe_erase_after_ms = $6,
            plaintext_schema = $7, plaintext_size_bytes = $8,
            plaintext_digest = $9, aad_digest = $10,
            envelope_schema = $11, wrapping_key_id = $12,
            wrapped_data_key = $13, nonce = $14, ciphertext = $15,
            state_updated_at_ms = $16
        WHERE authority_id = $1 AND generation = $2
          AND state IN ('minting', 'indeterminate')
          AND mint_started_owner_id = $3
          AND mint_started_claim_fence = $4
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(claim.key().authority_id().as_uuid())
    .bind(pg_bigint(claim.key().generation().get()))
    .bind(claim.worker().as_uuid())
    .bind(pg_bigint(claim.fence().get()))
    .bind(metadata.provider_expires_at().map(UnixMillis::get))
    .bind(metadata.safe_erase_after().get())
    .bind(i32::from(metadata.plaintext_schema()))
    .bind(i64_from_u64(metadata.plaintext_size_bytes())?)
    .bind(metadata.plaintext_digest().as_bytes().as_slice())
    .bind(metadata.aad_digest().as_bytes().as_slice())
    .bind(i32::from(envelope.schema()))
    .bind(envelope.wrapping_key_id().as_str())
    .bind(envelope.wrapped_data_key().ciphertext())
    .bind(envelope.nonce().as_slice())
    .bind(envelope.ciphertext())
    .bind(transition_at)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::ClaimRejected)?;

    if descriptor.refresh_generation() == Some(claim.key().generation()) {
        let cleared = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET refresh_issuance_generation = NULL,
                consecutive_generation_failures = LEAST(
                    consecutive_generation_failures + 1, 32
                ),
                failure_budget_rearm_at_ms = CASE
                    WHEN consecutive_generation_failures = 31 THEN $6
                    ELSE failure_budget_rearm_at_ms
                END,
                mint_gate_generation = CASE
                    WHEN next_mint_not_before_ms IS NULL
                        OR $5 > next_mint_not_before_ms THEN $4
                    ELSE mint_gate_generation
                END,
                next_mint_not_before_ms = GREATEST(
                    COALESCE(next_mint_not_before_ms, $5), $5
                ),
                state_updated_at_ms = $3
            WHERE tenant_id = $1 AND id = $2
              AND refresh_issuance_generation = $4
              AND state_updated_at_ms <= $3
            ",
        )
        .bind(claim.selector().tenant().as_str())
        .bind(claim.key().authority_id().as_uuid())
        .bind(transition_at)
        .bind(pg_bigint(claim.key().generation().get()))
        .bind(generation_failure_not_before(&row)?)
        .bind(failure_budget_rearm_at(UnixMillis::new(transition_at))?)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if cleared.rows_affected() != 1 {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
    } else if state == GithubServerServiceIssuanceState::Indeterminate
        && descriptor.state() == GithubServerServiceAuthorityState::Active
        && descriptor.mint_gate_generation() == Some(claim.key().generation())
    {
        recompute_github_server_service_failure_gate(
            &mut transaction,
            &descriptor,
            claim.key(),
            UnixMillis::new(transition_at),
        )
        .await?;
    }
    let receipt = decode_issuance_receipt(&row)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn finish_mint_without_credential(
    store: &PostgresStore,
    claim: GithubServerServiceClaim,
    target_state: &str,
    failure: Option<&str>,
    observed_at: UnixMillis,
    retry_at: Option<UnixMillis>,
    terminal_reason: Option<&str>,
    clear_refresh: bool,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let authority_row = select_authority_for_update(&mut transaction, claim.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&authority_row)?;
    let existing = select_issuance_for_update(&mut transaction, claim.key())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let request_deadline = i64_column(&existing, "request_deadline_at_ms")?;
    let retry_limit_reached = target_state == "mint_retry"
        && u16_column(&existing, "mint_attempt_count")? >= MAX_GITHUB_SERVICE_MINT_ATTEMPTS;
    let retry_window_expired = target_state == "mint_retry"
        && observed_at
            .get()
            .checked_add(1)
            .is_none_or(|next| next >= request_deadline);
    let effective_state = if retry_limit_reached || retry_window_expired {
        "rejected"
    } else {
        target_state
    };
    let effective_retry_at = if effective_state == "mint_retry" {
        retry_at.map(|retry| UnixMillis::new(retry.get().min(request_deadline - 1)))
    } else {
        None
    };
    let effective_terminal = if retry_limit_reached {
        Some("retry_exhausted")
    } else if retry_window_expired {
        Some("request_expired")
    } else {
        terminal_reason
    };
    let effective_clear_refresh = clear_refresh || retry_limit_reached || retry_window_expired;
    if github_server_service_issuance_state_name(issuance_state(&existing)?) == effective_state
        && positive_u64(&existing, "mint_claim_fence")? == claim.fence().get()
        && exact_mint_result_claim(&existing, &claim)?
        && optional_string(&existing, "mint_failure_kind")?.as_deref() == failure
        && i64_column(&existing, "state_updated_at_ms")? == observed_at.get()
        && optional_i64(&existing, "next_mint_at_ms")? == effective_retry_at.map(UnixMillis::get)
        && optional_string(&existing, "terminal_reason")?.as_deref() == effective_terminal
    {
        let receipt = decode_issuance_receipt(&existing)?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let database_now = database_now_ms(&mut transaction).await?;
    validate_caller_clock(observed_at, database_now)?;
    require_live_mint_claim(&existing, &claim, observed_at, database_now)?;
    if descriptor.refresh_generation() != Some(claim.key().generation()) {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = $5, mint_claim_owner_id = NULL,
            mint_claimed_at_ms = NULL, mint_claim_expires_at_ms = NULL,
            next_mint_at_ms = $6, mint_failure_kind = $7,
            generation_failure_gate_at_ms = CASE
                WHEN $5 = 'rejected' THEN $9 + 60000
                WHEN $5 = 'indeterminate' THEN safe_erase_after_ms
                ELSE generation_failure_gate_at_ms
            END,
            terminal_reason = $8, state_updated_at_ms = $9
        WHERE authority_id = $1 AND generation = $2
          AND state = 'minting' AND mint_claim_owner_id = $3
          AND mint_claim_fence = $4
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(claim.key().authority_id().as_uuid())
    .bind(pg_bigint(claim.key().generation().get()))
    .bind(claim.worker().as_uuid())
    .bind(pg_bigint(claim.fence().get()))
    .bind(effective_state)
    .bind(effective_retry_at.map(UnixMillis::get))
    .bind(failure)
    .bind(effective_terminal)
    .bind(observed_at.get())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
    if effective_clear_refresh {
        let updated = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET refresh_issuance_generation = NULL,
                consecutive_generation_failures = LEAST(
                    consecutive_generation_failures + 1, 32
                ),
                failure_budget_rearm_at_ms = CASE
                    WHEN consecutive_generation_failures = 31 THEN $5
                    ELSE failure_budget_rearm_at_ms
                END,
                mint_gate_generation = CASE
                    WHEN next_mint_not_before_ms IS NULL
                        OR $4 > next_mint_not_before_ms THEN $2
                    ELSE mint_gate_generation
                END,
                next_mint_not_before_ms = GREATEST(
                    COALESCE(next_mint_not_before_ms, $4), $4
                ),
                state_updated_at_ms = $3
            WHERE id = $1 AND refresh_issuance_generation = $2
              AND state_updated_at_ms <= $3
            ",
        )
        .bind(claim.key().authority_id().as_uuid())
        .bind(pg_bigint(claim.key().generation().get()))
        .bind(observed_at.get())
        .bind(generation_failure_not_before(&row)?)
        .bind(failure_budget_rearm_at(observed_at)?)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if updated.rows_affected() != 1 {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
    }
    let receipt = decode_issuance_receipt(&row)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(receipt)
}

#[allow(clippy::too_many_lines)]
async fn acquire_handoff(
    store: &PostgresStore,
    request: AcquireGithubServerServiceHandoff,
) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let authority_row = select_authority_for_update(&mut transaction, request.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&authority_row)?;
    if descriptor.identity().scope() != request.consumer().action().required_scope() {
        return Err(GithubServerServiceStoreError::HandoffRejected);
    }
    let consumer_check_now = database_now_ms(&mut transaction).await?;
    let consumer_expires_at = revalidate_handoff_consumer(
        &mut transaction,
        descriptor.identity(),
        request.consumer(),
        UnixMillis::new(consumer_check_now),
    )
    .await?;
    if consumer_expires_at
        .get()
        .checked_add(request.consumer().action().provider_tail_millis())
        .is_none_or(|maximum| request.required_through().get() > maximum)
    {
        return Err(GithubServerServiceStoreError::HandoffRejected);
    }
    let consumer = request.consumer();
    let existing_handoff = sqlx::query(
        r"
        SELECT id, tenant_id, authority_id, generation, consumer_id,
               consumer_owner_id, consumer_claim_fence, consumer_action,
               consumer_revision, required_through_ms, granted_at_ms,
               released_at_ms
        FROM github_server_service_authority_handoffs
        WHERE authority_id = $1 AND consumer_id = $2
          AND consumer_owner_id = $3 AND consumer_claim_fence = $4
          AND consumer_action = $5 AND consumer_revision = $6
        FOR UPDATE
        ",
    )
    .bind(request.authority_id().as_uuid())
    .bind(consumer.consumer_id().as_uuid())
    .bind(consumer.owner().as_uuid())
    .bind(pg_bigint(consumer.fence().get()))
    .bind(consumer.action().as_str())
    .bind(pg_bigint(consumer.revision().get()))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let is_replay = existing_handoff.is_some();

    let (handoff_id, generation, granted_at) = if let Some(row) = &existing_handoff {
        let replay_consumer = decode_consumer_claim(row)?;
        if string_column(row, "tenant_id")? != descriptor.identity().tenant().as_str()
            || uuid_column(row, "authority_id")? != request.authority_id().as_uuid()
            || replay_consumer != request.consumer()
            || optional_i64(row, "released_at_ms")?.is_some()
        {
            return Err(GithubServerServiceStoreError::HandoffRejected);
        }
        let durable_required_through = i64_column(row, "required_through_ms")?;
        let durable_granted_at = i64_column(row, "granted_at_ms")?;
        if durable_required_through != request.required_through().get()
            || request.observed_at().get() < durable_granted_at
        {
            return Err(GithubServerServiceStoreError::HandoffRejected);
        }
        (
            GithubServerServiceHandoffId::from_uuid(uuid_column(row, "id")?)
                .map_err(|_| GithubServerServiceStoreError::CorruptData)?,
            generation_column(row, "generation")?,
            UnixMillis::new(durable_granted_at),
        )
    } else {
        if descriptor.state() != GithubServerServiceAuthorityState::Active {
            return Err(GithubServerServiceStoreError::HandoffRejected);
        }
        let generation = descriptor
            .current_generation()
            .ok_or(GithubServerServiceStoreError::HandoffRejected)?;
        let key = GithubServerServiceIssuanceKey::new(request.authority_id(), generation);
        let issuance = select_issuance_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubServerServiceStoreError::CorruptData)?;
        let receipt = decode_issuance_receipt(&issuance)?;
        if receipt.state() != GithubServerServiceIssuanceState::Ready
            || receipt
                .usable_until()
                .is_none_or(|until| until < request.required_through())
        {
            return Err(GithubServerServiceStoreError::HandoffRejected);
        }
        let inserted = sqlx::query(
            r"
            INSERT INTO github_server_service_authority_handoffs (
                id, tenant_id, authority_id, generation, consumer_id,
                consumer_owner_id, consumer_claim_fence, consumer_action,
                consumer_revision, required_through_ms, granted_at_ms
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT DO NOTHING
            ",
        )
        .bind(request.proposed_handoff_id().as_uuid())
        .bind(descriptor.identity().tenant().as_str())
        .bind(request.authority_id().as_uuid())
        .bind(pg_bigint(generation.get()))
        .bind(consumer.consumer_id().as_uuid())
        .bind(consumer.owner().as_uuid())
        .bind(pg_bigint(consumer.fence().get()))
        .bind(consumer.action().as_str())
        .bind(pg_bigint(consumer.revision().get()))
        .bind(request.required_through().get())
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if inserted.rows_affected() != 1 {
            return Err(GithubServerServiceStoreError::HandoffRejected);
        }
        (
            request.proposed_handoff_id(),
            generation,
            request.observed_at(),
        )
    };

    let key = GithubServerServiceIssuanceKey::new(request.authority_id(), generation);
    let issuance = select_issuance_for_update(&mut transaction, key)
        .await?
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let receipt = decode_issuance_receipt(&issuance)?;
    let database_now = database_now_ms(&mut transaction).await?;
    validate_caller_clock(request.observed_at(), database_now)
        .map_err(|_| GithubServerServiceStoreError::HandoffRejected)?;
    let consumer_expires_at = revalidate_handoff_consumer(
        &mut transaction,
        descriptor.identity(),
        request.consumer(),
        UnixMillis::new(database_now),
    )
    .await?;
    if (request.consumer().action() != GithubServerServiceAction::ObserveWorkflowPermissionDefaults
        && database_now >= consumer_expires_at.get())
        || database_now >= request.required_through().get()
        || consumer_expires_at
            .get()
            .checked_add(request.consumer().action().provider_tail_millis())
            .is_none_or(|maximum| request.required_through().get() > maximum)
        || !matches!(
            receipt.state(),
            GithubServerServiceIssuanceState::Ready
                | GithubServerServiceIssuanceState::RevokePending
        )
        || receipt
            .usable_until()
            .is_none_or(|until| until.get() < request.required_through().get())
        || !is_replay
            && (receipt.state() != GithubServerServiceIssuanceState::Ready
                || descriptor.current_generation() != Some(generation))
    {
        return Err(GithubServerServiceStoreError::HandoffRejected);
    }
    let protected = match decode_protected(descriptor.identity().clone(), &issuance) {
        Ok(protected) => protected,
        Err(GithubServerServiceStoreError::CorruptData) => {
            if receipt.state() == GithubServerServiceIssuanceState::Ready
                && descriptor.current_generation() == Some(generation)
            {
                quarantine_current_decode_corruption(
                    &mut transaction,
                    &descriptor,
                    key,
                    UnixMillis::new(database_now.max(receipt.state_updated_at().get())),
                )
                .await?;
            } else if receipt.state() == GithubServerServiceIssuanceState::RevokePending {
                quarantine_retained_decode_corruption(
                    &mut transaction,
                    key,
                    UnixMillis::new(database_now.max(receipt.state_updated_at().get())),
                )
                .await?;
            } else {
                return Err(GithubServerServiceStoreError::CorruptData);
            }
            transaction.commit().await.map_err(operation_error)?;
            return Err(GithubServerServiceStoreError::CorruptData);
        }
        Err(error) => return Err(error),
    };
    let handoff = GithubServerServiceCredentialHandoff::from_durable_parts(
        handoff_id,
        request.consumer(),
        descriptor.identity().clone(),
        receipt,
        request.required_through(),
        granted_at,
        request.observed_at(),
        protected,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(handoff)
}

#[allow(clippy::too_many_lines)]
async fn revalidate_handoff_consumer(
    connection: &mut PgConnection,
    identity: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
) -> Result<UnixMillis, GithubServerServiceStoreError> {
    let claim_expires_at = match identity.scope() {
        GithubServerServiceScope::ChecksWrite => {
            let claim_action = match consumer.action() {
                GithubServerServiceAction::EnsureCheckSuite => "ensure_suite",
                GithubServerServiceAction::CreateCheckRun => "prepare_run_create",
                GithubServerServiceAction::ReconcileCheckRun => "reconcile_run_create",
                GithubServerServiceAction::PublishCheckRun => "publish",
                GithubServerServiceAction::FetchPrivateRepositoryRevision
                | GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
                | GithubServerServiceAction::FetchPrivatePullRequestFiles
                | GithubServerServiceAction::DiscoverPrivateRepositorySchedules
                | GithubServerServiceAction::ObserveWorkflowPermissionDefaults => {
                    return Err(GithubServerServiceStoreError::HandoffRejected);
                }
            };
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT outbox.claim_expires_at_ms
                FROM github_check_projection_outbox AS outbox
                JOIN github_check_subjects AS subject
                  ON subject.id = outbox.subject_id
                WHERE outbox.subject_id = $1
                  AND outbox.state = 'claimed'
                  AND outbox.claim_owner_id = $2
                  AND outbox.claim_fence = $3
                  AND outbox.claim_action = $4
                  AND outbox.claimed_desired_revision = $5
                  AND outbox.claimed_at_ms <= $6
                  AND outbox.state_updated_at_ms <= $6
                  AND outbox.claim_expires_at_ms > $6
                  AND subject.tenant_id = $7
                  AND subject.repository_id = $8
                  AND subject.provider_connection_id = $9
                  AND subject.provider_installation_id = $10
                  AND subject.github_app_id = $11
                  AND subject.github_repository_id = $12
                  AND subject.github_repository_name = $13
                FOR SHARE OF outbox, subject
                ",
            )
            .bind(consumer.consumer_id().as_uuid())
            .bind(consumer.owner().as_uuid())
            .bind(pg_bigint(consumer.fence().get()))
            .bind(claim_action)
            .bind(pg_bigint(consumer.revision().get()))
            .bind(observed_at.get())
            .bind(identity.tenant().as_str())
            .bind(identity.repository_id().as_uuid())
            .bind(identity.connection_id().as_uuid())
            .bind(pg_bigint(identity.installation_id().get()))
            .bind(pg_bigint(identity.github_app_id().get()))
            .bind(pg_bigint(identity.github_repository_id().get()))
            .bind(identity.github_repository_name().as_str())
            .fetch_optional(&mut *connection)
            .await
            .map_err(operation_error)?
            .map(UnixMillis::new)
        }
        GithubServerServiceScope::PrivateRepositorySourceRead => {
            if consumer.action() == GithubServerServiceAction::DiscoverPrivateRepositorySchedules {
                return revalidate_schedule_discovery_consumer(
                    connection,
                    identity,
                    consumer,
                    observed_at,
                )
                .await;
            }
            if !matches!(
                consumer.action(),
                GithubServerServiceAction::FetchPrivateRepositoryRevision
                    | GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
            ) {
                return Err(GithubServerServiceStoreError::HandoffRejected);
            }
            revalidate_delivery_consumer(connection, identity, consumer, observed_at, false).await?
        }
        GithubServerServiceScope::PrivatePullRequestFilesRead => {
            if consumer.action() != GithubServerServiceAction::FetchPrivatePullRequestFiles {
                return Err(GithubServerServiceStoreError::HandoffRejected);
            }
            revalidate_delivery_consumer(connection, identity, consumer, observed_at, true).await?
        }
        GithubServerServiceScope::WorkflowPermissionsRead => {
            if consumer.action() != GithubServerServiceAction::ObserveWorkflowPermissionDefaults {
                return Err(GithubServerServiceStoreError::HandoffRejected);
            }
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT candidate.claimed_at_ms
                  FROM github_workflow_permission_observation_candidates AS candidate
                 WHERE candidate.tenant_id = $1
                   AND candidate.observation_id = $2
                   AND candidate.consumer_owner_id = $3
                   AND candidate.consumer_claim_fence = $4
                   AND candidate.consumer_action = $5
                   AND candidate.consumer_revision = $6
                   AND candidate.authority_id = $7
                   AND candidate.authority_identity_digest = $8
                   AND candidate.repository_id = $9
                   AND candidate.provider_connection_id = $10
                   AND candidate.provider_installation_id = $11
                   AND candidate.github_app_id = $12
                   AND candidate.github_repository_id = $13
                   AND candidate.github_repository_name = $14
                   AND candidate.github_app_client_id = $15
                   AND candidate.github_app_jwt_issuer_kind = $16
                   AND candidate.app_key_spki_sha256 = $17
                   AND candidate.app_configuration_revision = $18
                   AND candidate.policy_revision = $19
                   AND candidate.claimed_at_ms <= $20
                   AND candidate.expires_at_ms > $20
                 FOR SHARE OF candidate
                ",
            )
            .bind(identity.tenant().as_str())
            .bind(consumer.consumer_id().as_uuid())
            .bind(consumer.owner().as_uuid())
            .bind(pg_bigint(consumer.fence().get()))
            .bind(consumer.action().as_str())
            .bind(pg_bigint(consumer.revision().get()))
            .bind(identity.authority_id().as_uuid())
            .bind(identity.identity_digest().as_bytes().as_slice())
            .bind(identity.repository_id().as_uuid())
            .bind(identity.connection_id().as_uuid())
            .bind(pg_bigint(identity.installation_id().get()))
            .bind(pg_bigint(identity.github_app_id().get()))
            .bind(pg_bigint(identity.github_repository_id().get()))
            .bind(identity.github_repository_name().as_str())
            .bind(identity.app_client_id().as_str())
            .bind(identity.jwt_issuer().as_str())
            .bind(identity.app_key_spki_sha256().as_bytes().as_slice())
            .bind(pg_bigint(identity.app_configuration_revision().get()))
            .bind(pg_bigint(identity.policy_revision().get()))
            .bind(observed_at.get())
            .fetch_optional(&mut *connection)
            .await
            .map_err(operation_error)?
            .map(UnixMillis::new)
        }
    };
    claim_expires_at.ok_or(GithubServerServiceStoreError::HandoffRejected)
}

async fn revalidate_delivery_consumer(
    connection: &mut PgConnection,
    identity: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    require_pull_request_files_pin: bool,
) -> Result<Option<UnixMillis>, GithubServerServiceStoreError> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT delivery.claim_expires_at_ms
        FROM provider_delivery_inbox AS delivery
        JOIN repositories AS repository
          ON repository.id = $7
         AND repository.tenant_id = delivery.tenant_id
         AND repository.scm_provider = 'github'
         AND repository.provider_repository_id = delivery.provider_repository_id::TEXT
        WHERE delivery.id = $1
          AND delivery.state = 'claimed'
          AND delivery.claim_owner_id = $2
          AND delivery.claim_fence = $3
          AND delivery.attempt_count = $4
          AND delivery.claimed_at_ms <= $5
          AND delivery.state_updated_at_ms <= $5
          AND delivery.claim_expires_at_ms > $5
          AND delivery.tenant_id = $6
          AND delivery.provider = 'github'
          AND delivery.repository_visibility = 'private'
          AND delivery.connection_id = $8
          AND delivery.installation_id = $9
          AND delivery.provider_repository_id = $10
          AND delivery.repository_identity = $11
          AND (
              NOT $12
              OR EXISTS (
                  SELECT 1
                  FROM github_provider_delivery_evidence AS evidence
                  WHERE evidence.provider_delivery_id = delivery.id
                    AND evidence.tenant_id = delivery.tenant_id
                    AND evidence.authenticated_event_name = 'pull_request'
                    AND evidence.private_pull_request_files_authority_id = $13
                    AND evidence.private_pull_request_files_authority_identity_digest = $14
                    AND evidence.private_pull_request_files_authority_app_configuration_revision = $15
                    AND evidence.private_pull_request_files_authority_policy_revision = $16
              )
          )
        FOR SHARE OF delivery, repository
        ",
    )
    .bind(consumer.consumer_id().as_uuid())
    .bind(consumer.owner().as_uuid())
    .bind(pg_bigint(consumer.fence().get()))
    .bind(pg_bigint(consumer.revision().get()))
    .bind(observed_at.get())
    .bind(identity.tenant().as_str())
    .bind(identity.repository_id().as_uuid())
    .bind(identity.connection_id().as_uuid())
    .bind(pg_bigint(identity.installation_id().get()))
    .bind(pg_bigint(identity.github_repository_id().get()))
    .bind(identity.github_repository_name().as_str())
    .bind(require_pull_request_files_pin)
    .bind(identity.authority_id().as_uuid())
    .bind(identity.identity_digest().as_bytes().as_slice())
    .bind(pg_bigint(identity.app_configuration_revision().get()))
    .bind(pg_bigint(identity.policy_revision().get()))
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)
    .map(|value| value.map(UnixMillis::new))
}

async fn revalidate_schedule_discovery_consumer(
    connection: &mut PgConnection,
    identity: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
) -> Result<UnixMillis, GithubServerServiceStoreError> {
    if pg_bigint(consumer.revision().get()) != 1 {
        return Err(GithubServerServiceStoreError::HandoffRejected);
    }
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT discovery.claim_expires_at_ms
          FROM github_schedule_discovery_claims AS discovery
          JOIN github_provider_manifest_current AS current
            ON current.tenant_id = discovery.tenant_id
           AND current.repository_id = discovery.repository_id
           AND current.provider_connection_id = discovery.provider_connection_id
           AND current.manifest_revision = discovery.manifest_revision
           AND current.manifest_digest = discovery.manifest_digest
          JOIN github_provider_manifest_revisions AS manifest
            ON manifest.tenant_id = current.tenant_id
           AND manifest.repository_id = current.repository_id
           AND manifest.provider_connection_id = current.provider_connection_id
           AND manifest.manifest_revision = current.manifest_revision
           AND manifest.manifest_digest = current.manifest_digest
          JOIN repositories AS repository
            ON repository.id = discovery.repository_id
           AND repository.tenant_id = discovery.tenant_id
           AND repository.scm_provider = 'github'
           AND repository.provider_repository_id = manifest.github_repository_id::TEXT
         WHERE discovery.discovery_id = $1
           AND discovery.state = 'claimed'
           AND discovery.claim_owner_id = $2
           AND discovery.claim_fence = $3
           AND discovery.claimed_at_ms <= $4
           AND discovery.updated_at_ms <= $4
           AND discovery.claim_expires_at_ms > $4
           AND discovery.tenant_id = $5
           AND discovery.repository_id = $6
           AND discovery.provider_connection_id = $7
           AND discovery.source_authority_kind = 'private_repository_source_read'
           AND discovery.private_source_authority_id = $8
           AND discovery.private_source_authority_identity_digest = $9
           AND discovery.private_source_authority_app_configuration_revision = $10
           AND discovery.private_source_authority_policy_revision = $11
           AND manifest.provider_installation_id = $12
           AND manifest.github_app_id = $13
           AND manifest.github_repository_id = $14
           AND manifest.github_repository_name = $15
         FOR SHARE OF discovery, current, manifest, repository
        ",
    )
    .bind(consumer.consumer_id().as_uuid())
    .bind(consumer.owner().as_uuid())
    .bind(pg_bigint(consumer.fence().get()))
    .bind(observed_at.get())
    .bind(identity.tenant().as_str())
    .bind(identity.repository_id().as_uuid())
    .bind(identity.connection_id().as_uuid())
    .bind(identity.authority_id().as_uuid())
    .bind(identity.identity_digest().as_bytes().as_slice())
    .bind(pg_bigint(identity.app_configuration_revision().get()))
    .bind(pg_bigint(identity.policy_revision().get()))
    .bind(pg_bigint(identity.installation_id().get()))
    .bind(pg_bigint(identity.github_app_id().get()))
    .bind(pg_bigint(identity.github_repository_id().get()))
    .bind(identity.github_repository_name().as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)?
    .map(UnixMillis::new)
    .ok_or(GithubServerServiceStoreError::HandoffRejected)
}

async fn release_handoff(
    store: &PostgresStore,
    request: ReleaseGithubServerServiceHandoff,
) -> Result<(), GithubServerServiceStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    select_authority_for_update(&mut transaction, request.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let consumer = request.consumer();
    let changed = sqlx::query(
        r"
        UPDATE github_server_service_authority_handoffs
        SET released_at_ms = $7
        WHERE id = $1 AND consumer_id = $2 AND consumer_owner_id = $3
          AND consumer_claim_fence = $4 AND consumer_action = $5
          AND consumer_revision = $6 AND released_at_ms IS NULL
          AND granted_at_ms <= $7
          AND authority_id = $8 AND tenant_id = $9
        ",
    )
    .bind(request.handoff_id().as_uuid())
    .bind(consumer.consumer_id().as_uuid())
    .bind(consumer.owner().as_uuid())
    .bind(pg_bigint(consumer.fence().get()))
    .bind(consumer.action().as_str())
    .bind(pg_bigint(consumer.revision().get()))
    .bind(request.released_at().get())
    .bind(request.selector().authority_id().as_uuid())
    .bind(request.selector().tenant().as_str())
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() == 1 {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(());
    }
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM github_server_service_authority_handoffs
            WHERE id = $1 AND consumer_id = $2 AND consumer_owner_id = $3
              AND consumer_claim_fence = $4 AND consumer_action = $5
              AND consumer_revision = $6 AND released_at_ms = $7
              AND authority_id = $8 AND tenant_id = $9
        )
        ",
    )
    .bind(request.handoff_id().as_uuid())
    .bind(consumer.consumer_id().as_uuid())
    .bind(consumer.owner().as_uuid())
    .bind(pg_bigint(consumer.fence().get()))
    .bind(consumer.action().as_str())
    .bind(pg_bigint(consumer.revision().get()))
    .bind(request.released_at().get())
    .bind(request.selector().authority_id().as_uuid())
    .bind(request.selector().tenant().as_str())
    .fetch_one(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if exact {
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    } else {
        Err(GithubServerServiceStoreError::HandoffRejected)
    }
}

async fn quarantine_current(
    store: &PostgresStore,
    request: QuarantineGithubServerServiceCredential,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let authority_row = select_authority_for_update(&mut transaction, request.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&authority_row)?;
    let existing = select_issuance_for_update(&mut transaction, request.key())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let state = issuance_state(&existing)?;
    if state == GithubServerServiceIssuanceState::Quarantined
        && descriptor.current_generation() != Some(request.key().generation())
        && u16_column(&existing, "revoke_attempt_count")? == 0
        && optional_digest(&existing, "aad_digest")? == Some(request.aad_digest())
        && optional_string(&existing, "revoke_failure_kind")?.as_deref()
            == Some(request.failure().as_str())
        && i64_column(&existing, "state_updated_at_ms")? == request.observed_at().get()
    {
        let receipt = decode_issuance_receipt(&existing)?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let database_now = database_now_ms(&mut transaction).await?;
    validate_caller_clock(request.observed_at(), database_now)?;
    if descriptor.state() != GithubServerServiceAuthorityState::Active
        || descriptor.current_generation() != Some(request.key().generation())
        || state != GithubServerServiceIssuanceState::Ready
        || optional_digest(&existing, "aad_digest")? != Some(request.aad_digest())
        || i64_column(&existing, "state_updated_at_ms")? > request.observed_at().get()
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = 'quarantined', revoke_failure_kind = $3,
            generation_failure_gate_at_ms = safe_erase_after_ms,
            state_updated_at_ms = $4
        WHERE authority_id = $1 AND generation = $2 AND state = 'ready'
          AND aad_digest = $5
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(request.key().authority_id().as_uuid())
    .bind(pg_bigint(request.key().generation().get()))
    .bind(request.failure().as_str())
    .bind(request.observed_at().get())
    .bind(request.aad_digest().as_bytes().as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
    let cleared = sqlx::query(
        r"
        UPDATE github_server_service_authorities
        SET current_issuance_generation = NULL,
            consecutive_generation_failures = LEAST(
                consecutive_generation_failures + 1, 32
            ),
            failure_budget_rearm_at_ms = CASE
                WHEN consecutive_generation_failures = 31 THEN $6
                ELSE failure_budget_rearm_at_ms
            END,
            mint_gate_generation = CASE
                WHEN next_mint_not_before_ms IS NULL
                    OR $5 > next_mint_not_before_ms THEN $4
                ELSE mint_gate_generation
            END,
            next_mint_not_before_ms = GREATEST(
                COALESCE(next_mint_not_before_ms, $5), $5
            ),
            state_updated_at_ms = $3
        WHERE tenant_id = $1 AND id = $2 AND state = 'active'
          AND current_issuance_generation = $4
          AND state_updated_at_ms <= $3
        ",
    )
    .bind(request.selector().tenant().as_str())
    .bind(request.key().authority_id().as_uuid())
    .bind(request.observed_at().get())
    .bind(pg_bigint(request.key().generation().get()))
    .bind(generation_failure_not_before(&row)?)
    .bind(failure_budget_rearm_at(request.observed_at())?)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if cleared.rows_affected() != 1 {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let receipt = decode_issuance_receipt(&row)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(receipt)
}

async fn quarantine_current_decode_corruption(
    connection: &mut PgConnection,
    descriptor: &GithubServerServiceAuthorityDescriptor,
    key: GithubServerServiceIssuanceKey,
    observed_at: UnixMillis,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = 'quarantined',
            generation_failure_gate_at_ms = safe_erase_after_ms,
            revoke_failure_kind = 'protected_custody_corrupt',
            state_updated_at_ms = $3
        WHERE authority_id = $1 AND generation = $2 AND state = 'ready'
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(key.authority_id().as_uuid())
    .bind(pg_bigint(key.generation().get()))
    .bind(observed_at.get())
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let gate_at = generation_failure_not_before(&row)?;
    let changed = sqlx::query(
        r"
        UPDATE github_server_service_authorities
        SET current_issuance_generation = NULL,
            consecutive_generation_failures = LEAST(
                consecutive_generation_failures + 1, 32
            ),
            failure_budget_rearm_at_ms = CASE
                WHEN consecutive_generation_failures = 31 THEN $6
                ELSE failure_budget_rearm_at_ms
            END,
            mint_gate_generation = CASE
                WHEN next_mint_not_before_ms IS NULL
                    OR $5 > next_mint_not_before_ms THEN $4
                ELSE mint_gate_generation
            END,
            next_mint_not_before_ms = GREATEST(
                COALESCE(next_mint_not_before_ms, $5), $5
            ),
            state_updated_at_ms = $3
        WHERE tenant_id = $1 AND id = $2 AND state = 'active'
          AND current_issuance_generation = $4
          AND state_updated_at_ms <= $3
        ",
    )
    .bind(descriptor.identity().tenant().as_str())
    .bind(key.authority_id().as_uuid())
    .bind(observed_at.get())
    .bind(pg_bigint(key.generation().get()))
    .bind(gate_at)
    .bind(failure_budget_rearm_at(observed_at)?)
    .execute(&mut *connection)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() != 1 {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    decode_issuance_receipt(&row)
}

async fn quarantine_retained_decode_corruption(
    connection: &mut PgConnection,
    key: GithubServerServiceIssuanceKey,
    observed_at: UnixMillis,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = 'quarantined',
            revoke_claim_owner_id = NULL,
            revoke_claimed_at_ms = NULL,
            revoke_claim_expires_at_ms = NULL,
            revoke_result_owner_id = CASE
                WHEN state = 'revoke_claimed' THEN revoke_claim_owner_id
                ELSE revoke_result_owner_id
            END,
            revoke_result_claim_fence = CASE
                WHEN state = 'revoke_claimed' THEN revoke_claim_fence
                ELSE revoke_result_claim_fence
            END,
            revoke_result_claimed_at_ms = CASE
                WHEN state = 'revoke_claimed' THEN revoke_claimed_at_ms
                ELSE revoke_result_claimed_at_ms
            END,
            revoke_result_claim_expires_at_ms = CASE
                WHEN state = 'revoke_claimed' THEN revoke_claim_expires_at_ms
                ELSE revoke_result_claim_expires_at_ms
            END,
            next_revoke_at_ms = NULL,
            revoke_failure_kind = 'protected_custody_corrupt',
            state_updated_at_ms = $3
        WHERE authority_id = $1 AND generation = $2
          AND state IN ('revoke_pending', 'revoke_retry', 'revoke_claimed')
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(key.authority_id().as_uuid())
    .bind(pg_bigint(key.generation().get()))
    .bind(observed_at.get())
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::CorruptData)?;
    decode_issuance_receipt(&row)
}

#[allow(clippy::too_many_lines)]
async fn claim_next_maintenance(
    store: &PostgresStore,
    request: ClaimNextGithubServerServiceMaintenance,
) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError> {
    let claim_duration = requested_duration(request.observed_at(), request.claim_expires_at())?;
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let selection_now = database_now_ms(&mut transaction).await?;
    validate_caller_clock(request.observed_at(), selection_now)?;
    let selection_claim_expires_at = issue_deadline(selection_now, claim_duration)?;
    let candidate = sqlx::query(
        r"
        WITH erase_head AS MATERIALIZED (
            SELECT authority_id, generation, state, safe_erase_after_ms
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND state IN (
                  'ready', 'indeterminate', 'revoke_pending',
                  'revoke_claimed', 'revoke_retry', 'quarantined'
              )
              AND safe_erase_after_ms <= $2
            ORDER BY safe_erase_after_ms, authority_id, generation
            LIMIT 64
        ), mint_claim_head AS MATERIALIZED (
            SELECT authority_id, generation, state,
                   LEAST(mint_claim_expires_at_ms, request_deadline_at_ms) AS due_at_ms
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND state IN ('claimed', 'minting')
              AND LEAST(mint_claim_expires_at_ms, request_deadline_at_ms) <= $2
            ORDER BY LEAST(mint_claim_expires_at_ms, request_deadline_at_ms),
                     authority_id, generation
            LIMIT 64
        ), mint_retry_deadline_head AS MATERIALIZED (
            SELECT authority_id, generation, request_deadline_at_ms
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1 AND state = 'mint_retry'
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND request_deadline_at_ms <= $2
            ORDER BY request_deadline_at_ms, authority_id, generation
            LIMIT 64
        ), mint_retry_head AS MATERIALIZED (
            SELECT authority_id, generation, next_mint_at_ms,
                   request_deadline_at_ms, mint_attempt_count
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1 AND state = 'mint_retry'
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND next_mint_at_ms <= $2
            ORDER BY next_mint_at_ms, authority_id, generation
            LIMIT 64
        ), revoke_pending_head AS MATERIALIZED (
            SELECT authority_id, generation, state_updated_at_ms,
                   safe_erase_after_ms, revoke_attempt_count
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1 AND state = 'revoke_pending'
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND state_updated_at_ms <= $2
            ORDER BY state_updated_at_ms, authority_id, generation
            LIMIT 64
        ), revoke_retry_head AS MATERIALIZED (
            SELECT authority_id, generation, next_revoke_at_ms,
                   safe_erase_after_ms, revoke_attempt_count
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1 AND state = 'revoke_retry'
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND next_revoke_at_ms <= $2
            ORDER BY next_revoke_at_ms, authority_id, generation
            LIMIT 64
        ), revoke_claim_head AS MATERIALIZED (
            SELECT authority_id, generation, revoke_claim_expires_at_ms,
                   safe_erase_after_ms, revoke_attempt_count
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1 AND state = 'revoke_claimed'
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND revoke_claim_expires_at_ms <= $2
            ORDER BY revoke_claim_expires_at_ms, authority_id, generation
            LIMIT 64
        ), bootstrap_head AS MATERIALIZED (
            SELECT id, next_issuance_generation, state_updated_at_ms,
                   consecutive_generation_failures, failure_budget_rearm_at_ms,
                   next_mint_not_before_ms
            FROM github_server_service_authorities
            WHERE tenant_id = $1 AND state = 'active'
              AND ($4::UUID IS NULL OR id = $4)
              AND current_issuance_generation IS NULL
              AND refresh_issuance_generation IS NULL
              AND state_updated_at_ms <= $2
            ORDER BY state_updated_at_ms, id, next_issuance_generation
            LIMIT 64
        ), refresh_head AS MATERIALIZED (
            SELECT authority_id, generation,
                   (provider_expires_at_ms::NUMERIC - 1680000)::BIGINT AS due_at_ms
            FROM github_server_service_authority_issuances
            WHERE tenant_id = $1 AND state = 'ready'
              AND ($4::UUID IS NULL OR authority_id = $4)
              AND provider_expires_at_ms::NUMERIC - 1680000 <= $2
            ORDER BY provider_expires_at_ms::NUMERIC - 1680000,
                     authority_id, generation
            LIMIT 64
        ), candidate_work AS MATERIALIZED (
            SELECT head.authority_id, head.generation,
                   'erase'::TEXT AS maintenance_action,
                   head.safe_erase_after_ms AS due_at_ms
            FROM erase_head AS head
            JOIN github_server_service_authorities AS descriptor
              ON descriptor.id = head.authority_id AND descriptor.tenant_id = $1
            WHERE head.state <> 'ready'
               OR descriptor.current_issuance_generation = head.generation
            UNION ALL
            SELECT authority_id, generation,
                   CASE state
                       WHEN 'claimed' THEN 'reconcile_claimed'
                       ELSE 'reconcile_minting'
                   END,
                   due_at_ms
            FROM mint_claim_head
            UNION ALL
            SELECT authority_id, generation, 'reconcile_mint_retry'::TEXT,
                   request_deadline_at_ms
            FROM mint_retry_deadline_head
            UNION ALL
            SELECT head.authority_id, head.generation, 'claim_mint'::TEXT,
                   head.next_mint_at_ms
            FROM mint_retry_head AS head
            JOIN github_server_service_authorities AS descriptor
              ON descriptor.id = head.authority_id AND descriptor.tenant_id = $1
             AND descriptor.state = 'active'
             AND descriptor.refresh_issuance_generation = head.generation
            WHERE head.request_deadline_at_ms >= $3
              AND head.mint_attempt_count < 32
            UNION ALL
            SELECT head.authority_id, head.generation, 'claim_revoke'::TEXT,
                   head.state_updated_at_ms
            FROM revoke_pending_head AS head
            WHERE head.safe_erase_after_ms >= $3 AND head.revoke_attempt_count < 64
              AND NOT EXISTS (
                  SELECT 1 FROM github_server_service_authority_handoffs AS handoff
                  WHERE handoff.authority_id = head.authority_id
                    AND handoff.generation = head.generation
                    AND handoff.released_at_ms IS NULL
                    AND handoff.required_through_ms > $2
              )
            UNION ALL
            SELECT head.authority_id, head.generation, 'claim_revoke'::TEXT,
                   head.next_revoke_at_ms
            FROM revoke_retry_head AS head
            WHERE head.safe_erase_after_ms >= $3 AND head.revoke_attempt_count < 64
              AND NOT EXISTS (
                  SELECT 1 FROM github_server_service_authority_handoffs AS handoff
                  WHERE handoff.authority_id = head.authority_id
                    AND handoff.generation = head.generation
                    AND handoff.released_at_ms IS NULL
                    AND handoff.required_through_ms > $2
              )
            UNION ALL
            SELECT head.authority_id, head.generation, 'claim_revoke'::TEXT,
                   head.revoke_claim_expires_at_ms
            FROM revoke_claim_head AS head
            WHERE head.safe_erase_after_ms >= $3 AND head.revoke_attempt_count < 64
              AND NOT EXISTS (
                  SELECT 1 FROM github_server_service_authority_handoffs AS handoff
                  WHERE handoff.authority_id = head.authority_id
                    AND handoff.generation = head.generation
                    AND handoff.released_at_ms IS NULL
                    AND handoff.required_through_ms > $2
              )
            UNION ALL
            SELECT id, next_issuance_generation, 'claim_new'::TEXT,
                   state_updated_at_ms
            FROM bootstrap_head
            WHERE next_issuance_generation < 9223372036854775807
              AND (
                  consecutive_generation_failures < 32
                  OR consecutive_generation_failures = 32
                     AND failure_budget_rearm_at_ms <= $2
              )
              AND (next_mint_not_before_ms IS NULL OR next_mint_not_before_ms <= $2)
            UNION ALL
            SELECT descriptor.id, descriptor.next_issuance_generation,
                   'claim_new'::TEXT, head.due_at_ms
            FROM refresh_head AS head
            JOIN github_server_service_authorities AS descriptor
              ON descriptor.id = head.authority_id AND descriptor.tenant_id = $1
             AND descriptor.current_issuance_generation = head.generation
            WHERE descriptor.state = 'active'
              AND descriptor.refresh_issuance_generation IS NULL
              AND descriptor.state_updated_at_ms <= $2
              AND descriptor.next_issuance_generation < 9223372036854775807
              AND (
                  descriptor.consecutive_generation_failures < 32
                  OR descriptor.consecutive_generation_failures = 32
                     AND descriptor.failure_budget_rearm_at_ms <= $2
              )
              AND (
                  descriptor.next_mint_not_before_ms IS NULL
                  OR descriptor.next_mint_not_before_ms <= $2
              )
        ), candidate AS (
            SELECT DISTINCT ON (authority_id)
                   authority_id, generation, maintenance_action, due_at_ms
            FROM candidate_work
            ORDER BY authority_id, due_at_ms, generation, maintenance_action
        )
        SELECT descriptor.id AS authority_id, candidate.generation,
               candidate.maintenance_action
        FROM candidate
        JOIN github_server_service_authorities AS descriptor
          ON descriptor.id = candidate.authority_id
         AND descriptor.tenant_id = $1
        ORDER BY candidate.due_at_ms, descriptor.id,
                 candidate.generation, candidate.maintenance_action
        LIMIT 1
        FOR UPDATE OF descriptor SKIP LOCKED
        ",
    )
    .bind(request.tenant().as_str())
    .bind(selection_now)
    .bind(selection_claim_expires_at)
    .bind(
        request
            .authority()
            .map(|selector| selector.authority_id().as_uuid()),
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let Some(candidate) = candidate else {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(None);
    };
    let authority_id =
        GithubServerServiceAuthorityId::from_uuid(uuid_column(&candidate, "authority_id")?)
            .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let generation = generation_column(&candidate, "generation")?;
    let action = string_column(&candidate, "maintenance_action")?;
    let authority_row =
        select_authority_by_tenant_id_for_update(&mut transaction, request.tenant(), authority_id)
            .await?
            .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let mut descriptor = decode_authority(&authority_row)?;
    let selector = GithubServerServiceAuthoritySelector::from_identity(descriptor.identity());
    if request
        .authority()
        .is_some_and(|expected| expected != &selector)
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    let key = GithubServerServiceIssuanceKey::new(authority_id, generation);
    let mut operation_now = database_now_ms(&mut transaction).await?;
    if operation_now < selection_now {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    validate_caller_clock(request.observed_at(), operation_now)?;

    if action == "claim_new" {
        if let Some(current_generation) = descriptor.current_generation() {
            let current_key = GithubServerServiceIssuanceKey::new(authority_id, current_generation);
            let current = select_issuance_for_update(&mut transaction, current_key)
                .await?
                .ok_or(GithubServerServiceStoreError::CorruptData)?;
            operation_now = database_now_ms(&mut transaction).await?;
            if operation_now < selection_now {
                return Err(GithubServerServiceStoreError::CorruptData);
            }
            validate_caller_clock(request.observed_at(), operation_now)?;
            if issuance_state(&current)? != GithubServerServiceIssuanceState::Ready
                || optional_i64(&current, "provider_expires_at_ms")?
                    .and_then(|expires_at| expires_at.checked_sub(1_680_000))
                    .is_none_or(|refresh_at| refresh_at > operation_now)
            {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
        }
        if descriptor.consecutive_generation_failures()
            >= MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES
        {
            if !rearm_github_server_service_failure_budget(
                &mut transaction,
                &descriptor,
                UnixMillis::new(operation_now),
            )
            .await?
            {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            let rearmed = select_authority_by_tenant_id_for_update(
                &mut transaction,
                request.tenant(),
                authority_id,
            )
            .await?
            .ok_or(GithubServerServiceStoreError::CorruptData)?;
            descriptor = decode_authority(&rearmed)?;
        }
        if descriptor.state() != GithubServerServiceAuthorityState::Active
            || descriptor.refresh_generation().is_some()
            || descriptor.next_generation() != generation
            || descriptor.consecutive_generation_failures()
                >= MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES
            || descriptor
                .next_mint_not_before()
                .is_some_and(|not_before| not_before.get() > operation_now)
        {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
        let next_generation = generation
            .get()
            .checked_add(1)
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or(GithubServerServiceStoreError::FenceExhausted)?;
        let claim_expires_at = issue_deadline(operation_now, claim_duration)?;
        let conservative_expiry = claim_expires_at
            .checked_add(3_780_000)
            .ok_or(GithubServerServiceStoreError::CorruptData)?;
        let row = sqlx::query(AssertSqlSafe(format!(
            r"
            INSERT INTO github_server_service_authority_issuances (
                tenant_id, authority_id, generation, state,
                mint_attempt_count, mint_claim_fence, mint_claim_owner_id,
                mint_claimed_at_ms, mint_claim_expires_at_ms,
                requested_at_ms, request_deadline_at_ms,
                conservative_expiry_at_ms, safe_erase_after_ms,
                created_at_ms, state_updated_at_ms
            ) VALUES (
                $1, $2, $3, 'claimed', 1, 1, $4, $5, $6,
                $5, $6, $7, $7, $5, $5
            )
            RETURNING {ISSUANCE_COLUMNS}
            "
        )))
        .bind(request.tenant().as_str())
        .bind(authority_id.as_uuid())
        .bind(pg_bigint(generation.get()))
        .bind(request.worker().as_uuid())
        .bind(operation_now)
        .bind(claim_expires_at)
        .bind(conservative_expiry)
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let changed = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET refresh_issuance_generation = $3,
                next_issuance_generation = $4,
                state_updated_at_ms = $5
            WHERE tenant_id = $1 AND id = $2 AND state = 'active'
              AND refresh_issuance_generation IS NULL
              AND next_issuance_generation = $3
              AND state_updated_at_ms <= $5
            ",
        )
        .bind(request.tenant().as_str())
        .bind(authority_id.as_uuid())
        .bind(pg_bigint(generation.get()))
        .bind(i64_from_u64(next_generation)?)
        .bind(operation_now)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if changed.rows_affected() != 1 {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
        let outcome = GithubServerServiceMaintenanceOutcome::Mint(Box::new(decode_claimed_mint(
            descriptor.identity().clone(),
            &row,
        )?));
        transaction.commit().await.map_err(operation_error)?;
        return Ok(Some(outcome));
    }

    let existing = select_issuance_for_update(&mut transaction, key)
        .await?
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    operation_now = database_now_ms(&mut transaction).await?;
    if operation_now < selection_now {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    validate_caller_clock(request.observed_at(), operation_now)?;

    let outcome = match action.as_str() {
        "claim_mint" => {
            if issuance_state(&existing)? != GithubServerServiceIssuanceState::MintRetryPending
                || optional_i64(&existing, "next_mint_at_ms")?
                    .is_none_or(|next| next > operation_now)
                || i64_column(&existing, "request_deadline_at_ms")? <= operation_now
                || u16_column(&existing, "mint_attempt_count")? >= MAX_GITHUB_SERVICE_MINT_ATTEMPTS
            {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            let next_fence = positive_u64(&existing, "mint_claim_fence")?
                .checked_add(1)
                .filter(|value| i64::try_from(*value).is_ok())
                .ok_or(GithubServerServiceStoreError::FenceExhausted)?;
            let request_deadline = i64_column(&existing, "request_deadline_at_ms")?;
            let claim_expires_at = issue_deadline(operation_now, claim_duration)?;
            if claim_expires_at > request_deadline {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            let row = sqlx::query(AssertSqlSafe(format!(
                r"
                UPDATE github_server_service_authority_issuances
                SET state = 'claimed',
                    mint_attempt_count = mint_attempt_count + 1,
                    mint_claim_fence = $3, mint_claim_owner_id = $4,
                    mint_claimed_at_ms = $5, mint_claim_expires_at_ms = $6,
                    mint_started_at_ms = NULL, mint_started_owner_id = NULL,
                    mint_started_claim_fence = NULL,
                    mint_started_claimed_at_ms = NULL,
                    mint_started_claim_expires_at_ms = NULL,
                    next_mint_at_ms = NULL, mint_failure_kind = NULL,
                    state_updated_at_ms = $5
                WHERE authority_id = $1 AND generation = $2
                  AND state = 'mint_retry' AND next_mint_at_ms <= $5
                  AND request_deadline_at_ms > $5
                RETURNING {ISSUANCE_COLUMNS}
                "
            )))
            .bind(authority_id.as_uuid())
            .bind(pg_bigint(generation.get()))
            .bind(i64_from_u64(next_fence)?)
            .bind(request.worker().as_uuid())
            .bind(operation_now)
            .bind(claim_expires_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
            GithubServerServiceMaintenanceOutcome::Mint(Box::new(decode_claimed_mint(
                descriptor.identity().clone(),
                &row,
            )?))
        }
        "claim_revoke" => {
            let state = issuance_state(&existing)?;
            let eligible = state == GithubServerServiceIssuanceState::RevokePending
                || state == GithubServerServiceIssuanceState::RevokeRetryPending
                    && optional_i64(&existing, "next_revoke_at_ms")?
                        .is_some_and(|next| next <= operation_now)
                || state == GithubServerServiceIssuanceState::RevokeClaimed
                    && optional_i64(&existing, "revoke_claim_expires_at_ms")?
                        .is_some_and(|expiry| expiry <= operation_now);
            if !eligible
                || u16_column(&existing, "revoke_attempt_count")?
                    >= MAX_GITHUB_SERVICE_REVOKE_ATTEMPTS
            {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            if has_live_handoff(&mut transaction, key, UnixMillis::new(operation_now)).await? {
                return Err(GithubServerServiceStoreError::HandoffStillLive);
            }
            let next_fence = nonnegative_u64(&existing, "revoke_claim_fence")?
                .checked_add(1)
                .filter(|value| i64::try_from(*value).is_ok())
                .ok_or(GithubServerServiceStoreError::FenceExhausted)?;
            let safe_erase_after = i64_column(&existing, "safe_erase_after_ms")?;
            let claim_expires_at = issue_deadline(operation_now, claim_duration)?;
            if claim_expires_at > safe_erase_after {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            let row = sqlx::query(AssertSqlSafe(format!(
                r"
                UPDATE github_server_service_authority_issuances
                SET state = 'revoke_claimed',
                    revoke_attempt_count = revoke_attempt_count + 1,
                    revoke_claim_fence = $3, revoke_claim_owner_id = $4,
                    revoke_claimed_at_ms = $5, revoke_claim_expires_at_ms = $6,
                    revoke_result_owner_id = NULL,
                    revoke_result_claim_fence = NULL,
                    revoke_result_claimed_at_ms = NULL,
                    revoke_result_claim_expires_at_ms = NULL,
                    next_revoke_at_ms = NULL, revoke_failure_kind = NULL,
                    state_updated_at_ms = $5
                WHERE authority_id = $1 AND generation = $2
                  AND state IN ('revoke_pending', 'revoke_retry', 'revoke_claimed')
                RETURNING {ISSUANCE_COLUMNS}
                "
            )))
            .bind(authority_id.as_uuid())
            .bind(pg_bigint(generation.get()))
            .bind(i64_from_u64(next_fence)?)
            .bind(request.worker().as_uuid())
            .bind(operation_now)
            .bind(claim_expires_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
            let Some(claimed) = decode_claimed_revocation_or_quarantine(
                &mut transaction,
                descriptor.identity().clone(),
                &row,
                UnixMillis::new(operation_now),
            )
            .await?
            else {
                transaction.commit().await.map_err(operation_error)?;
                return Err(GithubServerServiceStoreError::CorruptData);
            };
            GithubServerServiceMaintenanceOutcome::Revocation(Box::new(claimed))
        }
        "reconcile_claimed" | "reconcile_minting" | "reconcile_mint_retry" => {
            let state = issuance_state(&existing)?;
            let due = match action.as_str() {
                "reconcile_claimed" => {
                    state == GithubServerServiceIssuanceState::Claimed
                        && (optional_i64(&existing, "mint_claim_expires_at_ms")?
                            .is_some_and(|claim_expiry| claim_expiry <= operation_now)
                            || i64_column(&existing, "request_deadline_at_ms")? <= operation_now)
                }
                "reconcile_minting" => {
                    state == GithubServerServiceIssuanceState::Minting
                        && (optional_i64(&existing, "mint_claim_expires_at_ms")?
                            .is_some_and(|claim_expiry| claim_expiry <= operation_now)
                            || i64_column(&existing, "request_deadline_at_ms")? <= operation_now)
                }
                "reconcile_mint_retry" => {
                    state == GithubServerServiceIssuanceState::MintRetryPending
                        && i64_column(&existing, "request_deadline_at_ms")? <= operation_now
                }
                _ => false,
            };
            if !due {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            let (target_state, failure, terminal_reason) = match action.as_str() {
                "reconcile_minting" => (
                    "indeterminate",
                    "mint_outcome_unobserved_after_claim_expiry".to_owned(),
                    None,
                ),
                "reconcile_mint_retry" => (
                    "rejected",
                    optional_string(&existing, "mint_failure_kind")?
                        .ok_or(GithubServerServiceStoreError::CorruptData)?,
                    Some("request_expired"),
                ),
                _ => (
                    "rejected",
                    "mint_request_expired_before_provider_call".to_owned(),
                    Some("request_expired"),
                ),
            };
            let row = sqlx::query(AssertSqlSafe(format!(
                r"
                UPDATE github_server_service_authority_issuances
                SET state = $4, mint_claim_owner_id = NULL,
                    mint_claimed_at_ms = NULL, mint_claim_expires_at_ms = NULL,
                    next_mint_at_ms = NULL, mint_failure_kind = $5,
                    generation_failure_gate_at_ms = CASE
                        WHEN $4 = 'rejected' THEN $7 + 60000
                        ELSE safe_erase_after_ms
                    END,
                    terminal_reason = $6, state_updated_at_ms = $7
                WHERE authority_id = $1 AND generation = $2 AND state = $3
                RETURNING {ISSUANCE_COLUMNS}
                "
            )))
            .bind(authority_id.as_uuid())
            .bind(pg_bigint(generation.get()))
            .bind(github_server_service_issuance_state_name(state))
            .bind(target_state)
            .bind(&failure)
            .bind(terminal_reason)
            .bind(operation_now)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
            if descriptor.refresh_generation() == Some(generation) {
                let changed = sqlx::query(
                    r"
                    UPDATE github_server_service_authorities
                    SET refresh_issuance_generation = NULL,
                        consecutive_generation_failures = LEAST(
                            consecutive_generation_failures + 1, 32
                        ),
                        failure_budget_rearm_at_ms = CASE
                            WHEN consecutive_generation_failures = 31 THEN $6
                            ELSE failure_budget_rearm_at_ms
                        END,
                        mint_gate_generation = CASE
                            WHEN next_mint_not_before_ms IS NULL
                                OR $5 > next_mint_not_before_ms THEN $4
                            ELSE mint_gate_generation
                        END,
                        next_mint_not_before_ms = GREATEST(
                            COALESCE(next_mint_not_before_ms, $5), $5
                        ),
                        state_updated_at_ms = $3
                    WHERE tenant_id = $1 AND id = $2
                      AND refresh_issuance_generation = $4
                      AND state_updated_at_ms <= $3
                    ",
                )
                .bind(request.tenant().as_str())
                .bind(authority_id.as_uuid())
                .bind(operation_now)
                .bind(pg_bigint(generation.get()))
                .bind(generation_failure_not_before(&row)?)
                .bind(failure_budget_rearm_at(UnixMillis::new(operation_now))?)
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                if changed.rows_affected() != 1 {
                    return Err(GithubServerServiceStoreError::ClaimRejected);
                }
            }
            GithubServerServiceMaintenanceOutcome::Reduced {
                selector,
                receipt: decode_issuance_receipt(&row)?,
            }
        }
        "erase" => {
            let state = issuance_state(&existing)?;
            if !matches!(
                state,
                GithubServerServiceIssuanceState::Ready
                    | GithubServerServiceIssuanceState::Indeterminate
                    | GithubServerServiceIssuanceState::Quarantined
                    | GithubServerServiceIssuanceState::RevokePending
                    | GithubServerServiceIssuanceState::RevokeClaimed
                    | GithubServerServiceIssuanceState::RevokeRetryPending
            ) || i64_column(&existing, "safe_erase_after_ms")? > operation_now
            {
                return Err(GithubServerServiceStoreError::ClaimRejected);
            }
            let terminal_reason = if optional_i64(&existing, "provider_expires_at_ms")?.is_some() {
                "provider_expired"
            } else {
                "conservative_expiry"
            };
            let row = sqlx::query(AssertSqlSafe(format!(
                r"
                UPDATE github_server_service_authority_issuances
                SET state = 'revoked', mint_claim_owner_id = NULL,
                    mint_claimed_at_ms = NULL, mint_claim_expires_at_ms = NULL,
                    next_mint_at_ms = NULL, revoke_claim_owner_id = NULL,
                    revoke_claimed_at_ms = NULL, revoke_claim_expires_at_ms = NULL,
                    next_revoke_at_ms = NULL, revoke_failure_kind = NULL,
                    plaintext_schema = NULL, plaintext_size_bytes = NULL,
                    plaintext_digest = NULL, aad_digest = NULL,
                    envelope_schema = NULL, wrapping_key_id = NULL,
                    wrapped_data_key = NULL, nonce = NULL, ciphertext = NULL,
                    terminal_reason = $3, state_updated_at_ms = $4
                WHERE authority_id = $1 AND generation = $2
                  AND state IN ('ready', 'indeterminate', 'quarantined',
                                'revoke_pending', 'revoke_claimed', 'revoke_retry')
                  AND safe_erase_after_ms <= $4
                RETURNING {ISSUANCE_COLUMNS}
                "
            )))
            .bind(authority_id.as_uuid())
            .bind(pg_bigint(generation.get()))
            .bind(terminal_reason)
            .bind(operation_now)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
            if state == GithubServerServiceIssuanceState::Ready {
                let changed = sqlx::query(
                    r"
                    UPDATE github_server_service_authorities
                    SET current_issuance_generation = NULL, state_updated_at_ms = $3
                    WHERE tenant_id = $1 AND id = $2 AND state = 'active'
                      AND current_issuance_generation = $4
                      AND state_updated_at_ms <= $3
                    ",
                )
                .bind(request.tenant().as_str())
                .bind(authority_id.as_uuid())
                .bind(operation_now)
                .bind(pg_bigint(generation.get()))
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                if changed.rows_affected() != 1 {
                    return Err(GithubServerServiceStoreError::ClaimRejected);
                }
            }
            maybe_finish_retirement(
                &mut transaction,
                authority_id,
                UnixMillis::new(operation_now),
            )
            .await?;
            GithubServerServiceMaintenanceOutcome::Reduced {
                selector,
                receipt: decode_issuance_receipt(&row)?,
            }
        }
        _ => return Err(GithubServerServiceStoreError::CorruptData),
    };
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(outcome))
}

async fn retire_authority(
    store: &PostgresStore,
    request: RetireGithubServerServiceAuthority,
) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let row = select_authority_for_update(&mut transaction, request.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&row)?;
    if descriptor.state() == GithubServerServiceAuthorityState::Retired {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(descriptor);
    }
    if descriptor.state() == GithubServerServiceAuthorityState::Active {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT generation
            FROM github_server_service_authority_issuances
            WHERE authority_id = $1
              AND state IN ('claimed', 'minting', 'mint_retry', 'ready')
            ORDER BY generation
            FOR UPDATE
            ",
        )
        .bind(request.authority_id().as_uuid())
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
    }
    let database_now = database_now_ms(&mut transaction).await?;
    validate_caller_clock(request.observed_at(), database_now)?;
    if descriptor.state() == GithubServerServiceAuthorityState::Active {
        let changed = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET state = 'retiring', current_issuance_generation = NULL,
                refresh_issuance_generation = NULL, state_updated_at_ms = $2
            WHERE id = $1 AND state = 'active' AND state_updated_at_ms <= $2
            ",
        )
        .bind(request.authority_id().as_uuid())
        .bind(database_now)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if changed.rows_affected() != 1 {
            return Err(GithubServerServiceStoreError::ClaimRejected);
        }
        sqlx::query(
            r"
            UPDATE github_server_service_authority_issuances
            SET state = CASE
                    WHEN state IN ('claimed', 'mint_retry') THEN 'rejected'
                    WHEN state = 'minting' THEN 'indeterminate'
                    WHEN state = 'ready' THEN 'revoke_pending'
                    ELSE state
                END,
                mint_claim_owner_id = CASE WHEN state IN ('claimed', 'minting') THEN NULL ELSE mint_claim_owner_id END,
                mint_claimed_at_ms = CASE WHEN state IN ('claimed', 'minting') THEN NULL ELSE mint_claimed_at_ms END,
                mint_claim_expires_at_ms = CASE WHEN state IN ('claimed', 'minting') THEN NULL ELSE mint_claim_expires_at_ms END,
                next_mint_at_ms = CASE WHEN state = 'mint_retry' THEN NULL ELSE next_mint_at_ms END,
                generation_failure_gate_at_ms = CASE
                    WHEN state IN ('claimed', 'mint_retry') THEN $2 + 60000
                    WHEN state = 'minting' THEN safe_erase_after_ms
                    ELSE generation_failure_gate_at_ms
                END,
                mint_failure_kind = CASE
                    WHEN state = 'minting' THEN 'authority_retired_during_mint'
                    WHEN state = 'claimed' THEN 'authority_retired_before_mint'
                    ELSE mint_failure_kind
                END,
                terminal_reason = CASE
                    WHEN state IN ('claimed', 'mint_retry') THEN 'authority_retired_before_mint'
                    ELSE terminal_reason
                END,
                state_updated_at_ms = $2
            WHERE authority_id = $1
              AND state IN ('claimed', 'minting', 'mint_retry', 'ready')
              AND state_updated_at_ms <= $2
            ",
        )
        .bind(request.authority_id().as_uuid())
        .bind(database_now)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    }
    maybe_finish_retirement(
        &mut transaction,
        request.authority_id(),
        UnixMillis::new(database_now),
    )
    .await?;
    let final_row = select_authority_for_update(&mut transaction, request.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let result = decode_authority(&final_row)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(result)
}

async fn has_live_handoff(
    connection: &mut PgConnection,
    key: GithubServerServiceIssuanceKey,
    observed_at: UnixMillis,
) -> Result<bool, GithubServerServiceStoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM github_server_service_authority_handoffs
            WHERE authority_id = $1 AND generation = $2
              AND released_at_ms IS NULL AND required_through_ms > $3
        )
        ",
    )
    .bind(key.authority_id().as_uuid())
    .bind(pg_bigint(key.generation().get()))
    .bind(observed_at.get())
    .fetch_one(&mut *connection)
    .await
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)]
async fn finish_revocation(
    store: &PostgresStore,
    request: FinishGithubServerServiceRevocation,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let (claim, target_state, observed_at, retry_at, failure, terminal) = match &request {
        FinishGithubServerServiceRevocation::Confirmed {
            claim,
            confirmed_at,
        } => (
            claim.clone(),
            "revoked",
            *confirmed_at,
            None,
            None,
            Some("provider_revoked"),
        ),
        FinishGithubServerServiceRevocation::Retry {
            claim,
            failure,
            observed_at,
            retry_at,
        } => (
            claim.clone(),
            "revoke_retry",
            *observed_at,
            Some(*retry_at),
            Some(failure.as_str()),
            None,
        ),
        FinishGithubServerServiceRevocation::Quarantined {
            claim,
            failure,
            observed_at,
        } => (
            claim.clone(),
            "quarantined",
            *observed_at,
            None,
            Some(failure.as_str()),
            None,
        ),
    };
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    pin_read_committed(&mut transaction).await?;
    let authority_row = select_authority_for_update(&mut transaction, claim.selector())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let descriptor = decode_authority(&authority_row)?;
    let existing = select_issuance_for_update(&mut transaction, claim.key())
        .await?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    let safe_erase_after = i64_column(&existing, "safe_erase_after_ms")?;
    let exhausted_retry = target_state == "revoke_retry"
        && (u16_column(&existing, "revoke_attempt_count")? >= MAX_GITHUB_SERVICE_REVOKE_ATTEMPTS
            || retry_at.is_some_and(|retry| retry.get() >= safe_erase_after));
    let effective_state = if exhausted_retry {
        "quarantined"
    } else {
        target_state
    };
    let effective_retry_at = if exhausted_retry { None } else { retry_at };
    if github_server_service_issuance_state_name(issuance_state(&existing)?) == effective_state
        && positive_u64(&existing, "revoke_claim_fence")? == claim.fence().get()
        && optional_uuid(&existing, "revoke_result_owner_id")? == Some(claim.worker().as_uuid())
        && optional_i64(&existing, "revoke_result_claim_fence")?
            == Some(pg_bigint(claim.fence().get()))
        && i64_column(&existing, "state_updated_at_ms")? == observed_at.get()
        && optional_i64(&existing, "next_revoke_at_ms")? == effective_retry_at.map(UnixMillis::get)
        && optional_string(&existing, "revoke_failure_kind")?.as_deref() == failure
        && optional_string(&existing, "terminal_reason")?.as_deref() == terminal
    {
        let receipt = decode_issuance_receipt(&existing)?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let database_now = database_now_ms(&mut transaction).await?;
    validate_caller_clock(observed_at, database_now)?;
    require_live_revoke_claim(&existing, &claim, observed_at, database_now)?;
    let clear_protected = effective_state == "revoked";
    let row = sqlx::query(AssertSqlSafe(format!(
        r"
        UPDATE github_server_service_authority_issuances
        SET state = $5, revoke_claim_owner_id = NULL,
            revoke_claimed_at_ms = NULL, revoke_claim_expires_at_ms = NULL,
            revoke_result_owner_id = revoke_claim_owner_id,
            revoke_result_claim_fence = revoke_claim_fence,
            revoke_result_claimed_at_ms = revoke_claimed_at_ms,
            revoke_result_claim_expires_at_ms = revoke_claim_expires_at_ms,
            next_revoke_at_ms = $6, revoke_failure_kind = $7,
            terminal_reason = $8,
            plaintext_schema = CASE WHEN $9 THEN NULL ELSE plaintext_schema END,
            plaintext_size_bytes = CASE WHEN $9 THEN NULL ELSE plaintext_size_bytes END,
            plaintext_digest = CASE WHEN $9 THEN NULL ELSE plaintext_digest END,
            aad_digest = CASE WHEN $9 THEN NULL ELSE aad_digest END,
            envelope_schema = CASE WHEN $9 THEN NULL ELSE envelope_schema END,
            wrapping_key_id = CASE WHEN $9 THEN NULL ELSE wrapping_key_id END,
            wrapped_data_key = CASE WHEN $9 THEN NULL ELSE wrapped_data_key END,
            nonce = CASE WHEN $9 THEN NULL ELSE nonce END,
            ciphertext = CASE WHEN $9 THEN NULL ELSE ciphertext END,
            state_updated_at_ms = $10
        WHERE authority_id = $1 AND generation = $2
          AND state = 'revoke_claimed' AND revoke_claim_owner_id = $3
          AND revoke_claim_fence = $4
        RETURNING {ISSUANCE_COLUMNS}
        "
    )))
    .bind(claim.key().authority_id().as_uuid())
    .bind(pg_bigint(claim.key().generation().get()))
    .bind(claim.worker().as_uuid())
    .bind(pg_bigint(claim.fence().get()))
    .bind(effective_state)
    .bind(effective_retry_at.map(UnixMillis::get))
    .bind(failure)
    .bind(terminal)
    .bind(clear_protected)
    .bind(observed_at.get())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::ClaimRejected)?;
    if effective_state == "revoked"
        && descriptor.state() == GithubServerServiceAuthorityState::Active
        && descriptor.mint_gate_generation() == Some(claim.key().generation())
    {
        recompute_github_server_service_failure_gate(
            &mut transaction,
            &descriptor,
            claim.key(),
            observed_at,
        )
        .await?;
    }
    maybe_finish_retirement(&mut transaction, claim.key().authority_id(), observed_at).await?;
    let receipt = decode_issuance_receipt(&row)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(receipt)
}

async fn recompute_github_server_service_failure_gate(
    connection: &mut PgConnection,
    descriptor: &GithubServerServiceAuthorityDescriptor,
    transitioned_key: GithubServerServiceIssuanceKey,
    transition_at: UnixMillis,
) -> Result<(), GithubServerServiceStoreError> {
    let next = sqlx::query(
        r"
        SELECT generation,
               CASE
                   WHEN state = 'revoked' AND terminal_reason = 'provider_revoked'
                       THEN LEAST(
                           generation_failure_gate_at_ms,
                           state_updated_at_ms + 60000
                       )
                   ELSE generation_failure_gate_at_ms
               END AS effective_gate_at_ms
        FROM github_server_service_authority_issuances
        WHERE authority_id = $1
          AND generation_failure_gate_at_ms IS NOT NULL
        ORDER BY effective_gate_at_ms DESC, generation DESC
        LIMIT 1
        FOR SHARE
        ",
    )
    .bind(transitioned_key.authority_id().as_uuid())
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)?
    .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let next_mint_at = i64_column(&next, "effective_gate_at_ms")?;
    let gate_generation = generation_column(&next, "generation")?;
    if descriptor.next_mint_not_before().map(UnixMillis::get) == Some(next_mint_at)
        && descriptor.mint_gate_generation() == Some(gate_generation)
    {
        return Ok(());
    }
    let changed = sqlx::query(
        r"
        UPDATE github_server_service_authorities
        SET next_mint_not_before_ms = $3, mint_gate_generation = $4,
            state_updated_at_ms = $5
        WHERE tenant_id = $1 AND id = $2 AND state = 'active'
          AND mint_gate_generation = $6
          AND consecutive_generation_failures > 0
          AND next_mint_not_before_ms = $7
          AND state_updated_at_ms <= $5
        ",
    )
    .bind(descriptor.identity().tenant().as_str())
    .bind(transitioned_key.authority_id().as_uuid())
    .bind(next_mint_at)
    .bind(pg_bigint(gate_generation.get()))
    .bind(transition_at.get())
    .bind(pg_bigint(transitioned_key.generation().get()))
    .bind(
        descriptor
            .next_mint_not_before()
            .ok_or(GithubServerServiceStoreError::CorruptData)?
            .get(),
    )
    .execute(&mut *connection)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() != 1 {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    Ok(())
}

async fn rearm_github_server_service_failure_budget(
    connection: &mut PgConnection,
    descriptor: &GithubServerServiceAuthorityDescriptor,
    observed_at: UnixMillis,
) -> Result<bool, GithubServerServiceStoreError> {
    if descriptor.consecutive_generation_failures()
        != MAX_GITHUB_SERVICE_CONSECUTIVE_GENERATION_FAILURES
        || descriptor.refresh_generation().is_some()
        || descriptor
            .next_mint_not_before()
            .is_none_or(|not_before| not_before > observed_at)
        || descriptor
            .failure_budget_rearm_at()
            .is_none_or(|rearm_at| rearm_at > observed_at)
    {
        return Ok(false);
    }
    let changed = sqlx::query(
        r"
        UPDATE github_server_service_authorities
        SET consecutive_generation_failures = 31,
            failure_budget_rearm_at_ms = NULL,
            state_updated_at_ms = $3
        WHERE tenant_id = $1 AND id = $2 AND state = 'active'
          AND refresh_issuance_generation IS NULL
          AND consecutive_generation_failures = 32
          AND next_mint_not_before_ms <= $3
          AND failure_budget_rearm_at_ms <= $3
          AND state_updated_at_ms <= $3
        ",
    )
    .bind(descriptor.identity().tenant().as_str())
    .bind(descriptor.identity().authority_id().as_uuid())
    .bind(observed_at.get())
    .execute(&mut *connection)
    .await
    .map_err(operation_error)?;
    Ok(changed.rows_affected() == 1)
}

async fn maybe_finish_retirement(
    connection: &mut PgConnection,
    authority_id: GithubServerServiceAuthorityId,
    observed_at: UnixMillis,
) -> Result<(), GithubServerServiceStoreError> {
    sqlx::query(
        r"
        UPDATE github_server_service_authorities AS authority
        SET state = 'retired', retired_at_ms = $2, state_updated_at_ms = $2
        WHERE authority.id = $1 AND authority.state = 'retiring'
          AND authority.state_updated_at_ms <= $2
          AND NOT EXISTS (
              SELECT 1 FROM github_server_service_authority_issuances AS issuance
              WHERE issuance.authority_id = authority.id
                AND issuance.state NOT IN ('rejected', 'revoked')
          )
        ",
    )
    .bind(authority_id.as_uuid())
    .bind(observed_at.get())
    .execute(connection)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn load_authority_from_pool(
    pool: &sqlx::PgPool,
    tenant: &TenantScope,
    authority_id: GithubServerServiceAuthorityId,
) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError> {
    let query = format!(
        "SELECT {AUTHORITY_COLUMNS} FROM github_server_service_authorities WHERE tenant_id = $1 AND id = $2"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(tenant.as_str())
        .bind(authority_id.as_uuid())
        .fetch_optional(pool)
        .await
        .map_err(operation_error)?
        .ok_or(GithubServerServiceStoreError::NotFound)?;
    decode_authority(&row)
}

async fn select_authority_for_update(
    connection: &mut PgConnection,
    selector: &GithubServerServiceAuthoritySelector,
) -> Result<Option<PgRow>, GithubServerServiceStoreError> {
    let query = format!(
        "SELECT {AUTHORITY_COLUMNS} FROM github_server_service_authorities \
         WHERE tenant_id = $1 AND id = $2 AND identity_digest = $3 \
           AND app_configuration_revision = $4 AND policy_revision = $5 FOR UPDATE"
    );
    sqlx::query(AssertSqlSafe(query))
        .bind(selector.tenant().as_str())
        .bind(selector.authority_id().as_uuid())
        .bind(selector.identity_digest().as_bytes().as_slice())
        .bind(pg_bigint(selector.app_configuration_revision().get()))
        .bind(pg_bigint(selector.policy_revision().get()))
        .fetch_optional(connection)
        .await
        .map_err(operation_error)
}

async fn select_authority_by_tenant_id_for_update(
    connection: &mut PgConnection,
    tenant: &TenantScope,
    authority_id: GithubServerServiceAuthorityId,
) -> Result<Option<PgRow>, GithubServerServiceStoreError> {
    let query = format!(
        "SELECT {AUTHORITY_COLUMNS} FROM github_server_service_authorities \
         WHERE tenant_id = $1 AND id = $2 FOR UPDATE"
    );
    sqlx::query(AssertSqlSafe(query))
        .bind(tenant.as_str())
        .bind(authority_id.as_uuid())
        .fetch_optional(connection)
        .await
        .map_err(operation_error)
}

async fn select_issuance_for_update(
    connection: &mut PgConnection,
    key: GithubServerServiceIssuanceKey,
) -> Result<Option<PgRow>, GithubServerServiceStoreError> {
    let query = format!(
        "SELECT {ISSUANCE_COLUMNS} FROM github_server_service_authority_issuances WHERE authority_id = $1 AND generation = $2 FOR UPDATE"
    );
    sqlx::query(AssertSqlSafe(query))
        .bind(key.authority_id().as_uuid())
        .bind(pg_bigint(key.generation().get()))
        .fetch_optional(connection)
        .await
        .map_err(operation_error)
}

fn decode_authority(
    row: &PgRow,
) -> Result<GithubServerServiceAuthorityDescriptor, GithubServerServiceStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(string_column(row, "tenant_id")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let authority_id = GithubServerServiceAuthorityId::from_uuid(uuid_column(row, "id")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let repository_id = RepositoryId::from_uuid(uuid_column(row, "repository_id")?);
    let connection_id =
        ProviderConnectionId::from_uuid(uuid_column(row, "provider_connection_id")?)
            .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let installation_id =
        ProviderInstallationId::new(positive_u64(row, "provider_installation_id")?)
            .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let app_id = GithubServerServiceAppId::new(positive_u64(row, "github_app_id")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let app_client_id =
        GithubServerServiceAppClientId::new(string_column(row, "github_app_client_id")?)
            .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let jwt_issuer =
        decode_github_server_service_jwt_issuer(&string_column(row, "github_app_jwt_issuer_kind")?)
            .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let github_repository_id =
        ProviderRepositoryId::new(positive_u64(row, "github_repository_id")?)
            .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let github_repository_name =
        GithubRepositoryName::new(string_column(row, "github_repository_name")?)
            .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let scope = decode_github_server_service_scope(&string_column(row, "service_scope")?)
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    if digest_column(row, "policy_digest")? != scope.policy_digest() {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    let policy_revision = revision_column(row, "policy_revision")?;
    let app_key_spki_sha256 = digest_column(row, "app_key_spki_sha256")?;
    let app_configuration_revision = revision_column(row, "app_configuration_revision")?;
    let configuration_fingerprint = digest_column(row, "configuration_fingerprint")?;
    let identity = GithubServerServiceAuthorityIdentity::new(
        tenant,
        authority_id,
        repository_id,
        connection_id,
        installation_id,
        app_id,
        github_repository_id,
        github_repository_name,
        scope,
        app_client_id,
        jwt_issuer,
        app_key_spki_sha256,
        app_configuration_revision,
        policy_revision,
        configuration_fingerprint,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    if digest_column(row, "identity_digest")? != identity.identity_digest() {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    let state = decode_github_server_service_authority_state(&string_column(row, "state")?)
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    GithubServerServiceAuthorityDescriptor::from_durable_parts(
        identity,
        state,
        optional_generation(row, "current_issuance_generation")?,
        optional_generation(row, "refresh_issuance_generation")?,
        generation_column(row, "next_issuance_generation")?,
        u16_column(row, "consecutive_generation_failures")?,
        optional_timestamp(row, "next_mint_not_before_ms")?,
        optional_generation(row, "mint_gate_generation")?,
        optional_timestamp(row, "failure_budget_rearm_at_ms")?,
        timestamp_column(row, "created_at_ms")?,
        timestamp_column(row, "state_updated_at_ms")?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn decode_issuance_receipt(
    row: &PgRow,
) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
    let authority_id = GithubServerServiceAuthorityId::from_uuid(uuid_column(row, "authority_id")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let generation = generation_column(row, "generation")?;
    let key = GithubServerServiceIssuanceKey::new(authority_id, generation);
    let state = issuance_state(row)?;
    GithubServerServiceIssuanceReceipt::from_durable_parts(
        key,
        state,
        u16_column(row, "mint_attempt_count")?,
        u16_column(row, "revoke_attempt_count")?,
        timestamp_column(row, "requested_at_ms")?,
        timestamp_column(row, "request_deadline_at_ms")?,
        timestamp_column(row, "conservative_expiry_at_ms")?,
        optional_timestamp(row, "provider_expires_at_ms")?,
        timestamp_column(row, "safe_erase_after_ms")?,
        optional_timestamp(row, "ready_at_ms")?,
        timestamp_column(row, "state_updated_at_ms")?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn generation_failure_not_before(row: &PgRow) -> Result<i64, GithubServerServiceStoreError> {
    optional_i64(row, "generation_failure_gate_at_ms")?
        .ok_or(GithubServerServiceStoreError::CorruptData)
}

fn failure_budget_rearm_at(
    transition_at: UnixMillis,
) -> Result<i64, GithubServerServiceStoreError> {
    transition_at
        .get()
        .checked_add(GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS)
        .ok_or(GithubServerServiceStoreError::CorruptData)
}

fn decode_claimed_mint(
    identity: GithubServerServiceAuthorityIdentity,
    row: &PgRow,
) -> Result<ClaimedGithubServerServiceMint, GithubServerServiceStoreError> {
    let receipt = decode_issuance_receipt(row)?;
    let worker = GithubServerServiceWorkerId::from_uuid(
        optional_uuid(row, "mint_claim_owner_id")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let fence = GithubServerServiceClaimFence::new(positive_u64(row, "mint_claim_fence")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        receipt.key(),
        worker,
        fence,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    ClaimedGithubServerServiceMint::from_durable_parts(
        identity,
        receipt,
        claim,
        optional_timestamp(row, "mint_claimed_at_ms")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
        optional_timestamp(row, "mint_claim_expires_at_ms")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn decode_claimed_revocation(
    identity: GithubServerServiceAuthorityIdentity,
    row: &PgRow,
) -> Result<ClaimedGithubServerServiceRevocation, GithubServerServiceStoreError> {
    let receipt = decode_issuance_receipt(row)?;
    let worker = GithubServerServiceWorkerId::from_uuid(
        optional_uuid(row, "revoke_claim_owner_id")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let fence = GithubServerServiceClaimFence::new(positive_u64(row, "revoke_claim_fence")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        receipt.key(),
        worker,
        fence,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let protected = decode_protected(identity.clone(), row)?;
    ClaimedGithubServerServiceRevocation::from_durable_parts(
        claim,
        identity,
        receipt,
        optional_timestamp(row, "revoke_claimed_at_ms")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
        optional_timestamp(row, "revoke_claim_expires_at_ms")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
        protected,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

async fn decode_claimed_revocation_or_quarantine(
    connection: &mut PgConnection,
    identity: GithubServerServiceAuthorityIdentity,
    row: &PgRow,
    observed_at: UnixMillis,
) -> Result<Option<ClaimedGithubServerServiceRevocation>, GithubServerServiceStoreError> {
    match decode_claimed_revocation(identity.clone(), row) {
        Ok(claimed) => Ok(Some(claimed)),
        Err(GithubServerServiceStoreError::CorruptData) => {
            let key = GithubServerServiceIssuanceKey::new(
                identity.authority_id(),
                generation_column(row, "generation")?,
            );
            quarantine_retained_decode_corruption(connection, key, observed_at).await?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn decode_protected(
    identity: GithubServerServiceAuthorityIdentity,
    row: &PgRow,
) -> Result<ProtectedGithubServerServiceCredential, GithubServerServiceStoreError> {
    let generation = generation_column(row, "generation")?;
    let requested_at = timestamp_column(row, "requested_at_ms")?;
    let request_deadline = timestamp_column(row, "request_deadline_at_ms")?;
    let provider_expires_at = optional_timestamp(row, "provider_expires_at_ms")?;
    let plaintext_schema = optional_i16(row, "plaintext_schema")?
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let plaintext_size = optional_i64(row, "plaintext_size_bytes")?
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let plaintext_digest = optional_digest(row, "plaintext_digest")?
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let metadata = match provider_expires_at {
        Some(provider_expires_at) => GithubServerServiceEnvelopeMetadata::new(
            identity,
            generation,
            requested_at,
            request_deadline,
            provider_expires_at,
            plaintext_size,
            plaintext_digest,
        ),
        None => GithubServerServiceEnvelopeMetadata::unknown_provider_expiry(
            identity,
            generation,
            requested_at,
            request_deadline,
            plaintext_size,
            plaintext_digest,
        ),
    }
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    if metadata.plaintext_schema() != plaintext_schema
        || metadata.safe_erase_after() != timestamp_column(row, "safe_erase_after_ms")?
        || metadata.aad_digest()
            != optional_digest(row, "aad_digest")?
                .ok_or(GithubServerServiceStoreError::CorruptData)?
    {
        return Err(GithubServerServiceStoreError::CorruptData);
    }
    let envelope_schema = optional_i16(row, "envelope_schema")?
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let key_id = KeyId::new(
        optional_string(row, "wrapping_key_id")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let wrapped = WrappedDataKey::new(
        key_id,
        optional_bytes(row, "wrapped_data_key")?
            .ok_or(GithubServerServiceStoreError::CorruptData)?,
    )
    .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let nonce: [u8; 12] = optional_bytes(row, "nonce")?
        .ok_or(GithubServerServiceStoreError::CorruptData)?
        .try_into()
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let ciphertext =
        optional_bytes(row, "ciphertext")?.ok_or(GithubServerServiceStoreError::CorruptData)?;
    let envelope = EncryptedEnvelope::from_parts(envelope_schema, wrapped, nonce, ciphertext)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    ProtectedGithubServerServiceCredential::new(metadata, envelope)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn decode_consumer_claim(
    row: &PgRow,
) -> Result<GithubServerServiceConsumerClaim, GithubServerServiceStoreError> {
    let consumer_id = GithubServerServiceConsumerId::from_uuid(uuid_column(row, "consumer_id")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let owner = GithubServerServiceWorkerId::from_uuid(uuid_column(row, "consumer_owner_id")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let fence = GithubServerServiceClaimFence::new(positive_u64(row, "consumer_claim_fence")?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
    let action = decode_github_server_service_action(&string_column(row, "consumer_action")?)
        .ok_or(GithubServerServiceStoreError::CorruptData)?;
    let revision = revision_column(row, "consumer_revision")?;
    Ok(GithubServerServiceConsumerClaim::new(
        consumer_id,
        owner,
        fence,
        action,
        revision,
    ))
}

fn require_exact_begin_evidence(
    row: &PgRow,
    request: &BeginGithubServerServiceMint,
) -> Result<(), GithubServerServiceStoreError> {
    let claim = request.claim();
    if optional_uuid(row, "mint_started_owner_id")? != Some(claim.worker().as_uuid())
        || optional_i64(row, "mint_started_claim_fence")? != Some(pg_bigint(claim.fence().get()))
        || optional_i64(row, "mint_started_claimed_at_ms")? != Some(request.claimed_at().get())
        || optional_i64(row, "mint_started_claim_expires_at_ms")?
            != Some(request.claim_expires_at().get())
        || optional_i64(row, "mint_started_at_ms")? != Some(request.started_at().get())
        || i64_column(row, "request_deadline_at_ms")? != request.request_deadline().get()
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    Ok(())
}

fn exact_protected_replay(
    row: &PgRow,
    claim: &GithubServerServiceClaim,
    protected: &ProtectedGithubServerServiceCredential,
    committed_at: UnixMillis,
) -> Result<bool, GithubServerServiceStoreError> {
    Ok(exact_protected_evidence(row, claim, protected)?
        && i64_column(row, "state_updated_at_ms")? == committed_at.get())
}

fn exact_revoke_only_replay(
    row: &PgRow,
    claim: &GithubServerServiceClaim,
    protected: &ProtectedGithubServerServiceCredential,
    committed_at: UnixMillis,
) -> Result<bool, GithubServerServiceStoreError> {
    Ok(exact_protected_evidence(row, claim, protected)?
        && optional_i64(row, "mint_started_at_ms")?
            .is_some_and(|started_at| started_at <= committed_at.get())
        && committed_at.get() <= i64_column(row, "state_updated_at_ms")?)
}

fn exact_protected_evidence(
    row: &PgRow,
    claim: &GithubServerServiceClaim,
    protected: &ProtectedGithubServerServiceCredential,
) -> Result<bool, GithubServerServiceStoreError> {
    let metadata = protected.metadata();
    let envelope = protected.envelope();
    Ok(exact_mint_result_claim(row, claim)?
        && i64_column(row, "requested_at_ms")? == metadata.requested_at().get()
        && i64_column(row, "request_deadline_at_ms")? == metadata.request_deadline().get()
        && optional_i64(row, "provider_expires_at_ms")?
            == metadata.provider_expires_at().map(UnixMillis::get)
        && i64_column(row, "safe_erase_after_ms")? == metadata.safe_erase_after().get()
        && optional_i16(row, "plaintext_schema")?
            == Some(
                i16::try_from(metadata.plaintext_schema())
                    .map_err(|_| GithubServerServiceStoreError::CorruptData)?,
            )
        && optional_i64(row, "plaintext_size_bytes")?
            == Some(i64_from_u64(metadata.plaintext_size_bytes())?)
        && optional_digest(row, "plaintext_digest")? == Some(metadata.plaintext_digest())
        && optional_digest(row, "aad_digest")? == Some(metadata.aad_digest())
        && optional_i16(row, "envelope_schema")?
            == Some(
                i16::try_from(envelope.schema())
                    .map_err(|_| GithubServerServiceStoreError::CorruptData)?,
            )
        && optional_string(row, "wrapping_key_id")?.as_deref()
            == Some(envelope.wrapping_key_id().as_str())
        && optional_bytes(row, "wrapped_data_key")?.as_deref()
            == Some(envelope.wrapped_data_key().ciphertext())
        && optional_bytes(row, "nonce")?.as_deref() == Some(envelope.nonce().as_slice())
        && optional_bytes(row, "ciphertext")?.as_deref() == Some(envelope.ciphertext()))
}

fn exact_mint_result_claim(
    row: &PgRow,
    claim: &GithubServerServiceClaim,
) -> Result<bool, GithubServerServiceStoreError> {
    Ok(
        optional_uuid(row, "mint_started_owner_id")? == Some(claim.worker().as_uuid())
            && optional_i64(row, "mint_started_claim_fence")?
                == Some(pg_bigint(claim.fence().get())),
    )
}

fn require_live_mint_claim(
    row: &PgRow,
    claim: &GithubServerServiceClaim,
    caller_event_at: UnixMillis,
    database_now: i64,
) -> Result<(), GithubServerServiceStoreError> {
    if issuance_state(row)? != GithubServerServiceIssuanceState::Minting
        || optional_uuid(row, "mint_claim_owner_id")? != Some(claim.worker().as_uuid())
        || positive_u64(row, "mint_claim_fence")? != claim.fence().get()
        || optional_i64(row, "mint_claim_expires_at_ms")?
            .is_none_or(|expiry| expiry <= database_now)
        || optional_i64(row, "mint_claimed_at_ms")?
            .is_none_or(|claimed| claimed > database_now || claimed > caller_event_at.get())
        || i64_column(row, "request_deadline_at_ms")? <= database_now
        || i64_column(row, "request_deadline_at_ms")? <= caller_event_at.get()
        || optional_i64(row, "mint_claim_expires_at_ms")?
            .is_none_or(|expiry| expiry <= caller_event_at.get())
        || optional_i64(row, "mint_started_at_ms")?
            .is_none_or(|started| started > caller_event_at.get())
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    Ok(())
}

fn require_live_revoke_claim(
    row: &PgRow,
    claim: &GithubServerServiceClaim,
    caller_event_at: UnixMillis,
    database_now: i64,
) -> Result<(), GithubServerServiceStoreError> {
    if issuance_state(row)? != GithubServerServiceIssuanceState::RevokeClaimed
        || optional_uuid(row, "revoke_claim_owner_id")? != Some(claim.worker().as_uuid())
        || positive_u64(row, "revoke_claim_fence")? != claim.fence().get()
        || optional_i64(row, "revoke_claim_expires_at_ms")?
            .is_none_or(|expiry| expiry <= database_now || expiry <= caller_event_at.get())
        || optional_i64(row, "revoke_claimed_at_ms")?
            .is_none_or(|claimed| claimed > database_now || claimed > caller_event_at.get())
    {
        return Err(GithubServerServiceStoreError::ClaimRejected);
    }
    Ok(())
}

fn issuance_state(
    row: &PgRow,
) -> Result<GithubServerServiceIssuanceState, GithubServerServiceStoreError> {
    decode_github_server_service_issuance_state(&string_column(row, "state")?)
        .ok_or(GithubServerServiceStoreError::CorruptData)
}

fn decode_github_server_service_jwt_issuer(value: &str) -> Option<GithubServerServiceJwtIssuer> {
    match value {
        "app_client_id" => Some(GithubServerServiceJwtIssuer::AppClientId),
        "app_id" => Some(GithubServerServiceJwtIssuer::AppId),
        _ => None,
    }
}

fn decode_github_server_service_scope(value: &str) -> Option<GithubServerServiceScope> {
    match value {
        "checks_write" => Some(GithubServerServiceScope::ChecksWrite),
        "private_repository_source_read" => {
            Some(GithubServerServiceScope::PrivateRepositorySourceRead)
        }
        "workflow_permissions_read" => Some(GithubServerServiceScope::WorkflowPermissionsRead),
        "private_pull_request_files_read" => {
            Some(GithubServerServiceScope::PrivatePullRequestFilesRead)
        }
        _ => None,
    }
}

fn decode_github_server_service_authority_state(
    value: &str,
) -> Option<GithubServerServiceAuthorityState> {
    match value {
        "active" => Some(GithubServerServiceAuthorityState::Active),
        "retiring" => Some(GithubServerServiceAuthorityState::Retiring),
        "retired" => Some(GithubServerServiceAuthorityState::Retired),
        _ => None,
    }
}

fn decode_github_server_service_action(value: &str) -> Option<GithubServerServiceAction> {
    match value {
        "ensure_check_suite" => Some(GithubServerServiceAction::EnsureCheckSuite),
        "create_check_run" => Some(GithubServerServiceAction::CreateCheckRun),
        "reconcile_check_run" => Some(GithubServerServiceAction::ReconcileCheckRun),
        "publish_check_run" => Some(GithubServerServiceAction::PublishCheckRun),
        "fetch_private_repository_revision" => {
            Some(GithubServerServiceAction::FetchPrivateRepositoryRevision)
        }
        "fetch_private_repository_changed_files" => {
            Some(GithubServerServiceAction::FetchPrivateRepositoryChangedFiles)
        }
        "fetch_private_pull_request_files" => {
            Some(GithubServerServiceAction::FetchPrivatePullRequestFiles)
        }
        "discover_private_repository_schedules" => {
            Some(GithubServerServiceAction::DiscoverPrivateRepositorySchedules)
        }
        "observe_workflow_permission_defaults" => {
            Some(GithubServerServiceAction::ObserveWorkflowPermissionDefaults)
        }
        _ => None,
    }
}

const fn github_server_service_issuance_state_name(
    state: GithubServerServiceIssuanceState,
) -> &'static str {
    match state {
        GithubServerServiceIssuanceState::Claimed => "claimed",
        GithubServerServiceIssuanceState::Minting => "minting",
        GithubServerServiceIssuanceState::MintRetryPending => "mint_retry",
        GithubServerServiceIssuanceState::Indeterminate => "indeterminate",
        GithubServerServiceIssuanceState::Ready => "ready",
        GithubServerServiceIssuanceState::RevokePending => "revoke_pending",
        GithubServerServiceIssuanceState::RevokeClaimed => "revoke_claimed",
        GithubServerServiceIssuanceState::RevokeRetryPending => "revoke_retry",
        GithubServerServiceIssuanceState::Quarantined => "quarantined",
        GithubServerServiceIssuanceState::Rejected => "rejected",
        GithubServerServiceIssuanceState::Revoked => "revoked",
    }
}

fn decode_github_server_service_issuance_state(
    value: &str,
) -> Option<GithubServerServiceIssuanceState> {
    match value {
        "claimed" => Some(GithubServerServiceIssuanceState::Claimed),
        "minting" => Some(GithubServerServiceIssuanceState::Minting),
        "mint_retry" => Some(GithubServerServiceIssuanceState::MintRetryPending),
        "indeterminate" => Some(GithubServerServiceIssuanceState::Indeterminate),
        "ready" => Some(GithubServerServiceIssuanceState::Ready),
        "revoke_pending" => Some(GithubServerServiceIssuanceState::RevokePending),
        "revoke_claimed" => Some(GithubServerServiceIssuanceState::RevokeClaimed),
        "revoke_retry" => Some(GithubServerServiceIssuanceState::RevokeRetryPending),
        "quarantined" => Some(GithubServerServiceIssuanceState::Quarantined),
        "rejected" => Some(GithubServerServiceIssuanceState::Rejected),
        "revoked" => Some(GithubServerServiceIssuanceState::Revoked),
        _ => None,
    }
}

fn generation_column(
    row: &PgRow,
    column: &str,
) -> Result<GithubServerServiceGeneration, GithubServerServiceStoreError> {
    GithubServerServiceGeneration::new(positive_u64(row, column)?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn optional_generation(
    row: &PgRow,
    column: &str,
) -> Result<Option<GithubServerServiceGeneration>, GithubServerServiceStoreError> {
    optional_i64(row, column)?
        .map(|value| {
            u64::try_from(value)
                .ok()
                .and_then(|value| GithubServerServiceGeneration::new(value).ok())
                .ok_or(GithubServerServiceStoreError::CorruptData)
        })
        .transpose()
}

fn revision_column(
    row: &PgRow,
    column: &str,
) -> Result<GithubServerServiceRevision, GithubServerServiceStoreError> {
    GithubServerServiceRevision::new(positive_u64(row, column)?)
        .map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn timestamp_column(
    row: &PgRow,
    column: &str,
) -> Result<UnixMillis, GithubServerServiceStoreError> {
    let value = i64_column(row, column)?;
    if value < 0 {
        Err(GithubServerServiceStoreError::CorruptData)
    } else {
        Ok(UnixMillis::new(value))
    }
}

fn optional_timestamp(
    row: &PgRow,
    column: &str,
) -> Result<Option<UnixMillis>, GithubServerServiceStoreError> {
    optional_i64(row, column)?
        .map(|value| {
            if value < 0 {
                Err(GithubServerServiceStoreError::CorruptData)
            } else {
                Ok(UnixMillis::new(value))
            }
        })
        .transpose()
}

fn positive_u64(row: &PgRow, column: &str) -> Result<u64, GithubServerServiceStoreError> {
    let value = i64_column(row, column)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubServerServiceStoreError::CorruptData)
}

fn nonnegative_u64(row: &PgRow, column: &str) -> Result<u64, GithubServerServiceStoreError> {
    u64::try_from(i64_column(row, column)?).map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn u16_column(row: &PgRow, column: &str) -> Result<u16, GithubServerServiceStoreError> {
    let value: i16 = row.try_get(column).map_err(operation_error)?;
    u16::try_from(value).map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn i64_column(row: &PgRow, column: &str) -> Result<i64, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn optional_i64(row: &PgRow, column: &str) -> Result<Option<i64>, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn optional_i16(row: &PgRow, column: &str) -> Result<Option<i16>, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn uuid_column(row: &PgRow, column: &str) -> Result<Uuid, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn optional_uuid(row: &PgRow, column: &str) -> Result<Option<Uuid>, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn string_column(row: &PgRow, column: &str) -> Result<String, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn optional_string(
    row: &PgRow,
    column: &str,
) -> Result<Option<String>, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn optional_bytes(
    row: &PgRow,
    column: &str,
) -> Result<Option<Vec<u8>>, GithubServerServiceStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn digest_column(row: &PgRow, column: &str) -> Result<Sha256Digest, GithubServerServiceStoreError> {
    optional_digest(row, column)?.ok_or(GithubServerServiceStoreError::CorruptData)
}

fn optional_digest(
    row: &PgRow,
    column: &str,
) -> Result<Option<Sha256Digest>, GithubServerServiceStoreError> {
    optional_bytes(row, column)?
        .map(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| GithubServerServiceStoreError::CorruptData)?;
            Ok(Sha256Digest::from_bytes(bytes))
        })
        .transpose()
}

fn i64_from_u64(value: u64) -> Result<i64, GithubServerServiceStoreError> {
    i64::try_from(value).map_err(|_| GithubServerServiceStoreError::CorruptData)
}

fn operation_error(error: sqlx::Error) -> GithubServerServiceStoreError {
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    match constraint {
        Some(
            "github_server_service_handoffs_authority_exact"
            | "github_server_service_handoffs_checks_claim_exact"
            | "github_server_service_handoffs_source_claim_exact"
            | "github_server_service_handoffs_scope_exact"
            | "github_server_service_handoffs_immutable",
        ) => GithubServerServiceStoreError::HandoffRejected,
        Some("github_server_service_issuances_handoff_live") => {
            GithubServerServiceStoreError::HandoffStillLive
        }
        _ => GithubServerServiceStoreError::operation(error),
    }
}
