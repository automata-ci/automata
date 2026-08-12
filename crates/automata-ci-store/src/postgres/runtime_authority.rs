use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
    UnixMillis,
};
use automata_ci_key_management::{ENVELOPE_NONCE_BYTES, EncryptedEnvelope, KeyId, WrappedDataKey};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use crate::{
    AuthenticateGithubRuntimeAuthorityUnprotectedErasure, BeginGithubRuntimeAuthorityMint,
    BeginGithubRuntimeAuthorityMintOutcome, ClaimGithubRuntimeAuthorityMint,
    ClaimGithubRuntimeAuthorityRevocation, ClaimedGithubRuntimeAuthorityMint,
    ClaimedGithubRuntimeAuthorityRevocation, CommitGithubRuntimeAuthority,
    ConfirmGithubRuntimeAuthorityRevocation, DeferGithubRuntimeAuthorityRevocation,
    GithubRepositoryId, GithubRepositoryName, GithubRuntimeAuthorityActivationSelectionTail,
    GithubRuntimeAuthorityClaimFence, GithubRuntimeAuthorityCommitDisposition,
    GithubRuntimeAuthorityCorruptionKind, GithubRuntimeAuthorityEnvelopeMetadata,
    GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityInspection, GithubRuntimeAuthorityKey,
    GithubRuntimeAuthorityMaterializationSelectionTail, GithubRuntimeAuthorityNamespace,
    GithubRuntimeAuthorityPreparationSelectionTail, GithubRuntimeAuthorityReceipt,
    GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityRepository,
    GithubRuntimeAuthorityState, GithubRuntimeAuthorityStoreError,
    GithubRuntimeAuthorityTerminalReason, GithubRuntimeAuthorityWorkerId,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceJwtIssuer,
    InspectGithubRuntimeAuthority, LoadGithubRuntimeAuthority, LogicalActivationGeneration,
    LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS, MarkGithubRuntimeAuthorityIndeterminate,
    ProtectedGithubRuntimeAuthority, ProviderConnectionId, ProviderInstallationId,
    QuarantineGithubRuntimeAuthority, ReadyGithubRuntimeAuthority,
    ReconcileGithubRuntimeAuthorities, RejectGithubRuntimeAuthorityMint, RepositoryId,
    RetryGithubRuntimeAuthorityMint, RetryGithubRuntimeAuthorityRevocation,
    RevalidateGithubRuntimeAuthorityRevocation, RevalidatedGithubRuntimeAuthorityRevocation,
    RunnerGeneration, SessionEpoch, Sha256Digest, StableRunnerSlot, TenantScope,
};

use super::PostgresStore;

const MINT_COMMIT_OPERATION: &str = "mint_commit";
const QUARANTINE_OPERATION: &str = "quarantine";
const REVOCATION_OUTCOME_OPERATION: &str = "revocation_outcome";

const MINT_COMMIT_DIGEST_DOMAIN: &[u8] =
    b"automata.store.github-runtime-authority-operation.mint-commit.v4\0";
const QUARANTINE_DIGEST_DOMAIN: &[u8] =
    b"automata.store.github-runtime-authority-operation.quarantine.v4\0";
const REVOCATION_OUTCOME_DIGEST_DOMAIN: &[u8] =
    b"automata.store.github-runtime-authority-operation.revocation-outcome.v4\0";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"automata.store.github-runtime-authority-envelope.v1\0";

pub(super) fn github_manifest_origin_is_closed(origin_kind: &str) -> bool {
    matches!(
        origin_kind,
        "provider_delivery" | "scheduled_fire" | "workflow_rerun"
    )
}

#[async_trait]
#[allow(clippy::too_many_lines)] // The closed repository protocol is one atomic SQL adapter.
impl GithubRuntimeAuthorityRepository for PostgresStore {
    async fn inspect_github_runtime_authority(
        &self,
        request: InspectGithubRuntimeAuthority,
    ) -> Result<Option<GithubRuntimeAuthorityInspection>, GithubRuntimeAuthorityStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let Some(row) = load_row_for_update(&mut transaction, request.identity().key()).await?
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        };
        if decode_identity(&row)? != *request.identity() {
            return Err(GithubRuntimeAuthorityStoreError::IdentityConflict);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let inspection = decode_inspection(&row, database_now)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(Some(inspection))
    }

    #[allow(clippy::too_many_lines)]
    async fn claim_github_runtime_authority_mint(
        &self,
        request: ClaimGithubRuntimeAuthorityMint,
    ) -> Result<Option<ClaimedGithubRuntimeAuthorityMint>, GithubRuntimeAuthorityStoreError> {
        let identity = request.identity();
        let claim_duration = request.expires_at().get() - request.observed_at().get();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let mut durable = load_row_for_update(&mut transaction, identity.key()).await?;
        if durable.is_none() && !lock_exact_authority_attempt(&mut transaction, identity).await? {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let Some(claim_expires_at) =
            bounded_future_timestamp(database_now, claim_duration, identity.request_deadline())
        else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        };

        if durable.is_none() {
            let inserted = sqlx::query(
                r"
            INSERT INTO github_runtime_authority_issuances (
                tenant_id, attempt_id, fencing_token, lease_id,
                lease_issued_at_ms, lease_expires_at_ms, run_id, job_id,
                runner_id, runner_session_id, runner_session_epoch,
                runner_generation, runner_slot, job_ir_schema,
                job_ir_size_bytes, job_ir_digest, repository_id,
                provider_connection_id, provider_installation_id,
                github_app_id, github_app_client_id,
                github_app_jwt_issuer_kind, github_app_jwt_issuer_value,
                github_repository_id, github_repository_name,
                authority_namespace, policy_digest, issuer_fingerprint,
                configuration_fingerprint,
                preparation_selection_id, preparation_selection_owner_id,
                preparation_selection_generation,
                preparation_selection_descriptor_digest,
                preparation_selection_claimed_at_ms,
                preparation_selection_expires_at_ms,
                activation_selection_id, activation_selection_owner_id,
                activation_selection_generation, activation_selection_input_digest,
                activation_selection_claimed_at_ms,
                activation_selection_expires_at_ms,
                materialization_selection_id, materialization_selection_owner_id,
                materialization_selection_generation,
                materialization_selection_descriptor_digest,
                materialization_selection_claimed_at_ms,
                materialization_selection_expires_at_ms,
                requested_at_ms,
                request_deadline_at_ms, conservative_expiry_at_ms,
                mint_claim_owner_id, mint_claimed_at_ms,
                mint_claim_expires_at_ms, state_updated_at_ms
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
                $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
                $41, $42, $43, $44, $45, $46, $47, $48, $49, $50,
                $51, $52, $53, $52
            )
            ON CONFLICT (attempt_id, fencing_token) DO NOTHING
            RETURNING *
            ",
            )
            .bind(identity.tenant().as_str())
            .bind(identity.key().attempt_id().as_uuid())
            .bind(fencing_i64(identity.key().fencing_token()))
            .bind(identity.lease_id().as_uuid())
            .bind(identity.lease_issued_at().get())
            .bind(identity.lease_expires_at().get())
            .bind(identity.run_id().as_uuid())
            .bind(identity.job_id().as_uuid())
            .bind(identity.runner_id().as_uuid())
            .bind(identity.runner_session_id().as_uuid())
            .bind(positive_i64(identity.runner_session_epoch().get())?)
            .bind(positive_i64(identity.runner_generation().get())?)
            .bind(i32::from(identity.runner_slot().get()))
            .bind(i32::from(identity.job_ir_version().get()))
            .bind(positive_i64(identity.job_ir_size_bytes())?)
            .bind(identity.job_ir_digest().as_bytes().as_slice())
            .bind(identity.repository_id().as_uuid())
            .bind(identity.provider_connection_id().as_uuid())
            .bind(identity.provider_installation_id().as_i64())
            .bind(identity.github_app_id().as_i64())
            .bind(identity.github_app_client_id().as_str())
            .bind(identity.github_app_jwt_issuer_kind().as_str())
            .bind(identity.github_app_jwt_issuer_value())
            .bind(identity.github_repository_id().as_i64())
            .bind(identity.github_repository_name().as_str())
            .bind(identity.namespace().as_str())
            .bind(identity.policy_digest().as_bytes().as_slice())
            .bind(identity.app_key_spki_sha256().as_bytes().as_slice())
            .bind(identity.configuration_fingerprint().as_bytes().as_slice())
            .bind(
                identity
                    .preparation_selection_tail()
                    .selection_id()
                    .as_uuid(),
            )
            .bind(identity.preparation_selection_tail().owner().as_uuid())
            .bind(positive_i64(
                identity.preparation_selection_tail().generation().get(),
            )?)
            .bind(
                identity
                    .preparation_selection_tail()
                    .descriptor_digest()
                    .as_bytes()
                    .as_slice(),
            )
            .bind(identity.preparation_selection_tail().claimed_at().get())
            .bind(identity.preparation_selection_tail().expires_at().get())
            .bind(
                identity
                    .activation_selection_tail()
                    .selection_id()
                    .as_uuid(),
            )
            .bind(identity.activation_selection_tail().owner().as_uuid())
            .bind(positive_i64(
                identity.activation_selection_tail().generation().get(),
            )?)
            .bind(
                identity
                    .activation_selection_tail()
                    .activation_input_digest()
                    .as_bytes()
                    .as_slice(),
            )
            .bind(identity.activation_selection_tail().claimed_at().get())
            .bind(identity.activation_selection_tail().expires_at().get())
            .bind(
                identity
                    .materialization_selection_tail()
                    .selection_id()
                    .as_uuid(),
            )
            .bind(identity.materialization_selection_tail().owner().as_uuid())
            .bind(positive_i64(
                identity.materialization_selection_tail().generation().get(),
            )?)
            .bind(
                identity
                    .materialization_selection_tail()
                    .descriptor_digest()
                    .as_bytes()
                    .as_slice(),
            )
            .bind(identity.materialization_selection_tail().claimed_at().get())
            .bind(identity.materialization_selection_tail().expires_at().get())
            .bind(identity.requested_at().get())
            .bind(identity.request_deadline().get())
            .bind(identity.conservative_expiry().get())
            .bind(request.owner().as_uuid())
            .bind(database_now.get())
            .bind(claim_expires_at.get())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?;
            if let Some(row) = inserted {
                let claim = decode_mint_claim(&row)?;
                record_current_mint_claim(&mut transaction, identity.key()).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(Some(claim));
            }
            durable = load_row_for_update(&mut transaction, identity.key()).await?;
        }

        let Some(row) = durable else {
            return Err(GithubRuntimeAuthorityStoreError::CorruptData);
        };
        let durable_identity = decode_identity(&row)?;
        if durable_identity != *identity {
            return Err(GithubRuntimeAuthorityStoreError::IdentityConflict);
        }
        let state = decode_state(&row)?;
        if state == GithubRuntimeAuthorityState::MintRetryPending {
            let next_mint_at = timestamp_column(&row, "next_mint_at_ms")?;
            if database_now < next_mint_at {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(None);
            }
            let (attempt, fence) = decode_mint_history(&row)?;
            if attempt == MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS {
                return Err(GithubRuntimeAuthorityStoreError::RetryLimitReached);
            }
            if fence.get() == i64::MAX as u64 {
                return Err(GithubRuntimeAuthorityStoreError::FenceExhausted);
            }
            let row = sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'claimed',
                    mint_attempt_count = authority.mint_attempt_count + 1,
                    mint_claim_fence = authority.mint_claim_fence + 1,
                    mint_claim_owner_id = $3,
                mint_claimed_at_ms = $4,
                mint_claim_expires_at_ms = $5,
                mint_provider_request_millis = NULL,
                mint_started_at_ms = NULL,
                    next_mint_at_ms = NULL,
                    state_updated_at_ms = $4
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'mint_retry_pending'
                  AND authority.next_mint_at_ms <= $4
                  AND authority.mint_attempt_count < 32
                  AND authority.mint_claim_fence < 9223372036854775807
                  AND automata_github_runtime_authority_is_current(authority, $4)
                RETURNING authority.*
                ",
            )
            .bind(identity.key().attempt_id().as_uuid())
            .bind(fencing_i64(identity.key().fencing_token()))
            .bind(request.owner().as_uuid())
            .bind(database_now.get())
            .bind(claim_expires_at.get())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?;
            let claim = row.as_ref().map(decode_mint_claim).transpose()?;
            if claim.is_some() {
                record_current_mint_claim(&mut transaction, identity.key()).await?;
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(claim);
        }
        if state != GithubRuntimeAuthorityState::Claimed {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let existing = decode_mint_claim(&row)?;
        if existing.owner() == request.owner() && database_now < existing.expires_at() {
            record_current_mint_claim(&mut transaction, identity.key()).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(Some(existing));
        }
        if database_now < existing.expires_at() {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        if existing.attempt() == MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS {
            return Err(GithubRuntimeAuthorityStoreError::RetryLimitReached);
        }
        if existing.fence().get() == i64::MAX as u64 {
            return Err(GithubRuntimeAuthorityStoreError::FenceExhausted);
        }

        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET mint_attempt_count = authority.mint_attempt_count + 1,
                mint_claim_fence = authority.mint_claim_fence + 1,
                mint_claim_owner_id = $3,
                mint_claimed_at_ms = $4,
                mint_claim_expires_at_ms = $5,
                state_updated_at_ms = $4
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'claimed'
              AND authority.mint_claim_expires_at_ms <= $4
              AND authority.mint_attempt_count < 32
              AND authority.mint_claim_fence < 9223372036854775807
              AND automata_github_runtime_authority_is_current(authority, $4)
            RETURNING authority.*
            ",
        )
        .bind(identity.key().attempt_id().as_uuid())
        .bind(fencing_i64(identity.key().fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(database_now.get())
        .bind(claim_expires_at.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let claim = row.as_ref().map(decode_mint_claim).transpose()?;
        if claim.is_some() {
            record_current_mint_claim(&mut transaction, identity.key()).await?;
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(claim)
    }

    async fn begin_github_runtime_authority_mint(
        &self,
        request: BeginGithubRuntimeAuthorityMint,
    ) -> Result<BeginGithubRuntimeAuthorityMintOutcome, GithubRuntimeAuthorityStoreError> {
        let claim = request.claim();
        let key = claim.identity().key();
        let _caller_observed_at = request.observed_at();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        let state = decode_state(&durable)?;
        let mint_started_at = optional_timestamp_column(&durable, "mint_started_at_ms")?;
        if decode_identity(&durable)? != *claim.identity()
            || worker_column(&durable, "mint_claim_owner_id")? != claim.owner()
            || claim_fence_column(&durable, "mint_claim_fence")? != claim.fence()
        {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        if state != GithubRuntimeAuthorityState::Claimed {
            if mint_started_at.is_none()
                || !lock_exact_mint_begin(
                    &mut transaction,
                    claim,
                    request.provider_request_millis(),
                )
                .await?
            {
                return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
            }
            let receipt = decode_receipt(&durable)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BeginGithubRuntimeAuthorityMintOutcome::AlreadyStarted(
                receipt,
            ));
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = 'minting',
                mint_claim_expires_at_ms = NULL,
                mint_started_at_ms = $5,
                mint_provider_request_millis = $6,
                state_updated_at_ms = $5
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'claimed'
              AND authority.mint_claim_owner_id = $3
              AND authority.mint_claim_fence = $4
              AND authority.mint_claimed_at_ms <= $5
              AND authority.mint_claim_expires_at_ms > $5
              AND $5::NUMERIC + $6::NUMERIC
                    <= authority.mint_claim_expires_at_ms::NUMERIC
              AND $5::NUMERIC + $6::NUMERIC
                    <= authority.request_deadline_at_ms::NUMERIC
              AND automata_github_runtime_authority_is_current(authority, $5)
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(claim.owner().as_uuid())
        .bind(claim.fence().as_i64())
        .bind(database_now.get())
        .bind(request.provider_request_millis())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        if !lock_exact_mint_begin(&mut transaction, claim, request.provider_request_millis())
            .await?
        {
            return Err(GithubRuntimeAuthorityStoreError::CorruptData);
        }
        let receipt = decode_receipt(&row)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(BeginGithubRuntimeAuthorityMintOutcome::Started(receipt))
    }

    async fn authenticate_github_runtime_authority_unprotected_erasure(
        &self,
        request: AuthenticateGithubRuntimeAuthorityUnprotectedErasure,
    ) -> Result<Option<GithubRuntimeAuthorityReceipt>, GithubRuntimeAuthorityStoreError> {
        let claim = request.claim();
        let identity = claim.identity();
        let key = identity.key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        if decode_identity(&durable)? != *identity
            || !lock_exact_mint_claim(&mut transaction, claim).await?
            || worker_column(&durable, "mint_claim_owner_id")? != claim.owner()
            || claim_fence_column(&durable, "mint_claim_fence")? != claim.fence()
            || timestamp_column(&durable, "mint_claimed_at_ms")? != claim.claimed_at()
            || optional_timestamp_column(&durable, "mint_started_at_ms")?.is_none()
        {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }

        let database_now = database_now_ms(&mut transaction).await?;
        match decode_state(&durable)? {
            GithubRuntimeAuthorityState::Minting | GithubRuntimeAuthorityState::Indeterminate => {
                if database_now < identity.conservative_expiry() {
                    transaction.commit().await.map_err(operation_error)?;
                    return Ok(None);
                }
                let row = sqlx::query(
                    r"
                    UPDATE github_runtime_authority_issuances AS authority
                    SET state = 'revoked',
                        envelope_schema = NULL,
                        wrapping_key_id = NULL,
                        wrapped_data_key = NULL,
                        nonce = NULL,
                        ciphertext = NULL,
                        mint_claim_expires_at_ms = NULL,
                        revoked_at_ms = $5,
                        terminal_reason = 'indeterminate_authority_expired',
                        state_updated_at_ms = $5
                    WHERE authority.attempt_id = $1
                      AND authority.fencing_token = $2
                      AND authority.state IN ('minting', 'indeterminate')
                      AND authority.mint_claim_owner_id = $3
                      AND authority.mint_claim_fence = $4
                      AND authority.mint_started_at_ms IS NOT NULL
                      AND authority.conservative_expiry_at_ms <= $5
                    RETURNING authority.*
                    ",
                )
                .bind(key.attempt_id().as_uuid())
                .bind(fencing_i64(key.fencing_token()))
                .bind(claim.owner().as_uuid())
                .bind(claim.fence().as_i64())
                .bind(database_now.get())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(operation_error)?
                .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
                let receipt = decode_receipt(&row)?;
                transaction.commit().await.map_err(operation_error)?;
                Ok(Some(receipt))
            }
            GithubRuntimeAuthorityState::Revoked
                if terminal_reason(&durable)?
                    == Some(
                        GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired,
                    )
                    && database_now >= identity.conservative_expiry() =>
            {
                let receipt = decode_receipt(&durable)?;
                transaction.commit().await.map_err(operation_error)?;
                Ok(Some(receipt))
            }
            _ => Err(GithubRuntimeAuthorityStoreError::MintClaimRejected),
        }
    }

    async fn mark_github_runtime_authority_indeterminate(
        &self,
        request: MarkGithubRuntimeAuthorityIndeterminate,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        if worker_column(&durable, "mint_claim_owner_id")? != request.owner()
            || claim_fence_column(&durable, "mint_claim_fence")? != request.fence()
        {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        if decode_state(&durable)? != GithubRuntimeAuthorityState::Minting {
            let receipt = decode_receipt(&durable)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = 'indeterminate',
                indeterminate_at_ms = $5,
                state_updated_at_ms = $5
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'minting'
              AND authority.mint_claim_owner_id = $3
              AND authority.mint_claim_fence = $4
              AND authority.mint_started_at_ms IS NOT NULL
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(request.fence().as_i64())
        .bind(database_now.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn retry_github_runtime_authority_mint(
        &self,
        request: RetryGithubRuntimeAuthorityMint,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let retry_delay = request.retry_at().get() - request.observed_at().get();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        if worker_column(&durable, "mint_claim_owner_id")? != request.owner()
            || claim_fence_column(&durable, "mint_claim_fence")? != request.fence()
        {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        if decode_state(&durable)? != GithubRuntimeAuthorityState::Minting {
            let durable_failure: Option<String> = durable
                .try_get("last_mint_rejection_kind")
                .map_err(operation_error)?;
            if durable_failure.as_deref() != Some(request.failure().as_str()) {
                return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
            }
            let receipt = decode_receipt(&durable)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let database_retry_at = database_now.get().saturating_add(retry_delay);
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = CASE
                    WHEN authority.mint_attempt_count < 32
                     AND $6 < authority.request_deadline_at_ms
                     AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN 'mint_retry_pending'
                    ELSE 'rejected'
                END,
                mint_claim_expires_at_ms = NULL,
                next_mint_at_ms = CASE
                    WHEN authority.mint_attempt_count < 32
                     AND $6 < authority.request_deadline_at_ms
                     AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN $6 ELSE NULL
                END,
                last_mint_rejection_kind = $7,
                rejected_at_ms = CASE
                    WHEN authority.mint_attempt_count < 32
                     AND $6 < authority.request_deadline_at_ms
                     AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN NULL ELSE $5
                END,
                terminal_reason = CASE
                    WHEN authority.mint_attempt_count < 32
                     AND $6 < authority.request_deadline_at_ms
                     AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN NULL ELSE 'provider_mint_retry_expired'
                END,
                state_updated_at_ms = $5
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'minting'
              AND authority.mint_claim_owner_id = $3
              AND authority.mint_claim_fence = $4
              AND authority.mint_started_at_ms IS NOT NULL
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(request.fence().as_i64())
        .bind(database_now.get())
        .bind(database_retry_at)
        .bind(request.failure().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn reject_github_runtime_authority_mint(
        &self,
        request: RejectGithubRuntimeAuthorityMint,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        if worker_column(&durable, "mint_claim_owner_id")? != request.owner()
            || claim_fence_column(&durable, "mint_claim_fence")? != request.fence()
        {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        if decode_state(&durable)? != GithubRuntimeAuthorityState::Minting {
            let durable_failure: Option<String> = durable
                .try_get("last_mint_rejection_kind")
                .map_err(operation_error)?;
            if decode_state(&durable)? != GithubRuntimeAuthorityState::Rejected
                || terminal_reason(&durable)?
                    != Some(GithubRuntimeAuthorityTerminalReason::ProviderMintRejected)
                || durable_failure.as_deref() != Some(request.failure().as_str())
            {
                return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
            }
            let receipt = decode_receipt(&durable)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = 'rejected',
                mint_claim_expires_at_ms = NULL,
                next_mint_at_ms = NULL,
                last_mint_rejection_kind = $6,
                rejected_at_ms = $5,
                terminal_reason = 'provider_mint_rejected',
                state_updated_at_ms = $5
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'minting'
              AND authority.mint_claim_owner_id = $3
              AND authority.mint_claim_fence = $4
              AND authority.mint_started_at_ms IS NOT NULL
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(request.fence().as_i64())
        .bind(database_now.get())
        .bind(request.failure().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_lines)]
    async fn commit_github_runtime_authority(
        &self,
        request: &CommitGithubRuntimeAuthority,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let owner = request.owner();
        let fence = request.fence();
        let disposition = request.disposition();
        let metadata = request.protected().metadata();
        let envelope = request.protected().envelope();
        let identity = metadata.identity();
        let key = identity.key();
        let operation_digest = mint_commit_operation_digest(request);

        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if !lock_exact_mint_claim(&mut transaction, request.claim()).await? {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        match operation_receipt_matches(
            &mut transaction,
            key,
            MINT_COMMIT_OPERATION,
            fence.as_i64(),
            operation_digest,
            Some(owner.as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::IdentityConflict);
            }
            None => {}
        }
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        if decode_identity(&durable)? != *identity {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        match operation_receipt_matches(
            &mut transaction,
            key,
            MINT_COMMIT_OPERATION,
            fence.as_i64(),
            operation_digest,
            Some(owner.as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::IdentityConflict);
            }
            None => {}
        }
        if worker_column(&durable, "mint_claim_owner_id")? != owner
            || claim_fence_column(&durable, "mint_claim_fence")? != fence
        {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        let durable_state = decode_state(&durable)?;
        if durable_state == GithubRuntimeAuthorityState::Revoked
            && optional_timestamp_column(&durable, "mint_started_at_ms")?.is_some()
        {
            let row = sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET operation_request_kind = 'mint_commit',
                    operation_request_claim_fence = $3,
                    operation_request_claim_owner_id = $4,
                    operation_request_observed_at_ms = $5,
                    operation_request_retry_at_ms = NULL,
                    operation_request_failure_kind = NULL,
                    operation_request_commit_disposition = $6,
                    operation_request_provider_expires_at_ms = $7,
                    operation_request_safe_erase_after_ms = $8,
                    operation_request_plaintext_schema = $9,
                    operation_request_plaintext_size_bytes = $10,
                    operation_request_plaintext_digest = $11,
                    operation_request_aad_digest = $12,
                    operation_request_envelope_digest = $13
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'revoked'
                  AND authority.terminal_reason = 'indeterminate_authority_expired'
                  AND authority.mint_claim_fence = $3
                  AND authority.mint_claim_owner_id = $4
                  AND authority.mint_claimed_at_ms = $14
                RETURNING authority.*
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(fence.as_i64())
            .bind(owner.as_uuid())
            .bind(request.committed_at().get())
            .bind(commit_disposition_str(disposition))
            .bind(metadata.provider_expires_at().map(UnixMillis::get))
            .bind(metadata.safe_erase_after().get())
            .bind(i32::from(metadata.plaintext_schema()))
            .bind(positive_i64(metadata.plaintext_size_bytes())?)
            .bind(metadata.plaintext_digest().as_bytes().as_slice())
            .bind(metadata.aad_digest().as_bytes().as_slice())
            .bind(mint_envelope_digest(envelope).as_bytes().as_slice())
            .bind(request.claim().claimed_at().get())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                MINT_COMMIT_OPERATION,
                fence.as_i64(),
                operation_digest,
                Some(owner.as_uuid()),
                OperationReceiptDisposition::TerminalErasable,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        if !matches!(
            durable_state,
            GithubRuntimeAuthorityState::Minting | GithubRuntimeAuthorityState::Indeterminate
        ) {
            return Err(GithubRuntimeAuthorityStoreError::MintClaimRejected);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        if database_now >= metadata.safe_erase_after()
            || database_now >= identity.conservative_expiry()
        {
            let row = sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoked',
                    provider_expires_at_ms = $6,
                    safe_erase_after_ms = $7,
                    commit_disposition = $8,
                    plaintext_schema = $9,
                    plaintext_size_bytes = $10,
                    plaintext_digest = $11,
                    aad_digest = $12,
                    operation_request_kind = 'mint_commit',
                    operation_request_claim_fence = $4,
                    operation_request_claim_owner_id = $3,
                    operation_request_observed_at_ms = $13,
                    operation_request_retry_at_ms = NULL,
                    operation_request_failure_kind = NULL,
                    operation_request_commit_disposition = $8,
                    operation_request_provider_expires_at_ms = $6,
                    operation_request_safe_erase_after_ms = $7,
                    operation_request_plaintext_schema = $9,
                    operation_request_plaintext_size_bytes = $10,
                    operation_request_plaintext_digest = $11,
                    operation_request_aad_digest = $12,
                    operation_request_envelope_digest = $14,
                    envelope_schema = NULL,
                    wrapping_key_id = NULL,
                    wrapped_data_key = NULL,
                    nonce = NULL,
                    ciphertext = NULL,
                    mint_claim_expires_at_ms = NULL,
                    revoke_pending_at_ms = $5,
                    revoked_at_ms = $5,
                    terminal_reason = CASE WHEN $6 IS NULL
                        THEN 'conservative_authority_expired'
                        ELSE 'provider_authority_expired'
                    END,
                    state_updated_at_ms = $5
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state IN ('minting', 'indeterminate')
                  AND authority.mint_claim_owner_id = $3
                  AND authority.mint_claim_fence = $4
                RETURNING authority.*
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(owner.as_uuid())
            .bind(fence.as_i64())
            .bind(database_now.get())
            .bind(metadata.provider_expires_at().map(UnixMillis::get))
            .bind(metadata.safe_erase_after().get())
            .bind(commit_disposition_str(disposition))
            .bind(i32::from(metadata.plaintext_schema()))
            .bind(positive_i64(metadata.plaintext_size_bytes())?)
            .bind(metadata.plaintext_digest().as_bytes().as_slice())
            .bind(metadata.aad_digest().as_bytes().as_slice())
            .bind(request.committed_at().get())
            .bind(mint_envelope_digest(envelope).as_bytes().as_slice())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                MINT_COMMIT_OPERATION,
                fence.as_i64(),
                operation_digest,
                Some(owner.as_uuid()),
                OperationReceiptDisposition::Applied,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }

        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = CASE
                WHEN authority.state = 'minting'
                     AND $17 = 'deliverable'
                     AND $6 IS NOT NULL
                     AND $6::NUMERIC > $5::NUMERIC + 60000
                     AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN 'ready'
                    ELSE 'revoke_pending'
                END,
                provider_expires_at_ms = $6,
                safe_erase_after_ms = $7,
                commit_disposition = $17,
                plaintext_schema = $8,
                plaintext_size_bytes = $9,
                plaintext_digest = $10,
                aad_digest = $11,
                envelope_schema = $12,
                wrapping_key_id = $13,
                wrapped_data_key = $14,
                nonce = $15,
                ciphertext = $16,
                operation_request_kind = 'mint_commit',
                operation_request_claim_fence = $4,
                operation_request_claim_owner_id = $3,
                operation_request_observed_at_ms = $18,
                operation_request_retry_at_ms = NULL,
                operation_request_failure_kind = NULL,
                operation_request_commit_disposition = $17,
                operation_request_provider_expires_at_ms = $6,
                operation_request_safe_erase_after_ms = $7,
                operation_request_plaintext_schema = $8,
                operation_request_plaintext_size_bytes = $9,
                operation_request_plaintext_digest = $10,
                operation_request_aad_digest = $11,
                operation_request_envelope_digest = $19,
                ready_at_ms = CASE
                    WHEN authority.state = 'minting'
                         AND $17 = 'deliverable'
                         AND $6 IS NOT NULL
                         AND $6::NUMERIC > $5::NUMERIC + 60000
                         AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN $5 ELSE NULL
                END,
                revoke_pending_at_ms = CASE
                    WHEN authority.state = 'minting'
                         AND $17 = 'deliverable'
                         AND $6 IS NOT NULL
                         AND $6::NUMERIC > $5::NUMERIC + 60000
                         AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN NULL ELSE $5
                END,
                next_revoke_at_ms = CASE
                    WHEN authority.state = 'minting'
                         AND $17 = 'deliverable'
                         AND $6 IS NOT NULL
                         AND $6::NUMERIC > $5::NUMERIC + 60000
                         AND automata_github_runtime_authority_is_current(authority, $5)
                        THEN NULL ELSE $5
                END,
                state_updated_at_ms = $5
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state IN ('minting', 'indeterminate')
              AND authority.mint_claim_owner_id = $3
              AND authority.mint_claim_fence = $4
              AND authority.mint_started_at_ms <= $5
              AND authority.conservative_expiry_at_ms > $5
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(owner.as_uuid())
        .bind(fence.as_i64())
        .bind(database_now.get())
        .bind(metadata.provider_expires_at().map(UnixMillis::get))
        .bind(metadata.safe_erase_after().get())
        .bind(i32::from(metadata.plaintext_schema()))
        .bind(positive_i64(metadata.plaintext_size_bytes())?)
        .bind(metadata.plaintext_digest().as_bytes().as_slice())
        .bind(metadata.aad_digest().as_bytes().as_slice())
        .bind(i32::from(envelope.schema()))
        .bind(envelope.wrapping_key_id().as_str())
        .bind(envelope.wrapped_data_key().ciphertext())
        .bind(envelope.nonce().as_slice())
        .bind(envelope.ciphertext())
        .bind(commit_disposition_str(disposition))
        .bind(request.committed_at().get())
        .bind(mint_envelope_digest(envelope).as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::MintClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        record_operation_receipt(
            &mut transaction,
            key,
            MINT_COMMIT_OPERATION,
            fence.as_i64(),
            operation_digest,
            Some(owner.as_uuid()),
            OperationReceiptDisposition::Applied,
            receipt,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn load_ready_github_runtime_authority(
        &self,
        request: LoadGithubRuntimeAuthority,
    ) -> Result<Option<ReadyGithubRuntimeAuthority>, GithubRuntimeAuthorityStoreError> {
        let key = request.identity().key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let row = load_row_for_update(&mut transaction, key).await?;
        let Some(row) = row else { return Ok(None) };
        let identity = decode_identity(&row)?;
        if identity != *request.identity() {
            return Err(GithubRuntimeAuthorityStoreError::IdentityConflict);
        }
        let state = decode_state(&row)?;
        if state != GithubRuntimeAuthorityState::Ready {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let current: bool = sqlx::query_scalar(
            r"
            SELECT automata_github_runtime_authority_is_current(authority, $3)
            FROM github_runtime_authority_issuances AS authority
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(database_now.get())
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let provider_expires_at: Option<i64> = row
            .try_get("provider_expires_at_ms")
            .map_err(operation_error)?;
        let conservative_use_expires_at = provider_expires_at
            .and_then(|expires_at| {
                expires_at.checked_sub(crate::GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS)
            })
            .map(UnixMillis::new);
        let ready_at = timestamp_column(&row, "ready_at_ms")?;
        if !current
            || ready_at > database_now
            || conservative_use_expires_at.is_none_or(|expires_at| expires_at <= database_now)
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let protected = decode_protected(&row, identity)?;
        let disposition = decode_commit_disposition(&row)?
            .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
        let ready =
            ReadyGithubRuntimeAuthority::from_repository_parts(protected, disposition, ready_at)
                .map(Some)
                .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(ready)
    }

    async fn quarantine_github_runtime_authority(
        &self,
        request: QuarantineGithubRuntimeAuthority,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let operation_digest = quarantine_operation_digest(request);
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if !lock_exact_quarantine_operation_predecessor(&mut transaction, key, request.aad_digest())
            .await?
        {
            return Err(GithubRuntimeAuthorityStoreError::QuarantineRejected);
        }
        match operation_receipt_matches(
            &mut transaction,
            key,
            QUARANTINE_OPERATION,
            0,
            operation_digest,
            None,
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::QuarantineRejected);
            }
            None => {}
        }
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::QuarantineRejected)?;
        match operation_receipt_matches(
            &mut transaction,
            key,
            QUARANTINE_OPERATION,
            0,
            operation_digest,
            None,
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::QuarantineRejected);
            }
            None => {}
        }
        let state = decode_state(&durable)?;
        if state == GithubRuntimeAuthorityState::Revoked
            && optional_digest_column(&durable, "aad_digest")? == Some(request.aad_digest())
        {
            let row = sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET operation_request_kind = 'quarantine',
                    operation_request_claim_fence = 0,
                    operation_request_claim_owner_id = NULL,
                    operation_request_observed_at_ms = $4,
                    operation_request_retry_at_ms = NULL,
                    operation_request_failure_kind = $5,
                    operation_request_commit_disposition = NULL,
                    operation_request_provider_expires_at_ms = NULL,
                    operation_request_safe_erase_after_ms = NULL,
                    operation_request_plaintext_schema = NULL,
                    operation_request_plaintext_size_bytes = NULL,
                    operation_request_plaintext_digest = NULL,
                    operation_request_aad_digest = $3,
                    operation_request_envelope_digest = NULL
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'revoked'
                  AND authority.aad_digest = $3
                RETURNING authority.*
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(request.aad_digest().as_bytes().as_slice())
            .bind(request.observed_at().get())
            .bind(request.kind().as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubRuntimeAuthorityStoreError::QuarantineRejected)?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                QUARANTINE_OPERATION,
                0,
                operation_digest,
                None,
                OperationReceiptDisposition::TerminalErasable,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        if !matches!(
            state,
            GithubRuntimeAuthorityState::Ready | GithubRuntimeAuthorityState::RevokePending
        ) {
            return Err(GithubRuntimeAuthorityStoreError::QuarantineRejected);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let safe_erase_after = optional_timestamp_column(&durable, "safe_erase_after_ms")?
            .ok_or(GithubRuntimeAuthorityStoreError::QuarantineRejected)?;
        if database_now >= safe_erase_after {
            let row = sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoked',
                    envelope_schema = NULL,
                    wrapping_key_id = NULL,
                    wrapped_data_key = NULL,
                    nonce = NULL,
                    ciphertext = NULL,
                    revoke_claim_owner_id = NULL,
                    revoke_claimed_at_ms = NULL,
                    revoke_claim_expires_at_ms = NULL,
                    next_revoke_at_ms = NULL,
                    quarantine_at_ms = $4,
                    quarantine_kind = $5,
                    operation_request_kind = 'quarantine',
                    operation_request_claim_fence = 0,
                    operation_request_claim_owner_id = NULL,
                    operation_request_observed_at_ms = $6,
                    operation_request_retry_at_ms = NULL,
                    operation_request_failure_kind = $5,
                    operation_request_commit_disposition = NULL,
                    operation_request_provider_expires_at_ms = NULL,
                    operation_request_safe_erase_after_ms = NULL,
                    operation_request_plaintext_schema = NULL,
                    operation_request_plaintext_size_bytes = NULL,
                    operation_request_plaintext_digest = NULL,
                    operation_request_aad_digest = $3,
                    operation_request_envelope_digest = NULL,
                    revoked_at_ms = $4,
                    terminal_reason = 'quarantined_authority_expired',
                    state_updated_at_ms = $4
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state IN ('ready', 'revoke_pending')
                  AND authority.aad_digest = $3
                  AND authority.safe_erase_after_ms <= $4
                RETURNING authority.*
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(request.aad_digest().as_bytes().as_slice())
            .bind(database_now.get())
            .bind(request.kind().as_str())
            .bind(request.observed_at().get())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(GithubRuntimeAuthorityStoreError::QuarantineRejected)?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                QUARANTINE_OPERATION,
                0,
                operation_digest,
                None,
                OperationReceiptDisposition::Applied,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = 'quarantined',
                revoke_claim_owner_id = NULL,
                revoke_claimed_at_ms = NULL,
                revoke_claim_expires_at_ms = NULL,
                next_revoke_at_ms = NULL,
                quarantine_at_ms = $4,
                quarantine_kind = $5,
                operation_request_kind = 'quarantine',
                operation_request_claim_fence = 0,
                operation_request_claim_owner_id = NULL,
                operation_request_observed_at_ms = $6,
                operation_request_retry_at_ms = NULL,
                operation_request_failure_kind = $5,
                operation_request_commit_disposition = NULL,
                operation_request_provider_expires_at_ms = NULL,
                operation_request_safe_erase_after_ms = NULL,
                operation_request_plaintext_schema = NULL,
                operation_request_plaintext_size_bytes = NULL,
                operation_request_plaintext_digest = NULL,
                operation_request_aad_digest = $3,
                operation_request_envelope_digest = NULL,
                state_updated_at_ms = $4
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state IN ('ready', 'revoke_pending')
              AND authority.aad_digest = $3
              AND authority.safe_erase_after_ms > $4
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.aad_digest().as_bytes().as_slice())
        .bind(database_now.get())
        .bind(request.kind().as_str())
        .bind(request.observed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::QuarantineRejected)?;
        let receipt = decode_receipt(&row)?;
        record_operation_receipt(
            &mut transaction,
            key,
            QUARANTINE_OPERATION,
            0,
            operation_digest,
            None,
            OperationReceiptDisposition::Applied,
            receipt,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_lines)]
    async fn reconcile_github_runtime_authorities(
        &self,
        request: ReconcileGithubRuntimeAuthorities,
    ) -> Result<GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let mut report = GithubRuntimeAuthorityReconciliationReport::default();
        // Caller time is scheduling evidence only. Candidate discovery never
        // authorizes a transition: each selected key is decoded, its complete
        // authority graph is locked, the issuance is locked, and only then is
        // fresh PostgreSQL time sampled and the exact transition re-proved.
        let _caller_observed_at = request.observed_at();
        let mut remaining = request.batch_size();
        while remaining > 0 {
            let Some(key) = next_reconciliation_candidate(&mut transaction).await? else {
                break;
            };
            let Some(action) = reconcile_locked_authority(&mut transaction, key).await? else {
                continue;
            };
            match action {
                RuntimeAuthorityReconciliationAction::QuarantinedEnvelopeErased => {
                    report.quarantined_envelopes_erased += 1;
                }
                RuntimeAuthorityReconciliationAction::ExpiredEnvelopeErased => {
                    report.expired_envelopes_erased += 1;
                }
                RuntimeAuthorityReconciliationAction::IndeterminateAuthorityExpired => {
                    report.indeterminate_authorities_expired += 1;
                }
                RuntimeAuthorityReconciliationAction::RevokedBeforeMint => {
                    report.revoked_before_mint += 1;
                }
                RuntimeAuthorityReconciliationAction::MintRetryRejected => {
                    report.mint_retries_rejected += 1;
                }
                RuntimeAuthorityReconciliationAction::MintingMarkedIndeterminate => {
                    report.minting_marked_indeterminate += 1;
                }
                RuntimeAuthorityReconciliationAction::ReadyMarkedRevokePending => {
                    report.ready_marked_revoke_pending += 1;
                }
            }
            remaining -= 1;
        }

        transaction.commit().await.map_err(operation_error)?;
        Ok(report)
    }

    #[allow(clippy::too_many_lines)] // The exact SQL transition dominates the line count.
    async fn claim_github_runtime_authority_revocation(
        &self,
        request: ClaimGithubRuntimeAuthorityRevocation,
    ) -> Result<Option<ClaimedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>
    {
        let claim_duration = request.expires_at().get() - request.observed_at().get();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if let Some(row) =
            load_revocation_claim_for_owner_for_update(&mut transaction, request.owner()).await?
        {
            let database_now = database_now_ms(&mut transaction).await?;
            let expires_at = timestamp_column(&row, "revoke_claim_expires_at_ms")?;
            if expires_at > database_now {
                let claim = decode_revocation_claim(&row)?;
                record_current_revocation_claim(&mut transaction, claim.key()).await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(Some(claim));
            }
            let attempts: i16 = row
                .try_get("revoke_attempt_count")
                .map_err(operation_error)?;
            let fence: i64 = row.try_get("revoke_claim_fence").map_err(operation_error)?;
            if attempts >= 64 || fence == i64::MAX {
                let released = sqlx::query(
                    r"
                    UPDATE github_runtime_authority_issuances
                    SET revoke_claim_owner_id = NULL,
                        revoke_claimed_at_ms = NULL,
                        revoke_claim_expires_at_ms = NULL,
                        next_revoke_at_ms = safe_erase_after_ms,
                        last_revoke_failure_kind = 'claim_budget_exhausted',
                        state_updated_at_ms = $3
                    WHERE attempt_id = $1
                      AND fencing_token = $2
                      AND state = 'revoke_pending'
                      AND revoke_claim_owner_id = $4
                      AND revoke_claim_expires_at_ms <= $3
                    ",
                )
                .bind(uuid_column(&row, "attempt_id")?)
                .bind(
                    row.try_get::<i64, _>("fencing_token")
                        .map_err(operation_error)?,
                )
                .bind(database_now.get())
                .bind(request.owner().as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                if released.rows_affected() != 1 {
                    return Err(GithubRuntimeAuthorityStoreError::CorruptData);
                }
            }
        }

        let candidate = sqlx::query(
            r"
            SELECT authority.attempt_id, authority.fencing_token
            FROM github_runtime_authority_issuances AS authority
            WHERE authority.state = 'revoke_pending'
              AND authority.revoke_attempt_count < 64
              AND authority.revoke_claim_fence < 9223372036854775807
              AND (
                  authority.revoke_claim_owner_id = $1
                  OR NOT EXISTS (
                      SELECT 1
                      FROM github_runtime_authority_issuances AS owned
                      WHERE owned.revoke_claim_owner_id = $1
                  )
              )
            ORDER BY
                (authority.revoke_claim_owner_id = $1) DESC,
                coalesce(
                    authority.next_revoke_at_ms,
                    authority.revoke_claim_expires_at_ms
                ),
                authority.revoke_pending_at_ms,
                authority.attempt_id,
                authority.fencing_token
            LIMIT 1
            ",
        )
        .bind(request.owner().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let Some(candidate) = candidate else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        };
        let key = GithubRuntimeAuthorityKey::new(
            AttemptId::from_uuid(uuid_column(&candidate, "attempt_id")?),
            FencingToken::new(positive_u64_column(&candidate, "fencing_token")?)
                .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        );
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
        let database_now = database_now_ms(&mut transaction).await?;
        let safe_erase_after = optional_timestamp_column(&durable, "safe_erase_after_ms")?
            .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
        let current_owner = optional_uuid_column(&durable, "revoke_claim_owner_id")?;
        let next_revoke_at = optional_timestamp_column(&durable, "next_revoke_at_ms")?;
        let prior_claim_expires_at =
            optional_timestamp_column(&durable, "revoke_claim_expires_at_ms")?;
        let eligible = decode_state(&durable)? == GithubRuntimeAuthorityState::RevokePending
            && safe_erase_after
                .get()
                .checked_sub(claim_duration)
                .is_some_and(|latest_start| database_now.get() < latest_start)
            && match current_owner {
                None => next_revoke_at.is_some_and(|due| due <= database_now),
                Some(_) => prior_claim_expires_at.is_some_and(|expiry| expiry <= database_now),
            };
        if !eligible {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let attempts: i16 = durable
            .try_get("revoke_attempt_count")
            .map_err(operation_error)?;
        let fence: i64 = durable
            .try_get("revoke_claim_fence")
            .map_err(operation_error)?;
        if attempts >= 64 {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        if fence == i64::MAX {
            return Err(GithubRuntimeAuthorityStoreError::FenceExhausted);
        }
        let claim_expires_at = database_now
            .get()
            .checked_add(claim_duration)
            .map(UnixMillis::new)
            .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
        let claim_result = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET revoke_attempt_count = authority.revoke_attempt_count + 1,
                revoke_claim_fence = authority.revoke_claim_fence + 1,
                revoke_claim_owner_id = $3,
                revoke_claimed_at_ms = $4,
                revoke_claim_expires_at_ms = $5,
                next_revoke_at_ms = NULL,
                state_updated_at_ms = $4
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'revoke_pending'
              AND authority.safe_erase_after_ms > $5
              AND authority.revoke_claim_fence = $6
              AND authority.revoke_attempt_count = $7
              AND (
                  authority.revoke_claim_owner_id IS NULL
                  AND authority.next_revoke_at_ms <= $4
                  OR authority.revoke_claim_owner_id IS NOT NULL
                  AND authority.revoke_claim_expires_at_ms <= $4
              )
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(database_now.get())
        .bind(claim_expires_at.get())
        .bind(fence)
        .bind(attempts)
        .fetch_optional(&mut *transaction)
        .await;
        let row = match claim_result {
            Ok(row) => row,
            Err(error) if is_revoke_owner_conflict(&error) => None,
            Err(error) => return Err(operation_error(error)),
        };
        let claim = row.as_ref().map(decode_revocation_claim).transpose()?;
        if claim.is_some() {
            record_current_revocation_claim(&mut transaction, key).await?;
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(claim)
    }

    async fn revalidate_github_runtime_authority_revocation(
        &self,
        request: RevalidateGithubRuntimeAuthorityRevocation,
    ) -> Result<Option<RevalidatedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>
    {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let Some(durable) = load_row_for_update(&mut transaction, request.key()).await? else {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        };
        let identity = decode_identity(&durable)?;
        let exact = decode_state(&durable)? == GithubRuntimeAuthorityState::RevokePending
            && identity.identity_digest() == request.identity_digest()
            && optional_uuid_column(&durable, "revoke_claim_owner_id")?
                == Some(request.owner().as_uuid())
            && positive_u64_column(&durable, "revoke_claim_fence")? == request.fence().get()
            && timestamp_column(&durable, "revoke_claimed_at_ms")? == request.claimed_at()
            && timestamp_column(&durable, "revoke_claim_expires_at_ms")? == request.expires_at()
            && optional_timestamp_column(&durable, "safe_erase_after_ms")?
                == Some(request.safe_erase_after())
            && digest_column(&durable, "aad_digest")? == request.aad_digest();
        if !exact {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        if database_now < request.claimed_at()
            || database_now >= request.expires_at()
            || database_now >= request.safe_erase_after()
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        let provider_call_authorized = database_now
            .get()
            .checked_add(request.provider_request_millis())
            .is_some_and(|completion| {
                completion <= request.expires_at().get()
                    && completion < request.safe_erase_after().get()
            });
        let result = RevalidatedGithubRuntimeAuthorityRevocation::from_repository_parts(
            request,
            database_now,
            provider_call_authorized,
        )
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(Some(result))
    }

    async fn retry_github_runtime_authority_revocation(
        &self,
        request: RetryGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let operation_digest = revocation_retry_operation_digest(&request);
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if !lock_exact_revocation_operation_predecessor(
            &mut transaction,
            key,
            request.owner(),
            request.fence(),
            request.claimed_at(),
            request.expires_at(),
        )
        .await?
        {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        match operation_receipt_matches(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
            }
            None => {}
        }
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)?;
        match operation_receipt_matches(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
            }
            None => {}
        }
        let claimed_at = request.claimed_at();
        let expires_at = request.expires_at();
        if request.observed_at() < claimed_at || request.observed_at() >= expires_at {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let durable_state = decode_state(&durable)?;
        let exact_claim = durable_state == GithubRuntimeAuthorityState::RevokePending
            && optional_uuid_column(&durable, "revoke_claim_owner_id")?
                == Some(request.owner().as_uuid())
            && positive_u64_column(&durable, "revoke_claim_fence")? == request.fence().get();
        if !exact_claim {
            if revocation_outcome_is_terminal_erasable(
                &durable,
                request.fence(),
                expires_at,
                database_now,
            )? {
                let row = observe_terminal_revocation_outcome(
                    &mut transaction,
                    key,
                    request.owner(),
                    request.fence(),
                    "revocation_retry",
                    request.observed_at(),
                    Some(request.retry_at()),
                    Some(request.failure().as_str()),
                )
                .await?;
                let receipt = decode_receipt(&row)?;
                record_operation_receipt(
                    &mut transaction,
                    key,
                    REVOCATION_OUTCOME_OPERATION,
                    request.fence().as_i64(),
                    operation_digest,
                    Some(request.owner().as_uuid()),
                    OperationReceiptDisposition::TerminalErasable,
                    receipt,
                )
                .await?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        if database_now >= expires_at {
            let row = observe_terminal_revocation_outcome(
                &mut transaction,
                key,
                request.owner(),
                request.fence(),
                "revocation_retry",
                request.observed_at(),
                Some(request.retry_at()),
                Some(request.failure().as_str()),
            )
            .await?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                REVOCATION_OUTCOME_OPERATION,
                request.fence().as_i64(),
                operation_digest,
                Some(request.owner().as_uuid()),
                OperationReceiptDisposition::TerminalErasable,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let retry_delay = request.retry_at().get() - request.observed_at().get();
        let safe_erase_after = optional_timestamp_column(&durable, "safe_erase_after_ms")?
            .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
        let database_retry_at = UnixMillis::new(
            database_now
                .get()
                .saturating_add(retry_delay)
                .min(safe_erase_after.get()),
        );
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET revoke_claim_owner_id = NULL,
                revoke_claimed_at_ms = NULL,
                revoke_claim_expires_at_ms = NULL,
                next_revoke_at_ms = $5,
                last_revoke_failure_kind = $6,
                operation_request_kind = 'revocation_retry',
                operation_request_claim_fence = $4,
                operation_request_claim_owner_id = $3,
                operation_request_observed_at_ms = $8,
                operation_request_retry_at_ms = $9,
                operation_request_failure_kind = $6,
                operation_request_commit_disposition = NULL,
                operation_request_provider_expires_at_ms = NULL,
                operation_request_safe_erase_after_ms = NULL,
                operation_request_plaintext_schema = NULL,
                operation_request_plaintext_size_bytes = NULL,
                operation_request_plaintext_digest = NULL,
                operation_request_aad_digest = NULL,
                operation_request_envelope_digest = NULL,
                state_updated_at_ms = $7
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'revoke_pending'
              AND authority.revoke_claim_owner_id = $3
              AND authority.revoke_claim_fence = $4
              AND authority.revoke_claimed_at_ms <= $7
              AND authority.revoke_claim_expires_at_ms > $7
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(request.fence().as_i64())
        .bind(database_retry_at.get())
        .bind(request.failure().as_str())
        .bind(database_now.get())
        .bind(request.observed_at().get())
        .bind(request.retry_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        record_operation_receipt(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
            OperationReceiptDisposition::Applied,
            receipt,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn defer_github_runtime_authority_revocation(
        &self,
        request: DeferGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let operation_digest = revocation_defer_operation_digest(&request);
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if !lock_exact_revocation_operation_predecessor(
            &mut transaction,
            key,
            request.owner(),
            request.fence(),
            request.claimed_at(),
            request.expires_at(),
        )
        .await?
        {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        match operation_receipt_matches(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
            }
            None => {}
        }
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)?;
        match operation_receipt_matches(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
            }
            None => {}
        }
        let claimed_at = request.claimed_at();
        let expires_at = request.expires_at();
        if request.observed_at() < claimed_at || request.observed_at() >= expires_at {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let exact_claim = decode_state(&durable)? == GithubRuntimeAuthorityState::RevokePending
            && optional_uuid_column(&durable, "revoke_claim_owner_id")?
                == Some(request.owner().as_uuid())
            && positive_u64_column(&durable, "revoke_claim_fence")? == request.fence().get();
        if !exact_claim
            && !revocation_outcome_is_terminal_erasable(
                &durable,
                request.fence(),
                expires_at,
                database_now,
            )?
        {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        if !exact_claim || database_now >= expires_at {
            let row = observe_terminal_revocation_outcome(
                &mut transaction,
                key,
                request.owner(),
                request.fence(),
                "revocation_defer",
                request.observed_at(),
                None,
                Some(request.failure().as_str()),
            )
            .await?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                REVOCATION_OUTCOME_OPERATION,
                request.fence().as_i64(),
                operation_digest,
                Some(request.owner().as_uuid()),
                OperationReceiptDisposition::TerminalErasable,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET revoke_claim_owner_id = NULL,
                revoke_claimed_at_ms = NULL,
                revoke_claim_expires_at_ms = NULL,
                next_revoke_at_ms = authority.safe_erase_after_ms,
                last_revoke_failure_kind = $5,
                operation_request_kind = 'revocation_defer',
                operation_request_claim_fence = $4,
                operation_request_claim_owner_id = $3,
                operation_request_observed_at_ms = $7,
                operation_request_retry_at_ms = NULL,
                operation_request_failure_kind = $5,
                operation_request_commit_disposition = NULL,
                operation_request_provider_expires_at_ms = NULL,
                operation_request_safe_erase_after_ms = NULL,
                operation_request_plaintext_schema = NULL,
                operation_request_plaintext_size_bytes = NULL,
                operation_request_plaintext_digest = NULL,
                operation_request_aad_digest = NULL,
                operation_request_envelope_digest = NULL,
                state_updated_at_ms = $6
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'revoke_pending'
              AND authority.revoke_claim_owner_id = $3
              AND authority.revoke_claim_fence = $4
              AND authority.revoke_claimed_at_ms <= $6
              AND authority.revoke_claim_expires_at_ms > $6
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(request.fence().as_i64())
        .bind(request.failure().as_str())
        .bind(database_now.get())
        .bind(request.observed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        record_operation_receipt(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
            OperationReceiptDisposition::Applied,
            receipt,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn confirm_github_runtime_authority_revocation(
        &self,
        request: ConfirmGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let key = request.key();
        let operation_digest = revocation_confirmation_operation_digest(request);
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        if !lock_exact_revocation_operation_predecessor(
            &mut transaction,
            key,
            request.owner(),
            request.fence(),
            request.claimed_at(),
            request.expires_at(),
        )
        .await?
        {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        match operation_receipt_matches(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
            }
            None => {}
        }
        let durable = load_row_for_update(&mut transaction, key)
            .await?
            .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)?;
        match operation_receipt_matches(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
        )
        .await?
        {
            Some(OperationReceiptMatch::Exact(receipt)) => {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(receipt);
            }
            Some(OperationReceiptMatch::Conflict) => {
                return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
            }
            None => {}
        }
        let claimed_at = request.claimed_at();
        let expires_at = request.expires_at();
        if request.confirmed_at() < claimed_at || request.confirmed_at() >= expires_at {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        let database_now = database_now_ms(&mut transaction).await?;
        let exact_claim = decode_state(&durable)? == GithubRuntimeAuthorityState::RevokePending
            && optional_uuid_column(&durable, "revoke_claim_owner_id")?
                == Some(request.owner().as_uuid())
            && positive_u64_column(&durable, "revoke_claim_fence")? == request.fence().get();
        if !exact_claim
            && !revocation_outcome_is_terminal_erasable(
                &durable,
                request.fence(),
                expires_at,
                database_now,
            )?
        {
            return Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected);
        }
        if !exact_claim || database_now >= expires_at {
            let row = observe_terminal_revocation_outcome(
                &mut transaction,
                key,
                request.owner(),
                request.fence(),
                "revocation_confirm",
                request.confirmed_at(),
                None,
                None,
            )
            .await?;
            let receipt = decode_receipt(&row)?;
            record_operation_receipt(
                &mut transaction,
                key,
                REVOCATION_OUTCOME_OPERATION,
                request.fence().as_i64(),
                operation_digest,
                Some(request.owner().as_uuid()),
                OperationReceiptDisposition::TerminalErasable,
                receipt,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let row = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances AS authority
            SET state = 'revoked',
                envelope_schema = NULL,
                wrapping_key_id = NULL,
                wrapped_data_key = NULL,
                nonce = NULL,
                ciphertext = NULL,
                revoke_claim_owner_id = NULL,
                revoke_claimed_at_ms = NULL,
                revoke_claim_expires_at_ms = NULL,
                next_revoke_at_ms = NULL,
                operation_request_kind = 'revocation_confirm',
                operation_request_claim_fence = $4,
                operation_request_claim_owner_id = $3,
                operation_request_observed_at_ms = $6,
                operation_request_retry_at_ms = NULL,
                operation_request_failure_kind = NULL,
                operation_request_commit_disposition = NULL,
                operation_request_provider_expires_at_ms = NULL,
                operation_request_safe_erase_after_ms = NULL,
                operation_request_plaintext_schema = NULL,
                operation_request_plaintext_size_bytes = NULL,
                operation_request_plaintext_digest = NULL,
                operation_request_aad_digest = NULL,
                operation_request_envelope_digest = NULL,
                revoked_at_ms = $5,
                terminal_reason = 'provider_revocation_confirmed',
                state_updated_at_ms = $5
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'revoke_pending'
              AND authority.revoke_claim_owner_id = $3
              AND authority.revoke_claim_fence = $4
              AND authority.revoke_claimed_at_ms <= $5
              AND authority.revoke_claim_expires_at_ms > $5
            RETURNING authority.*
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(request.owner().as_uuid())
        .bind(request.fence().as_i64())
        .bind(database_now.get())
        .bind(request.confirmed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)?;
        let receipt = decode_receipt(&row)?;
        record_operation_receipt(
            &mut transaction,
            key,
            REVOCATION_OUTCOME_OPERATION,
            request.fence().as_i64(),
            operation_digest,
            Some(request.owner().as_uuid()),
            OperationReceiptDisposition::Applied,
            receipt,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeAuthorityReconciliationAction {
    QuarantinedEnvelopeErased,
    ExpiredEnvelopeErased,
    IndeterminateAuthorityExpired,
    RevokedBeforeMint,
    MintRetryRejected,
    MintingMarkedIndeterminate,
    ReadyMarkedRevokePending,
}

async fn next_reconciliation_candidate(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Option<GithubRuntimeAuthorityKey>, GithubRuntimeAuthorityStoreError> {
    // This unlocked read is only a scheduling hint. No state decision is made
    // until `reconcile_locked_authority` has locked the complete graph and row.
    let row = sqlx::query(
        r"
        WITH database_time AS MATERIALIZED (
            SELECT floor(
                extract(epoch FROM clock_timestamp()) * 1000
            )::BIGINT AS now_ms
        )
        SELECT authority.attempt_id, authority.fencing_token
        FROM github_runtime_authority_issuances AS authority
        CROSS JOIN database_time
        WHERE authority.state = 'quarantined'
              AND authority.safe_erase_after_ms <= database_time.now_ms
           OR authority.state IN ('ready', 'revoke_pending')
              AND authority.safe_erase_after_ms <= database_time.now_ms
           OR authority.state IN ('minting', 'indeterminate')
              AND authority.conservative_expiry_at_ms <= database_time.now_ms
           OR authority.state = 'claimed'
              AND (
                  authority.request_deadline_at_ms <= database_time.now_ms
                  OR NOT automata_github_runtime_authority_is_current(
                      authority, database_time.now_ms
                  )
              )
           OR authority.state = 'mint_retry_pending'
              AND (
                  authority.request_deadline_at_ms <= database_time.now_ms
                  OR NOT automata_github_runtime_authority_is_current(
                      authority, database_time.now_ms
                  )
              )
           OR authority.state = 'minting'
              AND authority.request_deadline_at_ms <= database_time.now_ms
           OR authority.state = 'ready'
              AND NOT automata_github_runtime_authority_is_current(
                  authority, database_time.now_ms
              )
        ORDER BY CASE
            WHEN authority.state = 'quarantined'
                 AND authority.safe_erase_after_ms <= database_time.now_ms THEN 1
            WHEN authority.state IN ('ready', 'revoke_pending')
                 AND authority.safe_erase_after_ms <= database_time.now_ms THEN 2
            WHEN authority.state IN ('minting', 'indeterminate')
                 AND authority.conservative_expiry_at_ms <= database_time.now_ms THEN 3
            WHEN authority.state = 'claimed' THEN 4
            WHEN authority.state = 'mint_retry_pending' THEN 5
            WHEN authority.state = 'minting' THEN 6
            WHEN authority.state = 'ready' THEN 7
            ELSE 8
        END,
        coalesce(
            authority.safe_erase_after_ms,
            authority.conservative_expiry_at_ms,
            authority.request_deadline_at_ms
        ),
        authority.attempt_id,
        authority.fencing_token
        LIMIT 1
        ",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.map(|row| {
        Ok(GithubRuntimeAuthorityKey::new(
            AttemptId::from_uuid(uuid_column(&row, "attempt_id")?),
            FencingToken::new(positive_u64_column(&row, "fencing_token")?)
                .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        ))
    })
    .transpose()
}

#[allow(clippy::too_many_lines)] // Exact lifecycle writes stay adjacent to their proofs.
async fn reconcile_locked_authority(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
) -> Result<Option<RuntimeAuthorityReconciliationAction>, GithubRuntimeAuthorityStoreError> {
    let Some(row) = load_row_for_update(transaction, key).await? else {
        return Ok(None);
    };
    let database_now = database_now_ms(transaction).await?;
    let state = decode_state(&row)?;
    let safe_erase_after = optional_timestamp_column(&row, "safe_erase_after_ms")?;
    let request_deadline = timestamp_column(&row, "request_deadline_at_ms")?;
    let conservative_expiry = timestamp_column(&row, "conservative_expiry_at_ms")?;
    let current = if matches!(
        state,
        GithubRuntimeAuthorityState::Claimed
            | GithubRuntimeAuthorityState::MintRetryPending
            | GithubRuntimeAuthorityState::Ready
    ) {
        sqlx::query_scalar(
            r"
            SELECT automata_github_runtime_authority_is_current(authority, $3)
            FROM github_runtime_authority_issuances AS authority
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
            ",
        )
        .bind(key.attempt_id().as_uuid())
        .bind(fencing_i64(key.fencing_token()))
        .bind(database_now.get())
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)?
    } else {
        true
    };
    let action = match state {
        GithubRuntimeAuthorityState::Quarantined
            if safe_erase_after.is_some_and(|horizon| horizon <= database_now) =>
        {
            RuntimeAuthorityReconciliationAction::QuarantinedEnvelopeErased
        }
        GithubRuntimeAuthorityState::Ready | GithubRuntimeAuthorityState::RevokePending
            if safe_erase_after.is_some_and(|horizon| horizon <= database_now) =>
        {
            RuntimeAuthorityReconciliationAction::ExpiredEnvelopeErased
        }
        GithubRuntimeAuthorityState::Minting | GithubRuntimeAuthorityState::Indeterminate
            if conservative_expiry <= database_now =>
        {
            RuntimeAuthorityReconciliationAction::IndeterminateAuthorityExpired
        }
        GithubRuntimeAuthorityState::Claimed if request_deadline <= database_now || !current => {
            RuntimeAuthorityReconciliationAction::RevokedBeforeMint
        }
        GithubRuntimeAuthorityState::MintRetryPending
            if request_deadline <= database_now || !current =>
        {
            RuntimeAuthorityReconciliationAction::MintRetryRejected
        }
        GithubRuntimeAuthorityState::Minting if request_deadline <= database_now => {
            RuntimeAuthorityReconciliationAction::MintingMarkedIndeterminate
        }
        GithubRuntimeAuthorityState::Ready if !current => {
            RuntimeAuthorityReconciliationAction::ReadyMarkedRevokePending
        }
        _ => return Ok(None),
    };

    let result = match action {
        RuntimeAuthorityReconciliationAction::QuarantinedEnvelopeErased => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoked',
                    envelope_schema = NULL,
                    wrapping_key_id = NULL,
                    wrapped_data_key = NULL,
                    nonce = NULL,
                    ciphertext = NULL,
                    revoked_at_ms = $3,
                    terminal_reason = 'quarantined_authority_expired',
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'quarantined'
                  AND authority.safe_erase_after_ms <= $3
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
        RuntimeAuthorityReconciliationAction::ExpiredEnvelopeErased => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoked',
                    envelope_schema = NULL,
                    wrapping_key_id = NULL,
                    wrapped_data_key = NULL,
                    nonce = NULL,
                    ciphertext = NULL,
                    revoke_claim_owner_id = NULL,
                    revoke_claimed_at_ms = NULL,
                    revoke_claim_expires_at_ms = NULL,
                    next_revoke_at_ms = NULL,
                    revoked_at_ms = $3,
                    terminal_reason = CASE
                        WHEN authority.provider_expires_at_ms IS NULL
                            THEN 'conservative_authority_expired'
                        ELSE 'provider_authority_expired'
                    END,
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state IN ('ready', 'revoke_pending')
                  AND authority.safe_erase_after_ms <= $3
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
        RuntimeAuthorityReconciliationAction::IndeterminateAuthorityExpired => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoked',
                    mint_claim_expires_at_ms = NULL,
                    revoked_at_ms = $3,
                    terminal_reason = 'indeterminate_authority_expired',
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state IN ('minting', 'indeterminate')
                  AND authority.conservative_expiry_at_ms <= $3
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
        RuntimeAuthorityReconciliationAction::RevokedBeforeMint => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoked',
                    mint_claim_expires_at_ms = NULL,
                    revoked_at_ms = $3,
                    terminal_reason = CASE
                        WHEN authority.request_deadline_at_ms <= $3
                            THEN 'request_expired_before_mint'
                        ELSE 'superseded_before_mint'
                    END,
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'claimed'
                  AND (
                      authority.request_deadline_at_ms <= $3
                      OR NOT automata_github_runtime_authority_is_current(authority, $3)
                  )
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
        RuntimeAuthorityReconciliationAction::MintRetryRejected => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'rejected',
                    next_mint_at_ms = NULL,
                    rejected_at_ms = $3,
                    terminal_reason = 'provider_mint_retry_expired',
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'mint_retry_pending'
                  AND (
                      authority.request_deadline_at_ms <= $3
                      OR NOT automata_github_runtime_authority_is_current(authority, $3)
                  )
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
        RuntimeAuthorityReconciliationAction::MintingMarkedIndeterminate => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'indeterminate',
                    indeterminate_at_ms = $3,
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'minting'
                  AND authority.request_deadline_at_ms <= $3
                  AND authority.conservative_expiry_at_ms > $3
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
        RuntimeAuthorityReconciliationAction::ReadyMarkedRevokePending => {
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances AS authority
                SET state = 'revoke_pending',
                    revoke_pending_at_ms = $3,
                    next_revoke_at_ms = $3,
                    state_updated_at_ms = $3
                WHERE authority.attempt_id = $1
                  AND authority.fencing_token = $2
                  AND authority.state = 'ready'
                  AND authority.safe_erase_after_ms > $3
                  AND NOT automata_github_runtime_authority_is_current(authority, $3)
                ",
            )
            .bind(key.attempt_id().as_uuid())
            .bind(fencing_i64(key.fencing_token()))
            .bind(database_now.get())
            .execute(&mut **transaction)
            .await
        }
    }
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(Some(action))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationReceiptMatch {
    Exact(GithubRuntimeAuthorityReceipt),
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationReceiptDisposition {
    Applied,
    TerminalErasable,
}

impl OperationReceiptDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::TerminalErasable => "terminal_erasable",
        }
    }
}

async fn operation_receipt_matches(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
    operation_kind: &str,
    claim_fence: i64,
    operation_digest: Sha256Digest,
    expected_owner: Option<Uuid>,
) -> Result<Option<OperationReceiptMatch>, GithubRuntimeAuthorityStoreError> {
    // The operation-specific immutable predecessor is locked before this
    // permanent tombstone and before any mutable graph/issuance lock.
    let Some(row) = sqlx::query(
        r"
        SELECT operation_digest, claim_owner_id,
               result_state AS state,
               result_updated_at_ms AS state_updated_at_ms,
               result_terminal_reason AS terminal_reason
        FROM github_runtime_authority_operation_receipts
        WHERE attempt_id = $1
          AND fencing_token = $2
          AND operation_kind = $3
          AND claim_fence = $4
        FOR UPDATE
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .bind(operation_kind)
    .bind(claim_fence)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    else {
        return Ok(None);
    };
    if digest_column(&row, "operation_digest")? != operation_digest
        || optional_uuid_column(&row, "claim_owner_id")? != expected_owner
    {
        return Ok(Some(OperationReceiptMatch::Conflict));
    }
    let receipt = GithubRuntimeAuthorityReceipt::from_repository_parts(
        key,
        decode_state(&row)?,
        timestamp_column(&row, "state_updated_at_ms")?,
        terminal_reason(&row)?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    Ok(Some(OperationReceiptMatch::Exact(receipt)))
}

async fn record_current_mint_claim(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
) -> Result<(), GithubRuntimeAuthorityStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_runtime_authority_mint_claims (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms
        )
        SELECT authority.tenant_id, authority.attempt_id,
               authority.fencing_token, authority.mint_claim_fence,
               authority.mint_claim_owner_id, authority.mint_claimed_at_ms,
               authority.mint_claim_expires_at_ms
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
          AND authority.state = 'claimed'
          AND authority.mint_claim_owner_id IS NOT NULL
          AND authority.mint_claimed_at_ms IS NOT NULL
          AND authority.mint_claim_expires_at_ms IS NOT NULL
        ON CONFLICT (attempt_id, fencing_token, claim_fence) DO NOTHING
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_runtime_authority_issuances AS authority
            JOIN github_runtime_authority_mint_claims AS claim
              ON claim.attempt_id = authority.attempt_id
             AND claim.fencing_token = authority.fencing_token
             AND claim.claim_fence = authority.mint_claim_fence
             AND claim.tenant_id = authority.tenant_id
             AND claim.claim_owner_id = authority.mint_claim_owner_id
             AND claim.claimed_at_ms = authority.mint_claimed_at_ms
             AND claim.expires_at_ms = authority.mint_claim_expires_at_ms
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'claimed'
        )
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if !exact {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(())
}

async fn record_current_revocation_claim(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
) -> Result<(), GithubRuntimeAuthorityStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_runtime_authority_revocation_claims (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms,
            aad_digest, safe_erase_after_ms
        )
        SELECT authority.tenant_id, authority.attempt_id,
               authority.fencing_token, authority.revoke_claim_fence,
               authority.revoke_claim_owner_id, authority.revoke_claimed_at_ms,
               authority.revoke_claim_expires_at_ms, authority.aad_digest,
               authority.safe_erase_after_ms
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
          AND authority.state = 'revoke_pending'
          AND authority.revoke_claim_owner_id IS NOT NULL
          AND authority.revoke_claimed_at_ms IS NOT NULL
          AND authority.revoke_claim_expires_at_ms IS NOT NULL
        ON CONFLICT (attempt_id, fencing_token, claim_fence) DO NOTHING
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_runtime_authority_issuances AS authority
            JOIN github_runtime_authority_revocation_claims AS claim
              ON claim.attempt_id = authority.attempt_id
             AND claim.fencing_token = authority.fencing_token
             AND claim.claim_fence = authority.revoke_claim_fence
             AND claim.tenant_id = authority.tenant_id
             AND claim.claim_owner_id = authority.revoke_claim_owner_id
             AND claim.claimed_at_ms = authority.revoke_claimed_at_ms
             AND claim.expires_at_ms = authority.revoke_claim_expires_at_ms
             AND claim.aad_digest = authority.aad_digest
             AND claim.safe_erase_after_ms = authority.safe_erase_after_ms
            WHERE authority.attempt_id = $1
              AND authority.fencing_token = $2
              AND authority.state = 'revoke_pending'
        )
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if !exact {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(())
}

async fn lock_exact_mint_claim(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &ClaimedGithubRuntimeAuthorityMint,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM github_runtime_authority_mint_claims AS predecessor
        WHERE predecessor.tenant_id = $1
          AND predecessor.attempt_id = $2
          AND predecessor.fencing_token = $3
          AND predecessor.claim_fence = $4
          AND predecessor.claim_owner_id = $5
          AND predecessor.claimed_at_ms = $6
          AND predecessor.expires_at_ms = $7
        FOR KEY SHARE
        ",
    )
    .bind(claim.identity().tenant().as_str())
    .bind(claim.identity().key().attempt_id().as_uuid())
    .bind(fencing_i64(claim.identity().key().fencing_token()))
    .bind(claim.fence().as_i64())
    .bind(claim.owner().as_uuid())
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map(|locked| locked.unwrap_or(false))
    .map_err(operation_error)
}

async fn lock_exact_mint_begin(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &ClaimedGithubRuntimeAuthorityMint,
    provider_request_millis: i64,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM github_runtime_authority_mint_begins AS predecessor
        WHERE predecessor.tenant_id = $1
          AND predecessor.attempt_id = $2
          AND predecessor.fencing_token = $3
          AND predecessor.claim_fence = $4
          AND predecessor.claim_owner_id = $5
          AND predecessor.claimed_at_ms = $6
          AND predecessor.expires_at_ms = $7
          AND predecessor.provider_request_millis = $8
        FOR KEY SHARE
        ",
    )
    .bind(claim.identity().tenant().as_str())
    .bind(claim.identity().key().attempt_id().as_uuid())
    .bind(fencing_i64(claim.identity().key().fencing_token()))
    .bind(claim.fence().as_i64())
    .bind(claim.owner().as_uuid())
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(provider_request_millis)
    .fetch_optional(&mut **transaction)
    .await
    .map(|locked| locked.unwrap_or(false))
    .map_err(operation_error)
}

fn revocation_outcome_is_terminal_erasable(
    durable: &PgRow,
    fence: GithubRuntimeAuthorityClaimFence,
    claim_expires_at: UnixMillis,
    database_now: UnixMillis,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    let state = decode_state(durable)?;
    let current_fence: i64 = durable
        .try_get("revoke_claim_fence")
        .map_err(operation_error)?;
    Ok(matches!(
        state,
        GithubRuntimeAuthorityState::Quarantined | GithubRuntimeAuthorityState::Revoked
    ) || current_fence != fence.as_i64()
        || database_now >= claim_expires_at)
}

#[allow(clippy::too_many_arguments)] // Exact persisted request evidence for one closed fence.
async fn observe_terminal_revocation_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    request_kind: &str,
    observed_at: UnixMillis,
    retry_at: Option<UnixMillis>,
    failure_kind: Option<&str>,
) -> Result<PgRow, GithubRuntimeAuthorityStoreError> {
    sqlx::query(
        r"
        UPDATE github_runtime_authority_issuances AS authority
        SET operation_request_kind = $5,
            operation_request_claim_fence = $3,
            operation_request_claim_owner_id = $4,
            operation_request_observed_at_ms = $6,
            operation_request_retry_at_ms = $7,
            operation_request_failure_kind = $8,
            operation_request_commit_disposition = NULL,
            operation_request_provider_expires_at_ms = NULL,
            operation_request_safe_erase_after_ms = NULL,
            operation_request_plaintext_schema = NULL,
            operation_request_plaintext_size_bytes = NULL,
            operation_request_plaintext_digest = NULL,
            operation_request_aad_digest = NULL,
            operation_request_envelope_digest = NULL
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
          AND authority.safe_erase_after_ms IS NOT NULL
        RETURNING authority.*
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .bind(fence.as_i64())
    .bind(owner.as_uuid())
    .bind(request_kind)
    .bind(observed_at.get())
    .bind(retry_at.map(UnixMillis::get))
    .bind(failure_kind)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
}

async fn lock_exact_revocation_operation_predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
    owner: GithubRuntimeAuthorityWorkerId,
    fence: GithubRuntimeAuthorityClaimFence,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM github_runtime_authority_revocation_claims AS predecessor
        WHERE predecessor.attempt_id = $1
          AND predecessor.fencing_token = $2
          AND predecessor.claim_fence = $3
          AND predecessor.claim_owner_id = $4
          AND predecessor.claimed_at_ms = $5
          AND predecessor.expires_at_ms = $6
        FOR KEY SHARE
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .bind(fence.as_i64())
    .bind(owner.as_uuid())
    .bind(claimed_at.get())
    .bind(expires_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map(|locked| locked.unwrap_or(false))
    .map_err(operation_error)
}

async fn lock_exact_quarantine_operation_predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
    aad_digest: Sha256Digest,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    let locked = sqlx::query_scalar::<_, bool>(
        r"
        SELECT TRUE
        FROM github_runtime_authority_operation_transitions AS transition
        JOIN github_runtime_authority_operation_receipts AS receipt
          ON receipt.attempt_id = transition.attempt_id
         AND receipt.fencing_token = transition.fencing_token
         AND receipt.operation_kind = transition.operation_kind
         AND receipt.claim_fence = transition.claim_fence
         AND receipt.tenant_id = transition.tenant_id
         AND receipt.operation_digest = transition.operation_digest
         AND receipt.disposition = transition.disposition
         AND receipt.claim_owner_id IS NOT DISTINCT FROM
             transition.claim_owner_id
         AND receipt.claim_claimed_at_ms IS NOT DISTINCT FROM
             transition.claim_claimed_at_ms
         AND receipt.claim_expires_at_ms IS NOT DISTINCT FROM
             transition.claim_expires_at_ms
         AND receipt.result_state = transition.result_state
         AND receipt.result_updated_at_ms = transition.result_updated_at_ms
         AND receipt.result_terminal_reason IS NOT DISTINCT FROM
             transition.result_terminal_reason
        WHERE transition.attempt_id = $1
          AND transition.fencing_token = $2
          AND transition.operation_kind = 'mint_commit'
          AND transition.disposition = 'applied'
          AND transition.request_aad_digest = $3
        FOR KEY SHARE OF transition, receipt
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .bind(aad_digest.as_bytes().as_slice())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match locked.as_slice() {
        [locked] => Ok(*locked),
        [] => Ok(false),
        _ => Err(GithubRuntimeAuthorityStoreError::CorruptData),
    }
}

#[allow(clippy::too_many_arguments)] // One exact locked predecessor/result SQL boundary.
async fn record_operation_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
    operation_kind: &str,
    claim_fence: i64,
    operation_digest: Sha256Digest,
    expected_owner: Option<Uuid>,
    disposition: OperationReceiptDisposition,
    receipt: GithubRuntimeAuthorityReceipt,
) -> Result<(), GithubRuntimeAuthorityStoreError> {
    let inserted = sqlx::query_scalar::<_, i32>(
        r"
        INSERT INTO github_runtime_authority_operation_receipts (
            tenant_id, attempt_id, fencing_token, operation_kind, claim_fence,
            operation_digest, disposition,
            claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
            result_state, result_updated_at_ms, result_terminal_reason,
            applied_at_ms
        )
        SELECT authority.tenant_id, $1, $2, $3, $4, $5, $7,
               CASE
                   WHEN $3 = 'mint_commit' THEN mint_claim.claim_owner_id
                   WHEN $3 = 'revocation_outcome' THEN revoke_claim.claim_owner_id
               END,
               CASE
                   WHEN $3 = 'mint_commit' THEN mint_claim.claimed_at_ms
                   WHEN $3 = 'revocation_outcome' THEN revoke_claim.claimed_at_ms
               END,
               CASE
                   WHEN $3 = 'mint_commit' THEN mint_claim.expires_at_ms
                   WHEN $3 = 'revocation_outcome' THEN revoke_claim.expires_at_ms
               END,
               $8, $9, $10, 0
        FROM github_runtime_authority_issuances AS authority
        LEFT JOIN github_runtime_authority_mint_claims AS mint_claim
          ON $3 = 'mint_commit'
         AND mint_claim.attempt_id = authority.attempt_id
         AND mint_claim.fencing_token = authority.fencing_token
         AND mint_claim.claim_fence = $4
        LEFT JOIN github_runtime_authority_revocation_claims AS revoke_claim
          ON $3 = 'revocation_outcome'
         AND revoke_claim.attempt_id = authority.attempt_id
         AND revoke_claim.fencing_token = authority.fencing_token
         AND revoke_claim.claim_fence = $4
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
          AND (
              $3 = 'quarantine' AND $4 = 0 AND $6::UUID IS NULL
              OR $3 = 'mint_commit'
                 AND mint_claim.claim_owner_id = $6::UUID
              OR $3 = 'revocation_outcome'
                 AND revoke_claim.claim_owner_id = $6::UUID
          )
        ON CONFLICT (attempt_id, fencing_token, operation_kind, claim_fence)
        DO NOTHING
        RETURNING 1
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .bind(operation_kind)
    .bind(claim_fence)
    .bind(operation_digest.as_bytes().as_slice())
    .bind(expected_owner)
    .bind(disposition.as_str())
    .bind(runtime_authority_state_str(receipt.state()))
    .bind(receipt.updated_at().get())
    .bind(
        receipt
            .terminal_reason()
            .map(runtime_authority_terminal_reason_str),
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if inserted != Some(1) {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(())
}

fn mint_commit_operation_digest(request: &CommitGithubRuntimeAuthority) -> Sha256Digest {
    let metadata = request.protected().metadata();
    let envelope = request.protected().envelope();
    let mut digest = Sha256::new();
    digest.update(MINT_COMMIT_DIGEST_DOMAIN);
    hash_authority_key(&mut digest, metadata.identity().key());
    digest.update(request.owner().as_uuid().as_bytes());
    digest.update(request.fence().get().to_be_bytes());
    digest.update(request.claim().claimed_at().get().to_be_bytes());
    digest.update(request.claim().expires_at().get().to_be_bytes());
    hash_bytes(
        &mut digest,
        commit_disposition_str(request.disposition()).as_bytes(),
    );
    digest.update(request.committed_at().get().to_be_bytes());
    hash_optional_timestamp(&mut digest, metadata.provider_expires_at());
    digest.update(metadata.safe_erase_after().get().to_be_bytes());
    digest.update(metadata.plaintext_schema().to_be_bytes());
    digest.update(metadata.plaintext_size_bytes().to_be_bytes());
    digest.update(metadata.plaintext_digest().as_bytes());
    digest.update(metadata.aad_digest().as_bytes());
    digest.update(mint_envelope_digest(envelope).as_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn quarantine_operation_digest(request: QuarantineGithubRuntimeAuthority) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(QUARANTINE_DIGEST_DOMAIN);
    hash_authority_key(&mut digest, request.key());
    digest.update(request.aad_digest().as_bytes());
    hash_bytes(&mut digest, request.kind().as_str().as_bytes());
    digest.update(request.observed_at().get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn revocation_retry_operation_digest(
    request: &RetryGithubRuntimeAuthorityRevocation,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REVOCATION_OUTCOME_DIGEST_DOMAIN);
    hash_bytes(&mut digest, b"retry");
    hash_authority_key(&mut digest, request.key());
    digest.update(request.owner().as_uuid().as_bytes());
    digest.update(request.fence().get().to_be_bytes());
    digest.update(request.claimed_at().get().to_be_bytes());
    digest.update(request.expires_at().get().to_be_bytes());
    hash_bytes(&mut digest, request.failure().as_str().as_bytes());
    digest.update(request.observed_at().get().to_be_bytes());
    digest.update(request.retry_at().get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn revocation_defer_operation_digest(
    request: &DeferGithubRuntimeAuthorityRevocation,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REVOCATION_OUTCOME_DIGEST_DOMAIN);
    hash_bytes(&mut digest, b"defer");
    hash_authority_key(&mut digest, request.key());
    digest.update(request.owner().as_uuid().as_bytes());
    digest.update(request.fence().get().to_be_bytes());
    digest.update(request.claimed_at().get().to_be_bytes());
    digest.update(request.expires_at().get().to_be_bytes());
    hash_bytes(&mut digest, request.failure().as_str().as_bytes());
    digest.update(request.observed_at().get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn revocation_confirmation_operation_digest(
    request: ConfirmGithubRuntimeAuthorityRevocation,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REVOCATION_OUTCOME_DIGEST_DOMAIN);
    hash_bytes(&mut digest, b"confirm");
    hash_authority_key(&mut digest, request.key());
    digest.update(request.owner().as_uuid().as_bytes());
    digest.update(request.fence().get().to_be_bytes());
    digest.update(request.claimed_at().get().to_be_bytes());
    digest.update(request.expires_at().get().to_be_bytes());
    digest.update(request.confirmed_at().get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn mint_envelope_digest(envelope: &EncryptedEnvelope) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(ENVELOPE_DIGEST_DOMAIN);
    digest.update(envelope.schema().to_be_bytes());
    hash_bytes(&mut digest, envelope.wrapping_key_id().as_str().as_bytes());
    hash_bytes(&mut digest, envelope.wrapped_data_key().ciphertext());
    hash_bytes(&mut digest, envelope.nonce());
    hash_bytes(&mut digest, envelope.ciphertext());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn hash_authority_key(digest: &mut Sha256, key: GithubRuntimeAuthorityKey) {
    digest.update(key.attempt_id().as_uuid().as_bytes());
    digest.update(key.fencing_token().get().to_be_bytes());
}

fn hash_optional_timestamp(digest: &mut Sha256, value: Option<UnixMillis>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.get().to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn hash_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

async fn load_row_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    key: GithubRuntimeAuthorityKey,
) -> Result<Option<PgRow>, GithubRuntimeAuthorityStoreError> {
    let candidate = sqlx::query(
        r"
        SELECT authority.*
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let candidate_identity = decode_identity(&candidate)?;
    if !lock_exact_authority_graph(transaction, &candidate_identity).await? {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    let locked = sqlx::query(
        r"
        SELECT authority.*
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
        FOR UPDATE
        ",
    )
    .bind(key.attempt_id().as_uuid())
    .bind(fencing_i64(key.fencing_token()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if locked
        .as_ref()
        .map(decode_identity)
        .transpose()?
        .as_ref()
        .is_some_and(|identity| identity != &candidate_identity)
    {
        return Err(GithubRuntimeAuthorityStoreError::IdentityConflict);
    }
    Ok(locked)
}

async fn lock_exact_authority_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    lock_exact_authority_graph(transaction, identity).await
}

async fn lock_exact_authority_runner_session(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM runners AS runner
        JOIN runner_sessions AS session
          ON session.id = $2
         AND session.runner_id = runner.id
        WHERE runner.id = $1
          AND runner.tenant_id = $3
          AND session.session_epoch = $4
          AND session.runner_generation = $5
        FOR SHARE OF runner, session
        ",
    )
    .bind(identity.runner_id().as_uuid())
    .bind(identity.runner_session_id().as_uuid())
    .bind(identity.tenant().as_str())
    .bind(positive_i64(identity.runner_session_epoch().get())?)
    .bind(positive_i64(identity.runner_generation().get())?)
    .fetch_optional(&mut **transaction)
    .await
    .map(|locked| locked.unwrap_or(false))
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // Phase-ordered queries lock the historical authority graph.
async fn lock_exact_authority_graph(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    // Lease renewal takes these same two locks before it locks the attempt.
    // Keep reconciliation and every other authority operation in that order:
    // runner/session, execution graph, historical graph, then issuance.
    if !lock_exact_authority_runner_session(transaction, identity).await? {
        return Ok(false);
    }

    let execution_locked: bool = sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM job_attempts AS attempt
        JOIN jobs AS job
          ON job.id = attempt.job_id
         AND job.id = $2
         AND job.run_id = $3
        JOIN workflow_runs AS run
          ON run.id = job.run_id
         AND run.repository_id = $4
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.tenant_id = $5
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        WHERE attempt.id = $1
          AND attempt.job_id = $2
          AND job.job_ir_schema = $6
          AND job.job_ir_size_bytes = $7
          AND job.job_ir_digest = $8
          AND job.job_ir_digest = $9
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id = $10::TEXT
          AND repository.owner || '/' || repository.name = $11
        FOR SHARE OF attempt, job, run, repository, workflow, snapshot
        ",
    )
    .bind(identity.key().attempt_id().as_uuid())
    .bind(identity.job_id().as_uuid())
    .bind(identity.run_id().as_uuid())
    .bind(identity.repository_id().as_uuid())
    .bind(identity.tenant().as_str())
    .bind(i32::from(identity.job_ir_version().get()))
    .bind(positive_i64(identity.job_ir_size_bytes())?)
    .bind(identity.job_ir_digest().as_bytes().as_slice())
    .bind(identity.policy_digest().as_bytes().as_slice())
    .bind(identity.github_repository_id().as_i64())
    .bind(identity.github_repository_name().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .unwrap_or(false);
    if !execution_locked {
        return Ok(false);
    }

    let historical = sqlx::query(
        r"
        SELECT origin.origin_kind, origin.origin_id, origin.repository_visibility,
               origin.private_source_authority_id
        FROM github_workflow_run_manifest_origins AS origin
        JOIN workflow_admission_receipts AS admission
          ON admission.tenant_id = origin.tenant_id
         AND admission.idempotency_kind = origin.admission_idempotency_kind
         AND admission.idempotency_key = origin.admission_idempotency_key
         AND admission.request_digest = origin.logical_admission_digest
         AND admission.repository_id = origin.repository_id
         AND admission.run_id = origin.run_id
         AND admission.committed_at_ms = origin.admitted_at_ms
         AND admission.github_subject_evidence_required
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS checks
          ON checks.tenant_id = origin.tenant_id
         AND checks.id = origin.checks_authority_id
         AND checks.repository_id = origin.repository_id
         AND checks.provider_connection_id = origin.provider_connection_id
         AND checks.provider_installation_id = origin.provider_installation_id
         AND checks.github_repository_id = origin.github_repository_id
         AND checks.github_repository_name = origin.github_repository_name
         AND checks.service_scope = 'checks_write'
         AND checks.identity_digest = origin.checks_authority_identity_digest
         AND checks.app_configuration_revision =
             origin.checks_authority_app_configuration_revision
         AND checks.policy_revision = origin.checks_authority_policy_revision
        JOIN logical_workflow_runtime_policy_pins AS pin
          ON pin.run_id = origin.run_id
         AND pin.tenant_id = origin.tenant_id
         AND pin.repository_id = origin.repository_id
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = pin.tenant_id
         AND policy.repository_id = pin.repository_id
         AND policy.policy_revision = pin.policy_revision
         AND policy.policy_digest = pin.policy_digest
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.job_id = $13
         AND concrete.run_id = origin.run_id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest = publication.activation_input_digest
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = concrete.run_id
        WHERE origin.tenant_id = $1
          AND origin.repository_id = $2
          AND origin.run_id = $3
          AND origin.provider_connection_id = $4
          AND origin.provider_installation_id = $5
          AND origin.github_repository_id = $6
          AND origin.github_repository_name = $7
          AND manifest.github_app_id = $8
          AND manifest.github_app_client_id = $9
          AND manifest.github_app_jwt_issuer_kind = $10
          AND manifest.app_key_spki_sha256 = $11
          AND manifest.github_app_id = checks.github_app_id
          AND manifest.github_app_client_id = checks.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind = checks.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks.app_key_spki_sha256
          AND manifest.app_configuration_revision = checks.app_configuration_revision
          AND manifest.policy_revision = checks.policy_revision
          AND checks.configuration_fingerprint = $12
          AND manifest.runtime_policy_revision = pin.policy_revision
          AND manifest.runtime_policy_digest = pin.policy_digest
          AND manifest.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
          AND manifest.runner_policy_object_key = 'github/runner-policy/v1/'
              || pg_catalog.encode(manifest.runner_policy_digest, 'hex') || '.json'
          AND manifest.runner_policy_size_bytes = pg_catalog.octet_length(policy.canonical_policy)
          AND manifest.runner_policy_media_type =
              'application/vnd.automata.github-runner-policy+json'
          AND policy.state = 'sealed'
          AND logical_job.runtime_policy_revision = pin.policy_revision
          AND logical_job.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runtime_policy_revision = pin.policy_revision
          AND preparation_claim.runtime_policy_digest = pin.policy_digest
          AND preparation_claim.runner_policy_digest = manifest.runner_policy_digest
          AND preparation_claim.runner_policy_object_key = manifest.runner_policy_object_key
          AND preparation_claim.runner_policy_size_bytes = manifest.runner_policy_size_bytes
          AND preparation_claim.runner_policy_media_type = manifest.runner_policy_media_type
          AND preparation.runtime_policy_revision = pin.policy_revision
          AND preparation.runtime_policy_digest = pin.policy_digest
          AND publication.runtime_policy_revision = pin.policy_revision
          AND publication.runtime_policy_digest = pin.policy_digest
          AND instance.runtime_policy_revision = pin.policy_revision
          AND instance.runtime_policy_digest = pin.policy_digest
          AND materialization.runtime_policy_revision = pin.policy_revision
          AND materialization.runtime_policy_digest = pin.policy_digest
          AND concrete.runtime_policy_revision = pin.policy_revision
          AND concrete.runtime_policy_digest = pin.policy_digest
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
        FOR SHARE OF admission, manifest, checks, pin, policy,
                     concrete, materialization, instance, publication, preparation,
                     preparation_claim, logical_job, invocation, marker
        ",
    )
    .bind(identity.tenant().as_str())
    .bind(identity.repository_id().as_uuid())
    .bind(identity.run_id().as_uuid())
    .bind(identity.provider_connection_id().as_uuid())
    .bind(identity.provider_installation_id().as_i64())
    .bind(identity.github_repository_id().as_i64())
    .bind(identity.github_repository_name().as_str())
    .bind(identity.github_app_id().as_i64())
    .bind(identity.github_app_client_id().as_str())
    .bind(identity.github_app_jwt_issuer_kind().as_str())
    .bind(identity.app_key_spki_sha256().as_bytes().as_slice())
    .bind(identity.configuration_fingerprint().as_bytes().as_slice())
    .bind(identity.job_id().as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let (origin_kind, origin_id, visibility, private_authority_id): (
        String,
        Uuid,
        String,
        Option<Uuid>,
    ) = match historical.as_slice() {
        [row] => (
            row.try_get("origin_kind").map_err(operation_error)?,
            row.try_get("origin_id").map_err(operation_error)?,
            row.try_get("repository_visibility")
                .map_err(operation_error)?,
            row.try_get("private_source_authority_id")
                .map_err(operation_error)?,
        ),
        [] => return Ok(false),
        _ => return Err(GithubRuntimeAuthorityStoreError::CorruptData),
    };
    if !lock_exact_selection_tails(transaction, identity).await? {
        return Ok(false);
    }
    if !lock_exact_private_runtime_authority(
        transaction,
        identity,
        &origin_kind,
        origin_id,
        &visibility,
        private_authority_id,
    )
    .await?
    {
        return Ok(false);
    }
    Ok(true)
}

#[allow(clippy::too_many_lines)] // One phase-ordered lock boundary for three 0043 tails.
async fn lock_exact_selection_tails(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    let preparation = identity.preparation_selection_tail();
    let activation = identity.activation_selection_tail();
    let materialization_tail = identity.materialization_selection_tail();
    let rows = sqlx::query(
        r"
        SELECT concrete.invocation_id, concrete.logical_job_id,
               concrete.instance_id, concrete.initial_attempt_id,
               preparation_selection.generation = $6
                   AND preparation_selection.claimed_at_ms = $8
                   AND preparation_selection.expires_at_ms = $9
                   AS preparation_is_base,
               activation_selection.generation = $12
                   AND activation_selection.claimed_at_ms = $14
                   AND activation_selection.expires_at_ms = $15
                   AS activation_is_base,
               materialization_selection.generation = $18
                   AND materialization_selection.claimed_at_ms = $20
                   AND materialization_selection.expires_at_ms = $21
                   AS materialization_is_base
        FROM logical_workflow_concrete_jobs AS concrete
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = logical_job.run_id
         AND publication.invocation_id = logical_job.invocation_id
         AND publication.logical_job_id = logical_job.id
         AND publication.activation_input_digest =
             logical_job.activation_input_digest
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest =
             publication.activation_input_digest
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN logical_workflow_activation_work_selections AS preparation_selection
          ON preparation_selection.selection_id = $4
         AND preparation_selection.outcome = 'claimed'
         AND preparation_selection.tenant_id = $1
         AND preparation_selection.run_id = $2
         AND preparation_selection.invocation_id = concrete.invocation_id
         AND preparation_selection.logical_job_id = concrete.logical_job_id
         AND preparation_selection.authority_kind = 'preparation'
         AND preparation_selection.owner_id = $5
         AND preparation_selection.authority_digest = $7
        JOIN logical_workflow_activation_work_selections AS activation_selection
          ON activation_selection.selection_id = $10
         AND activation_selection.outcome = 'claimed'
         AND activation_selection.tenant_id = $1
         AND activation_selection.run_id = $2
         AND activation_selection.invocation_id = concrete.invocation_id
         AND activation_selection.logical_job_id = concrete.logical_job_id
         AND activation_selection.authority_kind = 'activation'
         AND activation_selection.owner_id = $11
         AND activation_selection.authority_digest = $13
        JOIN logical_workflow_materialization_work_selections AS materialization_selection
          ON materialization_selection.selection_id = $16
         AND materialization_selection.outcome = 'claimed'
         AND materialization_selection.tenant_id = $1
         AND materialization_selection.run_id = $2
         AND materialization_selection.invocation_id = concrete.invocation_id
         AND materialization_selection.logical_job_id = concrete.logical_job_id
         AND materialization_selection.instance_id = concrete.instance_id
         AND materialization_selection.owner_id = $17
         AND materialization_selection.authority_digest = $19
        WHERE concrete.run_id = $2
          AND concrete.job_id = $3
          AND preparation_claim.origin_selection_id = $4
          AND preparation_claim.owner_id = $5
          AND preparation_claim.generation = $6
          AND preparation_claim.descriptor_digest = $7
          AND preparation_claim.claimed_at_ms = $8
          AND preparation_claim.expires_at_ms = $9
          AND logical_job.activation_origin_selection_id = $10
          AND logical_job.activation_fence = $12
          AND logical_job.activation_input_digest = $13
          AND publication.activation_owner_id = $11
          AND publication.activation_generation = $12
          AND publication.activation_input_digest = $13
          AND publication.activation_claimed_at_ms = $14
          AND publication.activation_expires_at_ms = $15
          AND materialization.origin_selection_id = $16
          AND materialization.owner_id = $17
          AND materialization.generation = $18
          AND materialization.descriptor_digest = $19
          AND materialization.claimed_at_ms = $20
          AND materialization.expires_at_ms = $21
        FOR SHARE OF concrete, materialization, logical_job, publication,
                     preparation, preparation_claim,
                     preparation_selection, activation_selection,
                     materialization_selection
        ",
    )
    .bind(identity.tenant().as_str())
    .bind(identity.run_id().as_uuid())
    .bind(identity.job_id().as_uuid())
    .bind(preparation.selection_id().as_uuid())
    .bind(preparation.owner().as_uuid())
    .bind(positive_i64(preparation.generation().get())?)
    .bind(preparation.descriptor_digest().as_bytes().as_slice())
    .bind(preparation.claimed_at().get())
    .bind(preparation.expires_at().get())
    .bind(activation.selection_id().as_uuid())
    .bind(activation.owner().as_uuid())
    .bind(positive_i64(activation.generation().get())?)
    .bind(activation.activation_input_digest().as_bytes().as_slice())
    .bind(activation.claimed_at().get())
    .bind(activation.expires_at().get())
    .bind(materialization_tail.selection_id().as_uuid())
    .bind(materialization_tail.owner().as_uuid())
    .bind(positive_i64(materialization_tail.generation().get())?)
    .bind(
        materialization_tail
            .descriptor_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(materialization_tail.claimed_at().get())
    .bind(materialization_tail.expires_at().get())
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let row = match rows.as_slice() {
        [row] => row,
        [] => return Ok(false),
        _ => return Err(GithubRuntimeAuthorityStoreError::CorruptData),
    };
    let invocation_id = uuid_column(row, "invocation_id")?;
    let logical_job_id = uuid_column(row, "logical_job_id")?;
    let instance_id = uuid_column(row, "instance_id")?;
    let initial_attempt_id = uuid_column(row, "initial_attempt_id")?;

    if !row
        .try_get::<bool, _>("preparation_is_base")
        .map_err(operation_error)?
        && !lock_exact_activation_selection_renewal(
            transaction,
            identity,
            invocation_id,
            logical_job_id,
            "preparation",
            preparation.selection_id().as_uuid(),
            preparation.owner().as_uuid(),
            preparation.generation().get(),
            preparation.descriptor_digest(),
            preparation.claimed_at(),
            preparation.expires_at(),
        )
        .await?
    {
        return Ok(false);
    }
    if !row
        .try_get::<bool, _>("activation_is_base")
        .map_err(operation_error)?
        && !lock_exact_activation_selection_renewal(
            transaction,
            identity,
            invocation_id,
            logical_job_id,
            "activation",
            activation.selection_id().as_uuid(),
            activation.owner().as_uuid(),
            activation.generation().get(),
            activation.activation_input_digest(),
            activation.claimed_at(),
            activation.expires_at(),
        )
        .await?
    {
        return Ok(false);
    }
    if !row
        .try_get::<bool, _>("materialization_is_base")
        .map_err(operation_error)?
        && !lock_exact_materialization_selection_renewal(
            transaction,
            identity,
            invocation_id,
            logical_job_id,
            instance_id,
            initial_attempt_id,
        )
        .await?
    {
        return Ok(false);
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn lock_exact_activation_selection_renewal(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    authority_kind: &str,
    selection_id: Uuid,
    owner_id: Uuid,
    generation: u64,
    authority_digest: Sha256Digest,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM logical_workflow_activation_renewal_receipts AS renewal
        JOIN logical_workflow_runtime_policy_pins AS pin
          ON pin.run_id = renewal.run_id
         AND pin.tenant_id = renewal.tenant_id
         AND pin.repository_id = $12
        WHERE renewal.tenant_id = $1
          AND renewal.run_id = $2
          AND renewal.invocation_id = $3
          AND renewal.logical_job_id = $4
          AND renewal.authority_kind = $5
          AND renewal.selection_id = $6
          AND renewal.owner_id = $7
          AND renewal.authority_digest = $8
          AND renewal.runtime_policy_revision = pin.policy_revision
          AND renewal.runtime_policy_digest = pin.policy_digest
          AND renewal.successor_generation = $9
          AND renewal.successor_claimed_at_ms = $10
          AND renewal.successor_expires_at_ms = $11
        FOR KEY SHARE
        ",
    )
    .bind(identity.tenant().as_str())
    .bind(identity.run_id().as_uuid())
    .bind(invocation_id)
    .bind(logical_job_id)
    .bind(authority_kind)
    .bind(selection_id)
    .bind(owner_id)
    .bind(authority_digest.as_bytes().as_slice())
    .bind(positive_i64(generation)?)
    .bind(claimed_at.get())
    .bind(expires_at.get())
    .bind(identity.repository_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map(|locked| locked.unwrap_or(false))
    .map_err(operation_error)
}

async fn lock_exact_materialization_selection_renewal(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    instance_id: Uuid,
    initial_attempt_id: Uuid,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    let tail = identity.materialization_selection_tail();
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM logical_workflow_materialization_renewal_receipts AS renewal
        JOIN logical_workflow_runtime_policy_pins AS pin
          ON pin.run_id = renewal.run_id
         AND pin.tenant_id = renewal.tenant_id
         AND pin.repository_id = $14
        WHERE renewal.tenant_id = $1
          AND renewal.run_id = $2
          AND renewal.invocation_id = $3
          AND renewal.logical_job_id = $4
          AND renewal.instance_id = $5
          AND renewal.expected_job_id = $6
          AND renewal.expected_attempt_id = $7
          AND renewal.selection_id = $8
          AND renewal.owner_id = $9
          AND renewal.authority_digest = $10
          AND renewal.runtime_policy_revision = pin.policy_revision
          AND renewal.runtime_policy_digest = pin.policy_digest
          AND renewal.successor_generation = $11
          AND renewal.successor_claimed_at_ms = $12
          AND renewal.successor_expires_at_ms = $13
        FOR KEY SHARE
        ",
    )
    .bind(identity.tenant().as_str())
    .bind(identity.run_id().as_uuid())
    .bind(invocation_id)
    .bind(logical_job_id)
    .bind(instance_id)
    .bind(identity.job_id().as_uuid())
    .bind(initial_attempt_id)
    .bind(tail.selection_id().as_uuid())
    .bind(tail.owner().as_uuid())
    .bind(tail.descriptor_digest().as_bytes().as_slice())
    .bind(positive_i64(tail.generation().get())?)
    .bind(tail.claimed_at().get())
    .bind(tail.expires_at().get())
    .bind(identity.repository_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map(|locked| locked.unwrap_or(false))
    .map_err(operation_error)
}

async fn lock_exact_private_runtime_authority(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &GithubRuntimeAuthorityIdentity,
    origin_kind: &str,
    origin_id: Uuid,
    visibility: &str,
    private_authority_id: Option<Uuid>,
) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    if visibility == "public"
        && private_authority_id.is_none()
        && github_manifest_origin_is_closed(origin_kind)
        && !origin_id.is_nil()
    {
        return Ok(true);
    }
    let Some(private_authority_id) = private_authority_id.filter(|_| {
        visibility == "private"
            && github_manifest_origin_is_closed(origin_kind)
            && !origin_id.is_nil()
    }) else {
        return Ok(false);
    };
    sqlx::query_scalar(
        r"
        SELECT TRUE
        FROM github_workflow_run_manifest_origins AS evidence
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        JOIN github_server_service_authorities AS authority
          ON authority.tenant_id = evidence.tenant_id
         AND authority.id = evidence.private_source_authority_id
         AND authority.repository_id = evidence.repository_id
         AND authority.provider_connection_id = evidence.provider_connection_id
         AND authority.provider_installation_id = evidence.provider_installation_id
         AND authority.github_repository_id = evidence.github_repository_id
         AND authority.github_repository_name = evidence.github_repository_name
         AND authority.service_scope = 'private_repository_source_read'
         AND authority.github_app_id = manifest.github_app_id
         AND authority.github_app_client_id = manifest.github_app_client_id
         AND authority.github_app_jwt_issuer_kind = manifest.github_app_jwt_issuer_kind
         AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
         AND authority.app_configuration_revision =
             evidence.private_source_authority_app_configuration_revision
         AND authority.app_configuration_revision = manifest.app_configuration_revision
         AND authority.policy_revision = evidence.private_source_authority_policy_revision
         AND authority.policy_revision = manifest.policy_revision
         AND authority.identity_digest = evidence.private_source_authority_identity_digest
         AND authority.state = 'active'
        WHERE evidence.origin_kind = $1
          AND evidence.origin_id = $2
          AND evidence.tenant_id = $3
          AND evidence.repository_id = $4
          AND evidence.private_source_authority_id = $5
          AND evidence.provider_connection_id = $6
          AND evidence.provider_installation_id = $7
          AND evidence.github_repository_id = $8
          AND evidence.github_repository_name = $9
          AND manifest.github_app_id = $10
          AND manifest.github_app_client_id = $11
          AND manifest.github_app_jwt_issuer_kind = $12
          AND manifest.app_key_spki_sha256 = $13
        FOR SHARE OF manifest, authority
        ",
    )
    .bind(origin_kind)
    .bind(origin_id)
    .bind(identity.tenant().as_str())
    .bind(identity.repository_id().as_uuid())
    .bind(private_authority_id)
    .bind(identity.provider_connection_id().as_uuid())
    .bind(identity.provider_installation_id().as_i64())
    .bind(identity.github_repository_id().as_i64())
    .bind(identity.github_repository_name().as_str())
    .bind(identity.github_app_id().as_i64())
    .bind(identity.github_app_client_id().as_str())
    .bind(identity.github_app_jwt_issuer_kind().as_str())
    .bind(identity.app_key_spki_sha256().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map(|row| row.unwrap_or(false))
    .map_err(operation_error)
}

async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<UnixMillis, GithubRuntimeAuthorityStoreError> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    if now < 0 {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(UnixMillis::new(now))
}

fn bounded_future_timestamp(
    database_now: UnixMillis,
    duration_millis: i64,
    ceiling: UnixMillis,
) -> Option<UnixMillis> {
    let expires_at = database_now.get().checked_add(duration_millis)?;
    let expires_at = UnixMillis::new(expires_at.min(ceiling.get()));
    (expires_at > database_now).then_some(expires_at)
}

async fn load_revocation_claim_for_owner_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    owner: GithubRuntimeAuthorityWorkerId,
) -> Result<Option<PgRow>, GithubRuntimeAuthorityStoreError> {
    let candidate = sqlx::query(
        r"
        SELECT authority.attempt_id, authority.fencing_token
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.state = 'revoke_pending'
          AND authority.revoke_claim_owner_id = $1
        ORDER BY authority.revoke_claimed_at_ms, authority.attempt_id,
                 authority.fencing_token
        LIMIT 1
        ",
    )
    .bind(owner.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let key = GithubRuntimeAuthorityKey::new(
        AttemptId::from_uuid(uuid_column(&candidate, "attempt_id")?),
        FencingToken::new(positive_u64_column(&candidate, "fencing_token")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
    );
    load_row_for_update(transaction, key).await
}

#[allow(clippy::too_many_lines)] // Every durable identity field is decoded and revalidated.
fn decode_identity(
    row: &PgRow,
) -> Result<GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityStoreError> {
    let tenant: String = row.try_get("tenant_id").map_err(operation_error)?;
    let tenant = TenantScope::from_authenticated_tenant_id(tenant)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let attempt_id = AttemptId::from_uuid(uuid_column(row, "attempt_id")?);
    let fencing_token = FencingToken::new(positive_u64_column(row, "fencing_token")?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let lease_id = LeaseId::from_uuid(uuid_column(row, "lease_id")?);
    let run_id = RunId::from_uuid(uuid_column(row, "run_id")?);
    let job_id = JobId::from_uuid(uuid_column(row, "job_id")?);
    let runner_id = RunnerId::from_uuid(uuid_column(row, "runner_id")?);
    let runner_session_id = RunnerSessionId::from_uuid(uuid_column(row, "runner_session_id")?);
    let session_epoch = SessionEpoch::new(positive_u64_column(row, "runner_session_epoch")?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let runner_generation = RunnerGeneration::new(positive_u64_column(row, "runner_generation")?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let runner_slot_value: i32 = row.try_get("runner_slot").map_err(operation_error)?;
    let runner_slot = u16::try_from(runner_slot_value)
        .ok()
        .and_then(|value| StableRunnerSlot::new(value).ok())
        .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
    let job_ir_schema: i32 = row.try_get("job_ir_schema").map_err(operation_error)?;
    let job_ir_version = u16::try_from(job_ir_schema)
        .ok()
        .and_then(|value| JobIrVersion::new(value).ok())
        .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
    let job_ir_size_bytes = positive_u64_column(row, "job_ir_size_bytes")?;
    let repository_id = RepositoryId::from_uuid(uuid_column(row, "repository_id")?);
    let provider_connection_id =
        ProviderConnectionId::from_uuid(uuid_column(row, "provider_connection_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let provider_installation_id =
        ProviderInstallationId::new(positive_u64_column(row, "provider_installation_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let github_app_id = GithubServerServiceAppId::new(positive_u64_column(row, "github_app_id")?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let github_app_client_id = GithubServerServiceAppClientId::new(
        row.try_get::<String, _>("github_app_client_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let github_app_jwt_issuer_kind = GithubServerServiceJwtIssuer::from_durable(
        &row.try_get::<String, _>("github_app_jwt_issuer_kind")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let github_repository_id =
        GithubRepositoryId::new(positive_u64_column(row, "github_repository_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let repository_name: String = row
        .try_get("github_repository_name")
        .map_err(operation_error)?;
    let repository_name = GithubRepositoryName::new(repository_name)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let namespace: String = row
        .try_get("authority_namespace")
        .map_err(operation_error)?;
    let namespace = GithubRuntimeAuthorityNamespace::new(namespace)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let preparation_selection_tail = GithubRuntimeAuthorityPreparationSelectionTail::new(
        LogicalWorkSelectionId::from_uuid(uuid_column(row, "preparation_selection_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        LogicalActivationWorkerId::from_uuid(uuid_column(row, "preparation_selection_owner_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        LogicalActivationPreparationGeneration::new(positive_u64_column(
            row,
            "preparation_selection_generation",
        )?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        digest_column(row, "preparation_selection_descriptor_digest")?,
        timestamp_column(row, "preparation_selection_claimed_at_ms")?,
        timestamp_column(row, "preparation_selection_expires_at_ms")?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let activation_selection_tail = GithubRuntimeAuthorityActivationSelectionTail::new(
        LogicalWorkSelectionId::from_uuid(uuid_column(row, "activation_selection_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        LogicalActivationWorkerId::from_uuid(uuid_column(row, "activation_selection_owner_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        LogicalActivationGeneration::new(positive_u64_column(
            row,
            "activation_selection_generation",
        )?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        digest_column(row, "activation_selection_input_digest")?,
        timestamp_column(row, "activation_selection_claimed_at_ms")?,
        timestamp_column(row, "activation_selection_expires_at_ms")?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let materialization_selection_tail = GithubRuntimeAuthorityMaterializationSelectionTail::new(
        LogicalWorkSelectionId::from_uuid(uuid_column(row, "materialization_selection_id")?)
            .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        LogicalMaterializationWorkerId::from_uuid(uuid_column(
            row,
            "materialization_selection_owner_id",
        )?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        LogicalMaterializationGeneration::new(positive_u64_column(
            row,
            "materialization_selection_generation",
        )?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?,
        digest_column(row, "materialization_selection_descriptor_digest")?,
        timestamp_column(row, "materialization_selection_claimed_at_ms")?,
        timestamp_column(row, "materialization_selection_expires_at_ms")?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let identity = GithubRuntimeAuthorityIdentity::new(
        tenant,
        attempt_id,
        fencing_token,
        lease_id,
        timestamp_column(row, "lease_issued_at_ms")?,
        timestamp_column(row, "lease_expires_at_ms")?,
        run_id,
        job_id,
        runner_id,
        runner_session_id,
        session_epoch,
        runner_generation,
        runner_slot,
        job_ir_version,
        job_ir_size_bytes,
        digest_column(row, "job_ir_digest")?,
        repository_id,
        provider_connection_id,
        provider_installation_id,
        github_app_id,
        github_app_client_id,
        github_app_jwt_issuer_kind,
        github_repository_id,
        repository_name,
        namespace,
        digest_column(row, "policy_digest")?,
        digest_column(row, "issuer_fingerprint")?,
        digest_column(row, "configuration_fingerprint")?,
        preparation_selection_tail,
        activation_selection_tail,
        materialization_selection_tail,
        timestamp_column(row, "requested_at_ms")?,
        timestamp_column(row, "request_deadline_at_ms")?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let durable_issuer_value: String = row
        .try_get("github_app_jwt_issuer_value")
        .map_err(operation_error)?;
    if durable_issuer_value != identity.github_app_jwt_issuer_value()
        || identity.conservative_expiry().get()
            != row
                .try_get::<i64, _>("conservative_expiry_at_ms")
                .map_err(operation_error)?
    {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(identity)
}

fn decode_metadata(
    row: &PgRow,
    identity: GithubRuntimeAuthorityIdentity,
) -> Result<Option<GithubRuntimeAuthorityEnvelopeMetadata>, GithubRuntimeAuthorityStoreError> {
    let provider_expires_at: Option<i64> = row
        .try_get("provider_expires_at_ms")
        .map_err(operation_error)?;
    let safe_erase_after: Option<i64> = row
        .try_get("safe_erase_after_ms")
        .map_err(operation_error)?;
    let plaintext_size: Option<i64> = row
        .try_get("plaintext_size_bytes")
        .map_err(operation_error)?;
    let plaintext_schema: Option<i32> = row.try_get("plaintext_schema").map_err(operation_error)?;
    let plaintext_digest: Option<Vec<u8>> =
        row.try_get("plaintext_digest").map_err(operation_error)?;
    let aad_digest: Option<Vec<u8>> = row.try_get("aad_digest").map_err(operation_error)?;
    let presence = [
        safe_erase_after.is_some(),
        plaintext_size.is_some(),
        plaintext_schema.is_some(),
        plaintext_digest.is_some(),
        aad_digest.is_some(),
    ];
    if presence.iter().any(|present| *present != presence[0]) {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    if !presence[0] {
        if provider_expires_at.is_some() {
            return Err(GithubRuntimeAuthorityStoreError::CorruptData);
        }
        return Ok(None);
    }
    let plaintext_size_bytes = positive_u64_column(row, "plaintext_size_bytes")?;
    let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity,
        provider_expires_at.map(UnixMillis::new),
        plaintext_size_bytes,
        digest_column(row, "plaintext_digest")?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    if plaintext_schema.and_then(|value| u16::try_from(value).ok())
        != Some(metadata.plaintext_schema())
        || row
            .try_get::<Option<i64>, _>("safe_erase_after_ms")
            .map_err(operation_error)?
            != Some(metadata.safe_erase_after().get())
        || digest_column(row, "aad_digest")? != metadata.aad_digest()
    {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(Some(metadata))
}

fn decode_protected(
    row: &PgRow,
    identity: GithubRuntimeAuthorityIdentity,
) -> Result<ProtectedGithubRuntimeAuthority, GithubRuntimeAuthorityStoreError> {
    let metadata =
        decode_metadata(row, identity)?.ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
    let schema: i32 = row.try_get("envelope_schema").map_err(operation_error)?;
    let schema =
        u16::try_from(schema).map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let wrapping_key_id: String = row.try_get("wrapping_key_id").map_err(operation_error)?;
    let wrapping_key_id =
        KeyId::new(wrapping_key_id).map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let wrapped_data_key: Vec<u8> = row.try_get("wrapped_data_key").map_err(operation_error)?;
    let wrapped_data_key = WrappedDataKey::new(wrapping_key_id, wrapped_data_key)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let nonce: Vec<u8> = row.try_get("nonce").map_err(operation_error)?;
    let nonce: [u8; ENVELOPE_NONCE_BYTES] = nonce
        .try_into()
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    let ciphertext: Vec<u8> = row.try_get("ciphertext").map_err(operation_error)?;
    let envelope = EncryptedEnvelope::from_parts(schema, wrapped_data_key, nonce, ciphertext)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    ProtectedGithubRuntimeAuthority::new(metadata, envelope)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
}

fn decode_mint_claim(
    row: &PgRow,
) -> Result<ClaimedGithubRuntimeAuthorityMint, GithubRuntimeAuthorityStoreError> {
    if decode_state(row)? != GithubRuntimeAuthorityState::Claimed {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    let (attempt, fence) = decode_mint_history(row)?;
    Ok(ClaimedGithubRuntimeAuthorityMint {
        identity: decode_identity(row)?,
        owner: worker_column(row, "mint_claim_owner_id")?,
        fence,
        attempt,
        claimed_at: timestamp_column(row, "mint_claimed_at_ms")?,
        expires_at: timestamp_column(row, "mint_claim_expires_at_ms")?,
    })
}

fn decode_mint_history(
    row: &PgRow,
) -> Result<(u16, GithubRuntimeAuthorityClaimFence), GithubRuntimeAuthorityStoreError> {
    let attempt: i16 = row.try_get("mint_attempt_count").map_err(operation_error)?;
    let attempt = u16::try_from(attempt)
        .ok()
        .filter(|value| (1..=MAX_GITHUB_AUTHORITY_MINT_ATTEMPTS).contains(value))
        .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
    Ok((attempt, claim_fence_column(row, "mint_claim_fence")?))
}

fn decode_revocation_claim(
    row: &PgRow,
) -> Result<ClaimedGithubRuntimeAuthorityRevocation, GithubRuntimeAuthorityStoreError> {
    if decode_state(row)? != GithubRuntimeAuthorityState::RevokePending {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    let identity = decode_identity(row)?;
    let protected = decode_protected(row, identity)?;
    let attempt: i16 = row
        .try_get("revoke_attempt_count")
        .map_err(operation_error)?;
    let attempt = u16::try_from(attempt)
        .ok()
        .filter(|value| (1..=64).contains(value))
        .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
    ClaimedGithubRuntimeAuthorityRevocation::from_repository_parts(
        protected,
        worker_column(row, "revoke_claim_owner_id")?,
        claim_fence_column(row, "revoke_claim_fence")?,
        attempt,
        timestamp_column(row, "revoke_claimed_at_ms")?,
        timestamp_column(row, "revoke_claim_expires_at_ms")?,
    )
    .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
}

fn decode_receipt(
    row: &PgRow,
) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
    let identity = decode_identity(row)?;
    let state = decode_state(row)?;
    let terminal_reason = terminal_reason(row)?;
    let metadata = decode_metadata(row, identity.clone())?;
    let has_envelope = envelope_is_present(row)?;
    let disposition = decode_commit_disposition(row)?;
    let corruption = decode_corruption_kind(row)?;
    let protected_state = matches!(
        state,
        GithubRuntimeAuthorityState::Ready
            | GithubRuntimeAuthorityState::RevokePending
            | GithubRuntimeAuthorityState::Quarantined
    );
    if protected_state != (metadata.is_some() && has_envelope) {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    if metadata.is_some() != disposition.is_some()
        || (state == GithubRuntimeAuthorityState::Ready
            && disposition != Some(GithubRuntimeAuthorityCommitDisposition::Deliverable))
        || (state == GithubRuntimeAuthorityState::Quarantined
            || terminal_reason
                == Some(GithubRuntimeAuthorityTerminalReason::QuarantinedAuthorityExpired))
            != corruption.is_some()
    {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    if protected_state {
        let _protected = decode_protected(row, identity.clone())?;
    }
    match (state, terminal_reason, metadata.is_some(), has_envelope) {
        (
            GithubRuntimeAuthorityState::Claimed
            | GithubRuntimeAuthorityState::Minting
            | GithubRuntimeAuthorityState::MintRetryPending
            | GithubRuntimeAuthorityState::Indeterminate,
            None,
            false,
            false,
        )
        | (
            GithubRuntimeAuthorityState::Ready
            | GithubRuntimeAuthorityState::RevokePending
            | GithubRuntimeAuthorityState::Quarantined,
            None,
            true,
            true,
        )
        | (
            GithubRuntimeAuthorityState::Rejected,
            Some(
                GithubRuntimeAuthorityTerminalReason::ProviderMintRejected
                | GithubRuntimeAuthorityTerminalReason::ProviderMintRetryExpired,
            ),
            false,
            false,
        )
        | (
            GithubRuntimeAuthorityState::Revoked,
            Some(
                GithubRuntimeAuthorityTerminalReason::SupersededBeforeMint
                | GithubRuntimeAuthorityTerminalReason::RequestExpiredBeforeMint
                | GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired,
            ),
            false,
            false,
        )
        | (
            GithubRuntimeAuthorityState::Revoked,
            Some(
                GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed
                | GithubRuntimeAuthorityTerminalReason::ProviderAuthorityExpired
                | GithubRuntimeAuthorityTerminalReason::ConservativeAuthorityExpired
                | GithubRuntimeAuthorityTerminalReason::QuarantinedAuthorityExpired,
            ),
            true,
            false,
        ) => {}
        _ => return Err(GithubRuntimeAuthorityStoreError::CorruptData),
    }
    Ok(GithubRuntimeAuthorityReceipt {
        key: identity.key(),
        state,
        updated_at: timestamp_column(row, "state_updated_at_ms")?,
        terminal_reason,
    })
}

fn envelope_is_present(row: &PgRow) -> Result<bool, GithubRuntimeAuthorityStoreError> {
    let envelope_schema: Option<i32> = row.try_get("envelope_schema").map_err(operation_error)?;
    let wrapping_key_id: Option<String> =
        row.try_get("wrapping_key_id").map_err(operation_error)?;
    let wrapped_data_key: Option<Vec<u8>> =
        row.try_get("wrapped_data_key").map_err(operation_error)?;
    let nonce: Option<Vec<u8>> = row.try_get("nonce").map_err(operation_error)?;
    let ciphertext: Option<Vec<u8>> = row.try_get("ciphertext").map_err(operation_error)?;
    let presence = [
        envelope_schema.is_some(),
        wrapping_key_id.is_some(),
        wrapped_data_key.is_some(),
        nonce.is_some(),
        ciphertext.is_some(),
    ];
    if presence.iter().any(|present| *present != presence[0]) {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(presence[0])
}

fn decode_state(
    row: &PgRow,
) -> Result<GithubRuntimeAuthorityState, GithubRuntimeAuthorityStoreError> {
    let state: String = row.try_get("state").map_err(operation_error)?;
    match state.as_str() {
        "claimed" => Ok(GithubRuntimeAuthorityState::Claimed),
        "minting" => Ok(GithubRuntimeAuthorityState::Minting),
        "mint_retry_pending" => Ok(GithubRuntimeAuthorityState::MintRetryPending),
        "indeterminate" => Ok(GithubRuntimeAuthorityState::Indeterminate),
        "ready" => Ok(GithubRuntimeAuthorityState::Ready),
        "revoke_pending" => Ok(GithubRuntimeAuthorityState::RevokePending),
        "quarantined" => Ok(GithubRuntimeAuthorityState::Quarantined),
        "rejected" => Ok(GithubRuntimeAuthorityState::Rejected),
        "revoked" => Ok(GithubRuntimeAuthorityState::Revoked),
        _ => Err(GithubRuntimeAuthorityStoreError::CorruptData),
    }
}

const fn runtime_authority_state_str(state: GithubRuntimeAuthorityState) -> &'static str {
    match state {
        GithubRuntimeAuthorityState::Claimed => "claimed",
        GithubRuntimeAuthorityState::Minting => "minting",
        GithubRuntimeAuthorityState::MintRetryPending => "mint_retry_pending",
        GithubRuntimeAuthorityState::Indeterminate => "indeterminate",
        GithubRuntimeAuthorityState::Ready => "ready",
        GithubRuntimeAuthorityState::RevokePending => "revoke_pending",
        GithubRuntimeAuthorityState::Quarantined => "quarantined",
        GithubRuntimeAuthorityState::Rejected => "rejected",
        GithubRuntimeAuthorityState::Revoked => "revoked",
    }
}

fn terminal_reason(
    row: &PgRow,
) -> Result<Option<GithubRuntimeAuthorityTerminalReason>, GithubRuntimeAuthorityStoreError> {
    let value: Option<String> = row.try_get("terminal_reason").map_err(operation_error)?;
    value
        .map(|value| match value.as_str() {
            "superseded_before_mint" => {
                Ok(GithubRuntimeAuthorityTerminalReason::SupersededBeforeMint)
            }
            "request_expired_before_mint" => {
                Ok(GithubRuntimeAuthorityTerminalReason::RequestExpiredBeforeMint)
            }
            "provider_mint_rejected" => {
                Ok(GithubRuntimeAuthorityTerminalReason::ProviderMintRejected)
            }
            "provider_mint_retry_expired" => {
                Ok(GithubRuntimeAuthorityTerminalReason::ProviderMintRetryExpired)
            }
            "provider_revocation_confirmed" => {
                Ok(GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed)
            }
            "provider_authority_expired" => {
                Ok(GithubRuntimeAuthorityTerminalReason::ProviderAuthorityExpired)
            }
            "conservative_authority_expired" => {
                Ok(GithubRuntimeAuthorityTerminalReason::ConservativeAuthorityExpired)
            }
            "indeterminate_authority_expired" => {
                Ok(GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired)
            }
            "quarantined_authority_expired" => {
                Ok(GithubRuntimeAuthorityTerminalReason::QuarantinedAuthorityExpired)
            }
            _ => Err(GithubRuntimeAuthorityStoreError::CorruptData),
        })
        .transpose()
}

const fn runtime_authority_terminal_reason_str(
    reason: GithubRuntimeAuthorityTerminalReason,
) -> &'static str {
    match reason {
        GithubRuntimeAuthorityTerminalReason::SupersededBeforeMint => "superseded_before_mint",
        GithubRuntimeAuthorityTerminalReason::RequestExpiredBeforeMint => {
            "request_expired_before_mint"
        }
        GithubRuntimeAuthorityTerminalReason::ProviderMintRejected => "provider_mint_rejected",
        GithubRuntimeAuthorityTerminalReason::ProviderMintRetryExpired => {
            "provider_mint_retry_expired"
        }
        GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed => {
            "provider_revocation_confirmed"
        }
        GithubRuntimeAuthorityTerminalReason::ProviderAuthorityExpired => {
            "provider_authority_expired"
        }
        GithubRuntimeAuthorityTerminalReason::ConservativeAuthorityExpired => {
            "conservative_authority_expired"
        }
        GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired => {
            "indeterminate_authority_expired"
        }
        GithubRuntimeAuthorityTerminalReason::QuarantinedAuthorityExpired => {
            "quarantined_authority_expired"
        }
    }
}

fn decode_commit_disposition(
    row: &PgRow,
) -> Result<Option<GithubRuntimeAuthorityCommitDisposition>, GithubRuntimeAuthorityStoreError> {
    let value: Option<String> = row.try_get("commit_disposition").map_err(operation_error)?;
    value
        .map(|value| match value.as_str() {
            "deliverable" => Ok(GithubRuntimeAuthorityCommitDisposition::Deliverable),
            "revoke_only" => Ok(GithubRuntimeAuthorityCommitDisposition::RevokeOnly),
            _ => Err(GithubRuntimeAuthorityStoreError::CorruptData),
        })
        .transpose()
}

fn commit_disposition_str(disposition: GithubRuntimeAuthorityCommitDisposition) -> &'static str {
    match disposition {
        GithubRuntimeAuthorityCommitDisposition::Deliverable => "deliverable",
        GithubRuntimeAuthorityCommitDisposition::RevokeOnly => "revoke_only",
    }
}

fn decode_corruption_kind(
    row: &PgRow,
) -> Result<Option<GithubRuntimeAuthorityCorruptionKind>, GithubRuntimeAuthorityStoreError> {
    let value: Option<String> = row.try_get("quarantine_kind").map_err(operation_error)?;
    value
        .map(|value| match value.as_str() {
            "invalid_envelope" => Ok(GithubRuntimeAuthorityCorruptionKind::InvalidEnvelope),
            "unsupported_envelope_schema" => {
                Ok(GithubRuntimeAuthorityCorruptionKind::UnsupportedEnvelopeSchema)
            }
            "envelope_authentication_failed" => {
                Ok(GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed)
            }
            "invalid_wrapped_data_key" => {
                Ok(GithubRuntimeAuthorityCorruptionKind::InvalidWrappedDataKey)
            }
            "unknown_wrapping_key" => Ok(GithubRuntimeAuthorityCorruptionKind::UnknownWrappingKey),
            "retired_wrapping_key" => Ok(GithubRuntimeAuthorityCorruptionKind::RetiredWrappingKey),
            "cryptographic_failure" => {
                Ok(GithubRuntimeAuthorityCorruptionKind::CryptographicFailure)
            }
            _ => Err(GithubRuntimeAuthorityStoreError::CorruptData),
        })
        .transpose()
}

fn decode_inspection(
    row: &PgRow,
    _observed_at: UnixMillis,
) -> Result<GithubRuntimeAuthorityInspection, GithubRuntimeAuthorityStoreError> {
    let receipt = decode_receipt(row)?;
    let (mint_attempts, _) = decode_mint_history(row)?;
    let state = receipt.state();
    let next_action_at = match state {
        GithubRuntimeAuthorityState::Claimed => {
            optional_timestamp_column(row, "mint_claim_expires_at_ms")?
        }
        GithubRuntimeAuthorityState::Minting => {
            optional_timestamp_column(row, "request_deadline_at_ms")?
        }
        GithubRuntimeAuthorityState::MintRetryPending => {
            optional_timestamp_column(row, "next_mint_at_ms")?
        }
        GithubRuntimeAuthorityState::Indeterminate => {
            optional_timestamp_column(row, "conservative_expiry_at_ms")?
        }
        GithubRuntimeAuthorityState::Ready => {
            optional_timestamp_column(row, "provider_expires_at_ms")?.and_then(|expires_at| {
                expires_at
                    .get()
                    .checked_sub(crate::GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS)
                    .map(UnixMillis::new)
            })
        }
        GithubRuntimeAuthorityState::RevokePending => {
            optional_timestamp_column(row, "revoke_claim_expires_at_ms")?
                .or(optional_timestamp_column(row, "next_revoke_at_ms")?)
        }
        GithubRuntimeAuthorityState::Quarantined => {
            optional_timestamp_column(row, "safe_erase_after_ms")?
        }
        GithubRuntimeAuthorityState::Rejected | GithubRuntimeAuthorityState::Revoked => None,
    };
    Ok(GithubRuntimeAuthorityInspection {
        receipt,
        mint_attempts,
        next_action_at,
        commit_disposition: decode_commit_disposition(row)?,
        provider_expiry_known: optional_timestamp_column(row, "provider_expires_at_ms")?.is_some(),
        safe_erase_after: optional_timestamp_column(row, "safe_erase_after_ms")?,
        corruption: decode_corruption_kind(row)?,
    })
}

fn timestamp_column(
    row: &PgRow,
    column: &str,
) -> Result<UnixMillis, GithubRuntimeAuthorityStoreError> {
    let value: i64 = row.try_get(column).map_err(operation_error)?;
    if value < 0 {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(UnixMillis::new(value))
}

fn optional_timestamp_column(
    row: &PgRow,
    column: &str,
) -> Result<Option<UnixMillis>, GithubRuntimeAuthorityStoreError> {
    let value: Option<i64> = row.try_get(column).map_err(operation_error)?;
    value
        .map(|value| {
            if value < 0 {
                return Err(GithubRuntimeAuthorityStoreError::CorruptData);
            }
            Ok(UnixMillis::new(value))
        })
        .transpose()
}

fn uuid_column(row: &PgRow, column: &str) -> Result<Uuid, GithubRuntimeAuthorityStoreError> {
    let value: Uuid = row.try_get(column).map_err(operation_error)?;
    if value.is_nil() {
        return Err(GithubRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(value)
}

fn optional_uuid_column(
    row: &PgRow,
    column: &str,
) -> Result<Option<Uuid>, GithubRuntimeAuthorityStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn worker_column(
    row: &PgRow,
    column: &str,
) -> Result<GithubRuntimeAuthorityWorkerId, GithubRuntimeAuthorityStoreError> {
    GithubRuntimeAuthorityWorkerId::from_uuid(uuid_column(row, column)?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
}

fn claim_fence_column(
    row: &PgRow,
    column: &str,
) -> Result<GithubRuntimeAuthorityClaimFence, GithubRuntimeAuthorityStoreError> {
    GithubRuntimeAuthorityClaimFence::new(positive_u64_column(row, column)?)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
}

fn positive_u64_column(row: &PgRow, column: &str) -> Result<u64, GithubRuntimeAuthorityStoreError> {
    let value: i64 = row.try_get(column).map_err(operation_error)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)
}

fn digest_column(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, GithubRuntimeAuthorityStoreError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_digest_column(
    row: &PgRow,
    column: &str,
) -> Result<Option<Sha256Digest>, GithubRuntimeAuthorityStoreError> {
    let bytes: Option<Vec<u8>> = row.try_get(column).map_err(operation_error)?;
    bytes
        .map(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)?;
            Ok(Sha256Digest::from_bytes(bytes))
        })
        .transpose()
}

fn positive_i64(value: u64) -> Result<i64, GithubRuntimeAuthorityStoreError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)
}

fn fencing_i64(value: FencingToken) -> i64 {
    i64::try_from(value.get()).expect("validated fencing token fits in i64")
}

fn operation_error(error: sqlx::Error) -> GithubRuntimeAuthorityStoreError {
    GithubRuntimeAuthorityStoreError::operation(error)
}

fn is_revoke_owner_conflict(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        == Some("github_runtime_authority_revoke_owner_unique")
}

#[cfg(test)]
mod tests {
    use super::github_manifest_origin_is_closed;

    #[test]
    fn manifest_origins_are_closed_and_exhaustive() {
        for origin in ["provider_delivery", "scheduled_fire", "workflow_rerun"] {
            assert!(github_manifest_origin_is_closed(origin));
        }
        for origin in ["", "manual", "workflow_rerun_unsealed"] {
            assert!(!github_manifest_origin_is_closed(origin));
        }
    }
}
