use async_trait::async_trait;
use automata_ci_core::{JobAuthorityProfile, RunId, Sha256Digest, UnixMillis, WorkflowId};
use sqlx::{AssertSqlSafe, Postgres, Row as _, Transaction, ValueRef as _, postgres::PgRow};
use uuid::Uuid;

use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptManifestPinnedGithubRepositoryDispatch,
    AdmissionObject, AuthenticatedGithubDeliveryClaim, GithubAuthenticatedEvent,
    GithubAuthenticatedEventKind, GithubCheckHeadSha, GithubCheckName, GithubCheckSubjectId,
    GithubCheckSubjectKey, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins, GithubProviderRunnerPolicyObject,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryDispatchEvidenceRepository, GithubRepositoryDispatchResolution,
    GithubRepositoryDispatchResolutionAuthority, GithubRepositoryName,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthoritySelector, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository,
    GithubSubjectEvidenceStoreError, GithubWorkflowRunSubjectEvidence, LogicalWorkflowInvocationId,
    ManifestPinnedGithubDeliveryEvidence, ManifestPinnedGithubDeliveryReceipt, ObjectKey,
    PendingGithubRepositoryDispatchEvidence, PendingGithubRepositoryDispatchReceipt,
    ProviderConnectionId, ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RecordGithubWorkflowRunSubjectEvidence, RepositoryId,
    ResolveGithubRepositoryDispatch, TenantScope, ValidateGithubWorkflowRunSubjectEvidenceReplay,
    WorkflowRuntimePolicyRevision, WorkflowSnapshotId,
};

use super::{PostgresStore, durable_schema::current_durable_schemas, pg_bigint};

const AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION: i16 = 1;

const fn authenticated_event_envelope_schema_is_current(version: i16) -> bool {
    version == AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION
}

fn workflow_plan_schema_is_current(version: i16) -> bool {
    version == current_durable_schemas().workflow_plan_i16
}

#[derive(Debug)]
struct CurrentManifestPin {
    manifest: GithubProviderManifest,
    checks_authority: GithubServerServiceAuthoritySelector,
    private_source_authority: Option<GithubServerServiceAuthoritySelector>,
}

#[derive(Debug)]
struct DurableAcceptance {
    receipt: ManifestPinnedGithubDeliveryReceipt,
    tenant_id: String,
    provider: String,
    connection_id: Uuid,
    installation_id: i64,
    github_repository_id: i64,
    github_repository_name: String,
    repository_visibility: String,
    delivery_key: String,
    request_digest: Sha256Digest,
    raw_event_digest: Sha256Digest,
    raw_event_object_key: String,
    raw_event_size_bytes: i64,
    raw_event_media_type: String,
    event_envelope_schema: i16,
    event_registry_schema: i16,
    event_envelope_digest: Sha256Digest,
    event_envelope_bytes: Vec<u8>,
    event_envelope_media_type: String,
}

#[derive(Debug)]
struct DurablePendingAcceptance {
    receipt: PendingGithubRepositoryDispatchReceipt,
    tenant_id: String,
    provider: String,
    connection_id: Uuid,
    installation_id: i64,
    github_repository_id: i64,
    github_repository_name: String,
    repository_visibility: String,
    delivery_key: String,
    request_digest: Sha256Digest,
    raw_event_digest: Sha256Digest,
    raw_event_object_key: String,
    raw_event_size_bytes: i64,
    raw_event_media_type: String,
    event_envelope_schema: i16,
    event_registry_schema: i16,
    event_envelope_digest: Sha256Digest,
    event_envelope_bytes: Vec<u8>,
    event_envelope_media_type: String,
}

#[async_trait]
impl GithubSubjectEvidenceRepository for PostgresStore {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let pin = load_matching_current_manifest(&mut transaction, &request).await?;
        let proposed_delivery_id = Uuid::new_v4();
        let proposed_subject_id = Uuid::new_v4();
        let inserted = if let Some(pin) = pin.as_ref() {
            insert_generic_inbox(&mut transaction, proposed_delivery_id, request.delivery())
                .await?
                .then_some(pin)
        } else {
            None
        };

        if let Some(pin) = inserted {
            insert_delivery_evidence(
                &mut transaction,
                proposed_delivery_id,
                proposed_subject_id,
                &request,
                pin,
            )
            .await?;
            insert_queued_check(
                &mut transaction,
                proposed_subject_id,
                proposed_delivery_id,
                &request,
                pin,
            )
            .await?;

            let receipt = ManifestPinnedGithubDeliveryReceipt::from_durable_parts(
                evidence_from_request(proposed_delivery_id, proposed_subject_id, &request, pin)?,
            );
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }

        let durable = load_acceptance_by_replay_key(&mut transaction, &request)
            .await?
            .ok_or(GithubSubjectEvidenceStoreError::AuthorityRejected)?;
        if !acceptance_matches(&durable, &request) {
            return Err(GithubSubjectEvidenceStoreError::ReplayConflict);
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(durable.receipt)
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        load_delivery_evidence(&self.pool, tenant, delivery_id)
            .await?
            .ok_or(GithubSubjectEvidenceStoreError::NotFound)
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        run_id: RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        load_run_evidence(&self.pool, tenant, repository_id, run_id)
            .await?
            .ok_or(GithubSubjectEvidenceStoreError::NotFound)
    }
}

#[async_trait]
impl GithubRepositoryDispatchEvidenceRepository for PostgresStore {
    async fn accept_manifest_pinned_github_repository_dispatch(
        &self,
        request: AcceptManifestPinnedGithubRepositoryDispatch,
    ) -> Result<PendingGithubRepositoryDispatchReceipt, GithubSubjectEvidenceStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let pin = load_matching_current_manifest_for_dispatch(&mut transaction, &request).await?;
        let proposed_delivery_id = Uuid::new_v4();
        let inserted = if let Some(pin) = pin.as_ref() {
            insert_generic_inbox(&mut transaction, proposed_delivery_id, request.delivery())
                .await?
                .then_some(pin)
        } else {
            None
        };

        if let Some(pin) = inserted {
            insert_pending_repository_dispatch(
                &mut transaction,
                proposed_delivery_id,
                &request,
                pin,
            )
            .await?;
            let receipt = PendingGithubRepositoryDispatchReceipt::from_durable_parts(
                pending_evidence_from_request(proposed_delivery_id, &request, pin)?,
            );
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }

        let durable = load_pending_acceptance_by_replay_key(&mut transaction, &request)
            .await?
            .ok_or(GithubSubjectEvidenceStoreError::AuthorityRejected)?;
        if !pending_acceptance_matches(&durable, &request) {
            return Err(GithubSubjectEvidenceStoreError::ReplayConflict);
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(durable.receipt)
    }

    async fn load_pending_github_repository_dispatch_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<PendingGithubRepositoryDispatchEvidence, GithubSubjectEvidenceStoreError> {
        load_pending_repository_dispatch(&self.pool, tenant, delivery_id)
            .await?
            .ok_or(GithubSubjectEvidenceStoreError::NotFound)
    }

    async fn resolve_github_repository_dispatch(
        &self,
        request: ResolveGithubRepositoryDispatch,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        require_current_repository_dispatch_claim(&mut transaction, &request).await?;
        let durable_pending = load_pending_repository_dispatch(
            &mut *transaction,
            request.pending().tenant(),
            request.pending().delivery_id(),
        )
        .await?
        .ok_or(GithubSubjectEvidenceStoreError::NotFound)?;
        if &durable_pending != request.pending() {
            return Err(GithubSubjectEvidenceStoreError::ReplayConflict);
        }

        if let Some(existing) = load_delivery_evidence(
            &mut *transaction,
            request.pending().tenant(),
            request.pending().delivery_id(),
        )
        .await?
        {
            if existing.repository_dispatch_resolution() != Some(request.resolution())
                || existing.authenticated_event() != request.pending().event()
                || existing.manifest() != request.pending().manifest()
            {
                return Err(GithubSubjectEvidenceStoreError::ReplayConflict);
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(existing);
        }

        let subject_id = Uuid::new_v4();
        insert_resolved_repository_dispatch_evidence(&mut transaction, subject_id, &request)
            .await?;
        insert_resolved_repository_dispatch_check(&mut transaction, subject_id, &request).await?;
        let evidence = resolved_repository_dispatch_evidence(subject_id, &request)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(evidence)
    }
}

/// Links the delivery's database-derived Check and inserts its run receipt
/// inside the caller's logical-admission transaction.
#[allow(clippy::too_many_lines)] // One exact SQL statement binds the full admission aggregate.
pub(crate) async fn record_github_workflow_run_subject_evidence_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordGithubWorkflowRunSubjectEvidence,
) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
    require_exact_github_record_authority(transaction, request).await?;
    let subject_id = ensure_workflow_check_subject(transaction, request).await?;
    let subject_id = link_exact_check_to_run(transaction, request, subject_id).await?;
    let schemas = current_durable_schemas();
    let inserted = sqlx::query(
        r"
        INSERT INTO github_workflow_run_subject_evidence (
            tenant_id, repository_id, workflow_id, snapshot_id, run_id,
            root_invocation_id, provider_delivery_id,
            provider_delivery_idempotency_key, admission_claim_owner_id,
            admission_claim_attempt, admission_claim_fence,
            admission_claimed_at_ms, admission_claim_expires_at_ms,
            github_check_subject_id,
            github_check_head_sha, workflow_path, source_digest, event_name,
            event_digest, git_ref, workflow_plan_schema, plan_digest,
            logical_admission_digest, subject_evidence_sha256, admitted_at_ms
        )
        SELECT
            $1, $2, $3, $4, $5, $6, $7, $18, $19, $20, $21, $22, $23,
            subject.id, subject.head_sha,
            workflow.path, snapshot.source_digest, run.event_name,
            run.event_digest, run.git_ref, run.plan_schema::SMALLINT,
            run.plan_digest, marker.admission_digest,
            automata_github_workflow_run_subject_evidence_digest(
                $1, $2, $3, $4, $5, $6, $7, $18, $19, $20, $21, $22, $23,
                subject.id, subject.head_sha,
                evidence.provider_connection_id,
                evidence.provider_installation_id,
                evidence.github_repository_id,
                evidence.github_repository_owner_id,
                evidence.github_repository_name,
                evidence.repository_visibility,
                evidence.provider_manifest_revision,
                evidence.provider_manifest_digest,
                evidence.authenticated_webhook_verifier_fingerprint_sha256,
                evidence.authenticated_webhook_verifier_revision,
                evidence.checks_authority_id,
                evidence.checks_authority_identity_digest,
                evidence.checks_authority_app_configuration_revision,
                evidence.checks_authority_policy_revision,
                evidence.private_source_authority_id,
                evidence.private_source_authority_identity_digest,
                evidence.private_source_authority_app_configuration_revision,
                evidence.private_source_authority_policy_revision,
                inbox.request_digest, inbox.raw_event_digest,
                inbox.accepted_at_ms, workflow.path, snapshot.source_digest,
                run.event_name, run.event_digest, run.git_ref,
                run.plan_schema::SMALLINT, run.plan_digest,
                marker.admission_digest, run.created_at_ms
            ),
            run.created_at_ms
        FROM github_provider_delivery_evidence AS evidence
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN repositories AS repository
          ON repository.tenant_id = evidence.tenant_id
         AND repository.id = evidence.repository_id
        JOIN github_check_subjects AS subject
          ON subject.id = $8
         AND subject.tenant_id = evidence.tenant_id
        JOIN workflow_runs AS run
          ON run.repository_id = evidence.repository_id
         AND run.id = $5
        JOIN workflow_definitions AS workflow
          ON workflow.repository_id = run.repository_id
         AND workflow.id = run.workflow_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_admission_receipts AS admission_receipt
         ON admission_receipt.tenant_id = evidence.tenant_id
         AND admission_receipt.idempotency_kind = 'provider_delivery'
         AND admission_receipt.idempotency_key = $18
         AND admission_receipt.request_digest = marker.admission_digest
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        WHERE evidence.tenant_id = $1
          AND evidence.repository_id = $2
          AND evidence.provider_delivery_id = $7
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              evidence.github_repository_id::TEXT
          AND repository.owner = split_part(evidence.github_repository_name, '/', 1)
          AND repository.name = split_part(evidence.github_repository_name, '/', 2)
          AND admission_receipt.github_subject_evidence_required
          AND admission_receipt.repository_id = $2
          AND admission_receipt.run_id = $5
          AND admission_receipt.committed_at_ms = $15
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $19
          AND inbox.attempt_count = $20
          AND inbox.claim_fence = $21
          AND inbox.claimed_at_ms = $22
          AND inbox.claim_expires_at_ms = $23
          AND run.workflow_id = $3
          AND run.snapshot_id = $4
          AND marker.root_invocation_id = $6
          AND subject.id = $8
          AND subject.provider_delivery_id = $7
          AND subject.workflow_run_id = $5
          AND subject.linked_at_ms = $15
          AND subject.desired_state = 'in_progress'
          AND subject.desired_conclusion IS NULL
          AND subject.terminal_cause IS NULL
          AND subject.desired_revision = 2
          AND subject.desired_updated_at_ms = $15
          AND subject.head_sha = $9
          AND evidence.github_check_head_sha = $9
          AND run.head_sha = $9
          AND workflow.path = $10
          AND subject.subject_key = workflow.path
          AND (
              manifest.workflow_selection_kind = 'all_direct'
              AND EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_inventories AS inventory
                  JOIN provider_delivery_workflow_inventory_entries AS entry
                    ON entry.inbox_id = inventory.inbox_id
                   AND entry.tenant_id = inventory.tenant_id
                  WHERE inventory.inbox_id = evidence.provider_delivery_id
                    AND inventory.tenant_id = evidence.tenant_id
                    AND inventory.manifest_digest = manifest.manifest_digest
                    AND entry.workflow_path = workflow.path
                    AND entry.source_state = 'ready'
                    AND entry.source_digest = snapshot.source_digest
              )
          )
          AND snapshot.source_digest = $11
          AND run.event_name = $12
          AND run.event_name = COALESCE(
              evidence.authenticated_event_name,
              manifest.event_name
          )
          AND run.event_digest = $13
          AND run.event_digest = inbox.raw_event_digest
          AND run.git_ref = $14
          AND run.git_ref = COALESCE(
              evidence.authenticated_event_git_ref,
              manifest.git_ref
          )
          AND run.admission_epoch = $25
          AND run.plan_schema = $24
          AND run.plan_schema = invocation.plan_schema
          AND run.plan_digest = $16
          AND run.plan_digest = invocation.plan_digest
          AND marker.admission_digest = $17
          AND run.created_at_ms = $15
          AND run.created_at_ms >= $22
          AND run.created_at_ms < $23
          AND marker.admitted_at_ms = $15
          AND run.created_at_ms >= inbox.accepted_at_ms
        RETURNING tenant_id, repository_id, workflow_id, snapshot_id, run_id,
                  root_invocation_id, provider_delivery_id,
                  provider_delivery_idempotency_key, admission_claim_owner_id,
                  admission_claim_attempt, admission_claim_fence,
                  admission_claimed_at_ms, admission_claim_expires_at_ms,
                  github_check_subject_id, github_check_head_sha,
                  workflow_path, source_digest, event_name, event_digest,
                  git_ref, workflow_plan_schema, plan_digest,
                  logical_admission_digest, subject_evidence_sha256,
                  admitted_at_ms
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.workflow_id().as_uuid())
    .bind(request.snapshot_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.root_invocation_id().as_uuid())
    .bind(request.delivery_id().as_uuid())
    .bind(subject_id.as_uuid())
    .bind(request.head_sha().as_bytes().as_slice())
    .bind(request.workflow_path().as_str())
    .bind(request.source_digest().as_bytes().as_slice())
    .bind(request.event_name())
    .bind(request.event_digest().as_bytes().as_slice())
    .bind(request.git_ref())
    .bind(request.admitted_at().get())
    .bind(request.plan_digest().as_bytes().as_slice())
    .bind(request.logical_admission_digest().as_bytes().as_slice())
    .bind(request.provider_delivery_idempotency_key())
    .bind(request.admission_claim().claim().owner().as_uuid())
    .bind(i16::try_from(request.admission_claim().attempt()).expect("attempt fits SMALLINT"))
    .bind(pg_bigint(request.admission_claim().claim().fence()))
    .bind(request.admission_claim().claimed_at().get())
    .bind(request.admission_claim().expires_at().get())
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.admission_epoch_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubSubjectEvidenceStoreError::AuthorityRejected)?;
    decode_run_evidence(&inserted)
}

/// Validates an existing receipt during exact logical-admission replay without
/// inserting, linking, or backfilling any state.
pub(crate) async fn validate_github_workflow_run_subject_evidence_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ValidateGithubWorkflowRunSubjectEvidenceReplay,
) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
    require_exact_github_replay_authority(transaction, request).await?;
    let command = automata_ci_store::adapter_spi::github_subject_evidence_replay_command(request);
    let existing = load_run_evidence(
        &mut **transaction,
        command.tenant(),
        command.repository().id(),
        command.run_id(),
    )
    .await?
    .ok_or(GithubSubjectEvidenceStoreError::NotFound)?;
    if !automata_ci_store::adapter_spi::github_subject_evidence_matches_logical_admission(
        existing.request(),
        request.current_claim().claim().delivery_id(),
        request.durable_admitted_at(),
        command,
    ) {
        return Err(GithubSubjectEvidenceStoreError::ReplayConflict);
    }
    Ok(existing)
}

async fn require_exact_github_record_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordGithubWorkflowRunSubjectEvidence,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let claim = request.admission_claim();
    let exact = sqlx::query_scalar::<_, bool>(
        r"
        SELECT TRUE
        FROM github_provider_delivery_evidence AS evidence
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
         AND manifest.webhook_verifier_fingerprint_sha256 =
             evidence.authenticated_webhook_verifier_fingerprint_sha256
         AND manifest.webhook_verifier_revision =
             evidence.authenticated_webhook_verifier_revision
        JOIN repositories AS repository
          ON repository.tenant_id = evidence.tenant_id
         AND repository.id = evidence.repository_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = evidence.tenant_id
         AND admission_receipt.idempotency_kind = 'provider_delivery'
         AND admission_receipt.idempotency_key = $7
         AND admission_receipt.request_digest = $5
        WHERE evidence.tenant_id = $1
          AND evidence.repository_id = $2
          AND evidence.provider_delivery_id = $4
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              evidence.github_repository_id::TEXT
          AND repository.owner = split_part(evidence.github_repository_name, '/', 1)
          AND repository.name = split_part(evidence.github_repository_name, '/', 2)
          AND admission_receipt.github_subject_evidence_required
          AND admission_receipt.repository_id = $2
          AND admission_receipt.run_id = $3
          AND admission_receipt.committed_at_ms = $6
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $8
          AND inbox.attempt_count = $9
          AND inbox.claim_fence = $10
          AND inbox.claimed_at_ms = $11
          AND inbox.claim_expires_at_ms = $12
          AND $6 >= $11
          AND $6 < $12
        FOR SHARE OF evidence, inbox, manifest, repository, admission_receipt
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.delivery_id().as_uuid())
    .bind(request.logical_admission_digest().as_bytes().as_slice())
    .bind(request.admitted_at().get())
    .bind(request.provider_delivery_idempotency_key())
    .bind(claim.claim().owner().as_uuid())
    .bind(i16::try_from(claim.attempt()).expect("attempt fits SMALLINT"))
    .bind(pg_bigint(claim.claim().fence()))
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact == Some(true) {
        Ok(())
    } else {
        Err(GithubSubjectEvidenceStoreError::AuthorityRejected)
    }
}

async fn require_exact_github_replay_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ValidateGithubWorkflowRunSubjectEvidenceReplay,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let command = automata_ci_store::adapter_spi::github_subject_evidence_replay_command(request);
    let claim = request.current_claim();
    let exact = sqlx::query_scalar::<_, bool>(
        r"
        SELECT TRUE
        FROM github_provider_delivery_evidence AS evidence
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
         AND manifest.webhook_verifier_fingerprint_sha256 =
             evidence.authenticated_webhook_verifier_fingerprint_sha256
         AND manifest.webhook_verifier_revision =
             evidence.authenticated_webhook_verifier_revision
        JOIN repositories AS repository
          ON repository.tenant_id = evidence.tenant_id
         AND repository.id = evidence.repository_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = evidence.tenant_id
         AND admission_receipt.idempotency_kind = 'provider_delivery'
         AND admission_receipt.idempotency_key = $7
         AND admission_receipt.request_digest = $5
        WHERE evidence.tenant_id = $1
          AND evidence.repository_id = $2
          AND evidence.provider_delivery_id = $4
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              evidence.github_repository_id::TEXT
          AND repository.owner = split_part(evidence.github_repository_name, '/', 1)
          AND repository.name = split_part(evidence.github_repository_name, '/', 2)
          AND admission_receipt.github_subject_evidence_required
          AND admission_receipt.repository_id = $2
          AND admission_receipt.run_id = $3
          AND admission_receipt.committed_at_ms = $6
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $8
          AND inbox.attempt_count = $9
          AND inbox.claim_fence = $10
          AND inbox.claimed_at_ms = $11
          AND inbox.claim_expires_at_ms = $12
          AND $13 >= $11
          AND $13 < $12
        FOR SHARE OF evidence, inbox, manifest, repository, admission_receipt
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(claim.claim().delivery_id().as_uuid())
    .bind(command.request_digest().as_bytes().as_slice())
    .bind(request.durable_admitted_at().get())
    .bind(command.idempotency().key())
    .bind(claim.claim().owner().as_uuid())
    .bind(i16::try_from(claim.attempt()).expect("attempt fits SMALLINT"))
    .bind(pg_bigint(claim.claim().fence()))
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(request.observed_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact == Some(true) {
        Ok(())
    } else {
        Err(GithubSubjectEvidenceStoreError::ReplayConflict)
    }
}

async fn ensure_workflow_check_subject(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordGithubWorkflowRunSubjectEvidence,
) -> Result<GithubCheckSubjectId, GithubSubjectEvidenceStoreError> {
    insert_all_direct_workflow_check_subject(transaction, request).await?;
    load_queued_workflow_check_subject(transaction, request).await
}

async fn insert_all_direct_workflow_check_subject(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordGithubWorkflowRunSubjectEvidence,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let candidate_id = Uuid::new_v4();
    let external_id = format!("automata-check:{candidate_id}");
    sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        )
        SELECT $1, evidence.tenant_id, evidence.repository_id,
               evidence.provider_delivery_id, entry.workflow_path,
               evidence.provider_connection_id, evidence.provider_installation_id,
               evidence.github_repository_id, manifest.github_app_id,
               evidence.github_check_head_sha, manifest.check_name, $2,
               inbox.accepted_at_ms, inbox.accepted_at_ms
        FROM github_provider_delivery_evidence AS evidence
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        JOIN provider_delivery_workflow_inventories AS inventory
          ON inventory.inbox_id = evidence.provider_delivery_id
         AND inventory.tenant_id = evidence.tenant_id
         AND inventory.manifest_digest = manifest.manifest_digest
        JOIN provider_delivery_workflow_inventory_entries AS entry
          ON entry.inbox_id = inventory.inbox_id
         AND entry.tenant_id = inventory.tenant_id
        WHERE evidence.tenant_id = $3
          AND evidence.repository_id = $4
          AND evidence.provider_delivery_id = $5
          AND manifest.workflow_selection_kind = 'all_direct'
          AND entry.workflow_path = $6
          AND entry.source_state = 'ready'
          AND entry.source_digest = $7
          AND evidence.github_check_head_sha = $8
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $9
          AND inbox.attempt_count = $10
          AND inbox.claim_fence = $11
          AND inbox.claimed_at_ms = $12
          AND inbox.claim_expires_at_ms = $13
          AND $14 >= $12
          AND $14 < $13
        ON CONFLICT (provider_delivery_id, subject_key) DO NOTHING
        ",
    )
    .bind(candidate_id)
    .bind(external_id)
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.delivery_id().as_uuid())
    .bind(request.workflow_path().as_str())
    .bind(request.source_digest().as_bytes().as_slice())
    .bind(request.head_sha().as_bytes().as_slice())
    .bind(request.admission_claim().claim().owner().as_uuid())
    .bind(i16::try_from(request.admission_claim().attempt()).expect("attempt fits SMALLINT"))
    .bind(pg_bigint(request.admission_claim().claim().fence()))
    .bind(request.admission_claim().claimed_at().get())
    .bind(request.admission_claim().expires_at().get())
    .bind(request.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn load_queued_workflow_check_subject(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordGithubWorkflowRunSubjectEvidence,
) -> Result<GithubCheckSubjectId, GithubSubjectEvidenceStoreError> {
    let subject_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT subject.id
        FROM github_check_subjects AS subject
        JOIN github_provider_delivery_evidence AS evidence
          ON evidence.provider_delivery_id = subject.provider_delivery_id
         AND evidence.tenant_id = subject.tenant_id
         AND evidence.repository_id = subject.repository_id
        JOIN provider_delivery_inbox AS inbox
          ON inbox.id = evidence.provider_delivery_id
         AND inbox.tenant_id = evidence.tenant_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = evidence.tenant_id
         AND manifest.repository_id = evidence.repository_id
         AND manifest.provider_connection_id = evidence.provider_connection_id
         AND manifest.manifest_revision = evidence.provider_manifest_revision
         AND manifest.manifest_digest = evidence.provider_manifest_digest
        WHERE evidence.tenant_id = $1
          AND evidence.repository_id = $2
          AND evidence.provider_delivery_id = $3
          AND subject.subject_key = $4
          AND subject.provider_connection_id = evidence.provider_connection_id
          AND subject.provider_installation_id = evidence.provider_installation_id
          AND subject.github_repository_id = evidence.github_repository_id
          AND subject.github_repository_name = evidence.github_repository_name
          AND subject.github_app_id = manifest.github_app_id
          AND subject.head_sha = $5
          AND subject.head_sha = evidence.github_check_head_sha
          AND subject.check_name = manifest.check_name
          AND subject.created_at_ms = inbox.accepted_at_ms
          AND subject.workflow_run_id IS NULL
          AND subject.linked_at_ms IS NULL
          AND subject.desired_state = 'queued'
          AND subject.desired_conclusion IS NULL
          AND subject.terminal_cause IS NULL
          AND subject.desired_revision = 1
          AND subject.desired_updated_at_ms = inbox.accepted_at_ms
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $7
          AND inbox.attempt_count = $8
          AND inbox.claim_fence = $9
          AND inbox.claimed_at_ms = $10
          AND inbox.claim_expires_at_ms = $11
          AND (
              manifest.workflow_selection_kind = 'all_direct'
              AND EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_inventories AS inventory
                  JOIN provider_delivery_workflow_inventory_entries AS entry
                    ON entry.inbox_id = inventory.inbox_id
                   AND entry.tenant_id = inventory.tenant_id
                  WHERE inventory.inbox_id = evidence.provider_delivery_id
                    AND inventory.tenant_id = evidence.tenant_id
                    AND inventory.manifest_digest = manifest.manifest_digest
                    AND entry.workflow_path = subject.subject_key
                    AND entry.source_state = 'ready'
                    AND entry.source_digest = $6
              )
          )
        FOR SHARE OF subject, evidence, inbox, manifest
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.delivery_id().as_uuid())
    .bind(request.workflow_path().as_str())
    .bind(request.head_sha().as_bytes().as_slice())
    .bind(request.source_digest().as_bytes().as_slice())
    .bind(request.admission_claim().claim().owner().as_uuid())
    .bind(i16::try_from(request.admission_claim().attempt()).expect("attempt fits SMALLINT"))
    .bind(pg_bigint(request.admission_claim().claim().fence()))
    .bind(request.admission_claim().claimed_at().get())
    .bind(request.admission_claim().expires_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubSubjectEvidenceStoreError::AuthorityRejected)?;
    GithubCheckSubjectId::from_uuid(subject_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

#[allow(clippy::too_many_lines)] // One transition exact-matches the full run and claim authority.
async fn link_exact_check_to_run(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecordGithubWorkflowRunSubjectEvidence,
    subject_id: GithubCheckSubjectId,
) -> Result<GithubCheckSubjectId, GithubSubjectEvidenceStoreError> {
    let schemas = current_durable_schemas();
    let subject_id = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE github_check_subjects AS subject
        SET workflow_run_id = $3,
            linked_at_ms = $4,
            desired_state = 'in_progress',
            desired_revision = desired_revision + 1,
            desired_updated_at_ms = $4
        FROM github_provider_delivery_evidence AS evidence,
             provider_delivery_inbox AS inbox,
             repositories AS repository,
             github_provider_manifest_revisions AS manifest,
             workflow_runs AS run,
             workflow_definitions AS workflow,
             workflow_snapshots AS snapshot,
             logical_workflow_runs AS marker,
             logical_workflow_invocations AS invocation,
             workflow_admission_receipts AS admission_receipt
        WHERE evidence.tenant_id = $1
          AND evidence.repository_id = $2
          AND evidence.provider_delivery_id = $5
          AND inbox.id = evidence.provider_delivery_id
          AND inbox.tenant_id = evidence.tenant_id
          AND repository.tenant_id = evidence.tenant_id
          AND repository.id = evidence.repository_id
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              evidence.github_repository_id::TEXT
          AND repository.owner = split_part(evidence.github_repository_name, '/', 1)
          AND repository.name = split_part(evidence.github_repository_name, '/', 2)
          AND manifest.tenant_id = evidence.tenant_id
          AND manifest.repository_id = evidence.repository_id
          AND manifest.provider_connection_id = evidence.provider_connection_id
          AND manifest.manifest_revision = evidence.provider_manifest_revision
          AND manifest.manifest_digest = evidence.provider_manifest_digest
          AND subject.id = $23
          AND subject.tenant_id = evidence.tenant_id
          AND subject.provider_delivery_id = evidence.provider_delivery_id
          AND subject.repository_id = evidence.repository_id
          AND subject.workflow_run_id IS NULL
          AND subject.linked_at_ms IS NULL
          AND subject.desired_state = 'queued'
          AND subject.desired_conclusion IS NULL
          AND subject.terminal_cause IS NULL
          AND subject.desired_revision = 1
          AND subject.desired_updated_at_ms <= $4
          AND subject.head_sha = evidence.github_check_head_sha
          AND subject.head_sha = $6
          AND subject.subject_key = $13
          AND run.repository_id = evidence.repository_id
          AND run.id = $3
          AND run.workflow_id = $7
          AND run.snapshot_id = $8
          AND run.head_sha = subject.head_sha
          AND run.event_name = COALESCE(
              evidence.authenticated_event_name,
              manifest.event_name
          )
          AND run.event_name = $9
          AND run.event_digest = inbox.raw_event_digest
          AND run.event_digest = $10
          AND run.git_ref = COALESCE(
              evidence.authenticated_event_git_ref,
              manifest.git_ref
          )
          AND run.git_ref = $11
          AND run.admission_epoch = $25
          AND run.plan_schema = $24
          AND run.plan_digest = $12
          AND run.created_at_ms = $4
          AND workflow.repository_id = run.repository_id
          AND workflow.id = run.workflow_id
          AND workflow.path = $13
          AND (
              manifest.workflow_selection_kind = 'all_direct'
              AND EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_inventories AS inventory
                  JOIN provider_delivery_workflow_inventory_entries AS entry
                    ON entry.inbox_id = inventory.inbox_id
                   AND entry.tenant_id = inventory.tenant_id
                  WHERE inventory.inbox_id = evidence.provider_delivery_id
                    AND inventory.tenant_id = evidence.tenant_id
                    AND inventory.manifest_digest = manifest.manifest_digest
                    AND entry.workflow_path = workflow.path
                    AND entry.source_state = 'ready'
                    AND entry.source_digest = snapshot.source_digest
              )
          )
          AND snapshot.id = run.snapshot_id
          AND snapshot.workflow_id = run.workflow_id
          AND snapshot.source_digest = $14
          AND marker.run_id = run.id
          AND marker.root_invocation_id = $15
          AND marker.admission_digest = $16
          AND marker.admitted_at_ms = $4
          AND invocation.run_id = run.id
          AND invocation.id = marker.root_invocation_id
          AND invocation.plan_schema = run.plan_schema
          AND invocation.plan_digest = run.plan_digest
          AND admission_receipt.tenant_id = evidence.tenant_id
          AND admission_receipt.idempotency_kind = 'provider_delivery'
          AND admission_receipt.idempotency_key = $17
          AND admission_receipt.request_digest = marker.admission_digest
          AND admission_receipt.github_subject_evidence_required
          AND admission_receipt.repository_id = $2
          AND admission_receipt.run_id = $3
          AND admission_receipt.committed_at_ms = $4
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $18
          AND inbox.attempt_count = $19
          AND inbox.claim_fence = $20
          AND inbox.claimed_at_ms = $21
          AND inbox.claim_expires_at_ms = $22
          AND run.created_at_ms >= $21
          AND run.created_at_ms < $22
          AND run.created_at_ms >= inbox.accepted_at_ms
        RETURNING subject.id
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.admitted_at().get())
    .bind(request.delivery_id().as_uuid())
    .bind(request.head_sha().as_bytes().as_slice())
    .bind(request.workflow_id().as_uuid())
    .bind(request.snapshot_id().as_uuid())
    .bind(request.event_name())
    .bind(request.event_digest().as_bytes().as_slice())
    .bind(request.git_ref())
    .bind(request.plan_digest().as_bytes().as_slice())
    .bind(request.workflow_path().as_str())
    .bind(request.source_digest().as_bytes().as_slice())
    .bind(request.root_invocation_id().as_uuid())
    .bind(request.logical_admission_digest().as_bytes().as_slice())
    .bind(request.provider_delivery_idempotency_key())
    .bind(request.admission_claim().claim().owner().as_uuid())
    .bind(i16::try_from(request.admission_claim().attempt()).expect("attempt fits SMALLINT"))
    .bind(pg_bigint(request.admission_claim().claim().fence()))
    .bind(request.admission_claim().claimed_at().get())
    .bind(request.admission_claim().expires_at().get())
    .bind(subject_id.as_uuid())
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.admission_epoch_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubSubjectEvidenceStoreError::AuthorityRejected)?;
    GithubCheckSubjectId::from_uuid(subject_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

async fn load_matching_current_manifest(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AcceptManifestPinnedGithubDelivery,
) -> Result<Option<CurrentManifestPin>, GithubSubjectEvidenceStoreError> {
    load_matching_current_manifest_for_delivery(
        transaction,
        request.delivery(),
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
    )
    .await
}

async fn load_matching_current_manifest_for_dispatch(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AcceptManifestPinnedGithubRepositoryDispatch,
) -> Result<Option<CurrentManifestPin>, GithubSubjectEvidenceStoreError> {
    load_matching_current_manifest_for_delivery(
        transaction,
        request.delivery(),
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
    )
    .await
}

async fn load_matching_current_manifest_for_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &automata_ci_store::AcceptProviderDelivery,
    verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    verifier_revision: GithubServerServiceRevision,
) -> Result<Option<CurrentManifestPin>, GithubSubjectEvidenceStoreError> {
    let identity = delivery.identity();
    let row = sqlx::query(CURRENT_MANIFEST_SELECT)
        .bind(identity.tenant().as_str())
        .bind(identity.connection_id().as_uuid())
        .bind(pg_bigint(identity.installation_id().get()))
        .bind(pg_bigint(identity.repository_id().get()))
        .bind(provider_repository_visibility_name(
            identity.repository_visibility(),
        ))
        .bind(identity.repository_identity())
        .bind(delivery.accepted_at().get())
        .bind(verifier_fingerprint.sha256().as_bytes().as_slice())
        .bind(pg_bigint(verifier_revision.get()))
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let manifest = decode_manifest(&row)?;
    let checks_authority = load_current_authority_selector(
        transaction,
        &manifest,
        GithubServerServiceScope::ChecksWrite,
        delivery.accepted_at(),
    )
    .await?;
    let Some(checks_authority) = checks_authority else {
        return Ok(None);
    };
    let private_source_authority = match manifest.repository_visibility() {
        ProviderRepositoryVisibility::Public => None,
        ProviderRepositoryVisibility::Private => {
            let authority = load_current_authority_selector(
                transaction,
                &manifest,
                GithubServerServiceScope::PrivateRepositorySourceRead,
                delivery.accepted_at(),
            )
            .await?;
            let Some(authority) = authority else {
                return Ok(None);
            };
            Some(authority)
        }
    };
    Ok(Some(CurrentManifestPin {
        manifest,
        checks_authority,
        private_source_authority,
    }))
}

async fn load_current_authority_selector(
    transaction: &mut Transaction<'_, Postgres>,
    manifest: &GithubProviderManifest,
    scope: GithubServerServiceScope,
    accepted_at: UnixMillis,
) -> Result<Option<GithubServerServiceAuthoritySelector>, GithubSubjectEvidenceStoreError> {
    let row = sqlx::query(
        r"
        SELECT id AS authority_id, identity_digest AS authority_identity_digest,
               app_configuration_revision AS authority_app_configuration_revision,
               policy_revision AS authority_policy_revision
        FROM github_server_service_authorities
        WHERE tenant_id = $1
          AND repository_id = $2
          AND provider_connection_id = $3
          AND provider_installation_id = $4
          AND github_app_id = $5
          AND github_repository_id = $6
          AND github_repository_name = $7
          AND service_scope = $8
          AND github_app_client_id = $9
          AND github_app_jwt_issuer_kind = $10
          AND app_key_spki_sha256 = $11
          AND app_configuration_revision = $12
          AND policy_revision = $13
          AND state = 'active'
          AND created_at_ms <= $14
        FOR SHARE
        ",
    )
    .bind(manifest.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(manifest.connection_id().as_uuid())
    .bind(pg_bigint(manifest.installation_id().get()))
    .bind(pg_bigint(manifest.github_app_id().get()))
    .bind(pg_bigint(manifest.github_repository_id().get()))
    .bind(manifest.github_repository_name().as_str())
    .bind(scope.as_str())
    .bind(manifest.app_client_id().as_str())
    .bind(manifest.jwt_issuer().as_str())
    .bind(manifest.app_key_spki_sha256().as_bytes().as_slice())
    .bind(pg_bigint(manifest.app_configuration_revision().get()))
    .bind(pg_bigint(manifest.policy_revision().get()))
    .bind(accepted_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.map(|row| decode_authority_selector(&row, manifest.tenant().clone(), "authority"))
        .transpose()
}

async fn insert_generic_inbox(
    transaction: &mut Transaction<'_, Postgres>,
    proposed_id: Uuid,
    request: &automata_ci_store::AcceptProviderDelivery,
) -> Result<bool, GithubSubjectEvidenceStoreError> {
    let identity = request.identity();
    let row = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO provider_delivery_inbox (
            id, tenant_id, provider, connection_id, installation_id,
            provider_repository_id, repository_visibility,
            repository_identity, delivery_id, request_digest,
            raw_event_digest, raw_event_object_key, raw_event_size_bytes,
            raw_event_media_type, event_envelope_schema,
            event_registry_schema, event_envelope_digest,
            event_envelope_bytes, event_envelope_media_type,
            accepted_at_ms, state_updated_at_ms
        ) VALUES (
            $1, $2, 'github', $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13, $14, $15, $16,
            $17, $18, $19, $19
        )
        ON CONFLICT (provider, connection_id, delivery_id) DO NOTHING
        RETURNING id
        ",
    )
    .bind(proposed_id)
    .bind(identity.tenant().as_str())
    .bind(identity.connection_id().as_uuid())
    .bind(pg_bigint(identity.installation_id().get()))
    .bind(pg_bigint(identity.repository_id().get()))
    .bind(provider_repository_visibility_name(
        identity.repository_visibility(),
    ))
    .bind(identity.repository_identity())
    .bind(identity.delivery_id())
    .bind(request.request_digest().as_bytes().as_slice())
    .bind(request.raw_event().digest().as_bytes().as_slice())
    .bind(request.raw_event().object_key().as_str())
    .bind(
        i64::try_from(request.raw_event().encoded_size())
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
    )
    .bind(request.raw_event().media_type())
    .bind(i16::try_from(request.event_envelope().schema()).expect("validated schema fits"))
    .bind(
        i16::try_from(request.event_envelope().registry_schema())
            .expect("validated registry schema fits"),
    )
    .bind(request.event_envelope().digest().as_bytes().as_slice())
    .bind(request.event_envelope().canonical_bytes())
    .bind(request.event_envelope().media_type())
    .bind(request.accepted_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(row.is_some())
}

async fn insert_pending_repository_dispatch(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
    request: &AcceptManifestPinnedGithubRepositoryDispatch,
    pin: &CurrentManifestPin,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let identity = request.delivery().identity();
    let private_id = pin
        .private_source_authority
        .as_ref()
        .map(|selector| selector.authority_id().as_uuid());
    let private_digest = pin
        .private_source_authority
        .as_ref()
        .map(|selector| selector.identity_digest().as_bytes().to_vec());
    let private_app_revision = pin
        .private_source_authority
        .as_ref()
        .map(|selector| pg_bigint(selector.app_configuration_revision().get()));
    let private_policy_revision = pin
        .private_source_authority
        .as_ref()
        .map(|selector| pg_bigint(selector.policy_revision().get()));
    let result = sqlx::query(
        r"
        INSERT INTO github_repository_dispatch_pending_evidence (
            provider_delivery_id, tenant_id, repository_id,
            provider_connection_id, github_repository_owner_id,
            provider_manifest_revision, provider_manifest_digest,
            authenticated_webhook_verifier_fingerprint_sha256,
            authenticated_webhook_verifier_revision,
            authenticated_event_envelope_version,
            authenticated_event_name, authenticated_event_git_ref,
            checks_authority_id, checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision,
            private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$19,'repository_dispatch',$10,
            $11,$12,$13,$14,$15,$16,$17,$18
        )
        ",
    )
    .bind(delivery_id)
    .bind(identity.tenant().as_str())
    .bind(pin.manifest.repository_id().as_uuid())
    .bind(identity.connection_id().as_uuid())
    .bind(pg_bigint(request.repository_owner_id().get()))
    .bind(pg_bigint(pin.manifest.revision().get()))
    .bind(pin.manifest.digest().as_bytes().as_slice())
    .bind(
        request
            .authenticated_webhook_verifier_fingerprint()
            .sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(pg_bigint(
        request.authenticated_webhook_verifier_revision().get(),
    ))
    .bind(request.event().git_ref())
    .bind(pin.checks_authority.authority_id().as_uuid())
    .bind(pin.checks_authority.identity_digest().as_bytes().as_slice())
    .bind(pg_bigint(
        pin.checks_authority.app_configuration_revision().get(),
    ))
    .bind(pg_bigint(pin.checks_authority.policy_revision().get()))
    .bind(private_id)
    .bind(private_digest)
    .bind(private_app_revision)
    .bind(private_policy_revision)
    .bind(AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    Ok(())
}

fn pending_evidence_from_request(
    delivery_id: Uuid,
    request: &AcceptManifestPinnedGithubRepositoryDispatch,
    pin: &CurrentManifestPin,
) -> Result<PendingGithubRepositoryDispatchEvidence, GithubSubjectEvidenceStoreError> {
    let delivery_id = ProviderDeliveryId::from_uuid(delivery_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    PendingGithubRepositoryDispatchEvidence::from_durable_parts(
        delivery_id,
        request.repository_owner_id(),
        pin.manifest.clone(),
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        pin.checks_authority.clone(),
        pin.private_source_authority.clone(),
        request.event().clone(),
        request.delivery().accepted_at(),
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

async fn insert_resolved_repository_dispatch_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: Uuid,
    request: &ResolveGithubRepositoryDispatch,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let pending = request.pending();
    let manifest = pending.manifest();
    let webhook_fingerprint = pending
        .authenticated_webhook_verifier_fingerprint()
        .sha256();
    let checks_authority = pending.checks_authority();
    let private_id = pending
        .private_source_authority()
        .map(|selector| selector.authority_id().as_uuid());
    let private_digest = pending
        .private_source_authority()
        .map(|selector| selector.identity_digest().as_bytes().to_vec());
    let private_app_revision = pending
        .private_source_authority()
        .map(|selector| pg_bigint(selector.app_configuration_revision().get()));
    let private_policy_revision = pending
        .private_source_authority()
        .map(|selector| pg_bigint(selector.policy_revision().get()));
    let result = sqlx::query(
        r"
        INSERT INTO github_provider_delivery_evidence (
            provider_delivery_id, tenant_id, repository_id,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_repository_owner_id,
            github_repository_name, repository_visibility,
            provider_manifest_revision, provider_manifest_digest,
            authenticated_webhook_verifier_fingerprint_sha256,
            authenticated_webhook_verifier_revision,
            authenticated_event_envelope_version,
            authenticated_event_name, authenticated_event_git_ref,
            authenticated_event_source_revision,
            authenticated_event_source_authority,
            checks_authority_id, checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision,
            private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision,
            github_check_subject_id, github_check_head_sha
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$26,
            'repository_dispatch',$14,$15,$16,$17,$18,$19,$20,$21,$22,
            $23,$24,$25,$15
        )
        ",
    )
    .bind(pending.delivery_id().as_uuid())
    .bind(pending.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(manifest.connection_id().as_uuid())
    .bind(pg_bigint(manifest.installation_id().get()))
    .bind(pg_bigint(manifest.github_repository_id().get()))
    .bind(pg_bigint(pending.repository_owner_id().get()))
    .bind(manifest.github_repository_name().as_str())
    .bind(provider_repository_visibility_name(
        manifest.repository_visibility(),
    ))
    .bind(pg_bigint(manifest.revision().get()))
    .bind(manifest.digest().as_bytes().as_slice())
    .bind(webhook_fingerprint.as_bytes().as_slice())
    .bind(pg_bigint(
        pending.authenticated_webhook_verifier_revision().get(),
    ))
    .bind(pending.event().git_ref())
    .bind(request.resolution().source_revision().as_bytes().as_slice())
    .bind(request.resolution().authority().as_str())
    .bind(checks_authority.authority_id().as_uuid())
    .bind(checks_authority.identity_digest().as_bytes().as_slice())
    .bind(pg_bigint(
        checks_authority.app_configuration_revision().get(),
    ))
    .bind(pg_bigint(checks_authority.policy_revision().get()))
    .bind(private_id)
    .bind(private_digest)
    .bind(private_app_revision)
    .bind(private_policy_revision)
    .bind(subject_id)
    .bind(AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    Ok(())
}

async fn insert_resolved_repository_dispatch_check(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: Uuid,
    request: &ResolveGithubRepositoryDispatch,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let pending = request.pending();
    let manifest = pending.manifest();
    let external_id = format!("automata-check:{subject_id}");
    let result = sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13
        )
        ",
    )
    .bind(subject_id)
    .bind(pending.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(pending.delivery_id().as_uuid())
    .bind(manifest.check_subject_key().as_str())
    .bind(manifest.connection_id().as_uuid())
    .bind(pg_bigint(manifest.installation_id().get()))
    .bind(pg_bigint(manifest.github_repository_id().get()))
    .bind(pg_bigint(manifest.github_app_id().get()))
    .bind(request.resolution().source_revision().as_bytes().as_slice())
    .bind(manifest.check_name().as_str())
    .bind(external_id)
    .bind(pending.accepted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    Ok(())
}

fn resolved_repository_dispatch_evidence(
    subject_id: Uuid,
    request: &ResolveGithubRepositoryDispatch,
) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
    let pending = request.pending();
    let subject_id = GithubCheckSubjectId::from_uuid(subject_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    ManifestPinnedGithubDeliveryEvidence::from_durable_parts_resolved_repository_dispatch(
        pending.delivery_id(),
        pending.repository_owner_id(),
        pending.manifest().clone(),
        pending.authenticated_webhook_verifier_fingerprint(),
        pending.authenticated_webhook_verifier_revision(),
        pending.checks_authority().clone(),
        pending.private_source_authority().cloned(),
        subject_id,
        request.resolution().source_revision(),
        pending.event().clone(),
        request.resolution(),
        pending.accepted_at(),
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

async fn insert_delivery_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: Uuid,
    subject_id: Uuid,
    request: &AcceptManifestPinnedGithubDelivery,
    pin: &CurrentManifestPin,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let identity = request.delivery().identity();
    let private_id = pin
        .private_source_authority
        .as_ref()
        .map(|selector| selector.authority_id().as_uuid());
    let private_digest = pin
        .private_source_authority
        .as_ref()
        .map(|selector| selector.identity_digest().as_bytes().to_vec());
    let private_app_revision = pin
        .private_source_authority
        .as_ref()
        .map(|selector| pg_bigint(selector.app_configuration_revision().get()));
    let private_policy_revision = pin
        .private_source_authority
        .as_ref()
        .map(|selector| pg_bigint(selector.policy_revision().get()));
    let authenticated_event = request.authenticated_event();
    let authenticated_event_name = authenticated_event.kind().as_str();
    let authenticated_event_git_ref = authenticated_event.git_ref();
    let result = sqlx::query(
        r"
        INSERT INTO github_provider_delivery_evidence (
            provider_delivery_id, tenant_id, repository_id,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_repository_owner_id,
            github_repository_name, repository_visibility,
            provider_manifest_revision, provider_manifest_digest,
            authenticated_webhook_verifier_fingerprint_sha256,
            authenticated_webhook_verifier_revision,
            authenticated_event_envelope_version,
            authenticated_event_name, authenticated_event_git_ref,
            checks_authority_id, checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision,
            private_source_authority_id,
            private_source_authority_identity_digest,
            private_source_authority_app_configuration_revision,
            private_source_authority_policy_revision,
            github_check_subject_id, github_check_head_sha
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
            $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26
        )
        ",
    )
    .bind(delivery_id)
    .bind(identity.tenant().as_str())
    .bind(pin.manifest.repository_id().as_uuid())
    .bind(identity.connection_id().as_uuid())
    .bind(pg_bigint(identity.installation_id().get()))
    .bind(pg_bigint(identity.repository_id().get()))
    .bind(pg_bigint(request.repository_owner_id().get()))
    .bind(identity.repository_identity())
    .bind(provider_repository_visibility_name(
        identity.repository_visibility(),
    ))
    .bind(pg_bigint(pin.manifest.revision().get()))
    .bind(pin.manifest.digest().as_bytes().as_slice())
    .bind(
        request
            .authenticated_webhook_verifier_fingerprint()
            .sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(pg_bigint(
        request.authenticated_webhook_verifier_revision().get(),
    ))
    .bind(AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION)
    .bind(authenticated_event_name)
    .bind(authenticated_event_git_ref)
    .bind(pin.checks_authority.authority_id().as_uuid())
    .bind(pin.checks_authority.identity_digest().as_bytes().as_slice())
    .bind(pg_bigint(
        pin.checks_authority.app_configuration_revision().get(),
    ))
    .bind(pg_bigint(pin.checks_authority.policy_revision().get()))
    .bind(private_id)
    .bind(private_digest)
    .bind(private_app_revision)
    .bind(private_policy_revision)
    .bind(subject_id)
    .bind(request.head_sha().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    Ok(())
}

async fn insert_queued_check(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: Uuid,
    delivery_id: Uuid,
    request: &AcceptManifestPinnedGithubDelivery,
    pin: &CurrentManifestPin,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let identity = request.delivery().identity();
    let external_id = format!("automata-check:{subject_id}");
    let manifest = &pin.manifest;
    let result = sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13
        )
        ",
    )
    .bind(subject_id)
    .bind(identity.tenant().as_str())
    .bind(manifest.repository_id().as_uuid())
    .bind(delivery_id)
    .bind(manifest.check_subject_key().as_str())
    .bind(identity.connection_id().as_uuid())
    .bind(pg_bigint(identity.installation_id().get()))
    .bind(pg_bigint(identity.repository_id().get()))
    .bind(pg_bigint(manifest.github_app_id().get()))
    .bind(request.head_sha().as_bytes().as_slice())
    .bind(manifest.check_name().as_str())
    .bind(external_id)
    .bind(request.delivery().accepted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    Ok(())
}

fn evidence_from_request(
    delivery_id: Uuid,
    subject_id: Uuid,
    request: &AcceptManifestPinnedGithubDelivery,
    pin: &CurrentManifestPin,
) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
    let delivery_id = ProviderDeliveryId::from_uuid(delivery_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let subject_id = GithubCheckSubjectId::from_uuid(subject_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let result = ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
        delivery_id,
        request.repository_owner_id(),
        pin.manifest.clone(),
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        pin.checks_authority.clone(),
        pin.private_source_authority.clone(),
        subject_id,
        request.head_sha(),
        request.authenticated_event().clone(),
        request.delivery().accepted_at(),
    );
    result.map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

async fn require_current_repository_dispatch_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveGithubRepositoryDispatch,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let pending = request.pending();
    let claim = request.claim();
    let authorized = sqlx::query_scalar::<_, bool>(
        r"
        SELECT TRUE
        FROM provider_delivery_inbox AS inbox
        JOIN github_repository_dispatch_pending_evidence AS pending
          ON pending.provider_delivery_id = inbox.id
         AND pending.tenant_id = inbox.tenant_id
         AND pending.provider_connection_id = inbox.connection_id
        WHERE inbox.id = $1
          AND inbox.tenant_id = $2
          AND inbox.provider = 'github'
          AND inbox.connection_id = $3
          AND inbox.state = 'claimed'
          AND inbox.claim_owner_id = $4
          AND inbox.attempt_count = $5
          AND inbox.claim_fence = $6
          AND inbox.claimed_at_ms = $7
          AND inbox.claim_expires_at_ms = $8
          AND inbox.accepted_at_ms = $9
          AND $10 >= inbox.claimed_at_ms
          AND $10 < inbox.claim_expires_at_ms
        FOR UPDATE OF inbox
        ",
    )
    .bind(pending.delivery_id().as_uuid())
    .bind(pending.tenant().as_str())
    .bind(pending.manifest().connection_id().as_uuid())
    .bind(claim.claim().owner().as_uuid())
    .bind(i16::try_from(claim.attempt()).expect("validated claim attempt fits SMALLINT"))
    .bind(pg_bigint(claim.claim().fence()))
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .bind(pending.accepted_at().get())
    .bind(request.observed_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if authorized != Some(true) {
        return Err(GithubSubjectEvidenceStoreError::AuthorityRejected);
    }
    Ok(())
}

async fn load_pending_acceptance_by_replay_key(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AcceptManifestPinnedGithubRepositoryDispatch,
) -> Result<Option<DurablePendingAcceptance>, GithubSubjectEvidenceStoreError> {
    let identity = request.delivery().identity();
    let query = format!(
        "{PENDING_EVIDENCE_SELECT} WHERE inbox.provider = $1 AND inbox.connection_id = $2 \
         AND inbox.delivery_id = $3 {PENDING_EVIDENCE_VISIBILITY_AUTHORITY_EXACT}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(identity.provider())
        .bind(identity.connection_id().as_uuid())
        .bind(identity.delivery_id())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    row.map(|row| decode_pending_acceptance(&row)).transpose()
}

fn decode_pending_acceptance(
    row: &PgRow,
) -> Result<DurablePendingAcceptance, GithubSubjectEvidenceStoreError> {
    let evidence = decode_pending_repository_dispatch(row)?;
    Ok(DurablePendingAcceptance {
        receipt: PendingGithubRepositoryDispatchReceipt::from_durable_parts(evidence),
        tenant_id: row.try_get("inbox_tenant_id").map_err(operation_error)?,
        provider: row.try_get("inbox_provider").map_err(operation_error)?,
        connection_id: row
            .try_get("inbox_connection_id")
            .map_err(operation_error)?,
        installation_id: row
            .try_get("inbox_installation_id")
            .map_err(operation_error)?,
        github_repository_id: row
            .try_get("inbox_repository_id")
            .map_err(operation_error)?,
        github_repository_name: row
            .try_get("inbox_repository_name")
            .map_err(operation_error)?,
        repository_visibility: row
            .try_get("inbox_repository_visibility")
            .map_err(operation_error)?,
        delivery_key: row.try_get("inbox_delivery_key").map_err(operation_error)?,
        request_digest: digest_column(row, "request_digest")?,
        raw_event_digest: digest_column(row, "raw_event_digest")?,
        raw_event_object_key: row
            .try_get("raw_event_object_key")
            .map_err(operation_error)?,
        raw_event_size_bytes: row
            .try_get("raw_event_size_bytes")
            .map_err(operation_error)?,
        raw_event_media_type: row
            .try_get("raw_event_media_type")
            .map_err(operation_error)?,
        event_envelope_schema: row
            .try_get("event_envelope_schema")
            .map_err(operation_error)?,
        event_registry_schema: row
            .try_get("event_registry_schema")
            .map_err(operation_error)?,
        event_envelope_digest: digest_column(row, "event_envelope_digest")?,
        event_envelope_bytes: row
            .try_get("event_envelope_bytes")
            .map_err(operation_error)?,
        event_envelope_media_type: row
            .try_get("event_envelope_media_type")
            .map_err(operation_error)?,
    })
}

fn pending_acceptance_matches(
    durable: &DurablePendingAcceptance,
    request: &AcceptManifestPinnedGithubRepositoryDispatch,
) -> bool {
    let identity = request.delivery().identity();
    let evidence = durable.receipt.evidence();
    durable.tenant_id == identity.tenant().as_str()
        && durable.provider == identity.provider()
        && durable.connection_id == identity.connection_id().as_uuid()
        && durable.installation_id == pg_bigint(identity.installation_id().get())
        && durable.github_repository_id == pg_bigint(identity.repository_id().get())
        && durable.github_repository_name == identity.repository_identity()
        && durable.repository_visibility
            == provider_repository_visibility_name(identity.repository_visibility())
        && durable.delivery_key == identity.delivery_id()
        && durable.request_digest == request.delivery().request_digest()
        && durable.raw_event_digest == request.delivery().raw_event().digest()
        && durable.raw_event_object_key == request.delivery().raw_event().object_key().as_str()
        && u64::try_from(durable.raw_event_size_bytes).ok()
            == Some(request.delivery().raw_event().encoded_size())
        && durable.raw_event_media_type == request.delivery().raw_event().media_type()
        && u16::try_from(durable.event_envelope_schema).ok()
            == Some(request.delivery().event_envelope().schema())
        && u16::try_from(durable.event_registry_schema).ok()
            == Some(request.delivery().event_envelope().registry_schema())
        && durable.event_envelope_digest == request.delivery().event_envelope().digest()
        && durable.event_envelope_bytes == request.delivery().event_envelope().canonical_bytes()
        && durable.event_envelope_media_type == request.delivery().event_envelope().media_type()
        && evidence.accepted_at() == request.delivery().accepted_at()
        && evidence.repository_owner_id() == request.repository_owner_id()
        && evidence.event() == request.event()
        && evidence.authenticated_webhook_verifier_fingerprint()
            == request.authenticated_webhook_verifier_fingerprint()
        && evidence.authenticated_webhook_verifier_revision()
            == request.authenticated_webhook_verifier_revision()
}

async fn load_pending_repository_dispatch<'e, E>(
    executor: E,
    tenant: &TenantScope,
    delivery_id: ProviderDeliveryId,
) -> Result<Option<PendingGithubRepositoryDispatchEvidence>, GithubSubjectEvidenceStoreError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let query = format!(
        "{PENDING_EVIDENCE_SELECT} WHERE inbox.id = $1 AND inbox.tenant_id = $2 \
         AND inbox.provider = 'github' {PENDING_EVIDENCE_VISIBILITY_AUTHORITY_EXACT}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(delivery_id.as_uuid())
        .bind(tenant.as_str())
        .fetch_optional(executor)
        .await
        .map_err(operation_error)?;
    row.map(|row| decode_pending_repository_dispatch(&row))
        .transpose()
}

fn decode_pending_repository_dispatch(
    row: &PgRow,
) -> Result<PendingGithubRepositoryDispatchEvidence, GithubSubjectEvidenceStoreError> {
    let manifest = decode_manifest(row)?;
    let checks_authority =
        decode_authority_selector(row, manifest.tenant().clone(), "checks_authority")?;
    let private_source_authority =
        optional_authority_selector(row, manifest.tenant().clone(), "private_source_authority")?;
    let delivery_id =
        ProviderDeliveryId::from_uuid(row.try_get("inbox_id").map_err(operation_error)?)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let owner_id = ProviderRepositoryOwnerId::new(positive_u64(
        row.try_get("github_repository_owner_id")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let verifier_fingerprint = GithubProviderWebhookVerifierFingerprint::from_sha256(
        digest_column(row, "authenticated_webhook_verifier_fingerprint_sha256")?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let verifier_revision = GithubServerServiceRevision::new(positive_column(
        row,
        "authenticated_webhook_verifier_revision",
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let version: i16 = row
        .try_get("authenticated_event_envelope_version")
        .map_err(operation_error)?;
    let event_name: String = row
        .try_get("authenticated_event_name")
        .map_err(operation_error)?;
    let git_ref: String = row
        .try_get("authenticated_event_git_ref")
        .map_err(operation_error)?;
    if !authenticated_event_envelope_schema_is_current(version)
        || event_name != GithubAuthenticatedEventKind::RepositoryDispatch.as_str()
    {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    let event =
        GithubAuthenticatedEvent::new(GithubAuthenticatedEventKind::RepositoryDispatch, git_ref)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let accepted_at: i64 = row.try_get("accepted_at_ms").map_err(operation_error)?;
    PendingGithubRepositoryDispatchEvidence::from_durable_parts(
        delivery_id,
        owner_id,
        manifest,
        verifier_fingerprint,
        verifier_revision,
        checks_authority,
        private_source_authority,
        event,
        UnixMillis::new(accepted_at),
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

async fn load_acceptance_by_replay_key(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AcceptManifestPinnedGithubDelivery,
) -> Result<Option<DurableAcceptance>, GithubSubjectEvidenceStoreError> {
    let identity = request.delivery().identity();
    let query = format!(
        "{EVIDENCE_SELECT} WHERE inbox.provider = $1 AND inbox.connection_id = $2 \
         AND inbox.delivery_id = $3 {EVIDENCE_VISIBILITY_AUTHORITY_EXACT}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(identity.provider())
        .bind(identity.connection_id().as_uuid())
        .bind(identity.delivery_id())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    row.map(|row| decode_acceptance(&row)).transpose()
}

fn decode_acceptance(row: &PgRow) -> Result<DurableAcceptance, GithubSubjectEvidenceStoreError> {
    let evidence = decode_delivery_evidence(row)?;
    let durable = DurableAcceptance {
        receipt: ManifestPinnedGithubDeliveryReceipt::from_durable_parts(evidence),
        tenant_id: row.try_get("inbox_tenant_id").map_err(operation_error)?,
        provider: row.try_get("inbox_provider").map_err(operation_error)?,
        connection_id: row
            .try_get("inbox_connection_id")
            .map_err(operation_error)?,
        installation_id: row
            .try_get("inbox_installation_id")
            .map_err(operation_error)?,
        github_repository_id: row
            .try_get("inbox_repository_id")
            .map_err(operation_error)?,
        github_repository_name: row
            .try_get("inbox_repository_name")
            .map_err(operation_error)?,
        repository_visibility: row
            .try_get("inbox_repository_visibility")
            .map_err(operation_error)?,
        delivery_key: row.try_get("inbox_delivery_key").map_err(operation_error)?,
        request_digest: digest_column(row, "request_digest")?,
        raw_event_digest: digest_column(row, "raw_event_digest")?,
        raw_event_object_key: row
            .try_get("raw_event_object_key")
            .map_err(operation_error)?,
        raw_event_size_bytes: row
            .try_get("raw_event_size_bytes")
            .map_err(operation_error)?,
        raw_event_media_type: row
            .try_get("raw_event_media_type")
            .map_err(operation_error)?,
        event_envelope_schema: row
            .try_get("event_envelope_schema")
            .map_err(operation_error)?,
        event_registry_schema: row
            .try_get("event_registry_schema")
            .map_err(operation_error)?,
        event_envelope_digest: digest_column(row, "event_envelope_digest")?,
        event_envelope_bytes: row
            .try_get("event_envelope_bytes")
            .map_err(operation_error)?,
        event_envelope_media_type: row
            .try_get("event_envelope_media_type")
            .map_err(operation_error)?,
    };
    Ok(durable)
}

fn acceptance_matches(
    durable: &DurableAcceptance,
    request: &AcceptManifestPinnedGithubDelivery,
) -> bool {
    let identity = request.delivery().identity();
    durable.tenant_id == identity.tenant().as_str()
        && durable.provider == identity.provider()
        && durable.connection_id == identity.connection_id().as_uuid()
        && durable.installation_id == pg_bigint(identity.installation_id().get())
        && durable.github_repository_id == pg_bigint(identity.repository_id().get())
        && durable.github_repository_name == identity.repository_identity()
        && durable.repository_visibility
            == provider_repository_visibility_name(identity.repository_visibility())
        && durable.delivery_key == identity.delivery_id()
        && durable.request_digest == request.delivery().request_digest()
        && durable.raw_event_digest == request.delivery().raw_event().digest()
        && durable.raw_event_object_key == request.delivery().raw_event().object_key().as_str()
        && u64::try_from(durable.raw_event_size_bytes).ok()
            == Some(request.delivery().raw_event().encoded_size())
        && durable.raw_event_media_type == request.delivery().raw_event().media_type()
        && u16::try_from(durable.event_envelope_schema).ok()
            == Some(request.delivery().event_envelope().schema())
        && u16::try_from(durable.event_registry_schema).ok()
            == Some(request.delivery().event_envelope().registry_schema())
        && durable.event_envelope_digest == request.delivery().event_envelope().digest()
        && durable.event_envelope_bytes == request.delivery().event_envelope().canonical_bytes()
        && durable.event_envelope_media_type == request.delivery().event_envelope().media_type()
        && durable.receipt.accepted_at() == request.delivery().accepted_at()
        && durable.receipt.repository_owner_id() == request.repository_owner_id()
        && durable.receipt.evidence().check_head_sha() == request.head_sha()
        && durable.receipt.evidence().authenticated_event() == request.authenticated_event()
        && durable
            .receipt
            .evidence()
            .authenticated_webhook_verifier_fingerprint()
            == request.authenticated_webhook_verifier_fingerprint()
        && durable
            .receipt
            .evidence()
            .authenticated_webhook_verifier_revision()
            == request.authenticated_webhook_verifier_revision()
}

async fn load_delivery_evidence<'e, E>(
    executor: E,
    tenant: &TenantScope,
    delivery_id: ProviderDeliveryId,
) -> Result<Option<ManifestPinnedGithubDeliveryEvidence>, GithubSubjectEvidenceStoreError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let query = format!(
        "{EVIDENCE_SELECT} WHERE inbox.id = $1 AND inbox.tenant_id = $2 \
         AND inbox.provider = 'github' {EVIDENCE_VISIBILITY_AUTHORITY_EXACT}"
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(delivery_id.as_uuid())
        .bind(tenant.as_str())
        .fetch_optional(executor)
        .await
        .map_err(operation_error)?;
    row.map(|row| decode_delivery_evidence(&row)).transpose()
}

fn decode_delivery_evidence(
    row: &PgRow,
) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
    let manifest = decode_manifest(row)?;
    let checks_authority =
        decode_authority_selector(row, manifest.tenant().clone(), "checks_authority")?;
    let private_source_authority =
        optional_authority_selector(row, manifest.tenant().clone(), "private_source_authority")?;
    let delivery_id: Uuid = row.try_get("inbox_id").map_err(operation_error)?;
    let owner_id: i64 = row
        .try_get("github_repository_owner_id")
        .map_err(operation_error)?;
    let authenticated_verifier_fingerprint = GithubProviderWebhookVerifierFingerprint::from_sha256(
        digest_column(row, "authenticated_webhook_verifier_fingerprint_sha256")?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let authenticated_verifier_revision = GithubServerServiceRevision::new(positive_column(
        row,
        "authenticated_webhook_verifier_revision",
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let subject_id: Uuid = row
        .try_get("github_check_subject_id")
        .map_err(operation_error)?;
    let head_sha = GithubCheckHeadSha::try_from_slice(
        &row.try_get::<Vec<u8>, _>("github_check_head_sha")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let accepted_at: i64 = row.try_get("accepted_at_ms").map_err(operation_error)?;
    let delivery_id = ProviderDeliveryId::from_uuid(delivery_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let owner_id = ProviderRepositoryOwnerId::new(positive_u64(owner_id)?)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let subject_id = GithubCheckSubjectId::from_uuid(subject_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    decode_delivery_event_evidence(
        row,
        DecodedDeliveryEvidenceParts {
            delivery_id,
            owner_id,
            manifest,
            authenticated_verifier_fingerprint,
            authenticated_verifier_revision,
            checks_authority,
            private_source_authority,
            subject_id,
            head_sha,
            accepted_at: UnixMillis::new(accepted_at),
        },
    )
}

struct DecodedDeliveryEvidenceParts {
    delivery_id: ProviderDeliveryId,
    owner_id: ProviderRepositoryOwnerId,
    manifest: GithubProviderManifest,
    authenticated_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    authenticated_verifier_revision: GithubServerServiceRevision,
    checks_authority: GithubServerServiceAuthoritySelector,
    private_source_authority: Option<GithubServerServiceAuthoritySelector>,
    subject_id: GithubCheckSubjectId,
    head_sha: GithubCheckHeadSha,
    accepted_at: UnixMillis,
}

type DecodedAuthenticatedEventColumns = (
    Option<i16>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
);

fn decode_authenticated_event_columns(
    row: &PgRow,
) -> Result<DecodedAuthenticatedEventColumns, GithubSubjectEvidenceStoreError> {
    Ok((
        row.try_get("authenticated_event_envelope_version")
            .map_err(operation_error)?,
        row.try_get("authenticated_event_name")
            .map_err(operation_error)?,
        row.try_get("authenticated_event_git_ref")
            .map_err(operation_error)?,
        row.try_get("authenticated_event_source_revision")
            .map_err(operation_error)?,
        row.try_get("authenticated_event_source_authority")
            .map_err(operation_error)?,
    ))
}

fn decode_delivery_event_evidence(
    row: &PgRow,
    parts: DecodedDeliveryEvidenceParts,
) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
    let DecodedDeliveryEvidenceParts {
        delivery_id,
        owner_id,
        manifest,
        authenticated_verifier_fingerprint,
        authenticated_verifier_revision,
        checks_authority,
        private_source_authority,
        subject_id,
        head_sha,
        accepted_at,
    } = parts;
    let (version, event_name, git_ref, source_revision, source_authority) =
        decode_authenticated_event_columns(row)?;
    let result = match (
        version,
        event_name,
        git_ref,
        source_revision,
        source_authority,
    ) {
        (Some(version), Some(event_name), Some(git_ref), None, None)
            if authenticated_event_envelope_schema_is_current(version) =>
        {
            let kind = decode_github_authenticated_event_kind(&event_name)
                .ok_or(GithubSubjectEvidenceStoreError::CorruptData)?;
            if kind == GithubAuthenticatedEventKind::RepositoryDispatch {
                return Err(GithubSubjectEvidenceStoreError::CorruptData);
            }
            let event = GithubAuthenticatedEvent::new(kind, git_ref)
                .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
                delivery_id,
                owner_id,
                manifest,
                authenticated_verifier_fingerprint,
                authenticated_verifier_revision,
                checks_authority,
                private_source_authority,
                subject_id,
                head_sha,
                event,
                accepted_at,
            )
        }
        (
            Some(version),
            Some(event_name),
            Some(git_ref),
            Some(source_revision),
            Some(source_authority),
        ) if authenticated_event_envelope_schema_is_current(version) => {
            let kind = decode_github_authenticated_event_kind(&event_name)
                .filter(|kind| *kind == GithubAuthenticatedEventKind::RepositoryDispatch)
                .ok_or(GithubSubjectEvidenceStoreError::CorruptData)?;
            let event = GithubAuthenticatedEvent::new(kind, git_ref)
                .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
            let revision = GithubCheckHeadSha::try_from_slice(&source_revision)
                .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
            let authority =
                decode_github_repository_dispatch_resolution_authority(&source_authority)
                    .ok_or(GithubSubjectEvidenceStoreError::CorruptData)?;
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts_resolved_repository_dispatch(
                delivery_id,
                owner_id,
                manifest,
                authenticated_verifier_fingerprint,
                authenticated_verifier_revision,
                checks_authority,
                private_source_authority,
                subject_id,
                head_sha,
                event,
                GithubRepositoryDispatchResolution::new(revision, authority),
                accepted_at,
            )
        }
        _ => return Err(GithubSubjectEvidenceStoreError::CorruptData),
    };
    result.map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

async fn load_run_evidence<'e, E>(
    executor: E,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
) -> Result<Option<GithubWorkflowRunSubjectEvidence>, GithubSubjectEvidenceStoreError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r"
        SELECT tenant_id, repository_id, workflow_id, snapshot_id, run_id,
               root_invocation_id, provider_delivery_id,
               provider_delivery_idempotency_key, admission_claim_owner_id,
               admission_claim_attempt, admission_claim_fence,
               admission_claimed_at_ms, admission_claim_expires_at_ms,
               github_check_subject_id, github_check_head_sha,
               workflow_path, source_digest, event_name, event_digest, git_ref,
               workflow_plan_schema, plan_digest, logical_admission_digest,
               subject_evidence_sha256, admitted_at_ms
        FROM github_workflow_run_subject_evidence
        WHERE tenant_id = $1 AND repository_id = $2 AND run_id = $3
        ",
    )
    .bind(tenant.as_str())
    .bind(repository_id.as_uuid())
    .bind(run_id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(operation_error)?;
    row.map(|row| decode_run_evidence(&row)).transpose()
}

fn decode_run_evidence(
    row: &PgRow,
) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let repository_id: Uuid = row.try_get("repository_id").map_err(operation_error)?;
    let workflow_id: Uuid = row.try_get("workflow_id").map_err(operation_error)?;
    let snapshot_id: Uuid = row.try_get("snapshot_id").map_err(operation_error)?;
    let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
    let root_invocation_id: Uuid = row.try_get("root_invocation_id").map_err(operation_error)?;
    let delivery_id: Uuid = row
        .try_get("provider_delivery_id")
        .map_err(operation_error)?;
    let delivery_id = ProviderDeliveryId::from_uuid(delivery_id)
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let claim_owner: Uuid = row
        .try_get("admission_claim_owner_id")
        .map_err(operation_error)?;
    let claim_fence: i64 = row
        .try_get("admission_claim_fence")
        .map_err(operation_error)?;
    let admission_claim = AuthenticatedGithubDeliveryClaim::new(
        ProviderDeliveryClaimFence::from_durable_parts(
            delivery_id,
            ProviderDeliveryClaimOwnerId::from_uuid(claim_owner)
                .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
            positive_u64(claim_fence)?,
        )
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        u16::try_from(
            row.try_get::<i16, _>("admission_claim_attempt")
                .map_err(operation_error)?,
        )
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        UnixMillis::new(
            row.try_get("admission_claimed_at_ms")
                .map_err(operation_error)?,
        ),
        UnixMillis::new(
            row.try_get("admission_claim_expires_at_ms")
                .map_err(operation_error)?,
        ),
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let subject_id: Uuid = row
        .try_get("github_check_subject_id")
        .map_err(operation_error)?;
    let plan_schema: i16 = row
        .try_get("workflow_plan_schema")
        .map_err(operation_error)?;
    if !workflow_plan_schema_is_current(plan_schema) {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    let request = RecordGithubWorkflowRunSubjectEvidence::new(
        tenant,
        RepositoryId::from_uuid(repository_id),
        WorkflowId::from_uuid(workflow_id),
        WorkflowSnapshotId::from_uuid(snapshot_id),
        RunId::from_uuid(run_id),
        LogicalWorkflowInvocationId::from_uuid(root_invocation_id)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        delivery_id,
        row.try_get::<String, _>("provider_delivery_idempotency_key")
            .map_err(operation_error)?,
        admission_claim,
        GithubCheckHeadSha::try_from_slice(
            &row.try_get::<Vec<u8>, _>("github_check_head_sha")
                .map_err(operation_error)?,
        )
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        GithubCheckSubjectKey::new(
            row.try_get::<String, _>("workflow_path")
                .map_err(operation_error)?,
        )
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        digest_column(row, "source_digest")?,
        row.try_get::<String, _>("event_name")
            .map_err(operation_error)?,
        digest_column(row, "event_digest")?,
        row.try_get::<String, _>("git_ref")
            .map_err(operation_error)?,
        digest_column(row, "plan_digest")?,
        digest_column(row, "logical_admission_digest")?,
        UnixMillis::new(row.try_get("admitted_at_ms").map_err(operation_error)?),
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    Ok(GithubWorkflowRunSubjectEvidence::from_durable_parts(
        request,
        GithubCheckSubjectId::from_uuid(subject_id)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        digest_column(row, "subject_evidence_sha256")?,
    ))
}

fn decode_authority_selector(
    row: &PgRow,
    tenant: TenantScope,
    prefix: &str,
) -> Result<GithubServerServiceAuthoritySelector, GithubSubjectEvidenceStoreError> {
    let id = row
        .try_get::<Uuid, _>(format!("{prefix}_id").as_str())
        .map_err(operation_error)?;
    let digest = digest_column(row, format!("{prefix}_identity_digest").as_str())?;
    let app_revision = row
        .try_get::<i64, _>(format!("{prefix}_app_configuration_revision").as_str())
        .map_err(operation_error)?;
    let policy_revision = row
        .try_get::<i64, _>(format!("{prefix}_policy_revision").as_str())
        .map_err(operation_error)?;
    Ok(GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant,
        GithubServerServiceAuthorityId::from_uuid(id)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        digest,
        GithubServerServiceRevision::new(positive_u64(app_revision)?)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
        GithubServerServiceRevision::new(positive_u64(policy_revision)?)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
    ))
}

fn optional_authority_selector(
    row: &PgRow,
    tenant: TenantScope,
    prefix: &str,
) -> Result<Option<GithubServerServiceAuthoritySelector>, GithubSubjectEvidenceStoreError> {
    let id = row
        .try_get::<Option<Uuid>, _>(format!("{prefix}_id").as_str())
        .map_err(operation_error)?;
    if id.is_none() {
        for suffix in [
            "identity_digest",
            "app_configuration_revision",
            "policy_revision",
        ] {
            let value = row
                .try_get_raw(format!("{prefix}_{suffix}").as_str())
                .map_err(operation_error)?;
            if !value.is_null() {
                return Err(GithubSubjectEvidenceStoreError::CorruptData);
            }
        }
        return Ok(None);
    }
    decode_authority_selector(row, tenant, prefix).map(Some)
}

#[allow(clippy::too_many_lines)]
fn decode_manifest(row: &PgRow) -> Result<GithubProviderManifest, GithubSubjectEvidenceStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let repository_id =
        RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
    let connection_id = ProviderConnectionId::from_uuid(
        row.try_get("provider_connection_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let installation_id = ProviderInstallationId::new(positive_u64(
        row.try_get("provider_installation_id")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let github_repository_id = ProviderRepositoryId::new(positive_u64(
        row.try_get("github_repository_id")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let github_repository_owner_id = row
        .try_get::<Option<i64>, _>("github_repository_owner_id")
        .map_err(operation_error)?
        .map(positive_u64)
        .transpose()?
        .map(ProviderRepositoryOwnerId::new)
        .transpose()
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let github_repository_name = GithubRepositoryName::new(
        row.try_get::<String, _>("github_repository_name")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let repository_visibility = decode_provider_repository_visibility(
        &row.try_get::<String, _>("repository_visibility")
            .map_err(operation_error)?,
    )
    .ok_or(GithubSubjectEvidenceStoreError::CorruptData)?;
    let github_app_id = GithubServerServiceAppId::new(positive_u64(
        row.try_get("github_app_id").map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let app_client_id = GithubServerServiceAppClientId::new(
        row.try_get::<String, _>("github_app_client_id")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let jwt_issuer = decode_github_server_service_jwt_issuer(
        &row.try_get::<String, _>("github_app_jwt_issuer_kind")
            .map_err(operation_error)?,
    )
    .ok_or(GithubSubjectEvidenceStoreError::CorruptData)?;
    let app_configuration_revision = GithubServerServiceRevision::new(positive_u64(
        row.try_get("app_configuration_revision")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let webhook_verifier_fingerprint = GithubProviderWebhookVerifierFingerprint::from_sha256(
        digest_column(row, "webhook_verifier_fingerprint_sha256")?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let webhook_verifier_revision = GithubServerServiceRevision::new(positive_u64(
        row.try_get("webhook_verifier_revision")
            .map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let policy_revision = GithubServerServiceRevision::new(positive_u64(
        row.try_get("policy_revision").map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let authority_profile = match row
        .try_get::<String, _>("authority_profile")
        .map_err(operation_error)?
        .as_str()
    {
        "standard" => JobAuthorityProfile::Standard,
        "credential_free" => JobAuthorityProfile::CredentialFree,
        _ => return Err(GithubSubjectEvidenceStoreError::CorruptData),
    };
    let runner_policy = GithubProviderRunnerPolicyObject::new(
        AdmissionObject::new(
            digest_column(row, "runner_policy_digest")?,
            ObjectKey::new(
                row.try_get::<String, _>("runner_policy_object_key")
                    .map_err(operation_error)?,
            )
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
            positive_column(row, "runner_policy_size_bytes")?,
            row.try_get::<String, _>("runner_policy_media_type")
                .map_err(operation_error)?,
        )
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let runtime_policy_revision =
        WorkflowRuntimePolicyRevision::new(positive_column(row, "runtime_policy_revision")?)
            .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let runtime_policy_digest = digest_column(row, "runtime_policy_digest")?;
    let check_name = GithubCheckName::new(
        row.try_get::<String, _>("check_name")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let limits = GithubProviderManifestLimits::new(
        positive_column(row, "webhook_max_body_bytes")?,
        positive_column(row, "webhook_accept_timeout_ms")?,
        positive_column(row, "push_webhook_max_commits")?,
        positive_column(row, "path_filter_max_commits")?,
        positive_column(row, "path_filter_max_changed_files")?,
        positive_column(row, "archive_max_compressed_bytes")?,
        positive_column(row, "archive_max_decompressed_bytes")?,
        positive_column(row, "archive_max_entries")?,
        positive_column(row, "archive_max_expanded_bytes")?,
        positive_column(row, "archive_max_entry_path_bytes")?,
        positive_column(row, "archive_max_workflows")?,
        positive_column(row, "workflow_max_bytes")?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    let revision = GithubProviderManifestRevision::new(positive_u64(
        row.try_get("manifest_revision").map_err(operation_error)?,
    )?)
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;

    let workflow_path: String = row.try_get("workflow_path").map_err(operation_error)?;
    let check_subject_key: String = row.try_get("check_subject_key").map_err(operation_error)?;
    if workflow_path != check_subject_key {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    require_exact_text(row, "workflow_selection_kind", "all_direct")?;
    if workflow_path != automata_ci_store::GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    let workflow_selection = GithubProviderWorkflowSelection::all_direct();
    require_exact_text(row, "event_name", automata_ci_store::GITHUB_PROVIDER_EVENT)?;
    let git_ref = automata_ci_store::GithubProviderGitRef::new(
        row.try_get::<String, _>("git_ref")
            .map_err(operation_error)?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    require_exact_text(
        row,
        "github_web_origin",
        automata_ci_store::GITHUB_PROVIDER_WEB_ORIGIN,
    )?;
    require_exact_text(
        row,
        "github_api_origin",
        automata_ci_store::GITHUB_PROVIDER_API_ORIGIN,
    )?;
    require_exact_text(
        row,
        "github_archive_origin",
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_ORIGIN,
    )?;
    require_exact_text(
        row,
        "github_rest_api_version",
        automata_ci_store::GITHUB_PROVIDER_REST_API_VERSION,
    )?;
    require_exact_text(
        row,
        "github_rest_accept",
        automata_ci_store::GITHUB_PROVIDER_REST_ACCEPT,
    )?;
    require_exact_text(
        row,
        "github_archive_accept",
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_ACCEPT,
    )?;
    require_exact_text(
        row,
        "repository_source_authentication",
        match repository_visibility {
            ProviderRepositoryVisibility::Public => {
                automata_ci_store::GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION
            }
            ProviderRepositoryVisibility::Private => {
                automata_ci_store::GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION
            }
        },
    )?;
    require_exact_text(
        row,
        "repository_source_revision",
        automata_ci_store::GITHUB_PROVIDER_SOURCE_REVISION,
    )?;
    require_exact_text(
        row,
        "repository_archive_format",
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_FORMAT,
    )?;

    let mut manifest = GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant,
        connection_id,
        installation_id,
        github_repository_id,
        github_repository_name,
        repository_visibility,
        github_app_id,
        app_client_id,
        jwt_issuer,
        digest_column(row, "app_key_spki_sha256")?,
        app_configuration_revision,
        webhook_verifier_fingerprint,
        webhook_verifier_revision,
        policy_revision,
        authority_profile,
        runner_policy,
        runtime_policy_revision,
        runtime_policy_digest,
        workflow_selection,
        git_ref,
        check_name,
        GithubProviderOrigins::github_dot_com(),
        limits,
        revision,
    );
    if let Some(owner_id) = github_repository_owner_id {
        manifest = manifest.with_repository_owner_id(owner_id);
    }
    automata_ci_store::adapter_spi::github_provider_manifest(
        manifest,
        repository_id,
        digest_column(row, "manifest_digest")?,
    )
    .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)
}

const fn provider_repository_visibility_name(
    visibility: ProviderRepositoryVisibility,
) -> &'static str {
    match visibility {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    }
}

fn decode_provider_repository_visibility(value: &str) -> Option<ProviderRepositoryVisibility> {
    match value {
        "public" => Some(ProviderRepositoryVisibility::Public),
        "private" => Some(ProviderRepositoryVisibility::Private),
        _ => None,
    }
}

fn decode_github_authenticated_event_kind(value: &str) -> Option<GithubAuthenticatedEventKind> {
    match value {
        "push" => Some(GithubAuthenticatedEventKind::Push),
        "pull_request" => Some(GithubAuthenticatedEventKind::PullRequest),
        "merge_group" => Some(GithubAuthenticatedEventKind::MergeGroup),
        "repository_dispatch" => Some(GithubAuthenticatedEventKind::RepositoryDispatch),
        _ => None,
    }
}

fn decode_github_repository_dispatch_resolution_authority(
    value: &str,
) -> Option<GithubRepositoryDispatchResolutionAuthority> {
    match value {
        "public_anonymous" => Some(GithubRepositoryDispatchResolutionAuthority::PublicAnonymous),
        "private_source_authority" => {
            Some(GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority)
        }
        _ => None,
    }
}

fn decode_github_server_service_jwt_issuer(value: &str) -> Option<GithubServerServiceJwtIssuer> {
    match value {
        "app_client_id" => Some(GithubServerServiceJwtIssuer::AppClientId),
        "app_id" => Some(GithubServerServiceJwtIssuer::AppId),
        _ => None,
    }
}

fn digest_column(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, GithubSubjectEvidenceStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| GithubSubjectEvidenceStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn positive_column(row: &PgRow, column: &str) -> Result<u64, GithubSubjectEvidenceStoreError> {
    positive_u64(row.try_get(column).map_err(operation_error)?)
}

fn positive_u64(value: i64) -> Result<u64, GithubSubjectEvidenceStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubSubjectEvidenceStoreError::CorruptData)
}

fn require_exact_text(
    row: &PgRow,
    column: &str,
    expected: &str,
) -> Result<(), GithubSubjectEvidenceStoreError> {
    let value: String = row.try_get(column).map_err(operation_error)?;
    if value != expected {
        return Err(GithubSubjectEvidenceStoreError::CorruptData);
    }
    Ok(())
}

fn operation_error(error: sqlx::Error) -> GithubSubjectEvidenceStoreError {
    GithubSubjectEvidenceStoreError::operation(error)
}

const CURRENT_MANIFEST_SELECT: &str = r"
    SELECT
        revision.tenant_id, revision.repository_id,
        revision.provider_connection_id, revision.manifest_revision,
        revision.manifest_digest, revision.provider_installation_id,
        revision.github_repository_id, revision.github_repository_owner_id,
        revision.github_repository_name,
        revision.repository_visibility, revision.github_app_id,
        revision.github_app_client_id, revision.github_app_jwt_issuer_kind,
        revision.app_key_spki_sha256, revision.app_configuration_revision,
        revision.webhook_verifier_fingerprint_sha256,
        revision.webhook_verifier_revision, revision.policy_revision,
        revision.authority_profile,
        revision.runner_policy_digest,
        revision.runner_policy_object_key,
        revision.runner_policy_size_bytes,
        revision.runner_policy_media_type,
        revision.runtime_policy_revision,
        revision.runtime_policy_digest,
        revision.workflow_selection_kind,
        revision.workflow_path, revision.event_name, revision.git_ref,
        revision.check_subject_key, revision.check_name,
        revision.github_web_origin, revision.github_api_origin,
        revision.github_archive_origin, revision.github_rest_api_version,
        revision.github_rest_accept, revision.github_archive_accept,
        revision.repository_source_authentication,
        revision.repository_source_revision, revision.repository_archive_format,
        revision.webhook_max_body_bytes, revision.webhook_accept_timeout_ms,
        revision.push_webhook_max_commits, revision.path_filter_max_commits,
        revision.path_filter_max_changed_files,
        revision.archive_max_compressed_bytes,
        revision.archive_max_decompressed_bytes, revision.archive_max_entries,
        revision.archive_max_expanded_bytes,
        revision.archive_max_entry_path_bytes, revision.archive_max_workflows,
        revision.workflow_max_bytes
    FROM github_provider_manifest_current AS current_manifest
    JOIN github_provider_manifest_revisions AS revision
      ON revision.tenant_id = current_manifest.tenant_id
     AND revision.repository_id = current_manifest.repository_id
     AND revision.provider_connection_id = current_manifest.provider_connection_id
     AND revision.manifest_revision = current_manifest.manifest_revision
     AND revision.manifest_digest = current_manifest.manifest_digest
    WHERE current_manifest.tenant_id = $1
      AND current_manifest.provider_connection_id = $2
      AND revision.provider_installation_id = $3
      AND revision.github_repository_id = $4
      AND revision.repository_visibility = $5
      AND revision.github_repository_name = $6
      AND current_manifest.activated_at_ms <= $7
      AND revision.webhook_verifier_fingerprint_sha256 = $8
      AND revision.webhook_verifier_revision = $9
    FOR SHARE OF current_manifest, revision
";

const PENDING_EVIDENCE_SELECT: &str = r"
    SELECT
        inbox.id AS inbox_id, inbox.tenant_id AS inbox_tenant_id,
        inbox.provider AS inbox_provider,
        inbox.connection_id AS inbox_connection_id,
        inbox.installation_id AS inbox_installation_id,
        inbox.provider_repository_id AS inbox_repository_id,
        inbox.repository_visibility AS inbox_repository_visibility,
        inbox.repository_identity AS inbox_repository_name,
        inbox.delivery_id AS inbox_delivery_key,
        inbox.request_digest, inbox.raw_event_digest,
        inbox.raw_event_object_key, inbox.raw_event_size_bytes,
        inbox.raw_event_media_type, inbox.event_envelope_schema,
        inbox.event_registry_schema, inbox.event_envelope_digest,
        inbox.event_envelope_bytes, inbox.event_envelope_media_type,
        inbox.accepted_at_ms,
        pending.github_repository_owner_id,
        pending.authenticated_event_envelope_version,
        pending.authenticated_event_name, pending.authenticated_event_git_ref,
        pending.authenticated_webhook_verifier_fingerprint_sha256,
        pending.authenticated_webhook_verifier_revision,
        pending.checks_authority_id,
        pending.checks_authority_identity_digest,
        pending.checks_authority_app_configuration_revision,
        pending.checks_authority_policy_revision,
        pending.private_source_authority_id,
        pending.private_source_authority_identity_digest,
        pending.private_source_authority_app_configuration_revision,
        pending.private_source_authority_policy_revision,
        manifest.tenant_id, manifest.repository_id,
        manifest.provider_connection_id, manifest.manifest_revision,
        manifest.manifest_digest, manifest.provider_installation_id,
        manifest.github_repository_id, manifest.github_repository_name,
        manifest.repository_visibility, manifest.github_app_id,
        manifest.github_app_client_id, manifest.github_app_jwt_issuer_kind,
        manifest.app_key_spki_sha256, manifest.app_configuration_revision,
        manifest.webhook_verifier_fingerprint_sha256,
        manifest.webhook_verifier_revision, manifest.policy_revision,
        manifest.authority_profile,
        manifest.runner_policy_digest, manifest.runner_policy_object_key,
        manifest.runner_policy_size_bytes, manifest.runner_policy_media_type,
        manifest.runtime_policy_revision, manifest.runtime_policy_digest,
        manifest.workflow_selection_kind,
        manifest.workflow_path, manifest.event_name, manifest.git_ref,
        manifest.check_subject_key, manifest.check_name,
        manifest.github_web_origin, manifest.github_api_origin,
        manifest.github_archive_origin, manifest.github_rest_api_version,
        manifest.github_rest_accept, manifest.github_archive_accept,
        manifest.repository_source_authentication,
        manifest.repository_source_revision, manifest.repository_archive_format,
        manifest.webhook_max_body_bytes, manifest.webhook_accept_timeout_ms,
        manifest.push_webhook_max_commits, manifest.path_filter_max_commits,
        manifest.path_filter_max_changed_files,
        manifest.archive_max_compressed_bytes,
        manifest.archive_max_decompressed_bytes, manifest.archive_max_entries,
        manifest.archive_max_expanded_bytes,
        manifest.archive_max_entry_path_bytes, manifest.archive_max_workflows,
        manifest.workflow_max_bytes
    FROM provider_delivery_inbox AS inbox
    JOIN github_repository_dispatch_pending_evidence AS pending
      ON pending.provider_delivery_id = inbox.id
     AND pending.tenant_id = inbox.tenant_id
     AND pending.provider_connection_id = inbox.connection_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = pending.tenant_id
     AND manifest.repository_id = pending.repository_id
     AND manifest.provider_connection_id = pending.provider_connection_id
     AND manifest.manifest_revision = pending.provider_manifest_revision
     AND manifest.manifest_digest = pending.provider_manifest_digest
     AND manifest.provider_installation_id = inbox.installation_id
     AND manifest.github_repository_id = inbox.provider_repository_id
     AND manifest.github_repository_name = inbox.repository_identity
     AND manifest.repository_visibility = inbox.repository_visibility
     AND manifest.webhook_verifier_fingerprint_sha256 =
         pending.authenticated_webhook_verifier_fingerprint_sha256
     AND manifest.webhook_verifier_revision =
         pending.authenticated_webhook_verifier_revision
    JOIN repositories AS repository
      ON repository.tenant_id = pending.tenant_id
     AND repository.id = pending.repository_id
     AND repository.scm_provider = 'github'
     AND repository.provider_repository_id = manifest.github_repository_id::TEXT
     AND repository.owner = split_part(manifest.github_repository_name, '/', 1)
     AND repository.name = split_part(manifest.github_repository_name, '/', 2)
    JOIN github_server_service_authorities AS checks_authority
      ON checks_authority.id = pending.checks_authority_id
     AND checks_authority.tenant_id = pending.tenant_id
     AND checks_authority.repository_id = pending.repository_id
     AND checks_authority.provider_connection_id = pending.provider_connection_id
     AND checks_authority.provider_installation_id = manifest.provider_installation_id
     AND checks_authority.github_app_id = manifest.github_app_id
     AND checks_authority.github_repository_id = manifest.github_repository_id
     AND checks_authority.github_repository_name = manifest.github_repository_name
     AND checks_authority.service_scope = 'checks_write'
     AND checks_authority.identity_digest = pending.checks_authority_identity_digest
     AND checks_authority.app_configuration_revision =
         pending.checks_authority_app_configuration_revision
     AND checks_authority.policy_revision = pending.checks_authority_policy_revision
    LEFT JOIN github_server_service_authorities AS private_source_authority
      ON private_source_authority.id = pending.private_source_authority_id
     AND private_source_authority.tenant_id = pending.tenant_id
     AND private_source_authority.repository_id = pending.repository_id
     AND private_source_authority.provider_connection_id = pending.provider_connection_id
     AND private_source_authority.provider_installation_id = manifest.provider_installation_id
     AND private_source_authority.github_app_id = manifest.github_app_id
     AND private_source_authority.github_repository_id = manifest.github_repository_id
     AND private_source_authority.github_repository_name = manifest.github_repository_name
     AND private_source_authority.service_scope = 'private_repository_source_read'
     AND private_source_authority.identity_digest =
         pending.private_source_authority_identity_digest
     AND private_source_authority.app_configuration_revision =
         pending.private_source_authority_app_configuration_revision
     AND private_source_authority.policy_revision =
         pending.private_source_authority_policy_revision
";

const PENDING_EVIDENCE_VISIBILITY_AUTHORITY_EXACT: &str = r"
    AND (
        manifest.repository_visibility = 'public'
        AND pending.private_source_authority_id IS NULL
        OR manifest.repository_visibility = 'private'
        AND private_source_authority.id IS NOT NULL
    )
";

const EVIDENCE_SELECT: &str = r"
    SELECT
        inbox.id AS inbox_id, inbox.tenant_id AS inbox_tenant_id,
        inbox.provider AS inbox_provider,
        inbox.connection_id AS inbox_connection_id,
        inbox.installation_id AS inbox_installation_id,
        inbox.provider_repository_id AS inbox_repository_id,
        inbox.repository_visibility AS inbox_repository_visibility,
        inbox.repository_identity AS inbox_repository_name,
        inbox.delivery_id AS inbox_delivery_key,
        inbox.request_digest, inbox.raw_event_digest,
        inbox.raw_event_object_key, inbox.raw_event_size_bytes,
        inbox.raw_event_media_type, inbox.event_envelope_schema,
        inbox.event_registry_schema, inbox.event_envelope_digest,
        inbox.event_envelope_bytes, inbox.event_envelope_media_type,
        inbox.accepted_at_ms,
        evidence.github_repository_owner_id,
        evidence.authenticated_event_envelope_version,
        evidence.authenticated_event_name, evidence.authenticated_event_git_ref,
        evidence.authenticated_event_source_revision,
        evidence.authenticated_event_source_authority,
        evidence.authenticated_webhook_verifier_fingerprint_sha256,
        evidence.authenticated_webhook_verifier_revision,
        evidence.checks_authority_id,
        evidence.checks_authority_identity_digest,
        evidence.checks_authority_app_configuration_revision,
        evidence.checks_authority_policy_revision,
        evidence.private_source_authority_id,
        evidence.private_source_authority_identity_digest,
        evidence.private_source_authority_app_configuration_revision,
        evidence.private_source_authority_policy_revision,
        evidence.github_check_subject_id, evidence.github_check_head_sha,
        manifest.tenant_id, manifest.repository_id,
        manifest.provider_connection_id, manifest.manifest_revision,
        manifest.manifest_digest, manifest.provider_installation_id,
        manifest.github_repository_id, manifest.github_repository_name,
        manifest.repository_visibility, manifest.github_app_id,
        manifest.github_app_client_id, manifest.github_app_jwt_issuer_kind,
        manifest.app_key_spki_sha256, manifest.app_configuration_revision,
        manifest.webhook_verifier_fingerprint_sha256,
        manifest.webhook_verifier_revision, manifest.policy_revision,
        manifest.authority_profile,
        manifest.runner_policy_digest, manifest.runner_policy_object_key,
        manifest.runner_policy_size_bytes, manifest.runner_policy_media_type,
        manifest.runtime_policy_revision, manifest.runtime_policy_digest,
        manifest.workflow_selection_kind,
        manifest.workflow_path, manifest.event_name, manifest.git_ref,
        manifest.check_subject_key, manifest.check_name,
        manifest.github_web_origin, manifest.github_api_origin,
        manifest.github_archive_origin, manifest.github_rest_api_version,
        manifest.github_rest_accept, manifest.github_archive_accept,
        manifest.repository_source_authentication,
        manifest.repository_source_revision, manifest.repository_archive_format,
        manifest.webhook_max_body_bytes, manifest.webhook_accept_timeout_ms,
        manifest.push_webhook_max_commits, manifest.path_filter_max_commits,
        manifest.path_filter_max_changed_files,
        manifest.archive_max_compressed_bytes,
        manifest.archive_max_decompressed_bytes, manifest.archive_max_entries,
        manifest.archive_max_expanded_bytes,
        manifest.archive_max_entry_path_bytes, manifest.archive_max_workflows,
        manifest.workflow_max_bytes
    FROM provider_delivery_inbox AS inbox
    JOIN github_provider_delivery_evidence AS evidence
      ON evidence.provider_delivery_id = inbox.id
     AND evidence.tenant_id = inbox.tenant_id
     AND evidence.provider_connection_id = inbox.connection_id
     AND evidence.provider_installation_id = inbox.installation_id
     AND evidence.github_repository_id = inbox.provider_repository_id
     AND evidence.github_repository_name = inbox.repository_identity
     AND evidence.repository_visibility = inbox.repository_visibility
    JOIN repositories AS repository
      ON repository.tenant_id = evidence.tenant_id
     AND repository.id = evidence.repository_id
     AND repository.scm_provider = 'github'
     AND repository.provider_repository_id = evidence.github_repository_id::TEXT
     AND repository.owner = split_part(evidence.github_repository_name, '/', 1)
     AND repository.name = split_part(evidence.github_repository_name, '/', 2)
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = evidence.tenant_id
     AND manifest.repository_id = evidence.repository_id
     AND manifest.provider_connection_id = evidence.provider_connection_id
     AND manifest.manifest_revision = evidence.provider_manifest_revision
     AND manifest.manifest_digest = evidence.provider_manifest_digest
     AND manifest.webhook_verifier_fingerprint_sha256 =
         evidence.authenticated_webhook_verifier_fingerprint_sha256
     AND manifest.webhook_verifier_revision =
         evidence.authenticated_webhook_verifier_revision
    JOIN github_server_service_authorities AS checks_authority
      ON checks_authority.id = evidence.checks_authority_id
     AND checks_authority.tenant_id = evidence.tenant_id
     AND checks_authority.repository_id = evidence.repository_id
     AND checks_authority.provider_connection_id = evidence.provider_connection_id
     AND checks_authority.provider_installation_id = evidence.provider_installation_id
     AND checks_authority.github_app_id = manifest.github_app_id
     AND checks_authority.github_repository_id = evidence.github_repository_id
     AND checks_authority.github_repository_name = evidence.github_repository_name
     AND checks_authority.service_scope = 'checks_write'
     AND checks_authority.identity_digest = evidence.checks_authority_identity_digest
     AND checks_authority.app_configuration_revision =
         evidence.checks_authority_app_configuration_revision
     AND checks_authority.policy_revision = evidence.checks_authority_policy_revision
    LEFT JOIN github_server_service_authorities AS private_source_authority
      ON private_source_authority.id = evidence.private_source_authority_id
     AND private_source_authority.tenant_id = evidence.tenant_id
     AND private_source_authority.repository_id = evidence.repository_id
     AND private_source_authority.provider_connection_id = evidence.provider_connection_id
     AND private_source_authority.provider_installation_id = evidence.provider_installation_id
     AND private_source_authority.github_app_id = manifest.github_app_id
     AND private_source_authority.github_repository_id = evidence.github_repository_id
     AND private_source_authority.github_repository_name = evidence.github_repository_name
     AND private_source_authority.service_scope = 'private_repository_source_read'
     AND private_source_authority.identity_digest =
         evidence.private_source_authority_identity_digest
     AND private_source_authority.app_configuration_revision =
         evidence.private_source_authority_app_configuration_revision
     AND private_source_authority.policy_revision =
         evidence.private_source_authority_policy_revision
    JOIN github_check_subjects AS subject
      ON subject.id = evidence.github_check_subject_id
     AND subject.tenant_id = evidence.tenant_id
     AND subject.provider_delivery_id = evidence.provider_delivery_id
     AND subject.repository_id = evidence.repository_id
     AND subject.subject_key = manifest.check_subject_key
     AND subject.head_sha = evidence.github_check_head_sha
    JOIN github_check_projection_outbox AS outbox ON outbox.subject_id = subject.id
";

const EVIDENCE_VISIBILITY_AUTHORITY_EXACT: &str = r"
    AND (
        manifest.repository_visibility = 'public'
        AND evidence.private_source_authority_id IS NULL
        OR manifest.repository_visibility = 'private'
        AND private_source_authority.id IS NOT NULL
    )
";

#[cfg(test)]
mod schema_tests {
    use super::{
        AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION, authenticated_event_envelope_schema_is_current,
    };

    #[test]
    fn authenticated_event_envelope_rejects_noncurrent_schemas() {
        assert!(authenticated_event_envelope_schema_is_current(
            AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION
        ));
        for version in [
            0,
            AUTHENTICATED_EVENT_ENVELOPE_SCHEMA_VERSION
                .checked_add(1)
                .expect("schema version has room for a forward-version test"),
        ] {
            assert!(!authenticated_event_envelope_schema_is_current(version));
        }
    }
}
