//! `PostgreSQL` implementation of deployment-gate selection and hydration.

use std::collections::BTreeSet;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use automata_ci_store::{
    BindLeasedJobSecrets, CancellationActor, CancellationReason, DeploymentEnvironmentName,
    EnvironmentReviewDecision, InspectLeasedJobSecretBindings, IssueLeasedJobSecretGrants,
    IssuedLeasedJobSecretBinding, JobEnvironmentActivationEvidence, JobEnvironmentGatePhase,
    JobEnvironmentGateSnapshot, JobEnvironmentGateState, JobEventTrust, JobSourceKind,
    PrepareJobEnvironment, ProtectedEnvironmentRepository, ProtectedEnvironmentStoreError,
    RequestCancellation, ReusableSecretPermission, ReviewJobEnvironment, StoreError, TenantScope,
};

use super::{PostgresStore, secret_management::authorize_human_repository_action};

const PROTECTED_ENVIRONMENT_REVIEW_PERMISSION: &str = "environments:approve";
const TERMINAL_CANCELLATION_ID_DOMAIN: &[u8] =
    b"automata.store.protected-environment-terminal-cancellation.v1\0";
const PROTECTED_ENVIRONMENT_GATE_LIFETIME_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
const TERMINAL_CANCELLATION_ACTOR: &str = "protected-environment-gate";
const TERMINAL_CANCELLATION_REASON: &str = "protected environment gate terminated";

pub(super) const fn job_event_trust_name(trust: JobEventTrust) -> &'static str {
    match trust {
        JobEventTrust::Trusted => "trusted",
        JobEventTrust::Untrusted => "untrusted",
    }
}

pub(super) const fn job_source_kind_name(source: JobSourceKind) -> &'static str {
    match source {
        JobSourceKind::SameRepository => "same_repository",
        JobSourceKind::Fork => "fork",
        JobSourceKind::Dependabot => "dependabot",
    }
}

pub(super) const fn reusable_secret_permission_name(
    permission: ReusableSecretPermission,
) -> &'static str {
    match permission {
        ReusableSecretPermission::None => "none",
        ReusableSecretPermission::Explicit => "explicit",
    }
}

const fn environment_review_decision_name(decision: EnvironmentReviewDecision) -> &'static str {
    match decision {
        EnvironmentReviewDecision::Approve => "approve",
        EnvironmentReviewDecision::Reject => "reject",
    }
}

#[async_trait]
impl ProtectedEnvironmentRepository for PostgresStore {
    async fn inspect_job_environment_gate(
        &self,
        tenant: &TenantScope,
        attempt_id: automata_ci_core::AttemptId,
    ) -> Result<JobEnvironmentGateSnapshot, ProtectedEnvironmentStoreError> {
        inspect_job_environment_gate(self, tenant, attempt_id).await
    }

    async fn prepare_job_environment(
        &self,
        request: PrepareJobEnvironment,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
        prepare_job_environment(&self.pool, request).await
    }

    async fn review_job_environment(
        &self,
        request: ReviewJobEnvironment,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
        review_job_environment(self, request).await
    }

    async fn conclude_terminal_job_environment(
        &self,
        tenant: &TenantScope,
        attempt_id: automata_ci_core::AttemptId,
    ) -> Result<(), ProtectedEnvironmentStoreError> {
        conclude_terminal_job_environment(self, tenant, attempt_id).await
    }

    async fn resolve_job_credentials(
        &self,
        tenant: &TenantScope,
        attempt_id: automata_ci_core::AttemptId,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
        resolve_job_credentials(self, tenant, attempt_id.as_uuid()).await
    }

    async fn bind_leased_job_secrets(
        &self,
        request: BindLeasedJobSecrets,
    ) -> Result<(), ProtectedEnvironmentStoreError> {
        bind_leased_job_secrets(&self.pool, request).await
    }

    async fn issue_leased_job_secret_grants(
        &self,
        request: IssueLeasedJobSecretGrants,
    ) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError> {
        issue_leased_job_secret_grants(&self.pool, request).await
    }

    async fn inspect_leased_job_secret_bindings(
        &self,
        request: InspectLeasedJobSecretBindings,
    ) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError> {
        inspect_leased_job_secret_bindings(&self.pool, request).await
    }
}

async fn conclude_terminal_job_environment(
    store: &PostgresStore,
    tenant: &TenantScope,
    attempt_id: automata_ci_core::AttemptId,
) -> Result<(), ProtectedEnvironmentStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    super::admission::lock_attempt_concurrency(&mut transaction, attempt_id)
        .await
        .map_err(ProtectedEnvironmentStoreError::Operation)?;
    let row = lock_gate_attempt(&mut transaction, tenant, attempt_id).await?;
    let now = database_now(&mut transaction).await?;
    let mut state: String = row.try_get("state").map_err(operation_error)?;
    let attempt_lifecycle: String = row.try_get("lifecycle").map_err(operation_error)?;
    if state == "ready" && attempt_lifecycle == "cancelled" {
        // Stale-ready inspection preserves the immutable ready snapshot while
        // atomically cancelling the attempt. The scheduler's follow-up
        // conclusion call must therefore replay that canonical cancellation.
        conclude_gate_in_transaction(store, &mut transaction, attempt_id, now).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(());
    }
    if state == "selection_pending" {
        let created_at_ms: i64 = row.try_get("created_at_ms").map_err(operation_error)?;
        if now < gate_deadline(created_at_ms)? {
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
        // The canonical cancellation transition changes an unprepared gate to
        // `cancelled`; no unproven environment identity is fabricated merely
        // to represent expiry.
        "cancelled".clone_into(&mut state);
    }
    if !matches!(state.as_str(), "rejected" | "expired" | "cancelled") {
        return Err(ProtectedEnvironmentStoreError::Conflict);
    }
    conclude_gate_in_transaction(store, &mut transaction, attempt_id, now).await?;
    transaction.commit().await.map_err(operation_error)
}

fn terminal_cancellation_operation_id(
    attempt_id: automata_ci_core::AttemptId,
) -> automata_ci_core::OperationId {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_CANCELLATION_ID_DOMAIN);
    hasher.update(attempt_id.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    automata_ci_core::OperationId::from_uuid(Uuid::from_bytes(bytes))
}

async fn lock_gate_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    attempt_id: automata_ci_core::AttemptId,
) -> Result<PgRow, ProtectedEnvironmentStoreError> {
    sqlx::query(
        r"
        SELECT gate.state, gate.created_at_ms, attempt.lifecycle
        FROM job_environment_gates AS gate
        JOIN job_attempts AS attempt ON attempt.id = gate.attempt_id
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
        FOR UPDATE OF gate, attempt
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)
}

fn gate_deadline(created_at_ms: i64) -> Result<i64, ProtectedEnvironmentStoreError> {
    created_at_ms
        .checked_add(PROTECTED_ENVIRONMENT_GATE_LIFETIME_MILLIS)
        .ok_or(ProtectedEnvironmentStoreError::CorruptData)
}

async fn conclude_gate_in_transaction(
    store: &PostgresStore,
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: automata_ci_core::AttemptId,
    now: i64,
) -> Result<(), ProtectedEnvironmentStoreError> {
    conclude_gate_with_encryption(
        transaction,
        store.runner_payload_encryption.as_ref(),
        attempt_id,
        now,
    )
    .await
}

async fn conclude_gate_with_encryption(
    transaction: &mut Transaction<'_, Postgres>,
    encryption: Option<&super::RunnerPayloadEncryption>,
    attempt_id: automata_ci_core::AttemptId,
    now: i64,
) -> Result<(), ProtectedEnvironmentStoreError> {
    let attempt_lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(attempt_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(operation_error)?
            .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    if !matches!(attempt_lifecycle.as_str(), "queued" | "cancelled") {
        return Err(ProtectedEnvironmentStoreError::Conflict);
    }

    let existing = sqlx::query(
        r"
        SELECT operation_id, requested_by, reason, requested_at_ms,
               acknowledged_at_ms, delivery_session_id,
               delivery_command_sequence
        FROM attempt_cancellation_intents
        WHERE attempt_id = $1
        FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let request = if let Some(existing) = existing {
        if attempt_lifecycle != "cancelled"
            || existing
                .try_get::<Option<i64>, _>("acknowledged_at_ms")
                .map_err(operation_error)?
                .is_some()
            || existing
                .try_get::<Option<Uuid>, _>("delivery_session_id")
                .map_err(operation_error)?
                .is_some()
            || existing
                .try_get::<Option<i64>, _>("delivery_command_sequence")
                .map_err(operation_error)?
                .is_some()
        {
            return Err(ProtectedEnvironmentStoreError::CorruptData);
        }
        let actor: String = existing.try_get("requested_by").map_err(operation_error)?;
        let reason: Option<String> = existing.try_get("reason").map_err(operation_error)?;
        RequestCancellation::new(
            automata_ci_core::OperationId::from_uuid(
                existing.try_get("operation_id").map_err(operation_error)?,
            ),
            attempt_id,
            CancellationActor::new(actor)
                .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?,
            reason
                .map(CancellationReason::new)
                .transpose()
                .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?,
            automata_ci_core::UnixMillis::new(
                existing
                    .try_get("requested_at_ms")
                    .map_err(operation_error)?,
            ),
        )
    } else {
        if attempt_lifecycle != "queued" {
            return Err(ProtectedEnvironmentStoreError::CorruptData);
        }
        RequestCancellation::new(
            terminal_cancellation_operation_id(attempt_id),
            attempt_id,
            CancellationActor::new(TERMINAL_CANCELLATION_ACTOR)
                .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?,
            Some(
                CancellationReason::new(TERMINAL_CANCELLATION_REASON)
                    .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?,
            ),
            automata_ci_core::UnixMillis::new(now),
        )
    };
    super::g1::request_cancellation_in_transaction(transaction, encryption, request.clone())
        .await
        .map_err(terminal_cancellation_error)?;
    // An arbitrary immutable cancellation row is not enough. A prior user or
    // administrator cancellation is reusable only when the canonical G1 state
    // machine produced the exact no-delivery queued terminal authority for it.
    super::server_cancellation_terminal::verify_queued_server_cancellation_terminal(
        transaction,
        &request,
    )
    .await
    .map_err(terminal_cancellation_error)?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // One closed predicate proves every ready-gate authority edge.
async fn ready_gate_is_current(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    attempt_id: automata_ci_core::AttemptId,
    now: i64,
) -> Result<bool, ProtectedEnvironmentStoreError> {
    sqlx::query_scalar(
        r"
        SELECT (
            gate.state = 'ready'
            AND gate.resolution_digest IS NOT DISTINCT FROM
                automata_job_credential_resolution_digest(gate.attempt_id)
            AND (
                gate.environment_id IS NULL
                OR EXISTS (
                    SELECT 1 FROM repository_environments AS environment
                    WHERE environment.tenant_id = gate.tenant_id
                      AND environment.repository_id = gate.repository_id
                      AND environment.id = gate.environment_id
                      AND environment.status = 'active'
                      AND environment.revision = gate.environment_revision
                )
            )
            AND (
                gate.approval_request_id IS NULL
                OR automata_protected_environment_approval_is_current(
                    gate.tenant_id, gate.approval_request_id, $3
                )
            )
            AND gate.resolved_secret_count = (
                SELECT count(*)
                FROM job_secret_selections AS selection
                JOIN secrets AS secret
                  ON secret.tenant_id = selection.tenant_id
                 AND secret.id = selection.secret_id
                 AND secret.current_version_id = selection.secret_version_id
                 AND secret.current_version_number = selection.secret_version_number
                 AND secret.canonical_name = selection.canonical_name
                JOIN secret_policies AS policy
                  ON policy.tenant_id = secret.tenant_id
                 AND policy.secret_id = secret.id
                WHERE selection.attempt_id = gate.attempt_id
                  AND selection.binding_digest IS NOT DISTINCT FROM
                      automata_job_secret_selection_digest(
                          selection.attempt_id, selection.canonical_name,
                          selection.tenant_id, selection.secret_id,
                          selection.secret_version_id,
                          selection.secret_version_number,
                          selection.scope_kind, selection.environment_id
                      )
                  AND automata_secret_is_available_to_gate(secret, policy, gate)
                  AND NOT (
                      selection.scope_kind = 'repository'
                      AND EXISTS (
                          SELECT 1 FROM secrets AS higher
                          JOIN secret_policies AS higher_policy
                            ON higher_policy.tenant_id = higher.tenant_id
                           AND higher_policy.secret_id = higher.id
                          WHERE higher.tenant_id = gate.tenant_id
                            AND higher.repository_id = gate.repository_id
                            AND higher.environment_id = gate.environment_id
                            AND higher.scope_kind = 'environment'
                            AND higher.canonical_name = selection.canonical_name
                            AND automata_secret_is_available_to_gate(
                                higher, higher_policy, gate
                            )
                      )
                  )
                  AND NOT (
                      selection.scope_kind = 'tenant'
                      AND EXISTS (
                          SELECT 1 FROM secrets AS higher
                          JOIN secret_policies AS higher_policy
                            ON higher_policy.tenant_id = higher.tenant_id
                           AND higher_policy.secret_id = higher.id
                          WHERE higher.tenant_id = gate.tenant_id
                            AND higher.repository_id = gate.repository_id
                            AND higher.canonical_name = selection.canonical_name
                            AND higher.scope_kind IN ('repository', 'environment')
                            AND (higher.scope_kind = 'repository'
                                 OR higher.environment_id = gate.environment_id)
                            AND automata_secret_is_available_to_gate(
                                higher, higher_policy, gate
                            )
                      )
                  )
            )
            AND gate.resolved_variable_count = (
                SELECT count(*)
                FROM job_variable_bindings AS binding
                JOIN workflow_variables AS variable
                  ON variable.tenant_id = binding.tenant_id
                 AND variable.id = binding.variable_id
                 AND variable.repository_id = gate.repository_id
                 AND variable.canonical_name = binding.canonical_name
                 AND variable.scope_kind = binding.scope_kind
                 AND variable.environment_id IS NOT DISTINCT FROM binding.environment_id
                 AND variable.current_version_id = binding.variable_version_id
                 AND variable.current_version_number = binding.variable_version_number
                 AND variable.status = 'active'
                WHERE binding.attempt_id = gate.attempt_id
                  AND binding.binding_digest IS NOT DISTINCT FROM
                      automata_job_variable_binding_digest(
                          binding.attempt_id, binding.canonical_name,
                          binding.tenant_id, binding.variable_id,
                          binding.variable_version_id,
                          binding.variable_version_number,
                          binding.scope_kind, binding.environment_id
                      )
                  AND (binding.scope_kind = 'repository'
                       OR binding.environment_id = gate.environment_id)
                  AND NOT EXISTS (
                      SELECT 1 FROM workflow_variables AS higher
                      WHERE higher.tenant_id = gate.tenant_id
                        AND higher.repository_id = gate.repository_id
                        AND higher.environment_id = gate.environment_id
                        AND higher.scope_kind = 'environment'
                        AND higher.canonical_name = binding.canonical_name
                        AND higher.status = 'active'
                        AND binding.scope_kind = 'repository'
                  )
            )
            AND gate.missing_secret_count = (
                -- Missing bindings deliberately snapshot GitHub-compatible
                -- absence. A later create does not rewrite an immutable
                -- resolution; only a selected authority becoming stale or
                -- shadowed invalidates schedulability.
                SELECT count(*) FROM job_missing_secret_bindings
                WHERE attempt_id = gate.attempt_id
            )
            AND gate.missing_variable_count = (
                SELECT count(*) FROM job_missing_variable_bindings
                WHERE attempt_id = gate.attempt_id
            )
        )
        FROM job_environment_gates AS gate
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id.as_uuid())
    .bind(now)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)
}

#[allow(clippy::too_many_lines)] // Inspection locks and reconciles one complete gate snapshot.
async fn inspect_job_environment_gate(
    store: &PostgresStore,
    tenant: &TenantScope,
    attempt_id: automata_ci_core::AttemptId,
) -> Result<JobEnvironmentGateSnapshot, ProtectedEnvironmentStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    super::admission::lock_attempt_concurrency(&mut transaction, attempt_id)
        .await
        .map_err(ProtectedEnvironmentStoreError::Operation)?;
    let row = sqlx::query(
        r"
        SELECT gate.state, gate.created_at_ms, gate.approval_request_id,
               concrete.runtime_context_digest,
               cardinality(job.variable_reference_names) AS variable_reference_count,
               evidence.environment_normalized_name AS gate_environment,
               evidence.event_trust AS gate_event_trust,
               evidence.source_kind AS gate_source_kind,
               evidence.reusable_secret_permission AS gate_reusable_permission
        FROM job_environment_gates AS gate
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = gate.instance_id AND concrete.job_id = gate.job_id
        JOIN logical_workflow_jobs AS job
          ON job.run_id = gate.run_id AND job.invocation_id = gate.invocation_id
         AND job.id = gate.logical_job_id
        JOIN job_attempts AS attempt ON attempt.id = gate.attempt_id
        LEFT JOIN logical_workflow_job_environment_evidence AS evidence
          ON evidence.instance_id = gate.instance_id
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
          AND attempt.lifecycle = 'queued'
        FOR UPDATE OF gate, attempt
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    let database_now_ms = database_now(&mut transaction).await?;
    let mut state: String = row.try_get("state").map_err(operation_error)?;
    if state == "selection_pending"
        && database_now_ms >= gate_deadline(row.try_get("created_at_ms").map_err(operation_error)?)?
    {
        "cancelled".clone_into(&mut state);
    }
    if state == "waiting" {
        let approval_id: Option<Uuid> = row
            .try_get("approval_request_id")
            .map_err(operation_error)?;
        let approval_id = approval_id.ok_or(ProtectedEnvironmentStoreError::CorruptData)?;
        let approval = sqlx::query(
            r"
            SELECT status, expires_at_ms
            FROM protected_environment_approval_requests
            WHERE tenant_id = $1 AND id = $2
            FOR UPDATE
            ",
        )
        .bind(tenant.as_str())
        .bind(approval_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(ProtectedEnvironmentStoreError::CorruptData)?;
        let approval_status: String = approval.try_get("status").map_err(operation_error)?;
        let expires_at_ms: i64 = approval.try_get("expires_at_ms").map_err(operation_error)?;
        if approval_status != "pending" {
            return Err(ProtectedEnvironmentStoreError::CorruptData);
        }
        if database_now_ms >= expires_at_ms {
            expire_gate(
                &mut transaction,
                tenant,
                attempt_id.as_uuid(),
                approval_id,
                database_now_ms,
            )
            .await?;
            "expired".clone_into(&mut state);
        }
    }
    if state == "resolving"
        && !resolving_gate_is_current(&mut transaction, tenant, attempt_id, database_now_ms).await?
    {
        "cancelled".clone_into(&mut state);
    }
    if state == "ready"
        && !ready_gate_is_current(&mut transaction, tenant, attempt_id, database_now_ms).await?
    {
        // `ready` resolution evidence is immutable. Cancellation concludes the
        // attempt while preserving that historical snapshot for audit.
        "cancelled".clone_into(&mut state);
    }
    if matches!(state.as_str(), "rejected" | "expired" | "cancelled") {
        conclude_gate_in_transaction(store, &mut transaction, attempt_id, database_now_ms).await?;
    }
    let phase = match state.as_str() {
        "selection_pending" => JobEnvironmentGatePhase::SelectionPending,
        "waiting" => JobEnvironmentGatePhase::Waiting,
        "resolving" => JobEnvironmentGatePhase::Resolving,
        "ready" => JobEnvironmentGatePhase::Ready,
        "rejected" | "expired" | "cancelled" => JobEnvironmentGatePhase::Terminal,
        "unclassified" => return Err(ProtectedEnvironmentStoreError::AuthorityRejected),
        _ => return Err(ProtectedEnvironmentStoreError::CorruptData),
    };
    let activation = decode_job_environment_activation_evidence(&row).map_err(|error| {
        if matches!(error, StoreError::CorruptData(_)) {
            ProtectedEnvironmentStoreError::CorruptData
        } else {
            ProtectedEnvironmentStoreError::Operation(error)
        }
    })?;
    let runtime_context_digest = decode_sha256_digest(
        row.try_get::<Vec<u8>, _>("runtime_context_digest")
            .map_err(operation_error)?,
    )
    .map_err(|()| ProtectedEnvironmentStoreError::CorruptData)?;
    let variable_reference_count = usize::try_from(
        row.try_get::<i32, _>("variable_reference_count")
            .map_err(operation_error)?,
    )
    .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
    let snapshot = JobEnvironmentGateSnapshot::new(
        phase,
        activation,
        runtime_context_digest,
        automata_ci_core::UnixMillis::new(row.try_get("created_at_ms").map_err(operation_error)?),
        variable_reference_count,
    );
    transaction.commit().await.map_err(operation_error)?;
    Ok(snapshot)
}

async fn resolving_gate_is_current(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    attempt_id: automata_ci_core::AttemptId,
    now: i64,
) -> Result<bool, ProtectedEnvironmentStoreError> {
    sqlx::query_scalar(
        r"
        SELECT (
            gate.state = 'resolving'
            AND (
                gate.environment_id IS NULL
                OR EXISTS (
                    SELECT 1 FROM repository_environments AS environment
                    WHERE environment.tenant_id = gate.tenant_id
                      AND environment.repository_id = gate.repository_id
                      AND environment.id = gate.environment_id
                      AND environment.status = 'active'
                      AND environment.revision = gate.environment_revision
                )
            )
            AND (
                gate.approval_request_id IS NULL
                OR automata_protected_environment_approval_is_current(
                    gate.tenant_id, gate.approval_request_id, $3
                )
            )
        )
        FROM job_environment_gates AS gate
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id.as_uuid())
    .bind(now)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)
}

pub(super) fn decode_job_environment_activation_evidence(
    row: &PgRow,
) -> Result<Option<JobEnvironmentActivationEvidence>, StoreError> {
    let environment: Option<String> = row
        .try_get("gate_environment")
        .map_err(StoreError::operation)?;
    let event_trust: Option<String> = row
        .try_get("gate_event_trust")
        .map_err(StoreError::operation)?;
    let source_kind: Option<String> = row
        .try_get("gate_source_kind")
        .map_err(StoreError::operation)?;
    let reusable_permission: Option<String> = row
        .try_get("gate_reusable_permission")
        .map_err(StoreError::operation)?;
    match (environment, event_trust, source_kind, reusable_permission) {
        (environment, Some(event_trust), Some(source_kind), Some(reusable_permission)) => {
            let environment = environment
                .map(DeploymentEnvironmentName::new)
                .transpose()
                .map_err(|_| StoreError::corrupt_data("invalid activation environment name"))?;
            let event_trust = match event_trust.as_str() {
                "trusted" => JobEventTrust::Trusted,
                "untrusted" => JobEventTrust::Untrusted,
                _ => return Err(StoreError::corrupt_data("invalid activation event trust")),
            };
            let source_kind = match source_kind.as_str() {
                "same_repository" => JobSourceKind::SameRepository,
                "fork" => JobSourceKind::Fork,
                "dependabot" => JobSourceKind::Dependabot,
                _ => return Err(StoreError::corrupt_data("invalid activation source kind")),
            };
            if source_kind != JobSourceKind::SameRepository
                && event_trust != JobEventTrust::Untrusted
            {
                return Err(StoreError::corrupt_data(
                    "activation source trust is inconsistent",
                ));
            }
            let reusable_permission = match reusable_permission.as_str() {
                "none" => ReusableSecretPermission::None,
                "explicit" => ReusableSecretPermission::Explicit,
                _ => {
                    return Err(StoreError::corrupt_data(
                        "invalid activation reusable-secret permission",
                    ));
                }
            };
            Ok(Some(JobEnvironmentActivationEvidence::new(
                environment,
                event_trust,
                source_kind,
                reusable_permission,
            )))
        }
        (None, None, None, None) => Ok(None),
        _ => Err(StoreError::corrupt_data(
            "partial activation environment evidence",
        )),
    }
}

#[derive(Debug)]
struct GateRow {
    attempt_id: Uuid,
    run_id: Uuid,
    repository_id: Uuid,
    state: String,
    requirement_kind: String,
    runtime_context_digest: Vec<u8>,
    event_trust: String,
    source_kind: String,
    reusable_secret_permission: String,
    approval_request_id: Option<Uuid>,
}

#[derive(Debug)]
struct StoredPrepareReplay {
    requirement_kind: String,
    event_trust: String,
    source_kind: String,
    reusable_secret_permission: String,
    environment_normalized_name: Option<String>,
    approval_request_id: Option<Uuid>,
    requested_by_principal_id: Option<Uuid>,
    approval_expires_at_ms: Option<i64>,
}

#[allow(clippy::too_many_lines)] // One transaction binds selection and approval evidence.
async fn prepare_job_environment(
    pool: &PgPool,
    request: PrepareJobEnvironment,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    let request = automata_ci_store::adapter_spi::prepare_job_environment(&request);
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let gate = lock_gate_for_prepare(
        &mut transaction,
        request.tenant(),
        request.attempt_id().as_uuid(),
    )
    .await?;
    verify_runtime_context(&gate, request.activation_context_digest().as_bytes())?;
    let database_now_ms = database_now(&mut transaction).await?;
    let request_age_ms = database_now_ms
        .checked_sub(request.requested_at().get())
        .ok_or(ProtectedEnvironmentStoreError::AuthorityRejected)?;
    if request.requested_at().get() > database_now_ms
        || request_age_ms > 60_000
        || request.approval_expires_at().get() <= database_now_ms
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    match gate.state.as_str() {
        "waiting" | "resolving" | "ready" | "rejected" | "expired" | "cancelled" => {
            let requested_by_principal_id = if gate.approval_request_id.is_some() {
                derive_requester_principal(&mut transaction, request.tenant(), &gate).await?
            } else {
                None
            };
            let stored = load_prepare_replay(&mut transaction, &gate, request.tenant()).await?;
            verify_prepare_replay(&stored, &request, requested_by_principal_id)?;
            transaction.commit().await.map_err(operation_error)?;
            return parse_gate_state(&gate.state);
        }
        "selection_pending" => {}
        "unclassified" => return Err(ProtectedEnvironmentStoreError::AuthorityRejected),
        _ => return Err(ProtectedEnvironmentStoreError::CorruptData),
    }

    let requested_environment = request.environment();
    match (gate.requirement_kind.as_str(), requested_environment) {
        ("none", None) => {
            sqlx::query(
                r"
                UPDATE job_environment_gates
                SET state = 'resolving', event_trust = $3, source_kind = $4,
                    reusable_secret_permission = $5, updated_at_ms = $6,
                    revision = revision + 1
                WHERE attempt_id = $1 AND tenant_id = $2 AND state = 'selection_pending'
                ",
            )
            .bind(request.attempt_id().as_uuid())
            .bind(request.tenant().as_str())
            .bind(job_event_trust_name(request.event_trust()))
            .bind(job_source_kind_name(request.source_kind()))
            .bind(reusable_secret_permission_name(
                request.reusable_secret_permission(),
            ))
            .bind(database_now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        }
        ("environment", Some(environment_name)) => {
            let environment = sqlx::query(
                r"
                SELECT id, revision, protection_mode
                FROM repository_environments
                WHERE tenant_id = $1 AND repository_id = $2
                  AND normalized_name = $3 AND status = 'active'
                FOR SHARE
                ",
            )
            .bind(request.tenant().as_str())
            .bind(gate.repository_id)
            .bind(automata_ci_store::adapter_spi::deployment_environment_name(
                environment_name,
            ))
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(ProtectedEnvironmentStoreError::AuthorityRejected)?;
            let environment_id: Uuid = environment.try_get("id").map_err(operation_error)?;
            let environment_revision: i64 =
                environment.try_get("revision").map_err(operation_error)?;
            let protection_mode: String = environment
                .try_get("protection_mode")
                .map_err(operation_error)?;
            let requested_by_principal_id = if protection_mode == "required_approvals" {
                derive_requester_principal(&mut transaction, request.tenant(), &gate).await?
            } else {
                None
            };

            if protection_mode == "required_approvals" {
                sqlx::query(
                    r"
                    INSERT INTO protected_environment_approval_requests (
                        tenant_id, repository_id, environment_id, run_id, job_id,
                        attempt_id, id, required_approvals, prevent_self_review,
                        requested_by_principal_id, status, created_at_ms, expires_at_ms,
                        resolved_at_ms, resolution_reason, revision
                    )
                    SELECT gate.tenant_id, gate.repository_id, $3, gate.run_id, gate.job_id,
                           gate.attempt_id, $4, environment.required_approvals,
                           environment.prevent_self_review, $5, 'pending', $6, $7,
                           NULL, NULL, 1
                    FROM job_environment_gates AS gate
                    JOIN repository_environments AS environment
                      ON environment.tenant_id = gate.tenant_id
                     AND environment.repository_id = gate.repository_id
                     AND environment.id = $3
                    WHERE gate.attempt_id = $1 AND gate.tenant_id = $2
                      AND gate.state = 'selection_pending'
                    ",
                )
                .bind(request.attempt_id().as_uuid())
                .bind(request.tenant().as_str())
                .bind(environment_id)
                .bind(request.approval_request_id())
                .bind(requested_by_principal_id)
                .bind(database_now_ms)
                .bind(request.approval_expires_at().get())
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
            }

            let target_state = if protection_mode == "required_approvals" {
                "waiting"
            } else {
                "resolving"
            };
            let approval_id =
                (protection_mode == "required_approvals").then_some(request.approval_request_id());
            let result = sqlx::query(
                r"
                UPDATE job_environment_gates
                SET state = $3, environment_id = $4, environment_revision = $5,
                    approval_request_id = $6, event_trust = $7, source_kind = $8,
                    reusable_secret_permission = $9, updated_at_ms = $10,
                    revision = revision + 1
                WHERE attempt_id = $1 AND tenant_id = $2 AND state = 'selection_pending'
                ",
            )
            .bind(request.attempt_id().as_uuid())
            .bind(request.tenant().as_str())
            .bind(target_state)
            .bind(environment_id)
            .bind(environment_revision)
            .bind(approval_id)
            .bind(job_event_trust_name(request.event_trust()))
            .bind(job_source_kind_name(request.source_kind()))
            .bind(reusable_secret_permission_name(
                request.reusable_secret_permission(),
            ))
            .bind(database_now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
            if result.rows_affected() != 1 {
                return Err(ProtectedEnvironmentStoreError::Conflict);
            }
        }
        _ => return Err(ProtectedEnvironmentStoreError::AuthorityRejected),
    }

    transaction.commit().await.map_err(operation_error)?;
    if gate.requirement_kind == "environment" && requested_environment.is_some() {
        let state = if request.environment().is_some() {
            gate_state_after_environment(pool, request.tenant(), request.attempt_id().as_uuid())
                .await?
        } else {
            JobEnvironmentGateState::Resolving
        };
        return Ok(state);
    }
    Ok(JobEnvironmentGateState::Resolving)
}

#[allow(clippy::too_many_lines)] // One transaction serializes review, threshold, and gate state.
async fn review_job_environment(
    store: &PostgresStore,
    request: ReviewJobEnvironment,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    let request = automata_ci_store::adapter_spi::review_job_environment(&request);
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let tenant = TenantScope::from_authenticated_tenant_id(request.actor().tenant_id().as_str())
        .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
    let actor = authorize_human_repository_action(
        &mut transaction,
        request.actor(),
        PROTECTED_ENVIRONMENT_REVIEW_PERMISSION,
        request.repository_id().as_uuid(),
    )
    .await
    .map_err(human_action_error)?
    .ok_or(ProtectedEnvironmentStoreError::AuthorityRejected)?;
    if actor.tenant_id != request.actor().tenant_id().as_str()
        || actor.principal_id.hyphenated().to_string() != request.actor().principal_id().as_str()
        || actor.session_id.hyphenated().to_string() != request.actor().session_id().as_str()
        || i64::try_from(request.actor().authorization_revision().value()).ok()
            != Some(actor.authorization_revision)
    {
        return Err(ProtectedEnvironmentStoreError::CorruptData);
    }
    super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id())
        .await
        .map_err(ProtectedEnvironmentStoreError::Operation)?;
    let gate = sqlx::query(
        r"
        SELECT repository_id, approval_request_id, state
        FROM job_environment_gates
        WHERE tenant_id = $1 AND attempt_id = $2
        FOR UPDATE
        ",
    )
    .bind(tenant.as_str())
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    let repository_id: Uuid = gate.try_get("repository_id").map_err(operation_error)?;
    if repository_id != request.repository_id().as_uuid() {
        return Err(ProtectedEnvironmentStoreError::NotFound);
    }
    let state: String = gate.try_get("state").map_err(operation_error)?;
    let approval_id: Option<Uuid> = gate
        .try_get("approval_request_id")
        .map_err(operation_error)?;
    if state != "waiting" {
        let state = parse_gate_state(&state).map_err(|error| {
            if state == "selection_pending" {
                ProtectedEnvironmentStoreError::Conflict
            } else {
                error
            }
        })?;
        let decision_is_exact = if let Some(approval_id) = approval_id {
            existing_review_decision(&mut transaction, &tenant, approval_id, actor.principal_id)
                .await?
                .as_deref()
                == Some(environment_review_decision_name(request.decision()))
        } else {
            false
        };
        if matches!(
            state,
            JobEnvironmentGateState::Expired | JobEnvironmentGateState::Cancelled
        ) {
            let database_now_ms = database_now(&mut transaction).await?;
            conclude_gate_in_transaction(
                store,
                &mut transaction,
                request.attempt_id(),
                database_now_ms,
            )
            .await?;
            // Expiry/cancellation never applies the requested review decision.
            // Commit liveness, but do not turn an older matching approval row
            // into a successful replay of this non-applied review.
            transaction.commit().await.map_err(operation_error)?;
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
        if state == JobEnvironmentGateState::Rejected {
            let database_now_ms = database_now(&mut transaction).await?;
            conclude_gate_in_transaction(
                store,
                &mut transaction,
                request.attempt_id(),
                database_now_ms,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return if decision_is_exact {
                Ok(state)
            } else {
                Err(ProtectedEnvironmentStoreError::Conflict)
            };
        }
        if !decision_is_exact {
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
        transaction.commit().await.map_err(operation_error)?;
        return Ok(state);
    }
    let approval_id = approval_id.ok_or(ProtectedEnvironmentStoreError::CorruptData)?;

    let request_row = sqlx::query(
        r"
        SELECT repository_id, environment_id, environment_revision, status,
               required_approvals, prevent_self_review,
               requested_by_principal_id, expires_at_ms
        FROM protected_environment_approval_requests
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::CorruptData)?;
    let approval_repository_id: Uuid = request_row
        .try_get("repository_id")
        .map_err(operation_error)?;
    let environment_id: Uuid = request_row
        .try_get("environment_id")
        .map_err(operation_error)?;
    let environment_revision: i64 = request_row
        .try_get("environment_revision")
        .map_err(operation_error)?;
    let status: String = request_row.try_get("status").map_err(operation_error)?;
    let required: i16 = request_row
        .try_get("required_approvals")
        .map_err(operation_error)?;
    let prevent_self_review: bool = request_row
        .try_get("prevent_self_review")
        .map_err(operation_error)?;
    let requested_by_principal_id: Option<Uuid> = request_row
        .try_get("requested_by_principal_id")
        .map_err(operation_error)?;
    let expires_at_ms: i64 = request_row
        .try_get("expires_at_ms")
        .map_err(operation_error)?;
    if approval_repository_id != repository_id
        || environment_id.is_nil()
        || environment_revision <= 0
        || required <= 0
    {
        return Err(ProtectedEnvironmentStoreError::CorruptData);
    }
    let database_now_ms = database_now(&mut transaction).await?;
    if status != "pending" {
        return Err(ProtectedEnvironmentStoreError::CorruptData);
    }
    if database_now_ms >= expires_at_ms {
        expire_gate(
            &mut transaction,
            &tenant,
            request.attempt_id().as_uuid(),
            approval_id,
            database_now_ms,
        )
        .await?;
        conclude_gate_in_transaction(
            store,
            &mut transaction,
            request.attempt_id(),
            database_now_ms,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        // The attempted decision was never recorded. Persist expiry and
        // terminalization, but report a non-applied review rather than echoing
        // a successful decision response that cannot be replayed exactly.
        return Err(ProtectedEnvironmentStoreError::Conflict);
    }

    let decision = environment_review_decision_name(request.decision());
    let inserted = sqlx::query(
        r"
        INSERT INTO protected_environment_approval_decisions (
            tenant_id, request_id, principal_id, decision, decided_at_ms
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (tenant_id, request_id, principal_id) DO NOTHING
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .bind(actor.principal_id)
    .bind(decision)
    .bind(database_now_ms)
    .execute(&mut *transaction)
    .await
    .map_err(review_operation_error)?;
    if inserted.rows_affected() == 0 {
        let existing =
            existing_review_decision(&mut transaction, &tenant, approval_id, actor.principal_id)
                .await?;
        if existing.as_deref() != Some(decision) {
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
    }

    let has_rejection: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM protected_environment_approval_decisions
            WHERE tenant_id = $1 AND request_id = $2 AND decision = 'reject'
              AND automata_environment_reviewer_assignment_is_current(
                  $1, $3, $4, $5, principal_id, $6
              )
        )
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .bind(repository_id)
    .bind(environment_id)
    .bind(environment_revision)
    .bind(database_now_ms)
    .fetch_one(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let approval_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM protected_environment_approval_decisions
        WHERE tenant_id = $1 AND request_id = $2 AND decision = 'approve'
          AND (
              NOT $7
              OR ($8::UUID IS NOT NULL AND principal_id <> $8)
          )
          AND automata_environment_reviewer_assignment_is_current(
              $1, $3, $4, $5, principal_id, $6
          )
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .bind(repository_id)
    .bind(environment_id)
    .bind(environment_revision)
    .bind(database_now_ms)
    .bind(prevent_self_review)
    .bind(requested_by_principal_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(operation_error)?;

    let (approval_status, gate_status, reason) = if has_rejection {
        ("rejected", "rejected", "approval_rejected")
    } else if approval_count >= i64::from(required) {
        ("approved", "resolving", "approval_threshold_met")
    } else {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(JobEnvironmentGateState::Waiting);
    };
    let approval_update = sqlx::query(
        r"
        UPDATE protected_environment_approval_requests
        SET status = $3, resolved_at_ms = $4, resolution_reason = $5,
            revision = revision + 1
        WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .bind(approval_status)
    .bind(database_now_ms)
    .bind(reason)
    .execute(&mut *transaction)
    .await
    .map_err(review_operation_error)?;
    if approval_update.rows_affected() != 1 {
        return Err(ProtectedEnvironmentStoreError::Conflict);
    }
    let gate_update = sqlx::query(
        r"
        UPDATE job_environment_gates
        SET state = $3, updated_at_ms = $4, revision = revision + 1
        WHERE tenant_id = $1 AND attempt_id = $2 AND state = 'waiting'
        ",
    )
    .bind(tenant.as_str())
    .bind(request.attempt_id().as_uuid())
    .bind(gate_status)
    .bind(database_now_ms)
    .execute(&mut *transaction)
    .await
    .map_err(review_operation_error)?;
    if gate_update.rows_affected() != 1 {
        return Err(ProtectedEnvironmentStoreError::Conflict);
    }
    if gate_status == "rejected" {
        conclude_gate_in_transaction(
            store,
            &mut transaction,
            request.attempt_id(),
            database_now_ms,
        )
        .await?;
    }
    transaction.commit().await.map_err(operation_error)?;
    parse_gate_state(gate_status)
}

async fn existing_review_decision(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    approval_id: Uuid,
    principal_id: Uuid,
) -> Result<Option<String>, ProtectedEnvironmentStoreError> {
    sqlx::query_scalar(
        r"
        SELECT decision FROM protected_environment_approval_decisions
        WHERE tenant_id = $1 AND request_id = $2 AND principal_id = $3
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // One transaction makes the complete resolution immutable.
async fn resolve_job_credentials(
    store: &PostgresStore,
    tenant: &TenantScope,
    attempt_id: Uuid,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let typed_attempt_id = automata_ci_core::AttemptId::from_uuid(attempt_id);
    super::admission::lock_attempt_concurrency(&mut transaction, typed_attempt_id)
        .await
        .map_err(ProtectedEnvironmentStoreError::Operation)?;
    let row = sqlx::query(
        r"
        SELECT gate.repository_id, gate.state, job.secret_reference_names,
               job.variable_reference_names
        FROM job_environment_gates AS gate
        JOIN logical_workflow_jobs AS job
          ON job.run_id = gate.run_id AND job.invocation_id = gate.invocation_id
         AND job.id = gate.logical_job_id
        JOIN job_attempts AS attempt ON attempt.id = gate.attempt_id
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
          AND attempt.lifecycle = 'queued'
        FOR UPDATE OF gate, attempt
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    let state: String = row.try_get("state").map_err(operation_error)?;
    if state == "ready" {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(JobEnvironmentGateState::Ready);
    }
    if state != "resolving" {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    let now = database_now(&mut transaction).await?;
    if !resolving_gate_is_current(&mut transaction, tenant, typed_attempt_id, now).await? {
        conclude_gate_in_transaction(store, &mut transaction, typed_attempt_id, now).await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(JobEnvironmentGateState::Cancelled);
    }
    let repository_id: Uuid = row.try_get("repository_id").map_err(operation_error)?;
    let secret_names: Vec<String> = row
        .try_get("secret_reference_names")
        .map_err(operation_error)?;
    let variable_names: Vec<String> = row
        .try_get("variable_reference_names")
        .map_err(operation_error)?;
    for name in &variable_names {
        let candidate = sqlx::query(
            r"
            SELECT variable.id, variable.current_version_id, variable.current_version_number,
                   variable.scope_kind, variable.environment_id
            FROM workflow_variables AS variable
            JOIN job_environment_gates AS gate ON gate.attempt_id = $1
            WHERE variable.tenant_id = gate.tenant_id
              AND variable.repository_id = gate.repository_id
              AND variable.canonical_name = $2 AND variable.status = 'active'
              AND (variable.scope_kind = 'repository'
                   OR (variable.scope_kind = 'environment'
                       AND variable.environment_id = gate.environment_id))
            ORDER BY CASE variable.scope_kind WHEN 'environment' THEN 0 ELSE 1 END
            LIMIT 1
            FOR SHARE OF variable
            ",
        )
        .bind(attempt_id)
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if let Some(candidate) = candidate {
            let variable_id: Uuid = candidate.try_get("id").map_err(operation_error)?;
            let version_id: Uuid = candidate
                .try_get("current_version_id")
                .map_err(operation_error)?;
            let version_number: i64 = candidate
                .try_get("current_version_number")
                .map_err(operation_error)?;
            let scope_kind: String = candidate.try_get("scope_kind").map_err(operation_error)?;
            let environment_id: Option<Uuid> = candidate
                .try_get("environment_id")
                .map_err(operation_error)?;
            sqlx::query(
                r"
                INSERT INTO job_variable_bindings (
                    attempt_id, canonical_name, tenant_id, variable_id,
                    variable_version_id, variable_version_number, scope_kind,
                    environment_id, binding_digest, created_at_ms
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8,
                    automata_job_variable_binding_digest($1,$2,$3,$4,$5,$6,$7,$8),$9
                )
                ",
            )
            .bind(attempt_id)
            .bind(name)
            .bind(tenant.as_str())
            .bind(variable_id)
            .bind(version_id)
            .bind(version_number)
            .bind(scope_kind)
            .bind(environment_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        } else {
            insert_missing_variable(&mut transaction, attempt_id, name, now).await?;
        }
    }

    for name in &secret_names {
        let candidate = sqlx::query(
            r"
            SELECT secret.id, secret.current_version_id, secret.current_version_number,
                   secret.scope_kind, secret.environment_id
            FROM secrets AS secret
            JOIN secret_policies AS policy
              ON policy.tenant_id = secret.tenant_id AND policy.secret_id = secret.id
            JOIN job_environment_gates AS gate ON gate.attempt_id = $1
            WHERE secret.tenant_id = gate.tenant_id
              AND secret.canonical_name = $2
              AND (
                  gate.invocation_kind = 'direct'
                  OR EXISTS (
                      SELECT 1
                      FROM logical_workflow_reusable_secret_bindings AS binding
                      WHERE binding.run_id = gate.run_id
                        AND binding.invocation_id = gate.invocation_id
                        AND upper(binding.target_name) = $2
                  )
              )
              AND automata_secret_is_available_to_gate(secret, policy, gate)
            ORDER BY CASE secret.scope_kind
                WHEN 'environment' THEN 0 WHEN 'repository' THEN 1 ELSE 2 END
            LIMIT 1
            FOR SHARE OF secret, policy
            ",
        )
        .bind(attempt_id)
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if let Some(candidate) = candidate {
            let secret_id: Uuid = candidate.try_get("id").map_err(operation_error)?;
            let version_id: Uuid = candidate
                .try_get("current_version_id")
                .map_err(operation_error)?;
            let version_number: i64 = candidate
                .try_get("current_version_number")
                .map_err(operation_error)?;
            let scope_kind: String = candidate.try_get("scope_kind").map_err(operation_error)?;
            let environment_id: Option<Uuid> = candidate
                .try_get("environment_id")
                .map_err(operation_error)?;
            sqlx::query(
                r"
                INSERT INTO job_secret_selections (
                    attempt_id, canonical_name, tenant_id, secret_id,
                    secret_version_id, secret_version_number, scope_kind,
                    environment_id, binding_digest, created_at_ms
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8,
                    automata_job_secret_selection_digest($1,$2,$3,$4,$5,$6,$7,$8),$9
                )
                ",
            )
            .bind(attempt_id)
            .bind(name)
            .bind(tenant.as_str())
            .bind(secret_id)
            .bind(version_id)
            .bind(version_number)
            .bind(scope_kind)
            .bind(environment_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        } else {
            insert_missing_secret(&mut transaction, attempt_id, name, now).await?;
        }
    }

    let updated = sqlx::query(
        r"
        UPDATE job_environment_gates
        SET state = 'ready',
            resolution_digest = automata_job_credential_resolution_digest(attempt_id),
            resolved_secret_count = (
                SELECT count(*) FROM job_secret_selections WHERE attempt_id = $1
            ),
            missing_secret_count = (
                SELECT count(*) FROM job_missing_secret_bindings WHERE attempt_id = $1
            ),
            resolved_variable_count = (
                SELECT count(*) FROM job_variable_bindings WHERE attempt_id = $1
            ),
            missing_variable_count = (
                SELECT count(*) FROM job_missing_variable_bindings WHERE attempt_id = $1
            ),
            updated_at_ms = $3, revision = revision + 1
        WHERE tenant_id = $2 AND attempt_id = $1 AND state = 'resolving'
        ",
    )
    .bind(attempt_id)
    .bind(tenant.as_str())
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(ProtectedEnvironmentStoreError::Conflict);
    }
    transaction.commit().await.map_err(operation_error)?;
    let _ = repository_id;
    Ok(JobEnvironmentGateState::Ready)
}

async fn bind_leased_job_secrets(
    pool: &PgPool,
    request: BindLeasedJobSecrets,
) -> Result<(), ProtectedEnvironmentStoreError> {
    let request = automata_ci_store::adapter_spi::bind_leased_job_secrets(&request);
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let state: Option<String> = sqlx::query_scalar(
        r"
        SELECT state FROM job_environment_gates
        WHERE tenant_id = $1 AND attempt_id = $2
        FOR SHARE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if state.as_deref() != Some("ready") {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    let selected_names: Vec<String> = sqlx::query_scalar(
        r"
        SELECT canonical_name FROM job_secret_selections
        WHERE attempt_id = $1 ORDER BY canonical_name
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .fetch_all(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let supplied_names = request
        .authorities()
        .iter()
        .map(|authority| {
            automata_ci_store::adapter_spi::secret_lease_authority(authority)
                .canonical_name()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    if supplied_names.len() != request.authorities().len()
        || selected_names.iter().collect::<BTreeSet<_>>() != supplied_names.iter().collect()
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    for authority in request.authorities() {
        let authority = automata_ci_store::adapter_spi::secret_lease_authority(authority);
        let authority_is_exact: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM secret_workload_grants
                WHERE tenant_id = $1 AND id = $2
                  AND authority_digest = $3 AND authority_digest_key_id = $4
                  AND issued_at_ms = $5 AND expires_at_ms = $6
            )
            ",
        )
        .bind(request.tenant().as_str())
        .bind(authority.grant_id())
        .bind(authority.authority_digest().as_bytes().as_slice())
        .bind(authority.authority_digest_key_id())
        .bind(request.issued_at().get())
        .bind(request.expires_at().get())
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if !authority_is_exact {
            return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
        }
        sqlx::query(
            r"
            INSERT INTO job_secret_bindings (
                attempt_id, canonical_name, tenant_id, grant_id, lease_id,
                fencing_token, binding_digest, created_at_ms
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                automata_job_secret_binding_digest($1,$2,$3,$4,$5,$6),$7
            )
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(authority.canonical_name())
        .bind(request.tenant().as_str())
        .bind(authority.grant_id())
        .bind(request.lease_id().as_uuid())
        .bind(
            i64::try_from(request.fencing_token().get())
                .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?,
        )
        .bind(request.issued_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    }
    transaction.commit().await.map_err(operation_error)
}

#[allow(clippy::too_many_lines)] // Issuance deliberately holds gate, attempt, selections, grants, and bindings together.
async fn issue_leased_job_secret_grants(
    pool: &PgPool,
    request: IssueLeasedJobSecretGrants,
) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError> {
    let request = automata_ci_store::adapter_spi::issue_leased_job_secret_grants(&request);
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let fence = i64::try_from(request.fencing_token().get())
        .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
    let gate = sqlx::query(
        r"
        SELECT gate.repository_id, gate.run_id, gate.job_id, gate.environment_id,
               gate.approval_request_id, gate.event_trust, gate.source_kind,
               gate.invocation_kind, gate.reusable_secret_permission, gate.state,
               attempt.lifecycle, attempt.lease_id, attempt.fencing_token,
               attempt.lease_issued_at_ms, attempt.lease_expires_at_ms
        FROM job_environment_gates AS gate
        JOIN job_attempts AS attempt ON attempt.id = gate.attempt_id
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
        FOR UPDATE OF gate, attempt
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    let state: String = gate.try_get("state").map_err(operation_error)?;
    let lifecycle: String = gate.try_get("lifecycle").map_err(operation_error)?;
    let lease_id: Option<Uuid> = gate.try_get("lease_id").map_err(operation_error)?;
    let stored_fence: i64 = gate.try_get("fencing_token").map_err(operation_error)?;
    let lease_issued_at: Option<i64> = gate
        .try_get("lease_issued_at_ms")
        .map_err(operation_error)?;
    let lease_expires_at: Option<i64> = gate
        .try_get("lease_expires_at_ms")
        .map_err(operation_error)?;
    let now = database_now(&mut transaction).await?;
    if state != "ready"
        || lifecycle != "leased"
        || lease_id != Some(request.lease_id().as_uuid())
        || stored_fence != fence
        || lease_issued_at != Some(request.issued_at().get())
        || request.issued_at().get() > now
        || request.expires_at().get() <= now
        || lease_expires_at.is_none_or(|expiry| request.expires_at().get() > expiry)
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    let repository_id: Uuid = gate.try_get("repository_id").map_err(operation_error)?;
    let run_id: Uuid = gate.try_get("run_id").map_err(operation_error)?;
    let job_id: Uuid = gate.try_get("job_id").map_err(operation_error)?;
    let environment_id: Option<Uuid> = gate.try_get("environment_id").map_err(operation_error)?;
    let approval_id: Option<Uuid> = gate
        .try_get("approval_request_id")
        .map_err(operation_error)?;
    let event_trust: String = gate.try_get("event_trust").map_err(operation_error)?;
    let source_kind: String = gate.try_get("source_kind").map_err(operation_error)?;
    let invocation_kind: String = gate.try_get("invocation_kind").map_err(operation_error)?;
    let reusable_permission: String = gate
        .try_get("reusable_secret_permission")
        .map_err(operation_error)?;
    if !matches!(event_trust.as_str(), "trusted" | "untrusted")
        || !matches!(
            source_kind.as_str(),
            "same_repository" | "fork" | "dependabot"
        )
        || !matches!(invocation_kind.as_str(), "direct" | "reusable")
        || !matches!(reusable_permission.as_str(), "none" | "explicit")
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    if let Some(approval_id) = approval_id {
        let approval_current: bool = sqlx::query_scalar(
            "SELECT automata_protected_environment_approval_is_current($1, $2, $3)",
        )
        .bind(request.tenant().as_str())
        .bind(approval_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if !approval_current {
            return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
        }
    }
    let expected_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM job_secret_selections WHERE attempt_id = $1")
            .bind(request.attempt_id().as_uuid())
            .fetch_one(&mut *transaction)
            .await
            .map_err(operation_error)?;
    if !secret_selection_permission_allows_issue(
        &invocation_kind,
        &reusable_permission,
        expected_count,
    ) {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    let selections = sqlx::query(
        r"
        SELECT selection.canonical_name, selection.secret_id,
               selection.secret_version_id, selection.secret_version_number,
               secret.provider_id
        FROM job_secret_selections AS selection
        JOIN secrets AS secret
          ON secret.tenant_id = selection.tenant_id AND secret.id = selection.secret_id
        JOIN secret_policies AS policy
          ON policy.tenant_id = secret.tenant_id AND policy.secret_id = secret.id
        JOIN secret_versions AS version
          ON version.tenant_id = selection.tenant_id
         AND version.id = selection.secret_version_id
         AND version.secret_id = selection.secret_id
         AND version.version_number = selection.secret_version_number
         AND version.provider_id = secret.provider_id
        JOIN secret_version_lifecycle AS lifecycle
          ON lifecycle.tenant_id = version.tenant_id
         AND lifecycle.secret_version_id = version.id
        JOIN secret_providers AS provider
          ON provider.tenant_id = secret.tenant_id AND provider.provider_id = secret.provider_id
        JOIN job_environment_gates AS current_gate ON current_gate.attempt_id = selection.attempt_id
        WHERE selection.attempt_id = $1
          AND selection.binding_digest IS NOT DISTINCT FROM
              automata_job_secret_selection_digest(
                  selection.attempt_id, selection.canonical_name, selection.tenant_id,
                  selection.secret_id, selection.secret_version_id,
                  selection.secret_version_number, selection.scope_kind,
                  selection.environment_id
              )
          AND automata_secret_is_available_to_gate(secret, policy, current_gate)
          AND NOT (
              selection.scope_kind = 'repository'
              AND EXISTS (
                  SELECT 1 FROM secrets AS higher
                  JOIN secret_policies AS higher_policy
                    ON higher_policy.tenant_id = higher.tenant_id
                   AND higher_policy.secret_id = higher.id
                  WHERE higher.tenant_id = current_gate.tenant_id
                    AND higher.repository_id = current_gate.repository_id
                    AND higher.environment_id = current_gate.environment_id
                    AND higher.scope_kind = 'environment'
                    AND higher.canonical_name = selection.canonical_name
                    AND automata_secret_is_available_to_gate(
                        higher, higher_policy, current_gate
                    )
              )
          )
          AND NOT (
              selection.scope_kind = 'tenant'
              AND EXISTS (
                  SELECT 1 FROM secrets AS higher
                  JOIN secret_policies AS higher_policy
                    ON higher_policy.tenant_id = higher.tenant_id
                   AND higher_policy.secret_id = higher.id
                  WHERE higher.tenant_id = current_gate.tenant_id
                    AND higher.repository_id = current_gate.repository_id
                    AND higher.canonical_name = selection.canonical_name
                    AND higher.scope_kind IN ('repository', 'environment')
                    AND (higher.scope_kind = 'repository'
                         OR higher.environment_id = current_gate.environment_id)
                    AND automata_secret_is_available_to_gate(
                        higher, higher_policy, current_gate
                    )
              )
          )
          AND secret.provider_id = 'builtin'
          AND version.storage_kind = 'built_in_ciphertext'
          AND lifecycle.status = 'active'
          AND provider.status = 'active'
        ORDER BY selection.canonical_name
        LIMIT 257
        FOR SHARE OF selection, secret, policy, version, lifecycle, provider, current_gate
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .fetch_all(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if selections.len()
        != usize::try_from(expected_count)
            .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?
        || selections.len() > 256
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }

    let mut issued = Vec::with_capacity(selections.len());
    for selection in selections {
        let name: String = selection
            .try_get("canonical_name")
            .map_err(operation_error)?;
        let secret_id: Uuid = selection.try_get("secret_id").map_err(operation_error)?;
        let version_id: Uuid = selection
            .try_get("secret_version_id")
            .map_err(operation_error)?;
        let version_number: i64 = selection
            .try_get("secret_version_number")
            .map_err(operation_error)?;
        let provider_id: String = selection.try_get("provider_id").map_err(operation_error)?;
        let grant_id = deterministic_grant_id(
            request.attempt_id().as_uuid(),
            secret_id,
            version_id,
            request.lease_id().as_uuid(),
            fence,
        );
        let authority_digest = deterministic_grant_authority_digest(
            request.tenant().as_str(),
            grant_id,
            request.lease_id().as_uuid(),
            fence,
            request.issued_at().get(),
            request.expires_at().get(),
        );
        sqlx::query(
            r"
            INSERT INTO secret_workload_grants (
                tenant_id, repository_id, run_id, job_id, attempt_id, id,
                fencing_token, secret_id, secret_version_id, secret_version_number,
                provider_id, environment_id, environment_approval_request_id, grant_mode,
                event_trust, source_kind, authority_digest, authority_digest_key_id,
                invocation_kind, reusable_secret_permission, lease_id,
                issued_at_ms, expires_at_ms
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'readable_secret',
                $14,$15,$16,'leased-job-secret-grant-v1',$17,$18,$19,$20,$21
            ) ON CONFLICT (tenant_id, attempt_id, secret_id, secret_version_id, grant_mode)
            DO NOTHING
            ",
        )
        .bind(request.tenant().as_str())
        .bind(repository_id)
        .bind(run_id)
        .bind(job_id)
        .bind(request.attempt_id().as_uuid())
        .bind(grant_id)
        .bind(fence)
        .bind(secret_id)
        .bind(version_id)
        .bind(version_number)
        .bind(&provider_id)
        .bind(environment_id)
        .bind(approval_id)
        .bind(&event_trust)
        .bind(&source_kind)
        .bind(authority_digest.as_slice())
        .bind(&invocation_kind)
        .bind(&reusable_permission)
        .bind(request.lease_id().as_uuid())
        .bind(request.issued_at().get())
        .bind(request.expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let existing = sqlx::query(
            r"
            SELECT id, repository_id, run_id, job_id, fencing_token, provider_id,
                   environment_id, environment_approval_request_id, event_trust,
                   source_kind, authority_digest, authority_digest_key_id,
                   invocation_kind, reusable_secret_permission, lease_id,
                   issued_at_ms, expires_at_ms
            FROM secret_workload_grants
            WHERE tenant_id = $1 AND attempt_id = $2 AND secret_id = $3
              AND secret_version_id = $4 AND grant_mode = 'readable_secret'
            FOR SHARE
            ",
        )
        .bind(request.tenant().as_str())
        .bind(request.attempt_id().as_uuid())
        .bind(secret_id)
        .bind(version_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let existing_digest: Vec<u8> = existing
            .try_get("authority_digest")
            .map_err(operation_error)?;
        if existing.try_get::<Uuid, _>("id").map_err(operation_error)? != grant_id
            || existing
                .try_get::<Uuid, _>("repository_id")
                .map_err(operation_error)?
                != repository_id
            || existing
                .try_get::<Uuid, _>("run_id")
                .map_err(operation_error)?
                != run_id
            || existing
                .try_get::<Uuid, _>("job_id")
                .map_err(operation_error)?
                != job_id
            || existing
                .try_get::<i64, _>("fencing_token")
                .map_err(operation_error)?
                != fence
            || existing
                .try_get::<String, _>("provider_id")
                .map_err(operation_error)?
                != provider_id
            || existing
                .try_get::<Option<Uuid>, _>("environment_id")
                .map_err(operation_error)?
                != environment_id
            || existing
                .try_get::<Option<Uuid>, _>("environment_approval_request_id")
                .map_err(operation_error)?
                != approval_id
            || existing
                .try_get::<String, _>("event_trust")
                .map_err(operation_error)?
                != event_trust
            || existing
                .try_get::<String, _>("source_kind")
                .map_err(operation_error)?
                != source_kind
            || existing_digest.as_slice() != authority_digest.as_slice()
            || existing
                .try_get::<String, _>("authority_digest_key_id")
                .map_err(operation_error)?
                != "leased-job-secret-grant-v1"
            || existing
                .try_get::<String, _>("invocation_kind")
                .map_err(operation_error)?
                != invocation_kind
            || existing
                .try_get::<String, _>("reusable_secret_permission")
                .map_err(operation_error)?
                != reusable_permission
            || existing
                .try_get::<Option<Uuid>, _>("lease_id")
                .map_err(operation_error)?
                != Some(request.lease_id().as_uuid())
            || existing
                .try_get::<i64, _>("issued_at_ms")
                .map_err(operation_error)?
                != request.issued_at().get()
            || existing
                .try_get::<i64, _>("expires_at_ms")
                .map_err(operation_error)?
                != request.expires_at().get()
        {
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
        sqlx::query(
            r"
            INSERT INTO job_secret_bindings (
                attempt_id, canonical_name, tenant_id, grant_id, lease_id,
                fencing_token, binding_digest, created_at_ms
            ) VALUES (
                $1,$2,$3,$4,$5,$6,
                automata_job_secret_binding_digest($1,$2,$3,$4,$5,$6),$7
            ) ON CONFLICT (attempt_id, canonical_name) DO NOTHING
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(&name)
        .bind(request.tenant().as_str())
        .bind(grant_id)
        .bind(request.lease_id().as_uuid())
        .bind(fence)
        .bind(request.issued_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let binding_exact: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM job_secret_bindings
                WHERE attempt_id = $1 AND canonical_name = $2 AND tenant_id = $3
                  AND grant_id = $4 AND lease_id = $5 AND fencing_token = $6
                  AND binding_digest IS NOT DISTINCT FROM
                      automata_job_secret_binding_digest($1,$2,$3,$4,$5,$6)
            )
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(&name)
        .bind(request.tenant().as_str())
        .bind(grant_id)
        .bind(request.lease_id().as_uuid())
        .bind(fence)
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if !binding_exact {
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
        let binding = automata_ci_core::SecretBinding::new(grant_id.hyphenated().to_string())
            .and_then(|binding| binding.with_version_id(version_id.hyphenated().to_string()))
            .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
        issued
            .push(automata_ci_store::adapter_spi::issued_leased_job_secret_binding(name, binding));
    }
    transaction.commit().await.map_err(operation_error)?;
    Ok(issued)
}

fn secret_selection_permission_allows_issue(
    invocation_kind: &str,
    reusable_permission: &str,
    selected_secret_count: i64,
) -> bool {
    match (invocation_kind, reusable_permission) {
        ("direct", "none") | ("reusable", "explicit") => true,
        ("reusable", "none") => selected_secret_count == 0,
        _ => false,
    }
}

#[allow(clippy::too_many_lines)] // One snapshot verifies the full leased binding authority.
async fn inspect_leased_job_secret_bindings(
    pool: &PgPool,
    request: InspectLeasedJobSecretBindings,
) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError> {
    let request = automata_ci_store::adapter_spi::inspect_leased_job_secret_bindings(&request);
    let lease = request.lease();
    let fence = i64::try_from(lease.fencing_token().get())
        .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let counts = sqlx::query(
        r"
        SELECT gate.state, attempt.lifecycle, attempt.lease_id,
               attempt.fencing_token, attempt.runner_id,
               attempt.lease_issued_at_ms, attempt.lease_expires_at_ms,
               (SELECT count(*) FROM job_secret_selections AS selection
                WHERE selection.attempt_id = gate.attempt_id) AS selected_secret_count,
               (SELECT count(*) FROM job_secret_bindings AS binding
                WHERE binding.attempt_id = gate.attempt_id) AS issued_binding_count
        FROM job_environment_gates AS gate
        JOIN job_attempts AS attempt ON attempt.id = gate.attempt_id
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
        FOR SHARE OF gate, attempt
        ",
    )
    .bind(request.tenant().as_str())
    .bind(lease.attempt_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    let state: String = counts.try_get("state").map_err(operation_error)?;
    let lifecycle: String = counts.try_get("lifecycle").map_err(operation_error)?;
    let lease_id: Option<Uuid> = counts.try_get("lease_id").map_err(operation_error)?;
    let stored_fence: i64 = counts.try_get("fencing_token").map_err(operation_error)?;
    let runner_id: Option<Uuid> = counts.try_get("runner_id").map_err(operation_error)?;
    let issued_at: Option<i64> = counts
        .try_get("lease_issued_at_ms")
        .map_err(operation_error)?;
    let expires_at: Option<i64> = counts
        .try_get("lease_expires_at_ms")
        .map_err(operation_error)?;
    if state != "ready"
        || !matches!(lifecycle.as_str(), "leased" | "preparing" | "running")
        || lease_id != Some(lease.lease_id().as_uuid())
        || stored_fence != fence
        || runner_id != Some(lease.runner_id().as_uuid())
        || issued_at != Some(lease.issued_at().get())
        || expires_at != Some(lease.expires_at().get())
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    let selected_secret_count: i64 = counts
        .try_get("selected_secret_count")
        .map_err(operation_error)?;
    let issued_binding_count: i64 = counts
        .try_get("issued_binding_count")
        .map_err(operation_error)?;
    let rows = sqlx::query(
        r"
        SELECT binding.canonical_name, binding.grant_id,
               grant.secret_version_id
        FROM job_secret_bindings AS binding
        JOIN job_secret_selections AS selection
          ON selection.attempt_id = binding.attempt_id
         AND selection.canonical_name = binding.canonical_name
        JOIN secret_workload_grants AS grant
          ON grant.tenant_id = binding.tenant_id
         AND grant.id = binding.grant_id
         AND grant.attempt_id = binding.attempt_id
         AND grant.secret_id = selection.secret_id
         AND grant.secret_version_id = selection.secret_version_id
         AND grant.secret_version_number = selection.secret_version_number
        WHERE binding.attempt_id = $1
          AND binding.tenant_id = $2
          AND binding.lease_id = $3
          AND binding.fencing_token = $4
          AND binding.binding_digest IS NOT DISTINCT FROM
              automata_job_secret_binding_digest(
                  binding.attempt_id, binding.canonical_name, binding.tenant_id,
                  binding.grant_id, binding.lease_id, binding.fencing_token
              )
          AND grant.lease_id = $3
          AND grant.fencing_token = $4
          AND grant.issued_at_ms = $5
          AND grant.expires_at_ms = $6
          AND grant.grant_mode = 'readable_secret'
          AND grant.status = 'active'
        ORDER BY binding.canonical_name
        LIMIT 257
        FOR SHARE OF binding, selection, grant
        ",
    )
    .bind(lease.attempt_id().as_uuid())
    .bind(request.tenant().as_str())
    .bind(lease.lease_id().as_uuid())
    .bind(fence)
    .bind(lease.issued_at().get())
    .bind(lease.expires_at().get())
    .fetch_all(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let expected = usize::try_from(selected_secret_count)
        .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
    let issued = usize::try_from(issued_binding_count)
        .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
    if expected > 256 || issued != expected || rows.len() != expected {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    let bindings = rows
        .into_iter()
        .map(|row| {
            let name: String = row.try_get("canonical_name").map_err(operation_error)?;
            let grant_id: Uuid = row.try_get("grant_id").map_err(operation_error)?;
            let version_id: Uuid = row.try_get("secret_version_id").map_err(operation_error)?;
            let binding = automata_ci_core::SecretBinding::new(grant_id.hyphenated().to_string())
                .and_then(|value| value.with_version_id(version_id.hyphenated().to_string()))
                .map_err(|_| ProtectedEnvironmentStoreError::CorruptData)?;
            Ok(automata_ci_store::adapter_spi::issued_leased_job_secret_binding(name, binding))
        })
        .collect::<Result<Vec<_>, ProtectedEnvironmentStoreError>>()?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(bindings)
}

fn deterministic_grant_id(
    attempt_id: Uuid,
    secret_id: Uuid,
    version_id: Uuid,
    lease_id: Uuid,
    fencing_token: i64,
) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"automata.store.leased-job-secret-grant.v1\0");
    for identity in [attempt_id, secret_id, version_id, lease_id] {
        digest.update(identity.as_bytes());
    }
    digest.update(fencing_token.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    // This is a deterministic opaque UUID, with RFC-4122 version/variant bits
    // set explicitly without enabling UUID v5 as a workspace-wide dependency.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_grant_authority_digest(
    tenant: &str,
    grant_id: Uuid,
    lease_id: Uuid,
    fencing_token: i64,
    issued_at: i64,
    expires_at: i64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"automata.store.leased-job-secret-grant-authority.v1\0");
    digest.update((tenant.len() as u64).to_be_bytes());
    digest.update(tenant.as_bytes());
    digest.update(grant_id.as_bytes());
    digest.update(lease_id.as_bytes());
    digest.update(fencing_token.to_be_bytes());
    digest.update(issued_at.to_be_bytes());
    digest.update(expires_at.to_be_bytes());
    digest.finalize().into()
}

async fn lock_gate_for_prepare(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    attempt_id: Uuid,
) -> Result<GateRow, ProtectedEnvironmentStoreError> {
    let row = sqlx::query(
        r"
        SELECT gate.run_id, gate.repository_id, gate.state,
               gate.environment_requirement_kind,
               concrete.runtime_context_digest, gate.event_trust,
               gate.source_kind, gate.reusable_secret_permission,
               gate.approval_request_id
        FROM job_environment_gates AS gate
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = gate.instance_id AND concrete.job_id = gate.job_id
        JOIN job_attempts AS attempt ON attempt.id = gate.attempt_id
        WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
          AND attempt.lifecycle = 'queued'
        FOR UPDATE OF gate, attempt
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    Ok(GateRow {
        attempt_id,
        run_id: row.try_get("run_id").map_err(operation_error)?,
        repository_id: row.try_get("repository_id").map_err(operation_error)?,
        state: row.try_get("state").map_err(operation_error)?,
        requirement_kind: row
            .try_get("environment_requirement_kind")
            .map_err(operation_error)?,
        runtime_context_digest: row
            .try_get("runtime_context_digest")
            .map_err(operation_error)?,
        event_trust: row.try_get("event_trust").map_err(operation_error)?,
        source_kind: row.try_get("source_kind").map_err(operation_error)?,
        reusable_secret_permission: row
            .try_get("reusable_secret_permission")
            .map_err(operation_error)?,
        approval_request_id: row
            .try_get("approval_request_id")
            .map_err(operation_error)?,
    })
}

/// Resolves only immutable, exact human admission evidence for the gate's run.
/// Provider webhooks and schedules intentionally return `None`: a display login
/// is not a stable human identity and must never weaken self-review separation.
#[allow(clippy::too_many_lines)] // The exact human authority union stays visible in one proof.
async fn derive_requester_principal(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    gate: &GateRow,
) -> Result<Option<Uuid>, ProtectedEnvironmentStoreError> {
    let rerun = sqlx::query(
        r"
        SELECT rerun.actor_principal_id, rerun.actor_session_id,
               rerun.authorization_revision, rerun.committed_at_ms,
               evidence.recorded_at_ms, audit.occurred_at_ms,
               audit.actor_kind, audit.actor_principal_id AS audit_principal_id,
               audit.actor_session_id AS audit_session_id,
               audit.authorization_revision AS audit_authorization_revision,
               audit.action, audit.outcome, audit.resource_kind, audit.resource_id
        FROM workflow_rerun_requests AS rerun
        LEFT JOIN workflow_rerun_audit_evidence AS evidence
          ON evidence.tenant_id = rerun.tenant_id
         AND evidence.operation_id = rerun.operation_id
         AND evidence.run_id = rerun.rerun_run_id
        LEFT JOIN security_audit_events AS audit
          ON audit.event_id = evidence.event_id
         AND audit.tenant_id = rerun.tenant_id
        WHERE rerun.tenant_id = $1
          AND rerun.repository_id = $2
          AND rerun.rerun_run_id = $3
        ",
    )
    .bind(tenant.as_str())
    .bind(gate.repository_id)
    .bind(gate.run_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = rerun {
        let principal_id: Uuid = row.try_get("actor_principal_id").map_err(operation_error)?;
        let session_id: Uuid = row.try_get("actor_session_id").map_err(operation_error)?;
        let authorization_revision: i64 = row
            .try_get("authorization_revision")
            .map_err(operation_error)?;
        let committed_at_ms: Option<i64> =
            row.try_get("committed_at_ms").map_err(operation_error)?;
        let expected_resource_id = gate.run_id.hyphenated().to_string();
        let exact = !principal_id.is_nil()
            && !session_id.is_nil()
            && authorization_revision > 0
            && committed_at_ms.is_some()
            && row
                .try_get::<Option<i64>, _>("recorded_at_ms")
                .map_err(operation_error)?
                == committed_at_ms
            && row
                .try_get::<Option<i64>, _>("occurred_at_ms")
                .map_err(operation_error)?
                == committed_at_ms
            && row
                .try_get::<Option<String>, _>("actor_kind")
                .map_err(operation_error)?
                .as_deref()
                == Some("human")
            && row
                .try_get::<Option<Uuid>, _>("audit_principal_id")
                .map_err(operation_error)?
                == Some(principal_id)
            && row
                .try_get::<Option<Uuid>, _>("audit_session_id")
                .map_err(operation_error)?
                == Some(session_id)
            && row
                .try_get::<Option<i64>, _>("audit_authorization_revision")
                .map_err(operation_error)?
                == Some(authorization_revision)
            && row
                .try_get::<Option<String>, _>("action")
                .map_err(operation_error)?
                .as_deref()
                == Some("workflow.rerun")
            && row
                .try_get::<Option<String>, _>("outcome")
                .map_err(operation_error)?
                .as_deref()
                == Some("succeeded")
            && row
                .try_get::<Option<String>, _>("resource_kind")
                .map_err(operation_error)?
                .as_deref()
                == Some("workflow_run")
            && row
                .try_get::<Option<String>, _>("resource_id")
                .map_err(operation_error)?
                .as_deref()
                == Some(expected_resource_id.as_str());
        return exact
            .then_some(Some(principal_id))
            .ok_or(ProtectedEnvironmentStoreError::CorruptData);
    }

    let rows = sqlx::query(
        r"
        SELECT run.event_name, run.actor, run.created_at_ms,
               audit.actor_kind, audit.actor_principal_id,
               audit.actor_session_id, audit.authorization_revision,
               audit.occurred_at_ms, audit.outcome
        FROM repositories AS repository
        JOIN workflow_runs AS run ON run.repository_id = repository.id
        LEFT JOIN security_audit_events AS audit
          ON audit.tenant_id = repository.tenant_id
         AND audit.action = 'workflow.dispatch'
         AND audit.resource_kind = 'workflow_run'
         AND audit.resource_id = run.id::TEXT
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND run.id = $3
        LIMIT 2
        ",
    )
    .bind(tenant.as_str())
    .bind(gate.repository_id)
    .bind(gate.run_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.is_empty() || rows.len() > 1 {
        return Err(ProtectedEnvironmentStoreError::CorruptData);
    }
    let row = &rows[0];
    let event_name: String = row.try_get("event_name").map_err(operation_error)?;
    if event_name != "workflow_dispatch" {
        return Ok(None);
    }
    let principal_id: Option<Uuid> = row.try_get("actor_principal_id").map_err(operation_error)?;
    let run_actor: Option<String> = row.try_get("actor").map_err(operation_error)?;
    let run_created_at_ms: i64 = row.try_get("created_at_ms").map_err(operation_error)?;
    let expected_actor = principal_id.map(|id| id.hyphenated().to_string());
    let exact = principal_id.is_some_and(|id| !id.is_nil())
        && run_actor.as_deref() == expected_actor.as_deref()
        && row
            .try_get::<Option<String>, _>("actor_kind")
            .map_err(operation_error)?
            .as_deref()
            == Some("human")
        && row
            .try_get::<Option<Uuid>, _>("actor_session_id")
            .map_err(operation_error)?
            .is_some_and(|id| !id.is_nil())
        && row
            .try_get::<Option<i64>, _>("authorization_revision")
            .map_err(operation_error)?
            .is_some_and(|revision| revision > 0)
        && row
            .try_get::<Option<i64>, _>("occurred_at_ms")
            .map_err(operation_error)?
            == Some(run_created_at_ms)
        && row
            .try_get::<Option<String>, _>("outcome")
            .map_err(operation_error)?
            .as_deref()
            == Some("succeeded");
    exact
        .then_some(principal_id)
        .flatten()
        .map(Some)
        .ok_or(ProtectedEnvironmentStoreError::CorruptData)
}

fn verify_runtime_context(
    gate: &GateRow,
    supplied_digest: &[u8],
) -> Result<(), ProtectedEnvironmentStoreError> {
    if gate.runtime_context_digest.len() != 32
        || gate.runtime_context_digest.as_slice() != supplied_digest
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    Ok(())
}

async fn load_prepare_replay(
    transaction: &mut Transaction<'_, Postgres>,
    gate: &GateRow,
    tenant: &TenantScope,
) -> Result<StoredPrepareReplay, ProtectedEnvironmentStoreError> {
    let (environment_normalized_name, requested_by_principal_id, approval_expires_at_ms): (
        Option<String>,
        Option<Uuid>,
        Option<i64>,
    ) = sqlx::query_as(
        r"
            SELECT environment.normalized_name, approval.requested_by_principal_id,
                   approval.expires_at_ms
            FROM job_environment_gates AS gate
            LEFT JOIN repository_environments AS environment
              ON environment.tenant_id = gate.tenant_id
             AND environment.repository_id = gate.repository_id
             AND environment.id = gate.environment_id
            LEFT JOIN protected_environment_approval_requests AS approval
              ON approval.tenant_id = gate.tenant_id
             AND approval.id = gate.approval_request_id
            WHERE gate.tenant_id = $1 AND gate.attempt_id = $2
            ",
    )
    .bind(tenant.as_str())
    .bind(gate.attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::CorruptData)?;
    Ok(StoredPrepareReplay {
        requirement_kind: gate.requirement_kind.clone(),
        event_trust: gate.event_trust.clone(),
        source_kind: gate.source_kind.clone(),
        reusable_secret_permission: gate.reusable_secret_permission.clone(),
        environment_normalized_name,
        approval_request_id: gate.approval_request_id,
        requested_by_principal_id,
        approval_expires_at_ms,
    })
}

fn verify_prepare_replay(
    stored: &StoredPrepareReplay,
    request: &PrepareJobEnvironment,
    requested_by_principal_id: Option<Uuid>,
) -> Result<(), ProtectedEnvironmentStoreError> {
    let request = automata_ci_store::adapter_spi::prepare_job_environment(request);
    let environment_matches = match (
        stored.requirement_kind.as_str(),
        stored.environment_normalized_name.as_deref(),
        request.environment(),
    ) {
        ("none", None, None) => true,
        ("environment", Some(stored_name), Some(requested_name)) => {
            automata_ci_store::adapter_spi::deployment_environment_name(requested_name)
                == stored_name
        }
        _ => false,
    };
    let approval_matches = match stored.approval_request_id {
        Some(approval_id) => {
            approval_id == request.approval_request_id()
                && stored.requested_by_principal_id == requested_by_principal_id
                && stored.approval_expires_at_ms == Some(request.approval_expires_at().get())
        }
        None => true,
    };
    if environment_matches
        && approval_matches
        && stored.event_trust == job_event_trust_name(request.event_trust())
        && stored.source_kind == job_source_kind_name(request.source_kind())
        && stored.reusable_secret_permission
            == reusable_secret_permission_name(request.reusable_secret_permission())
    {
        Ok(())
    } else {
        Err(ProtectedEnvironmentStoreError::Conflict)
    }
}

async fn insert_missing_variable(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
    name: &str,
    now: i64,
) -> Result<(), ProtectedEnvironmentStoreError> {
    sqlx::query(
        r"
        INSERT INTO job_missing_variable_bindings (attempt_id, canonical_name, created_at_ms)
        VALUES ($1, $2, $3)
        ",
    )
    .bind(attempt_id)
    .bind(name)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_missing_secret(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
    name: &str,
    now: i64,
) -> Result<(), ProtectedEnvironmentStoreError> {
    sqlx::query(
        r"
        INSERT INTO job_missing_secret_bindings (attempt_id, canonical_name, created_at_ms)
        VALUES ($1, $2, $3)
        ",
    )
    .bind(attempt_id)
    .bind(name)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, ProtectedEnvironmentStoreError> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn expire_gate(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    attempt_id: Uuid,
    approval_id: Uuid,
    now: i64,
) -> Result<(), ProtectedEnvironmentStoreError> {
    sqlx::query(
        r"
        UPDATE protected_environment_approval_requests
        SET status = 'expired', resolved_at_ms = $3,
            resolution_reason = 'approval_expired', revision = revision + 1
        WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
        ",
    )
    .bind(tenant.as_str())
    .bind(approval_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        UPDATE job_environment_gates
        SET state = 'expired', updated_at_ms = $3, revision = revision + 1
        WHERE tenant_id = $1 AND attempt_id = $2 AND state = 'waiting'
        ",
    )
    .bind(tenant.as_str())
    .bind(attempt_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn gate_state_after_environment(
    pool: &PgPool,
    tenant: &TenantScope,
    attempt_id: Uuid,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    let state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM job_environment_gates WHERE tenant_id = $1 AND attempt_id = $2",
    )
    .bind(tenant.as_str())
    .bind(attempt_id)
    .fetch_optional(pool)
    .await
    .map_err(operation_error)?;
    state
        .as_deref()
        .ok_or(ProtectedEnvironmentStoreError::NotFound)
        .and_then(parse_gate_state)
}

fn parse_gate_state(
    value: &str,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    match value {
        "waiting" => Ok(JobEnvironmentGateState::Waiting),
        "resolving" => Ok(JobEnvironmentGateState::Resolving),
        "ready" => Ok(JobEnvironmentGateState::Ready),
        "rejected" => Ok(JobEnvironmentGateState::Rejected),
        "expired" => Ok(JobEnvironmentGateState::Expired),
        "cancelled" => Ok(JobEnvironmentGateState::Cancelled),
        _ => Err(ProtectedEnvironmentStoreError::CorruptData),
    }
}

fn decode_sha256_digest(value: Vec<u8>) -> Result<automata_ci_core::Sha256Digest, ()> {
    let bytes = value.try_into().map_err(|_| ())?;
    Ok(automata_ci_core::Sha256Digest::from_bytes(bytes))
}

fn operation_error(error: sqlx::Error) -> ProtectedEnvironmentStoreError {
    ProtectedEnvironmentStoreError::Operation(StoreError::operation(error))
}

fn terminal_cancellation_error(error: StoreError) -> ProtectedEnvironmentStoreError {
    match error {
        StoreError::CorruptData(_) => ProtectedEnvironmentStoreError::CorruptData,
        error => ProtectedEnvironmentStoreError::Operation(error),
    }
}

fn human_action_error(error: StoreError) -> ProtectedEnvironmentStoreError {
    match error {
        operation @ StoreError::Operation(_) => {
            ProtectedEnvironmentStoreError::Operation(operation)
        }
        _ => ProtectedEnvironmentStoreError::CorruptData,
    }
}

fn review_operation_error(error: sqlx::Error) -> ProtectedEnvironmentStoreError {
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    match constraint {
        Some(
            "protected_environment_approval_decisions_pending"
            | "protected_environment_approval_decisions_current_policy"
            | "protected_environment_approval_decisions_lifetime"
            | "protected_environment_approval_decisions_reviewer"
            | "protected_environment_approval_decisions_self_review"
            | "protected_environment_approval_requester_required"
            | "protected_environment_approval_resolution_current"
            | "protected_environment_approval_resolution_proven"
            | "protected_environment_approval_threshold_proven"
            | "protected_environment_approval_rejection_proven",
        ) => ProtectedEnvironmentStoreError::AuthorityRejected,
        _ => operation_error(error),
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{AttemptId, Sha256Digest, UnixMillis};

    use super::*;
    use automata_ci_store::{
        DeploymentEnvironmentName, JobEventTrust, JobSourceKind, ReusableSecretPermission,
    };

    const REQUESTED_AT: i64 = 10;
    const EXPIRES_AT: i64 = 100;

    #[test]
    fn reusable_permission_is_required_only_when_secret_selection_is_nonempty() {
        assert!(secret_selection_permission_allows_issue(
            "reusable", "none", 0
        ));
        assert!(!secret_selection_permission_allows_issue(
            "reusable", "none", 1
        ));
        assert!(secret_selection_permission_allows_issue(
            "reusable", "explicit", 1
        ));
        assert!(secret_selection_permission_allows_issue(
            "direct", "none", 1
        ));
        assert!(!secret_selection_permission_allows_issue(
            "direct", "explicit", 0
        ));
    }

    fn prepare_request(
        environment: &str,
        approval_request_id: Uuid,
        approval_expires_at: i64,
        event_trust: JobEventTrust,
        source_kind: JobSourceKind,
        reusable_secret_permission: ReusableSecretPermission,
    ) -> PrepareJobEnvironment {
        PrepareJobEnvironment::new(
            TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
            AttemptId::from_uuid(Uuid::from_u128(1)),
            Some(DeploymentEnvironmentName::new(environment).expect("environment")),
            Sha256Digest::from_bytes([7; 32]),
            event_trust,
            source_kind,
            reusable_secret_permission,
            approval_request_id,
            UnixMillis::new(REQUESTED_AT),
            UnixMillis::new(approval_expires_at),
        )
        .expect("prepare request")
    }

    #[test]
    fn prepare_replay_accepts_only_the_exact_persisted_identity() {
        let approval_request_id = Uuid::from_u128(2);
        let requested_by_principal_id = Uuid::from_u128(3);
        let stored = StoredPrepareReplay {
            requirement_kind: "environment".to_owned(),
            event_trust: "trusted".to_owned(),
            source_kind: "same_repository".to_owned(),
            reusable_secret_permission: "none".to_owned(),
            environment_normalized_name: Some("production".to_owned()),
            approval_request_id: Some(approval_request_id),
            requested_by_principal_id: Some(requested_by_principal_id),
            approval_expires_at_ms: Some(EXPIRES_AT),
        };
        let exact = prepare_request(
            "Production",
            approval_request_id,
            EXPIRES_AT,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        );
        assert!(verify_prepare_replay(&stored, &exact, Some(requested_by_principal_id)).is_ok());

        let mismatches = [
            prepare_request(
                "staging",
                approval_request_id,
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                Uuid::from_u128(4),
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                EXPIRES_AT + 1,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                EXPIRES_AT,
                JobEventTrust::Untrusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::Fork,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::Explicit,
            ),
        ];
        for mismatch in mismatches {
            assert!(matches!(
                verify_prepare_replay(&stored, &mismatch, Some(requested_by_principal_id)),
                Err(ProtectedEnvironmentStoreError::Conflict)
            ));
        }
        assert!(matches!(
            verify_prepare_replay(&stored, &exact, Some(Uuid::from_u128(5))),
            Err(ProtectedEnvironmentStoreError::Conflict)
        ));
    }
}
