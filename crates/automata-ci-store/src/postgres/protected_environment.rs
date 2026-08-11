//! `PostgreSQL` implementation of deployment-gate selection and hydration.

use std::collections::BTreeSet;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    BindLeasedJobSecrets, IssueLeasedJobSecretGrants, IssuedLeasedJobSecretBinding,
    JobEnvironmentGateState, PrepareJobEnvironment, ProtectedEnvironmentRepository,
    ProtectedEnvironmentStoreError, ReviewJobEnvironment, StoreError, TenantScope,
};

use super::PostgresStore;

#[async_trait]
impl ProtectedEnvironmentRepository for PostgresStore {
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
        review_job_environment(&self.pool, request).await
    }

    async fn resolve_job_credentials(
        &self,
        tenant: &TenantScope,
        attempt_id: automata_ci_core::AttemptId,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
        resolve_job_credentials(&self.pool, tenant, attempt_id.as_uuid()).await
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
}

#[derive(Debug)]
struct GateRow {
    attempt_id: Uuid,
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
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let gate = lock_gate_for_prepare(
        &mut transaction,
        request.tenant(),
        request.attempt_id().as_uuid(),
    )
    .await?;
    verify_runtime_context(&gate, request.activation_context_digest().as_bytes())?;
    let database_now_ms = database_now(&mut transaction).await?;
    if request.requested_at().get() > database_now_ms
        || database_now_ms - request.requested_at().get() > 60_000
        || request.approval_expires_at().get() <= database_now_ms
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }

    match gate.state.as_str() {
        "waiting" | "resolving" | "ready" | "rejected" | "expired" | "cancelled" => {
            let stored = load_prepare_replay(&mut transaction, &gate, request.tenant()).await?;
            verify_prepare_replay(&stored, &request)?;
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
            .bind(request.event_trust().as_str())
            .bind(request.source_kind().as_str())
            .bind(request.reusable_secret_permission().as_str())
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
            .bind(environment_name.normalized())
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
                .bind(request.requested_by_principal_id())
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
            .bind(request.event_trust().as_str())
            .bind(request.source_kind().as_str())
            .bind(request.reusable_secret_permission().as_str())
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
    pool: &PgPool,
    request: ReviewJobEnvironment,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let gate = sqlx::query(
        r"
        SELECT approval_request_id, state
        FROM job_environment_gates
        WHERE tenant_id = $1 AND attempt_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::NotFound)?;
    let state: String = gate.try_get("state").map_err(operation_error)?;
    let approval_id: Option<Uuid> = gate
        .try_get("approval_request_id")
        .map_err(operation_error)?;
    let approval_id = approval_id.ok_or(ProtectedEnvironmentStoreError::AuthorityRejected)?;
    if state != "waiting" {
        transaction.commit().await.map_err(operation_error)?;
        return parse_gate_state(&state);
    }

    let request_row = sqlx::query(
        r"
        SELECT status, required_approvals, expires_at_ms
        FROM protected_environment_approval_requests
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(approval_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ProtectedEnvironmentStoreError::CorruptData)?;
    let status: String = request_row.try_get("status").map_err(operation_error)?;
    let required: i16 = request_row
        .try_get("required_approvals")
        .map_err(operation_error)?;
    let expires_at_ms: i64 = request_row
        .try_get("expires_at_ms")
        .map_err(operation_error)?;
    let database_now_ms = database_now(&mut transaction).await?;
    if status != "pending" {
        transaction.commit().await.map_err(operation_error)?;
        return gate_state_after_environment(
            pool,
            request.tenant(),
            request.attempt_id().as_uuid(),
        )
        .await;
    }
    if database_now_ms >= expires_at_ms {
        expire_gate(
            &mut transaction,
            request.tenant(),
            request.attempt_id().as_uuid(),
            approval_id,
            database_now_ms,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(JobEnvironmentGateState::Expired);
    }

    let decision = request.decision().as_str();
    let inserted = sqlx::query(
        r"
        INSERT INTO protected_environment_approval_decisions (
            tenant_id, request_id, principal_id, decision, decided_at_ms
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (tenant_id, request_id, principal_id) DO NOTHING
        ",
    )
    .bind(request.tenant().as_str())
    .bind(approval_id)
    .bind(request.principal_id())
    .bind(decision)
    .bind(request.decided_at().get())
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    if inserted.rows_affected() == 0 {
        let existing: Option<(String, i64)> = sqlx::query_as(
            r"
            SELECT decision, decided_at_ms FROM protected_environment_approval_decisions
            WHERE tenant_id = $1 AND request_id = $2 AND principal_id = $3
            ",
        )
        .bind(request.tenant().as_str())
        .bind(approval_id)
        .bind(request.principal_id())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if existing
            .as_ref()
            .is_none_or(|(stored_decision, stored_at_ms)| {
                stored_decision != decision || *stored_at_ms != request.decided_at().get()
            })
        {
            return Err(ProtectedEnvironmentStoreError::Conflict);
        }
    }

    let has_rejection: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM protected_environment_approval_decisions
            WHERE tenant_id = $1 AND request_id = $2 AND decision = 'reject'
        )
        ",
    )
    .bind(request.tenant().as_str())
    .bind(approval_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let approval_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM protected_environment_approval_decisions
        WHERE tenant_id = $1 AND request_id = $2 AND decision = 'approve'
        ",
    )
    .bind(request.tenant().as_str())
    .bind(approval_id)
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
    sqlx::query(
        r"
        UPDATE protected_environment_approval_requests
        SET status = $3, resolved_at_ms = $4, resolution_reason = $5,
            revision = revision + 1
        WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
        ",
    )
    .bind(request.tenant().as_str())
    .bind(approval_id)
    .bind(approval_status)
    .bind(database_now_ms)
    .bind(reason)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        UPDATE job_environment_gates
        SET state = $3, updated_at_ms = $4, revision = revision + 1
        WHERE tenant_id = $1 AND attempt_id = $2 AND state = 'waiting'
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.attempt_id().as_uuid())
    .bind(gate_status)
    .bind(database_now_ms)
    .execute(&mut *transaction)
    .await
    .map_err(operation_error)?;
    transaction.commit().await.map_err(operation_error)?;
    parse_gate_state(gate_status)
}

#[allow(clippy::too_many_lines)] // One transaction makes the complete resolution immutable.
async fn resolve_job_credentials(
    pool: &PgPool,
    tenant: &TenantScope,
    attempt_id: Uuid,
) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    let row = sqlx::query(
        r"
        SELECT gate.repository_id, gate.state, job.secret_reference_names,
               job.variable_reference_names
        FROM job_environment_gates AS gate
        JOIN workflow_plan_v2_jobs AS job
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
    let repository_id: Uuid = row.try_get("repository_id").map_err(operation_error)?;
    let secret_names: Vec<String> = row
        .try_get("secret_reference_names")
        .map_err(operation_error)?;
    let variable_names: Vec<String> = row
        .try_get("variable_reference_names")
        .map_err(operation_error)?;
    let now = database_now(&mut transaction).await?;

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
        .map(|authority| authority.canonical_name().to_owned())
        .collect::<BTreeSet<_>>();
    if supplied_names.len() != request.authorities().len()
        || selected_names.iter().collect::<BTreeSet<_>>() != supplied_names.iter().collect()
    {
        return Err(ProtectedEnvironmentStoreError::AuthorityRejected);
    }
    for authority in request.authorities() {
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
        || (invocation_kind == "reusable" && reusable_permission != "explicit")
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
        issued.push(IssuedLeasedJobSecretBinding::new(name, binding));
    }
    transaction.commit().await.map_err(operation_error)?;
    Ok(issued)
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
        SELECT gate.repository_id, gate.state, gate.environment_requirement_kind,
               concrete.runtime_context_digest, gate.event_trust,
               gate.source_kind, gate.reusable_secret_permission,
               gate.approval_request_id
        FROM job_environment_gates AS gate
        JOIN workflow_plan_v2_concrete_jobs AS concrete
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
) -> Result<(), ProtectedEnvironmentStoreError> {
    let environment_matches = match (
        stored.requirement_kind.as_str(),
        stored.environment_normalized_name.as_deref(),
        request.environment(),
    ) {
        ("none", None, None) => true,
        ("environment", Some(stored_name), Some(requested_name)) => {
            requested_name.normalized() == stored_name
        }
        _ => false,
    };
    let approval_matches = match stored.approval_request_id {
        Some(approval_id) => {
            approval_id == request.approval_request_id()
                && stored.requested_by_principal_id == request.requested_by_principal_id()
                && stored.approval_expires_at_ms == Some(request.approval_expires_at().get())
        }
        None => true,
    };
    if environment_matches
        && approval_matches
        && stored.event_trust == request.event_trust().as_str()
        && stored.source_kind == request.source_kind().as_str()
        && stored.reusable_secret_permission == request.reusable_secret_permission().as_str()
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

fn operation_error(error: sqlx::Error) -> ProtectedEnvironmentStoreError {
    ProtectedEnvironmentStoreError::Operation(StoreError::operation(error))
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{AttemptId, Sha256Digest, UnixMillis};

    use super::*;
    use crate::{
        DeploymentEnvironmentName, JobEventTrust, JobSourceKind, ReusableSecretPermission,
    };

    const REQUESTED_AT: i64 = 10;
    const EXPIRES_AT: i64 = 100;

    fn prepare_request(
        environment: &str,
        approval_request_id: Uuid,
        requested_by_principal_id: Option<Uuid>,
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
            requested_by_principal_id,
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
            Some(requested_by_principal_id),
            EXPIRES_AT,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        );
        assert!(verify_prepare_replay(&stored, &exact).is_ok());

        let mismatches = [
            prepare_request(
                "staging",
                approval_request_id,
                Some(requested_by_principal_id),
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                Uuid::from_u128(4),
                Some(requested_by_principal_id),
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                Some(Uuid::from_u128(5)),
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                Some(requested_by_principal_id),
                EXPIRES_AT + 1,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                Some(requested_by_principal_id),
                EXPIRES_AT,
                JobEventTrust::Untrusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                Some(requested_by_principal_id),
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::Fork,
                ReusableSecretPermission::None,
            ),
            prepare_request(
                "production",
                approval_request_id,
                Some(requested_by_principal_id),
                EXPIRES_AT,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::Explicit,
            ),
        ];
        for mismatch in mismatches {
            assert!(matches!(
                verify_prepare_replay(&stored, &mismatch),
                Err(ProtectedEnvironmentStoreError::Conflict)
            ));
        }
    }
}
