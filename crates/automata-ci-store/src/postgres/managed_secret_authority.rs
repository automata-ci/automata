use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use automata_ci_core::{Sha256Digest, UnixMillis};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    MANAGED_SECRET_AUTHORITY_SCHEMA, MAX_MANAGED_SECRET_BINDINGS, ManagedSecretAuthorityBinding,
    ManagedSecretAuthorityReceipt, ManagedSecretAuthorityRepository,
    ManagedSecretAuthorityStoreError, ManagedSecretGrantMode, ManagedSecretProviderId,
    RepositorySecretId, RepositorySecretVersionId, ResolveManagedSecretAuthority,
    SecretWorkloadGrantId,
};

use super::PostgresStore;

const EVIDENCE_DOMAIN: &[u8] = b"automata/store/managed-secret-authority:v1\0";

#[derive(Debug)]
struct ExecutionRow {
    attempt_number: i32,
    secret_exposure_class: String,
    job_ir_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    event_digest: Sha256Digest,
    runtime_context_digest: Sha256Digest,
}

#[derive(Debug)]
struct RawGrantRow {
    grant_id: Uuid,
    version_id: Uuid,
}

#[derive(Debug)]
struct GrantRow {
    grant_id: Uuid,
    fencing_token: i64,
    secret_id: Uuid,
    version_id: Uuid,
    version_number: i64,
    provider_id: String,
    environment_id: Option<Uuid>,
    approval_id: Option<Uuid>,
    grant_mode: String,
    event_trust: String,
    source_kind: String,
    authority_digest: Vec<u8>,
    authority_digest_key_id: String,
    grant_status: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    revocation_reason: Option<String>,
    secret_scope_kind: String,
    secret_repository_id: Option<Uuid>,
    secret_environment_id: Option<Uuid>,
    secret_status: String,
    current_version_id: Option<Uuid>,
    current_version_number: Option<i64>,
    secret_revision: i64,
    repository_access_mode: String,
    minimum_event_trust: String,
    allow_fork_pull_requests: bool,
    allow_dependabot: bool,
    reusable_workflow_mode: String,
    policy_revision: i64,
    storage_kind: String,
    version_lifecycle_status: String,
    version_lifecycle_revision: i64,
    provider_adapter_kind: String,
    provider_supports_dynamic_leases: bool,
    provider_status: String,
    provider_revision: i64,
}

#[derive(Debug)]
struct EnvironmentRow {
    id: Uuid,
    protection_mode: String,
    required_approvals: i16,
    prevent_self_review: bool,
    status: String,
    revision: i64,
}

#[derive(Debug)]
struct ApprovalRow {
    id: Uuid,
    environment_id: Uuid,
    required_approvals: i16,
    prevent_self_review: bool,
    status: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    resolved_at_ms: Option<i64>,
    resolution_reason: Option<String>,
    revision: i64,
}

#[async_trait]
impl ManagedSecretAuthorityRepository for PostgresStore {
    async fn resolve_managed_secret_authority(
        &self,
        request: ResolveManagedSecretAuthority,
    ) -> Result<ManagedSecretAuthorityReceipt, ManagedSecretAuthorityStoreError> {
        match check_managed_secret_authority(&self.pool, &request).await {
            Err(ManagedSecretAuthorityStoreError::Unavailable) => {
                Err(ManagedSecretAuthorityStoreError::Unavailable)
            }
            Ok(()) | Err(_) => Err(ManagedSecretAuthorityStoreError::Unauthorized),
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep the one-transaction check order visible and auditable.
async fn check_managed_secret_authority(
    pool: &PgPool,
    request: &ResolveManagedSecretAuthority,
) -> Result<(), ManagedSecretAuthorityStoreError> {
    let mut transaction = pool.begin().await.map_err(operation_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    let execution = lock_current_execution(&mut transaction, request).await?;
    lock_current_attempt_set(&mut transaction, request, execution.attempt_number).await?;
    let mut raw_grants = lock_raw_workload_grants(&mut transaction, request).await?;
    if raw_grants.len() > MAX_MANAGED_SECRET_BINDINGS {
        return Err(ManagedSecretAuthorityStoreError::ResourceExhausted);
    }
    raw_grants.sort_unstable_by_key(|grant| grant.grant_id);
    if raw_grants
        .windows(2)
        .any(|pair| pair[0].grant_id == pair[1].grant_id)
    {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }

    let expected = request
        .bindings()
        .entries()
        .map(|(grant_id, version_id)| (grant_id.as_uuid(), version_id.as_uuid()))
        .collect::<BTreeMap<_, _>>();
    if raw_grants.len() != expected.len()
        || raw_grants
            .iter()
            .any(|grant| expected.get(&grant.grant_id).copied() != Some(grant.version_id))
    {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }

    let mut grants = lock_grant_dependencies(&mut transaction, request).await?;
    grants.sort_unstable_by_key(|grant| grant.grant_id);
    if grants.len() != raw_grants.len()
        || grants.iter().zip(&raw_grants).any(|(grant, raw)| {
            grant.grant_id != raw.grant_id || grant.version_id != raw.version_id
        })
    {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }

    let access_secret_ids = grants
        .iter()
        .filter(|grant| {
            grant.secret_scope_kind == "tenant"
                && grant.repository_access_mode == "selected_repositories"
        })
        .map(|grant| grant.secret_id)
        .collect::<BTreeSet<_>>();
    let repository_access =
        lock_repository_access(&mut transaction, request, &access_secret_ids).await?;
    let environment_ids = grants
        .iter()
        .filter_map(|grant| grant.environment_id)
        .collect::<BTreeSet<_>>();
    let environments = lock_environments(&mut transaction, request, &environment_ids).await?;
    let approval_ids = grants
        .iter()
        .filter_map(|grant| grant.approval_id)
        .collect::<BTreeSet<_>>();
    let approvals = lock_approvals(&mut transaction, request, &approval_ids).await?;

    let mut usable_until = request.lease().expires_at();
    let mut checked_bindings = Vec::with_capacity(grants.len());
    for grant in &grants {
        let verified = validate_grant(
            request,
            &execution,
            grant,
            &repository_access,
            &environments,
            &approvals,
        )?;
        usable_until = UnixMillis::new(usable_until.get().min(grant.expires_at_ms));
        if let Some(approval_id) = grant.approval_id {
            let approval = approvals
                .get(&approval_id)
                .ok_or(ManagedSecretAuthorityStoreError::CorruptData)?;
            usable_until = UnixMillis::new(usable_until.get().min(approval.expires_at_ms));
        }
        checked_bindings.push(verified);
    }
    if usable_until <= request.observed_at() {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    let _pending_evidence_digest = evidence_digest(
        request,
        &execution,
        &checked_bindings,
        &grants,
        &repository_access,
        &environments,
        &approvals,
        usable_until,
    );
    transaction.commit().await.map_err(operation_error)?;

    // No receipt can be issued on the current schema/credential contract.
    // Migration 0012 permits a terminal grant to be reactivated, so this
    // read cannot prove monotonic non-replay. The schema also permits a
    // terminal historical attempt to become live again and has no exact
    // one-current-attempt invariant. In addition, the request only carries
    // public execution/binding identities and never proves possession of
    // the credential authenticated by `authority_digest`. Keep the fully
    // checked, value-free foundation closed until those durable invariants
    // and an exact authenticated credential or control-session binding are
    // inputs, with a one-operation consumption fence after this transaction.
    // This port has no proof-of-possession or authenticated control-call
    // input. Returning a distinct "otherwise matched" result would turn
    // public binding IDs into an authority-validation oracle, so the
    // current adapter deliberately collapses its non-issuing outcome into
    // the same closed result as every unauthorized target.
    Ok(())
}

// `FOR UPDATE OF attempt` is deliberate: besides pinning the live lease, it
// conflicts with the FK key-share lock of an in-flight workload-grant insert.
// The subsequent exact-set query therefore cannot miss a concurrently committed
// grant for this attempt/fence.
#[allow(clippy::too_many_lines)] // The exact execution lock is one auditable SQL predicate.
async fn lock_current_execution(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
) -> Result<ExecutionRow, ManagedSecretAuthorityStoreError> {
    let lease = request.lease();
    let session = request.session();
    let row = sqlx::query(
        r"
        SELECT attempt.attempt_number, attempt.secret_exposure_class,
               job.job_ir_digest, run.plan_digest, run.event_digest,
               concrete.runtime_context_digest
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        JOIN workflow_plan_v2_concrete_jobs AS concrete ON concrete.job_id = job.id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN runners AS runner ON runner.id = attempt.runner_id
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.runner_id = attempt.runner_id
        WHERE attempt.id = $1
          AND attempt.job_id = $2
          AND attempt.fencing_token = $3
          AND attempt.lease_id = $4
          AND attempt.lease_issued_at_ms = $5
          AND attempt.lease_expires_at_ms = $6
          AND attempt.runner_id = $7
          AND attempt.runner_session_id = $8
          AND attempt.runner_session_epoch = $9
          AND attempt.runner_generation = $10
          AND attempt.runner_slot = $11
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= $16
          AND attempt.lease_expires_at_ms > $16
          AND job.id = $2
          AND job.run_id = $12
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND run.id = $12
          AND run.repository_id = $13
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.status IN ('queued', 'in_progress')
          AND run.plan_digest = invocation.plan_digest
          AND repository.id = $13
          AND repository.tenant_id = $14
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND marker.root_invocation_id = invocation.id
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND instance.job_ir_version = 5
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.runtime_context_schema = 2
          AND instance.runtime_context_digest = $15
          AND concrete.runtime_context_schema = 2
          AND concrete.runtime_context_digest = $15
          AND concrete.runtime_context_digest = instance.runtime_context_digest
          AND concrete.requirements = job.requirements
          AND concrete.event_digest = run.event_digest
          AND runner.id = $7
          AND runner.tenant_id = $14
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.generation = $10
          AND runner.session_epoch = $9
          AND session.id = $8
          AND session.session_epoch = $9
          AND session.runner_generation = $10
          AND session.job_ir_schema = 5
          AND session.disconnected_at_ms IS NULL
        FOR UPDATE OF attempt, job
        FOR SHARE OF run, repository, marker, concrete, instance,
                     logical_job, invocation, runner, session
        ",
    )
    .bind(lease.attempt_id().as_uuid())
    .bind(request.job_id().as_uuid())
    .bind(positive_i64(lease.fencing_token().get())?)
    .bind(lease.lease_id().as_uuid())
    .bind(lease.issued_at().get())
    .bind(lease.expires_at().get())
    .bind(lease.runner_id().as_uuid())
    .bind(session.session_id().as_uuid())
    .bind(positive_i64(session.session_epoch().get())?)
    .bind(positive_i64(session.runner_generation().get())?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.run_id().as_uuid())
    .bind(request.repository_id().as_uuid())
    .bind(request.tenant().as_str())
    .bind(request.runtime_context_digest().as_bytes().as_slice())
    .bind(request.observed_at().get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
    let execution = ExecutionRow {
        attempt_number: field(&row, "attempt_number")?,
        secret_exposure_class: field(&row, "secret_exposure_class")?,
        job_ir_digest: digest_field(&row, "job_ir_digest")?,
        plan_digest: digest_field(&row, "plan_digest")?,
        event_digest: digest_field(&row, "event_digest")?,
        runtime_context_digest: digest_field(&row, "runtime_context_digest")?,
    };
    if execution.attempt_number <= 0
        || !matches!(
            execution.secret_exposure_class.as_str(),
            "secretless" | "capability_only" | "readable_secret"
        )
        || execution.runtime_context_digest != request.runtime_context_digest()
    {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }
    Ok(execution)
}

// Locking the job `FOR UPDATE` above conflicts with the FK key-share lock of a
// new attempt insert. This bounded probe locks rows that currently disprove
// authority: the selected attempt, another nonterminal attempt, or a newer
// attempt. It intentionally does not claim a complete current-attempt proof:
// the current schema can reactivate an older terminal row outside this probe.
// No receipt is issued until terminal-attempt immutability and an exact
// one-current-attempt invariant make that predicate durable.
async fn lock_current_attempt_set(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
    requested_attempt_number: i32,
) -> Result<(), ManagedSecretAuthorityStoreError> {
    let rows = sqlx::query(
        r"
        SELECT id, attempt_number, lifecycle
        FROM job_attempts
        WHERE job_id = $1
          AND (
              id = $2
              OR attempt_number > $3
              OR lifecycle IN (
                  'queued', 'leased', 'preparing', 'running',
                  'cancelling', 'finalizing'
              )
          )
        ORDER BY attempt_number, id
        LIMIT 3
        FOR SHARE
        ",
    )
    .bind(request.job_id().as_uuid())
    .bind(request.lease().attempt_id().as_uuid())
    .bind(requested_attempt_number)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut live_count = 0_usize;
    let mut requested_count = 0_usize;
    let mut has_newer_attempt = false;
    for row in &rows {
        let id: Uuid = field(row, "id")?;
        let attempt_number: i32 = field(row, "attempt_number")?;
        let lifecycle: String = field(row, "lifecycle")?;
        if id.is_nil() || attempt_number <= 0 {
            return Err(ManagedSecretAuthorityStoreError::CorruptData);
        }
        has_newer_attempt |= attempt_number > requested_attempt_number;
        if matches!(
            lifecycle.as_str(),
            "queued" | "leased" | "preparing" | "running" | "cancelling" | "finalizing"
        ) {
            live_count += 1;
        }
        if id == request.lease().attempt_id().as_uuid()
            && attempt_number == requested_attempt_number
        {
            requested_count += 1;
        }
    }
    if requested_count != 1 || live_count != 1 || has_newer_attempt {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    Ok(())
}

async fn lock_raw_workload_grants(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
) -> Result<Vec<RawGrantRow>, ManagedSecretAuthorityStoreError> {
    let rows = sqlx::query(
        r"
        SELECT id AS grant_id, secret_version_id
        FROM secret_workload_grants
        WHERE tenant_id = $1
          AND repository_id = $2
          AND run_id = $3
          AND job_id = $4
          AND attempt_id = $5
          AND fencing_token = $6
        ORDER BY id
        LIMIT 257
        FOR SHARE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.job_id().as_uuid())
    .bind(request.lease().attempt_id().as_uuid())
    .bind(positive_i64(request.lease().fencing_token().get())?)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.iter()
        .map(|row| {
            Ok(RawGrantRow {
                grant_id: field(row, "grant_id")?,
                version_id: field(row, "secret_version_id")?,
            })
        })
        .collect()
}

async fn lock_grant_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
) -> Result<Vec<GrantRow>, ManagedSecretAuthorityStoreError> {
    let rows = sqlx::query(
        r"
        SELECT grant_row.id AS grant_id, grant_row.fencing_token,
               grant_row.secret_id, grant_row.secret_version_id,
               grant_row.secret_version_number, grant_row.provider_id,
               grant_row.environment_id,
               grant_row.environment_approval_request_id AS approval_id,
               grant_row.grant_mode, grant_row.event_trust,
               grant_row.source_kind, grant_row.authority_digest,
               grant_row.authority_digest_key_id,
               grant_row.status AS grant_status,
               grant_row.issued_at_ms, grant_row.expires_at_ms,
               grant_row.revoked_at_ms, grant_row.revocation_reason,
               secret.scope_kind AS secret_scope_kind,
               secret.repository_id AS secret_repository_id,
               secret.environment_id AS secret_environment_id,
               secret.status AS secret_status,
               secret.current_version_id, secret.current_version_number,
               secret.revision AS secret_revision,
               policy.tenant_repository_access_mode AS repository_access_mode,
               policy.minimum_event_trust, policy.allow_fork_pull_requests,
               policy.allow_dependabot, policy.reusable_workflow_mode,
               policy.revision AS policy_revision,
               version.storage_kind,
               lifecycle.status AS version_lifecycle_status,
               lifecycle.revision AS version_lifecycle_revision,
               provider.adapter_kind AS provider_adapter_kind,
               provider.supports_dynamic_leases AS provider_supports_dynamic_leases,
               provider.status AS provider_status,
               provider.revision AS provider_revision
        FROM secret_workload_grants AS grant_row
        JOIN secrets AS secret
          ON secret.tenant_id = grant_row.tenant_id
         AND secret.id = grant_row.secret_id
         AND secret.provider_id = grant_row.provider_id
        JOIN secret_policies AS policy
          ON policy.tenant_id = secret.tenant_id
         AND policy.secret_id = secret.id
        JOIN secret_versions AS version
          ON version.tenant_id = grant_row.tenant_id
         AND version.id = grant_row.secret_version_id
         AND version.secret_id = grant_row.secret_id
         AND version.version_number = grant_row.secret_version_number
         AND version.provider_id = grant_row.provider_id
        JOIN secret_version_lifecycle AS lifecycle
          ON lifecycle.tenant_id = version.tenant_id
         AND lifecycle.secret_version_id = version.id
         AND lifecycle.secret_id = version.secret_id
         AND lifecycle.version_number = version.version_number
         AND lifecycle.provider_id = version.provider_id
        JOIN secret_providers AS provider
          ON provider.tenant_id = grant_row.tenant_id
         AND provider.provider_id = grant_row.provider_id
        WHERE grant_row.tenant_id = $1
          AND grant_row.repository_id = $2
          AND grant_row.run_id = $3
          AND grant_row.job_id = $4
          AND grant_row.attempt_id = $5
          AND grant_row.fencing_token = $6
        ORDER BY grant_row.id
        LIMIT 257
        FOR SHARE OF grant_row, secret, policy, version, lifecycle, provider
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.job_id().as_uuid())
    .bind(request.lease().attempt_id().as_uuid())
    .bind(positive_i64(request.lease().fencing_token().get())?)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.iter().map(decode_grant).collect()
}

fn decode_grant(row: &sqlx::postgres::PgRow) -> Result<GrantRow, ManagedSecretAuthorityStoreError> {
    Ok(GrantRow {
        grant_id: field(row, "grant_id")?,
        fencing_token: field(row, "fencing_token")?,
        secret_id: field(row, "secret_id")?,
        version_id: field(row, "secret_version_id")?,
        version_number: field(row, "secret_version_number")?,
        provider_id: field(row, "provider_id")?,
        environment_id: field(row, "environment_id")?,
        approval_id: field(row, "approval_id")?,
        grant_mode: field(row, "grant_mode")?,
        event_trust: field(row, "event_trust")?,
        source_kind: field(row, "source_kind")?,
        authority_digest: field(row, "authority_digest")?,
        authority_digest_key_id: field(row, "authority_digest_key_id")?,
        grant_status: field(row, "grant_status")?,
        issued_at_ms: field(row, "issued_at_ms")?,
        expires_at_ms: field(row, "expires_at_ms")?,
        revoked_at_ms: field(row, "revoked_at_ms")?,
        revocation_reason: field(row, "revocation_reason")?,
        secret_scope_kind: field(row, "secret_scope_kind")?,
        secret_repository_id: field(row, "secret_repository_id")?,
        secret_environment_id: field(row, "secret_environment_id")?,
        secret_status: field(row, "secret_status")?,
        current_version_id: field(row, "current_version_id")?,
        current_version_number: field(row, "current_version_number")?,
        secret_revision: field(row, "secret_revision")?,
        repository_access_mode: field(row, "repository_access_mode")?,
        minimum_event_trust: field(row, "minimum_event_trust")?,
        allow_fork_pull_requests: field(row, "allow_fork_pull_requests")?,
        allow_dependabot: field(row, "allow_dependabot")?,
        reusable_workflow_mode: field(row, "reusable_workflow_mode")?,
        policy_revision: field(row, "policy_revision")?,
        storage_kind: field(row, "storage_kind")?,
        version_lifecycle_status: field(row, "version_lifecycle_status")?,
        version_lifecycle_revision: field(row, "version_lifecycle_revision")?,
        provider_adapter_kind: field(row, "provider_adapter_kind")?,
        provider_supports_dynamic_leases: field(row, "provider_supports_dynamic_leases")?,
        provider_status: field(row, "provider_status")?,
        provider_revision: field(row, "provider_revision")?,
    })
}

async fn lock_repository_access(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
    secret_ids: &BTreeSet<Uuid>,
) -> Result<BTreeSet<Uuid>, ManagedSecretAuthorityStoreError> {
    if secret_ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let values = secret_ids.iter().copied().collect::<Vec<_>>();
    let rows = sqlx::query(
        r"
        SELECT secret_id
        FROM secret_repository_access
        WHERE tenant_id = $1
          AND repository_id = $2
          AND secret_id = ANY($3)
        ORDER BY secret_id
        FOR SHARE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(&values)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    rows.iter().map(|row| field(row, "secret_id")).collect()
}

async fn lock_environments(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
    ids: &BTreeSet<Uuid>,
) -> Result<BTreeMap<Uuid, EnvironmentRow>, ManagedSecretAuthorityStoreError> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let values = ids.iter().copied().collect::<Vec<_>>();
    let rows = sqlx::query(
        r"
        SELECT id, protection_mode, required_approvals,
               prevent_self_review, status, revision
        FROM repository_environments
        WHERE tenant_id = $1
          AND repository_id = $2
          AND id = ANY($3)
        ORDER BY id
        FOR SHARE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(&values)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut environments = BTreeMap::new();
    for row in &rows {
        let environment = EnvironmentRow {
            id: field(row, "id")?,
            protection_mode: field(row, "protection_mode")?,
            required_approvals: field(row, "required_approvals")?,
            prevent_self_review: field(row, "prevent_self_review")?,
            status: field(row, "status")?,
            revision: field(row, "revision")?,
        };
        if environment.id.is_nil() || environments.insert(environment.id, environment).is_some() {
            return Err(ManagedSecretAuthorityStoreError::CorruptData);
        }
    }
    Ok(environments)
}

async fn lock_approvals(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ResolveManagedSecretAuthority,
    ids: &BTreeSet<Uuid>,
) -> Result<BTreeMap<Uuid, ApprovalRow>, ManagedSecretAuthorityStoreError> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let values = ids.iter().copied().collect::<Vec<_>>();
    let rows = sqlx::query(
        r"
        SELECT id, environment_id, required_approvals,
               prevent_self_review, status, created_at_ms, expires_at_ms,
               resolved_at_ms, resolution_reason, revision
        FROM protected_environment_approval_requests
        WHERE tenant_id = $1
          AND repository_id = $2
          AND run_id = $3
          AND job_id = $4
          AND attempt_id = $5
          AND id = ANY($6)
        ORDER BY id
        FOR SHARE
        ",
    )
    .bind(request.tenant().as_str())
    .bind(request.repository_id().as_uuid())
    .bind(request.run_id().as_uuid())
    .bind(request.job_id().as_uuid())
    .bind(request.lease().attempt_id().as_uuid())
    .bind(&values)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let mut approvals = BTreeMap::new();
    for row in &rows {
        let approval = ApprovalRow {
            id: field(row, "id")?,
            environment_id: field(row, "environment_id")?,
            required_approvals: field(row, "required_approvals")?,
            prevent_self_review: field(row, "prevent_self_review")?,
            status: field(row, "status")?,
            created_at_ms: field(row, "created_at_ms")?,
            expires_at_ms: field(row, "expires_at_ms")?,
            resolved_at_ms: field(row, "resolved_at_ms")?,
            resolution_reason: field(row, "resolution_reason")?,
            revision: field(row, "revision")?,
        };
        if approval.id.is_nil()
            || approval.environment_id.is_nil()
            || approvals.insert(approval.id, approval).is_some()
        {
            return Err(ManagedSecretAuthorityStoreError::CorruptData);
        }
    }
    Ok(approvals)
}

fn validate_grant(
    request: &ResolveManagedSecretAuthority,
    execution: &ExecutionRow,
    grant: &GrantRow,
    repository_access: &BTreeSet<Uuid>,
    environments: &BTreeMap<Uuid, EnvironmentRow>,
    approvals: &BTreeMap<Uuid, ApprovalRow>,
) -> Result<ManagedSecretAuthorityBinding, ManagedSecretAuthorityStoreError> {
    if grant.environment_id.is_some_and(|value| value.is_nil())
        || grant.approval_id.is_some_and(|value| value.is_nil())
    {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }
    let observed_at = request.observed_at().get();
    let expected_fence = positive_i64(request.lease().fencing_token().get())?;
    let valid_active_grant = grant.fencing_token == expected_fence
        && grant.grant_status == "active"
        && grant.revoked_at_ms.is_none()
        && grant.revocation_reason.is_none()
        && grant.issued_at_ms >= 0
        && grant.issued_at_ms >= request.lease().issued_at().get()
        && grant.issued_at_ms <= observed_at
        && grant.expires_at_ms > observed_at;
    if !valid_active_grant {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    let mode = ManagedSecretGrantMode::from_durable(&grant.grant_mode)
        .ok_or(ManagedSecretAuthorityStoreError::CorruptData)?;
    let exposure_permits_mode = match mode {
        ManagedSecretGrantMode::ReadableSecret => {
            execution.secret_exposure_class == "readable_secret"
        }
        ManagedSecretGrantMode::CapabilityOnly => {
            execution.secret_exposure_class != "secretless"
                && grant.provider_supports_dynamic_leases
        }
    };
    if !exposure_permits_mode {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    if grant.secret_status != "active"
        || grant.current_version_id != Some(grant.version_id)
        || grant.current_version_number != Some(grant.version_number)
        || grant.version_lifecycle_status != "active"
        || grant.provider_status != "active"
    {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    if grant.secret_revision <= 0
        || grant.policy_revision <= 0
        || grant.version_lifecycle_revision <= 0
        || grant.provider_revision <= 0
        || grant.version_number <= 0
        || grant.authority_digest.len() != 32
        || !canonical_machine_id(&grant.authority_digest_key_id, 128)
        || !canonical_lower_machine_id(&grant.provider_adapter_kind, 128)
        || !matches!(
            grant.storage_kind.as_str(),
            "built_in_ciphertext" | "external_provider"
        )
        || !matches!(grant.event_trust.as_str(), "trusted" | "untrusted")
        || !matches!(
            grant.source_kind.as_str(),
            "same_repository" | "fork" | "dependabot" | "unknown"
        )
        || !matches!(
            grant.reusable_workflow_mode.as_str(),
            "disabled" | "explicit_only"
        )
    {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }
    let provider_id = ManagedSecretProviderId::new(grant.provider_id.clone())
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)?;
    if provider_id.as_str() != "builtin" {
        // `RepositorySecretVersionId` is explicitly a built-in UUID. Returning
        // an external-provider handle behind that type would misstate the
        // public contract, even though the handle itself is never selected.
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    if grant.provider_adapter_kind != "builtin_postgres"
        || grant.storage_kind != "built_in_ciphertext"
    {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }
    validate_scope(request, grant, repository_access)?;
    validate_policy(grant)?;
    validate_environment(request, grant, environments, approvals)?;

    let grant_id = SecretWorkloadGrantId::from_uuid(grant.grant_id)
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)?;
    let secret_id = RepositorySecretId::from_uuid(grant.secret_id)
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)?;
    let version_id = RepositorySecretVersionId::from_uuid(grant.version_id)
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)?;
    let version_number = u64::try_from(grant.version_number)
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)?;
    Ok(ManagedSecretAuthorityBinding::from_verified_parts(
        grant_id,
        provider_id,
        secret_id,
        version_id,
        version_number,
        mode,
        grant.provider_supports_dynamic_leases,
    ))
}

fn validate_scope(
    request: &ResolveManagedSecretAuthority,
    grant: &GrantRow,
    repository_access: &BTreeSet<Uuid>,
) -> Result<(), ManagedSecretAuthorityStoreError> {
    let repository_id = request.repository_id().as_uuid();
    let permitted = match grant.secret_scope_kind.as_str() {
        "tenant" => {
            grant.secret_repository_id.is_none()
                && grant.secret_environment_id.is_none()
                && match grant.repository_access_mode.as_str() {
                    "all_repositories" => true,
                    "selected_repositories" => repository_access.contains(&grant.secret_id),
                    _ => false,
                }
        }
        "repository" => {
            grant.secret_repository_id == Some(repository_id)
                && grant.secret_environment_id.is_none()
                && grant.repository_access_mode == "scope_only"
        }
        "environment" => {
            grant.secret_repository_id == Some(repository_id)
                && grant.secret_environment_id.is_some()
                && grant.secret_environment_id == grant.environment_id
                && grant.repository_access_mode == "scope_only"
        }
        _ => return Err(ManagedSecretAuthorityStoreError::CorruptData),
    };
    if permitted {
        Ok(())
    } else {
        Err(ManagedSecretAuthorityStoreError::Unauthorized)
    }
}

fn validate_policy(grant: &GrantRow) -> Result<(), ManagedSecretAuthorityStoreError> {
    if !matches!(grant.minimum_event_trust.as_str(), "trusted" | "untrusted") {
        return Err(ManagedSecretAuthorityStoreError::CorruptData);
    }
    let permitted = (grant.minimum_event_trust != "trusted" || grant.event_trust == "trusted")
        && (grant.source_kind != "fork" || grant.allow_fork_pull_requests)
        && (grant.source_kind != "dependabot" || grant.allow_dependabot);
    if permitted {
        Ok(())
    } else {
        Err(ManagedSecretAuthorityStoreError::Unauthorized)
    }
}

fn validate_environment(
    request: &ResolveManagedSecretAuthority,
    grant: &GrantRow,
    environments: &BTreeMap<Uuid, EnvironmentRow>,
    approvals: &BTreeMap<Uuid, ApprovalRow>,
) -> Result<(), ManagedSecretAuthorityStoreError> {
    let Some(environment_id) = grant.environment_id else {
        return if grant.approval_id.is_none() {
            Ok(())
        } else {
            Err(ManagedSecretAuthorityStoreError::CorruptData)
        };
    };
    let environment = environments
        .get(&environment_id)
        .ok_or(ManagedSecretAuthorityStoreError::CorruptData)?;
    if environment.status != "active" || environment.revision <= 0 {
        return Err(ManagedSecretAuthorityStoreError::Unauthorized);
    }
    match environment.protection_mode.as_str() {
        "unprotected" => {
            if environment.required_approvals != 0 || grant.approval_id.is_some() {
                return Err(ManagedSecretAuthorityStoreError::Unauthorized);
            }
        }
        "required_approvals" => {
            if !(1..=25).contains(&environment.required_approvals) {
                return Err(ManagedSecretAuthorityStoreError::CorruptData);
            }
            let approval_id = grant
                .approval_id
                .ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
            let approval = approvals
                .get(&approval_id)
                .ok_or(ManagedSecretAuthorityStoreError::CorruptData)?;
            let resolved_at = approval
                .resolved_at_ms
                .ok_or(ManagedSecretAuthorityStoreError::Unauthorized)?;
            let valid = approval.environment_id == environment_id
                && approval.status == "approved"
                && approval.required_approvals == environment.required_approvals
                && approval.prevent_self_review == environment.prevent_self_review
                && approval.revision > 0
                && approval.created_at_ms >= 0
                && resolved_at >= approval.created_at_ms
                && resolved_at <= request.observed_at().get()
                && approval.expires_at_ms > request.observed_at().get()
                && matches!(
                    approval.resolution_reason.as_deref(),
                    Some("approval_threshold_met" | "administrative_approval")
                );
            if !valid {
                return Err(ManagedSecretAuthorityStoreError::Unauthorized);
            }
            // The approval row snapshots the mutable settings, but migration
            // 0012 does not pin the approval to an immutable environment
            // revision or settings digest. Equality here cannot distinguish an
            // ABA policy change, so protected delivery remains fail-closed
            // until that missing durable contract exists.
            return Err(ManagedSecretAuthorityStoreError::Unauthorized);
        }
        _ => return Err(ManagedSecretAuthorityStoreError::CorruptData),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evidence_digest(
    request: &ResolveManagedSecretAuthority,
    execution: &ExecutionRow,
    bindings: &[ManagedSecretAuthorityBinding],
    grants: &[GrantRow],
    repository_access: &BTreeSet<Uuid>,
    environments: &BTreeMap<Uuid, EnvironmentRow>,
    approvals: &BTreeMap<Uuid, ApprovalRow>,
    usable_until: UnixMillis,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DOMAIN);
    hasher.update(MANAGED_SECRET_AUTHORITY_SCHEMA.to_be_bytes());
    hash_text(&mut hasher, request.tenant().as_str());
    hash_uuid(&mut hasher, request.repository_id().as_uuid());
    hash_uuid(&mut hasher, request.run_id().as_uuid());
    hash_uuid(&mut hasher, request.job_id().as_uuid());
    let lease = request.lease();
    hash_uuid(&mut hasher, lease.attempt_id().as_uuid());
    hash_uuid(&mut hasher, lease.lease_id().as_uuid());
    hash_uuid(&mut hasher, lease.runner_id().as_uuid());
    hasher.update(lease.fencing_token().get().to_be_bytes());
    hasher.update(lease.issued_at().get().to_be_bytes());
    hasher.update(lease.expires_at().get().to_be_bytes());
    let session = request.session();
    hash_uuid(&mut hasher, session.session_id().as_uuid());
    hasher.update(session.session_epoch().get().to_be_bytes());
    hasher.update(session.runner_generation().get().to_be_bytes());
    hasher.update(request.slot().ordinal().to_be_bytes());
    hasher.update(request.runtime_context_digest().as_bytes());
    hasher.update(execution.attempt_number.to_be_bytes());
    hash_text(&mut hasher, &execution.secret_exposure_class);
    hasher.update(execution.job_ir_digest.as_bytes());
    hasher.update(execution.plan_digest.as_bytes());
    hasher.update(execution.event_digest.as_bytes());
    hasher.update(usable_until.get().to_be_bytes());
    hasher.update(
        u64::try_from(bindings.len())
            .expect("managed-secret binding count is bounded")
            .to_be_bytes(),
    );
    for binding in bindings {
        hash_uuid(&mut hasher, binding.grant_id().as_uuid());
        hash_text(&mut hasher, binding.provider_id().as_str());
        hash_uuid(&mut hasher, binding.secret_id().as_uuid());
        hash_uuid(&mut hasher, binding.version_id().as_uuid());
        hasher.update(binding.version_number().to_be_bytes());
        hasher.update([match binding.mode() {
            ManagedSecretGrantMode::ReadableSecret => 0,
            ManagedSecretGrantMode::CapabilityOnly => 1,
        }]);
        hasher.update([u8::from(binding.provider_supports_dynamic_leases())]);
    }
    hasher.update(
        u64::try_from(grants.len())
            .expect("managed-secret grant count is bounded")
            .to_be_bytes(),
    );
    for grant in grants {
        hash_grant(
            &mut hasher,
            grant,
            repository_access.contains(&grant.secret_id),
            grant.environment_id.and_then(|id| environments.get(&id)),
            grant.approval_id.and_then(|id| approvals.get(&id)),
        );
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_grant(
    hasher: &mut Sha256,
    grant: &GrantRow,
    repository_access: bool,
    environment: Option<&EnvironmentRow>,
    approval: Option<&ApprovalRow>,
) {
    hash_uuid(hasher, grant.grant_id);
    hasher.update(grant.fencing_token.to_be_bytes());
    hash_uuid(hasher, grant.secret_id);
    hash_uuid(hasher, grant.version_id);
    hasher.update(grant.version_number.to_be_bytes());
    hash_text(hasher, &grant.provider_id);
    hash_optional_uuid(hasher, grant.environment_id);
    hash_optional_uuid(hasher, grant.approval_id);
    for value in [
        &grant.grant_mode,
        &grant.event_trust,
        &grant.source_kind,
        &grant.authority_digest_key_id,
        &grant.grant_status,
        &grant.secret_scope_kind,
        &grant.secret_status,
        &grant.repository_access_mode,
        &grant.minimum_event_trust,
        &grant.reusable_workflow_mode,
        &grant.storage_kind,
        &grant.version_lifecycle_status,
        &grant.provider_adapter_kind,
        &grant.provider_status,
    ] {
        hash_text(hasher, value);
    }
    hash_bytes(hasher, &grant.authority_digest);
    hasher.update(grant.issued_at_ms.to_be_bytes());
    hasher.update(grant.expires_at_ms.to_be_bytes());
    hash_optional_i64(hasher, grant.revoked_at_ms);
    hash_optional_text(hasher, grant.revocation_reason.as_deref());
    hash_optional_uuid(hasher, grant.secret_repository_id);
    hash_optional_uuid(hasher, grant.secret_environment_id);
    hash_optional_uuid(hasher, grant.current_version_id);
    hash_optional_i64(hasher, grant.current_version_number);
    hasher.update(grant.secret_revision.to_be_bytes());
    hasher.update([u8::from(grant.allow_fork_pull_requests)]);
    hasher.update([u8::from(grant.allow_dependabot)]);
    hasher.update(grant.policy_revision.to_be_bytes());
    hasher.update(grant.version_lifecycle_revision.to_be_bytes());
    hasher.update(grant.provider_revision.to_be_bytes());
    hasher.update([u8::from(grant.provider_supports_dynamic_leases)]);
    hasher.update([u8::from(repository_access)]);
    match environment {
        None => hasher.update([0]),
        Some(environment) => {
            hasher.update([1]);
            hash_uuid(hasher, environment.id);
            hash_text(hasher, &environment.protection_mode);
            hasher.update(environment.required_approvals.to_be_bytes());
            hasher.update([u8::from(environment.prevent_self_review)]);
            hash_text(hasher, &environment.status);
            hasher.update(environment.revision.to_be_bytes());
        }
    }
    match approval {
        None => hasher.update([0]),
        Some(approval) => {
            hasher.update([1]);
            hash_uuid(hasher, approval.id);
            hash_uuid(hasher, approval.environment_id);
            hasher.update(approval.required_approvals.to_be_bytes());
            hasher.update([u8::from(approval.prevent_self_review)]);
            hash_text(hasher, &approval.status);
            hasher.update(approval.created_at_ms.to_be_bytes());
            hasher.update(approval.expires_at_ms.to_be_bytes());
            hash_optional_i64(hasher, approval.resolved_at_ms);
            hash_optional_text(hasher, approval.resolution_reason.as_deref());
            hasher.update(approval.revision.to_be_bytes());
        }
    }
}

fn hash_uuid(hasher: &mut Sha256, value: Uuid) {
    hasher.update(value.as_bytes());
}

fn hash_optional_uuid(hasher: &mut Sha256, value: Option<Uuid>) {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_uuid(hasher, value);
        }
    }
}

fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
    }
}

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_text(hasher, value);
        }
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("durable managed-secret evidence fields are bounded")
            .to_be_bytes(),
    );
    hasher.update(value);
}

fn canonical_machine_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn canonical_lower_machine_id(value: &str, maximum: usize) -> bool {
    canonical_machine_id(value, maximum) && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn positive_i64(value: u64) -> Result<i64, ManagedSecretAuthorityStoreError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ManagedSecretAuthorityStoreError::CorruptData)
}

fn digest_field(
    row: &sqlx::postgres::PgRow,
    name: &str,
) -> Result<Sha256Digest, ManagedSecretAuthorityStoreError> {
    let value: Vec<u8> = field(row, name)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn field<'r, T>(
    row: &'r sqlx::postgres::PgRow,
    name: &str,
) -> Result<T, ManagedSecretAuthorityStoreError>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(name)
        .map_err(|_| ManagedSecretAuthorityStoreError::CorruptData)
}

#[allow(clippy::needless_pass_by_value)]
fn operation_error(_: sqlx::Error) -> ManagedSecretAuthorityStoreError {
    ManagedSecretAuthorityStoreError::Unavailable
}
