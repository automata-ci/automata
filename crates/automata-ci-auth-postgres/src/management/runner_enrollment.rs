use automata_ci_auth::management::{
    ManagementActor, ManagementMutationOutcome, ManagementRepositoryError,
};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::{
    AuditDescriptor, MutationAuthorization, PostgresHumanRbacManagementRepository,
    authorize_mutation, closed_authorization, commit, database_time_milliseconds, finish_applied,
    map_database_error,
};

const ACTION_TOKEN_CREATE: &str = "runner.enrollment_token.create";
const ACTION_ENROLL: &str = "runner.enroll";
const RESOURCE_ENROLLMENT: &str = "runner_enrollment";
const MIN_TOKEN_LIFETIME_MS: i64 = 60 * 1_000;
const MAX_TOKEN_LIFETIME_MS: i64 = 60 * 60 * 1_000;
const MAX_REGISTERED_RUNNERS: i64 = 64;
const RUNNER_ENROLLMENT_CAPACITY_LOCK: i64 = 0x4155_544f_4d41_5441;
const MAX_NAME_BYTES: usize = 255;
const MAX_GROUP_CHARACTERS: usize = 256;

/// Authorized request to create a short-lived runner enrollment token record.
pub struct CreateRunnerEnrollmentToken {
    /// Current human actor evidence, reauthorized transactionally.
    pub actor: ManagementActor,
    /// Public, non-secret identity of this token record.
    pub enrollment_id: Uuid,
    /// SHA-256 of the opaque token; plaintext is never persisted.
    pub token_sha256: [u8; 32],
    /// Canonical runner-group name to which redemption is scoped.
    pub runner_group: String,
    /// Requested lifetime in whole milliseconds.
    pub lifetime_ms: i64,
}

impl std::fmt::Debug for CreateRunnerEnrollmentToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateRunnerEnrollmentToken")
            .field("enrollment_id", &self.enrollment_id)
            .field("runner_group", &self.runner_group)
            .field("lifetime_ms", &self.lifetime_ms)
            .finish_non_exhaustive()
    }
}

/// Metadata returned after an enrollment token is durably issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerEnrollmentTokenRecord {
    /// Public token-record identifier.
    pub enrollment_id: Uuid,
    /// Durable runner-group identifier.
    pub runner_group_id: Uuid,
    /// Canonical runner-group name.
    pub runner_group: String,
    /// Database-clock expiration timestamp in Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Non-secret enrollment state loaded before certificate signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRunnerEnrollment {
    /// Public token-record identifier.
    pub enrollment_id: Uuid,
    /// Tenant selected by the issuing human authority.
    pub tenant_id: String,
    /// Durable group selected by the issuing human authority.
    pub runner_group_id: Uuid,
    /// Canonical group name selected by the issuing human authority.
    pub runner_group: String,
    /// Token expiration timestamp in Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Result of looking up a one-time token without consuming it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerEnrollmentPrepareOutcome {
    /// The token exists, is unconsumed, and has not expired.
    Prepared(PreparedRunnerEnrollment),
    /// The token is absent, consumed, or expired; these states are intentionally indistinguishable.
    Rejected,
}

/// Exact runner and certificate state committed while consuming a token.
pub struct ConsumeRunnerEnrollment {
    /// SHA-256 of the presented opaque token.
    pub token_sha256: [u8; 32],
    /// Durable identity contained in the canonical capability document.
    pub runner_id: Uuid,
    /// Human-readable runner name selected on the execution host.
    pub runner_name: String,
    /// Complete validated capability document.
    pub capabilities: Value,
    /// Canonical labels projected for routing queries.
    pub labels: Vec<String>,
    /// Maximum concurrent jobs from the capability document.
    pub slots: u16,
    /// SHA-256 of the newly signed leaf certificate DER.
    pub certificate_leaf_sha256: [u8; 32],
    /// Leaf-certificate expiration timestamp in Unix seconds.
    pub certificate_expires_at_seconds: i64,
}

impl std::fmt::Debug for ConsumeRunnerEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsumeRunnerEnrollment")
            .field("runner_id", &self.runner_id)
            .field("runner_name", &self.runner_name)
            .field("slots", &self.slots)
            .field(
                "certificate_expires_at_seconds",
                &self.certificate_expires_at_seconds,
            )
            .finish_non_exhaustive()
    }
}

/// Result of atomically consuming a token and registering its runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerEnrollmentConsumeOutcome {
    /// Enrollment, certificate registration, and audit append committed.
    Applied(PreparedRunnerEnrollment),
    /// The token was absent, consumed, or expired.
    Rejected,
    /// The runner ID or normalized name is already registered.
    AlreadyExists,
    /// The control plane's reviewed registered-runner capacity is full.
    CapacityExhausted,
}

#[derive(FromRow)]
struct EnrollmentRow {
    id: Uuid,
    tenant_id: String,
    runner_group_id: Uuid,
    runner_group: String,
    expires_at_ms: i64,
}

impl EnrollmentRow {
    fn prepared(self) -> Result<PreparedRunnerEnrollment, ManagementRepositoryError> {
        if self.id.is_nil()
            || self.runner_group_id.is_nil()
            || self.tenant_id.is_empty()
            || !valid_group(&self.runner_group)
            || self.expires_at_ms <= 0
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        Ok(PreparedRunnerEnrollment {
            enrollment_id: self.id,
            tenant_id: self.tenant_id,
            runner_group_id: self.runner_group_id,
            runner_group: self.runner_group,
            expires_at_ms: self.expires_at_ms,
        })
    }
}

impl PostgresHumanRbacManagementRepository {
    /// Creates an audited one-time token record after checking `runners:enroll`.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for invalid bounded input, unavailable
    /// storage, or durable state that violates an enrollment invariant.
    pub async fn create_runner_enrollment_token(
        &self,
        request: CreateRunnerEnrollmentToken,
    ) -> Result<ManagementMutationOutcome<RunnerEnrollmentTokenRecord>, ManagementRepositoryError>
    {
        if request.enrollment_id.is_nil()
            || request.token_sha256 == [0; 32]
            || !valid_group(&request.runner_group)
            || !(MIN_TOKEN_LIFETIME_MS..=MAX_TOKEN_LIFETIME_MS).contains(&request.lifetime_ms)
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let resource_id = request.enrollment_id.hyphenated().to_string();
        let descriptor = AuditDescriptor::new(
            ACTION_TOKEN_CREATE,
            RESOURCE_ENROLLMENT,
            &resource_id,
            &request.actor,
        );
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let authorization = authorize_mutation(
            &mut transaction,
            &request.actor,
            &["runners:enroll"],
            descriptor,
        )
        .await?;
        let MutationAuthorization::Authorized(actor) = authorization else {
            commit(transaction).await?;
            return Ok(closed_authorization(&authorization));
        };
        let group_id = ensure_runner_group(
            &mut transaction,
            &actor.tenant_id,
            &request.runner_group,
            actor.now_ms,
        )
        .await?;
        let expires_at_ms = actor
            .now_ms
            .checked_add(request.lifetime_ms)
            .ok_or(ManagementRepositoryError::InvalidRequest)?;
        let inserted = sqlx::query(
            r"
            INSERT INTO runner_enrollment_tokens (
                id,tenant_id,runner_group_id,token_sha256,
                issued_by_principal_id,issued_by_session_id,
                issued_authorization_revision,issued_at_ms,expires_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT DO NOTHING
            ",
        )
        .bind(request.enrollment_id)
        .bind(&actor.tenant_id)
        .bind(group_id)
        .bind(request.token_sha256.as_slice())
        .bind(actor.principal_id)
        .bind(actor.session_id)
        .bind(actor.authorization_revision)
        .bind(actor.now_ms)
        .bind(expires_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if inserted.rows_affected() != 1 {
            return super::finish_denied(
                transaction,
                actor,
                descriptor,
                ManagementMutationOutcome::AlreadyExists,
            )
            .await;
        }
        finish_applied(
            transaction,
            actor,
            descriptor,
            RunnerEnrollmentTokenRecord {
                enrollment_id: request.enrollment_id,
                runner_group_id: group_id,
                runner_group: request.runner_group,
                expires_at_ms,
            },
        )
        .await
    }

    /// Loads non-secret token scope before certificate signing.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for an invalid digest, unavailable
    /// storage, or corrupt durable enrollment state.
    pub async fn prepare_runner_enrollment(
        &self,
        token_sha256: [u8; 32],
    ) -> Result<RunnerEnrollmentPrepareOutcome, ManagementRepositoryError> {
        if token_sha256 == [0; 32] {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let now_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        let row = load_enrollment(&mut transaction, &token_sha256, now_ms, false).await?;
        commit(transaction).await?;
        row.map(EnrollmentRow::prepared)
            .transpose()?
            .map_or(Ok(RunnerEnrollmentPrepareOutcome::Rejected), |prepared| {
                Ok(RunnerEnrollmentPrepareOutcome::Prepared(prepared))
            })
    }

    /// Atomically consumes an enrollment token and registers the runner certificate.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for invalid runner/certificate input,
    /// unavailable storage, or durable state that violates an enrollment invariant.
    #[allow(
        clippy::too_many_lines,
        reason = "the transaction keeps token lock, runner, certificate, consumption, and audit visibly contiguous"
    )]
    pub async fn consume_runner_enrollment(
        &self,
        request: ConsumeRunnerEnrollment,
    ) -> Result<RunnerEnrollmentConsumeOutcome, ManagementRepositoryError> {
        if request.token_sha256 == [0; 32]
            || request.runner_id.is_nil()
            || !valid_runner_name(&request.runner_name)
            || !request.capabilities.is_object()
            || request.labels.len() > 256
            || request
                .labels
                .iter()
                .any(|label| label.is_empty() || label.len() > 255)
            || request.slots == 0
            || request.certificate_leaf_sha256 == [0; 32]
            || request.certificate_expires_at_seconds <= 0
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let now_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        let Some(row) =
            load_enrollment(&mut transaction, &request.token_sha256, now_ms, true).await?
        else {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        };
        if request.certificate_expires_at_seconds <= now_ms / 1_000 {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let prepared = row.prepared()?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RUNNER_ENROLLMENT_CAPACITY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        let runner_count: i64 = sqlx::query_scalar("SELECT count(*) FROM runners")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        if runner_count >= MAX_REGISTERED_RUNNERS {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::CapacityExhausted);
        }
        let normalized_name = request.runner_name.to_lowercase();
        let collision: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM runners WHERE id=$1 OR (tenant_id=$2 AND normalized_name=$3))",
        )
        .bind(request.runner_id)
        .bind(&prepared.tenant_id)
        .bind(&normalized_name)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if collision {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::AlreadyExists);
        }
        sqlx::query(
            r"
            INSERT INTO runners (
                id,tenant_id,group_id,name,normalized_name,labels,capabilities,
                slots,status,generation,created_at_ms,updated_at_ms,session_epoch,desired_state
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'offline',1,$9,$9,0,'active')
            ",
        )
        .bind(request.runner_id)
        .bind(&prepared.tenant_id)
        .bind(prepared.runner_group_id)
        .bind(&request.runner_name)
        .bind(&normalized_name)
        .bind(&request.labels)
        .bind(&request.capabilities)
        .bind(i32::from(request.slots))
        .bind(now_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256,runner_id,expires_at_seconds) VALUES ($1,$2,$3)",
        )
        .bind(request.certificate_leaf_sha256.as_slice())
        .bind(request.runner_id)
        .bind(request.certificate_expires_at_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let consumed = sqlx::query(
            "UPDATE runner_enrollment_tokens SET consumed_at_ms=$2,consumed_runner_id=$3 WHERE id=$1 AND consumed_at_ms IS NULL",
        )
        .bind(prepared.enrollment_id)
        .bind(now_ms)
        .bind(request.runner_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if consumed.rows_affected() != 1 {
            return Err(ManagementRepositoryError::CorruptData);
        }
        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id,tenant_id,occurred_at_ms,actor_kind,action,outcome,
                resource_kind,resource_id
            ) VALUES ($1,$2,$3,'system',$4,'succeeded',$5,$6)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&prepared.tenant_id)
        .bind(now_ms)
        .bind(ACTION_ENROLL)
        .bind(RESOURCE_ENROLLMENT)
        .bind(request.runner_id.hyphenated().to_string())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        commit(transaction).await?;
        Ok(RunnerEnrollmentConsumeOutcome::Applied(prepared))
    }
}

async fn ensure_runner_group(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    group: &str,
    now_ms: i64,
) -> Result<Uuid, ManagementRepositoryError> {
    let proposed = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO runner_groups (id,tenant_id,name,normalized_name,routing_policy,created_at_ms,updated_at_ms)
        VALUES ($1,$2,$3,$3,'{}'::jsonb,$4,$4)
        ON CONFLICT (tenant_id,normalized_name) DO NOTHING
        ",
    )
    .bind(proposed)
    .bind(tenant_id)
    .bind(group)
    .bind(now_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    sqlx::query_scalar(
        "SELECT id FROM runner_groups WHERE tenant_id=$1 AND normalized_name=$2 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(group)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn load_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    token_sha256: &[u8; 32],
    now_ms: i64,
    lock: bool,
) -> Result<Option<EnrollmentRow>, ManagementRepositoryError> {
    let row = if lock {
        sqlx::query_as::<_, EnrollmentRow>(
            "SELECT token.id,token.tenant_id,token.runner_group_id,groups.name AS runner_group,token.expires_at_ms FROM runner_enrollment_tokens AS token JOIN runner_groups AS groups ON groups.tenant_id=token.tenant_id AND groups.id=token.runner_group_id WHERE token.token_sha256=$1 AND token.consumed_at_ms IS NULL AND token.expires_at_ms>$2 FOR UPDATE",
        )
        .bind(token_sha256.as_slice())
        .bind(now_ms)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, EnrollmentRow>(
            "SELECT token.id,token.tenant_id,token.runner_group_id,groups.name AS runner_group,token.expires_at_ms FROM runner_enrollment_tokens AS token JOIN runner_groups AS groups ON groups.tenant_id=token.tenant_id AND groups.id=token.runner_group_id WHERE token.token_sha256=$1 AND token.consumed_at_ms IS NULL AND token.expires_at_ms>$2",
        )
        .bind(token_sha256.as_slice())
        .bind(now_ms)
        .fetch_optional(&mut **transaction)
        .await
    };
    row.map_err(map_database_error)
}

fn valid_group(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_GROUP_CHARACTERS
        && value.trim() == value
        && value == value.to_lowercase()
        && !value.chars().any(char::is_control)
}

fn valid_runner_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}
