use automata_ci_auth::management::{
    ManagementActor, ManagementMutationOutcome, ManagementRepositoryError,
};
use automata_ci_core::{MAX_REGISTERED_RUNNERS, RunnerCapabilities, RunnerGroup};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::{
    AuditDescriptor, AuthorizedActor, MutationAuthorization, PostgresHumanRbacManagementRepository,
    authorize_mutation, closed_authorization, commit, database_time_milliseconds, finish_applied,
    map_database_error,
};

const ACTION_TOKEN_CREATE: &str = "runner.enrollment_token.create";
const ACTION_ENROLL: &str = "runner.enroll";
const RESOURCE_ENROLLMENT: &str = "runner_enrollment";
const MIN_TOKEN_LIFETIME_MS: i64 = 60 * 1_000;
const MAX_TOKEN_LIFETIME_MS: i64 = 60 * 60 * 1_000;
const RUNNER_ENROLLMENT_CAPACITY_LOCK: i64 = 0x4155_544f_4d41_5441;
const RUNNER_ENROLLMENT_CREATE_LOCK_SALT: i64 = 0x454e_524f_4c4c_4d54;
const MAX_NAME_BYTES: usize = 255;
const MAX_GROUP_CHARACTERS: usize = 256;
const MAX_REDEEM_RESPONSE_BYTES: usize = 512 * 1_024;

/// Maximum lifetime used by the control-plane certificate profile. A leaf is
/// shorter when its issuing CA expires first.
pub const MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

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
    /// Database time sampled after this token row was read.
    pub database_time_ms: i64,
}

/// Stable identity of one runner redemption attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareRunnerEnrollment {
    /// SHA-256 of the presented opaque token.
    pub token_sha256: [u8; 32],
    /// Client-generated identity reused across ambiguous HTTP outcomes.
    pub operation_id: Uuid,
    /// Domain-separated digest of the non-secret semantic request.
    pub request_sha256: [u8; 32],
}

/// Result of looking up a one-time token without consuming it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerEnrollmentPrepareOutcome {
    /// The token exists, is unconsumed, and has not expired.
    Prepared(PreparedRunnerEnrollment),
    /// The exact response from a previously committed matching operation.
    Replayed(Vec<u8>),
    /// The token is absent, consumed, or expired; these states are intentionally indistinguishable.
    Rejected,
}

/// Exact runner and certificate state committed while consuming a token.
pub struct ConsumeRunnerEnrollment {
    /// SHA-256 of the presented opaque token.
    pub token_sha256: [u8; 32],
    /// Client-generated identity reused across ambiguous HTTP outcomes.
    pub operation_id: Uuid,
    /// Domain-separated digest of the non-secret semantic request.
    pub request_sha256: [u8; 32],
    /// Durable identity contained in the canonical capability document.
    pub runner_id: Uuid,
    /// Human-readable runner name selected on the execution host.
    pub runner_name: String,
    /// Complete validated capability document; routing projections are derived
    /// from this typed value inside the transaction.
    pub capabilities: RunnerCapabilities,
    /// SHA-256 of the newly signed leaf certificate DER.
    pub certificate_leaf_sha256: [u8; 32],
    /// Database-clock second used as the certificate profile's issuance time.
    pub certificate_issued_at_seconds: i64,
    /// Leaf-certificate expiration timestamp in Unix seconds.
    pub certificate_expires_at_seconds: i64,
    /// Exact bounded JSON response committed with runner registration.
    pub response: Vec<u8>,
}

impl std::fmt::Debug for ConsumeRunnerEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsumeRunnerEnrollment")
            .field("runner_id", &self.runner_id)
            .field("runner_name", &self.runner_name)
            .field("slots", &self.capabilities.max_parallel_jobs())
            .field("operation_id", &self.operation_id)
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
    Applied(Vec<u8>),
    /// An earlier matching operation committed; return its exact response.
    Replayed(Vec<u8>),
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
    issued_at_ms: i64,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    consumed_runner_id: Option<Uuid>,
    redeem_operation_id: Option<Uuid>,
    redeem_request_sha256: Option<Vec<u8>>,
    redeem_response: Option<Vec<u8>>,
    redeem_certificate_expires_at_seconds: Option<i64>,
}

#[derive(FromRow)]
struct CreatedEnrollmentRow {
    tenant_id: String,
    runner_group_id: Uuid,
    runner_group: String,
    token_sha256: Vec<u8>,
    issued_by_principal_id: Uuid,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

impl EnrollmentRow {
    fn validate(&self) -> Result<(), ManagementRepositoryError> {
        if self.id.is_nil()
            || self.runner_group_id.is_nil()
            || self.tenant_id.is_empty()
            || !valid_group(&self.runner_group)
            || self.issued_at_ms < 0
            || self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_none_or(|lifetime| {
                    !(MIN_TOKEN_LIFETIME_MS..=MAX_TOKEN_LIFETIME_MS).contains(&lifetime)
                })
        {
            return Err(ManagementRepositoryError::CorruptData);
        }
        match (
            self.consumed_at_ms,
            self.consumed_runner_id,
            self.redeem_operation_id,
            self.redeem_request_sha256.as_deref(),
            self.redeem_response.as_deref(),
            self.redeem_certificate_expires_at_seconds,
        ) {
            (None, None, None, None, None, None) => Ok(()),
            (
                Some(consumed_at_ms),
                Some(runner_id),
                Some(operation_id),
                Some(request),
                Some(response),
                Some(certificate_expires_at_seconds),
            ) if consumed_at_ms >= self.issued_at_ms
                && consumed_at_ms < self.expires_at_ms
                && !runner_id.is_nil()
                && !operation_id.is_nil()
                && request.len() == 32
                && !response.is_empty()
                && response.len() <= MAX_REDEEM_RESPONSE_BYTES
                && certificate_expires_at_seconds > consumed_at_ms.div_euclid(1_000) =>
            {
                Ok(())
            }
            _ => Err(ManagementRepositoryError::CorruptData),
        }
    }

    fn prepared(
        &self,
        database_time_ms: i64,
    ) -> Result<PreparedRunnerEnrollment, ManagementRepositoryError> {
        self.validate()?;
        if self.consumed_at_ms.is_some() || self.expires_at_ms <= database_time_ms {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        Ok(PreparedRunnerEnrollment {
            enrollment_id: self.id,
            tenant_id: self.tenant_id.clone(),
            runner_group_id: self.runner_group_id,
            runner_group: self.runner_group.clone(),
            expires_at_ms: self.expires_at_ms,
            database_time_ms,
        })
    }

    fn replay(
        &self,
        operation_id: Uuid,
        request_sha256: &[u8; 32],
        database_time_ms: i64,
    ) -> Result<Option<Vec<u8>>, ManagementRepositoryError> {
        self.validate()?;
        if self.consumed_at_ms.is_none() {
            return Ok(None);
        }
        if self.redeem_operation_id == Some(operation_id)
            && self.redeem_request_sha256.as_deref() == Some(request_sha256.as_slice())
            && self
                .redeem_certificate_expires_at_seconds
                .is_some_and(|expiry| expiry > database_time_ms.div_euclid(1_000))
        {
            Ok(self.redeem_response.clone())
        } else {
            Ok(None)
        }
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
        create_authorized_runner_enrollment(transaction, actor, descriptor, &request).await
    }

    /// Loads non-secret token scope before certificate signing.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error for an invalid digest, unavailable
    /// storage, or corrupt durable enrollment state.
    pub async fn prepare_runner_enrollment(
        &self,
        request: PrepareRunnerEnrollment,
    ) -> Result<RunnerEnrollmentPrepareOutcome, ManagementRepositoryError> {
        if request.token_sha256 == [0; 32]
            || request.operation_id.is_nil()
            || request.request_sha256 == [0; 32]
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let row = load_enrollment(&mut transaction, &request.token_sha256, true).await?;
        let now_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        commit(transaction).await?;
        let Some(row) = row else {
            return Ok(RunnerEnrollmentPrepareOutcome::Rejected);
        };
        if let Some(response) = row.replay(request.operation_id, &request.request_sha256, now_ms)? {
            return Ok(RunnerEnrollmentPrepareOutcome::Replayed(response));
        }
        if row.consumed_at_ms.is_some() || row.expires_at_ms <= now_ms {
            return Ok(RunnerEnrollmentPrepareOutcome::Rejected);
        }
        Ok(RunnerEnrollmentPrepareOutcome::Prepared(
            row.prepared(now_ms)?,
        ))
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
            || request.operation_id.is_nil()
            || request.request_sha256 == [0; 32]
            || request.runner_id.is_nil()
            || !valid_runner_name(&request.runner_name)
            || request.capabilities.runner_id().as_uuid() != request.runner_id
            || request.capabilities.validate().is_err()
            || request.certificate_leaf_sha256 == [0; 32]
            || request.certificate_issued_at_seconds < 0
            || request.certificate_expires_at_seconds <= request.certificate_issued_at_seconds
            || request.response.is_empty()
            || request.response.len() > MAX_REDEEM_RESPONSE_BYTES
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
        let Some(row) = load_enrollment(&mut transaction, &request.token_sha256, true).await?
        else {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        };
        let replay_time_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        if let Some(response) = row.replay(
            request.operation_id,
            &request.request_sha256,
            replay_time_ms,
        )? {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Replayed(response));
        }
        if row.consumed_at_ms.is_some() {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        }
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RUNNER_ENROLLMENT_CAPACITY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        let now_ms = database_time_milliseconds(&mut transaction)
            .await
            .map_err(map_database_error)?;
        if row.expires_at_ms <= now_ms {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        }
        let now_seconds = now_ms.div_euclid(1_000);
        if request.certificate_issued_at_seconds < row.issued_at_ms.div_euclid(1_000)
            || request.certificate_issued_at_seconds > now_seconds
            || request.certificate_expires_at_seconds <= now_seconds
            || request
                .certificate_expires_at_seconds
                .checked_sub(request.certificate_issued_at_seconds)
                .is_none_or(|lifetime| {
                    !(1..=MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS).contains(&lifetime)
                })
        {
            return Err(ManagementRepositoryError::InvalidRequest);
        }
        let prepared = row.prepared(now_ms)?;
        let expected_group =
            std::collections::BTreeSet::from([RunnerGroup::new(&prepared.runner_group)
                .map_err(|_| ManagementRepositoryError::CorruptData)?]);
        if request.capabilities.groups() != &expected_group {
            commit(transaction).await?;
            return Ok(RunnerEnrollmentConsumeOutcome::Rejected);
        }
        let runner_count: i64 = sqlx::query_scalar("SELECT count(*) FROM runners")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        let runner_count =
            usize::try_from(runner_count).map_err(|_| ManagementRepositoryError::CorruptData)?;
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
        let labels = request
            .capabilities
            .labels()
            .iter()
            .map(|label| label.as_str().to_owned())
            .collect::<Vec<_>>();
        let capabilities = serde_json::to_value(&request.capabilities)
            .map_err(|_| ManagementRepositoryError::InvalidRequest)?;
        let external_identity = enrolled_runner_external_identity(request.runner_id);
        sqlx::query(
            r"
            INSERT INTO runners (
                id,tenant_id,group_id,name,normalized_name,labels,capabilities,
                slots,status,generation,created_at_ms,updated_at_ms,session_epoch,
                external_identity,desired_state
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'offline',1,$9,$9,0,$10,'active')
            ",
        )
        .bind(request.runner_id)
        .bind(&prepared.tenant_id)
        .bind(prepared.runner_group_id)
        .bind(&request.runner_name)
        .bind(&normalized_name)
        .bind(labels)
        .bind(capabilities)
        .bind(i32::from(request.capabilities.max_parallel_jobs()))
        .bind(now_ms)
        .bind(external_identity)
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
            "UPDATE runner_enrollment_tokens SET consumed_at_ms=$2,consumed_runner_id=$3,redeem_operation_id=$4,redeem_request_sha256=$5,redeem_response=$6,redeem_certificate_expires_at_seconds=$7 WHERE id=$1 AND consumed_at_ms IS NULL",
        )
        .bind(prepared.enrollment_id)
        .bind(now_ms)
        .bind(request.runner_id)
        .bind(request.operation_id)
        .bind(request.request_sha256.as_slice())
        .bind(&request.response)
        .bind(request.certificate_expires_at_seconds)
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
        Ok(RunnerEnrollmentConsumeOutcome::Applied(request.response))
    }
}

async fn create_authorized_runner_enrollment(
    mut transaction: Transaction<'_, Postgres>,
    actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
    request: &CreateRunnerEnrollmentToken,
) -> Result<ManagementMutationOutcome<RunnerEnrollmentTokenRecord>, ManagementRepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,$2))")
        .bind(request.enrollment_id.hyphenated().to_string())
        .bind(RUNNER_ENROLLMENT_CREATE_LOCK_SALT)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
    if let Some(existing) = load_created_enrollment(&mut transaction, request.enrollment_id).await?
    {
        if existing.matches(&actor, request) {
            // The original transition already appended its audit event. Exact
            // transport replay returns the durable result without a mutation.
            commit(transaction).await?;
            return Ok(ManagementMutationOutcome::Applied(
                RunnerEnrollmentTokenRecord {
                    enrollment_id: request.enrollment_id,
                    runner_group_id: existing.runner_group_id,
                    runner_group: request.runner_group.clone(),
                    expires_at_ms: existing.expires_at_ms,
                },
            ));
        }
        return finish_enrollment_conflict(transaction, actor, descriptor).await;
    }
    let conflicting_digest: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM runner_enrollment_tokens WHERE token_sha256=$1 FOR UPDATE",
    )
    .bind(request.token_sha256.as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_database_error)?;
    if conflicting_digest.is_some() {
        return finish_enrollment_conflict(transaction, actor, descriptor).await;
    }
    let Some((group_id, expires_at_ms)) =
        try_insert_enrollment(&mut transaction, &actor, request).await?
    else {
        return finish_enrollment_conflict(transaction, actor, descriptor).await;
    };
    finish_applied(
        transaction,
        actor,
        descriptor,
        RunnerEnrollmentTokenRecord {
            enrollment_id: request.enrollment_id,
            runner_group_id: group_id,
            runner_group: request.runner_group.clone(),
            expires_at_ms,
        },
    )
    .await
}

impl CreatedEnrollmentRow {
    fn matches(&self, actor: &AuthorizedActor, request: &CreateRunnerEnrollmentToken) -> bool {
        self.tenant_id == actor.tenant_id
            && self.runner_group == request.runner_group
            && self.token_sha256 == request.token_sha256
            && self.issued_by_principal_id == actor.principal_id
            && self.expires_at_ms.checked_sub(self.issued_at_ms) == Some(request.lifetime_ms)
    }
}

async fn load_created_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    enrollment_id: Uuid,
) -> Result<Option<CreatedEnrollmentRow>, ManagementRepositoryError> {
    sqlx::query_as::<_, CreatedEnrollmentRow>(
        r"
        SELECT token.tenant_id,token.runner_group_id,
               groups.name AS runner_group,token.token_sha256,
               token.issued_by_principal_id,token.issued_at_ms,
               token.expires_at_ms
        FROM runner_enrollment_tokens AS token
        JOIN runner_groups AS groups
          ON groups.tenant_id=token.tenant_id
         AND groups.id=token.runner_group_id
        WHERE token.id=$1
        FOR UPDATE
        ",
    )
    .bind(enrollment_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)
}

async fn try_insert_enrollment(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &AuthorizedActor,
    request: &CreateRunnerEnrollmentToken,
) -> Result<Option<(Uuid, i64)>, ManagementRepositoryError> {
    sqlx::query("SAVEPOINT runner_enrollment_token_create")
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?;
    let issued_at_ms = database_time_milliseconds(transaction)
        .await
        .map_err(map_database_error)?;
    let group_id = ensure_runner_group(
        transaction,
        &actor.tenant_id,
        &request.runner_group,
        issued_at_ms,
    )
    .await?;
    let expires_at_ms = issued_at_ms
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
    .bind(issued_at_ms)
    .bind(expires_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let inserted = inserted.rows_affected() == 1;
    let savepoint_action = if inserted {
        "RELEASE SAVEPOINT runner_enrollment_token_create"
    } else {
        // Also removes a group proposed by the losing concurrent insertion.
        "ROLLBACK TO SAVEPOINT runner_enrollment_token_create"
    };
    sqlx::query(savepoint_action)
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?;
    Ok(inserted.then_some((group_id, expires_at_ms)))
}

async fn finish_enrollment_conflict(
    transaction: Transaction<'_, Postgres>,
    actor: AuthorizedActor,
    descriptor: AuditDescriptor<'_>,
) -> Result<ManagementMutationOutcome<RunnerEnrollmentTokenRecord>, ManagementRepositoryError> {
    super::finish_denied(
        transaction,
        actor,
        descriptor,
        ManagementMutationOutcome::AlreadyExists,
    )
    .await
}

fn enrolled_runner_external_identity(runner_id: Uuid) -> String {
    format!("automata:runner:{}", runner_id.hyphenated())
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
    lock: bool,
) -> Result<Option<EnrollmentRow>, ManagementRepositoryError> {
    let row = if lock {
        sqlx::query_as::<_, EnrollmentRow>(
            r"
            SELECT token.id,token.tenant_id,token.runner_group_id,
                   groups.name AS runner_group,token.issued_at_ms,
                   token.expires_at_ms,
                   token.consumed_at_ms,token.consumed_runner_id,
                   token.redeem_operation_id,token.redeem_request_sha256,
                   token.redeem_response,token.redeem_certificate_expires_at_seconds
            FROM runner_enrollment_tokens AS token
            JOIN runner_groups AS groups
              ON groups.tenant_id=token.tenant_id
             AND groups.id=token.runner_group_id
            WHERE token.token_sha256=$1
            FOR UPDATE
            ",
        )
        .bind(token_sha256.as_slice())
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, EnrollmentRow>(
            r"
            SELECT token.id,token.tenant_id,token.runner_group_id,
                   groups.name AS runner_group,token.issued_at_ms,
                   token.expires_at_ms,
                   token.consumed_at_ms,token.consumed_runner_id,
                   token.redeem_operation_id,token.redeem_request_sha256,
                   token.redeem_response,token.redeem_certificate_expires_at_seconds
            FROM runner_enrollment_tokens AS token
            JOIN runner_groups AS groups
              ON groups.tenant_id=token.tenant_id
             AND groups.id=token.runner_group_id
            WHERE token.token_sha256=$1
            ",
        )
        .bind(token_sha256.as_slice())
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
