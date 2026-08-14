use std::{fmt, sync::Arc};

use automata_ci_auth::{
    github::{
        GithubMembershipRepositoryError, PersistGithubMembershipSnapshot,
        PersistGithubMembershipSnapshotOutcome,
    },
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    installation::{
        ArmInstallationSetup, BindInstallationLogin, CompleteInstallationOutcome,
        CompleteInstallationSetup, CompletedInstallation, InstallationProof,
        InstallationProofDigest, InstallationProofKeyId, InstallationRepository,
        InstallationRepositoryError, InstallationRepositoryFuture, InstallationRevision,
        InstallationState,
    },
    login::LoginTransactionId,
    session::{
        CreateSession, CreateSessionOutcome, DurableSession, DurableSessionIdentity,
        SessionRepositoryError,
    },
    sign_in::PendingSessionConflict,
    vault::{ProviderTokenKey, ProviderTokenVaultError},
};
use automata_ci_key_management::KeyEncryptionProvider;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    PostgresGithubMembershipRepository, PostgresHumanSessionRepository, PostgresProviderTokenVault,
    session::{database_time_milliseconds, validate_caller_time},
    support::{canonical_uuid, constraint, timestamp_from_milliseconds, timestamp_to_milliseconds},
};

const INSTALLATION_OWNER_ROLE_NAME: &str = "installation-owner";
const INSTALLATION_OWNER_ROLE_DISPLAY_NAME: &str = "Installation owner";
const INSTALLATION_AUDIT_ACTION: &str = "auth.installation.configured";

/// Replica-safe database installation bootstrap state and completion adapter.
#[derive(Clone)]
pub struct PostgresInstallationRepository {
    pool: PgPool,
    provider_tokens: PostgresProviderTokenVault,
    memberships: PostgresGithubMembershipRepository,
}

impl PostgresInstallationRepository {
    /// Creates an installation repository using the same wrapping provider as
    /// provider-token custody.
    #[must_use]
    pub fn new(pool: PgPool, provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            provider_tokens: PostgresProviderTokenVault::new(pool.clone(), provider),
            memberships: PostgresGithubMembershipRepository::new(pool.clone()),
            pool,
        }
    }
}

impl fmt::Debug for PostgresInstallationRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresInstallationRepository")
            .field("provider_tokens", &self.provider_tokens)
            .field("memberships", &self.memberships)
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct InstallationRow {
    state: String,
    bootstrap_token_hash: Option<Vec<u8>>,
    bootstrap_hash_key_id: Option<String>,
    expected_provider_id: Option<String>,
    expected_provider_subject: Option<String>,
    challenge_expires_at_ms: Option<i64>,
    target_tenant_id: Option<String>,
    target_tenant_display_name: Option<String>,
    setup_transaction_id: Option<Uuid>,
    configured_tenant_id: Option<String>,
    configured_principal_id: Option<Uuid>,
    configured_at_ms: Option<i64>,
    revision: i64,
    updated_at_ms: i64,
}

impl InstallationRow {
    fn revision(&self) -> Result<InstallationRevision, InstallationRepositoryError> {
        u64::try_from(self.revision)
            .ok()
            .and_then(|value| InstallationRevision::new(value).ok())
            .ok_or(InstallationRepositoryError::CorruptData)
    }

    fn expires_at(
        &self,
    ) -> Result<automata_ci_auth::time::UnixTimestamp, InstallationRepositoryError> {
        self.challenge_expires_at_ms
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                timestamp_from_milliseconds(value)
                    .map_err(|()| InstallationRepositoryError::CorruptData)
            })
    }

    fn proof(&self) -> Result<InstallationProof, InstallationRepositoryError> {
        let key_id = self
            .bootstrap_hash_key_id
            .as_ref()
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                InstallationProofKeyId::new(value.clone())
                    .map_err(|_| InstallationRepositoryError::CorruptData)
            })?;
        let digest: [u8; 32] = self
            .bootstrap_token_hash
            .as_deref()
            .ok_or(InstallationRepositoryError::CorruptData)?
            .try_into()
            .map_err(|_| InstallationRepositoryError::CorruptData)?;
        Ok(InstallationProof::new(
            key_id,
            InstallationProofDigest::new(digest),
        ))
    }

    fn provider_id(&self) -> Result<ProviderId, InstallationRepositoryError> {
        self.expected_provider_id
            .as_ref()
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                ProviderId::new(value.clone()).map_err(|_| InstallationRepositoryError::CorruptData)
            })
    }

    fn provider_subject(&self) -> Result<ProviderSubject, InstallationRepositoryError> {
        self.expected_provider_subject
            .as_ref()
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                ProviderSubject::new(value.clone())
                    .map_err(|_| InstallationRepositoryError::CorruptData)
            })
    }

    fn target_tenant_id(&self) -> Result<TenantId, InstallationRepositoryError> {
        self.target_tenant_id
            .as_ref()
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                TenantId::new(value.clone()).map_err(|_| InstallationRepositoryError::CorruptData)
            })
    }

    fn setup_transaction_id(
        &self,
    ) -> Result<Option<LoginTransactionId>, InstallationRepositoryError> {
        self.setup_transaction_id
            .map(|value| {
                LoginTransactionId::new(value.hyphenated().to_string())
                    .map_err(|_| InstallationRepositoryError::CorruptData)
            })
            .transpose()
    }

    #[allow(clippy::too_many_lines)]
    fn state(&self) -> Result<InstallationState, InstallationRepositoryError> {
        let revision = self.revision()?;
        match self.state.as_str() {
            "unconfigured"
                if self.bootstrap_token_hash.is_none()
                    && self.bootstrap_hash_key_id.is_none()
                    && self.expected_provider_id.is_none()
                    && self.expected_provider_subject.is_none()
                    && self.challenge_expires_at_ms.is_none()
                    && self.target_tenant_id.is_none()
                    && self.target_tenant_display_name.is_none()
                    && self.setup_transaction_id.is_none()
                    && self.configured_tenant_id.is_none()
                    && self.configured_principal_id.is_none()
                    && self.configured_at_ms.is_none() =>
            {
                Ok(InstallationState::Unconfigured { revision })
            }
            "pending" => {
                drop(self.proof()?);
                let tenant_id = self.target_tenant_id()?;
                if self
                    .target_tenant_display_name
                    .as_deref()
                    .is_none_or(str::is_empty)
                    || self.configured_tenant_id.is_some()
                    || self.configured_principal_id.is_some()
                    || self.configured_at_ms.is_some()
                {
                    return Err(InstallationRepositoryError::CorruptData);
                }
                let provider_id = self.provider_id()?;
                let expected_provider_subject = self.provider_subject()?;
                let expires_at = self.expires_at()?;
                if let Some(login_transaction_id) = self.setup_transaction_id()? {
                    Ok(InstallationState::LoginBound {
                        revision,
                        tenant_id,
                        provider_id,
                        expected_provider_subject,
                        login_transaction_id,
                        expires_at,
                    })
                } else {
                    Ok(InstallationState::Armed {
                        revision,
                        tenant_id,
                        provider_id,
                        expected_provider_subject,
                        expires_at,
                    })
                }
            }
            "configured"
                if self.bootstrap_token_hash.is_none()
                    && self.bootstrap_hash_key_id.is_none()
                    && self.challenge_expires_at_ms.is_none() =>
            {
                let target_tenant_id = self.target_tenant_id()?;
                let configured_tenant_id = self
                    .configured_tenant_id
                    .as_ref()
                    .ok_or(InstallationRepositoryError::CorruptData)
                    .and_then(|value| {
                        TenantId::new(value.clone())
                            .map_err(|_| InstallationRepositoryError::CorruptData)
                    })?;
                if target_tenant_id != configured_tenant_id
                    || self
                        .target_tenant_display_name
                        .as_deref()
                        .is_none_or(str::is_empty)
                {
                    return Err(InstallationRepositoryError::CorruptData);
                }
                let principal_id = self
                    .configured_principal_id
                    .ok_or(InstallationRepositoryError::CorruptData)
                    .and_then(|value| {
                        PrincipalId::new(value.hyphenated().to_string())
                            .map_err(|_| InstallationRepositoryError::CorruptData)
                    })?;
                let login_transaction_id = self
                    .setup_transaction_id()?
                    .ok_or(InstallationRepositoryError::CorruptData)?;
                let configured_at = self
                    .configured_at_ms
                    .ok_or(InstallationRepositoryError::CorruptData)
                    .and_then(|value| {
                        timestamp_from_milliseconds(value)
                            .map_err(|()| InstallationRepositoryError::CorruptData)
                    })?;
                Ok(InstallationState::Configured {
                    revision,
                    tenant_id: configured_tenant_id,
                    principal_id,
                    provider_id: self.provider_id()?,
                    provider_subject: self.provider_subject()?,
                    login_transaction_id,
                    configured_at,
                })
            }
            _ => Err(InstallationRepositoryError::CorruptData),
        }
    }
}

#[derive(FromRow)]
struct SetupLoginRow {
    tenant_id: Option<String>,
    purpose: String,
    provider_id: String,
    status: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    completed_principal_id: Option<Uuid>,
    revision: i64,
    updated_at_ms: i64,
}

const INSTALLATION_SELECT: &str = r"
    SELECT state, bootstrap_token_hash, bootstrap_hash_key_id,
           expected_provider_id, expected_provider_subject,
           challenge_expires_at_ms, target_tenant_id,
           target_tenant_display_name, setup_transaction_id,
           configured_tenant_id, configured_principal_id, configured_at_ms,
           revision, updated_at_ms
    FROM human_auth_installation_state WHERE singleton=TRUE
";

const INSTALLATION_SELECT_FOR_UPDATE: &str = r"
    SELECT state, bootstrap_token_hash, bootstrap_hash_key_id,
           expected_provider_id, expected_provider_subject,
           challenge_expires_at_ms, target_tenant_id,
           target_tenant_display_name, setup_transaction_id,
           configured_tenant_id, configured_principal_id, configured_at_ms,
           revision, updated_at_ms
    FROM human_auth_installation_state WHERE singleton=TRUE
    FOR UPDATE
";

async fn load_row(pool: &PgPool) -> Result<InstallationRow, InstallationRepositoryError> {
    sqlx::query_as::<_, InstallationRow>(INSTALLATION_SELECT)
        .fetch_optional(pool)
        .await
        .map_err(map_database_error)?
        .ok_or(InstallationRepositoryError::CorruptData)
}

async fn lock_row(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<InstallationRow, InstallationRepositoryError> {
    sqlx::query_as::<_, InstallationRow>(INSTALLATION_SELECT_FOR_UPDATE)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .ok_or(InstallationRepositoryError::CorruptData)
}

fn next_revision(
    revision: InstallationRevision,
) -> Result<InstallationRevision, InstallationRepositoryError> {
    revision
        .value()
        .checked_add(1)
        .and_then(|value| InstallationRevision::new(value).ok())
        .ok_or(InstallationRepositoryError::CorruptData)
}

fn revision_to_i64(revision: InstallationRevision) -> Result<i64, InstallationRepositoryError> {
    i64::try_from(revision.value()).map_err(|_| InstallationRepositoryError::InvalidRequest)
}

fn map_database_error(error: sqlx::Error) -> InstallationRepositoryError {
    let mapped = match &error {
        sqlx::Error::RowNotFound
        | sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::Decode(_)
        | sqlx::Error::TypeNotFound { .. } => InstallationRepositoryError::CorruptData,
        _ if constraint(&error).is_some_and(|name| {
            name.contains("human_provider_identities")
                || name.contains("rbac_roles_tenant_name_unique")
                || name.contains("human_provider_tokens_one_active_identity")
        }) =>
        {
            InstallationRepositoryError::IdentityConflict
        }
        _ if constraint(&error).is_some() => InstallationRepositoryError::CorruptData,
        _ => InstallationRepositoryError::Unavailable,
    };
    drop(error);
    mapped
}

fn map_token_error(error: ProviderTokenVaultError) -> InstallationRepositoryError {
    match error {
        ProviderTokenVaultError::AlreadyExists
        | ProviderTokenVaultError::Revoked
        | ProviderTokenVaultError::VersionConflict => InstallationRepositoryError::IdentityConflict,
        ProviderTokenVaultError::InvalidRequest => InstallationRepositoryError::InvalidRequest,
        ProviderTokenVaultError::Unavailable => InstallationRepositoryError::Unavailable,
        ProviderTokenVaultError::NotFound | ProviderTokenVaultError::IntegrityFailure => {
            InstallationRepositoryError::CredentialCustody
        }
    }
}

fn map_membership_error(error: GithubMembershipRepositoryError) -> InstallationRepositoryError {
    match error {
        GithubMembershipRepositoryError::InvalidRequest => {
            InstallationRepositoryError::InvalidRequest
        }
        GithubMembershipRepositoryError::Unavailable => InstallationRepositoryError::Unavailable,
        GithubMembershipRepositoryError::CorruptData => InstallationRepositoryError::CorruptData,
    }
}

fn map_session_error(error: SessionRepositoryError) -> InstallationRepositoryError {
    match error {
        SessionRepositoryError::Unavailable => InstallationRepositoryError::Unavailable,
        SessionRepositoryError::InvalidRequest | SessionRepositoryError::CorruptData => {
            InstallationRepositoryError::CorruptData
        }
    }
}

async fn bind_login_row(
    transaction: &mut Transaction<'_, Postgres>,
    login_id: Uuid,
    now_ms: i64,
    expected_revision: InstallationRevision,
) -> Result<u64, InstallationRepositoryError> {
    Ok(sqlx::query(
        r"
        UPDATE human_auth_installation_state
        SET setup_transaction_id=$1,
            updated_at_ms=$2, revision=revision+1
        WHERE singleton=TRUE AND state='pending'
          AND revision=$3
          AND setup_transaction_id IS NULL
          AND challenge_expires_at_ms >
              floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
          AND EXISTS (
              SELECT 1
              FROM human_login_transactions AS login
              WHERE login.id=$1
                AND login.tenant_id IS NULL
                AND login.purpose='installation_setup'
                AND login.provider_id=expected_provider_id
                AND login.status='pending'
                AND login.expires_at_ms >
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
          )
        ",
    )
    .bind(login_id)
    .bind(now_ms)
    .bind(revision_to_i64(expected_revision)?)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?
    .rows_affected())
}

impl InstallationRepository for PostgresInstallationRepository {
    fn load(&self) -> InstallationRepositoryFuture<'_, InstallationState> {
        Box::pin(async move { load_row(&self.pool).await?.state() })
    }

    fn arm(
        &self,
        request: ArmInstallationSetup,
    ) -> InstallationRepositoryFuture<'_, InstallationState> {
        Box::pin(async move {
            let (tenant, proof, provider_id, provider_subject, now, expires_at) =
                request.into_parts();
            let requested_lifetime = expires_at
                .as_seconds()
                .checked_sub(now.as_seconds())
                .ok_or(InstallationRepositoryError::InvalidRequest)?;
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let row = lock_row(&mut transaction).await?;
            let now_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            let database_time = validate_caller_time(now, now_ms)
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let expires_at = database_time
                .checked_add(requested_lifetime)
                .map_err(|_| InstallationRepositoryError::InvalidRequest)?;
            let expires_at_ms = timestamp_to_milliseconds(expires_at)
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let current = row.state()?;
            match &current {
                InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::AlreadyConfigured);
                }
                InstallationState::Armed { expires_at, .. }
                | InstallationState::LoginBound { expires_at, .. }
                    if *expires_at > database_time =>
                {
                    let exact = row.target_tenant_id()?.as_str() == tenant.tenant_id().as_str()
                        && row.target_tenant_display_name.as_deref() == Some(tenant.display_name())
                        && row.provider_id()?.as_str() == provider_id.as_str()
                        && row.provider_subject()?.as_str() == provider_subject.as_str()
                        && row.proof()?.eq(&proof);
                    if !exact {
                        return Err(InstallationRepositoryError::VersionConflict);
                    }
                    transaction.commit().await.map_err(map_database_error)?;
                    return Ok(current);
                }
                InstallationState::Unconfigured { .. }
                | InstallationState::Armed { .. }
                | InstallationState::LoginBound { .. } => {}
            }
            if now_ms < row.updated_at_ms {
                return Err(InstallationRepositoryError::CorruptData);
            }
            let revision = row.revision()?;
            let updated = sqlx::query(
                r"
                UPDATE human_auth_installation_state
                SET state='pending', bootstrap_token_hash=$1,
                    bootstrap_hash_key_id=$2, expected_provider_id=$3,
                    expected_provider_subject=$4, challenge_expires_at_ms=$5,
                    target_tenant_id=$6, target_tenant_display_name=$7,
                    setup_transaction_id=NULL, configured_tenant_id=NULL,
                    configured_principal_id=NULL, configured_at_ms=NULL,
                    updated_at_ms=$8, revision=revision+1
                WHERE singleton=TRUE AND revision=$9
                ",
            )
            .bind(proof.digest().as_bytes().as_slice())
            .bind(proof.key_id().as_str())
            .bind(provider_id.as_str())
            .bind(provider_subject.as_str())
            .bind(expires_at_ms)
            .bind(tenant.tenant_id().as_str())
            .bind(tenant.display_name())
            .bind(now_ms)
            .bind(revision_to_i64(revision)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if updated.rows_affected() != 1 {
                return Err(InstallationRepositoryError::VersionConflict);
            }
            let state = lock_row(&mut transaction).await?.state()?;
            transaction.commit().await.map_err(map_database_error)?;
            Ok(state)
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the bind transaction keeps predecessor replay and locked login evidence in one auditable flow"
    )]
    fn bind_login(
        &self,
        request: BindInstallationLogin,
    ) -> InstallationRepositoryFuture<'_, InstallationState> {
        Box::pin(async move {
            let (expected_revision, proof, login_transaction_id, now) = request.into_parts();
            let login_id = canonical_uuid(login_transaction_id.as_str())
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let row = lock_row(&mut transaction).await?;
            let current_revision = row.revision()?;
            let bound_login_id = row.setup_transaction_id;
            let predecessor_replay = current_revision == next_revision(expected_revision)?
                && bound_login_id == Some(login_id);
            if current_revision != expected_revision && !predecessor_replay {
                return Err(InstallationRepositoryError::VersionConflict);
            }
            if row.proof()? != proof {
                return Err(InstallationRepositoryError::ProofRejected);
            }
            let login = sqlx::query_as::<_, SetupLoginRow>(
                r"
                SELECT tenant_id, purpose, provider_id, status, created_at_ms,
                       expires_at_ms, consumed_at_ms, completed_principal_id,
                       revision, updated_at_ms
                FROM human_login_transactions WHERE id=$1 FOR UPDATE
                ",
            )
            .bind(login_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .ok_or(InstallationRepositoryError::InvalidRequest)?;
            let now_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            let database_time = validate_caller_time(now, now_ms)
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let state = row.state()?;
            match &state {
                InstallationState::Unconfigured { .. } => {
                    return Err(InstallationRepositoryError::NotArmed);
                }
                InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::AlreadyConfigured);
                }
                InstallationState::Armed { expires_at, .. }
                | InstallationState::LoginBound { expires_at, .. }
                    if *expires_at <= database_time =>
                {
                    return Err(InstallationRepositoryError::Expired);
                }
                InstallationState::Armed { .. } | InstallationState::LoginBound { .. } => {}
            }
            let immutable_login_matches = login.tenant_id.is_none()
                && login.purpose == "installation_setup"
                && login.provider_id == row.provider_id()?.as_str()
                && login.created_at_ms >= 0
                && login.expires_at_ms > login.created_at_ms;
            if !immutable_login_matches {
                return Err(if bound_login_id == Some(login_id) {
                    InstallationRepositoryError::CorruptData
                } else {
                    InstallationRepositoryError::InvalidRequest
                });
            }
            if let Some(bound) = row.setup_transaction_id()? {
                if bound != login_transaction_id {
                    return Err(InstallationRepositoryError::AlreadyBound);
                }
                // A committed bind advances the singleton exactly once. The
                // original predecessor request may therefore replay at its
                // successor revision after a lost response, but only while the
                // exact locked login still carries the immutable evidence that
                // made the original bind valid.
                if login.created_at_ms > row.updated_at_ms
                    || login.expires_at_ms <= row.updated_at_ms
                    || row.updated_at_ms > now_ms
                {
                    return Err(InstallationRepositoryError::CorruptData);
                }
                transaction.commit().await.map_err(map_database_error)?;
                return Ok(state);
            }
            if login.status != "pending" {
                return Err(
                    if login.status == "expired" || login.expires_at_ms <= now_ms {
                        InstallationRepositoryError::Expired
                    } else {
                        InstallationRepositoryError::InvalidRequest
                    },
                );
            }
            if login.created_at_ms < row.updated_at_ms || login.created_at_ms > now_ms {
                return Err(InstallationRepositoryError::InvalidRequest);
            }
            if login.expires_at_ms <= now_ms {
                return Err(InstallationRepositoryError::Expired);
            }
            if bind_login_row(&mut transaction, login_id, now_ms, expected_revision).await? != 1 {
                let final_now_ms = database_time_milliseconds(&mut transaction)
                    .await
                    .map_err(map_database_error)?;
                if row
                    .challenge_expires_at_ms
                    .is_none_or(|expires_at_ms| expires_at_ms <= final_now_ms)
                    || login.expires_at_ms <= final_now_ms
                {
                    return Err(InstallationRepositoryError::Expired);
                }
                return Err(InstallationRepositoryError::VersionConflict);
            }
            let state = lock_row(&mut transaction).await?.state()?;
            transaction.commit().await.map_err(map_database_error)?;
            Ok(state)
        })
    }

    #[allow(clippy::too_many_lines)]
    fn complete(
        &self,
        request: CompleteInstallationSetup,
    ) -> InstallationRepositoryFuture<'_, CompleteInstallationOutcome> {
        Box::pin(async move {
            let (retry, session) = request.into_retry_parts();
            let expected_revision = retry.expected_revision();
            let tenant = retry.tenant();
            let login_transaction_id = retry.login_transaction_id();
            let identity = retry.identity();
            let provider_tokens = retry.provider_tokens();
            let now = retry.now();
            let login_id = canonical_uuid(login_transaction_id.as_str())
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let authenticated_at_ms = timestamp_to_milliseconds(identity.authenticated_at())
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let row = lock_row(&mut transaction).await?;
            if row.revision()? != expected_revision {
                return Err(InstallationRepositoryError::VersionConflict);
            }
            if row.target_tenant_id()?.as_str() != tenant.tenant_id().as_str()
                || row.target_tenant_display_name.as_deref() != Some(tenant.display_name())
                || row.provider_id()? != *identity.provider_id()
                || row.provider_subject()? != *identity.provider_subject()
            {
                return Err(InstallationRepositoryError::IdentityConflict);
            }
            let metadata = provider_tokens.metadata();
            if metadata.provider_id() != identity.provider_id()
                || metadata.provider_subject() != Some(identity.provider_subject())
                || metadata.issued_at() > identity.authenticated_at()
            {
                return Err(InstallationRepositoryError::InvalidRequest);
            }

            let login = sqlx::query_as::<_, SetupLoginRow>(
                r"
                SELECT tenant_id, purpose, provider_id, status, created_at_ms,
                       expires_at_ms, consumed_at_ms, completed_principal_id,
                       revision, updated_at_ms
                FROM human_login_transactions WHERE id=$1 FOR UPDATE
                ",
            )
            .bind(login_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_database_error)?
            .ok_or(InstallationRepositoryError::InvalidRequest)?;
            let now_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            let database_time = validate_caller_time(now, now_ms)
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            match row.state()? {
                InstallationState::Unconfigured { .. } | InstallationState::Armed { .. } => {
                    return Err(InstallationRepositoryError::NotArmed);
                }
                InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::AlreadyConfigured);
                }
                InstallationState::LoginBound {
                    login_transaction_id: bound,
                    expires_at,
                    ..
                } => {
                    if expires_at <= database_time {
                        return Err(InstallationRepositoryError::Expired);
                    }
                    if &bound != login_transaction_id {
                        return Err(InstallationRepositoryError::AlreadyBound);
                    }
                }
            }
            let consumed_at_ms = login
                .consumed_at_ms
                .ok_or(InstallationRepositoryError::CorruptData)?;
            if login.tenant_id.is_some()
                || login.purpose != "installation_setup"
                || login.provider_id != identity.provider_id().as_str()
                || login.completed_principal_id.is_some()
            {
                return Err(InstallationRepositoryError::InvalidRequest);
            }
            if login.status != "consumed" {
                return Err(match login.status.as_str() {
                    "expired" | "denied" => InstallationRepositoryError::Expired,
                    "succeeded" => InstallationRepositoryError::CorruptData,
                    _ => InstallationRepositoryError::InvalidRequest,
                });
            }
            if consumed_at_ms < login.created_at_ms
                || consumed_at_ms >= login.expires_at_ms
                || consumed_at_ms > login.updated_at_ms
                || login.updated_at_ms > now_ms
                || authenticated_at_ms < consumed_at_ms
            {
                return Err(InstallationRepositoryError::CorruptData);
            }

            sqlx::query(
                r"
                INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
                VALUES ($1,$2,$3,$3) ON CONFLICT (id) DO NOTHING
                ",
            )
            .bind(tenant.tenant_id().as_str())
            .bind(tenant.display_name())
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            let stored_tenant_display_name: String =
                sqlx::query_scalar("SELECT display_name FROM tenants WHERE id=$1 FOR UPDATE")
                    .bind(tenant.tenant_id().as_str())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(map_database_error)?;
            if stored_tenant_display_name != tenant.display_name() {
                return Err(InstallationRepositoryError::IdentityConflict);
            }
            let existing_memberships: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM tenant_human_memberships WHERE tenant_id=$1)",
            )
            .bind(tenant.tenant_id().as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if existing_memberships {
                return Err(InstallationRepositoryError::IdentityConflict);
            }

            let principal_uuid = Uuid::new_v4();
            let principal_id = PrincipalId::new(principal_uuid.hyphenated().to_string())
                .map_err(|_| InstallationRepositoryError::CorruptData)?;
            let role_id = Uuid::new_v4();
            let binding_id = Uuid::new_v4();
            sqlx::query(
                r"
                INSERT INTO human_principals (
                    id, status, display_name, revision, created_at_ms, updated_at_ms
                ) VALUES ($1,'active',$2,1,$3,$3)
                ",
            )
            .bind(principal_uuid)
            .bind(identity.display_name())
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            sqlx::query(
                r"
                INSERT INTO human_provider_identities (
                    principal_id, provider_id, provider_subject, provider_login,
                    normalized_login, display_name, first_authenticated_at_ms,
                    last_authenticated_at_ms, last_observed_at_ms, revision,
                    created_at_ms, updated_at_ms
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,1,$8,$8)
                ",
            )
            .bind(principal_uuid)
            .bind(identity.provider_id().as_str())
            .bind(identity.provider_subject().as_str())
            .bind(identity.login())
            .bind(identity.login().to_ascii_lowercase())
            .bind(identity.display_name())
            .bind(authenticated_at_ms)
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            sqlx::query(
                r"
                INSERT INTO tenant_human_memberships (
                    tenant_id, principal_id, status, authorization_revision,
                    revision, created_at_ms, updated_at_ms
                ) VALUES ($1,$2,'active',1,1,$3,$3)
                ",
            )
            .bind(tenant.tenant_id().as_str())
            .bind(principal_uuid)
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            sqlx::query(
                r"
                INSERT INTO rbac_roles (
                    tenant_id, id, name, display_name, role_kind, immutable,
                    revision, created_by_principal_id, created_at_ms, updated_at_ms
                ) VALUES ($1,$2,$3,$4,'built_in',TRUE,1,$5,$6,$6)
                ",
            )
            .bind(tenant.tenant_id().as_str())
            .bind(role_id)
            .bind(INSTALLATION_OWNER_ROLE_NAME)
            .bind(INSTALLATION_OWNER_ROLE_DISPLAY_NAME)
            .bind(principal_uuid)
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            let granted_permissions: i64 = sqlx::query_scalar(
                r"
                WITH granted AS (
                    INSERT INTO rbac_role_permissions (
                        tenant_id, role_id, permission_name,
                        granted_by_principal_id, granted_at_ms
                    )
                    SELECT $1,$2,name,$3,$4 FROM rbac_permissions
                    RETURNING 1
                )
                SELECT count(*) FROM granted
                ",
            )
            .bind(tenant.tenant_id().as_str())
            .bind(role_id)
            .bind(principal_uuid)
            .bind(now_ms)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if granted_permissions <= 0 {
                return Err(InstallationRepositoryError::CorruptData);
            }
            sqlx::query(
                r"
                INSERT INTO rbac_role_bindings (
                    tenant_id, id, principal_id, role_id, scope_kind,
                    assignment_source, status, created_by_principal_id,
                    created_at_ms, revision
                ) VALUES ($1,$2,$3,$4,'tenant','bootstrap','active',$3,$5,1)
                ",
            )
            .bind(tenant.tenant_id().as_str())
            .bind(binding_id)
            .bind(principal_uuid)
            .bind(role_id)
            .bind(now_ms)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            let token_key = ProviderTokenKey::new(
                tenant.tenant_id().clone(),
                identity.provider_id().clone(),
                identity.provider_subject().clone(),
            );
            let provider_token_version = self
                .provider_tokens
                .insert_in_transaction(&mut transaction, &token_key, provider_tokens)
                .await
                .map_err(map_token_error)?;

            let membership_request = PersistGithubMembershipSnapshot::new(
                tenant.tenant_id().clone(),
                principal_id.clone(),
                identity.provider_subject().clone(),
                provider_token_version,
                retry.membership().clone(),
            )
            .map_err(|_| InstallationRepositoryError::InvalidRequest)?;
            let authorization_revision = match self
                .memberships
                .persist_in_transaction(&mut transaction, &membership_request)
                .await
                .map_err(map_membership_error)?
            {
                PersistGithubMembershipSnapshotOutcome::Stored {
                    authorization_revision,
                    ..
                }
                | PersistGithubMembershipSnapshotOutcome::AlreadyStored {
                    authorization_revision,
                } => authorization_revision,
                PersistGithubMembershipSnapshotOutcome::PrincipalNotFound
                | PersistGithubMembershipSnapshotOutcome::PrincipalDisabled
                | PersistGithubMembershipSnapshotOutcome::IdentityNotFound
                | PersistGithubMembershipSnapshotOutcome::MembershipNotFound
                | PersistGithubMembershipSnapshotOutcome::MembershipSuspended
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenNotFound
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenRevoked
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenNotYetValid
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenExpired
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenVersionChanged { .. }
                | PersistGithubMembershipSnapshotOutcome::SnapshotConflict
                | PersistGithubMembershipSnapshotOutcome::ObservationOutOfOrder => {
                    return Err(InstallationRepositoryError::CorruptData);
                }
            };

            let final_now_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            validate_caller_time(now, final_now_ms)
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            if row
                .challenge_expires_at_ms
                .is_none_or(|expires_at_ms| expires_at_ms <= final_now_ms)
                || login.expires_at_ms <= final_now_ms
            {
                return Err(InstallationRepositoryError::Expired);
            }

            let (session_id, lookup, kind, issued_at, idle_expires_at, expires_at) =
                session.into_parts();
            let durable_identity = DurableSessionIdentity::new(
                session_id,
                tenant.tenant_id().clone(),
                principal_id.clone(),
                identity.provider_id().clone(),
                identity.provider_subject().clone(),
                kind,
            )
            .map_err(|_| InstallationRepositoryError::CorruptData)?;
            let durable_session = DurableSession::new(
                durable_identity,
                authorization_revision,
                issued_at,
                issued_at,
                idle_expires_at,
                expires_at,
                None,
            )
            .map_err(|_| InstallationRepositoryError::CorruptData)?;
            let (create_outcome, created_session) =
                PostgresHumanSessionRepository::create_in_transaction(
                    &mut transaction,
                    CreateSession::new(lookup, durable_session.clone()),
                )
                .await
                .map_err(map_session_error)?;
            match create_outcome {
                CreateSessionOutcome::Created => {}
                CreateSessionOutcome::SessionIdConflict => {
                    return Ok(CompleteInstallationOutcome::SessionConflict {
                        conflict: PendingSessionConflict::SessionId,
                        retry: Box::new(retry),
                    });
                }
                CreateSessionOutcome::TokenDigestConflict => {
                    return Ok(CompleteInstallationOutcome::SessionConflict {
                        conflict: PendingSessionConflict::TokenDigest,
                        retry: Box::new(retry),
                    });
                }
            }
            let durable_session =
                created_session.ok_or(InstallationRepositoryError::CorruptData)?;
            let completed_at_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            validate_caller_time(now, completed_at_ms)
                .map_err(|()| InstallationRepositoryError::InvalidRequest)?;
            let completed_at = timestamp_from_milliseconds(completed_at_ms)
                .map_err(|()| InstallationRepositoryError::CorruptData)?;
            // The caller clock is bounded transport evidence, not authority.
            // Revalidate the provider and membership ceilings after KMS and
            // persistence waits, immediately before bootstrap ownership and the
            // new session are permitted to commit.
            if row
                .challenge_expires_at_ms
                .is_none_or(|expires_at_ms| expires_at_ms <= completed_at_ms)
                || login.expires_at_ms <= completed_at_ms
                || retry
                    .provider_tokens()
                    .metadata()
                    .access_expires_at()
                    .is_none_or(|expires_at| expires_at <= completed_at)
                || retry.membership().valid_until() <= completed_at
                || durable_session.idle_expires_at() <= completed_at
                || durable_session.expires_at() <= completed_at
            {
                return Err(InstallationRepositoryError::Expired);
            }

            let login_updated = sqlx::query(
                r"
                UPDATE human_login_transactions
                SET status='succeeded', completed_principal_id=$2,
                    updated_at_ms=$3, revision=revision+1
                WHERE id=$1 AND status='consumed' AND revision=$4
                  AND expires_at_ms >
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                ",
            )
            .bind(login_id)
            .bind(principal_uuid)
            .bind(completed_at_ms)
            .bind(login.revision)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if login_updated.rows_affected() != 1 {
                return Err(InstallationRepositoryError::VersionConflict);
            }

            let next = next_revision(expected_revision)?;
            let installation_updated = sqlx::query(
                r"
                UPDATE human_auth_installation_state
                SET state='configured', bootstrap_token_hash=NULL,
                    bootstrap_hash_key_id=NULL, challenge_expires_at_ms=NULL,
                    configured_tenant_id=$1, configured_principal_id=$2,
                    configured_at_ms=$3, updated_at_ms=$3, revision=revision+1
                WHERE singleton=TRUE AND state='pending'
                  AND setup_transaction_id=$4 AND revision=$5
                  AND challenge_expires_at_ms >
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                ",
            )
            .bind(tenant.tenant_id().as_str())
            .bind(principal_uuid)
            .bind(completed_at_ms)
            .bind(login_id)
            .bind(revision_to_i64(expected_revision)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if installation_updated.rows_affected() != 1 {
                return Err(InstallationRepositoryError::VersionConflict);
            }
            sqlx::query(
                r"
                INSERT INTO security_audit_events (
                    event_id, tenant_id, occurred_at_ms, actor_kind, action,
                    outcome, resource_kind, resource_id
                ) VALUES ($1,$2,$3,'system',$4,'succeeded','installation','singleton')
                ",
            )
            .bind(Uuid::new_v4())
            .bind(tenant.tenant_id().as_str())
            .bind(completed_at_ms)
            .bind(INSTALLATION_AUDIT_ACTION)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            transaction.commit().await.map_err(map_database_error)?;
            let completed = CompletedInstallation::new(
                tenant.tenant_id().clone(),
                principal_id,
                next,
                Box::new(durable_session),
            )
            .map_err(|_| InstallationRepositoryError::CorruptData)?;
            Ok(CompleteInstallationOutcome::Completed(completed))
        })
    }
}
