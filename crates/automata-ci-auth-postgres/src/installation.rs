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
        InstallationState, InstallationTenant,
    },
    login::LoginTransactionId,
    session::{DurableSession, DurableSessionIdentity, SessionRepositoryError},
    sign_in::PendingSessionConflict,
    vault::{ProviderTokenKey, ProviderTokenVaultError},
};
use automata_ci_key_management::KeyEncryptionProvider;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    PostgresGithubMembershipRepository, PostgresHumanSessionRepository, PostgresProviderTokenVault,
    session::{
        CreateSession, CreateSessionOutcome, database_time_milliseconds, validate_caller_time,
    },
    support::{canonical_uuid, constraint, timestamp_from_milliseconds, timestamp_to_milliseconds},
};

const INSTALLATION_OWNER_ROLE_NAME: &str = "installation-owner";
const INSTALLATION_OWNER_ROLE_DISPLAY_NAME: &str = "Installation owner";
const INSTALLATION_AUDIT_ACTION: &str = "auth.installation.configured";
const DEPLOYMENT_INSTALLATION_AUDIT_ACTION: &str = "auth.installation.deployment_configured";
const INSTALLATION_RESOURCE_KIND: &str = "installation";
const INSTALLATION_RESOURCE_ID: &str = "singleton";

/// Provider-neutral `PostgreSQL` authority for the singleton installation.
///
/// This is the shared durable core used by human installation setup and by a
/// deployment bootstrap consumer. It owns the one installation transition; it
/// does not introduce another tenant or enrollment authority.
#[derive(Clone)]
pub struct PostgresInstallationAuthorityRepository {
    pool: PgPool,
}

impl PostgresInstallationAuthorityRepository {
    /// Binds the singleton installation authority to one `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Atomically creates and binds a deployment installation when the
    /// singleton and requested tenant are wholly absent.
    ///
    /// Exact retries return the same opaque proof without another audit event.
    /// Any configured installation, pending human setup, pre-existing tenant,
    /// or crossed authority, operation, tenant, or display name fails closed.
    ///
    /// A bootstrap consumer must apply one total deadline around this complete
    /// future, including pool acquisition and transaction commit. A timeout is
    /// ambiguous and must be recovered by retrying the identical request.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository error when storage is unavailable or the
    /// singleton violates its closed installation-state contract.
    pub async fn configure_deployment(
        &self,
        request: ConfigureDeploymentInstallation,
    ) -> Result<ConfigureDeploymentInstallationOutcome, InstallationRepositoryError> {
        configure_deployment_installation(&self.pool, request).await
    }
}

impl fmt::Debug for PostgresInstallationAuthorityRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresInstallationAuthorityRepository")
            .finish_non_exhaustive()
    }
}

/// Digest-only request for the one deployment installation transition.
#[derive(Clone)]
pub struct ConfigureDeploymentInstallation {
    pub(crate) installation_authority_sha256: [u8; 32],
    pub(crate) bootstrap_operation_id: Uuid,
    pub(crate) tenant: InstallationTenant,
}

impl ConfigureDeploymentInstallation {
    /// Creates an exact deployment installation request.
    ///
    /// The authority digest is derived by the deployment bootstrap layer; its
    /// source bytes never cross this repository boundary.
    ///
    /// # Errors
    ///
    /// Rejects a zero authority digest or nil operation identity. The tenant has
    /// already passed the shared installation-value validation boundary.
    pub fn new(
        installation_authority_sha256: [u8; 32],
        bootstrap_operation_id: Uuid,
        tenant: InstallationTenant,
    ) -> Result<Self, DeploymentInstallationRequestError> {
        if installation_authority_sha256 == [0; 32] || bootstrap_operation_id.is_nil() {
            return Err(DeploymentInstallationRequestError);
        }
        Ok(Self {
            installation_authority_sha256,
            bootstrap_operation_id,
            tenant,
        })
    }
}

impl fmt::Debug for ConfigureDeploymentInstallation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigureDeploymentInstallation")
            .field("bootstrap_operation_id", &self.bootstrap_operation_id)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

/// Sanitized invalid deployment-installation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentInstallationRequestError;

impl fmt::Display for DeploymentInstallationRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deployment installation request is invalid")
    }
}

impl std::error::Error for DeploymentInstallationRequestError {}

/// Opaque proof issued only after deployment installation commits.
///
/// There is deliberately no public constructor or accessor. Runner bootstrap
/// revalidates every field against the immutable singleton in its transaction.
#[derive(Clone)]
pub struct ConfiguredDeploymentInstallationProof {
    pub(crate) installation_authority_sha256: [u8; 32],
    pub(crate) bootstrap_operation_id: Uuid,
    pub(crate) tenant_id: TenantId,
    pub(crate) tenant_display_name: String,
    pub(crate) bootstrap_audit_event_id: Uuid,
    pub(crate) configured_at_ms: i64,
    pub(crate) installation_revision: InstallationRevision,
}

impl fmt::Debug for ConfiguredDeploymentInstallationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredDeploymentInstallationProof")
            .finish_non_exhaustive()
    }
}

/// Durable result of the deployment installation transition.
#[derive(Clone, Debug)]
pub enum ConfigureDeploymentInstallationOutcome {
    /// Tenant, singleton binding, and one success audit committed together.
    Applied(ConfiguredDeploymentInstallationProof),
    /// The identical transition had already committed.
    Replayed(ConfiguredDeploymentInstallationProof),
    /// Durable installation or tenant identity conflicts with the request.
    Conflict,
}

/// Replica-safe database installation bootstrap state and completion adapter.
#[derive(Clone)]
pub struct PostgresInstallationRepository {
    authority: PostgresInstallationAuthorityRepository,
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
            authority: PostgresInstallationAuthorityRepository::new(pool),
        }
    }
}

impl fmt::Debug for PostgresInstallationRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresInstallationRepository")
            .field("authority", &self.authority)
            .field("provider_tokens", &self.provider_tokens)
            .field("memberships", &self.memberships)
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct InstallationRow {
    state: String,
    configuration_mode: Option<String>,
    bootstrap_token_hash: Option<Vec<u8>>,
    bootstrap_hash_key_id: Option<String>,
    expected_provider_id: Option<String>,
    expected_provider_subject: Option<String>,
    challenge_expires_at_ms: Option<i64>,
    tenant_id: Option<String>,
    tenant_display_name: Option<String>,
    setup_transaction_id: Option<Uuid>,
    configured_tenant_id: Option<String>,
    configured_principal_id: Option<Uuid>,
    configured_at_ms: Option<i64>,
    deployment_authority_sha256: Option<Vec<u8>>,
    deployment_bootstrap_operation_id: Option<Uuid>,
    deployment_bootstrap_audit_event_id: Option<Uuid>,
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

    fn tenant_id(&self) -> Result<TenantId, InstallationRepositoryError> {
        self.tenant_id
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

    fn state(&self) -> Result<InstallationState, InstallationRepositoryError> {
        let revision = self.revision()?;
        match (self.state.as_str(), self.configuration_mode.as_deref()) {
            ("unconfigured", None) => self.unconfigured_state(revision),
            ("pending", Some("human")) => self.pending_human_state(revision),
            ("configured", Some("human")) => self.configured_human_state(revision),
            ("configured", Some("deployment")) => {
                self.validate_configured_deployment()?;
                Err(InstallationRepositoryError::AlreadyConfigured)
            }
            _ => Err(InstallationRepositoryError::CorruptData),
        }
    }

    fn unconfigured_state(
        &self,
        revision: InstallationRevision,
    ) -> Result<InstallationState, InstallationRepositoryError> {
        if self.bootstrap_token_hash.is_some()
            || self.bootstrap_hash_key_id.is_some()
            || self.expected_provider_id.is_some()
            || self.expected_provider_subject.is_some()
            || self.challenge_expires_at_ms.is_some()
            || self.tenant_id.is_some()
            || self.tenant_display_name.is_some()
            || self.setup_transaction_id.is_some()
            || self.configured_tenant_id.is_some()
            || self.configured_principal_id.is_some()
            || self.configured_at_ms.is_some()
            || self.deployment_authority_sha256.is_some()
            || self.deployment_bootstrap_operation_id.is_some()
            || self.deployment_bootstrap_audit_event_id.is_some()
        {
            return Err(InstallationRepositoryError::CorruptData);
        }
        Ok(InstallationState::Unconfigured { revision })
    }

    fn pending_human_state(
        &self,
        revision: InstallationRevision,
    ) -> Result<InstallationState, InstallationRepositoryError> {
        drop(self.proof()?);
        let tenant_id = self.tenant_id()?;
        if self
            .tenant_display_name
            .as_deref()
            .is_none_or(str::is_empty)
            || self.configured_tenant_id.is_some()
            || self.configured_principal_id.is_some()
            || self.configured_at_ms.is_some()
            || self.deployment_authority_sha256.is_some()
            || self.deployment_bootstrap_operation_id.is_some()
            || self.deployment_bootstrap_audit_event_id.is_some()
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

    fn configured_human_state(
        &self,
        revision: InstallationRevision,
    ) -> Result<InstallationState, InstallationRepositoryError> {
        if self.deployment_authority_sha256.is_some()
            || self.deployment_bootstrap_operation_id.is_some()
            || self.deployment_bootstrap_audit_event_id.is_some()
            || self.bootstrap_token_hash.is_some()
            || self.bootstrap_hash_key_id.is_some()
            || self.challenge_expires_at_ms.is_some()
        {
            return Err(InstallationRepositoryError::CorruptData);
        }
        let tenant_id = self.exact_configured_tenant_id()?;
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
        Ok(InstallationState::Configured {
            revision,
            tenant_id,
            principal_id,
            provider_id: self.provider_id()?,
            provider_subject: self.provider_subject()?,
            login_transaction_id,
            configured_at: self.configured_at()?,
        })
    }

    fn validate_configured_deployment(&self) -> Result<(), InstallationRepositoryError> {
        if self.bootstrap_token_hash.is_some()
            || self.bootstrap_hash_key_id.is_some()
            || self.expected_provider_id.is_some()
            || self.expected_provider_subject.is_some()
            || self.challenge_expires_at_ms.is_some()
            || self.setup_transaction_id.is_some()
            || self.configured_principal_id.is_some()
            || self
                .deployment_authority_sha256
                .as_deref()
                .is_none_or(|digest| digest.len() != 32 || digest == [0; 32])
            || self
                .deployment_bootstrap_operation_id
                .is_none_or(|id| id.is_nil())
            || self
                .deployment_bootstrap_audit_event_id
                .is_none_or(|id| id.is_nil())
        {
            return Err(InstallationRepositoryError::CorruptData);
        }
        drop(self.exact_configured_tenant_id()?);
        let _ = self.configured_at()?;
        Ok(())
    }

    fn is_configured_deployment(&self) -> Result<bool, InstallationRepositoryError> {
        if self.state == "configured" && self.configuration_mode.as_deref() == Some("deployment") {
            self.validate_configured_deployment()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn exact_configured_tenant_id(&self) -> Result<TenantId, InstallationRepositoryError> {
        let tenant_id = self.tenant_id()?;
        let configured_tenant_id = self
            .configured_tenant_id
            .as_ref()
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                TenantId::new(value.clone()).map_err(|_| InstallationRepositoryError::CorruptData)
            })?;
        if tenant_id != configured_tenant_id
            || self
                .tenant_display_name
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(InstallationRepositoryError::CorruptData);
        }
        Ok(configured_tenant_id)
    }

    fn configured_at(
        &self,
    ) -> Result<automata_ci_auth::time::UnixTimestamp, InstallationRepositoryError> {
        self.configured_at_ms
            .ok_or(InstallationRepositoryError::CorruptData)
            .and_then(|value| {
                timestamp_from_milliseconds(value)
                    .map_err(|()| InstallationRepositoryError::CorruptData)
            })
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
    SELECT state, configuration_mode, bootstrap_token_hash, bootstrap_hash_key_id,
           expected_provider_id, expected_provider_subject,
           challenge_expires_at_ms, tenant_id,
           tenant_display_name, setup_transaction_id,
           configured_tenant_id, configured_principal_id, configured_at_ms,
           deployment_authority_sha256, deployment_bootstrap_operation_id,
           deployment_bootstrap_audit_event_id,
           revision, updated_at_ms
    FROM installation_state WHERE singleton=TRUE
";

const INSTALLATION_SELECT_FOR_UPDATE: &str = r"
    SELECT state, configuration_mode, bootstrap_token_hash, bootstrap_hash_key_id,
           expected_provider_id, expected_provider_subject,
           challenge_expires_at_ms, tenant_id,
           tenant_display_name, setup_transaction_id,
           configured_tenant_id, configured_principal_id, configured_at_ms,
           deployment_authority_sha256, deployment_bootstrap_operation_id,
           deployment_bootstrap_audit_event_id,
           revision, updated_at_ms
    FROM installation_state WHERE singleton=TRUE
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

impl InstallationRow {
    fn deployment_proof(
        &self,
    ) -> Result<ConfiguredDeploymentInstallationProof, InstallationRepositoryError> {
        if !self.is_configured_deployment()? {
            return Err(InstallationRepositoryError::CorruptData);
        }
        let revision = self.revision()?;
        let tenant_id = self.exact_configured_tenant_id()?;
        let installation_authority_sha256 = self
            .deployment_authority_sha256
            .as_deref()
            .ok_or(InstallationRepositoryError::CorruptData)?
            .try_into()
            .map_err(|_| InstallationRepositoryError::CorruptData)?;
        Ok(ConfiguredDeploymentInstallationProof {
            installation_authority_sha256,
            bootstrap_operation_id: self
                .deployment_bootstrap_operation_id
                .ok_or(InstallationRepositoryError::CorruptData)?,
            tenant_id,
            tenant_display_name: self
                .tenant_display_name
                .clone()
                .ok_or(InstallationRepositoryError::CorruptData)?,
            bootstrap_audit_event_id: self
                .deployment_bootstrap_audit_event_id
                .ok_or(InstallationRepositoryError::CorruptData)?,
            configured_at_ms: self
                .configured_at_ms
                .ok_or(InstallationRepositoryError::CorruptData)?,
            installation_revision: revision,
        })
    }

    fn matches_deployment_request(
        &self,
        request: &ConfigureDeploymentInstallation,
    ) -> Result<bool, InstallationRepositoryError> {
        let proof = self.deployment_proof()?;
        Ok(
            proof.installation_authority_sha256 == request.installation_authority_sha256
                && proof.bootstrap_operation_id == request.bootstrap_operation_id
                && proof.tenant_id == *request.tenant.tenant_id()
                && proof.tenant_display_name == request.tenant.display_name(),
        )
    }

    fn matches_deployment_proof(
        &self,
        proof: &ConfiguredDeploymentInstallationProof,
    ) -> Result<bool, InstallationRepositoryError> {
        let current = self.deployment_proof()?;
        Ok(
            current.installation_authority_sha256 == proof.installation_authority_sha256
                && current.bootstrap_operation_id == proof.bootstrap_operation_id
                && current.tenant_id == proof.tenant_id
                && current.tenant_display_name == proof.tenant_display_name
                && current.bootstrap_audit_event_id == proof.bootstrap_audit_event_id
                && current.configured_at_ms == proof.configured_at_ms
                && current.installation_revision == proof.installation_revision,
        )
    }
}

async fn validate_deployment_installation_evidence(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), InstallationRepositoryError> {
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM installation_state AS installation
            JOIN tenants AS tenant
              ON tenant.id=installation.configured_tenant_id
             AND tenant.display_name=installation.tenant_display_name
            JOIN security_audit_events AS audit
              ON audit.event_id=installation.deployment_bootstrap_audit_event_id
            WHERE installation.singleton=TRUE
              AND installation.state='configured'
              AND installation.configuration_mode='deployment'
              AND installation.configured_tenant_id=installation.tenant_id
              AND audit.tenant_id=installation.configured_tenant_id
              AND audit.occurred_at_ms=installation.configured_at_ms
              AND audit.actor_kind='system'
              AND audit.actor_principal_id IS NULL
              AND audit.actor_session_id IS NULL
              AND audit.authorization_revision IS NULL
              AND audit.action=$1
              AND audit.outcome='succeeded'
              AND audit.resource_kind=$2
              AND audit.resource_id=$3
              AND audit.request_id=
                  installation.deployment_bootstrap_operation_id::text
        )
        ",
    )
    .bind(DEPLOYMENT_INSTALLATION_AUDIT_ACTION)
    .bind(INSTALLATION_RESOURCE_KIND)
    .bind(INSTALLATION_RESOURCE_ID)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    if !exact {
        return Err(InstallationRepositoryError::CorruptData);
    }
    Ok(())
}

async fn insert_installation_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &InstallationTenant,
    created_at_ms: i64,
) -> Result<bool, InstallationRepositoryError> {
    // Installation is rare. This table lock closes adoption races with every
    // ordinary tenant writer, including writers outside installation setup.
    sqlx::query("LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?;
    let collision: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id=$1 OR display_name=$2)")
            .bind(tenant.tenant_id().as_str())
            .bind(tenant.display_name())
            .fetch_one(&mut **transaction)
            .await
            .map_err(map_database_error)?;
    if collision {
        return Ok(false);
    }
    sqlx::query(
        r"
        INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms)
        VALUES ($1,$2,$3,$3)
        ",
    )
    .bind(tenant.tenant_id().as_str())
    .bind(tenant.display_name())
    .bind(created_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(true)
}

async fn append_deployment_installation_audit(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ConfigureDeploymentInstallation,
    audit_event_id: Uuid,
    occurred_at_ms: i64,
) -> Result<(), InstallationRepositoryError> {
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id,tenant_id,occurred_at_ms,actor_kind,action,outcome,
            resource_kind,resource_id,request_id
        ) VALUES ($1,$2,$3,'system',$4,'succeeded',$5,$6,$7)
        ",
    )
    .bind(audit_event_id)
    .bind(request.tenant.tenant_id().as_str())
    .bind(occurred_at_ms)
    .bind(DEPLOYMENT_INSTALLATION_AUDIT_ACTION)
    .bind(INSTALLATION_RESOURCE_KIND)
    .bind(INSTALLATION_RESOURCE_ID)
    .bind(request.bootstrap_operation_id.hyphenated().to_string())
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

async fn configure_deployment_installation(
    pool: &PgPool,
    request: ConfigureDeploymentInstallation,
) -> Result<ConfigureDeploymentInstallationOutcome, InstallationRepositoryError> {
    let mut transaction = pool.begin().await.map_err(map_database_error)?;
    let row = lock_row(&mut transaction).await?;
    if row.is_configured_deployment()? {
        validate_deployment_installation_evidence(&mut transaction).await?;
        if !row.matches_deployment_request(&request)? {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(ConfigureDeploymentInstallationOutcome::Conflict);
        }
        let proof = row.deployment_proof()?;
        transaction.commit().await.map_err(map_database_error)?;
        return Ok(ConfigureDeploymentInstallationOutcome::Replayed(proof));
    }
    match row.state()? {
        InstallationState::Configured { .. }
        | InstallationState::Armed { .. }
        | InstallationState::LoginBound { .. } => {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(ConfigureDeploymentInstallationOutcome::Conflict);
        }
        InstallationState::Unconfigured { .. } => {}
    }
    let configured_at_ms = database_time_milliseconds(&mut transaction)
        .await
        .map_err(map_database_error)?;
    if !insert_installation_tenant(&mut transaction, &request.tenant, configured_at_ms).await? {
        transaction.commit().await.map_err(map_database_error)?;
        return Ok(ConfigureDeploymentInstallationOutcome::Conflict);
    }
    let audit_event_id = Uuid::new_v4();
    append_deployment_installation_audit(
        &mut transaction,
        &request,
        audit_event_id,
        configured_at_ms,
    )
    .await?;
    let current_revision = row.revision()?;
    let next_revision = next_revision(current_revision)?;
    let updated = sqlx::query(
        r"
        UPDATE installation_state
        SET state='configured',configuration_mode='deployment',
            tenant_id=$1,tenant_display_name=$2,configured_tenant_id=$1,
            configured_at_ms=$3,deployment_authority_sha256=$4,
            deployment_bootstrap_operation_id=$5,
            deployment_bootstrap_audit_event_id=$6,
            updated_at_ms=$3,revision=revision+1
        WHERE singleton=TRUE AND state='unconfigured'
          AND configuration_mode IS NULL AND revision=$7
        ",
    )
    .bind(request.tenant.tenant_id().as_str())
    .bind(request.tenant.display_name())
    .bind(configured_at_ms)
    .bind(request.installation_authority_sha256.as_slice())
    .bind(request.bootstrap_operation_id)
    .bind(audit_event_id)
    .bind(revision_to_i64(current_revision)?)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_error)?;
    if updated.rows_affected() != 1 {
        return Err(InstallationRepositoryError::CorruptData);
    }
    validate_deployment_installation_evidence(&mut transaction).await?;
    let proof = ConfiguredDeploymentInstallationProof {
        installation_authority_sha256: request.installation_authority_sha256,
        bootstrap_operation_id: request.bootstrap_operation_id,
        tenant_id: request.tenant.tenant_id().clone(),
        tenant_display_name: request.tenant.display_name().to_owned(),
        bootstrap_audit_event_id: audit_event_id,
        configured_at_ms,
        installation_revision: next_revision,
    };
    transaction.commit().await.map_err(map_database_error)?;
    Ok(ConfigureDeploymentInstallationOutcome::Applied(proof))
}

pub(crate) async fn revalidate_configured_deployment_installation(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &ConfiguredDeploymentInstallationProof,
) -> Result<(), InstallationRepositoryError> {
    let row = lock_row(transaction).await?;
    if !row.is_configured_deployment()? || !row.matches_deployment_proof(proof)? {
        return Err(InstallationRepositoryError::InvalidRequest);
    }
    validate_deployment_installation_evidence(transaction).await
}

async fn bind_login_row(
    transaction: &mut Transaction<'_, Postgres>,
    login_id: Uuid,
    now_ms: i64,
    expected_revision: InstallationRevision,
) -> Result<u64, InstallationRepositoryError> {
    Ok(sqlx::query(
        r"
        UPDATE installation_state
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
        Box::pin(async move { load_row(&self.authority.pool).await?.state() })
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
            let mut transaction = self
                .authority
                .pool
                .begin()
                .await
                .map_err(map_database_error)?;
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
                    let exact = row.tenant_id()?.as_str() == tenant.tenant_id().as_str()
                        && row.tenant_display_name.as_deref() == Some(tenant.display_name())
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
                UPDATE installation_state
                SET state='pending', configuration_mode='human',
                    bootstrap_token_hash=$1,
                    bootstrap_hash_key_id=$2, expected_provider_id=$3,
                    expected_provider_subject=$4, challenge_expires_at_ms=$5,
                    tenant_id=$6, tenant_display_name=$7,
                    setup_transaction_id=NULL, configured_tenant_id=NULL,
                    configured_principal_id=NULL, configured_at_ms=NULL,
                    deployment_authority_sha256=NULL,
                    deployment_bootstrap_operation_id=NULL,
                    deployment_bootstrap_audit_event_id=NULL,
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
            let mut transaction = self
                .authority
                .pool
                .begin()
                .await
                .map_err(map_database_error)?;
            let row = lock_row(&mut transaction).await?;
            let state = row.state()?;
            match &state {
                InstallationState::Unconfigured { .. } => {
                    return Err(InstallationRepositoryError::NotArmed);
                }
                InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::AlreadyConfigured);
                }
                InstallationState::Armed { .. } | InstallationState::LoginBound { .. } => {}
            }
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
            match &state {
                InstallationState::Armed { expires_at, .. }
                | InstallationState::LoginBound { expires_at, .. }
                    if *expires_at <= database_time =>
                {
                    return Err(InstallationRepositoryError::Expired);
                }
                InstallationState::Armed { .. } | InstallationState::LoginBound { .. } => {}
                InstallationState::Unconfigured { .. } | InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::CorruptData);
                }
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
            let mut transaction = self
                .authority
                .pool
                .begin()
                .await
                .map_err(map_database_error)?;
            let row = lock_row(&mut transaction).await?;
            match row.state()? {
                InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::AlreadyConfigured);
                }
                InstallationState::Unconfigured { .. } | InstallationState::Armed { .. } => {
                    return Err(InstallationRepositoryError::NotArmed);
                }
                InstallationState::LoginBound { .. } => {}
            }
            if row.revision()? != expected_revision {
                return Err(InstallationRepositoryError::VersionConflict);
            }
            if row.tenant_id()?.as_str() != tenant.tenant_id().as_str()
                || row.tenant_display_name.as_deref() != Some(tenant.display_name())
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
                InstallationState::Unconfigured { .. }
                | InstallationState::Armed { .. }
                | InstallationState::Configured { .. } => {
                    return Err(InstallationRepositoryError::CorruptData);
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
            if stored_tenant_display_name != tenant.display_name() {
                if stored_tenant_display_name != tenant.tenant_id().as_str() {
                    return Err(InstallationRepositoryError::IdentityConflict);
                }
                let claimed = sqlx::query(
                    r"
                    UPDATE tenants
                    SET display_name=$2, updated_at_ms=$3
                    WHERE id=$1 AND display_name=id
                    ",
                )
                .bind(tenant.tenant_id().as_str())
                .bind(tenant.display_name())
                .bind(now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(map_database_error)?;
                if claimed.rows_affected() != 1 {
                    return Err(InstallationRepositoryError::IdentityConflict);
                }
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
                UPDATE installation_state
                SET state='configured',configuration_mode='human',
                    bootstrap_token_hash=NULL,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment_tenant(display_name: &str) -> InstallationTenant {
        InstallationTenant::new(
            TenantId::new("local-installation").expect("tenant ID"),
            display_name,
        )
        .expect("installation tenant")
    }

    #[test]
    fn deployment_request_accepts_and_redacts_prederived_authority_digest() {
        let operation_id = Uuid::new_v4();
        let request = ConfigureDeploymentInstallation::new(
            [1; 32],
            operation_id,
            deployment_tenant("Local installation"),
        )
        .expect("deployment request");
        let replay = ConfigureDeploymentInstallation::new(
            [1; 32],
            operation_id,
            deployment_tenant("Local installation"),
        )
        .expect("deployment replay");
        let other_source = ConfigureDeploymentInstallation::new(
            [2; 32],
            operation_id,
            deployment_tenant("Local installation"),
        )
        .expect("other deployment source");

        assert_eq!(request.installation_authority_sha256, [1; 32]);
        assert_eq!(
            request.installation_authority_sha256,
            replay.installation_authority_sha256
        );
        assert_ne!(
            request.installation_authority_sha256,
            other_source.installation_authority_sha256
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains(&format!("{:?}", [1_u8; 32])));
        assert!(!debug.contains("installation_authority_sha256"));
    }

    #[test]
    fn deployment_request_rejects_zero_and_nil_authority_identity() {
        assert!(
            ConfigureDeploymentInstallation::new(
                [0; 32],
                Uuid::new_v4(),
                deployment_tenant("Local installation"),
            )
            .is_err()
        );
        assert!(
            ConfigureDeploymentInstallation::new(
                [1; 32],
                Uuid::nil(),
                deployment_tenant("Local installation"),
            )
            .is_err()
        );
    }
}
