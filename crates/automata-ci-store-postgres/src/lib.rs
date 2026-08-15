#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `PostgreSQL` implementation of Automata's durable store ports.

use std::{fmt, net::IpAddr, str::FromStr as _, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::authorization::{OutputVisibility, SecretExposureClass};
use automata_ci_control::{
    adapter_spi::{
        AcquireLease, AttemptSnapshot, ConcludeQueuedAttempt, InternalAttemptRepository,
        QueuedAttempt, TenantAttemptQuery, TransitionAttempt,
    },
    attempt::RenewLease,
};
use automata_ci_core::{
    AttemptId, AttemptNumber, FencingToken, IdentifierError, JobAuthorityProfile, JobId,
    JobLifecycle, Lease, LeaseGuard, LeaseId, RunnerId, RunnerSessionId, UnixMillis,
};
use automata_ci_key_management::{EnvelopeCodec, KeyEncryptionProvider, KeyPurpose};
use sqlx::{
    PgConnection, PgPool, Row as _,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use thiserror::Error;
use uuid::Uuid;

use crate::migration::MIGRATOR;
use automata_ci_store::{
    AttemptAssignment, AttemptSnapshotError, AttemptStoreError, RunnerGeneration,
    RunnerSessionFence, SessionEpoch, StableRunnerSlot, TenantScope,
};

mod migration;
#[cfg(test)]
mod migration_layout_tests;
#[cfg(test)]
mod schema_bindings_tests;

mod admission;
mod conformance;
mod durable_schema;
mod g1;
mod github_checks;
mod github_job_runtime_authority;
mod github_oidc;
mod github_provider_manifest;
mod github_schedule;
mod github_service_authority;
mod github_subject_evidence;
mod live_log_ticket;
mod log_notifications;
mod logical_activation;
mod logical_activation_preparation;
mod logical_graph;
mod logical_instance_result;
mod logical_job_result;
mod logical_materialization;
mod logical_orchestration;
mod logical_run_finalization;
mod logical_work_selection;
mod maintenance;
mod managed_secret_authority;
mod observability;
mod protected_environment;
mod provider_delivery;
mod publication;
mod reusable_workflow_admission;
mod reusable_workflow_runtime;
mod runner_capability_admission;
mod runtime_authority;
mod secret_custody;
mod secret_management;
mod server_cancellation_terminal;
mod web;
mod workflow_rerun;
mod workflow_runtime_policy;

pub use github_oidc::{
    PostgresGithubOidcAuthorityRepository, PostgresGithubOidcIssuanceRepository,
};
pub use live_log_ticket::PostgresLiveLogTicketRepository;
pub use log_notifications::PostgresLogCommitListener;
pub use secret_custody::PostgresSecretCustodyRepository;
pub use secret_management::PostgresSecretManagementRepository;

/// Failures specific to configuring or migrating the `PostgreSQL` adapter.
///
/// Repository operations use the backend-neutral [`AttemptStoreError`]
/// instead. This type is intentionally limited to concrete adapter lifecycle
/// APIs where exposing the `PostgreSQL` driver as an error source is useful.
#[derive(Debug, Error)]
pub enum PostgresStoreError {
    /// The connection URL or pool configuration is invalid.
    #[error("PostgreSQL connection configuration is invalid")]
    InvalidConfiguration,
    /// Plaintext transport was requested for a non-local endpoint.
    #[error("plaintext PostgreSQL is restricted to a local socket or literal loopback address")]
    InsecureTransport,
    /// Establishing the configured database pool failed.
    #[error("failed to connect to PostgreSQL")]
    Connection(#[source] sqlx::Error),
    /// Applying the embedded schema migrations failed.
    #[error("failed to migrate PostgreSQL")]
    Migration(#[source] sqlx::migrate::MigrateError),
}

/// Fail-closed transport policy for a `PostgreSQL` connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresTransportSecurity {
    /// Require TLS with both certificate-chain and hostname verification.
    VerifyFull,
    /// Explicit local-development exception that disables TLS.
    ///
    /// This mode accepts only a Unix-domain socket or a literal loopback IP
    /// address. Hostnames such as `localhost` are deliberately rejected.
    LoopbackPlaintext,
}

const RUNNER_COMMAND_ENCRYPTION_PURPOSE: &str = "control-plane/runner-command:v1";
const RUNNER_RPC_RESPONSE_ENCRYPTION_PURPOSE: &str = "control-plane/runner-rpc-response:v1";

fn pg_bigint(value: u64) -> i64 {
    i64::try_from(value).expect("validated durable identifier fits PostgreSQL BIGINT")
}

/// Immutable safety fields written by current admission or copied by retry.
///
/// Standard execution requires a Results runtime authority, and the GitHub
/// execution context exposes its bearer to user code as
/// `ACTIONS_RUNTIME_TOKEN`. Standard attempts are
/// therefore readable-secret. Only a fully validated credential-free `JobIR` may
/// admit a secretless logical attempt. Attempts persist runner-redacted logs,
/// while readable-secret attempts retain a private visibility ceiling. Retries
/// must reproduce the canonical snapshot exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentAttemptOutputSafety {
    secret_exposure: SecretExposureClass,
    raw_log_disposition: &'static str,
    requested_log_visibility: OutputVisibility,
    effective_log_visibility: OutputVisibility,
    output_safety_reason: &'static str,
    output_safety_schema: i32,
}

impl CurrentAttemptOutputSafety {
    pub(crate) fn readable(requested_log_visibility: &str) -> Option<Self> {
        Self::with_exposure(
            SecretExposureClass::ReadableSecret,
            requested_log_visibility,
        )
    }

    pub(crate) fn for_authority_profile(
        authority_profile: JobAuthorityProfile,
        requested_log_visibility: &str,
    ) -> Option<Self> {
        let secret_exposure = match authority_profile {
            JobAuthorityProfile::Standard => SecretExposureClass::ReadableSecret,
            JobAuthorityProfile::CredentialFree => SecretExposureClass::Secretless,
        };
        Self::with_exposure(secret_exposure, requested_log_visibility)
    }

    pub(crate) fn from_durable(
        secret_exposure: &str,
        raw_log_disposition: &str,
        requested_log_visibility: &str,
        effective_log_visibility: &str,
        output_safety_reason: &str,
        output_safety_schema: i32,
    ) -> Option<Self> {
        let secret_exposure = parse_secret_exposure(secret_exposure)?;
        let raw_log_disposition = parse_raw_log_disposition(raw_log_disposition)?;
        let snapshot = Self {
            secret_exposure,
            raw_log_disposition,
            requested_log_visibility: parse_output_visibility(requested_log_visibility)?,
            effective_log_visibility: parse_output_visibility(effective_log_visibility)?,
            output_safety_reason: parse_output_safety_reason(output_safety_reason)?,
            output_safety_schema,
        };
        (valid_raw_log_policy(secret_exposure, raw_log_disposition, output_safety_schema)
            && snapshot.effective_log_visibility <= snapshot.requested_log_visibility
            && (!matches!(
                snapshot.secret_exposure,
                SecretExposureClass::ReadableSecret
            ) || matches!(snapshot.effective_log_visibility, OutputVisibility::Private)))
        .then_some(snapshot)
    }

    pub(crate) const fn secret_exposure_class(self) -> &'static str {
        match self.secret_exposure {
            SecretExposureClass::Secretless => "secretless",
            SecretExposureClass::CapabilityOnly => "capability_only",
            SecretExposureClass::ReadableSecret => "readable_secret",
        }
    }

    pub(crate) const fn raw_log_disposition(self) -> &'static str {
        self.raw_log_disposition
    }

    pub(crate) const fn requested_log_visibility(self) -> &'static str {
        output_visibility_name(self.requested_log_visibility)
    }

    pub(crate) const fn effective_log_visibility(self) -> &'static str {
        output_visibility_name(self.effective_log_visibility)
    }

    pub(crate) const fn output_safety_reason(self) -> &'static str {
        self.output_safety_reason
    }

    pub(crate) const fn output_safety_schema(self) -> i32 {
        self.output_safety_schema
    }

    pub(crate) fn supports_current_authority_profile(self) -> bool {
        let profile = match self.secret_exposure {
            SecretExposureClass::Secretless => JobAuthorityProfile::CredentialFree,
            SecretExposureClass::ReadableSecret => JobAuthorityProfile::Standard,
            SecretExposureClass::CapabilityOnly => return false,
        };
        let Some(current) = Self::for_authority_profile(profile, self.requested_log_visibility())
        else {
            return false;
        };
        self == current
    }

    fn with_exposure(
        secret_exposure: SecretExposureClass,
        requested_log_visibility: &str,
    ) -> Option<Self> {
        let requested_log_visibility = parse_output_visibility(requested_log_visibility)?;
        let readable_secret = matches!(secret_exposure, SecretExposureClass::ReadableSecret);
        Some(Self {
            secret_exposure,
            raw_log_disposition: "persist",
            requested_log_visibility,
            effective_log_visibility: if readable_secret {
                OutputVisibility::Private
            } else {
                requested_log_visibility
            },
            output_safety_reason: if readable_secret
                && !matches!(requested_log_visibility, OutputVisibility::Private)
            {
                "secret_exposure"
            } else {
                "repository_policy"
            },
            output_safety_schema: automata_ci_store::HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA,
        })
    }
}

const fn parse_raw_log_disposition(value: &str) -> Option<&'static str> {
    match value.as_bytes() {
        b"persist" => Some("persist"),
        _ => None,
    }
}

const fn valid_raw_log_policy(
    exposure: SecretExposureClass,
    disposition: &str,
    schema: i32,
) -> bool {
    automata_ci_store::human_output_publication_safety_schema_is_current(schema)
        && matches!(
            exposure,
            SecretExposureClass::Secretless
                | SecretExposureClass::CapabilityOnly
                | SecretExposureClass::ReadableSecret
        )
        && matches!(disposition.as_bytes(), b"persist")
}

const fn parse_output_visibility(value: &str) -> Option<OutputVisibility> {
    match value.as_bytes() {
        b"private" => Some(OutputVisibility::Private),
        b"authenticated" => Some(OutputVisibility::Authenticated),
        b"public" => Some(OutputVisibility::Public),
        _ => None,
    }
}

const fn output_visibility_name(value: OutputVisibility) -> &'static str {
    match value {
        OutputVisibility::Private => "private",
        OutputVisibility::Authenticated => "authenticated",
        OutputVisibility::Public => "public",
    }
}

const fn parse_secret_exposure(value: &str) -> Option<SecretExposureClass> {
    match value.as_bytes() {
        b"secretless" => Some(SecretExposureClass::Secretless),
        b"capability_only" => Some(SecretExposureClass::CapabilityOnly),
        b"readable_secret" => Some(SecretExposureClass::ReadableSecret),
        _ => None,
    }
}

const fn parse_output_safety_reason(value: &str) -> Option<&'static str> {
    match value.as_bytes() {
        b"repository_policy" => Some("repository_policy"),
        b"secret_exposure" => Some("secret_exposure"),
        _ => None,
    }
}

#[cfg(test)]
mod attempt_output_safety_tests {
    use automata_ci_core::JobAuthorityProfile;

    use super::CurrentAttemptOutputSafety;

    #[test]
    fn current_readable_snapshot_closes_every_requested_audience() {
        for (requested, reason) in [
            ("private", "repository_policy"),
            ("authenticated", "secret_exposure"),
            ("public", "secret_exposure"),
        ] {
            let snapshot = CurrentAttemptOutputSafety::readable(requested)
                .expect("closed publication audience");
            assert_eq!(snapshot.secret_exposure_class(), "readable_secret");
            assert_eq!(snapshot.raw_log_disposition(), "persist");
            assert_eq!(snapshot.requested_log_visibility(), requested);
            assert_eq!(snapshot.effective_log_visibility(), "private");
            assert_eq!(snapshot.output_safety_reason(), reason);
            assert_eq!(snapshot.output_safety_schema(), 1);
        }
        assert!(CurrentAttemptOutputSafety::readable("unknown").is_none());

        let credential_free = CurrentAttemptOutputSafety::for_authority_profile(
            JobAuthorityProfile::CredentialFree,
            "public",
        )
        .expect("credential-free public snapshot");
        assert_eq!(credential_free.secret_exposure_class(), "secretless");
        assert_eq!(credential_free.raw_log_disposition(), "persist");
        assert_eq!(credential_free.effective_log_visibility(), "public");
        assert_eq!(credential_free.output_safety_reason(), "repository_policy");
    }

    #[test]
    fn durable_snapshot_accepts_only_the_canonical_schema() {
        let secretless = CurrentAttemptOutputSafety::from_durable(
            "secretless",
            "persist",
            "public",
            "public",
            "repository_policy",
            1,
        )
        .expect("canonical secretless snapshot");
        assert_eq!(secretless.secret_exposure_class(), "secretless");
        assert_eq!(secretless.output_safety_schema(), 1);
        let current = CurrentAttemptOutputSafety::from_durable(
            "readable_secret",
            "persist",
            "public",
            "private",
            "secret_exposure",
            1,
        )
        .expect("current readable-secret snapshot");
        assert!(current.supports_current_authority_profile());
        assert!(
            CurrentAttemptOutputSafety::from_durable(
                "readable_secret",
                "persist",
                "public",
                "private",
                "secret_exposure",
                2,
            )
            .is_none()
        );
        assert!(
            CurrentAttemptOutputSafety::from_durable(
                "secretless",
                "invalid",
                "public",
                "private",
                "secret_exposure",
                1,
            )
            .is_none()
        );
        assert!(
            CurrentAttemptOutputSafety::from_durable(
                "secretless",
                "persist",
                "private",
                "public",
                "repository_policy",
                1,
            )
            .is_none()
        );
    }
}

/// Clone-safe encryption configuration shared by all runner payload paths.
#[derive(Clone)]
pub(crate) struct RunnerPayloadEncryption {
    pub(crate) codec: Arc<EnvelopeCodec>,
    pub(crate) command_purpose: KeyPurpose,
    pub(crate) response_purpose: KeyPurpose,
}

impl RunnerPayloadEncryption {
    fn new(provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            codec: Arc::new(EnvelopeCodec::new(provider)),
            command_purpose: KeyPurpose::new(RUNNER_COMMAND_ENCRYPTION_PURPOSE)
                .expect("the runner command encryption purpose is valid"),
            response_purpose: KeyPurpose::new(RUNNER_RPC_RESPONSE_ENCRYPTION_PURPOSE)
                .expect("the runner RPC response encryption purpose is valid"),
        }
    }
}

impl fmt::Debug for RunnerPayloadEncryption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerPayloadEncryption")
            .field("command_purpose", &self.command_purpose)
            .field("response_purpose", &self.response_purpose)
            .field("codec", &"[CONFIGURED]")
            .finish_non_exhaustive()
    }
}

/// Concrete `PostgreSQL` implementation of the CI persistence contracts.
#[derive(Clone, Debug)]
pub struct PostgresStore {
    pool: PgPool,
    pub(crate) runner_payload_encryption: Option<RunnerPayloadEncryption>,
}

impl PostgresStore {
    /// Connects to `PostgreSQL` with a bounded pool and explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL or pool bound is invalid, a plaintext policy
    /// targets anything other than a local socket or literal loopback address,
    /// or `PostgreSQL` cannot be reached.
    pub async fn connect(
        database_url: &str,
        maximum_connections: u32,
        transport_security: PostgresTransportSecurity,
    ) -> Result<Self, PostgresStoreError> {
        if maximum_connections == 0 {
            return Err(PostgresStoreError::InvalidConfiguration);
        }
        let options = connection_options(database_url, transport_security)?;
        let pool = PgPoolOptions::new()
            .max_connections(maximum_connections)
            .connect_with(options)
            .await
            .map_err(PostgresStoreError::Connection)?;
        Ok(Self {
            pool,
            runner_payload_encryption: None,
        })
    }

    /// Creates the concrete adapter from an existing `sqlx` `PostgreSQL`
    /// pool. This is an adapter-specific integration hook, not a portable
    /// storage port.
    #[must_use]
    pub fn from_postgres_pool(pool: PgPool) -> Self {
        Self {
            pool,
            runner_payload_encryption: None,
        }
    }

    /// Configures authenticated envelope encryption for durable runner command
    /// and RPC response payloads.
    ///
    /// The provider may be a local keyring, KMS, HSM, or transit service. G1
    /// payload reads and writes fail closed until this builder is applied;
    /// migration and payload-independent repository operations remain usable.
    #[must_use]
    pub fn with_runner_payload_encryption(
        mut self,
        provider: Arc<dyn KeyEncryptionProvider>,
    ) -> Self {
        self.runner_payload_encryption = Some(RunnerPayloadEncryption::new(provider));
        self
    }

    pub(crate) fn require_runner_payload_encryption(
        &self,
    ) -> Result<&RunnerPayloadEncryption, automata_ci_store::StoreError> {
        self.runner_payload_encryption
            .as_ref()
            .ok_or(automata_ci_store::StoreError::RunnerPayloadEncryptionUnavailable)
    }

    /// Returns the adapter's raw `sqlx` `PostgreSQL` pool for concrete
    /// integration and migration tests. Portable callers should depend on
    /// [`InternalAttemptRepository`] or [`TenantAttemptQuery`] instead.
    #[must_use]
    pub const fn postgres_pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies all embedded migrations under `PostgreSQL`'s migration lock.
    ///
    /// # Errors
    ///
    /// Returns an error if a migration cannot acquire its lock or commit.
    pub async fn migrate(&self) -> Result<(), PostgresStoreError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(PostgresStoreError::Migration)?;
        Ok(())
    }

    async fn snapshot(&self, attempt_id: AttemptId) -> Result<AttemptSnapshot, AttemptStoreError> {
        let row = sqlx::query(
            r"
            SELECT id, job_id, attempt_number, lifecycle, fencing_token,
                   lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
                   runner_session_id, runner_session_epoch, runner_generation,
                   runner_slot,
                   lease_failures, queued_at_ms, changed_at_ms
            FROM job_attempts
            WHERE id = $1
            ",
        )
        .bind(attempt_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(AttemptStoreError::NotFound(attempt_id))?;

        decode_snapshot(&row)
    }
}

fn connection_options(
    database_url: &str,
    transport_security: PostgresTransportSecurity,
) -> Result<PgConnectOptions, PostgresStoreError> {
    let scheme = database_url
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .ok_or(PostgresStoreError::InvalidConfiguration)?;
    if !scheme.eq_ignore_ascii_case("postgres") && !scheme.eq_ignore_ascii_case("postgresql") {
        return Err(PostgresStoreError::InvalidConfiguration);
    }
    let options = PgConnectOptions::from_str(database_url)
        .map_err(|_| PostgresStoreError::InvalidConfiguration)?;
    match transport_security {
        PostgresTransportSecurity::VerifyFull => Ok(options.ssl_mode(PgSslMode::VerifyFull)),
        PostgresTransportSecurity::LoopbackPlaintext => {
            let host = options.get_host();
            let local_socket = options.get_socket().is_some() || host.starts_with('/');
            let ip_literal = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            let literal_loopback = ip_literal
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
            if !local_socket && !literal_loopback {
                return Err(PostgresStoreError::InsecureTransport);
            }
            Ok(options.ssl_mode(PgSslMode::Disable))
        }
    }
}

#[cfg(test)]
mod transport_security_tests {
    use super::*;

    #[test]
    fn verified_transport_overrides_fallback_modes() {
        let options = connection_options(
            "postgresql://user:secret@database.example.test/automata?sslmode=disable",
            PostgresTransportSecurity::VerifyFull,
        )
        .expect("verified transport configuration");
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
    }

    #[test]
    fn plaintext_transport_accepts_only_effective_local_targets() {
        for url in [
            "postgresql://user@127.0.0.1/automata?sslmode=prefer",
            "postgresql://user@[::1]/automata?sslmode=require",
            "postgresql://user@%2Fvar%2Frun%2Fpostgresql/automata",
        ] {
            let options = connection_options(url, PostgresTransportSecurity::LoopbackPlaintext)
                .unwrap_or_else(|error| panic!("explicit local target {url}: {error}"));
            assert!(matches!(options.get_ssl_mode(), PgSslMode::Disable));
        }

        for url in [
            "postgresql://user@localhost/automata",
            "postgresql://user@database.example.test/automata",
            "postgresql://user@127.0.0.1/automata?host=database.example.test",
        ] {
            assert!(matches!(
                connection_options(url, PostgresTransportSecurity::LoopbackPlaintext),
                Err(PostgresStoreError::InsecureTransport)
            ));
        }
    }

    #[test]
    fn non_postgres_urls_are_rejected_without_echoing_the_input() {
        let error = connection_options(
            "https://user:unique-secret@example.test/automata",
            PostgresTransportSecurity::VerifyFull,
        )
        .expect_err("wrong URL scheme");
        assert!(matches!(error, PostgresStoreError::InvalidConfiguration));
        assert!(!error.to_string().contains("unique-secret"));
    }
}

async fn output_safety_for_queued_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    attempt: QueuedAttempt,
) -> Result<(CurrentAttemptOutputSafety, i64), AttemptStoreError> {
    let job = sqlx::query(
        r"
        SELECT run.requested_log_visibility
        FROM jobs AS job
        JOIN workflow_runs AS run ON run.id = job.run_id
        WHERE job.id = $1
        FOR UPDATE OF job
        ",
    )
    .bind(attempt.job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let job = job.ok_or_else(|| {
        AttemptStoreError::corrupt_data("queued attempt references a missing workflow job")
    })?;
    let requested_log_visibility = job
        .try_get::<String, _>("requested_log_visibility")
        .map_err(operation_error)?;
    let prior = sqlx::query(
        r"
            SELECT secret_exposure_class, raw_log_disposition,
                   requested_log_visibility, effective_log_visibility,
                   output_safety_reason, output_safety_schema,
                   classified_at_ms
            FROM job_attempts
            WHERE job_id = $1 AND attempt_number = 1
            ",
    )
    .bind(attempt.job_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = prior else {
        let safety =
            CurrentAttemptOutputSafety::readable(&requested_log_visibility).ok_or_else(|| {
                AttemptStoreError::corrupt_data(
                    "workflow run log publication snapshot is malformed",
                )
            })?;
        return Ok((safety, attempt.queued_at().get()));
    };

    let durable_requested: String = row
        .try_get("requested_log_visibility")
        .map_err(operation_error)?;
    let classified_at: i64 = row.try_get("classified_at_ms").map_err(operation_error)?;
    let safety = CurrentAttemptOutputSafety::from_durable(
        &row.try_get::<String, _>("secret_exposure_class")
            .map_err(operation_error)?,
        &row.try_get::<String, _>("raw_log_disposition")
            .map_err(operation_error)?,
        &durable_requested,
        &row.try_get::<String, _>("effective_log_visibility")
            .map_err(operation_error)?,
        &row.try_get::<String, _>("output_safety_reason")
            .map_err(operation_error)?,
        row.try_get("output_safety_schema")
            .map_err(operation_error)?,
    )
    .filter(|snapshot| {
        snapshot.requested_log_visibility() == requested_log_visibility.as_str()
            && classified_at >= 0
    })
    .ok_or_else(|| {
        AttemptStoreError::corrupt_data("prior attempt output-safety snapshot is inconsistent")
    })?;
    Ok((safety, classified_at))
}

#[async_trait]
impl InternalAttemptRepository for PostgresStore {
    async fn insert_queued(&self, attempt: QueuedAttempt) -> Result<(), AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let (safety, classified_at) =
            output_safety_for_queued_attempt(&mut transaction, attempt).await?;
        sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                lease_failures, queued_at_ms, changed_at_ms,
                secret_exposure_class, raw_log_disposition,
                requested_log_visibility, effective_log_visibility,
                output_safety_reason, output_safety_schema, classified_at_ms
            )
            VALUES (
                $1, $2, $3, 'queued', 0, 0, $4, $4,
                $5, $6, $7, $8, $9, $10, $11
            )
            ",
        )
        .bind(attempt.attempt_id().as_uuid())
        .bind(attempt.job_id().as_uuid())
        .bind(i32::try_from(attempt.attempt_number().get()).map_err(|_| {
            AttemptStoreError::corrupt_data("attempt number does not fit PostgreSQL INTEGER")
        })?)
        .bind(attempt.queued_at().get())
        .bind(safety.secret_exposure_class())
        .bind(safety.raw_log_disposition())
        .bind(safety.requested_log_visibility())
        .bind(safety.effective_log_visibility())
        .bind(safety.output_safety_reason())
        .bind(safety.output_safety_schema())
        .bind(classified_at)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        github_checks::insert_github_job_check_subject(
            &mut transaction,
            attempt.job_id(),
            attempt.attempt_id(),
            attempt.queued_at(),
        )
        .await
        .map_err(github_checks::GithubJobCheckInsertError::into_attempt_error)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn get_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError> {
        self.snapshot(attempt_id).await
    }

    async fn acquire_lease(&self, request: AcquireLease) -> Result<Lease, AttemptStoreError> {
        let requested_duration =
            runner_attempt_requested_duration(request.observed_at(), request.expires_at())?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_runner_attempt_read_committed(&mut transaction).await?;
        verify_live_session_and_slot(
            &mut transaction,
            request.attempt_id(),
            request.session(),
            request.slot(),
        )
        .await?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id()).await?;
        if snapshot.lifecycle() != JobLifecycle::Queued {
            return Err(AttemptStoreError::NotQueued {
                attempt_id: request.attempt_id(),
                lifecycle: snapshot.lifecycle(),
            });
        }
        verify_runner_tenant(
            &mut transaction,
            request.attempt_id(),
            snapshot.job_id(),
            request.runner_id(),
        )
        .await?;
        let database_now = runner_attempt_database_now(&mut transaction).await?;
        validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
        verify_state_time(request.attempt_id(), database_now, &snapshot)?;
        let database_expires_at = runner_attempt_database_expiry(database_now, requested_duration)?;
        let fencing_token = match snapshot.fencing_token() {
            Some(current) => current
                .checked_next()
                .map_err(|_| AttemptStoreError::FencingTokenExhausted(request.attempt_id()))?,
            None => FencingToken::new(1).map_err(identifier_error)?,
        };

        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = 'leased',
                fencing_token = $2,
                lease_id = $3,
                runner_id = $4,
                lease_issued_at_ms = $5,
                lease_expires_at_ms = $6,
                runner_session_id = $7,
                runner_session_epoch = $8,
                runner_generation = $9,
                runner_slot = $10,
                changed_at_ms = $5
            WHERE id = $1
              AND lifecycle = 'queued'
              AND changed_at_ms <= $5
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(fencing_to_i64(fencing_token)?)
        .bind(request.lease_id().as_uuid())
        .bind(request.runner_id().as_uuid())
        .bind(database_now.get())
        .bind(database_expires_at.get())
        .bind(request.session().session_id().as_uuid())
        .bind(g1::session_epoch_to_i64(request.session().session_epoch())?)
        .bind(g1::runner_generation_to_i64(
            request.session().runner_generation(),
        )?)
        .bind(i32::from(request.slot().ordinal()))
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        let lease = Lease::new(
            request.lease_id(),
            request.attempt_id(),
            request.runner_id(),
            fencing_token,
            database_now,
            database_expires_at,
        )
        .map_err(|error| {
            AttemptStoreError::corrupt_data(format!(
                "validated lease acquisition produced an invalid lease: {error}"
            ))
        })?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(lease)
    }

    async fn conclude_queued(
        &self,
        request: ConcludeQueuedAttempt,
    ) -> Result<(), AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id()).await?;
        if snapshot.lifecycle() != JobLifecycle::Queued {
            return Err(AttemptStoreError::NotQueued {
                attempt_id: request.attempt_id(),
                lifecycle: snapshot.lifecycle(),
            });
        }
        verify_state_time(request.attempt_id(), request.observed_at(), &snapshot)?;

        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = $2,
                changed_at_ms = $3
            WHERE id = $1
              AND lifecycle = 'queued'
              AND changed_at_ms <= $3
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(lifecycle_name(request.conclusion()))
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn renew_lease(&self, request: RenewLease) -> Result<Lease, AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_runner_attempt_read_committed(&mut transaction).await?;
        let issued = issue_lease_renewal_in_transaction(&mut transaction, request, None).await?;
        let lease =
            commit_database_issued_lease_renewal_in_transaction(&mut transaction, issued).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(lease)
    }

    async fn transition(&self, request: TransitionAttempt) -> Result<(), AttemptStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        verify_live_session(
            &mut transaction,
            request.attempt_id(),
            request.session(),
            SessionUse::ExistingWork,
        )
        .await?;
        let snapshot = locked_snapshot(&mut transaction, request.attempt_id()).await?;
        verify_guard(request.attempt_id(), request.guard(), &snapshot)?;
        verify_assignment(request.attempt_id(), request.session(), &snapshot)?;
        verify_mutation_time(request.attempt_id(), request.observed_at(), &snapshot)?;
        snapshot
            .lifecycle()
            .validate_transition(request.next())
            .map_err(|_| AttemptStoreError::InvalidTransition {
                attempt_id: request.attempt_id(),
                from: snapshot.lifecycle(),
                to: request.next(),
            })?;
        let next = lifecycle_name(request.next());
        let result = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = $4,
                lease_id = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN lease_id ELSE NULL END,
                runner_id = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN runner_id ELSE NULL END,
                lease_issued_at_ms = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN lease_issued_at_ms ELSE NULL END,
                lease_expires_at_ms = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN lease_expires_at_ms ELSE NULL END,
                runner_session_id = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN runner_session_id ELSE NULL END,
                runner_session_epoch = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN runner_session_epoch ELSE NULL END,
                runner_generation = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN runner_generation ELSE NULL END,
                runner_slot = CASE
                    WHEN $4 IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
                    THEN runner_slot ELSE NULL END,
                queued_at_ms = CASE WHEN $4 = 'queued' THEN $5 ELSE queued_at_ms END,
                changed_at_ms = $5
            WHERE id = $1
              AND lease_id = $2
              AND fencing_token = $3
              AND runner_id = $6
              AND runner_session_id = $7
              AND runner_session_epoch = $8
              AND runner_generation = $9
              AND changed_at_ms <= $5
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(request.guard().lease_id().as_uuid())
        .bind(fencing_to_i64(request.guard().fencing_token())?)
        .bind(next)
        .bind(request.observed_at().get())
        .bind(request.runner_id().as_uuid())
        .bind(request.session().session_id().as_uuid())
        .bind(g1::session_epoch_to_i64(request.session().session_epoch())?)
        .bind(g1::runner_generation_to_i64(
            request.session().runner_generation(),
        )?)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        require_single_update(result.rows_affected())?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn requeue_expired(
        &self,
        now: UnixMillis,
        maximum_failures: u32,
        limit: u32,
    ) -> Result<Vec<AttemptId>, AttemptStoreError> {
        if maximum_failures == 0 {
            return Err(AttemptStoreError::InvalidRetryPolicy);
        }
        let maximum_failures =
            i32::try_from(maximum_failures).map_err(|_| AttemptStoreError::InvalidRetryPolicy)?;
        let limit = i64::from(limit);
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_runner_attempt_read_committed(&mut transaction).await?;
        let admission_now = runner_attempt_database_now(&mut transaction).await?;
        validate_runner_attempt_caller_clock(now, admission_now)?;
        let candidates = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM job_attempts
            WHERE lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
              AND lease_expires_at_ms <= $1
              AND changed_at_ms <= $1
            ORDER BY lease_expires_at_ms, id
            FOR UPDATE SKIP LOCKED
            LIMIT $2
            ",
        )
        .bind(admission_now.get())
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if candidates.is_empty() {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(Vec::new());
        }
        let decision_now = runner_attempt_database_now(&mut transaction).await?;
        validate_runner_attempt_caller_clock(now, decision_now)?;
        let rows = sqlx::query(
            r"
            UPDATE job_attempts AS attempt
            SET lifecycle = CASE
                    WHEN attempt.lifecycle IN ('running', 'cancelling', 'finalizing')
                         OR attempt.lease_failures + 1 >= $2 THEN 'lost'
                    ELSE 'queued' END,
                lease_id = NULL,
                runner_id = NULL,
                lease_issued_at_ms = NULL,
                lease_expires_at_ms = NULL,
                runner_session_id = NULL,
                runner_session_epoch = NULL,
                runner_generation = NULL,
                runner_slot = NULL,
                lease_failures = attempt.lease_failures + 1,
                queued_at_ms = CASE
                    WHEN attempt.lifecycle IN ('running', 'cancelling', 'finalizing')
                         OR attempt.lease_failures + 1 >= $2 THEN attempt.queued_at_ms
                    ELSE $1 END,
                changed_at_ms = $1
            WHERE attempt.id = ANY($3)
              AND attempt.lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
              AND attempt.lease_expires_at_ms <= $1
              AND attempt.changed_at_ms <= $1
            RETURNING attempt.id
            ",
        )
        .bind(decision_now.get())
        .bind(maximum_failures)
        .bind(&candidates)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        transaction.commit().await.map_err(operation_error)?;

        rows.into_iter()
            .map(|row| {
                row.try_get::<Uuid, _>("id")
                    .map(AttemptId::from_uuid)
                    .map_err(operation_error)
            })
            .collect()
    }
}

const MAX_RUNNER_ATTEMPT_CALLER_CLOCK_SKEW_MILLIS: u64 = 60_000;

pub(crate) async fn pin_runner_attempt_read_committed(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), AttemptStoreError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

pub(crate) async fn runner_attempt_database_now(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<UnixMillis, AttemptStoreError> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(&mut **transaction)
        .await
        .map(UnixMillis::new)
        .map_err(operation_error)
}

pub(crate) fn validate_runner_attempt_caller_clock(
    caller_time: UnixMillis,
    database_time: UnixMillis,
) -> Result<(), AttemptStoreError> {
    if caller_time.get().abs_diff(database_time.get()) > MAX_RUNNER_ATTEMPT_CALLER_CLOCK_SKEW_MILLIS
    {
        return Err(AttemptStoreError::operation(std::io::Error::other(
            "runner attempt caller clock is outside the bounded skew window",
        )));
    }
    Ok(())
}

pub(crate) fn runner_attempt_requested_duration(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<i64, AttemptStoreError> {
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| duration.is_positive())
        .ok_or_else(|| AttemptStoreError::corrupt_data("invalid runner attempt lease duration"))
}

pub(crate) fn runner_attempt_database_expiry(
    database_time: UnixMillis,
    requested_duration: i64,
) -> Result<UnixMillis, AttemptStoreError> {
    database_time
        .get()
        .checked_add(requested_duration)
        .map(UnixMillis::new)
        .ok_or_else(|| AttemptStoreError::corrupt_data("runner attempt lease expiry overflowed"))
}

pub(crate) async fn issue_lease_renewal_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RenewLease,
    reported_lifecycle: Option<JobLifecycle>,
) -> Result<RenewLease, AttemptStoreError> {
    let requested_duration =
        runner_attempt_requested_duration(request.observed_at(), request.expires_at())?;
    verify_live_session(
        transaction,
        request.attempt_id(),
        request.session(),
        SessionUse::ExistingWork,
    )
    .await?;
    let snapshot = locked_snapshot(transaction, request.attempt_id()).await?;
    verify_guard(request.attempt_id(), request.guard(), &snapshot)?;
    verify_assignment(request.attempt_id(), request.session(), &snapshot)?;
    let authority_lifecycle = reported_lifecycle.unwrap_or(snapshot.lifecycle());
    let authority_evidence = if lifecycle_can_expose_runtime_authority(authority_lifecycle) {
        lock_github_runtime_authority_renewal_evidence(transaction, request).await?
    } else {
        None
    };
    let database_now = runner_attempt_database_now(transaction).await?;
    validate_runner_attempt_caller_clock(request.observed_at(), database_now)?;
    let current_expiration = snapshot
        .lease_expires_at()
        .ok_or_else(|| corrupt("active lease is missing its expiration"))?;
    if database_now >= current_expiration {
        return Err(AttemptStoreError::LeaseExpired(request.attempt_id()));
    }
    let requested_expires_at = runner_attempt_database_expiry(database_now, requested_duration)?;
    let authority_ceiling = validate_github_runtime_authority_renewal_evidence(
        transaction,
        authority_evidence,
        request,
        current_expiration,
        database_now,
    )
    .await?;
    let expires_at = authority_ceiling.map_or(requested_expires_at, |ceiling| {
        requested_expires_at.min(ceiling)
    });
    if expires_at <= database_now {
        return Err(AttemptStoreError::RuntimeAuthorityCeilingExceeded(
            request.attempt_id(),
        ));
    }
    RenewLease::new(
        request.attempt_id(),
        request.session(),
        request.guard(),
        database_now,
        expires_at,
    )
    .map_err(|error| {
        AttemptStoreError::corrupt_data(format!(
            "runtime-authority-bounded lease renewal is invalid: {error}"
        ))
    })
}

pub(crate) async fn commit_database_issued_lease_renewal_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RenewLease,
) -> Result<Lease, AttemptStoreError> {
    verify_live_session(
        transaction,
        request.attempt_id(),
        request.session(),
        SessionUse::ExistingWork,
    )
    .await?;
    let snapshot = locked_snapshot(transaction, request.attempt_id()).await?;
    verify_guard(request.attempt_id(), request.guard(), &snapshot)?;
    verify_assignment(request.attempt_id(), request.session(), &snapshot)?;
    let authority_evidence = if lifecycle_can_expose_runtime_authority(snapshot.lifecycle()) {
        lock_github_runtime_authority_renewal_evidence(transaction, request).await?
    } else {
        None
    };
    let database_now = runner_attempt_database_now(transaction).await?;
    let current_expiration = snapshot
        .lease_expires_at()
        .ok_or_else(|| corrupt("active lease is missing its expiration"))?;
    if database_now >= current_expiration || database_now >= request.expires_at() {
        return Err(AttemptStoreError::LeaseExpired(request.attempt_id()));
    }
    let authority_ceiling = validate_github_runtime_authority_renewal_evidence(
        transaction,
        authority_evidence,
        request,
        current_expiration,
        database_now,
    )
    .await?;
    if authority_ceiling.is_some_and(|ceiling| request.expires_at() > ceiling) {
        return Err(AttemptStoreError::RuntimeAuthorityCeilingExceeded(
            request.attempt_id(),
        ));
    }
    let refreshes_exact_ceiling = authority_ceiling
        .is_some_and(|ceiling| request.expires_at() == ceiling && current_expiration == ceiling);
    if request.expires_at() < current_expiration
        || (request.expires_at() == current_expiration && !refreshes_exact_ceiling)
    {
        return Err(AttemptStoreError::RenewalDoesNotExtend(
            request.attempt_id(),
        ));
    }

    if !refreshes_exact_ceiling {
        if authority_evidence.is_some() {
            record_github_runtime_authority_lease_renewal(
                transaction,
                request,
                current_expiration,
                database_now,
            )
            .await?;
        }
        update_database_issued_lease_expiration(
            transaction,
            request,
            current_expiration,
            database_now,
        )
        .await?;
    }
    let runner_id = snapshot
        .runner_id()
        .ok_or_else(|| corrupt("active lease is missing its runner"))?;
    let issued_at = snapshot
        .lease_issued_at()
        .ok_or_else(|| corrupt("active lease is missing its issuance"))?;
    Lease::new(
        request.guard().lease_id(),
        request.attempt_id(),
        runner_id,
        request.guard().fencing_token(),
        issued_at,
        request.expires_at(),
    )
    .map_err(|error| {
        AttemptStoreError::corrupt_data(format!(
            "durable renewal produced an invalid lease: {error}"
        ))
    })
}

async fn update_database_issued_lease_expiration(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RenewLease,
    previous_expires_at: UnixMillis,
    database_now: UnixMillis,
) -> Result<(), AttemptStoreError> {
    let result = sqlx::query(
        r"
        UPDATE job_attempts
        SET lease_expires_at_ms = $5,
            changed_at_ms = $6
        WHERE id = $1
          AND lease_id = $2
          AND fencing_token = $3
          AND runner_id = $4
          AND runner_session_id = $7
          AND runner_session_epoch = $8
          AND runner_generation = $9
          AND lease_expires_at_ms = $10
          AND changed_at_ms <= $6
          AND lease_expires_at_ms > $6
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_to_i64(request.guard().fencing_token())?)
    .bind(request.runner_id().as_uuid())
    .bind(request.expires_at().get())
    .bind(database_now.get())
    .bind(request.session().session_id().as_uuid())
    .bind(g1::session_epoch_to_i64(request.session().session_epoch())?)
    .bind(g1::runner_generation_to_i64(
        request.session().runner_generation(),
    )?)
    .bind(previous_expires_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    require_single_update(result.rows_affected())
}

async fn record_github_runtime_authority_lease_renewal(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RenewLease,
    previous_expires_at: UnixMillis,
    authorized_at: UnixMillis,
) -> Result<(), AttemptStoreError> {
    let result = sqlx::query(
        r"
        INSERT INTO github_runtime_authority_lease_renewal_receipts (
            attempt_id, fencing_token, lease_id, runner_id,
            runner_session_id, runner_session_epoch, runner_generation,
            previous_lease_expires_at_ms, renewed_lease_expires_at_ms,
            authorized_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fencing_to_i64(request.guard().fencing_token())?)
    .bind(request.guard().lease_id().as_uuid())
    .bind(request.runner_id().as_uuid())
    .bind(request.session().session_id().as_uuid())
    .bind(g1::session_epoch_to_i64(request.session().session_epoch())?)
    .bind(g1::runner_generation_to_i64(
        request.session().runner_generation(),
    )?)
    .bind(previous_expires_at.get())
    .bind(request.expires_at().get())
    .bind(authorized_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    require_single_update(result.rows_affected())
}

pub(crate) async fn authorize_lease_renewal_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RenewLease,
    reported_lifecycle: JobLifecycle,
) -> Result<RenewLease, AttemptStoreError> {
    issue_lease_renewal_in_transaction(transaction, request, Some(reported_lifecycle)).await
}

const fn lifecycle_can_expose_runtime_authority(lifecycle: JobLifecycle) -> bool {
    matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
    )
}

#[derive(Clone, Copy, Debug)]
struct LockedGithubRuntimeAuthorityRenewalEvidence {
    state_is_ready: bool,
    ready_at: Option<UnixMillis>,
    provider_expires_at: Option<UnixMillis>,
    exact_identity: bool,
}

async fn lock_github_runtime_authority_renewal_evidence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RenewLease,
) -> Result<Option<LockedGithubRuntimeAuthorityRenewalEvidence>, AttemptStoreError> {
    let row = sqlx::query(
        r"
        SELECT authority.state,
               authority.ready_at_ms,
               authority.provider_expires_at_ms,
               authority.lease_id = $3
                 AND authority.runner_id = $4
                 AND authority.runner_session_id = $5
                 AND authority.runner_session_epoch = $6
                 AND authority.runner_generation = $7 AS exact_identity
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
        FOR SHARE OF authority
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fencing_to_i64(request.guard().fencing_token())?)
    .bind(request.guard().lease_id().as_uuid())
    .bind(request.runner_id().as_uuid())
    .bind(request.session().session_id().as_uuid())
    .bind(g1::session_epoch_to_i64(request.session().session_epoch())?)
    .bind(g1::runner_generation_to_i64(
        request.session().runner_generation(),
    )?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(LockedGithubRuntimeAuthorityRenewalEvidence {
        state_is_ready: row.try_get::<String, _>("state").map_err(operation_error)? == "ready",
        ready_at: row
            .try_get::<Option<i64>, _>("ready_at_ms")
            .map_err(operation_error)?
            .map(UnixMillis::new),
        provider_expires_at: row
            .try_get::<Option<i64>, _>("provider_expires_at_ms")
            .map_err(operation_error)?
            .map(UnixMillis::new),
        exact_identity: row.try_get("exact_identity").map_err(operation_error)?,
    }))
}

async fn validate_github_runtime_authority_renewal_evidence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    evidence: Option<LockedGithubRuntimeAuthorityRenewalEvidence>,
    request: RenewLease,
    current_expiration: UnixMillis,
    database_now: UnixMillis,
) -> Result<Option<UnixMillis>, AttemptStoreError> {
    let Some(evidence) = evidence else {
        return Ok(None);
    };
    let ceiling = evidence.provider_expires_at.and_then(|expires_at| {
        expires_at
            .get()
            .checked_sub(automata_ci_store::GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS)
            .map(UnixMillis::new)
    });
    if !evidence.state_is_ready
        || !evidence.exact_identity
        || evidence
            .ready_at
            .is_none_or(|ready_at| ready_at > database_now)
        || ceiling.is_none_or(|ceiling| ceiling <= database_now)
    {
        return Err(AttemptStoreError::RuntimeAuthorityUnavailable(
            request.attempt_id(),
        ));
    }
    let horizon_is_tail: bool = sqlx::query_scalar(
        r"
        SELECT automata_github_runtime_authority_lease_horizon_is_tail(
            authority, $3, $4
        )
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = $1
          AND authority.fencing_token = $2
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fencing_to_i64(request.guard().fencing_token())?)
    .bind(current_expiration.get())
    .bind(database_now.get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if !horizon_is_tail {
        return Err(AttemptStoreError::RuntimeAuthorityUnavailable(
            request.attempt_id(),
        ));
    }
    Ok(ceiling)
}

#[async_trait]
impl TenantAttemptQuery for PostgresStore {
    async fn get_attempt_for_tenant(
        &self,
        tenant: &TenantScope,
        attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError> {
        let row = sqlx::query(
            r"
            SELECT attempt.id, attempt.job_id, attempt.attempt_number,
                   attempt.lifecycle, attempt.fencing_token, attempt.lease_id,
                   attempt.runner_id, attempt.lease_issued_at_ms,
                   attempt.lease_expires_at_ms, attempt.lease_failures,
                   attempt.runner_session_id, attempt.runner_session_epoch,
                   attempt.runner_generation, attempt.runner_slot,
                   attempt.queued_at_ms, attempt.changed_at_ms
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN workflow_definitions AS workflow
              ON workflow.id = run.workflow_id
             AND workflow.repository_id = run.repository_id
            JOIN repositories AS repository
              ON repository.id = workflow.repository_id
            WHERE attempt.id = $1
              AND repository.tenant_id = $2
            ",
        )
        .bind(attempt_id.as_uuid())
        .bind(tenant.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(AttemptStoreError::NotFound(attempt_id))?;

        decode_snapshot(&row)
    }
}

#[allow(clippy::too_many_lines)]
fn decode_snapshot(row: &sqlx::postgres::PgRow) -> Result<AttemptSnapshot, AttemptStoreError> {
    let attempt_id = AttemptId::from_uuid(row.try_get("id").map_err(operation_error)?);
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let attempt_number = u32::try_from(
        row.try_get::<i32, _>("attempt_number")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| AttemptNumber::new(value).ok())
    .ok_or_else(|| AttemptStoreError::corrupt_data("invalid attempt number"))?;
    let lifecycle_name: &str = row.try_get("lifecycle").map_err(operation_error)?;
    let lifecycle = parse_lifecycle(lifecycle_name)?;
    let raw_fence: i64 = row.try_get("fencing_token").map_err(operation_error)?;
    let fencing_token = if raw_fence == 0 {
        None
    } else {
        Some(decode_fencing_token(raw_fence)?)
    };
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(operation_error)?
        .map(LeaseId::from_uuid);
    let runner_id = row
        .try_get::<Option<Uuid>, _>("runner_id")
        .map_err(operation_error)?
        .map(RunnerId::from_uuid);
    let lease_issued_at = row
        .try_get::<Option<i64>, _>("lease_issued_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let lease_expires_at = row
        .try_get::<Option<i64>, _>("lease_expires_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let runner_session_id = row
        .try_get::<Option<Uuid>, _>("runner_session_id")
        .map_err(operation_error)?
        .map(RunnerSessionId::from_uuid);
    let runner_session_epoch = row
        .try_get::<Option<i64>, _>("runner_session_epoch")
        .map_err(operation_error)?;
    let runner_generation = row
        .try_get::<Option<i64>, _>("runner_generation")
        .map_err(operation_error)?;
    let runner_slot = row
        .try_get::<Option<i32>, _>("runner_slot")
        .map_err(operation_error)?;
    let lease_failures = u32::try_from(
        row.try_get::<i32, _>("lease_failures")
            .map_err(operation_error)?,
    )
    .map_err(|_| AttemptStoreError::corrupt_data("negative lease failure count"))?;
    let queued_at = UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?);
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);

    let active = match (
        lease_id,
        runner_id,
        lease_issued_at,
        lease_expires_at,
        runner_session_id,
        runner_session_epoch,
        runner_generation,
        runner_slot,
    ) {
        (None, None, None, None, None, None, None, None) => None,
        (
            Some(lease_id),
            Some(runner_id),
            Some(issued_at),
            Some(expires_at),
            Some(session_id),
            Some(raw_epoch),
            Some(raw_generation),
            Some(raw_slot),
        ) => {
            let fencing_token = fencing_token.ok_or_else(|| {
                AttemptStoreError::corrupt_data("active lease is missing its fencing token")
            })?;
            let epoch = u64::try_from(raw_epoch)
                .ok()
                .and_then(|value| SessionEpoch::new(value).ok())
                .ok_or_else(|| AttemptStoreError::corrupt_data("invalid runner session epoch"))?;
            let generation = u64::try_from(raw_generation)
                .ok()
                .and_then(|value| RunnerGeneration::new(value).ok())
                .ok_or_else(|| AttemptStoreError::corrupt_data("invalid runner generation"))?;
            let slot = u16::try_from(raw_slot)
                .ok()
                .and_then(|value| StableRunnerSlot::new(value).ok())
                .ok_or_else(|| AttemptStoreError::corrupt_data("invalid stable runner slot"))?;
            let lease = Lease::new(
                lease_id,
                attempt_id,
                runner_id,
                fencing_token,
                issued_at,
                expires_at,
            )
            .map_err(AttemptSnapshotError::InvalidLease)?;
            let assignment = AttemptAssignment::new(
                RunnerSessionFence::new(session_id, runner_id, generation, epoch),
                slot,
            );
            Some((lease, assignment))
        }
        _ => {
            return Err(AttemptStoreError::corrupt_data(
                "active lease columns are incomplete",
            ));
        }
    };

    let mut builder = AttemptSnapshot::builder(
        attempt_id,
        job_id,
        attempt_number,
        lifecycle,
        queued_at,
        changed_at,
    )
    .with_lease_failures(lease_failures);
    if let Some((active_lease, assignment)) = active {
        builder = builder.with_active_lease(active_lease, assignment);
    } else if let Some(fencing_token) = fencing_token {
        builder = builder.with_retained_fencing_token(fencing_token);
    }
    builder.build().map_err(AttemptStoreError::from)
}

async fn locked_snapshot(
    connection: &mut PgConnection,
    attempt_id: AttemptId,
) -> Result<AttemptSnapshot, AttemptStoreError> {
    let row = sqlx::query(
        r"
        SELECT id, job_id, attempt_number, lifecycle, fencing_token,
               lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
               runner_session_id, runner_session_epoch, runner_generation,
               runner_slot,
               lease_failures, queued_at_ms, changed_at_ms
        FROM job_attempts
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(connection)
    .await
    .map_err(operation_error)?
    .ok_or(AttemptStoreError::NotFound(attempt_id))?;
    decode_snapshot(&row)
}

fn verify_mutation_time(
    attempt_id: AttemptId,
    observed_at: UnixMillis,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    verify_state_time(attempt_id, observed_at, snapshot)?;
    snapshot
        .lease_issued_at()
        .ok_or_else(|| corrupt("active lease is missing its issuance"))?;
    let expires_at = snapshot
        .lease_expires_at()
        .ok_or_else(|| corrupt("active lease is missing its expiration"))?;
    if observed_at >= expires_at {
        return Err(AttemptStoreError::LeaseExpired(attempt_id));
    }
    Ok(())
}

fn verify_state_time(
    attempt_id: AttemptId,
    observed_at: UnixMillis,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    if observed_at < snapshot.changed_at() {
        return Err(AttemptStoreError::MutationPredatesState {
            attempt_id,
            observed_at,
            changed_at: snapshot.changed_at(),
        });
    }
    Ok(())
}

fn require_single_update(rows_affected: u64) -> Result<(), AttemptStoreError> {
    if rows_affected == 1 {
        return Ok(());
    }
    Err(corrupt(
        "locked attempt update did not affect exactly one row",
    ))
}

fn corrupt(message: &str) -> AttemptStoreError {
    AttemptStoreError::corrupt_data(message)
}

fn verify_guard(
    attempt_id: AttemptId,
    guard: LeaseGuard,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    if snapshot.lease_id() != Some(guard.lease_id())
        || snapshot.fencing_token() != Some(guard.fencing_token())
    {
        return Err(AttemptStoreError::FenceRejected(attempt_id));
    }
    Ok(())
}

fn verify_assignment(
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    snapshot: &AttemptSnapshot,
) -> Result<(), AttemptStoreError> {
    if snapshot.assignment().map(AttemptAssignment::session) != Some(session) {
        return Err(AttemptStoreError::RunnerRejected(attempt_id));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionUse {
    ExistingWork,
    NewWork,
}

async fn verify_live_session(
    connection: &mut PgConnection,
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    session_use: SessionUse,
) -> Result<(), AttemptStoreError> {
    let desired_state = sqlx::query_scalar::<_, String>(
        r"
        SELECT runner.desired_state
        FROM runners AS runner
        JOIN runner_sessions AS session ON session.runner_id = runner.id
        WHERE session.id = $1
          AND runner.id = $2
          AND runner.generation = $3
          AND runner.session_epoch = $4
          AND runner.status = 'online'
          AND session.runner_generation = $3
          AND session.session_epoch = $4
          AND session.disconnected_at_ms IS NULL
        FOR UPDATE OF runner, session
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(session.runner_id().as_uuid())
    .bind(g1::runner_generation_to_i64(session.runner_generation())?)
    .bind(g1::session_epoch_to_i64(session.session_epoch())?)
    .fetch_optional(connection)
    .await
    .map_err(operation_error)?;
    let allowed = matches!(
        (session_use, desired_state.as_deref()),
        (SessionUse::NewWork, Some("active"))
            | (SessionUse::ExistingWork, Some("active" | "draining"))
    );
    if !allowed {
        return Err(AttemptStoreError::RunnerRejected(attempt_id));
    }
    Ok(())
}

async fn verify_live_session_and_slot(
    connection: &mut PgConnection,
    attempt_id: AttemptId,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
) -> Result<(), AttemptStoreError> {
    verify_live_session(connection, attempt_id, session, SessionUse::NewWork).await?;
    let in_range: bool = sqlx::query_scalar("SELECT slots >= $2 FROM runners WHERE id = $1")
        .bind(session.runner_id().as_uuid())
        .bind(i32::from(slot.ordinal()))
        .fetch_one(connection)
        .await
        .map_err(operation_error)?;
    if !in_range {
        return Err(AttemptStoreError::RunnerRejected(attempt_id));
    }
    Ok(())
}

async fn verify_runner_tenant(
    connection: &mut PgConnection,
    attempt_id: AttemptId,
    job_id: JobId,
    runner_id: RunnerId,
) -> Result<(), AttemptStoreError> {
    let matches_tenant: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            JOIN runners AS runner
              ON runner.id = $2
             AND runner.tenant_id = repository.tenant_id
            WHERE job.id = $1
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(runner_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(operation_error)?;
    if !matches_tenant {
        return Err(AttemptStoreError::RunnerRejected(attempt_id));
    }
    Ok(())
}

fn operation_error(error: sqlx::Error) -> AttemptStoreError {
    AttemptStoreError::operation(error)
}

fn decode_fencing_token(value: i64) -> Result<FencingToken, AttemptStoreError> {
    let value = u64::try_from(value)
        .map_err(|_| AttemptStoreError::corrupt_data("negative fencing token"))?;
    FencingToken::new(value).map_err(identifier_error)
}

fn fencing_to_i64(value: FencingToken) -> Result<i64, AttemptStoreError> {
    i64::try_from(value.get())
        .map_err(|_| AttemptStoreError::corrupt_data("fencing token exceeds PostgreSQL BIGINT"))
}

fn identifier_error(error: IdentifierError) -> AttemptStoreError {
    AttemptStoreError::corrupt_data(error.to_string())
}

const fn lifecycle_name(lifecycle: JobLifecycle) -> &'static str {
    match lifecycle {
        JobLifecycle::Queued => "queued",
        JobLifecycle::Leased => "leased",
        JobLifecycle::Preparing => "preparing",
        JobLifecycle::Running => "running",
        JobLifecycle::Cancelling => "cancelling",
        JobLifecycle::Finalizing => "finalizing",
        JobLifecycle::Succeeded => "succeeded",
        JobLifecycle::Failed => "failed",
        JobLifecycle::Cancelled => "cancelled",
        JobLifecycle::TimedOut => "timed_out",
        JobLifecycle::Skipped => "skipped",
        JobLifecycle::Lost => "lost",
    }
}

fn parse_lifecycle(value: &str) -> Result<JobLifecycle, AttemptStoreError> {
    match value {
        "queued" => Ok(JobLifecycle::Queued),
        "leased" => Ok(JobLifecycle::Leased),
        "preparing" => Ok(JobLifecycle::Preparing),
        "running" => Ok(JobLifecycle::Running),
        "cancelling" => Ok(JobLifecycle::Cancelling),
        "finalizing" => Ok(JobLifecycle::Finalizing),
        "succeeded" => Ok(JobLifecycle::Succeeded),
        "failed" => Ok(JobLifecycle::Failed),
        "cancelled" => Ok(JobLifecycle::Cancelled),
        "timed_out" => Ok(JobLifecycle::TimedOut),
        "skipped" => Ok(JobLifecycle::Skipped),
        "lost" => Ok(JobLifecycle::Lost),
        other => Err(AttemptStoreError::corrupt_data(format!(
            "unknown job lifecycle {other:?}"
        ))),
    }
}
