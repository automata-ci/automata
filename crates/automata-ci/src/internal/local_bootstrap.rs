//! File-backed, deployment-authorized bootstrap for one disposable local runner.

use std::{fmt, time::Duration};

use anyhow::Result;
use automata_ci_auth::{
    installation::{InstallationRepositoryError, InstallationTenant},
    management::ManagementRepositoryError,
    secret::{RunnerEnrollmentToken, SecretString},
};
use automata_ci_auth_postgres::{
    ConfigureDeploymentInstallation, ConfigureDeploymentInstallationOutcome,
    PostgresInstallationAuthorityRepository, PostgresRunnerEnrollmentRepository,
    management::{
        EnsureInstallationBootstrapRunnerEnrollmentToken,
        INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
        InstallationBootstrapRunnerEnrollmentTokenOutcome, RunnerEnrollmentTokenRecord,
    },
};
use automata_ci_core::{RunnerGroup, Sha256Digest};
use automata_ci_store_postgres::{
    MAX_POSTGRES_PRIVATE_CA_PEM_BYTES, PostgresConnectionConfig, PostgresStore,
    PostgresTransportSecurity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    cli::{InternalBootstrapFileSource, InternalBootstrapRunnerArgs},
    server::SecretSource,
};

pub(super) const REQUEST_SCHEMA: &str = "automata.local/bootstrap-runner-request/v1";
pub(super) const RECEIPT_SCHEMA: &str = "automata.local/bootstrap-runner-receipt/v1";
const MAX_DATABASE_URL_BYTES: usize = 16 * 1_024;
const MAX_REQUEST_BYTES: usize = 4 * 1_024;
const DATABASE_CONNECTIONS: u32 = 2;
const CONNECT_DEADLINE: Duration = Duration::from_secs(30);
const MIGRATION_DEADLINE: Duration = Duration::from_mins(2);
const TRANSACTION_DEADLINE: Duration = Duration::from_secs(30);
const TOKEN_LIFETIME_SECONDS: u64 = 60 * 60;

pub(super) async fn execute(args: &InternalBootstrapRunnerArgs) -> Result<()> {
    let prepared = PreparedBootstrapRunner::load(args)?;
    let transport = PostgresTransportSecurity::web_pki_plus_private_ca_verify_full(
        prepared.database_private_ca.as_slice(),
    )
    .map_err(|_| BootstrapRunnerError::InvalidInput)?;
    let connection = PostgresConnectionConfig::parse(&prepared.database_url, transport)
        .map_err(|_| BootstrapRunnerError::InvalidInput)?;
    let store = tokio::time::timeout(
        CONNECT_DEADLINE,
        PostgresStore::connect(connection, DATABASE_CONNECTIONS),
    )
    .await
    .map_err(|_| BootstrapRunnerError::DatabaseConnection)?
    .map_err(|_| BootstrapRunnerError::DatabaseConnection)?;
    tokio::time::timeout(MIGRATION_DEADLINE, store.migrate())
        .await
        .map_err(|_| BootstrapRunnerError::DatabaseMigration)?
        .map_err(|_| BootstrapRunnerError::DatabaseMigration)?;

    let result = bootstrap_runner(&store, prepared.operation, TRANSACTION_DEADLINE).await;
    finalize_bootstrap(&args.receipt_target, result)?;
    Ok(())
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRunnerRequest {
    schema: String,
    bootstrap_operation_id: Uuid,
    tenant: InstallationTenant,
    installation_authority_source_sha256: Sha256Digest,
    enrollment_id: Uuid,
    runner_group: RunnerGroup,
    token_lifetime_seconds: u64,
}

impl fmt::Debug for BootstrapRunnerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapRunnerRequest")
            .field("schema", &self.schema)
            .field("bootstrap_operation_id", &self.bootstrap_operation_id)
            .field("tenant", &self.tenant)
            .field("installation_authority_source_sha256", &"[redacted]")
            .field("enrollment_id", &self.enrollment_id)
            .field("runner_group", &self.runner_group)
            .field("token_lifetime_seconds", &self.token_lifetime_seconds)
            .finish()
    }
}

struct PreparedBootstrapRunner {
    database_url: Zeroizing<String>,
    database_private_ca: Zeroizing<Vec<u8>>,
    operation: BootstrapRunnerOperation,
}

impl PreparedBootstrapRunner {
    fn load(args: &InternalBootstrapRunnerArgs) -> Result<Self, BootstrapRunnerError> {
        if !args.database_url_source.is_valid()
            || !args.database_private_ca_source.is_valid()
            || !args.request_source.is_valid()
            || !args.runner_enrollment_token_source.is_valid()
            || !args.receipt_target.is_valid()
        {
            return Err(BootstrapRunnerError::InvalidInput);
        }
        let database_url = load_scalar(&args.database_url_source, MAX_DATABASE_URL_BYTES)?;
        let database_private_ca = load_bytes(
            &args.database_private_ca_source,
            MAX_POSTGRES_PRIVATE_CA_PEM_BYTES,
        )?;
        let request_bytes = load_bytes(&args.request_source, MAX_REQUEST_BYTES)?;
        let request = decode_canonical_request(&request_bytes)?;
        let mut persisted_token = load_scalar(
            &args.runner_enrollment_token_source,
            RunnerEnrollmentToken::BYTE_LENGTH,
        )?;
        let secret = SecretString::new(std::mem::take(&mut *persisted_token))
            .map_err(|_| BootstrapRunnerError::InvalidInput)?;
        let token = RunnerEnrollmentToken::from_secret(secret)
            .map_err(|_| BootstrapRunnerError::InvalidInput)?;
        let token_sha256 = token.digest();
        drop(token);
        Ok(Self {
            database_url,
            database_private_ca,
            operation: BootstrapRunnerOperation {
                request,
                token_sha256,
            },
        })
    }
}

impl fmt::Debug for PreparedBootstrapRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBootstrapRunner")
            .field("database_url", &"[redacted]")
            .field("database_private_ca", &"[redacted]")
            .field("operation", &self.operation)
            .finish()
    }
}

struct BootstrapRunnerOperation {
    request: BootstrapRunnerRequest,
    token_sha256: [u8; 32],
}

impl fmt::Debug for BootstrapRunnerOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapRunnerOperation")
            .field("request", &self.request)
            .field("token_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
enum BootstrapResult {
    Ready {
        bootstrap_operation_id: Uuid,
        record: RunnerEnrollmentTokenRecord,
        receipt_update: ReceiptUpdate,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptUpdate {
    EnsureExact,
    RefreshExpiration,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct BootstrapReceipt<'a> {
    schema: &'static str,
    bootstrap_operation_id: Uuid,
    enrollment_id: Uuid,
    runner_group: &'a str,
    status: &'static str,
    expires_at_ms: i64,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredBootstrapReceipt {
    schema: String,
    bootstrap_operation_id: Uuid,
    enrollment_id: Uuid,
    runner_group: String,
    status: String,
    expires_at_ms: i64,
}

impl BootstrapReceipt<'_> {
    fn canonical_bytes(&self) -> Result<Vec<u8>, BootstrapRunnerError> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| BootstrapRunnerError::Output)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn load_bytes(
    source: &InternalBootstrapFileSource,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, BootstrapRunnerError> {
    let path = source.path().ok_or(BootstrapRunnerError::InvalidInput)?;
    SecretSource::File(path.to_path_buf())
        .load_bytes(maximum_bytes)
        .map_err(|_| BootstrapRunnerError::InvalidInput)
}

fn load_scalar(
    source: &InternalBootstrapFileSource,
    maximum_bytes: usize,
) -> Result<Zeroizing<String>, BootstrapRunnerError> {
    let path = source.path().ok_or(BootstrapRunnerError::InvalidInput)?;
    SecretSource::File(path.to_path_buf())
        .load_scalar(maximum_bytes)
        .map_err(|_| BootstrapRunnerError::InvalidInput)
}

fn decode_canonical_request(
    encoded: &[u8],
) -> Result<BootstrapRunnerRequest, BootstrapRunnerError> {
    let request: BootstrapRunnerRequest =
        serde_json::from_slice(encoded).map_err(|_| BootstrapRunnerError::InvalidInput)?;
    if request.schema != REQUEST_SCHEMA
        || request.bootstrap_operation_id.is_nil()
        || request.installation_authority_source_sha256.as_bytes() == &[0; 32]
        || request.enrollment_id.is_nil()
        || request.token_lifetime_seconds != TOKEN_LIFETIME_SECONDS
        || request.tenant.display_name() != "Local Automata"
        || !request.tenant.tenant_id().as_str().starts_with("local-")
        || request.runner_group.as_str() != "default"
    {
        return Err(BootstrapRunnerError::InvalidInput);
    }
    let mut canonical =
        serde_json::to_vec(&request).map_err(|_| BootstrapRunnerError::InvalidInput)?;
    canonical.push(b'\n');
    if encoded != canonical {
        return Err(BootstrapRunnerError::InvalidInput);
    }
    Ok(request)
}

async fn bootstrap_runner(
    store: &PostgresStore,
    operation: BootstrapRunnerOperation,
    transaction_deadline: Duration,
) -> Result<BootstrapResult, BootstrapRunnerError> {
    let bootstrap_operation_id = operation.request.bootstrap_operation_id;
    let installation_request = ConfigureDeploymentInstallation::new(
        operation
            .request
            .installation_authority_source_sha256
            .into_bytes(),
        bootstrap_operation_id,
        operation.request.tenant,
    )
    .map_err(|_| BootstrapRunnerError::InvalidInput)?;
    let installation = tokio::time::timeout(
        transaction_deadline,
        PostgresInstallationAuthorityRepository::new(store.postgres_pool().clone())
            .configure_deployment(installation_request),
    )
    .await
    .map_err(|_| BootstrapRunnerError::TransactionOutcomeUncertain)?
    .map_err(map_installation_repository_error)?;
    let proof = match installation {
        ConfigureDeploymentInstallationOutcome::Applied(proof)
        | ConfigureDeploymentInstallationOutcome::Replayed(proof) => proof,
        ConfigureDeploymentInstallationOutcome::Conflict => {
            return Err(BootstrapRunnerError::InstallationConflict);
        }
    };

    let expected_enrollment_id = operation.request.enrollment_id;
    let expected_runner_group = operation.request.runner_group.as_str().to_owned();
    let enrollment_request = EnsureInstallationBootstrapRunnerEnrollmentToken::new(
        proof,
        expected_enrollment_id,
        operation.token_sha256,
        operation.request.runner_group,
        INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
    )
    .map_err(|_| BootstrapRunnerError::InvalidInput)?;
    let enrollment = tokio::time::timeout(
        transaction_deadline,
        PostgresRunnerEnrollmentRepository::new(store.postgres_pool().clone())
            .ensure_installation_bootstrap_runner_enrollment_token(enrollment_request),
    )
    .await
    .map_err(|_| BootstrapRunnerError::TransactionOutcomeUncertain)?
    .map_err(map_management_repository_error)?;
    let (record, receipt_update) = match enrollment {
        InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(record) => {
            (record, ReceiptUpdate::EnsureExact)
        }
        InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(record)
        | InstallationBootstrapRunnerEnrollmentTokenOutcome::Refreshed(record)
        | InstallationBootstrapRunnerEnrollmentTokenOutcome::Consumed(record) => {
            (record, ReceiptUpdate::RefreshExpiration)
        }
        InstallationBootstrapRunnerEnrollmentTokenOutcome::Conflict => {
            return Err(BootstrapRunnerError::EnrollmentConflict);
        }
    };
    validate_record(&record, expected_enrollment_id, &expected_runner_group)?;
    Ok(BootstrapResult::Ready {
        bootstrap_operation_id,
        record,
        receipt_update,
    })
}

fn map_installation_repository_error(error: InstallationRepositoryError) -> BootstrapRunnerError {
    match error {
        InstallationRepositoryError::Unavailable => {
            BootstrapRunnerError::TransactionOutcomeUncertain
        }
        InstallationRepositoryError::CorruptData
        | InstallationRepositoryError::InvalidRequest
        | InstallationRepositoryError::NotArmed
        | InstallationRepositoryError::ProofRejected
        | InstallationRepositoryError::Expired
        | InstallationRepositoryError::AlreadyBound
        | InstallationRepositoryError::AlreadyConfigured
        | InstallationRepositoryError::VersionConflict
        | InstallationRepositoryError::IdentityConflict
        | InstallationRepositoryError::CredentialCustody => BootstrapRunnerError::Storage,
    }
}

fn map_management_repository_error(error: ManagementRepositoryError) -> BootstrapRunnerError {
    match error {
        ManagementRepositoryError::Unavailable => BootstrapRunnerError::TransactionOutcomeUncertain,
        ManagementRepositoryError::InvalidRequest | ManagementRepositoryError::CorruptData => {
            BootstrapRunnerError::Storage
        }
    }
}

fn validate_record(
    record: &RunnerEnrollmentTokenRecord,
    expected_enrollment_id: Uuid,
    expected_runner_group: &str,
) -> Result<(), BootstrapRunnerError> {
    if record.enrollment_id != expected_enrollment_id
        || record.runner_group_id.is_nil()
        || record.runner_group != expected_runner_group
        || record.expires_at_ms <= 0
    {
        return Err(BootstrapRunnerError::Storage);
    }
    Ok(())
}

fn finalize_bootstrap(
    target: &InternalBootstrapFileSource,
    result: Result<BootstrapResult, BootstrapRunnerError>,
) -> Result<(), BootstrapRunnerError> {
    match result? {
        BootstrapResult::Ready {
            bootstrap_operation_id,
            record,
            receipt_update,
        } => persist_receipt(
            target,
            &BootstrapReceipt {
                schema: RECEIPT_SCHEMA,
                bootstrap_operation_id,
                enrollment_id: record.enrollment_id,
                runner_group: &record.runner_group,
                status: "ready",
                expires_at_ms: record.expires_at_ms,
            },
            receipt_update,
        ),
    }
}

fn persist_receipt(
    target: &InternalBootstrapFileSource,
    receipt: &BootstrapReceipt<'_>,
    update: ReceiptUpdate,
) -> Result<(), BootstrapRunnerError> {
    let path = target.path().ok_or(BootstrapRunnerError::InvalidInput)?;
    persist_receipt_bytes(
        path,
        &receipt.canonical_bytes()?,
        receipt.enrollment_id,
        update,
    )
}

fn decode_stored_receipt(bytes: &[u8]) -> Result<StoredBootstrapReceipt, BootstrapRunnerError> {
    let receipt: StoredBootstrapReceipt =
        serde_json::from_slice(bytes).map_err(|_| BootstrapRunnerError::Output)?;
    let mut canonical = serde_json::to_vec(&receipt).map_err(|_| BootstrapRunnerError::Output)?;
    canonical.push(b'\n');
    if bytes != canonical
        || receipt.schema != RECEIPT_SCHEMA
        || receipt.bootstrap_operation_id.is_nil()
        || receipt.enrollment_id.is_nil()
        || receipt.runner_group != "default"
        || receipt.status != "ready"
        || receipt.expires_at_ms <= 0
    {
        return Err(BootstrapRunnerError::Output);
    }
    Ok(receipt)
}

fn receipt_refresh_is_exact_predecessor(current: &[u8], replacement: &[u8]) -> bool {
    let Ok(current) = decode_stored_receipt(current) else {
        return false;
    };
    let Ok(replacement) = decode_stored_receipt(replacement) else {
        return false;
    };
    current.schema == replacement.schema
        && current.bootstrap_operation_id == replacement.bootstrap_operation_id
        && current.enrollment_id == replacement.enrollment_id
        && current.runner_group == replacement.runner_group
        && current.status == replacement.status
        && replacement.expires_at_ms > current.expires_at_ms
}

#[cfg(unix)]
#[allow(
    clippy::too_many_lines,
    reason = "the locked no-follow receipt replacement protocol must remain auditable as one operation"
)]
fn persist_receipt_bytes(
    path: &std::path::Path,
    bytes: &[u8],
    enrollment_id: Uuid,
    update: ReceiptUpdate,
) -> Result<(), BootstrapRunnerError> {
    use rustix::fs::{
        AtFlags, FlockOperation, Mode, OFlags, RenameFlags, fchmod, flock, fsync, openat, renameat,
        renameat_with, unlinkat,
    };
    use std::{
        fs::File,
        io::{Read as _, Seek as _, SeekFrom, Write as _},
    };

    let _replacement = decode_stored_receipt(bytes)?;
    let (parent, target_name) = open_private_parent(path)?;
    let mut replace_existing = false;
    let target_lock = match openat(
        &parent,
        &target_name,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(existing) => {
            verify_private_regular(&existing)?;
            flock(&existing, FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| BootstrapRunnerError::Output)?;
            let mut file = File::from(existing);
            let mut current = Vec::with_capacity(MAX_REQUEST_BYTES.min(8 * 1_024));
            (&mut file)
                .take(
                    u64::try_from(MAX_REQUEST_BYTES)
                        .map_err(|_| BootstrapRunnerError::Output)?
                        .saturating_add(1),
                )
                .read_to_end(&mut current)
                .map_err(|_| BootstrapRunnerError::Output)?;
            if current == bytes {
                return fsync(&parent).map_err(|_| BootstrapRunnerError::Output);
            }
            if update != ReceiptUpdate::RefreshExpiration
                || !receipt_refresh_is_exact_predecessor(&current, bytes)
            {
                return Err(BootstrapRunnerError::Output);
            }
            replace_existing = true;
            Some(file)
        }
        Err(rustix::io::Errno::NOENT) => None,
        Err(_) => return Err(BootstrapRunnerError::Output),
    };

    let temporary = format!(".automata-bootstrap-receipt-{enrollment_id}.tmp");
    let (staging, created) = match openat(
        &parent,
        temporary.as_str(),
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(staging) => (staging, true),
        Err(rustix::io::Errno::EXIST) => (
            openat(
                &parent,
                temporary.as_str(),
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| BootstrapRunnerError::Output)?,
            false,
        ),
        Err(_) => return Err(BootstrapRunnerError::Output),
    };
    if created {
        fchmod(&staging, Mode::from_raw_mode(0o600)).map_err(|_| BootstrapRunnerError::Output)?;
    }
    verify_private_regular(&staging)?;
    flock(&staging, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| BootstrapRunnerError::Output)?;
    let mut file = File::from(staging);
    if created {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| BootstrapRunnerError::Output)?;
    } else {
        let mut current = Vec::with_capacity(MAX_REQUEST_BYTES.min(8 * 1_024));
        (&mut file)
            .take(
                u64::try_from(MAX_REQUEST_BYTES)
                    .map_err(|_| BootstrapRunnerError::Output)?
                    .saturating_add(1),
            )
            .read_to_end(&mut current)
            .map_err(|_| BootstrapRunnerError::Output)?;
        if current != bytes {
            if update != ReceiptUpdate::RefreshExpiration
                || !receipt_refresh_is_exact_predecessor(&current, bytes)
            {
                return Err(BootstrapRunnerError::Output);
            }
            file.set_len(0).map_err(|_| BootstrapRunnerError::Output)?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| BootstrapRunnerError::Output)?;
            file.write_all(bytes)
                .map_err(|_| BootstrapRunnerError::Output)?;
        }
        file.sync_all().map_err(|_| BootstrapRunnerError::Output)?;
    }
    if replace_existing {
        renameat(&parent, temporary.as_str(), &parent, &target_name)
            .map_err(|_| BootstrapRunnerError::Output)?;
        drop(target_lock);
        return fsync(&parent).map_err(|_| BootstrapRunnerError::Output);
    }
    match renameat_with(
        &parent,
        temporary.as_str(),
        &parent,
        &target_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            let existing = openat(
                &parent,
                &target_name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| BootstrapRunnerError::Output)?;
            verify_private_regular(&existing)?;
            let mut existing = File::from(existing);
            let mut current = Vec::with_capacity(bytes.len().saturating_add(1));
            (&mut existing)
                .take(
                    u64::try_from(bytes.len())
                        .map_err(|_| BootstrapRunnerError::Output)?
                        .saturating_add(1),
                )
                .read_to_end(&mut current)
                .map_err(|_| BootstrapRunnerError::Output)?;
            if current != bytes {
                return Err(BootstrapRunnerError::Output);
            }
            unlinkat(&parent, temporary.as_str(), AtFlags::empty())
                .map_err(|_| BootstrapRunnerError::Output)?;
        }
        Err(_) => return Err(BootstrapRunnerError::Output),
    }
    fsync(&parent).map_err(|_| BootstrapRunnerError::Output)
}

#[cfg(unix)]
fn open_private_parent(
    path: &std::path::Path,
) -> Result<(rustix::fd::OwnedFd, std::ffi::OsString), BootstrapRunnerError> {
    use rustix::fd::OwnedFd;
    use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

    let mut components = Vec::<std::ffi::OsString>::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(value) => components.push(value.to_os_string()),
            _ => return Err(BootstrapRunnerError::Output),
        }
    }
    let (target_name, parents) = components
        .split_last()
        .ok_or(BootstrapRunnerError::Output)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut parent: OwnedFd =
        open("/", directory_flags, Mode::empty()).map_err(|_| BootstrapRunnerError::Output)?;
    for component in parents {
        parent = openat(&parent, component, directory_flags, Mode::empty())
            .map_err(|_| BootstrapRunnerError::Output)?;
    }
    let metadata = fstat(&parent).map_err(|_| BootstrapRunnerError::Output)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o077 != 0
    {
        return Err(BootstrapRunnerError::Output);
    }
    Ok((parent, target_name.clone()))
}

#[cfg(unix)]
fn verify_private_regular(descriptor: &impl std::os::fd::AsFd) -> Result<(), BootstrapRunnerError> {
    use rustix::fs::{FileType, fstat};

    let metadata = fstat(descriptor).map_err(|_| BootstrapRunnerError::Output)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(BootstrapRunnerError::Output);
    }
    Ok(())
}

#[cfg(not(unix))]
fn persist_receipt_bytes(
    _path: &std::path::Path,
    _bytes: &[u8],
    _enrollment_id: Uuid,
    _update: ReceiptUpdate,
) -> Result<(), BootstrapRunnerError> {
    Err(BootstrapRunnerError::Output)
}

#[derive(Debug, Eq, Error, PartialEq)]
enum BootstrapRunnerError {
    #[error("local runner bootstrap input is invalid")]
    InvalidInput,
    #[error("local runner bootstrap could not connect to PostgreSQL")]
    DatabaseConnection,
    #[error("local runner bootstrap could not prepare the PostgreSQL schema")]
    DatabaseMigration,
    #[error("local installation identity conflicts with durable state")]
    InstallationConflict,
    #[error("local runner enrollment identity conflicts with durable state")]
    EnrollmentConflict,
    #[error("local runner bootstrap storage is unavailable")]
    Storage,
    #[error(
        "local runner bootstrap transaction outcome is uncertain; retry the exact persisted request"
    )]
    TransactionOutcomeUncertain,
    #[error(
        "local runner bootstrap receipt update is uncertain; retry the exact persisted request"
    )]
    Output,
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::{human::TenantId, installation::InstallationTenant};

    use super::*;

    fn request() -> BootstrapRunnerRequest {
        BootstrapRunnerRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            bootstrap_operation_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                .expect("operation ID"),
            tenant: InstallationTenant::new(
                TenantId::new("local-11111111111141118111111111111111").expect("tenant ID"),
                "Local Automata",
            )
            .expect("installation tenant"),
            installation_authority_source_sha256: Sha256Digest::from_bytes([31; 32]),
            enrollment_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .expect("enrollment ID"),
            runner_group: RunnerGroup::new("default").expect("runner group"),
            token_lifetime_seconds: TOKEN_LIFETIME_SECONDS,
        }
    }

    fn encoded(request: &BootstrapRunnerRequest) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(request).expect("request JSON");
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn bootstrap_request_is_exact_fixed_canonical_and_redacted() {
        let expected = request();
        assert_eq!(decode_canonical_request(&encoded(&expected)), Ok(expected));
        let candidate = request();
        let rendered = format!("{candidate:?}");
        assert!(!rendered.contains(&"1f".repeat(32)));
        for invalid in [
            encoded(&candidate).strip_suffix(b"\n").unwrap().to_vec(),
            String::from_utf8(encoded(&candidate))
                .expect("request text")
                .replace("\"schema\":", "\"unknown\":true,\"schema\":")
                .into_bytes(),
        ] {
            assert_eq!(
                decode_canonical_request(&invalid),
                Err(BootstrapRunnerError::InvalidInput)
            );
        }
    }

    #[test]
    fn ready_receipt_is_canonical_and_contains_no_token_material() {
        let receipt = BootstrapReceipt {
            schema: RECEIPT_SCHEMA,
            bootstrap_operation_id: request().bootstrap_operation_id,
            enrollment_id: request().enrollment_id,
            runner_group: "default",
            status: "ready",
            expires_at_ms: 123_456,
        };
        let bytes = receipt.canonical_bytes().expect("receipt");
        assert!(bytes.ends_with(b"\n"));
        assert!(!bytes.windows(7).any(|window| window == b"atm_re_"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["status"],
            "ready"
        );
    }

    #[test]
    #[cfg(unix)]
    fn receipt_replay_preserves_exact_bytes_and_rejects_drift() {
        use std::{fs, os::unix::fs::PermissionsExt as _};

        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(
                ".automata-bootstrap-receipt-test-{}",
                Uuid::new_v4()
            ));
        fs::create_dir(&root).expect("receipt test root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private receipt test root");
        let path = root.join("receipt.json");
        let request = request();
        let exact = BootstrapReceipt {
            schema: RECEIPT_SCHEMA,
            bootstrap_operation_id: request.bootstrap_operation_id,
            enrollment_id: request.enrollment_id,
            runner_group: request.runner_group.as_str(),
            status: "ready",
            expires_at_ms: 100,
        }
        .canonical_bytes()
        .expect("exact receipt");
        persist_receipt_bytes(
            &path,
            &exact,
            request.enrollment_id,
            ReceiptUpdate::EnsureExact,
        )
        .expect("first receipt publication");
        persist_receipt_bytes(
            &path,
            &exact,
            request.enrollment_id,
            ReceiptUpdate::EnsureExact,
        )
        .expect("exact receipt replay");
        assert_eq!(fs::read(&path).expect("published receipt"), exact);

        let drifted = BootstrapReceipt {
            schema: RECEIPT_SCHEMA,
            bootstrap_operation_id: Uuid::new_v4(),
            enrollment_id: request.enrollment_id,
            runner_group: request.runner_group.as_str(),
            status: "ready",
            expires_at_ms: 100,
        }
        .canonical_bytes()
        .expect("drifted receipt");

        assert_eq!(
            persist_receipt_bytes(
                &path,
                &drifted,
                request.enrollment_id,
                ReceiptUpdate::EnsureExact,
            ),
            Err(BootstrapRunnerError::Output)
        );
        assert_eq!(
            fs::read(&path).expect("preserved receipt"),
            exact,
            "a replay must never replace an existing receipt"
        );
        fs::remove_dir_all(&root).expect("remove receipt test root");
    }

    #[test]
    #[cfg(unix)]
    fn receipt_refresh_changes_only_the_database_authorized_expiration() {
        use std::{fs, os::unix::fs::PermissionsExt as _};

        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(
                ".automata-bootstrap-refresh-test-{}",
                Uuid::new_v4()
            ));
        fs::create_dir(&root).expect("receipt test root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private receipt test root");
        let path = root.join("receipt.json");
        let request = request();
        let receipt = |expires_at_ms| BootstrapReceipt {
            schema: RECEIPT_SCHEMA,
            bootstrap_operation_id: request.bootstrap_operation_id,
            enrollment_id: request.enrollment_id,
            runner_group: request.runner_group.as_str(),
            status: "ready",
            expires_at_ms,
        };
        let old = receipt(100).canonical_bytes().expect("old receipt");
        let refreshed = receipt(200).canonical_bytes().expect("refreshed receipt");
        persist_receipt_bytes(
            &path,
            &old,
            request.enrollment_id,
            ReceiptUpdate::EnsureExact,
        )
        .expect("initial receipt");
        persist_receipt_bytes(
            &path,
            &refreshed,
            request.enrollment_id,
            ReceiptUpdate::RefreshExpiration,
        )
        .expect("authorized expiration refresh");
        assert_eq!(fs::read(&path).expect("refreshed receipt"), refreshed);

        let drifted = BootstrapReceipt {
            runner_group: "drifted",
            expires_at_ms: 300,
            ..receipt(200)
        }
        .canonical_bytes()
        .expect("drifted receipt");
        assert_eq!(
            persist_receipt_bytes(
                &path,
                &drifted,
                request.enrollment_id,
                ReceiptUpdate::RefreshExpiration,
            ),
            Err(BootstrapRunnerError::Output)
        );
        assert_eq!(fs::read(&path).expect("preserved receipt"), refreshed);
        fs::remove_dir_all(&root).expect("remove receipt test root");
    }
}
