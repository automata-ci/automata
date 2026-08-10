use std::fmt;

use automata_ci_key_management::{
    ENVELOPE_NONCE_BYTES, EncryptedEnvelope, EnvelopeError, KeyId, WrappedDataKey,
};
use automata_ci_secret::{ProviderError, ProviderErrorKind};
use automata_ci_store::SECRET_MUTATION_CONFIRMATION_TTL_MILLIS;
use sqlx::{Error as SqlxError, FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::support::ValidatedSecretDescriptor;

const BUILTIN_ADAPTER_KIND: &str = "builtin_postgres";
const BUILTIN_STORAGE_KIND: &str = "built_in_ciphertext";
const VERSION_MUTATION_REQUEST_PREFIX: &str = "secret-version:";
const MAX_DATABASE_CIPHERTEXT_BYTES: usize = 131_072;
const MAX_DATABASE_WRAPPED_KEY_BYTES: usize = 4_096;

pub(crate) struct CreateVersionRecord {
    pub(crate) secret: ValidatedSecretDescriptor,
    pub(crate) request_id: String,
    pub(crate) expected_current_version_id: Option<Uuid>,
    pub(crate) candidate_version_id: Uuid,
    pub(crate) envelope: EnvelopeSqlParameters,
}

pub(crate) struct CreateVersionPreflightRecord {
    pub(crate) secret: ValidatedSecretDescriptor,
    pub(crate) request_id: String,
    pub(crate) expected_current_version_id: Option<Uuid>,
}

pub(crate) enum CreateVersionPreflight {
    Staged(StoredVersion),
    Reserved,
}

pub(crate) struct ReconcileCreateVersionRecord {
    pub(crate) secret: ValidatedSecretDescriptor,
    pub(crate) request_id: String,
    pub(crate) expected_current_version_id: Option<Uuid>,
}

pub(crate) enum ReconcileCreateVersion {
    AlreadyCommitted(StoredVersion),
    DefinitivelyNotCommitted,
}

pub(crate) struct StoredVersion {
    pub(crate) secret_id: Uuid,
    pub(crate) version_id: Uuid,
}

pub(crate) struct ResolveVersionRecord {
    pub(crate) secret: ValidatedSecretDescriptor,
    pub(crate) version_id: Uuid,
}

pub(crate) struct DestroyVersionRecord {
    pub(crate) secret: ValidatedSecretDescriptor,
    pub(crate) version_id: Uuid,
    pub(crate) request_id: String,
}

pub(crate) struct LockedEnvelope {
    transaction: Transaction<'static, Postgres>,
    envelope: EncryptedEnvelope,
}

impl LockedEnvelope {
    pub(crate) const fn envelope(&self) -> &EncryptedEnvelope {
        &self.envelope
    }

    pub(crate) async fn commit(self) -> Result<(), ProviderError> {
        self.transaction.commit().await.map_err(map_sql_error)
    }
}

pub(crate) struct EnvelopeSqlParameters {
    schema: i32,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EnvelopeSqlParameters {
    pub(crate) fn from_envelope(envelope: EncryptedEnvelope) -> Result<Self, ProviderError> {
        let (schema, wrapped_data_key, nonce, ciphertext) = envelope.into_parts();
        let (wrapping_key_id, wrapped_data_key) = wrapped_data_key.into_parts();
        if wrapped_data_key.len() > MAX_DATABASE_WRAPPED_KEY_BYTES
            || ciphertext.len() > MAX_DATABASE_CIPHERTEXT_BYTES
        {
            return Err(ProviderError::new(ProviderErrorKind::InvalidResponse));
        }
        Ok(Self {
            schema: i32::from(schema),
            wrapping_key_id: wrapping_key_id.as_str().to_owned(),
            wrapped_data_key,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn into_parts(self) -> (i32, String, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            self.schema,
            self.wrapping_key_id,
            self.wrapped_data_key,
            self.nonce,
            self.ciphertext,
        )
    }
}

impl fmt::Debug for EnvelopeSqlParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeSqlParameters")
            .field("schema", &self.schema)
            .field("wrapping_key_id", &self.wrapping_key_id)
            .field("wrapped_data_key", &"[OPAQUE]")
            .field("nonce", &"[NONCE]")
            .field("ciphertext", &"[OPAQUE]")
            .field("ciphertext_length", &self.ciphertext.len())
            .finish()
    }
}

pub(crate) async fn health(
    pool: &PgPool,
    tenant_id: &str,
    provider_id: &str,
) -> Result<automata_ci_secret::ProviderHealth, ProviderError> {
    let row = sqlx::query_as::<_, (String, String, String)>(
        r"
        SELECT adapter_kind, status, health
        FROM secret_providers
        WHERE tenant_id = $1 AND provider_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?;
    let Some((adapter_kind, status, health)) = row else {
        return Ok(automata_ci_secret::ProviderHealth::Unavailable);
    };
    if adapter_kind != BUILTIN_ADAPTER_KIND || status != "active" {
        return Ok(automata_ci_secret::ProviderHealth::Unavailable);
    }
    Ok(match health.as_str() {
        "healthy" => automata_ci_secret::ProviderHealth::Healthy,
        "degraded" | "unknown" => automata_ci_secret::ProviderHealth::Degraded,
        "unavailable" => automata_ci_secret::ProviderHealth::Unavailable,
        _ => return Err(integrity_failure()),
    })
}

#[derive(FromRow)]
struct ProviderRow {
    adapter_kind: String,
    status: String,
    supports_create_version: bool,
    supports_destroy_version: bool,
}

#[derive(FromRow)]
struct SecretRow {
    canonical_name: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    current_version_id: Option<Uuid>,
    current_version_number: Option<i64>,
    status: String,
    revision: i64,
}

#[derive(FromRow)]
struct ExistingVersionRow {
    id: Uuid,
    secret_id: Uuid,
    version_number: i64,
    storage_kind: String,
    mutation_id: Uuid,
    lifecycle_status: String,
    builtin_envelope_count: i64,
    external_reference_count: i64,
}

#[derive(FromRow)]
struct MutationRow {
    secret_id: Uuid,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    canonical_name: String,
    provider_id: String,
    mutation_kind: String,
    expected_secret_revision: Option<i64>,
    reserved_secret_revision: i64,
    reserved_version_number: i64,
    reserved_at_ms: i64,
    confirmation_deadline_ms: i64,
    expected_predecessor_version_id: Option<Uuid>,
    expected_predecessor_version_number: Option<i64>,
    provider_create_request_id: String,
    state: String,
    completion_kind: Option<String>,
    committed_version_id: Option<Uuid>,
    committed_version_number: Option<i64>,
    terminal_reason: Option<String>,
    abandoned_version_id: Option<Uuid>,
    abandoned_version_number: Option<i64>,
}

#[derive(FromRow)]
struct ResolveRow {
    canonical_name: String,
    scope_kind: String,
    repository_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    secret_status: String,
    adapter_kind: String,
    provider_status: String,
    secret_id: Uuid,
    storage_kind: String,
    lifecycle_status: String,
    envelope_schema: i32,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(FromRow)]
struct DestroyRow {
    secret_id: Uuid,
    storage_kind: String,
    lifecycle_status: String,
    destroy_request_id: Option<String>,
    lifecycle_revision: i64,
    changed_at_ms: i64,
}

pub(crate) async fn preflight_create_version(
    pool: &PgPool,
    provider_id: &str,
    record: CreateVersionPreflightRecord,
) -> Result<CreateVersionPreflight, ProviderError> {
    let mutation_id = mutation_id_from_request_id(&record.request_id)?;
    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    let provider = lock_provider(&mut transaction, record.secret.tenant_id(), provider_id).await?;
    if provider.adapter_kind != BUILTIN_ADAPTER_KIND {
        return Err(integrity_failure());
    }
    if provider.status != "active" || !provider.supports_create_version {
        return Err(ProviderError::new(ProviderErrorKind::Forbidden));
    }
    let secret = lock_secret(&mut transaction, &record.secret, provider_id).await?;
    if !record.secret.matches(
        &secret.canonical_name,
        &secret.scope_kind,
        secret.repository_id,
        secret.environment_id,
    ) {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    let mutation = lock_mutation(&mut transaction, record.secret.tenant_id(), mutation_id).await?;
    validate_mutation(
        &record.secret,
        &record.request_id,
        provider_id,
        mutation_id,
        &mutation,
    )?;
    ensure_reservation_is_live(&mutation, database_time(&mut transaction).await?)?;
    let existing = load_existing_version(
        &mut transaction,
        record.secret.tenant_id(),
        provider_id,
        &record.request_id,
    )
    .await?;
    let outcome = if let Some(existing) = existing {
        validate_staged_replay(
            &record.secret,
            record.expected_current_version_id,
            mutation_id,
            &mutation,
            &existing,
        )?;
        CreateVersionPreflight::Staged(StoredVersion {
            secret_id: existing.secret_id,
            version_id: existing.id,
        })
    } else {
        validate_reserved_head(record.expected_current_version_id, &secret, &mutation)?;
        if has_pending_expired_cleanup(
            &mut transaction,
            record.secret.tenant_id(),
            record.secret.secret_id(),
        )
        .await?
        {
            return Err(ProviderError::new(ProviderErrorKind::Unavailable));
        }
        CreateVersionPreflight::Reserved
    };
    transaction.commit().await.map_err(map_sql_error)?;
    Ok(outcome)
}

pub(crate) async fn reconcile_create_version(
    pool: &PgPool,
    provider_id: &str,
    record: ReconcileCreateVersionRecord,
) -> Result<ReconcileCreateVersion, ProviderError> {
    let mutation_id = mutation_id_from_request_id(&record.request_id)?;
    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    let provider = lock_provider(&mut transaction, record.secret.tenant_id(), provider_id).await?;
    if provider.adapter_kind != BUILTIN_ADAPTER_KIND || !provider.supports_create_version {
        return Err(integrity_failure());
    }

    let secret = lock_secret(&mut transaction, &record.secret, provider_id).await?;
    if !record.secret.matches(
        &secret.canonical_name,
        &secret.scope_kind,
        secret.repository_id,
        secret.environment_id,
    ) {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    let mutation = lock_mutation(&mut transaction, record.secret.tenant_id(), mutation_id).await?;
    validate_mutation(
        &record.secret,
        &record.request_id,
        provider_id,
        mutation_id,
        &mutation,
    )?;
    validate_reconciliation_predecessor(record.expected_current_version_id, &mutation)?;
    validate_confirmation_deadline(&mutation)?;

    let existing = load_existing_version(
        &mut transaction,
        record.secret.tenant_id(),
        provider_id,
        &record.request_id,
    )
    .await?;
    let outcome = if let Some(existing) = existing {
        validate_reconciled_version(&record.secret, mutation_id, &mutation, &existing)?;
        ReconcileCreateVersion::AlreadyCommitted(StoredVersion {
            secret_id: existing.secret_id,
            version_id: existing.id,
        })
    } else {
        let observed_at_ms = database_time(&mut transaction).await?;
        validate_definitive_absence(&secret, &mutation, observed_at_ms)?;
        ReconcileCreateVersion::DefinitivelyNotCommitted
    };
    transaction.commit().await.map_err(map_sql_error)?;
    Ok(outcome)
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn create_version(
    pool: &PgPool,
    provider_id: &str,
    record: CreateVersionRecord,
) -> Result<StoredVersion, ProviderError> {
    let mutation_id = mutation_id_from_request_id(&record.request_id)?;
    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    let provider = lock_provider(&mut transaction, record.secret.tenant_id(), provider_id).await?;
    if provider.adapter_kind != BUILTIN_ADAPTER_KIND {
        return Err(integrity_failure());
    }
    if provider.status != "active" || !provider.supports_create_version {
        return Err(ProviderError::new(ProviderErrorKind::Forbidden));
    }

    let secret = lock_secret(&mut transaction, &record.secret, provider_id).await?;
    if !record.secret.matches(
        &secret.canonical_name,
        &secret.scope_kind,
        secret.repository_id,
        secret.environment_id,
    ) {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    let mutation = lock_mutation(&mut transaction, record.secret.tenant_id(), mutation_id).await?;
    validate_mutation(
        &record.secret,
        &record.request_id,
        provider_id,
        mutation_id,
        &mutation,
    )?;
    let operation_time = database_time(&mut transaction).await?;
    ensure_reservation_is_live(&mutation, operation_time)?;

    let existing = load_existing_version(
        &mut transaction,
        record.secret.tenant_id(),
        provider_id,
        &record.request_id,
    )
    .await?;
    if let Some(existing) = existing {
        validate_staged_replay(
            &record.secret,
            record.expected_current_version_id,
            mutation_id,
            &mutation,
            &existing,
        )?;
        transaction.commit().await.map_err(map_sql_error)?;
        return Ok(StoredVersion {
            secret_id: existing.secret_id,
            version_id: existing.id,
        });
    }

    validate_reserved_head(record.expected_current_version_id, &secret, &mutation)?;
    let staged_mutation: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT mutation_id
        FROM secret_version_lifecycle
        WHERE tenant_id = $1 AND secret_id = $2 AND status = 'staged'
        FOR UPDATE
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.secret.secret_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    if staged_mutation.is_some() {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    if has_pending_expired_cleanup(
        &mut transaction,
        record.secret.tenant_id(),
        record.secret.secret_id(),
    )
    .await?
    {
        return Err(ProviderError::new(ProviderErrorKind::Unavailable));
    }
    let version_number = mutation.reserved_version_number;
    if version_number <= mutation.expected_predecessor_version_number.unwrap_or(0) {
        return Err(integrity_failure());
    }
    sqlx::query(
        r"
        INSERT INTO secret_versions (
            tenant_id, id, secret_id, version_number, provider_id,
            create_request_id, storage_kind, created_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, 'built_in_ciphertext', $7)
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.candidate_version_id)
    .bind(record.secret.secret_id())
    .bind(version_number)
    .bind(provider_id)
    .bind(&record.request_id)
    .bind(operation_time)
    .execute(&mut *transaction)
    .await
    .map_err(map_sql_error)?;

    sqlx::query(
        r"
        INSERT INTO secret_version_lifecycle (
            tenant_id, secret_version_id, secret_id, version_number,
            provider_id, status, mutation_id, revision, changed_at_ms
        ) VALUES ($1, $2, $3, $4, $5, 'staged', $6, 1, $7)
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.candidate_version_id)
    .bind(record.secret.secret_id())
    .bind(version_number)
    .bind(provider_id)
    .bind(mutation_id)
    .bind(operation_time)
    .execute(&mut *transaction)
    .await
    .map_err(map_sql_error)?;

    let (schema, wrapping_key_id, wrapped_data_key, nonce, ciphertext) =
        record.envelope.into_parts();
    sqlx::query(
        r"
        INSERT INTO secret_version_envelopes (
            tenant_id, secret_version_id, secret_id, version_number,
            storage_kind, envelope_generation, ciphertext, nonce,
            wrapped_data_key, wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES (
            $1, $2, $3, $4, 'built_in_ciphertext', 1, $5, $6, $7, $8, $9, $10
        )
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.candidate_version_id)
    .bind(record.secret.secret_id())
    .bind(version_number)
    .bind(ciphertext)
    .bind(nonce)
    .bind(wrapped_data_key)
    .bind(wrapping_key_id)
    .bind(schema)
    .bind(operation_time)
    .execute(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelope_heads (
            tenant_id, secret_version_id, envelope_generation, revision, updated_at_ms
        ) VALUES ($1, $2, 1, 1, $3)
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.candidate_version_id)
    .bind(operation_time)
    .execute(&mut *transaction)
    .await
    .map_err(map_sql_error)?;

    transaction.commit().await.map_err(map_sql_error)?;
    Ok(StoredVersion {
        secret_id: record.secret.secret_id(),
        version_id: record.candidate_version_id,
    })
}

pub(crate) async fn resolve_version(
    pool: &PgPool,
    provider_id: &str,
    record: ResolveVersionRecord,
) -> Result<LockedEnvelope, ProviderError> {
    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    let row = sqlx::query_as::<_, ResolveRow>(
        r"
        SELECT
            s.canonical_name, s.scope_kind, s.repository_id, s.environment_id,
            s.status AS secret_status,
            p.adapter_kind, p.status AS provider_status,
            v.secret_id, v.storage_kind,
            l.status AS lifecycle_status,
            e.envelope_schema, e.wrapping_key_id, e.wrapped_data_key,
            e.nonce, e.ciphertext
        FROM secrets s
        JOIN secret_providers p
          ON p.tenant_id = s.tenant_id AND p.provider_id = s.provider_id
        JOIN secret_versions v
          ON v.tenant_id = s.tenant_id AND v.secret_id = s.id
        JOIN secret_version_lifecycle l
          ON l.tenant_id = v.tenant_id AND l.secret_version_id = v.id
        JOIN secret_version_envelope_heads h
          ON h.tenant_id = v.tenant_id AND h.secret_version_id = v.id
        JOIN secret_version_envelopes e
          ON e.tenant_id = h.tenant_id
         AND e.secret_version_id = h.secret_version_id
         AND e.envelope_generation = h.envelope_generation
        WHERE s.tenant_id = $1 AND s.id = $2 AND s.provider_id = $3
          AND v.id = $4
        FOR SHARE OF s, v, l, h, e
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.secret.secret_id())
    .bind(provider_id)
    .bind(record.version_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    let Some(row) = row else {
        return Err(ProviderError::new(ProviderErrorKind::NotFound));
    };
    if !record.secret.matches(
        &row.canonical_name,
        &row.scope_kind,
        row.repository_id,
        row.environment_id,
    ) || row.secret_id != record.secret.secret_id()
    {
        return Err(ProviderError::new(ProviderErrorKind::NotFound));
    }
    if row.adapter_kind != BUILTIN_ADAPTER_KIND || row.storage_kind != BUILTIN_STORAGE_KIND {
        return Err(integrity_failure());
    }
    if !matches!(row.lifecycle_status.as_str(), "active" | "superseded") {
        return Err(ProviderError::new(ProviderErrorKind::NotFound));
    }
    if row.provider_status != "active" || row.secret_status != "active" {
        return Err(ProviderError::new(ProviderErrorKind::Forbidden));
    }
    let envelope = envelope_from_parts(
        row.envelope_schema,
        row.wrapping_key_id,
        row.wrapped_data_key,
        row.nonce,
        row.ciphertext,
    )?;
    Ok(LockedEnvelope {
        transaction,
        envelope,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn destroy_version(
    pool: &PgPool,
    provider_id: &str,
    record: DestroyVersionRecord,
) -> Result<(), ProviderError> {
    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    let provider = lock_provider(&mut transaction, record.secret.tenant_id(), provider_id).await?;
    if provider.adapter_kind != BUILTIN_ADAPTER_KIND {
        return Err(integrity_failure());
    }
    if !provider.supports_destroy_version {
        return Err(ProviderError::new(ProviderErrorKind::Unsupported));
    }
    let secret = lock_secret(&mut transaction, &record.secret, provider_id).await?;
    if !record.secret.matches(
        &secret.canonical_name,
        &secret.scope_kind,
        secret.repository_id,
        secret.environment_id,
    ) {
        return Err(ProviderError::new(ProviderErrorKind::NotFound));
    }

    let request_winner: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT secret_version_id
        FROM secret_version_lifecycle
        WHERE tenant_id = $1 AND provider_id = $2 AND destroy_request_id = $3
        FOR UPDATE
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(provider_id)
    .bind(&record.request_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    if request_winner.is_some_and(|winner| winner != record.version_id) {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }

    let row = sqlx::query_as::<_, DestroyRow>(
        r"
        SELECT
            v.secret_id, v.storage_kind,
            l.status AS lifecycle_status, l.destroy_request_id,
            l.revision AS lifecycle_revision, l.changed_at_ms
        FROM secret_versions v
        JOIN secret_version_lifecycle l
          ON l.tenant_id = v.tenant_id AND l.secret_version_id = v.id
        WHERE v.tenant_id = $1 AND v.id = $2 AND v.secret_id = $3
          AND v.provider_id = $4
        FOR UPDATE OF v, l
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.version_id)
    .bind(record.secret.secret_id())
    .bind(provider_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ProviderError::new(ProviderErrorKind::NotFound))?;
    if row.secret_id != record.secret.secret_id() || row.storage_kind != BUILTIN_STORAGE_KIND {
        return Err(ProviderError::new(ProviderErrorKind::NotFound));
    }
    if row.lifecycle_status == "destroyed" {
        if row.destroy_request_id.as_deref() != Some(&record.request_id) {
            return Err(ProviderError::new(ProviderErrorKind::Conflict));
        }
        ensure_crypto_erased(
            &mut transaction,
            record.secret.tenant_id(),
            record.version_id,
        )
        .await?;
        transaction.commit().await.map_err(map_sql_error)?;
        return Ok(());
    }
    if row.lifecycle_status == "destroy_pending"
        && row.destroy_request_id.as_deref() != Some(&record.request_id)
    {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    if row.lifecycle_status == "staged" {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    if secret.current_version_id == Some(record.version_id)
        && !matches!(secret.status.as_str(), "disabled" | "deleted")
    {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }

    let operation_time = database_time(&mut transaction).await?;
    let mut lifecycle_revision = row.lifecycle_revision;
    if row.lifecycle_status != "destroy_pending" {
        if !matches!(
            row.lifecycle_status.as_str(),
            "active" | "superseded" | "disabled"
        ) {
            return Err(integrity_failure());
        }
        let update = sqlx::query(
            r"
            UPDATE secret_version_lifecycle
            SET status = 'destroy_pending', destroy_request_id = $3,
                revision = revision + 1,
                changed_at_ms = GREATEST(changed_at_ms, $4)
            WHERE tenant_id = $1 AND secret_version_id = $2 AND revision = $5
            ",
        )
        .bind(record.secret.tenant_id())
        .bind(record.version_id)
        .bind(&record.request_id)
        .bind(operation_time)
        .bind(lifecycle_revision)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
        if update.rows_affected() != 1 {
            return Err(ProviderError::new(ProviderErrorKind::Conflict));
        }
        lifecycle_revision = lifecycle_revision
            .checked_add(1)
            .ok_or_else(integrity_failure)?;
    }

    for statement in [
        "DELETE FROM secret_provider_version_envelope_heads WHERE tenant_id = $1 AND secret_version_id = $2",
        "DELETE FROM secret_version_envelope_heads WHERE tenant_id = $1 AND secret_version_id = $2",
        "DELETE FROM secret_provider_version_envelopes WHERE tenant_id = $1 AND secret_version_id = $2",
        "DELETE FROM secret_version_envelopes WHERE tenant_id = $1 AND secret_version_id = $2",
    ] {
        sqlx::query(statement)
            .bind(record.secret.tenant_id())
            .bind(record.version_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sql_error)?;
    }
    ensure_crypto_erased(
        &mut transaction,
        record.secret.tenant_id(),
        record.version_id,
    )
    .await?;
    let final_update = sqlx::query(
        r"
        UPDATE secret_version_lifecycle
        SET status = 'destroyed', revision = revision + 1,
            changed_at_ms = GREATEST(changed_at_ms, $3),
            destroyed_at_ms = GREATEST(changed_at_ms, $3)
        WHERE tenant_id = $1 AND secret_version_id = $2 AND revision = $4
          AND status = 'destroy_pending' AND destroy_request_id = $5
        ",
    )
    .bind(record.secret.tenant_id())
    .bind(record.version_id)
    .bind(operation_time.max(row.changed_at_ms))
    .bind(lifecycle_revision)
    .bind(&record.request_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    if final_update.rows_affected() != 1 {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    transaction.commit().await.map_err(map_sql_error)
}

async fn load_existing_version(
    transaction: &mut Transaction<'static, Postgres>,
    tenant_id: &str,
    provider_id: &str,
    request_id: &str,
) -> Result<Option<ExistingVersionRow>, ProviderError> {
    sqlx::query_as::<_, ExistingVersionRow>(
        r"
        SELECT
            winner.id, winner.secret_id, winner.version_number,
            winner.storage_kind,
            lifecycle.mutation_id, lifecycle.status AS lifecycle_status,
            (
                SELECT count(*)
                FROM secret_version_envelope_heads AS head
                JOIN secret_version_envelopes AS envelope
                  ON envelope.tenant_id = head.tenant_id
                 AND envelope.secret_version_id = head.secret_version_id
                 AND envelope.envelope_generation = head.envelope_generation
                WHERE head.tenant_id = winner.tenant_id
                  AND head.secret_version_id = winner.id
            ) AS builtin_envelope_count,
            (
                (SELECT count(*) FROM secret_provider_locator_envelopes
                 WHERE tenant_id = winner.tenant_id
                   AND secret_id = winner.secret_id)
              + (SELECT count(*) FROM secret_provider_locator_envelope_heads
                 WHERE tenant_id = winner.tenant_id
                   AND secret_id = winner.secret_id)
              + (SELECT count(*) FROM secret_provider_version_envelopes
                 WHERE tenant_id = winner.tenant_id
                   AND secret_version_id = winner.id)
              + (SELECT count(*) FROM secret_provider_version_envelope_heads
                 WHERE tenant_id = winner.tenant_id
                   AND secret_version_id = winner.id)
            ) AS external_reference_count
        FROM secret_versions AS winner
        JOIN secret_version_lifecycle AS lifecycle
          ON lifecycle.tenant_id = winner.tenant_id
         AND lifecycle.secret_version_id = winner.id
        WHERE winner.tenant_id = $1 AND winner.provider_id = $2
          AND winner.create_request_id = $3
        FOR SHARE OF winner, lifecycle
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

async fn has_pending_expired_cleanup(
    transaction: &mut Transaction<'static, Postgres>,
    tenant_id: &str,
    secret_id: Uuid,
) -> Result<bool, ProviderError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM secret_version_lifecycle AS lifecycle
            JOIN secret_version_mutations AS mutation
              ON mutation.tenant_id = lifecycle.tenant_id
             AND mutation.mutation_id = lifecycle.mutation_id
            JOIN secret_version_envelope_heads AS head
              ON head.tenant_id = lifecycle.tenant_id
             AND head.secret_version_id = lifecycle.secret_version_id
            WHERE lifecycle.tenant_id = $1
              AND lifecycle.secret_id = $2
              AND lifecycle.status = 'destroy_pending'
              AND mutation.state = 'cancelled'
              AND mutation.completion_kind = 'reservation_expired'
              AND mutation.abandoned_version_id = lifecycle.secret_version_id
              AND mutation.abandoned_version_number = lifecycle.version_number
        )
        ",
    )
    .bind(tenant_id)
    .bind(secret_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)
}

fn validate_staged_replay(
    secret: &ValidatedSecretDescriptor,
    expected_current_version_id: Option<Uuid>,
    mutation_id: Uuid,
    mutation: &MutationRow,
    existing: &ExistingVersionRow,
) -> Result<(), ProviderError> {
    if existing.secret_id != secret.secret_id()
        || existing.storage_kind != BUILTIN_STORAGE_KIND
        || existing.version_number <= 0
    {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    if mutation.state == "cancelled"
        && mutation.completion_kind.as_deref() == Some("reservation_expired")
        && mutation.abandoned_version_id == Some(existing.id)
        && mutation.abandoned_version_number == Some(existing.version_number)
        && matches!(
            existing.lifecycle_status.as_str(),
            "destroy_pending" | "destroyed"
        )
    {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    if existing.mutation_id != mutation_id
        || existing.lifecycle_status != "staged"
        || existing.builtin_envelope_count != 1
        || existing.external_reference_count != 0
    {
        return Err(integrity_failure());
    }
    if mutation.state != "reserved"
        || expected_current_version_id != mutation.expected_predecessor_version_id
        || existing.version_number != mutation.reserved_version_number
    {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    match (
        mutation.mutation_kind.as_str(),
        mutation.expected_predecessor_version_id,
        mutation.expected_predecessor_version_number,
    ) {
        ("create", None, None) => {
            if existing.version_number == 1 && expected_current_version_id.is_none() {
                Ok(())
            } else {
                Err(integrity_failure())
            }
        }
        ("replace", Some(predecessor_id), Some(predecessor_number)) if predecessor_number > 0 => {
            if expected_current_version_id == Some(predecessor_id)
                && existing.version_number == mutation.reserved_version_number
                && existing.version_number > predecessor_number
            {
                Ok(())
            } else {
                Err(integrity_failure())
            }
        }
        _ => Err(integrity_failure()),
    }
}

fn validate_reconciliation_predecessor(
    expected_current_version_id: Option<Uuid>,
    mutation: &MutationRow,
) -> Result<(), ProviderError> {
    let durable_predecessor = match mutation.mutation_kind.as_str() {
        "create"
            if mutation.expected_secret_revision.is_none()
                && mutation.reserved_secret_revision == 1
                && mutation.reserved_version_number == 1
                && mutation.expected_predecessor_version_id.is_none()
                && mutation.expected_predecessor_version_number.is_none() =>
        {
            None
        }
        "replace"
            if mutation.expected_secret_revision == Some(mutation.reserved_secret_revision)
                && mutation.reserved_secret_revision > 0
                && mutation
                    .expected_predecessor_version_number
                    .is_some_and(|number| {
                        number > 0 && mutation.reserved_version_number > number
                    }) =>
        {
            Some(
                mutation
                    .expected_predecessor_version_id
                    .ok_or_else(integrity_failure)?,
            )
        }
        _ => return Err(integrity_failure()),
    };
    if expected_current_version_id == durable_predecessor {
        Ok(())
    } else {
        Err(ProviderError::new(ProviderErrorKind::Conflict))
    }
}

fn validate_reconciled_version(
    secret: &ValidatedSecretDescriptor,
    mutation_id: Uuid,
    mutation: &MutationRow,
    existing: &ExistingVersionRow,
) -> Result<(), ProviderError> {
    if existing.id.is_nil()
        || existing.secret_id != secret.secret_id()
        || existing.storage_kind != BUILTIN_STORAGE_KIND
        || existing.version_number != mutation.reserved_version_number
        || existing.version_number <= 0
        || existing.mutation_id != mutation_id
        || existing.external_reference_count != 0
    {
        return Err(integrity_failure());
    }
    let expected_envelope_count = i64::from(existing.lifecycle_status != "destroyed");
    if existing.builtin_envelope_count != expected_envelope_count {
        return Err(integrity_failure());
    }

    let exact_receipt = mutation.committed_version_id == Some(existing.id)
        && mutation.committed_version_number == Some(existing.version_number);
    let no_receipt =
        mutation.committed_version_id.is_none() && mutation.committed_version_number.is_none();
    let exact_abandoned = mutation.abandoned_version_id == Some(existing.id)
        && mutation.abandoned_version_number == Some(existing.version_number);
    let no_abandoned =
        mutation.abandoned_version_id.is_none() && mutation.abandoned_version_number.is_none();
    let valid = match (mutation.state.as_str(), mutation.completion_kind.as_deref()) {
        ("reserved", None) => {
            no_receipt
                && no_abandoned
                && mutation.terminal_reason.is_none()
                && existing.lifecycle_status == "staged"
        }
        ("confirmed", Some("builtin_created")) => {
            exact_receipt
                && no_abandoned
                && mutation.terminal_reason.is_none()
                && existing.lifecycle_status == "active"
        }
        ("superseded", Some("builtin_created")) => {
            exact_receipt
                && no_abandoned
                && matches!(
                    mutation.terminal_reason.as_deref(),
                    Some("applied_then_superseded" | "applied_then_deleted")
                )
                && matches!(
                    existing.lifecycle_status.as_str(),
                    "superseded" | "disabled" | "destroy_pending" | "destroyed"
                )
        }
        ("cancelled", Some("system_cancelled")) => {
            no_receipt
                && no_abandoned
                && mutation.terminal_reason.as_deref() == Some("secret_deleted")
                && matches!(
                    existing.lifecycle_status.as_str(),
                    "destroy_pending" | "destroyed"
                )
        }
        ("cancelled", Some("reservation_expired")) => {
            no_receipt
                && exact_abandoned
                && mutation.terminal_reason.as_deref() == Some("reservation_expired_staged")
                && matches!(
                    existing.lifecycle_status.as_str(),
                    "destroy_pending" | "destroyed"
                )
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

fn validate_definitive_absence(
    secret: &SecretRow,
    mutation: &MutationRow,
    observed_at_ms: i64,
) -> Result<(), ProviderError> {
    let no_receipt =
        mutation.committed_version_id.is_none() && mutation.committed_version_number.is_none();
    let no_abandoned =
        mutation.abandoned_version_id.is_none() && mutation.abandoned_version_number.is_none();
    match (mutation.state.as_str(), mutation.completion_kind.as_deref()) {
        ("reserved", None) if no_receipt && no_abandoned && mutation.terminal_reason.is_none() => {
            validate_reserved_head(mutation.expected_predecessor_version_id, secret, mutation)?;
            if observed_at_ms < mutation.confirmation_deadline_ms {
                Err(ProviderError::new(ProviderErrorKind::Unavailable))
            } else {
                Ok(())
            }
        }
        ("cancelled", Some("cas_lost"))
            if no_receipt
                && no_abandoned
                && mutation.terminal_reason.as_deref() == Some("cas_lost") =>
        {
            Ok(())
        }
        ("cancelled", Some("system_cancelled"))
            if no_receipt
                && no_abandoned
                && mutation.terminal_reason.as_deref() == Some("secret_deleted")
                && secret.status == "deleted" =>
        {
            Ok(())
        }
        ("cancelled", Some("reservation_expired"))
            if no_receipt
                && no_abandoned
                && mutation.terminal_reason.as_deref() == Some("reservation_expired_no_stage") =>
        {
            Ok(())
        }
        _ => Err(integrity_failure()),
    }
}

fn validate_reserved_head(
    expected_current_version_id: Option<Uuid>,
    secret: &SecretRow,
    mutation: &MutationRow,
) -> Result<(), ProviderError> {
    if mutation.state != "reserved" || secret.revision != mutation.reserved_secret_revision {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    match (
        mutation.mutation_kind.as_str(),
        mutation.expected_secret_revision,
        mutation.expected_predecessor_version_id,
        mutation.expected_predecessor_version_number,
    ) {
        ("create", None, None, None) => {
            if mutation.reserved_secret_revision == 1
                && secret.status == "provisioning"
                && secret.current_version_id.is_none()
                && secret.current_version_number.is_none()
                && expected_current_version_id.is_none()
            {
                Ok(())
            } else {
                Err(ProviderError::new(ProviderErrorKind::Conflict))
            }
        }
        ("replace", Some(expected_revision), Some(predecessor_id), Some(predecessor_number))
            if predecessor_number > 0 =>
        {
            if expected_revision == mutation.reserved_secret_revision
                && secret.status == "active"
                && secret.current_version_id == Some(predecessor_id)
                && secret.current_version_number == Some(predecessor_number)
                && expected_current_version_id == Some(predecessor_id)
            {
                Ok(())
            } else {
                Err(ProviderError::new(ProviderErrorKind::Conflict))
            }
        }
        _ => Err(integrity_failure()),
    }
}

async fn lock_provider(
    transaction: &mut Transaction<'static, Postgres>,
    tenant_id: &str,
    provider_id: &str,
) -> Result<ProviderRow, ProviderError> {
    sqlx::query_as::<_, ProviderRow>(
        r"
        SELECT adapter_kind, status, supports_create_version, supports_destroy_version
        FROM secret_providers
        WHERE tenant_id = $1 AND provider_id = $2
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(provider_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ProviderError::new(ProviderErrorKind::NotFound))
}

async fn lock_mutation(
    transaction: &mut Transaction<'static, Postgres>,
    tenant_id: &str,
    mutation_id: Uuid,
) -> Result<MutationRow, ProviderError> {
    sqlx::query_as::<_, MutationRow>(
        r"
        SELECT secret_id, scope_kind, repository_id, environment_id,
               canonical_name, provider_id, mutation_kind,
               expected_secret_revision, reserved_secret_revision,
               reserved_version_number, reserved_at_ms,
               confirmation_deadline_ms,
               expected_predecessor_version_id,
               expected_predecessor_version_number,
               provider_create_request_id, state, completion_kind,
               committed_version_id, committed_version_number, terminal_reason,
               abandoned_version_id, abandoned_version_number
        FROM secret_version_mutations
        WHERE tenant_id = $1 AND mutation_id = $2
        FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(mutation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ProviderError::new(ProviderErrorKind::Conflict))
}

fn mutation_id_from_request_id(request_id: &str) -> Result<Uuid, ProviderError> {
    let encoded = request_id
        .strip_prefix(VERSION_MUTATION_REQUEST_PREFIX)
        .ok_or_else(|| ProviderError::new(ProviderErrorKind::InvalidRequest))?;
    let mutation_id = Uuid::parse_str(encoded)
        .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))?;
    if mutation_id.is_nil() || mutation_id.hyphenated().to_string() != encoded {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    Ok(mutation_id)
}

fn validate_mutation(
    secret: &ValidatedSecretDescriptor,
    request_id: &str,
    provider_id: &str,
    mutation_id: Uuid,
    mutation: &MutationRow,
) -> Result<(), ProviderError> {
    let expected_request_id = format!(
        "{VERSION_MUTATION_REQUEST_PREFIX}{}",
        mutation_id.hyphenated()
    );
    if mutation.provider_id != provider_id
        || mutation.provider_create_request_id != expected_request_id
        || !matches!(
            mutation.state.as_str(),
            "reserved" | "confirmed" | "superseded" | "cancelled"
        )
    {
        return Err(integrity_failure());
    }
    if request_id != expected_request_id
        || mutation.secret_id != secret.secret_id()
        || !secret.matches(
            &mutation.canonical_name,
            &mutation.scope_kind,
            mutation.repository_id,
            mutation.environment_id,
        )
    {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    Ok(())
}

fn ensure_reservation_is_live(
    mutation: &MutationRow,
    observed_at_ms: i64,
) -> Result<(), ProviderError> {
    validate_confirmation_deadline(mutation)?;
    if observed_at_ms >= mutation.confirmation_deadline_ms {
        return Err(ProviderError::new(ProviderErrorKind::Conflict));
    }
    Ok(())
}

fn validate_confirmation_deadline(mutation: &MutationRow) -> Result<(), ProviderError> {
    let confirmation_ttl_millis =
        i64::try_from(SECRET_MUTATION_CONFIRMATION_TTL_MILLIS).map_err(|_| integrity_failure())?;
    let expected_deadline = mutation
        .reserved_at_ms
        .checked_add(confirmation_ttl_millis)
        .ok_or_else(integrity_failure)?;
    if mutation.reserved_at_ms < 0 || mutation.confirmation_deadline_ms != expected_deadline {
        return Err(integrity_failure());
    }
    Ok(())
}

async fn lock_secret(
    transaction: &mut Transaction<'static, Postgres>,
    secret: &ValidatedSecretDescriptor,
    provider_id: &str,
) -> Result<SecretRow, ProviderError> {
    sqlx::query_as::<_, SecretRow>(
        r"
        SELECT canonical_name, scope_kind, repository_id, environment_id,
               current_version_id, current_version_number, status, revision
        FROM secrets
        WHERE tenant_id = $1 AND id = $2 AND provider_id = $3
        FOR UPDATE
        ",
    )
    .bind(secret.tenant_id())
    .bind(secret.secret_id())
    .bind(provider_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ProviderError::new(ProviderErrorKind::NotFound))
}

async fn database_time(
    transaction: &mut Transaction<'static, Postgres>,
) -> Result<i64, ProviderError> {
    sqlx::query_scalar("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT")
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_sql_error)
}

async fn ensure_crypto_erased(
    transaction: &mut Transaction<'static, Postgres>,
    tenant_id: &str,
    version_id: Uuid,
) -> Result<(), ProviderError> {
    let count: i64 = sqlx::query_scalar(
        r"
        SELECT
            (SELECT count(*) FROM secret_version_envelopes
             WHERE tenant_id = $1 AND secret_version_id = $2)
          + (SELECT count(*) FROM secret_version_envelope_heads
             WHERE tenant_id = $1 AND secret_version_id = $2)
          + (SELECT count(*) FROM secret_provider_version_envelopes
             WHERE tenant_id = $1 AND secret_version_id = $2)
          + (SELECT count(*) FROM secret_provider_version_envelope_heads
             WHERE tenant_id = $1 AND secret_version_id = $2)
        ",
    )
    .bind(tenant_id)
    .bind(version_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sql_error)?;
    if count == 0 {
        Ok(())
    } else {
        Err(integrity_failure())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_sql_error(error: SqlxError) -> ProviderError {
    let is_integrity_failure = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code.starts_with("23"));
    let kind = if is_integrity_failure {
        ProviderErrorKind::IntegrityFailure
    } else {
        ProviderErrorKind::Unavailable
    };
    ProviderError::new(kind)
}

fn integrity_failure() -> ProviderError {
    ProviderError::new(ProviderErrorKind::IntegrityFailure)
}

fn envelope_from_parts(
    schema: i32,
    wrapping_key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<EncryptedEnvelope, ProviderError> {
    let schema = u16::try_from(schema).map_err(|_| integrity_failure())?;
    let key_id = KeyId::new(wrapping_key_id).map_err(|_| integrity_failure())?;
    let wrapped = WrappedDataKey::new(key_id, wrapped_data_key).map_err(|_| integrity_failure())?;
    let nonce: [u8; ENVELOPE_NONCE_BYTES] = nonce.try_into().map_err(|_| integrity_failure())?;
    EncryptedEnvelope::from_parts(schema, wrapped, nonce, ciphertext)
        .map_err(|_error: EnvelopeError| integrity_failure())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use automata_ci_key_management::{
        EnvelopeCodec, EnvelopeError, KeyEncryptionContext, KeyEncryptionError, KeyId, KeyPurpose,
        LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
    };

    use super::{EnvelopeSqlParameters, envelope_from_parts};

    fn codec() -> EnvelopeCodec {
        let key = LocalKeyMaterial::new(
            KeyId::new("secret-test-kek-v1").unwrap(),
            SecretBytes::new(vec![0x71; 32]).unwrap(),
        )
        .unwrap();
        EnvelopeCodec::new(Arc::new(
            LocalAes256GcmKeyring::new(key, Vec::new(), []).unwrap(),
        ))
    }

    fn context(tenant_id: &str, version_id: &str) -> KeyEncryptionContext {
        KeyEncryptionContext::new(
            tenant_id,
            KeyPurpose::new("secrets/builtin-value:v1").unwrap(),
            version_id,
        )
        .unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
    }

    #[tokio::test]
    async fn exact_sql_byte_parameters_are_ciphertext_only_and_redacted() {
        let sentinel = b"plaintext-sql-parameter-sentinel-4f28c6dd18d74548";
        let context = context("tenant-a", "01234567-89ab-4def-8123-456789abcdef");
        let envelope = codec()
            .seal(
                &context,
                SecretBytes::new(sentinel.to_vec()).expect("valid sentinel"),
            )
            .await
            .unwrap();
        let parameters = EnvelopeSqlParameters::from_envelope(envelope).unwrap();

        assert!(!contains(&parameters.ciphertext, sentinel));
        assert!(!contains(&parameters.wrapped_data_key, sentinel));
        assert!(!contains(&parameters.nonce, sentinel));
        let debug = format!("{parameters:?}");
        assert!(!debug.contains(std::str::from_utf8(sentinel).unwrap()));
        assert!(!debug.contains(&format!("{:?}", parameters.ciphertext)));
        assert!(debug.contains("[OPAQUE]"));
    }

    #[tokio::test]
    async fn persisted_payload_rejects_tenant_record_and_bit_flip_swaps() {
        let codec = codec();
        let expected = context("tenant-a", "01234567-89ab-4def-8123-456789abcdef");
        let envelope = codec
            .seal(
                &expected,
                SecretBytes::from_utf8("sensitive".into()).unwrap(),
            )
            .await
            .unwrap();
        for wrong in [
            context("tenant-b", "01234567-89ab-4def-8123-456789abcdef"),
            context("tenant-a", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        ] {
            assert!(matches!(
                codec.open(&wrong, &envelope).await,
                Err(
                    EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed)
                        | EnvelopeError::AuthenticationFailed
                )
            ));
        }

        let mut parameters = EnvelopeSqlParameters::from_envelope(envelope).unwrap();
        parameters.ciphertext[0] ^= 0x80;
        let tampered = envelope_from_parts(
            parameters.schema,
            parameters.wrapping_key_id,
            parameters.wrapped_data_key,
            parameters.nonce,
            parameters.ciphertext,
        )
        .unwrap();
        assert!(matches!(
            codec.open(&expected, &tampered).await,
            Err(EnvelopeError::AuthenticationFailed)
        ));
    }
}
