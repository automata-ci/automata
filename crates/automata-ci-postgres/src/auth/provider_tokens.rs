use std::{collections::BTreeSet, fmt, sync::Arc};

use automata_ci_auth::{
    human::{ProviderId, ProviderSubject},
    secret::SecretString,
    time::UnixTimestamp,
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenKey,
        ProviderTokenMetadata, ProviderTokenRevocationReason, ProviderTokenSet, ProviderTokenVault,
        ProviderTokenVaultError, TokenVersion, VaultFuture, VersionedProviderTokens,
    },
};
use automata_ci_key_management::{
    EncryptedEnvelope, EnvelopeCodec, EnvelopeError, KeyEncryptionContext, KeyEncryptionError,
    KeyEncryptionProvider, KeyId, KeyPurpose, SecretBytes, WrappedDataKey,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::support::{
    is_integrity_violation, timestamp_from_milliseconds, timestamp_to_milliseconds,
};

const PROVIDER_TOKEN_PURPOSE: &str = "auth/provider-token:v1";
const PROVIDER_TOKEN_PAYLOAD_SCHEMA: u8 = 1;

/// PostgreSQL-backed authenticated custody for provider OAuth credentials.
#[derive(Clone)]
pub struct PostgresProviderTokenVault {
    pool: PgPool,
    codec: Arc<EnvelopeCodec>,
    purpose: KeyPurpose,
}

impl PostgresProviderTokenVault {
    /// Creates a vault using the supplied pluggable wrapping-key provider.
    ///
    /// # Panics
    ///
    /// Panics only if the static provider-token encryption purpose is invalid.
    #[must_use]
    pub fn new(pool: PgPool, provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        let purpose = KeyPurpose::new(PROVIDER_TOKEN_PURPOSE)
            .expect("the static provider-token encryption purpose is valid");
        Self {
            pool,
            codec: Arc::new(EnvelopeCodec::new(provider)),
            purpose,
        }
    }

    fn context(
        &self,
        key: &ProviderTokenKey,
        record_id: Uuid,
        version: TokenVersion,
    ) -> Result<KeyEncryptionContext, ProviderTokenVaultError> {
        KeyEncryptionContext::new(
            key.tenant_id().as_str(),
            self.purpose.clone(),
            format!("{record_id}/version/{}", version.value()),
        )
        .map_err(|_| ProviderTokenVaultError::InvalidRequest)
    }

    async fn seal(
        &self,
        key: &ProviderTokenKey,
        record_id: Uuid,
        version: TokenVersion,
        tokens: &ProviderTokenSet,
    ) -> Result<EnvelopeParameters, ProviderTokenVaultError> {
        validate_tokens_for_key(key, tokens)?;
        let plaintext = encode_payload(tokens)?;
        let context = self.context(key, record_id, version)?;
        let envelope = self
            .codec
            .seal(&context, plaintext)
            .await
            .map_err(map_seal_error)?;
        Ok(EnvelopeParameters::from_envelope(envelope))
    }

    async fn open(
        &self,
        key: &ProviderTokenKey,
        row: &ProviderTokenRow,
    ) -> Result<ProviderTokenSet, ProviderTokenVaultError> {
        let version = row.version()?;
        let context = self.context(key, row.envelope_record_id, version)?;
        let envelope = row.envelope()?;
        let plaintext = self
            .codec
            .open(&context, &envelope)
            .await
            .map_err(map_open_error)?;
        let expected_metadata = row.metadata()?;
        decode_payload(key, &expected_metadata, plaintext.expose_secret())
    }
}

impl fmt::Debug for PostgresProviderTokenVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresProviderTokenVault")
            .field("encryption_purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct ProviderTokenRow {
    envelope_record_id: Uuid,
    tenant_id: String,
    provider_id: String,
    provider_subject: String,
    version: i64,
    grant_kind: String,
    token_type: String,
    scopes: Vec<String>,
    encrypted_payload: Option<Vec<u8>>,
    payload_nonce: Option<Vec<u8>>,
    wrapped_data_key: Option<Vec<u8>>,
    encryption_key_id: Option<String>,
    encryption_schema: Option<i32>,
    issued_at_ms: i64,
    access_expires_at_ms: Option<i64>,
    refresh_expires_at_ms: Option<i64>,
}

impl ProviderTokenRow {
    fn version(&self) -> Result<TokenVersion, ProviderTokenVaultError> {
        u64::try_from(self.version)
            .ok()
            .and_then(|value| TokenVersion::new(value).ok())
            .ok_or(ProviderTokenVaultError::IntegrityFailure)
    }

    fn envelope(&self) -> Result<EncryptedEnvelope, ProviderTokenVaultError> {
        let schema = self
            .encryption_schema
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(ProviderTokenVaultError::IntegrityFailure)?;
        let key_id = self
            .encryption_key_id
            .as_ref()
            .and_then(|value| KeyId::new(value.clone()).ok())
            .ok_or(ProviderTokenVaultError::IntegrityFailure)?;
        let wrapped_key = WrappedDataKey::new(
            key_id,
            self.wrapped_data_key
                .clone()
                .ok_or(ProviderTokenVaultError::IntegrityFailure)?,
        )
        .map_err(|_| ProviderTokenVaultError::IntegrityFailure)?;
        let nonce: [u8; 12] = self
            .payload_nonce
            .as_deref()
            .ok_or(ProviderTokenVaultError::IntegrityFailure)?
            .try_into()
            .map_err(|_| ProviderTokenVaultError::IntegrityFailure)?;
        EncryptedEnvelope::from_parts(
            schema,
            wrapped_key,
            nonce,
            self.encrypted_payload
                .clone()
                .ok_or(ProviderTokenVaultError::IntegrityFailure)?,
        )
        .map_err(|_| ProviderTokenVaultError::IntegrityFailure)
    }

    fn metadata(&self) -> Result<ProviderTokenMetadata, ProviderTokenVaultError> {
        let provider_id = ProviderId::new(self.provider_id.clone())
            .map_err(|_| ProviderTokenVaultError::IntegrityFailure)?;
        let provider_subject = ProviderSubject::new(self.provider_subject.clone())
            .map_err(|_| ProviderTokenVaultError::IntegrityFailure)?;
        let grant_kind = grant_kind_from_database(&self.grant_kind)?;
        let scopes = self.scopes.iter().cloned().collect::<BTreeSet<_>>();
        if scopes.len() != self.scopes.len() {
            return Err(ProviderTokenVaultError::IntegrityFailure);
        }
        ProviderTokenMetadata::builder(
            provider_id,
            grant_kind,
            self.token_type.clone(),
            timestamp_from_milliseconds(self.issued_at_ms)
                .map_err(|()| ProviderTokenVaultError::IntegrityFailure)?,
        )
        .provider_subject(Some(provider_subject))
        .scopes(scopes)
        .access_expires_at(
            self.access_expires_at_ms
                .map(timestamp_from_milliseconds)
                .transpose()
                .map_err(|()| ProviderTokenVaultError::IntegrityFailure)?,
        )
        .refresh_expires_at(
            self.refresh_expires_at_ms
                .map(timestamp_from_milliseconds)
                .transpose()
                .map_err(|()| ProviderTokenVaultError::IntegrityFailure)?,
        )
        .build()
        .map_err(|_| ProviderTokenVaultError::IntegrityFailure)
    }

    fn matches_key(&self, key: &ProviderTokenKey) -> bool {
        self.tenant_id == key.tenant_id().as_str()
            && self.provider_id == key.provider_id().as_str()
            && self.provider_subject == key.provider_subject().as_str()
    }
}

struct EnvelopeParameters {
    schema: i32,
    key_id: String,
    wrapped_data_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EnvelopeParameters {
    fn from_envelope(envelope: EncryptedEnvelope) -> Self {
        let (schema, wrapped_key, nonce, ciphertext) = envelope.into_parts();
        let (key_id, wrapped_data_key) = wrapped_key.into_parts();
        Self {
            schema: i32::from(schema),
            key_id: key_id.as_str().to_owned(),
            wrapped_data_key,
            nonce: nonce.to_vec(),
            ciphertext,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct EncodedProviderTokenPayload<'a> {
    schema: u8,
    access_token: &'a str,
    refresh_token: Option<&'a str>,
    provider_id: &'a ProviderId,
    provider_subject: Option<&'a ProviderSubject>,
    grant_kind: ProviderGrantKind,
    token_type: &'a str,
    scopes: &'a BTreeSet<String>,
    issued_at: u64,
    access_expires_at: Option<u64>,
    refresh_expires_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct DecodedProviderTokenPayload {
    schema: u8,
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    provider_id: ProviderId,
    provider_subject: Option<ProviderSubject>,
    grant_kind: ProviderGrantKind,
    token_type: String,
    scopes: BTreeSet<String>,
    issued_at: u64,
    access_expires_at: Option<u64>,
    refresh_expires_at: Option<u64>,
}

fn encode_payload(tokens: &ProviderTokenSet) -> Result<SecretBytes, ProviderTokenVaultError> {
    let metadata = tokens.metadata();
    let payload = EncodedProviderTokenPayload {
        schema: PROVIDER_TOKEN_PAYLOAD_SCHEMA,
        access_token: tokens.access_token().expose_secret(),
        refresh_token: tokens
            .refresh_token()
            .map(ProviderRefreshToken::expose_secret),
        provider_id: metadata.provider_id(),
        provider_subject: metadata.provider_subject(),
        grant_kind: metadata.grant_kind(),
        token_type: metadata.token_type(),
        scopes: metadata.scopes(),
        issued_at: metadata.issued_at().as_seconds(),
        access_expires_at: metadata.access_expires_at().map(UnixTimestamp::as_seconds),
        refresh_expires_at: metadata.refresh_expires_at().map(UnixTimestamp::as_seconds),
    };
    let bytes =
        serde_json::to_vec(&payload).map_err(|_| ProviderTokenVaultError::InvalidRequest)?;
    SecretBytes::new(bytes).map_err(|_| ProviderTokenVaultError::InvalidRequest)
}

fn decode_payload(
    key: &ProviderTokenKey,
    expected: &ProviderTokenMetadata,
    plaintext: &[u8],
) -> Result<ProviderTokenSet, ProviderTokenVaultError> {
    let payload: DecodedProviderTokenPayload =
        serde_json::from_slice(plaintext).map_err(|_| ProviderTokenVaultError::IntegrityFailure)?;
    if payload.schema != PROVIDER_TOKEN_PAYLOAD_SCHEMA {
        return Err(ProviderTokenVaultError::IntegrityFailure);
    }
    let metadata = ProviderTokenMetadata::builder(
        payload.provider_id,
        payload.grant_kind,
        payload.token_type,
        UnixTimestamp::from_seconds(payload.issued_at),
    )
    .provider_subject(payload.provider_subject)
    .scopes(payload.scopes)
    .access_expires_at(payload.access_expires_at.map(UnixTimestamp::from_seconds))
    .refresh_expires_at(payload.refresh_expires_at.map(UnixTimestamp::from_seconds))
    .build()
    .map_err(|_| ProviderTokenVaultError::IntegrityFailure)?;
    if &metadata != expected
        || metadata.provider_id() != key.provider_id()
        || metadata.provider_subject() != Some(key.provider_subject())
    {
        return Err(ProviderTokenVaultError::IntegrityFailure);
    }
    ProviderTokenSet::new(
        ProviderAccessToken::new(payload.access_token),
        payload.refresh_token.map(ProviderRefreshToken::new),
        metadata,
    )
    .map_err(|_| ProviderTokenVaultError::IntegrityFailure)
}

fn validate_tokens_for_key(
    key: &ProviderTokenKey,
    tokens: &ProviderTokenSet,
) -> Result<(), ProviderTokenVaultError> {
    let metadata = tokens.metadata();
    if metadata.provider_id() != key.provider_id()
        || metadata.provider_subject() != Some(key.provider_subject())
    {
        return Err(ProviderTokenVaultError::InvalidRequest);
    }
    Ok(())
}

fn grant_kind_to_database(value: ProviderGrantKind) -> &'static str {
    match value {
        ProviderGrantKind::BrowserAuthorizationCode => "browser_authorization_code",
        ProviderGrantKind::DeviceAuthorization => "device_authorization",
    }
}

fn grant_kind_from_database(value: &str) -> Result<ProviderGrantKind, ProviderTokenVaultError> {
    match value {
        "browser_authorization_code" => Ok(ProviderGrantKind::BrowserAuthorizationCode),
        "device_authorization" => Ok(ProviderGrantKind::DeviceAuthorization),
        _ => Err(ProviderTokenVaultError::IntegrityFailure),
    }
}

fn version_to_i64(version: TokenVersion) -> Result<i64, ProviderTokenVaultError> {
    i64::try_from(version.value()).map_err(|_| ProviderTokenVaultError::InvalidRequest)
}

fn map_seal_error(error: EnvelopeError) -> ProviderTokenVaultError {
    match error {
        EnvelopeError::RandomnessUnavailable
        | EnvelopeError::CryptographicFailure
        | EnvelopeError::KeyEncryption(
            KeyEncryptionError::Unavailable | KeyEncryptionError::RandomnessUnavailable,
        ) => ProviderTokenVaultError::Unavailable,
        _ => ProviderTokenVaultError::InvalidRequest,
    }
}

fn map_open_error(error: EnvelopeError) -> ProviderTokenVaultError {
    match error {
        EnvelopeError::KeyEncryption(
            KeyEncryptionError::Unavailable | KeyEncryptionError::RandomnessUnavailable,
        ) => ProviderTokenVaultError::Unavailable,
        _ => ProviderTokenVaultError::IntegrityFailure,
    }
}

fn map_database_error(error: sqlx::Error) -> ProviderTokenVaultError {
    let classified = if is_integrity_violation(&error) {
        ProviderTokenVaultError::InvalidRequest
    } else {
        ProviderTokenVaultError::Unavailable
    };
    drop(error);
    classified
}

const ACTIVE_TOKEN_SELECT_FOR_UPDATE: &str = r"
    SELECT envelope_record_id, tenant_id, provider_id, provider_subject,
           version, grant_kind, token_type, scopes, encrypted_payload,
           payload_nonce, wrapped_data_key, encryption_key_id,
           encryption_schema, issued_at_ms, access_expires_at_ms,
           refresh_expires_at_ms
    FROM human_provider_tokens
    WHERE tenant_id=$1 AND provider_id=$2 AND provider_subject=$3
      AND revoked_at_ms IS NULL
    FOR UPDATE
";

async fn load_active_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    key: &ProviderTokenKey,
) -> Result<Option<ProviderTokenRow>, ProviderTokenVaultError> {
    sqlx::query_as::<_, ProviderTokenRow>(ACTIVE_TOKEN_SELECT_FOR_UPDATE)
        .bind(key.tenant_id().as_str())
        .bind(key.provider_id().as_str())
        .bind(key.provider_subject().as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database_error)
}

async fn has_tombstone<'e, E>(
    executor: E,
    key: &ProviderTokenKey,
) -> Result<bool, ProviderTokenVaultError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM human_provider_tokens
            WHERE tenant_id=$1 AND provider_id=$2 AND provider_subject=$3
              AND revoked_at_ms IS NOT NULL
        )
        ",
    )
    .bind(key.tenant_id().as_str())
    .bind(key.provider_id().as_str())
    .bind(key.provider_subject().as_str())
    .fetch_one(executor)
    .await
    .map_err(map_database_error)
}

impl PostgresProviderTokenVault {
    pub(crate) async fn insert_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key: &ProviderTokenKey,
        tokens: &ProviderTokenSet,
    ) -> Result<TokenVersion, ProviderTokenVaultError> {
        validate_tokens_for_key(key, tokens)?;
        let version = TokenVersion::new(1).map_err(|_| ProviderTokenVaultError::InvalidRequest)?;
        let record_id = Uuid::new_v4();
        let envelope = self.seal(key, record_id, version, tokens).await?;
        let metadata = tokens.metadata();
        let scopes = metadata.scopes().iter().cloned().collect::<Vec<_>>();
        let inserted = sqlx::query(
            r"
            WITH candidate AS (
                SELECT identity.principal_id
                FROM human_provider_identities AS identity
                JOIN tenant_human_memberships AS membership
                  ON membership.principal_id=identity.principal_id
                 AND membership.tenant_id=$1 AND membership.status='active'
                JOIN human_principals AS principal
                  ON principal.id=identity.principal_id AND principal.status='active'
                WHERE identity.provider_id=$2 AND identity.provider_subject=$3
            ), observed AS (
                SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
            )
            INSERT INTO human_provider_tokens (
                envelope_record_id, tenant_id, principal_id, provider_id,
                provider_subject, version, grant_kind, token_type, scopes,
                encrypted_payload, payload_nonce, wrapped_data_key,
                encryption_key_id, encryption_schema, issued_at_ms,
                access_expires_at_ms, refresh_expires_at_ms,
                created_at_ms, updated_at_ms
            )
            SELECT $4, $1, candidate.principal_id, $2, $3, $5, $6, $7,
                   $8, $9, $10, $11, $12, $13, $14, $15, $16,
                   observed.now_ms, observed.now_ms
            FROM candidate CROSS JOIN observed
            ON CONFLICT DO NOTHING
            ",
        )
        .bind(key.tenant_id().as_str())
        .bind(key.provider_id().as_str())
        .bind(key.provider_subject().as_str())
        .bind(record_id)
        .bind(version_to_i64(version)?)
        .bind(grant_kind_to_database(metadata.grant_kind()))
        .bind(metadata.token_type())
        .bind(scopes)
        .bind(&envelope.ciphertext)
        .bind(&envelope.nonce)
        .bind(&envelope.wrapped_data_key)
        .bind(&envelope.key_id)
        .bind(envelope.schema)
        .bind(
            timestamp_to_milliseconds(metadata.issued_at())
                .map_err(|()| ProviderTokenVaultError::InvalidRequest)?,
        )
        .bind(
            metadata
                .access_expires_at()
                .map(timestamp_to_milliseconds)
                .transpose()
                .map_err(|()| ProviderTokenVaultError::InvalidRequest)?,
        )
        .bind(
            metadata
                .refresh_expires_at()
                .map(timestamp_to_milliseconds)
                .transpose()
                .map_err(|()| ProviderTokenVaultError::InvalidRequest)?,
        )
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .rows_affected();
        if inserted == 1 {
            return Ok(version);
        }
        let active: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM human_provider_tokens
                WHERE tenant_id=$1 AND provider_id=$2 AND provider_subject=$3
                  AND revoked_at_ms IS NULL
            )
            ",
        )
        .bind(key.tenant_id().as_str())
        .bind(key.provider_id().as_str())
        .bind(key.provider_subject().as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?;
        Err(if active {
            ProviderTokenVaultError::AlreadyExists
        } else {
            ProviderTokenVaultError::InvalidRequest
        })
    }

    async fn replace_locked_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key: &ProviderTokenKey,
        row: ProviderTokenRow,
        replacement: &ProviderTokenSet,
    ) -> Result<TokenVersion, ProviderTokenVaultError> {
        if !row.matches_key(key) {
            return Err(ProviderTokenVaultError::IntegrityFailure);
        }
        let expected = row.version()?;
        // Full sign-in authorization and refresh replacement both authenticate
        // the current envelope before cryptographically replacing it.
        drop(self.open(key, &row).await?);
        let next_value = expected
            .value()
            .checked_add(1)
            .ok_or(ProviderTokenVaultError::VersionConflict)?;
        let next =
            TokenVersion::new(next_value).map_err(|_| ProviderTokenVaultError::VersionConflict)?;
        let envelope = self
            .seal(key, row.envelope_record_id, next, replacement)
            .await?;
        let metadata = replacement.metadata();
        let scopes = metadata.scopes().iter().cloned().collect::<Vec<_>>();
        let updated = sqlx::query(
            r"
            UPDATE human_provider_tokens
            SET version=$2, grant_kind=$3, token_type=$4, scopes=$5,
                encrypted_payload=$6, payload_nonce=$7, wrapped_data_key=$8,
                encryption_key_id=$9, encryption_schema=$10,
                issued_at_ms=$11, access_expires_at_ms=$12,
                refresh_expires_at_ms=$13,
                updated_at_ms=GREATEST(
                    updated_at_ms,
                    floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                )
            WHERE envelope_record_id=$1 AND version=$14 AND revoked_at_ms IS NULL
            ",
        )
        .bind(row.envelope_record_id)
        .bind(version_to_i64(next)?)
        .bind(grant_kind_to_database(metadata.grant_kind()))
        .bind(metadata.token_type())
        .bind(scopes)
        .bind(&envelope.ciphertext)
        .bind(&envelope.nonce)
        .bind(&envelope.wrapped_data_key)
        .bind(&envelope.key_id)
        .bind(envelope.schema)
        .bind(
            timestamp_to_milliseconds(metadata.issued_at())
                .map_err(|()| ProviderTokenVaultError::InvalidRequest)?,
        )
        .bind(
            metadata
                .access_expires_at()
                .map(timestamp_to_milliseconds)
                .transpose()
                .map_err(|()| ProviderTokenVaultError::InvalidRequest)?,
        )
        .bind(
            metadata
                .refresh_expires_at()
                .map(timestamp_to_milliseconds)
                .transpose()
                .map_err(|()| ProviderTokenVaultError::InvalidRequest)?,
        )
        .bind(version_to_i64(expected)?)
        .execute(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .rows_affected();
        if updated != 1 {
            return Err(ProviderTokenVaultError::VersionConflict);
        }
        Ok(next)
    }

    pub(crate) async fn upsert_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key: &ProviderTokenKey,
        replacement: &ProviderTokenSet,
    ) -> Result<TokenVersion, ProviderTokenVaultError> {
        validate_tokens_for_key(key, replacement)?;
        if let Some(row) = load_active_for_update(transaction, key).await? {
            return self
                .replace_locked_in_transaction(transaction, key, row, replacement)
                .await;
        }
        if has_tombstone(&mut **transaction, key).await? {
            return Err(ProviderTokenVaultError::Revoked);
        }
        match self
            .insert_in_transaction(transaction, key, replacement)
            .await
        {
            Ok(version) => Ok(version),
            Err(ProviderTokenVaultError::AlreadyExists) => {
                let row = load_active_for_update(transaction, key)
                    .await?
                    .ok_or(ProviderTokenVaultError::VersionConflict)?;
                self.replace_locked_in_transaction(transaction, key, row, replacement)
                    .await
            }
            Err(error) => Err(error),
        }
    }
}

impl ProviderTokenVault for PostgresProviderTokenVault {
    fn load<'a>(&'a self, key: &'a ProviderTokenKey) -> VaultFuture<'a, VersionedProviderTokens> {
        Box::pin(async move {
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let Some(row) = load_active_for_update(&mut transaction, key).await? else {
                let revoked = has_tombstone(&mut *transaction, key).await?;
                transaction.commit().await.map_err(map_database_error)?;
                return Err(if revoked {
                    ProviderTokenVaultError::Revoked
                } else {
                    ProviderTokenVaultError::NotFound
                });
            };
            if !row.matches_key(key) {
                return Err(ProviderTokenVaultError::IntegrityFailure);
            }
            let version = row.version()?;
            let tokens = self.open(key, &row).await?;
            transaction.commit().await.map_err(map_database_error)?;
            Ok(VersionedProviderTokens::new(version, tokens))
        })
    }

    fn insert_if_absent<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        tokens: ProviderTokenSet,
    ) -> VaultFuture<'a, TokenVersion> {
        Box::pin(async move {
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let version = self
                .insert_in_transaction(&mut transaction, key, &tokens)
                .await?;
            transaction.commit().await.map_err(map_database_error)?;
            Ok(version)
        })
    }

    fn replace_if_version<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        expected: TokenVersion,
        replacement: ProviderTokenSet,
    ) -> VaultFuture<'a, TokenVersion> {
        Box::pin(async move {
            version_to_i64(expected)?;
            validate_tokens_for_key(key, &replacement)?;
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let Some(row) = load_active_for_update(&mut transaction, key).await? else {
                return Err(if has_tombstone(&mut *transaction, key).await? {
                    ProviderTokenVaultError::Revoked
                } else {
                    ProviderTokenVaultError::NotFound
                });
            };
            if row.version()? != expected {
                return Err(ProviderTokenVaultError::VersionConflict);
            }
            let next = self
                .replace_locked_in_transaction(&mut transaction, key, row, &replacement)
                .await?;
            transaction.commit().await.map_err(map_database_error)?;
            Ok(next)
        })
    }

    fn revoke<'a>(
        &'a self,
        key: &'a ProviderTokenKey,
        reason: ProviderTokenRevocationReason,
    ) -> VaultFuture<'a, ()> {
        Box::pin(async move {
            let revoked = sqlx::query(
                r"
                UPDATE human_provider_tokens
                SET version=version + 1,
                    encrypted_payload=NULL, payload_nonce=NULL,
                    wrapped_data_key=NULL, encryption_key_id=NULL,
                    encryption_schema=NULL,
                    revoked_at_ms=GREATEST(
                        issued_at_ms,
                        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                    ),
                    revocation_reason=$4,
                    updated_at_ms=GREATEST(
                        updated_at_ms,
                        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                    )
                WHERE tenant_id=$1 AND provider_id=$2 AND provider_subject=$3
                  AND revoked_at_ms IS NULL AND version < 9223372036854775807
                ",
            )
            .bind(key.tenant_id().as_str())
            .bind(key.provider_id().as_str())
            .bind(key.provider_subject().as_str())
            .bind(reason.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_database_error)?
            .rows_affected();
            if revoked == 1 || has_tombstone(&self.pool, key).await? {
                Ok(())
            } else {
                Err(ProviderTokenVaultError::NotFound)
            }
        })
    }
}
