use std::{fmt, sync::Arc};

use automata_ci_auth::{
    human::{ProviderId, TenantId},
    login::{
        ConsumeLoginTransaction, ConsumeLoginTransactionOutcome, CreateLoginTransactionOutcome,
        LoadLoginTransactionOutcome, LoginReturnPath, LoginTransaction, LoginTransactionAccess,
        LoginTransactionBinding, LoginTransactionFlow, LoginTransactionId, LoginTransactionKind,
        LoginTransactionProof, LoginTransactionPurpose, LoginTransactionRepository,
        LoginTransactionRepositoryError, LoginTransactionRepositoryFuture, LoginTransactionState,
        LoginTransactionVersion, ReplaceLoginTransactionOutcome, ReplaceLoginTransactionState,
        VersionedLoginTransaction,
    },
    secret::{SecretBytes as AuthSecretBytes, SecretString},
    time::UnixTimestamp,
};
use automata_ci_key_management::{
    EncryptedEnvelope, EnvelopeCodec, EnvelopeError, KeyEncryptionContext, KeyEncryptionError,
    KeyEncryptionProvider, KeyId, KeyPurpose, SecretBytes, WrappedDataKey,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    session::{database_time_milliseconds, validate_caller_time},
    support::{
        canonical_uuid, is_integrity_violation, timestamp_from_milliseconds,
        timestamp_to_milliseconds,
    },
};

const LOGIN_ENCRYPTION_PURPOSE: &str = "auth/login-state:v1";
const INSTALLATION_ENCRYPTION_SCOPE: &str = "system:installation";
const LOGIN_PAYLOAD_HEADER: &[u8; 4] = b"ALP1";
const BROWSER_PAYLOAD_KIND: u8 = 1;
const DEVICE_PAYLOAD_KIND: u8 = 2;

/// `PostgreSQL` login transaction adapter with authenticated envelope encryption.
#[derive(Clone)]
pub struct PostgresLoginTransactionRepository {
    pool: PgPool,
    codec: Arc<EnvelopeCodec>,
    purpose: KeyPurpose,
}

impl PostgresLoginTransactionRepository {
    /// Creates an adapter using a pluggable wrapping-key provider.
    ///
    /// # Panics
    ///
    /// Panics only if the crate's static encryption-purpose constant is invalid.
    #[must_use]
    pub fn new(pool: PgPool, provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        let purpose = KeyPurpose::new(LOGIN_ENCRYPTION_PURPOSE)
            .expect("the static login encryption purpose is valid");
        Self {
            pool,
            codec: Arc::new(EnvelopeCodec::new(provider)),
            purpose,
        }
    }

    fn context(
        &self,
        purpose: &LoginTransactionPurpose,
        id: &LoginTransactionId,
    ) -> Result<KeyEncryptionContext, LoginTransactionRepositoryError> {
        let scope = purpose.tenant_id().map_or_else(
            || INSTALLATION_ENCRYPTION_SCOPE.to_owned(),
            |tenant| format!("tenant:{}", tenant.as_str()),
        );
        KeyEncryptionContext::new(scope, self.purpose.clone(), id.as_str())
            .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)
    }

    async fn seal(
        &self,
        purpose: &LoginTransactionPurpose,
        id: &LoginTransactionId,
        flow: &LoginTransactionFlow,
        state: LoginTransactionState,
    ) -> Result<EncryptedEnvelope, LoginTransactionRepositoryError> {
        let (kind, user_code, verification_uri) = match flow {
            LoginTransactionFlow::Browser { .. } => (LoginTransactionKind::Browser, None, None),
            LoginTransactionFlow::Device {
                user_code,
                verification_uri,
                ..
            } => (
                LoginTransactionKind::Device,
                Some(user_code),
                Some(verification_uri.as_str()),
            ),
        };
        self.seal_fields(purpose, id, kind, state, user_code, verification_uri)
            .await
    }

    async fn seal_fields(
        &self,
        purpose: &LoginTransactionPurpose,
        id: &LoginTransactionId,
        kind: LoginTransactionKind,
        state: LoginTransactionState,
        user_code: Option<&SecretString>,
        verification_uri: Option<&str>,
    ) -> Result<EncryptedEnvelope, LoginTransactionRepositoryError> {
        let context = self.context(purpose, id)?;
        let plaintext = encode_payload(kind, &state, user_code, verification_uri)?;
        self.codec
            .seal(&context, plaintext)
            .await
            .map_err(map_seal_error)
    }

    async fn open(
        &self,
        row: &LoginRow,
        purpose: &LoginTransactionPurpose,
        id: &LoginTransactionId,
    ) -> Result<LoginPayload, LoginTransactionRepositoryError> {
        let context = self.context(purpose, id)?;
        let envelope = row.envelope()?;
        let plaintext = self
            .codec
            .open(&context, &envelope)
            .await
            .map_err(map_open_error)?;
        decode_payload(&row.flow_kind, plaintext.expose_secret())
    }
}

impl fmt::Debug for PostgresLoginTransactionRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresLoginTransactionRepository")
            .field("encryption_purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct LoginRow {
    id: Uuid,
    tenant_id: Option<String>,
    purpose: String,
    flow_kind: String,
    provider_id: String,
    return_path: Option<String>,
    state_hash: Option<Vec<u8>>,
    state_hash_key_id: Option<String>,
    browser_binding_hash: Option<Vec<u8>>,
    browser_binding_hash_key_id: Option<String>,
    poll_proof_hash: Option<Vec<u8>>,
    poll_proof_hash_key_id: Option<String>,
    encrypted_payload: Vec<u8>,
    payload_nonce: Vec<u8>,
    wrapped_data_key: Vec<u8>,
    encryption_key_id: String,
    encryption_schema: i32,
    status: String,
    poll_interval_ms: Option<i64>,
    next_poll_at_ms: Option<i64>,
    created_at_ms: i64,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    revision: i64,
}

impl LoginRow {
    fn purpose(&self) -> Result<LoginTransactionPurpose, LoginTransactionRepositoryError> {
        match (self.purpose.as_str(), self.tenant_id.as_deref()) {
            ("sign_in", Some(tenant)) => TenantId::new(tenant.to_owned())
                .map(|tenant_id| LoginTransactionPurpose::SignIn { tenant_id })
                .map_err(|_| LoginTransactionRepositoryError::CorruptData),
            ("installation_setup", None) => Ok(LoginTransactionPurpose::InstallationSetup),
            _ => Err(LoginTransactionRepositoryError::CorruptData),
        }
    }

    fn id(&self) -> Result<LoginTransactionId, LoginTransactionRepositoryError> {
        LoginTransactionId::new(self.id.hyphenated().to_string())
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)
    }

    fn version(&self) -> Result<LoginTransactionVersion, LoginTransactionRepositoryError> {
        u64::try_from(self.revision)
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)
            .and_then(|revision| {
                LoginTransactionVersion::new(revision)
                    .map_err(|_| LoginTransactionRepositoryError::CorruptData)
            })
    }

    fn envelope(&self) -> Result<EncryptedEnvelope, LoginTransactionRepositoryError> {
        let schema = u16::try_from(self.encryption_schema)
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
        let key_id = KeyId::new(self.encryption_key_id.clone())
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
        let wrapped = WrappedDataKey::new(key_id, self.wrapped_data_key.clone())
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
        let nonce: [u8; 12] = self
            .payload_nonce
            .as_slice()
            .try_into()
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
        EncryptedEnvelope::from_parts(schema, wrapped, nonce, self.encrypted_payload.clone())
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)
    }

    fn flow(
        &self,
        device_user_code: Option<SecretString>,
        verification_uri: Option<String>,
    ) -> Result<LoginTransactionFlow, LoginTransactionRepositoryError> {
        match self.flow_kind.as_str() {
            "browser" if device_user_code.is_none() && verification_uri.is_none() => {
                LoginTransactionFlow::browser(
                    binding_from_parts(
                        self.state_hash_key_id.as_deref(),
                        self.state_hash.as_deref(),
                    )?,
                    binding_from_parts(
                        self.browser_binding_hash_key_id.as_deref(),
                        self.browser_binding_hash.as_deref(),
                    )?,
                )
                .map_err(|_| LoginTransactionRepositoryError::CorruptData)
            }
            "device" => {
                let poll_interval = self
                    .poll_interval_ms
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(LoginTransactionRepositoryError::CorruptData)?;
                let next_poll_at = timestamp_from_milliseconds(
                    self.next_poll_at_ms
                        .ok_or(LoginTransactionRepositoryError::CorruptData)?,
                )
                .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
                LoginTransactionFlow::device(
                    binding_from_parts(
                        self.poll_proof_hash_key_id.as_deref(),
                        self.poll_proof_hash.as_deref(),
                    )?,
                    device_user_code.ok_or(LoginTransactionRepositoryError::CorruptData)?,
                    verification_uri.ok_or(LoginTransactionRepositoryError::CorruptData)?,
                    poll_interval,
                    next_poll_at,
                )
                .map_err(|_| LoginTransactionRepositoryError::CorruptData)
            }
            _ => Err(LoginTransactionRepositoryError::CorruptData),
        }
    }

    async fn into_domain(
        self,
        repository: &PostgresLoginTransactionRepository,
    ) -> Result<LoginTransaction, LoginTransactionRepositoryError> {
        let id = self.id()?;
        let purpose = self.purpose()?;
        let payload = repository.open(&self, &purpose, &id).await?;
        let provider_id = ProviderId::new(self.provider_id.clone())
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
        let flow = self.flow(payload.device_user_code, payload.verification_uri)?;
        let return_path = self
            .return_path
            .clone()
            .map(LoginReturnPath::new)
            .transpose()
            .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
        let created_at = timestamp_from_milliseconds(self.created_at_ms)
            .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
        let expires_at = timestamp_from_milliseconds(self.expires_at_ms)
            .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
        LoginTransaction::new(
            id,
            purpose,
            provider_id,
            flow,
            return_path,
            payload.state,
            created_at,
            expires_at,
        )
        .map_err(|_| LoginTransactionRepositoryError::CorruptData)
    }
}

fn binding_from_parts(
    key_id: Option<&str>,
    digest: Option<&[u8]>,
) -> Result<LoginTransactionBinding, LoginTransactionRepositoryError> {
    let key_id = automata_ci_auth::login::LoginBindingDigestKeyId::new(
        key_id.ok_or(LoginTransactionRepositoryError::CorruptData)?,
    )
    .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
    let digest: [u8; 32] = digest
        .ok_or(LoginTransactionRepositoryError::CorruptData)?
        .try_into()
        .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
    Ok(LoginTransactionBinding::new(
        key_id,
        automata_ci_auth::login::LoginBindingDigest::new(digest),
    ))
}

struct LoginPayload {
    state: LoginTransactionState,
    device_user_code: Option<SecretString>,
    verification_uri: Option<String>,
}

fn encode_payload(
    kind: LoginTransactionKind,
    state: &LoginTransactionState,
    device_user_code: Option<&SecretString>,
    verification_uri: Option<&str>,
) -> Result<SecretBytes, LoginTransactionRepositoryError> {
    let (kind_byte, user_code, verification_uri) = match (kind, device_user_code, verification_uri)
    {
        (LoginTransactionKind::Browser, None, None) => (BROWSER_PAYLOAD_KIND, &[][..], &[][..]),
        (LoginTransactionKind::Device, Some(user_code), Some(verification_uri)) => (
            DEVICE_PAYLOAD_KIND,
            user_code.expose_secret().as_bytes(),
            verification_uri.as_bytes(),
        ),
        _ => return Err(LoginTransactionRepositoryError::InvalidRequest),
    };
    let mut encoded = Vec::with_capacity(
        LOGIN_PAYLOAD_HEADER.len()
            + 1
            + 12
            + state.expose_secret().len()
            + user_code.len()
            + verification_uri.len(),
    );
    encoded.extend_from_slice(LOGIN_PAYLOAD_HEADER);
    encoded.push(kind_byte);
    append_payload_field(&mut encoded, state.expose_secret())?;
    append_payload_field(&mut encoded, user_code)?;
    append_payload_field(&mut encoded, verification_uri)?;
    SecretBytes::new(encoded).map_err(|_| LoginTransactionRepositoryError::InvalidRequest)
}

fn append_payload_field(
    destination: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), LoginTransactionRepositoryError> {
    let length =
        u32::try_from(value.len()).map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
    Ok(())
}

fn decode_payload(
    expected_flow_kind: &str,
    encoded: &[u8],
) -> Result<LoginPayload, LoginTransactionRepositoryError> {
    if encoded.get(..LOGIN_PAYLOAD_HEADER.len()) != Some(LOGIN_PAYLOAD_HEADER) {
        return Err(LoginTransactionRepositoryError::IntegrityFailure);
    }
    let kind = *encoded
        .get(LOGIN_PAYLOAD_HEADER.len())
        .ok_or(LoginTransactionRepositoryError::IntegrityFailure)?;
    let mut cursor = LOGIN_PAYLOAD_HEADER.len() + 1;
    let state = read_payload_field(encoded, &mut cursor)?;
    let user_code = read_payload_field(encoded, &mut cursor)?;
    let verification_uri = read_payload_field(encoded, &mut cursor)?;
    if cursor != encoded.len() {
        return Err(LoginTransactionRepositoryError::IntegrityFailure);
    }
    let state = AuthSecretBytes::new(state.to_vec())
        .map(LoginTransactionState::new)
        .map_err(|_| LoginTransactionRepositoryError::IntegrityFailure)?;
    match (expected_flow_kind, kind) {
        ("browser", BROWSER_PAYLOAD_KIND)
            if user_code.is_empty() && verification_uri.is_empty() =>
        {
            Ok(LoginPayload {
                state,
                device_user_code: None,
                verification_uri: None,
            })
        }
        ("device", DEVICE_PAYLOAD_KIND) => {
            let user_code = String::from_utf8(user_code.to_vec())
                .map_err(|_| LoginTransactionRepositoryError::IntegrityFailure)?;
            let user_code = SecretString::new(user_code)
                .map_err(|_| LoginTransactionRepositoryError::IntegrityFailure)?;
            let verification_uri = String::from_utf8(verification_uri.to_vec())
                .map_err(|_| LoginTransactionRepositoryError::IntegrityFailure)?;
            Ok(LoginPayload {
                state,
                device_user_code: Some(user_code),
                verification_uri: Some(verification_uri),
            })
        }
        _ => Err(LoginTransactionRepositoryError::IntegrityFailure),
    }
}

fn read_payload_field<'a>(
    encoded: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], LoginTransactionRepositoryError> {
    let length_bytes: [u8; 4] = encoded
        .get(*cursor..cursor.saturating_add(4))
        .ok_or(LoginTransactionRepositoryError::IntegrityFailure)?
        .try_into()
        .map_err(|_| LoginTransactionRepositoryError::IntegrityFailure)?;
    *cursor = cursor.saturating_add(4);
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| LoginTransactionRepositoryError::IntegrityFailure)?;
    let end = cursor
        .checked_add(length)
        .ok_or(LoginTransactionRepositoryError::IntegrityFailure)?;
    let value = encoded
        .get(*cursor..end)
        .ok_or(LoginTransactionRepositoryError::IntegrityFailure)?;
    *cursor = end;
    Ok(value)
}

fn map_seal_error(error: EnvelopeError) -> LoginTransactionRepositoryError {
    match error {
        EnvelopeError::RandomnessUnavailable
        | EnvelopeError::CryptographicFailure
        | EnvelopeError::KeyEncryption(
            KeyEncryptionError::Unavailable | KeyEncryptionError::RandomnessUnavailable,
        ) => LoginTransactionRepositoryError::Unavailable,
        _ => LoginTransactionRepositoryError::InvalidRequest,
    }
}

fn map_open_error(error: EnvelopeError) -> LoginTransactionRepositoryError {
    match error {
        EnvelopeError::KeyEncryption(
            KeyEncryptionError::Unavailable | KeyEncryptionError::RandomnessUnavailable,
        ) => LoginTransactionRepositoryError::Unavailable,
        _ => LoginTransactionRepositoryError::IntegrityFailure,
    }
}

const LOGIN_SELECT: &str = r"
    SELECT id, tenant_id, purpose, flow_kind, provider_id, return_path,
           state_hash, state_hash_key_id, browser_binding_hash,
           browser_binding_hash_key_id, poll_proof_hash, poll_proof_hash_key_id,
           encrypted_payload, payload_nonce,
           wrapped_data_key, encryption_key_id, encryption_schema, status,
           poll_interval_ms, next_poll_at_ms, created_at_ms, expires_at_ms,
           consumed_at_ms, revision
    FROM human_login_transactions
";

async fn find_row<'e, E>(
    executor: E,
    access: &LoginTransactionAccess,
    for_update: bool,
) -> Result<Option<LoginRow>, LoginTransactionRepositoryError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = canonical_uuid(access.id().as_str())
        .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
    let tenant = access.tenant_id().map(TenantId::as_str);
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    match access.proof() {
        LoginTransactionProof::Browser {
            state,
            client_binding,
        } => {
            let sql = format!(
                "{LOGIN_SELECT} WHERE id=$1 AND purpose=$2 AND tenant_id IS NOT DISTINCT FROM $3 \
                 AND provider_id=$4 AND flow_kind='browser' \
                 AND state_hash_key_id=$5 AND state_hash=$6 \
                 AND browser_binding_hash_key_id=$7 AND browser_binding_hash=$8{suffix}"
            );
            // `sql` combines only the static query above and a static lock suffix;
            // all request data remains in bind parameters.
            sqlx::query_as::<_, LoginRow>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(id)
                .bind(access.purpose().database_value())
                .bind(tenant)
                .bind(access.provider_id().as_str())
                .bind(state.key_id().as_str())
                .bind(state.digest().as_bytes().as_slice())
                .bind(client_binding.key_id().as_str())
                .bind(client_binding.digest().as_bytes().as_slice())
                .fetch_optional(executor)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)
        }
        LoginTransactionProof::Device { poll_proof } => {
            let sql = format!(
                "{LOGIN_SELECT} WHERE id=$1 AND purpose=$2 AND tenant_id IS NOT DISTINCT FROM $3 \
                 AND provider_id=$4 AND flow_kind='device' \
                 AND poll_proof_hash_key_id=$5 AND poll_proof_hash=$6{suffix}"
            );
            // `sql` combines only the static query above and a static lock suffix;
            // all request data remains in bind parameters.
            sqlx::query_as::<_, LoginRow>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(id)
                .bind(access.purpose().database_value())
                .bind(tenant)
                .bind(access.provider_id().as_str())
                .bind(poll_proof.key_id().as_str())
                .bind(poll_proof.digest().as_bytes().as_slice())
                .fetch_optional(executor)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)
        }
    }
}

fn status_at(
    row: &LoginRow,
    now: UnixTimestamp,
) -> Result<RowStatus, LoginTransactionRepositoryError> {
    let expires_at = timestamp_from_milliseconds(row.expires_at_ms)
        .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
    let created_at = timestamp_from_milliseconds(row.created_at_ms)
        .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
    Ok(match row.status.as_str() {
        "pending" if created_at > now => RowStatus::NotYetValid,
        "pending" if expires_at <= now => RowStatus::ExpiredPending,
        "pending" => RowStatus::Active,
        "expired" => RowStatus::Expired,
        "consumed" | "succeeded" | "denied" => RowStatus::Consumed,
        _ => return Err(LoginTransactionRepositoryError::CorruptData),
    })
}

enum RowStatus {
    Active,
    NotYetValid,
    ExpiredPending,
    Expired,
    Consumed,
}

pub(crate) struct ConsumedSignInLogin {
    id: Uuid,
    return_path: Option<LoginReturnPath>,
    observed_at_ms: i64,
    expires_at_ms: i64,
}

impl ConsumedSignInLogin {
    pub(crate) const fn id(&self) -> Uuid {
        self.id
    }

    pub(crate) const fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    pub(crate) const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    pub(crate) fn into_return_path(self) -> Option<LoginReturnPath> {
        self.return_path
    }
}

pub(crate) enum LockSignInOutcome {
    Consumed(ConsumedSignInLogin),
    NotFound,
    Expired,
    AlreadyConsumed,
    VersionConflict,
}

pub(crate) async fn lock_sign_in_for_finalization(
    transaction: &mut Transaction<'_, Postgres>,
    access: &LoginTransactionAccess,
    expected_version: LoginTransactionVersion,
    now: UnixTimestamp,
) -> Result<LockSignInOutcome, LoginTransactionRepositoryError> {
    if !matches!(access.purpose(), LoginTransactionPurpose::SignIn { .. }) {
        return Err(LoginTransactionRepositoryError::InvalidRequest);
    }
    let Some(row) = find_row(&mut **transaction, access, true).await? else {
        return Ok(LockSignInOutcome::NotFound);
    };
    let database_time_ms = database_time_milliseconds(transaction)
        .await
        .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
    let database_time = validate_caller_time(now, database_time_ms)
        .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
    let created_at = timestamp_from_milliseconds(row.created_at_ms)
        .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
    let expires_at = timestamp_from_milliseconds(row.expires_at_ms)
        .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
    if created_at > database_time {
        return Ok(LockSignInOutcome::NotFound);
    }
    match row.status.as_str() {
        "pending" | "consumed" if expires_at <= database_time => {
            return Ok(LockSignInOutcome::Expired);
        }
        "pending" => return Ok(LockSignInOutcome::NotFound),
        "succeeded" | "denied" => return Ok(LockSignInOutcome::AlreadyConsumed),
        "expired" => return Ok(LockSignInOutcome::Expired),
        "consumed" => {}
        _ => return Err(LoginTransactionRepositoryError::CorruptData),
    }
    let consumed_at_ms = row
        .consumed_at_ms
        .ok_or(LoginTransactionRepositoryError::CorruptData)?;
    let consumed_at = timestamp_from_milliseconds(consumed_at_ms)
        .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
    if consumed_at < created_at || consumed_at >= expires_at || consumed_at > database_time {
        return Err(LoginTransactionRepositoryError::CorruptData);
    }
    if row.version()? != expected_version {
        return Ok(LockSignInOutcome::VersionConflict);
    }
    let return_path = row
        .return_path
        .map(LoginReturnPath::new)
        .transpose()
        .map_err(|_| LoginTransactionRepositoryError::CorruptData)?;
    Ok(LockSignInOutcome::Consumed(ConsumedSignInLogin {
        id: row.id,
        return_path,
        observed_at_ms: database_time_ms,
        expires_at_ms: row.expires_at_ms,
    }))
}

async fn expire_pending_login(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
    observed_at_ms: i64,
) -> Result<(), LoginTransactionRepositoryError> {
    let expired = sqlx::query(
        r"
        UPDATE human_login_transactions
        SET status='expired', consumed_at_ms=$2, updated_at_ms=$2,
            revision=revision+1
        WHERE id=$1 AND status='pending' AND expires_at_ms<=$2
        ",
    )
    .bind(id)
    .bind(observed_at_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
    if expired.rows_affected() != 1 {
        return Err(LoginTransactionRepositoryError::CorruptData);
    }
    Ok(())
}

impl LoginTransactionRepository for PostgresLoginTransactionRepository {
    #[allow(clippy::too_many_lines)]
    fn create(
        &self,
        transaction: LoginTransaction,
    ) -> LoginTransactionRepositoryFuture<'_, CreateLoginTransactionOutcome> {
        Box::pin(async move {
            let (id, purpose, provider, flow, return_path, state, created_at, expires_at) =
                transaction.into_parts();
            let envelope = self.seal(&purpose, &id, &flow, state).await?;
            let id_uuid = canonical_uuid(id.as_str())
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            let lifetime = expires_at
                .as_seconds()
                .checked_sub(created_at.as_seconds())
                .ok_or(LoginTransactionRepositoryError::InvalidRequest)?;
            let mut database_transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let database_time_ms = database_time_milliseconds(&mut database_transaction)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(created_at, database_time_ms)
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            let expires_at = database_time
                .checked_add(lifetime)
                .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?;
            let created_at_ms = database_time_ms;
            let expires_at_ms = timestamp_to_milliseconds(expires_at)
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            let (state_binding, client_binding, poll_proof, poll_interval_ms, next_poll_at_ms) =
                match flow {
                    LoginTransactionFlow::Browser {
                        state,
                        client_binding,
                    } => (Some(state), Some(client_binding), None, None, None),
                    LoginTransactionFlow::Device {
                        poll_proof,
                        poll_interval_milliseconds,
                        next_poll_at,
                        ..
                    } => {
                        let next_poll_offset = next_poll_at
                            .as_seconds()
                            .checked_sub(created_at.as_seconds())
                            .ok_or(LoginTransactionRepositoryError::InvalidRequest)?;
                        let rebased_next_poll_at = database_time
                            .checked_add(next_poll_offset)
                            .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?;
                        (
                            None,
                            None,
                            Some(poll_proof),
                            Some(
                                i64::try_from(poll_interval_milliseconds)
                                    .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?,
                            ),
                            Some(
                                timestamp_to_milliseconds(rebased_next_poll_at).map_err(|()| {
                                    LoginTransactionRepositoryError::InvalidRequest
                                })?,
                            ),
                        )
                    }
                };
            let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
            let (key_id, wrapped_key) = wrapped.into_parts();
            let result = sqlx::query(
                r"
                INSERT INTO human_login_transactions (
                    id, tenant_id, purpose, flow_kind, provider_id, return_path,
                    state_hash, state_hash_key_id, browser_binding_hash,
                    browser_binding_hash_key_id, poll_proof_hash, poll_proof_hash_key_id,
                    encrypted_payload, payload_nonce, wrapped_data_key,
                    encryption_key_id, encryption_schema,
                    poll_interval_ms, next_poll_at_ms, created_at_ms, updated_at_ms,
                    expires_at_ms, revision
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                    $18,$19,$20,$20,$21,1
                )
                ",
            )
            .bind(id_uuid)
            .bind(purpose.tenant_id().map(TenantId::as_str))
            .bind(purpose.database_value())
            .bind(match (&state_binding, &poll_proof) {
                (Some(_), None) => "browser",
                (None, Some(_)) => "device",
                _ => return Err(LoginTransactionRepositoryError::InvalidRequest),
            })
            .bind(provider.as_str())
            .bind(return_path.as_ref().map(LoginReturnPath::as_str))
            .bind(
                state_binding
                    .as_ref()
                    .map(|binding| binding.digest().as_bytes().as_slice()),
            )
            .bind(
                state_binding
                    .as_ref()
                    .map(|binding| binding.key_id().as_str()),
            )
            .bind(
                client_binding
                    .as_ref()
                    .map(|binding| binding.digest().as_bytes().as_slice()),
            )
            .bind(
                client_binding
                    .as_ref()
                    .map(|binding| binding.key_id().as_str()),
            )
            .bind(
                poll_proof
                    .as_ref()
                    .map(|binding| binding.digest().as_bytes().as_slice()),
            )
            .bind(poll_proof.as_ref().map(|binding| binding.key_id().as_str()))
            .bind(ciphertext)
            .bind(nonce.as_slice())
            .bind(wrapped_key)
            .bind(key_id.as_str())
            .bind(i32::from(schema))
            .bind(poll_interval_ms)
            .bind(next_poll_at_ms)
            .bind(created_at_ms)
            .bind(expires_at_ms)
            .execute(&mut *database_transaction)
            .await;
            match result {
                Ok(_) => {
                    database_transaction
                        .commit()
                        .await
                        .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                    Ok(CreateLoginTransactionOutcome::Created(
                        LoginTransactionVersion::new(1).expect("one is a valid version"),
                    ))
                }
                Err(error)
                    if error
                        .as_database_error()
                        .is_some_and(sqlx::error::DatabaseError::is_unique_violation) =>
                {
                    Ok(CreateLoginTransactionOutcome::AlreadyExists)
                }
                Err(error) if is_integrity_violation(&error) => {
                    Err(LoginTransactionRepositoryError::InvalidRequest)
                }
                Err(_) => Err(LoginTransactionRepositoryError::Unavailable),
            }
        })
    }

    fn load<'a>(
        &'a self,
        access: &'a LoginTransactionAccess,
        now: UnixTimestamp,
    ) -> LoginTransactionRepositoryFuture<'a, LoadLoginTransactionOutcome> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let Some(row) = find_row(&mut *transaction, access, true).await? else {
                return Ok(LoadLoginTransactionOutcome::NotFound);
            };
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(now, database_time_ms)
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            let outcome = match status_at(&row, database_time)? {
                RowStatus::Active => {
                    let expires_at_ms = row.expires_at_ms;
                    let version = row.version()?;
                    let domain = row.into_domain(self).await?;
                    let completed_at_ms = database_time_milliseconds(&mut transaction)
                        .await
                        .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                    validate_caller_time(now, completed_at_ms)
                        .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
                    if expires_at_ms <= completed_at_ms {
                        Ok(LoadLoginTransactionOutcome::Expired)
                    } else {
                        Ok(LoadLoginTransactionOutcome::Active(Box::new(
                            VersionedLoginTransaction::new(version, domain),
                        )))
                    }
                }
                RowStatus::ExpiredPending | RowStatus::Expired => {
                    Ok(LoadLoginTransactionOutcome::Expired)
                }
                RowStatus::Consumed => Ok(LoadLoginTransactionOutcome::Consumed),
                RowStatus::NotYetValid => Ok(LoadLoginTransactionOutcome::NotFound),
            }?;
            transaction
                .commit()
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            Ok(outcome)
        })
    }

    #[allow(clippy::too_many_lines)]
    fn replace_state(
        &self,
        request: ReplaceLoginTransactionState,
        now: UnixTimestamp,
    ) -> LoginTransactionRepositoryFuture<'_, ReplaceLoginTransactionOutcome> {
        Box::pin(async move {
            request
                .validate()
                .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?;
            let (access, expected, replacement, next_poll_at, poll_interval_milliseconds) =
                request.into_parts();
            let next_poll_offset = next_poll_at
                .map(|next_poll_at| {
                    next_poll_at
                        .as_seconds()
                        .checked_sub(now.as_seconds())
                        .filter(|offset| *offset > 0)
                        .ok_or(LoginTransactionRepositoryError::InvalidRequest)
                })
                .transpose()?;
            let Some(existing) = find_row(&self.pool, &access, false).await? else {
                return Ok(ReplaceLoginTransactionOutcome::NotFound);
            };
            if existing.version()? != expected {
                return Ok(ReplaceLoginTransactionOutcome::VersionConflict);
            }
            let next_version = expected
                .value()
                .checked_add(1)
                .ok_or(LoginTransactionRepositoryError::InvalidRequest)
                .and_then(|value| {
                    LoginTransactionVersion::new(value)
                        .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)
                })?;
            let existing_payload = self.open(&existing, access.purpose(), access.id()).await?;
            let envelope = self
                .seal_fields(
                    access.purpose(),
                    access.id(),
                    access.kind(),
                    replacement,
                    existing_payload.device_user_code.as_ref(),
                    existing_payload.verification_uri.as_deref(),
                )
                .await?;
            let id = canonical_uuid(access.id().as_str())
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            let poll_interval_ms = poll_interval_milliseconds
                .map(i64::try_from)
                .transpose()
                .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?;
            let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
            let (key_id, wrapped_key) = wrapped.into_parts();
            let expected_i64 = i64::try_from(expected.value())
                .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)?;
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let Some(locked) = find_row(&mut *transaction, &access, true).await? else {
                return Ok(ReplaceLoginTransactionOutcome::NotFound);
            };
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(now, database_time_ms)
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            match status_at(&locked, database_time)? {
                RowStatus::ExpiredPending | RowStatus::Expired => {
                    return Ok(ReplaceLoginTransactionOutcome::Expired);
                }
                RowStatus::Consumed => return Ok(ReplaceLoginTransactionOutcome::Consumed),
                RowStatus::NotYetValid => return Ok(ReplaceLoginTransactionOutcome::NotFound),
                RowStatus::Active => {}
            }
            if locked.version()? != expected {
                return Ok(ReplaceLoginTransactionOutcome::VersionConflict);
            }
            let next_poll_at_ms = next_poll_offset
                .map(|offset| {
                    database_time
                        .checked_add(offset)
                        .map_err(|_| LoginTransactionRepositoryError::InvalidRequest)
                        .and_then(|next_poll_at| {
                            timestamp_to_milliseconds(next_poll_at)
                                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)
                        })
                })
                .transpose()?;
            if next_poll_at_ms
                .is_some_and(|next_poll_at_ms| next_poll_at_ms >= locked.expires_at_ms)
            {
                return Err(LoginTransactionRepositoryError::InvalidRequest);
            }
            let result = match access.proof() {
                LoginTransactionProof::Browser {
                    state,
                    client_binding,
                } => {
                    sqlx::query(
                        r"
                    UPDATE human_login_transactions SET
                        encrypted_payload=$9, payload_nonce=$10, wrapped_data_key=$11,
                        encryption_key_id=$12, encryption_schema=$13,
                        updated_at_ms=$14, revision=revision+1
                    WHERE id=$1 AND purpose=$2 AND tenant_id IS NOT DISTINCT FROM $3
                      AND provider_id=$4 AND flow_kind='browser'
                      AND state_hash_key_id=$5 AND state_hash=$6
                      AND browser_binding_hash_key_id=$7 AND browser_binding_hash=$8
                      AND status='pending' AND expires_at_ms>$14
                      AND expires_at_ms >
                          floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                      AND revision=$15
                    ",
                    )
                    .bind(id)
                    .bind(access.purpose().database_value())
                    .bind(access.tenant_id().map(TenantId::as_str))
                    .bind(access.provider_id().as_str())
                    .bind(state.key_id().as_str())
                    .bind(state.digest().as_bytes().as_slice())
                    .bind(client_binding.key_id().as_str())
                    .bind(client_binding.digest().as_bytes().as_slice())
                    .bind(ciphertext)
                    .bind(nonce.as_slice())
                    .bind(wrapped_key)
                    .bind(key_id.as_str())
                    .bind(i32::from(schema))
                    .bind(database_time_ms)
                    .bind(expected_i64)
                    .execute(&mut *transaction)
                    .await
                }
                LoginTransactionProof::Device { poll_proof } => {
                    sqlx::query(
                        r"
                    UPDATE human_login_transactions SET
                        encrypted_payload=$7, payload_nonce=$8, wrapped_data_key=$9,
                        encryption_key_id=$10, encryption_schema=$11,
                        next_poll_at_ms=COALESCE($12,next_poll_at_ms),
                        poll_interval_ms=COALESCE($13,poll_interval_ms),
                        poll_attempts=poll_attempts+1, updated_at_ms=$14,
                        revision=revision+1
                    WHERE id=$1 AND purpose=$2 AND tenant_id IS NOT DISTINCT FROM $3
                      AND provider_id=$4 AND flow_kind='device'
                      AND poll_proof_hash_key_id=$5 AND poll_proof_hash=$6
                      AND status='pending' AND expires_at_ms>$14
                      AND expires_at_ms >
                          floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                      AND revision=$15
                    ",
                    )
                    .bind(id)
                    .bind(access.purpose().database_value())
                    .bind(access.tenant_id().map(TenantId::as_str))
                    .bind(access.provider_id().as_str())
                    .bind(poll_proof.key_id().as_str())
                    .bind(poll_proof.digest().as_bytes().as_slice())
                    .bind(ciphertext)
                    .bind(nonce.as_slice())
                    .bind(wrapped_key)
                    .bind(key_id.as_str())
                    .bind(i32::from(schema))
                    .bind(next_poll_at_ms)
                    .bind(poll_interval_ms)
                    .bind(database_time_ms)
                    .bind(expected_i64)
                    .execute(&mut *transaction)
                    .await
                }
            }
            .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            if result.rows_affected() == 1 {
                transaction
                    .commit()
                    .await
                    .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                return Ok(ReplaceLoginTransactionOutcome::Replaced(next_version));
            }
            let Some(row) = find_row(&mut *transaction, &access, true).await? else {
                return Ok(ReplaceLoginTransactionOutcome::NotFound);
            };
            let final_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let final_time = timestamp_from_milliseconds(final_time_ms)
                .map_err(|()| LoginTransactionRepositoryError::CorruptData)?;
            Ok(match status_at(&row, final_time)? {
                RowStatus::ExpiredPending | RowStatus::Expired => {
                    ReplaceLoginTransactionOutcome::Expired
                }
                RowStatus::Consumed => ReplaceLoginTransactionOutcome::Consumed,
                RowStatus::NotYetValid => ReplaceLoginTransactionOutcome::NotFound,
                RowStatus::Active => ReplaceLoginTransactionOutcome::VersionConflict,
            })
        })
    }

    fn consume(
        &self,
        request: ConsumeLoginTransaction,
    ) -> LoginTransactionRepositoryFuture<'_, ConsumeLoginTransactionOutcome> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let Some(row) = find_row(&mut *transaction, request.access(), true).await? else {
                return Ok(ConsumeLoginTransactionOutcome::NotFound);
            };
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(request.now(), database_time_ms)
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            match status_at(&row, database_time)? {
                RowStatus::Consumed => {
                    return Ok(ConsumeLoginTransactionOutcome::AlreadyConsumed);
                }
                RowStatus::Expired => return Ok(ConsumeLoginTransactionOutcome::Expired),
                RowStatus::NotYetValid => return Ok(ConsumeLoginTransactionOutcome::NotFound),
                RowStatus::ExpiredPending => {
                    sqlx::query(
                        "UPDATE human_login_transactions SET status='expired', consumed_at_ms=$2, updated_at_ms=$2, revision=revision+1 WHERE id=$1 AND status='pending'",
                    )
                    .bind(row.id)
                    .bind(database_time_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                    return Ok(ConsumeLoginTransactionOutcome::Expired);
                }
                RowStatus::Active => {}
            }
            if let Some(expected) = request.expected_version()
                && row.version()? != expected
            {
                return Ok(ConsumeLoginTransactionOutcome::VersionConflict);
            }
            let id = row.id;
            let expires_at_ms = row.expires_at_ms;
            let domain = row.into_domain(self).await?;
            let completed_at_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            validate_caller_time(request.now(), completed_at_ms)
                .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
            if expires_at_ms <= completed_at_ms {
                expire_pending_login(&mut transaction, id, completed_at_ms).await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                return Ok(ConsumeLoginTransactionOutcome::Expired);
            }
            let result = sqlx::query(
                r"
                UPDATE human_login_transactions
                SET status='consumed', consumed_at_ms=$2, updated_at_ms=$2,
                    revision=revision+1
                WHERE id=$1 AND status='pending'
                  AND expires_at_ms >
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                ",
            )
            .bind(id)
            .bind(completed_at_ms)
            .execute(&mut *transaction)
            .await
            .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            if result.rows_affected() != 1 {
                let boundary_time_ms = database_time_milliseconds(&mut transaction)
                    .await
                    .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                validate_caller_time(request.now(), boundary_time_ms)
                    .map_err(|()| LoginTransactionRepositoryError::InvalidRequest)?;
                expire_pending_login(&mut transaction, id, boundary_time_ms).await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
                return Ok(ConsumeLoginTransactionOutcome::Expired);
            }
            transaction
                .commit()
                .await
                .map_err(|_| LoginTransactionRepositoryError::Unavailable)?;
            Ok(ConsumeLoginTransactionOutcome::Consumed(Box::new(domain)))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use automata_ci_auth::{
        login::{LoginBindingDigest, LoginBindingDigestKeyId},
        secret::SecretString,
    };
    use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;

    fn binding() -> LoginTransactionBinding {
        LoginTransactionBinding::new(
            LoginBindingDigestKeyId::new("poll-proof-v1").expect("key ID"),
            LoginBindingDigest::new([7; 32]),
        )
    }

    fn repository() -> PostgresLoginTransactionRepository {
        let material = LocalKeyMaterial::new(
            KeyId::new("login-kek-v1").expect("key ID"),
            SecretBytes::new(vec![0x31; 32]).expect("key bytes"),
        )
        .expect("key material");
        let keyring =
            Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("local keyring"));
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        PostgresLoginTransactionRepository::new(pool, keyring)
    }

    #[tokio::test]
    async fn device_secrets_are_encrypted_and_bound_to_exact_record_context() {
        let repository = repository();
        let purpose = LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new("tenant-a").expect("tenant"),
        };
        let id = LoginTransactionId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("login ID");
        let flow = LoginTransactionFlow::device(
            binding(),
            SecretString::new("ABCD-EFGH").expect("user code"),
            "https://github.com/login/device",
            5_000,
            UnixTimestamp::from_seconds(110),
        )
        .expect("device flow");
        let envelope = repository
            .seal(
                &purpose,
                &id,
                &flow,
                LoginTransactionState::new(
                    AuthSecretBytes::new(b"provider-device-code".to_vec()).expect("state"),
                ),
            )
            .await
            .expect("seal payload");
        assert!(
            !envelope
                .ciphertext()
                .windows(b"provider-device-code".len())
                .any(|window| window == b"provider-device-code")
        );
        assert!(
            !envelope
                .ciphertext()
                .windows(b"ABCD-EFGH".len())
                .any(|window| window == b"ABCD-EFGH")
        );

        let context = repository.context(&purpose, &id).expect("context");
        let plaintext = repository
            .codec
            .open(&context, &envelope)
            .await
            .expect("open payload");
        let decoded = decode_payload("device", plaintext.expose_secret()).expect("decode");
        assert_eq!(decoded.state.expose_secret(), b"provider-device-code");
        assert_eq!(
            decoded.device_user_code.expect("user code").expose_secret(),
            "ABCD-EFGH"
        );

        let wrong_id =
            LoginTransactionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("login ID");
        let wrong_context = repository.context(&purpose, &wrong_id).expect("context");
        assert!(matches!(
            repository
                .codec
                .open(&wrong_context, &envelope)
                .await
                .expect_err("copied envelope must not authenticate"),
            EnvelopeError::AuthenticationFailed
                | EnvelopeError::KeyEncryption(KeyEncryptionError::AuthenticationFailed)
        ));
    }
}
