//! Product test adapters that consume one derived conformance shard identity.

use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
};

use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobKeyError, BlobPayload, BlobStoreError, BlobStoreErrorKind,
    ImmutableBlobStore, MediaType, PutBlobOutcome, VerifiedBlob,
};
use automata_ci_conformance::{FixtureControlError, ShardIdentity, ShardPlan};
use bytes::Bytes;
use sqlx::{AssertSqlSafe, PgPool, Postgres, Transaction};
use thiserror::Error;
use tokio::net::TcpListener;

use super::conformance_github_stub::{HermeticGithubCredential, HermeticGithubStubError};

const PG_NAMESPACE_IDENTIFIER_HEAD: &str = "cf_";
const PG_NAMESPACE_DIGEST_HEX_LEN: usize = 20;
// foundation-governance: derived-contract owner=integration kind=storage-namespace
const PG_NAMESPACE_OWNERSHIP_MARKER_HEAD: &str = "automata-ci-conformance-shard:v1:";
// foundation-governance: operational-limit
const MAX_LOCAL_IDENTITY_BYTES: usize = 64;
// foundation-governance: operational-limit
const MAX_SPENT_PORT_RESERVATIONS: usize = 4_096;

static SPENT_PORT_RESERVATIONS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Product-facing adapters bound to one identity selected from a [`ShardPlan`].
///
/// Callers cannot supply individual schema, object, credential, or port-scope
/// strings. Every adapter below consumes the corresponding value from the same
/// derived [`ShardIdentity`].
#[derive(Clone, Debug)]
pub struct ProductConformanceShard {
    identity: ShardIdentity,
}

impl ProductConformanceShard {
    /// Binds product adapters to an identity already selected by fixture control.
    pub(crate) fn from_identity(identity: &ShardIdentity) -> Self {
        Self {
            identity: identity.clone(),
        }
    }

    /// Selects one shard from the complete deterministic plan.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureControlError::UnknownShard`] for an absent ordinal.
    pub fn from_plan(plan: &ShardPlan, ordinal: u16) -> Result<Self, FixtureControlError> {
        Ok(Self {
            identity: plan.shard(ordinal)?.clone(),
        })
    }

    /// Returns the single derived identity consumed by every adapter.
    #[must_use]
    pub const fn identity(&self) -> &ShardIdentity {
        &self.identity
    }

    /// Wraps an immutable object store with the shard's mandatory key prefix.
    ///
    /// # Errors
    ///
    /// Fails closed if a future shard-plan version produces a prefix that is
    /// not accepted by the product blob-key type.
    pub fn blob_store<Store>(
        &self,
        store: Store,
    ) -> Result<ConformanceShardBlobStore<Store>, ConformanceShardAdapterError>
    where
        Store: ImmutableBlobStore,
    {
        let prefix = self.identity.object_prefix().to_owned();
        BlobKey::new(format!("{prefix}scope-probe"))?;
        Ok(ConformanceShardBlobStore { store, prefix })
    }

    /// Creates a hermetic GitHub credential whose evidence identity is scoped
    /// by this shard. The secret authorization value is retained only by the
    /// existing redacting GitHub stub credential adapter.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical local identity or an invalid authorization
    /// header value.
    pub fn hermetic_github_credential(
        &self,
        local_identity: &str,
        authorization: SecretString,
    ) -> Result<HermeticGithubCredential, ConformanceShardAdapterError> {
        validate_local_identity(local_identity)?;
        HermeticGithubCredential::new(
            format!("{}:{local_identity}", self.identity.credential_scope()),
            authorization,
        )
        .map_err(ConformanceShardAdapterError::HermeticGithubCredential)
    }

    /// Binds and holds a real ephemeral IPv4 loopback listener owned by this
    /// shard and purpose.
    ///
    /// The returned listener closes the bind/use race: a process adapter takes
    /// the already-bound listener through [`ConformancePortReservation::into_listener`]
    /// instead of discovering an unused numeric port and rebinding it later.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical purpose or a listener that cannot be bound or
    /// inspected.
    pub async fn reserve_loopback_port(
        &self,
        purpose: &str,
    ) -> Result<ConformancePortReservation, ConformanceShardAdapterError> {
        validate_local_identity(purpose)?;
        let reservation_id = format!("{}:{purpose}", self.identity.port_reservation_key());
        claim_port_reservation(&reservation_id)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| {
                release_failed_port_reservation(&reservation_id);
                ConformanceShardAdapterError::PortReservation(error)
            })?;
        let local_addr = listener.local_addr().map_err(|error| {
            release_failed_port_reservation(&reservation_id);
            ConformanceShardAdapterError::PortReservation(error)
        })?;
        if !local_addr.ip().is_loopback() {
            release_failed_port_reservation(&reservation_id);
            return Err(ConformanceShardAdapterError::NonLoopbackPortReservation);
        }
        Ok(ConformancePortReservation {
            reservation_id,
            local_addr,
            listener,
        })
    }

    /// Creates and marks the shard's exact `PostgreSQL` schema transactionally.
    ///
    /// An already-present schema is never adopted, even when it has the same
    /// name. Cleanup later rechecks the immutable ownership marker before it
    /// can issue `DROP SCHEMA ... CASCADE`.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical derived name, an occupied schema, or any
    /// `PostgreSQL` failure.
    pub async fn provision_postgres_schema(
        &self,
        pool: &PgPool,
    ) -> Result<ConformancePostgresSchema, ConformanceShardAdapterError> {
        let name = self.identity.postgres_schema().to_owned();
        validate_postgres_schema(&name)?;
        if postgres_schema_marker(pool, &name).await?.is_some() {
            return Err(ConformanceShardAdapterError::PostgresSchemaOccupied);
        }

        let marker = format!("{PG_NAMESPACE_OWNERSHIP_MARKER_HEAD}{}", self.identity.id());
        let quoted_name = quote_postgres_identifier(&name);
        let quoted_marker = quote_postgres_literal(&marker);
        let mut transaction = pool.begin().await?;
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {quoted_name}")))
            .execute(&mut *transaction)
            .await?;
        sqlx::query(AssertSqlSafe(format!(
            "COMMENT ON SCHEMA {quoted_name} IS {quoted_marker}"
        )))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        Ok(ConformancePostgresSchema {
            pool: pool.clone(),
            name,
            marker,
        })
    }
}

/// Immutable object operations that cannot escape one shard prefix.
#[derive(Debug)]
pub struct ConformanceShardBlobStore<Store> {
    store: Store,
    prefix: String,
}

impl<Store> ConformanceShardBlobStore<Store>
where
    Store: ImmutableBlobStore,
{
    /// Builds one validated provider key below the derived shard prefix.
    ///
    /// # Errors
    ///
    /// Rejects empty, absolute, traversing, oversized, or otherwise invalid
    /// relative keys.
    pub fn provider_key(
        &self,
        relative_key: &str,
    ) -> Result<BlobKey, ConformanceShardAdapterError> {
        if relative_key.is_empty()
            || relative_key.starts_with('/')
            || self.is_provider_namespace_key(relative_key)
        {
            return Err(ConformanceShardAdapterError::InvalidRelativeObjectKey);
        }
        let key = BlobKey::new(format!("{}{relative_key}", self.prefix))?;
        if !self.owns_provider_key(&key) {
            return Err(ConformanceShardAdapterError::InvalidRelativeObjectKey);
        }
        Ok(key)
    }

    /// Stores immutable bytes below the derived prefix.
    ///
    /// # Errors
    ///
    /// Returns a key-validation or underlying immutable-store failure.
    pub async fn put_provider(
        &self,
        relative_key: &str,
        media_type: MediaType,
        bytes: Bytes,
    ) -> Result<(PutBlobOutcome, BlobDescriptor), ConformanceShardAdapterError> {
        let payload = BlobPayload::from_bytes(self.provider_key(relative_key)?, media_type, bytes);
        let descriptor = payload.descriptor().clone();
        let outcome = self.store.put_if_absent(payload).await?;
        Ok((outcome, descriptor))
    }

    /// Reads and verifies an immutable object only when its key belongs to this
    /// shard.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor from any other shard before consulting the store,
    /// or returns the underlying verified-read failure.
    pub async fn get_provider_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, ConformanceShardAdapterError> {
        if !self.owns_provider_key(descriptor.key()) {
            return Err(ConformanceShardAdapterError::ForeignObjectDescriptor);
        }
        Ok(self.store.get_verified(descriptor, maximum_bytes).await?)
    }

    /// Returns the exact derived object prefix enforced by this wrapper.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn owns_provider_key(&self, key: &BlobKey) -> bool {
        key.as_str().starts_with(&self.prefix)
    }

    fn is_provider_namespace_key(&self, key: &str) -> bool {
        let namespace_end = self
            .prefix
            .match_indices('/')
            .nth(1)
            .map_or(self.prefix.len(), |(index, _)| index + 1);
        key.starts_with(&self.prefix[..namespace_end])
    }

    fn scoped_provider_key(&self, logical: &BlobKey) -> Result<BlobKey, BlobStoreError> {
        if self.is_provider_namespace_key(logical.as_str()) {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Unauthorized));
        }
        BlobKey::new(format!("{}{}", self.prefix, logical.as_str()))
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::InvalidResponse))
    }
}

#[async_trait::async_trait]
impl<Store> ImmutableBlobStore for ConformanceShardBlobStore<Store>
where
    Store: ImmutableBlobStore,
{
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let (logical, bytes) = payload.into_parts();
        let provider_key = self.scoped_provider_key(logical.key())?;
        let provider_payload =
            BlobPayload::from_bytes(provider_key, logical.media_type().clone(), bytes);
        if provider_payload.descriptor().digest() != logical.digest()
            || provider_payload.descriptor().size() != logical.size()
        {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        self.store.put_if_absent(provider_payload).await
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let provider_descriptor = BlobDescriptor::new(
            self.scoped_provider_key(descriptor.key())?,
            descriptor.digest(),
            descriptor.size(),
            descriptor.media_type().clone(),
        );
        let verified = self
            .store
            .get_verified(&provider_descriptor, maximum_bytes)
            .await?;
        let logical_payload = BlobPayload::verify(descriptor.clone(), verified.into_bytes())
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        Ok(VerifiedBlob::from_payload(logical_payload))
    }
}

/// A held loopback port and its shard-derived ownership identity.
pub struct ConformancePortReservation {
    reservation_id: String,
    local_addr: SocketAddr,
    listener: TcpListener,
}

impl ConformancePortReservation {
    /// Returns the stable shard/purpose reservation identity retained in
    /// fixture evidence.
    #[must_use]
    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    /// Returns the actual held loopback socket address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Transfers the already-bound listener to a server or process adapter.
    ///
    /// Reservation identities are deliberately single-use for the process:
    /// transferring or dropping the listener does not make the same
    /// shard/purpose identity reservable again. A retry must derive a new run
    /// identity, which prevents two live adapters from emitting the same
    /// reservation evidence.
    #[must_use]
    pub fn into_listener(self) -> TcpListener {
        self.listener
    }
}

impl std::fmt::Debug for ConformancePortReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConformancePortReservation")
            .field("reservation_id", &self.reservation_id)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

/// One marker-owned `PostgreSQL` schema selected from a product shard plan.
#[derive(Debug)]
pub struct ConformancePostgresSchema {
    pool: PgPool,
    name: String,
    marker: String,
}

impl ConformancePostgresSchema {
    /// Returns the exact derived schema name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Begins a transaction whose unqualified objects resolve only below this
    /// shard schema, `pg_catalog`, and then an explicit `pg_temp`.
    ///
    /// The setting is transaction-local, so returning the pooled connection
    /// cannot leak a shard search path into another caller.
    ///
    /// # Errors
    ///
    /// Returns a `PostgreSQL` failure or a fail-closed search-path mismatch.
    pub async fn begin_isolated(
        &self,
    ) -> Result<Transaction<'_, Postgres>, ConformanceShardAdapterError> {
        let mut transaction = self.pool.begin().await?;
        let installed_path = sqlx::query_scalar::<_, String>(
            r"
            SELECT pg_catalog.set_config(
                'search_path',
                pg_catalog.quote_ident($1) || ', pg_catalog, pg_temp',
                TRUE
            )
            ",
        )
        .bind(&self.name)
        .fetch_one(&mut *transaction)
        .await?;
        let expected_path = format!("{}, pg_catalog, pg_temp", self.name);
        let current_schema: Option<String> =
            sqlx::query_scalar("SELECT pg_catalog.current_schema()")
                .fetch_one(&mut *transaction)
                .await?;
        if installed_path != expected_path || current_schema.as_deref() != Some(self.name.as_str())
        {
            return Err(ConformanceShardAdapterError::PostgresSearchPathMismatch);
        }
        Ok(transaction)
    }

    /// Drops exactly this schema after rechecking its ownership marker.
    ///
    /// # Errors
    ///
    /// Refuses an absent or differently owned schema and returns any
    /// `PostgreSQL` cleanup failure.
    pub async fn cleanup(self) -> Result<(), ConformanceShardAdapterError> {
        let mut transaction = self.pool.begin().await?;
        let marker = postgres_schema_marker_in(&mut transaction, &self.name).await?;
        match marker {
            None => return Err(ConformanceShardAdapterError::PostgresSchemaMissing),
            Some(marker) if marker.as_deref() != Some(self.marker.as_str()) => {
                return Err(ConformanceShardAdapterError::PostgresSchemaOwnershipMismatch);
            }
            Some(_) => {}
        }

        let quoted_name = quote_postgres_identifier(&self.name);
        sqlx::query(AssertSqlSafe(format!("DROP SCHEMA {quoted_name} CASCADE")))
            .execute(&mut *transaction)
            .await?;
        let remains: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)",
        )
        .bind(&self.name)
        .fetch_one(&mut *transaction)
        .await?;
        if remains {
            return Err(ConformanceShardAdapterError::PostgresSchemaCleanupInexact);
        }
        transaction.commit().await?;
        Ok(())
    }
}

async fn postgres_schema_marker(
    pool: &PgPool,
    name: &str,
) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar(
        r"
        SELECT pg_catalog.obj_description(oid, 'pg_namespace')
        FROM pg_catalog.pg_namespace
        WHERE nspname = $1
        ",
    )
    .bind(name)
    .fetch_optional(pool)
    .await
}

async fn postgres_schema_marker_in(
    transaction: &mut Transaction<'_, Postgres>,
    name: &str,
) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar(
        r"
        SELECT pg_catalog.obj_description(oid, 'pg_namespace')
        FROM pg_catalog.pg_namespace
        WHERE nspname = $1
        ",
    )
    .bind(name)
    .fetch_optional(&mut **transaction)
    .await
}

fn claim_port_reservation(reservation_id: &str) -> Result<(), ConformanceShardAdapterError> {
    let reservations = SPENT_PORT_RESERVATIONS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut reservations = reservations
        .lock()
        .map_err(|_| ConformanceShardAdapterError::PortReservationRegistryUnavailable)?;
    if !reservations.insert(reservation_id.to_owned()) {
        return Err(ConformanceShardAdapterError::DuplicatePortReservation);
    }
    if reservations.len() > MAX_SPENT_PORT_RESERVATIONS {
        reservations.remove(reservation_id);
        return Err(ConformanceShardAdapterError::PortReservationRegistryExhausted);
    }
    Ok(())
}

fn release_failed_port_reservation(reservation_id: &str) {
    if let Some(reservations) = SPENT_PORT_RESERVATIONS.get()
        && let Ok(mut reservations) = reservations.lock()
    {
        reservations.remove(reservation_id);
    }
}

fn validate_local_identity(value: &str) -> Result<(), ConformanceShardAdapterError> {
    let mut bytes = value.bytes();
    if value.len() > MAX_LOCAL_IDENTITY_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(ConformanceShardAdapterError::InvalidLocalIdentity);
    }
    Ok(())
}

fn validate_postgres_schema(name: &str) -> Result<(), ConformanceShardAdapterError> {
    let Some(digest) = name.strip_prefix(PG_NAMESPACE_IDENTIFIER_HEAD) else {
        return Err(ConformanceShardAdapterError::InvalidDerivedPostgresSchema);
    };
    if digest.len() != PG_NAMESPACE_DIGEST_HEX_LEN
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConformanceShardAdapterError::InvalidDerivedPostgresSchema);
    }
    Ok(())
}

fn quote_postgres_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_postgres_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Failure to bind a concrete product adapter to one conformance shard.
#[derive(Debug, Error)]
pub enum ConformanceShardAdapterError {
    /// A local purpose or credential identity was not canonical.
    #[error("the shard-local identity must be 1..=64 lowercase ASCII letters, digits, '-' or '_'")]
    InvalidLocalIdentity,
    /// A caller attempted to construct an empty or absolute relative object key.
    #[error("the shard-relative object key is invalid")]
    InvalidRelativeObjectKey,
    /// A product blob key rejected the derived prefix or requested relative key.
    #[error("the shard-scoped object key is invalid")]
    BlobKey(#[from] BlobKeyError),
    /// A read descriptor belongs to a different shard prefix.
    #[error("the immutable object descriptor belongs to another shard")]
    ForeignObjectDescriptor,
    /// The product immutable object store rejected an operation.
    #[error("the shard-scoped immutable object operation failed")]
    BlobStore(#[from] BlobStoreError),
    /// The existing hermetic GitHub adapter rejected the scoped credential.
    #[error("the shard-scoped hermetic GitHub credential is invalid")]
    HermeticGithubCredential(#[source] HermeticGithubStubError),
    /// A real loopback listener could not be bound or inspected.
    #[error("the shard-scoped loopback port could not be reserved")]
    PortReservation(#[source] io::Error),
    /// A listener unexpectedly resolved outside loopback.
    #[error("the shard-scoped port reservation was not loopback-only")]
    NonLoopbackPortReservation,
    /// The same shard/purpose reservation identity was already consumed.
    #[error("the shard-scoped port reservation identity is single-use and already consumed")]
    DuplicatePortReservation,
    /// The process-local single-use reservation ledger was unavailable.
    #[error("the shard-scoped port reservation ledger is unavailable")]
    PortReservationRegistryUnavailable,
    /// The bounded process-local single-use reservation ledger is full.
    #[error("the shard-scoped port reservation ledger is exhausted")]
    PortReservationRegistryExhausted,
    /// A future shard-plan version produced a `PostgreSQL` name this adapter
    /// cannot prove safe to quote.
    #[error("the derived PostgreSQL schema name is not canonical")]
    InvalidDerivedPostgresSchema,
    /// The exact derived `PostgreSQL` schema already exists and is never adopted.
    #[error("the derived PostgreSQL schema is already occupied")]
    PostgresSchemaOccupied,
    /// The isolated transaction did not resolve to the derived schema.
    #[error("PostgreSQL did not install the shard-isolated search path")]
    PostgresSearchPathMismatch,
    /// Cleanup found that the exact provisioned schema had disappeared.
    #[error("the owned PostgreSQL shard schema is missing")]
    PostgresSchemaMissing,
    /// Cleanup refused a schema whose ownership marker changed.
    #[error("the PostgreSQL shard schema ownership marker differs")]
    PostgresSchemaOwnershipMismatch,
    /// `PostgreSQL` reported a drop while the exact schema still existed.
    #[error("the PostgreSQL shard schema cleanup was inexact")]
    PostgresSchemaCleanupInexact,
    /// `PostgreSQL` rejected provisioning, use, or cleanup.
    #[error("the PostgreSQL shard adapter failed")]
    Postgres(#[from] sqlx::Error),
}
