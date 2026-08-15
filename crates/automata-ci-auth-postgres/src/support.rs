use automata_ci_auth::{
    management::{ManagementRepositoryError, ManagementRevision},
    time::UnixTimestamp,
};
use sqlx::{Error as SqlxError, Postgres, Transaction, postgres::PgDatabaseError};
use uuid::Uuid;

pub(crate) fn timestamp_to_milliseconds(value: UnixTimestamp) -> Result<i64, ()> {
    let milliseconds = value.as_seconds().checked_mul(1_000).ok_or(())?;
    i64::try_from(milliseconds).map_err(|_| ())
}

pub(crate) fn timestamp_from_milliseconds(value: i64) -> Result<UnixTimestamp, ()> {
    let value = u64::try_from(value).map_err(|_| ())?;
    if value % 1_000 != 0 {
        return Err(());
    }
    Ok(UnixTimestamp::from_seconds(value / 1_000))
}

pub(crate) fn canonical_uuid(value: &str) -> Result<Uuid, ()> {
    let parsed = Uuid::parse_str(value).map_err(|_| ())?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(());
    }
    Ok(parsed)
}

pub(crate) fn management_revision_to_i64(
    revision: ManagementRevision,
) -> Result<i64, ManagementRepositoryError> {
    i64::try_from(revision.value()).map_err(|_| ManagementRepositoryError::InvalidRequest)
}

pub(crate) fn management_revision_from_i64(
    revision: i64,
) -> Result<ManagementRevision, ManagementRepositoryError> {
    u64::try_from(revision)
        .ok()
        .and_then(|revision| ManagementRevision::new(revision).ok())
        .ok_or(ManagementRepositoryError::CorruptData)
}

pub(crate) async fn tenant_management_lock(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), SqlxError> {
    // One fixed namespace serializes all tenant RBAC writers across adapters.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 731662009))")
        .bind(tenant_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(crate) async fn tenant_management_read_lock(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), SqlxError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 731662009))")
        .bind(tenant_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(crate) fn constraint(error: &SqlxError) -> Option<&str> {
    error
        .as_database_error()
        .and_then(|error| error.try_downcast_ref::<PgDatabaseError>())
        .and_then(PgDatabaseError::constraint)
}

pub(crate) fn is_integrity_violation(error: &SqlxError) -> bool {
    error.as_database_error().is_some_and(|database| {
        database.is_unique_violation()
            || database.is_foreign_key_violation()
            || database.is_check_violation()
    })
}
