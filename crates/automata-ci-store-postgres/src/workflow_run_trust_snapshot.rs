use automata_ci_core::{
    Sha256Digest, TRUST_SNAPSHOT_SCHEMA_V1, TRUST_SNAPSHOT_V1_MEDIA_TYPE, TrustSnapshot,
};
use automata_ci_store::StoreError;
use sqlx::{Row as _, postgres::PgRow};

/// Decodes and validates one canonical run-bound trust snapshot projection.
pub(super) fn decode_trust_snapshot(row: &PgRow) -> Result<TrustSnapshot, StoreError> {
    let schema: i16 = row
        .try_get("trust_snapshot_schema")
        .map_err(StoreError::operation)?;
    if schema != i16::try_from(TRUST_SNAPSHOT_SCHEMA_V1).unwrap_or(i16::MAX) {
        return Err(StoreError::corrupt_data(
            "unsupported durable trust snapshot schema",
        ));
    }
    let policy_revision: i64 = row
        .try_get("trust_policy_revision")
        .map_err(StoreError::operation)?;
    let policy_digest = decode_digest(row, "trust_policy_digest")?;
    let snapshot_digest = decode_digest(row, "trust_snapshot_digest")?;
    let snapshot_bytes: Vec<u8> = row
        .try_get("trust_snapshot_bytes")
        .map_err(StoreError::operation)?;
    let media_type: String = row
        .try_get("trust_media_type")
        .map_err(StoreError::operation)?;
    if media_type != TRUST_SNAPSHOT_V1_MEDIA_TYPE {
        return Err(StoreError::corrupt_data(
            "unsupported durable trust snapshot media type",
        ));
    }
    let snapshot = TrustSnapshot::from_canonical_bytes(&snapshot_bytes, snapshot_digest)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let exact_metadata = i64::try_from(snapshot.policy_revision().get()).ok()
        == Some(policy_revision)
        && snapshot.policy_digest() == policy_digest;
    if !exact_metadata {
        return Err(StoreError::corrupt_data(
            "durable trust snapshot metadata disagrees with its canonical bytes",
        ));
    }
    Ok(snapshot)
}

fn decode_digest(row: &PgRow, column: &str) -> Result<Sha256Digest, StoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(StoreError::operation)?;
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{column} is not SHA-256")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}
