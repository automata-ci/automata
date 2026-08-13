const ARTIFACT_FINALIZATION_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn initial_schema_defines_recoverable_artifact_finalization_directly() {
    let normalized = ARTIFACT_FINALIZATION_MIGRATION.to_ascii_lowercase();
    assert!(normalized.contains("create table workflow_artifacts"));
    assert!(normalized.contains("finalization_generation bigint default 0 not null"));
    assert!(normalized.contains("finalization_claimed_size_bytes bigint"));
    assert!(normalized.contains("finalization_claimed_digest bytea"));
    assert!(normalized.contains("finalization_claim_expires_at_seconds bigint"));
    assert!(normalized.contains("manifest_bytes bytea"));
    assert!(normalized.contains("finalization_generation > 0"));
    assert!(normalized.contains("octet_length(manifest_bytes) = manifest_size_bytes"));
    assert!(normalized.contains("finalization_claimed_digest = content_digest"));
    assert!(
        !normalized.contains("update workflow_artifacts"),
        "the greenfield migration must not backfill legacy artifact rows"
    );
}
