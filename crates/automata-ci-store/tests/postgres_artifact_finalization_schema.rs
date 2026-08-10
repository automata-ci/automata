const ARTIFACT_FINALIZATION_MIGRATION: &str =
    include_str!("../migrations/0016_artifact_finalization_singleflight.sql");

#[test]
fn artifact_finalization_migration_is_greenfield_fenced_and_recoverable() {
    let normalized = ARTIFACT_FINALIZATION_MIGRATION.to_ascii_lowercase();
    assert!(normalized.contains("if exists (select 1 from workflow_artifacts limit 1)"));
    assert!(normalized.contains("finalization_generation bigint not null default 0"));
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
