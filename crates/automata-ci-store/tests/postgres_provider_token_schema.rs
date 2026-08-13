const PROVIDER_TOKEN_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn provider_token_vault_schema_is_ciphertext_only_fail_closed_and_one_way() {
    assert!(PROVIDER_TOKEN_MIGRATION.contains("human_provider_tokens_legacy_envelope_rows"));
    assert!(PROVIDER_TOKEN_MIGRATION.contains("envelope_record_id UUID NOT NULL"));
    assert!(PROVIDER_TOKEN_MIGRATION.contains("PRIMARY KEY (envelope_record_id)"));
    assert!(PROVIDER_TOKEN_MIGRATION.contains("human_provider_tokens_one_active_identity"));
    assert!(!PROVIDER_TOKEN_MIGRATION.contains("encrypted_payload BYTEA"));
    assert!(!PROVIDER_TOKEN_MIGRATION.contains("access_token"));
    assert!(!PROVIDER_TOKEN_MIGRATION.contains("refresh_token"));
    assert!(!PROVIDER_TOKEN_MIGRATION.contains("DELETE FROM human_provider_tokens"));
    assert!(PROVIDER_TOKEN_MIGRATION.contains("encrypted_payload IS NULL"));
    assert!(PROVIDER_TOKEN_MIGRATION.contains("wrapped_data_key IS NULL"));
    assert!(PROVIDER_TOKEN_MIGRATION.contains("human_provider_tokens_tombstone_immutable"));
    assert!(
        PROVIDER_TOKEN_MIGRATION
            .contains("revoked_at_ms IS NULL AND access_expires_at_ms IS NOT NULL")
    );
    assert!(!PROVIDER_TOKEN_MIGRATION.contains("'refresh'"));
}
