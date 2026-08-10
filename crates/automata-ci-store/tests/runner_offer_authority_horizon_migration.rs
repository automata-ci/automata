const MIGRATION: &str = include_str!("../migrations/0045_runner_offer_authority_horizon.sql");

#[test]
fn migration_refuses_ambiguous_backfill_and_pins_the_exclusive_horizon() {
    assert!(MIGRATION.contains(
        "LOCK TABLE runners, runner_sessions, job_attempts, runner_command_outbox,\n    runner_rpc_receipts, runner_lease_offer_publications"
    ));
    assert!(MIGRATION.contains("runner_database_time_upgrade"));
    assert!(MIGRATION.contains("heartbeat_at_ms > database_now_ms + 60000"));
    assert!(MIGRATION.contains("IF EXISTS (SELECT 1 FROM runner_lease_offer_publications)"));
    assert!(MIGRATION.contains("runner_lease_offer_authority_horizon_upgrade"));
    assert!(MIGRATION.contains("ADD COLUMN offer_valid_until_ms BIGINT NOT NULL"));
    assert!(MIGRATION.contains("created_at_ms >= lease_issued_at_ms"));
    assert!(MIGRATION.contains("offer_valid_until_ms > created_at_ms"));
    assert!(MIGRATION.contains("offer_valid_until_ms <= lease_expires_at_ms"));
    assert!(MIGRATION.contains("runner_lease_offer_authority_horizon_immutable"));
    assert!(
        MIGRATION
            .contains("BEFORE UPDATE OF offer_valid_until_ms ON runner_lease_offer_publications")
    );
    assert!(MIGRATION.contains("runner_lease_offer_delivery_revocation_authority"));
    assert!(MIGRATION.contains("FROM job_attempts AS attempt"));
    assert!(MIGRATION.contains("FOR UPDATE;"));
    assert!(MIGRATION.contains("database_now_ms := floor("));
    assert!(MIGRATION.contains("BEFORE INSERT OR UPDATE ON runner_lease_offer_publications"));
    assert!(!MIGRATION.contains("DEFAULT"));
    assert!(!MIGRATION.contains("SET offer_valid_until_ms = lease_expires_at_ms"));
}
