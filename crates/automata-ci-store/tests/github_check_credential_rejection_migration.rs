const MIGRATION: &str = include_str!("../migrations/0053_github_check_credential_rejection.sql");

#[test]
fn credential_rejection_is_one_exact_immutable_claim_transition() {
    for required in [
        "'ambiguous_create', 'attempt_limit', 'credential_rejected'",
        "github_check_projection_outbox_00_credential_rejection_guard",
        "OLD.state = 'blocked' AND OLD.blocked_reason = 'credential_rejected'",
        "NEW IS DISTINCT FROM OLD",
        "expected := OLD",
        "expected.state := 'blocked'",
        "expected.blocked_reason := 'credential_rejected'",
        "OLD.state <> 'claimed'",
        "NEW.state_updated_at_ms < OLD.claimed_at_ms",
        "NEW.state_updated_at_ms >= OLD.claim_expires_at_ms",
        "github_check_projection_credential_rejection_exact",
        "github_check_projection_credential_rejection_immutable",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing credential-rejection transition invariant: {required}"
        );
    }
}

#[test]
fn historical_authority_retirement_preserves_only_the_exact_live_route() {
    for (scope, fingerprint) in [
        (
            "checks_write",
            "86db54f098adc51219d176555d5f7b5461a4c45ddd0625393846b1b3a5ae6543",
        ),
        (
            "private_repository_source_read",
            "878f4bd01bfe4b04e84d9b9eee32667d31d55feebe78a7b2f59ed715b1145b32",
        ),
    ] {
        assert!(
            MIGRATION.contains(&format!(
                "'{scope}',\n        decode(\n            '{fingerprint}',"
            )),
            "compatible fingerprint is not bound to {scope}"
        );
    }
    for required in [
        "github_provider_manifest_current AS current",
        "automata_migration_0053_manifest_scopes",
        "automata_migration_0053_current_routes",
        "automata_migration_0053_compatible_routes",
        "86db54f098adc51219d176555d5f7b5461a4c45ddd0625393846b1b3a5ae6543",
        "878f4bd01bfe4b04e84d9b9eee32667d31d55feebe78a7b2f59ed715b1145b32",
        "authority.app_configuration_revision =",
        "scope.app_configuration_revision",
        "authority.policy_revision = scope.policy_revision",
        "HAVING count(route.authority_id) <> 1",
        "github_server_service_current_manifest_route_exact",
        "historical.configuration_fingerprint",
        "current_route.configuration_fingerprint",
        ") IS NOT DISTINCT FROM ROW(",
        "compatible.service_scope = historical.service_scope",
        "compatible.configuration_fingerprint",
        "manifest.repository_source_authentication = 'anonymous_public'",
        "historical.service_scope = 'private_repository_source_read'",
        "issuance.state NOT IN ('rejected', 'revoked')",
        "github_server_service_historical_route_retirement_safe",
        "state = 'retired'",
        "github_server_service_historical_route_retirement_complete",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing historical-authority retirement invariant: {required}"
        );
    }
}

#[test]
fn migration_never_rebinds_history_or_forges_provider_reconciliation() {
    for prohibited in [
        "UPDATE github_provider_delivery_evidence",
        "SET checks_authority_id",
        "SET private_source_authority_id",
        "DELETE FROM github_server_service",
        "WHEN state = 'ready' THEN 'revoke_pending'",
        "WHEN state = 'minting' THEN 'indeterminate'",
        "authority_retired_before_mint",
        "UPDATE github_server_service_authority_issuances",
        "provider_revoked",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "migration must not rewrite history or fake provider work: {prohibited}"
        );
    }
}
