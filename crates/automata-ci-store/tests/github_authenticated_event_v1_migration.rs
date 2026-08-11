const MIGRATION: &str = include_str!("../migrations/0049_github_authenticated_event_v1.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_versions_generic_event_evidence_without_reinterpreting_legacy_rows() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 49)
        .expect("migration 0049 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "github authenticated event v1"
    );

    for required in [
        "authenticated_event_envelope_version SMALLINT",
        "authenticated_event_name TEXT COLLATE \"C\"",
        "authenticated_event_git_ref TEXT COLLATE \"C\"",
        "authenticated_event_envelope_version IS NULL",
        "authenticated_event_name IS NULL",
        "authenticated_event_git_ref IS NULL",
        "authenticated_event_envelope_version = 1",
        "authenticated_event_name IN ('push', 'pull_request', 'merge_group')",
        "application/vnd.automata.github-authenticated-event.v1+json",
        "automata_github_authenticated_event_v1_exact",
        "COALESCE(source_evidence.authenticated_event_name, source_evidence.manifest_event_name)",
        "COALESCE(source_evidence.authenticated_event_git_ref, source_evidence.manifest_git_ref)",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing authenticated-event invariant: {required}"
        );
    }
}

#[test]
fn migration_retains_only_bounded_routing_evidence() {
    for prohibited in [
        "raw_event_body BYTEA",
        "webhook_secret",
        "installation_token",
        "pull_request_title",
        "merge_group_payload",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "migration must not retain private or redundant event content: {prohibited}"
        );
    }
}
