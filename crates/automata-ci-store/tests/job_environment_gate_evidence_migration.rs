static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0067_is_embedded_after_resource_policy_v2() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let index = migrations
        .iter()
        .position(|migration| migration.version == 67)
        .expect("migration 0067 is embedded");
    assert_eq!(migrations[index - 1].version, 66);
    assert_eq!(
        migrations[index].description.as_ref(),
        "job environment gate evidence"
    );
}
