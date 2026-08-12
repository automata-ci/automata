static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0066_is_embedded_after_resource_policy_v2() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let index = migrations
        .iter()
        .position(|migration| migration.version == 66)
        .expect("migration 0066 is embedded");
    assert_eq!(migrations[index - 1].version, 65);
    assert_eq!(
        migrations[index].description.as_ref(),
        "job environment gate evidence"
    );
}
