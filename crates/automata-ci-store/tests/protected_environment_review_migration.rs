static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn review_and_liveness_migrations_are_embedded_in_order() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let evidence = migrations
        .iter()
        .position(|migration| migration.version == 66)
        .expect("migration 0066 is embedded");
    let review = migrations
        .iter()
        .position(|migration| migration.version == 67)
        .expect("migration 0067 is embedded");
    let liveness = migrations
        .iter()
        .position(|migration| migration.version == 68)
        .expect("migration 0068 is embedded");
    assert!(evidence < review && review < liveness);
}
