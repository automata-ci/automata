use sha2::{Digest as _, Sha256};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
const RUNTIME_LIVENESS: &str =
    include_str!("../migrations/0069_protected_environment_gate_liveness.sql");
const RELEASED_0052: &str = include_str!("../migrations/0052_github_service_policy_rotation.sql");
const RELEASED_0053: &str =
    include_str!("../migrations/0053_github_check_credential_rejection.sql");

#[test]
fn released_0052_and_0053_remain_byte_exact() {
    let service: [u8; 32] = Sha256::digest(RELEASED_0052.as_bytes()).into();
    let rejection: [u8; 32] = Sha256::digest(RELEASED_0053.as_bytes()).into();
    assert_eq!(
        service,
        [
            0x91, 0x07, 0x71, 0x7d, 0x23, 0xdf, 0x5d, 0xc5, 0x83, 0x21, 0xa0, 0x45, 0xf2, 0xc1,
            0x91, 0xec, 0x13, 0xdd, 0xe7, 0xbb, 0xd2, 0x91, 0x52, 0x9d, 0xcb, 0x8e, 0x50, 0x4b,
            0x49, 0xdf, 0xb5, 0xbb,
        ]
    );
    assert_eq!(
        rejection,
        [
            0xd3, 0x98, 0x6a, 0xfe, 0x03, 0x43, 0xad, 0xec, 0xa4, 0xdc, 0xf8, 0xd0, 0xb1, 0x32,
            0x88, 0xa8, 0x08, 0x1b, 0xcd, 0x39, 0x24, 0xf4, 0x88, 0x12, 0x18, 0xfa, 0x84, 0x68,
            0xbd, 0xc2, 0xff, 0x7f,
        ]
    );
}

#[test]
fn runtime_liveness_migration_remains_byte_exact() {
    let digest: [u8; 32] = Sha256::digest(RUNTIME_LIVENESS.as_bytes()).into();
    assert_eq!(
        digest,
        [
            0x55, 0x45, 0x0f, 0x4a, 0x29, 0xda, 0xb8, 0xf2, 0xf2, 0xb6, 0x25, 0x05, 0xd5, 0x40,
            0x61, 0xd3, 0xc5, 0x63, 0x68, 0xe5, 0xd0, 0x81, 0x18, 0xd0, 0xd3, 0x97, 0x50, 0x06,
            0xb6, 0x39, 0x52, 0xaa,
        ],
        "runtime liveness migration changed bytes"
    );
}

#[test]
fn post_runtime_capability_migrations_are_embedded_in_order() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let service_rotation = migrations
        .iter()
        .position(|migration| migration.version == 52)
        .expect("migration 0052 is embedded");
    let credential_rejection = migrations
        .iter()
        .position(|migration| migration.version == 53)
        .expect("migration 0053 is embedded");
    let evidence = migrations
        .iter()
        .position(|migration| migration.version == 67)
        .expect("migration 0067 is embedded");
    let review = migrations
        .iter()
        .position(|migration| migration.version == 68)
        .expect("migration 0068 is embedded");
    let liveness = migrations
        .iter()
        .position(|migration| migration.version == 69)
        .expect("migration 0069 is embedded");
    let lease_authority = migrations
        .iter()
        .position(|migration| migration.version == 70)
        .expect("migration 0070 is embedded");
    assert!(
        service_rotation < credential_rejection
            && credential_rejection < evidence
            && evidence < review
            && review < liveness
            && liveness < lease_authority
    );
    assert_eq!(
        migrations[service_rotation].description.as_ref(),
        "github service policy rotation"
    );
    assert_eq!(
        migrations[credential_rejection].description.as_ref(),
        "github check credential rejection"
    );
    assert_eq!(
        migrations[lease_authority].description.as_ref(),
        "protected environment lease authority"
    );
}
