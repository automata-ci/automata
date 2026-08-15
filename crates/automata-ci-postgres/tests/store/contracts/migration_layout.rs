use std::{fmt::Write as _, fs, path::Path, path::PathBuf};

use sha2::{Digest as _, Sha384};

static EMBEDDED_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const FROZEN_MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_baseline_routines_01.sql",
        "a88f5c285d9d0286eb5f9d3812c06e254ff22ded8041b014ce666f73c29436d92f2ba0ec3633fdb59d779da6918e7a2a",
    ),
    (
        "0002_baseline_routines_02.sql",
        "4c898ae75d418faa47c31ad38b55369130c571ddcc6b7961112d9ee024faaa04e329ba8741b872f59a65608fe3e8dda3",
    ),
    (
        "0003_baseline_routines_03.sql",
        "6094bc86a6b041c70c8cfd3e04d202bf03272e94b39ea7131b61e7c67e30a6bb307a89771a3325e4a15a2b215237381f",
    ),
    (
        "0004_baseline_routines_04.sql",
        "e4161674d25811f9da1e1f6152ad6eb9c1086edb85e3f3791588450c1678105b0a799b3780c8272b4f8ad9eb364017be",
    ),
    (
        "0005_baseline_routines_05.sql",
        "4f796ebcfcf8390bf9b40843fe25e91bb935ac29730959cbee0830d2e96bbb8175253fc32ffbbc25792bb5894a7398f4",
    ),
    (
        "0006_baseline_routines_06.sql",
        "57d00fe6cd4a68825eeea8b964a28801bfba2c4e13b8b8112e1cec5b5ec655fe15b3e236e03fa8add09945ced1534625",
    ),
    (
        "0007_baseline_routines_07.sql",
        "39206936cadbfabef47a775440353367eaa1e9737f3a79c4da360c71511093f0c5e2c4fcb42b67a133d6f93ea4d333b7",
    ),
    (
        "0008_baseline_routines_08.sql",
        "bd208061cc3d0c296656fd50514fbbf6b2bca8eb6d7b8e07d25c2892923295f4b63348383b1b0fed8656c5d04da51def",
    ),
    (
        "0009_baseline_routines_09.sql",
        "4e1a8df6e6a29b5aa5faf1e501b33336db04e8bcc18cffe473b969f4bb5c7921f257cbf4e3093c370f11d3e49560ced1",
    ),
    (
        "0010_baseline_routines_10.sql",
        "5e1c67bd3d713fc9521d147a31fd0965c18f2f86ee27f4ac899c0db239e33f3d11e212ee6004877aa2c7c59b23229a86",
    ),
    (
        "0011_baseline_routines_11.sql",
        "92de743ed564db5d9abf3600c6c1e5f1c219b4a8cd8650a73683dc9c89cab30f87eead7526718388276a4f6545476c7c",
    ),
    (
        "0012_baseline_routines_12.sql",
        "22fe7a4a46350513482df3c314e700c0bc677087edbcb6510cbf45e9ed6020fb7ed6f30da0fb9a5bc8755e83a04f5042",
    ),
    (
        "0013_baseline_routines_13.sql",
        "83830f456686e1c70e489035dca32ab3591a653a3052c5153760a4a41df7b27155b4b7c93cbb3826e357a0f7d09a36e9",
    ),
    (
        "0014_baseline_routines_14.sql",
        "660156bf9bea050692a63cef6a7e945b8d8644ae03cf4993d6282b3c838b1db198af8ec190b927e47c82a089436dd387",
    ),
    (
        "0015_baseline_routines_15.sql",
        "04721f411fc6aa8aaba893b879d7a1ec42ed49d1d95bdfe0966db2584bc502cc55955dca8573ec3f0bb4ce4bd43336d0",
    ),
    (
        "0016_baseline_routines_16.sql",
        "d61dafdca2d3484583642b6f1faa7730b0f104ac46243c617e32f2ab89c1082557e309f727ea2ed5692947dbd415033d",
    ),
    (
        "0017_baseline_relations_execution.sql",
        "9d80766241d5b07160607c4e90fcd30d9ee2ac341e89576f1033fd7072e466c0364a10a4479e8eb919bb39979a1603b9",
    ),
    (
        "0018_baseline_relations_auth_and_delivery.sql",
        "5f9baeeea0fa3fa3c3abac2846b0228a8076a63b9dadb7fb8a6a203ec45021258574b1f81f587c396599058eb6c0a99b",
    ),
    (
        "0019_baseline_relations_access_runners_and_secrets.sql",
        "e6b47696f5959411fb0b63704044eab3c5f10b9ee8727a92e669179bd7b9abc20392c3f370c5e5c1e6709ede5e1a25b7",
    ),
    (
        "0020_baseline_relations_tenants_and_workflows.sql",
        "6245e235c08bd6ccd7aa1bc7d99ca003633bf3951b79f239f1b0710a3eba783ba86dd36970e7999ea15a67c08c110a61",
    ),
    (
        "0021_baseline_catalog_rows.sql",
        "44f3fe98a0d5df90196fac954b67fc321d5ddde3aec32a1e23804415ea96379e3775a76a718be6264aeef79f78bb6cc3",
    ),
    (
        "0022_baseline_keys_and_constraints.sql",
        "811561232385a17a9630e8534d98e0538af044ce0ec09f3abddb33a992301245264ceaf16831a92056c2bd82843340d7",
    ),
    (
        "0023_baseline_indexes.sql",
        "9b45a8ae13c283e0b42848782e912df82b0712b9cfdccf7656260cd23151ad27520e2c6e9ed9b65d70a98ca4ab338b59",
    ),
    (
        "0024_baseline_triggers_control_plane.sql",
        "b297b80748236be8b1bb1c1793de1d24be4b24bddb1ae628a93cca616457027658fc582c0560500e7331ce02e0a6a7ef",
    ),
    (
        "0025_baseline_triggers_orchestration.sql",
        "fae94404f5fcdb6283ea690189bf5fcebd46bcaefe11f030029851670d6da3281da0bf089a0abab3f58d69e0005247e5",
    ),
    (
        "0026_baseline_foreign_keys.sql",
        "57e7e93dcdc0ee7568393785b30774259dcf5300f9a8df99ac7795d9799c60b97dec36479976ae99e5c4bd320080a977",
    ),
    (
        "0027_workspace_usage_feed.sql",
        "23d9d52552f960e0b8015cedacf8bbe591773dbb82856e73eb4e436c4840be5475887da0ebbe6330185fee13f835734f",
    ),
];

const BASELINE_MIGRATION_COUNT: u32 = 26;
const MAX_MIGRATION_LINES: usize = 2_000;

#[test]
fn applied_migration_lineage_is_frozen() {
    let migrations = migration_paths();
    assert!(
        !EMBEDDED_MIGRATOR.ignore_missing,
        "the deployed migrator must reject missing applied versions"
    );
    assert_eq!(
        migrations.len(),
        FROZEN_MIGRATIONS.len(),
        "append each new migration to the frozen inventory; never remove an applied migration"
    );
    assert_eq!(
        EMBEDDED_MIGRATOR.iter().count(),
        FROZEN_MIGRATIONS.len(),
        "the embedded migrator must contain the complete frozen inventory"
    );

    for (index, ((path, embedded), (expected_name, expected_checksum))) in migrations
        .iter()
        .zip(EMBEDDED_MIGRATOR.iter())
        .zip(FROZEN_MIGRATIONS)
        .enumerate()
    {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("migration file name is UTF-8");
        let version = u32::try_from(index + 1).expect("migration count fits u32");
        assert_eq!(file_name, *expected_name, "applied migration was renamed");
        assert_eq!(migration_version(path), version);
        assert_eq!(embedded.version, i64::from(version));

        let source = fs::read(path).expect("read migration bytes");
        let checksum = Sha384::digest(source);
        assert_eq!(
            checksum_hex(&checksum),
            *expected_checksum,
            "applied migration {file_name} changed; restore its exact bytes and append a new migration"
        );
        assert_eq!(
            embedded.checksum.as_ref(),
            &checksum[..],
            "embedded migration {file_name} differs from its source bytes"
        );
    }
}

#[test]
fn migrations_are_bounded_and_the_baseline_is_explicit() {
    let migrations = migration_paths();

    assert!(
        migrations.len() >= BASELINE_MIGRATION_COUNT as usize,
        "the complete split baseline must be present"
    );
    for (index, path) in migrations.iter().enumerate() {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("migration file name is UTF-8");
        let version = migration_version(path);
        assert_eq!(
            version,
            u32::try_from(index + 1).expect("migration count fits u32"),
            "migrations use gap-free sequential versions"
        );
        if version <= BASELINE_MIGRATION_COUNT {
            assert!(
                file_name.contains("_baseline_"),
                "baseline migration {file_name} must be named explicitly"
            );
        }

        let source = fs::read_to_string(path).expect("read migration source");
        let lines = source.lines().count();
        assert!(
            lines <= MAX_MIGRATION_LINES,
            "migration {file_name} has {lines} lines; maximum is {MAX_MIGRATION_LINES}"
        );
    }
}

fn migration_paths() -> Vec<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut migrations = fs::read_dir(directory)
        .expect("read PostgreSQL migrations")
        .map(|entry| entry.expect("read migration entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    migrations.sort_by_key(|path| migration_version(path));
    migrations
}

fn checksum_hex(checksum: &[u8]) -> String {
    let mut encoded = String::with_capacity(checksum.len() * 2);
    for byte in checksum {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn migration_version(path: &Path) -> u32 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split_once('_'))
        .and_then(|(version, _description)| version.parse().ok())
        .expect("migration starts with a numeric version")
}
