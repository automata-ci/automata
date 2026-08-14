use std::{fs, path::Path};

const BASELINE_MIGRATION_COUNT: u32 = 26;
const MAX_MIGRATION_LINES: usize = 2_000;

#[test]
fn migrations_are_bounded_and_the_baseline_is_explicit() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut migrations = fs::read_dir(directory)
        .expect("read PostgreSQL migrations")
        .map(|entry| entry.expect("read migration entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    migrations.sort_by_key(|path| migration_version(path));

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

fn migration_version(path: &Path) -> u32 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split_once('_'))
        .and_then(|(version, _description)| version.parse().ok())
        .expect("migration starts with a numeric version")
}
