use std::{fs, path::Path};

#[test]
fn greenfield_schema_has_one_canonical_baseline() {
    let migration_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut entries = fs::read_dir(&migration_directory)
        .expect("read migration directory")
        .map(|entry| {
            entry
                .expect("read migration entry")
                .file_name()
                .into_string()
                .expect("UTF-8 migration filename")
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();

    assert_eq!(entries, ["0001_initial_schema.sql"]);
}
