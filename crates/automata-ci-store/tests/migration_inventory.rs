use std::{collections::BTreeMap, ffi::OsStr, fs, path::Path};

type InventoryEntry = (String, bool);

fn validate_migration_entries(
    entries: impl IntoIterator<Item = InventoryEntry>,
) -> Result<(), String> {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    let mut migrations_by_version = BTreeMap::<i64, String>::new();
    for (file_name, is_regular_file) in entries {
        let is_sql = Path::new(&file_name).extension() == Some(OsStr::new("sql"));
        if !is_regular_file || !is_sql {
            continue;
        }

        let stem = file_name
            .strip_suffix(".sql")
            .expect("the SQL suffix was checked above");
        let (version_prefix, description) = stem.split_once('_').ok_or_else(|| {
            format!("migration filename `{file_name}` must match <VERSION>_<DESCRIPTION>.sql")
        })?;
        if description.is_empty() {
            return Err(format!(
                "migration filename `{file_name}` must have a nonempty description"
            ));
        }
        if matches!(description.rsplit_once('.'), Some((_, "up" | "down"))) {
            return Err(format!(
                "migration filename `{file_name}` violates the forward-only simple migration contract"
            ));
        }

        let version = version_prefix.parse::<i64>().map_err(|_| {
            format!("migration filename `{file_name}` has a nonnumeric version prefix")
        })?;
        if version <= 0 {
            return Err(format!(
                "migration filename `{file_name}` must have a positive version"
            ));
        }

        if let Some(previous_file_name) = migrations_by_version.insert(version, file_name.clone()) {
            return Err(format!(
                "duplicate SQLx migration version {version}: `{previous_file_name}` and `{file_name}`"
            ));
        }
    }

    let mut migrations = migrations_by_version.into_iter();
    let Some((mut previous_version, mut previous_file_name)) = migrations.next() else {
        return Ok(());
    };
    if previous_version != 1 {
        return Err(format!(
            "noncontiguous SQLx migration versions: expected version 1 but first found version {previous_version} in `{previous_file_name}`"
        ));
    }

    for (version, file_name) in migrations {
        let expected_version = previous_version.checked_add(1).ok_or_else(|| {
            format!(
                "noncontiguous SQLx migration versions: `{previous_file_name}` uses the maximum supported version and cannot be followed by `{file_name}`"
            )
        })?;
        if version != expected_version {
            return Err(format!(
                "noncontiguous SQLx migration versions: expected version {expected_version} after `{previous_file_name}` but found version {version} in `{file_name}`"
            ));
        }
        previous_version = version;
        previous_file_name = file_name;
    }

    Ok(())
}

fn validate_migration_directory(directory: &Path) -> Result<(), String> {
    let directory_entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "failed to read migration directory `{}`: {error}",
            directory.display()
        )
    })?;
    let mut inventory = Vec::new();

    for directory_entry in directory_entries {
        let directory_entry = directory_entry.map_err(|error| {
            format!(
                "failed to read an entry in migration directory `{}`: {error}",
                directory.display()
            )
        })?;
        // SQLx resolves entries through `fs::metadata`, which follows symlinks.
        let metadata = fs::metadata(directory_entry.path()).map_err(|error| {
            format!(
                "failed to read the type of migration entry `{}`: {error}",
                directory_entry.path().display()
            )
        })?;
        let file_name = directory_entry
            .file_name()
            .into_string()
            .map_err(|file_name| {
                format!(
                    "migration entry name is not UTF-8: `{}`",
                    file_name.to_string_lossy()
                )
            })?;
        inventory.push((file_name, metadata.is_file()));
    }

    validate_migration_entries(inventory)
}

#[test]
fn current_migration_inventory_is_valid() {
    let migration_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    validate_migration_directory(&migration_directory)
        .expect("the checked-in SQLx migration inventory must be valid and contiguous");
}

#[test]
fn duplicate_numeric_versions_report_both_filenames() {
    let error = validate_migration_entries([
        ("0043_first.sql".to_owned(), true),
        ("43_second.sql".to_owned(), true),
    ])
    .expect_err("equivalent numeric migration versions must conflict");

    assert_eq!(
        error,
        "duplicate SQLx migration version 43: `0043_first.sql` and `43_second.sql`"
    );
}

#[test]
fn noncontiguous_versions_report_gap_adjacent_filenames() {
    let error = validate_migration_entries([
        ("0001_first.sql".to_owned(), true),
        ("0003_third.sql".to_owned(), true),
    ])
    .expect_err("a gap in the migration versions must be rejected");

    assert_eq!(
        error,
        "noncontiguous SQLx migration versions: expected version 2 after `0001_first.sql` but found version 3 in `0003_third.sql`"
    );
}

#[test]
fn migration_inventory_must_start_at_version_one() {
    let error = validate_migration_entries([("0002_second.sql".to_owned(), true)])
        .expect_err("the migration inventory must start at version one");

    assert_eq!(
        error,
        "noncontiguous SQLx migration versions: expected version 1 but first found version 2 in `0002_second.sql`"
    );
}

#[test]
fn malformed_sql_and_nonregular_entries_are_handled_deterministically() {
    let malformed = validate_migration_entries([("migration.sql".to_owned(), true)])
        .expect_err("a SQL migration without a numeric prefix must be rejected");
    assert_eq!(
        malformed,
        "migration filename `migration.sql` must match <VERSION>_<DESCRIPTION>.sql"
    );

    validate_migration_entries([
        ("0043_directory.sql".to_owned(), false),
        ("0001_regular.sql".to_owned(), true),
        ("README.md".to_owned(), true),
    ])
    .expect("nonregular and non-SQL entries are outside the SQLx migration inventory");
}

#[test]
fn reversible_migration_names_are_rejected_by_the_forward_only_contract() {
    for file_name in ["0044_policy.up.sql", "0044_policy.down.sql"] {
        let error = validate_migration_entries([(file_name.to_owned(), true)])
            .expect_err("reversible migrations must not enter the forward-only inventory");
        assert_eq!(
            error,
            format!(
                "migration filename `{file_name}` violates the forward-only simple migration contract"
            )
        );
    }
}
