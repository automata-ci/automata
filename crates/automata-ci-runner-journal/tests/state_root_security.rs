mod support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use automata_ci_core::RunnerId;
use automata_ci_runner_journal::{FileJournal, JournalError, StateRoot, StateRootError};
use support::{Fixture, Scratch, journal_file};

#[test]
fn state_root_rejects_relative_root_traversal_and_temporary_hierarchy() {
    assert_eq!(
        StateRoot::explicit("relative/state").expect_err("relative"),
        StateRootError::Relative
    );
    assert_eq!(
        StateRoot::explicit(Path::new(std::path::MAIN_SEPARATOR_STR)).expect_err("root"),
        StateRootError::FilesystemRoot
    );
    let scratch = Scratch::new("traversal-policy");
    assert_eq!(
        StateRoot::explicit(scratch.path().join("..").join("escape")).expect_err("traversal"),
        StateRootError::Traversal
    );
    let temporary = PathBuf::from(std::path::MAIN_SEPARATOR_STR)
        .join("tmp")
        .join("runner-state");
    assert_eq!(
        StateRoot::explicit(temporary).expect_err("temporary hierarchy"),
        StateRootError::TemporaryHierarchy
    );
    assert_eq!(
        StateRoot::explicit(scratch.path().join("tmp").join("runner-state"))
            .expect_err("nested temporary hierarchy"),
        StateRootError::TemporaryHierarchy
    );
}

#[test]
fn state_root_and_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("permissions");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = FileJournal::open(root.clone(), fixture.runner_id).expect("open");
    drop(journal);
    assert_eq!(
        fs::metadata(root.as_path())
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for entry in fs::read_dir(root.as_path()).expect("read root") {
        let entry = entry.expect("entry");
        if entry.file_type().expect("type").is_file() {
            assert_eq!(
                entry.metadata().expect("metadata").permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn a_second_process_owner_is_excluded_by_the_os_lock() {
    let scratch = Scratch::new("lock-contention");
    let fixture = Fixture::new();
    let first = fixture.open(&scratch);
    let error = FileJournal::open(scratch.state_root(), fixture.runner_id)
        .expect_err("second lock must fail");
    assert!(matches!(error, JournalError::AlreadyLocked));
    drop(first);
    FileJournal::open(scratch.state_root(), fixture.runner_id).expect("lock released on drop");
}

#[cfg(unix)]
#[test]
fn symlink_components_and_state_files_are_never_followed() {
    use std::os::unix::fs::symlink;

    let scratch = Scratch::new("symlink-attacks");
    let real = scratch.child("real");
    fs::create_dir_all(&real).expect("real directory");
    let link = scratch.child("linked");
    symlink(&real, &link).expect("root symlink");
    let root = StateRoot::explicit(link.join("state")).expect("syntactically valid");
    assert!(matches!(
        FileJournal::open(root, RunnerId::new()),
        Err(JournalError::PathSecurity)
    ));

    let fixture = Fixture::new();
    let root = scratch.state_root();
    drop(FileJournal::open(root.clone(), fixture.runner_id).expect("initialize"));
    let escaped = scratch.child("escaped-data");
    fs::write(&escaped, b"do not touch").expect("escape target");
    fs::remove_file(journal_file(root.as_path())).expect("remove isolated journal");
    symlink(&escaped, journal_file(root.as_path())).expect("state symlink");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::PathSecurity)
    ));
    assert_eq!(
        fs::read(&escaped).expect("escape unchanged"),
        b"do not touch"
    );
}

#[cfg(unix)]
#[test]
fn hard_linked_state_files_are_rejected_without_modifying_the_target() {
    let scratch = Scratch::new("hard-link-attack");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    drop(FileJournal::open(root.clone(), fixture.runner_id).expect("initialize"));
    let escaped = scratch.child("hard-linked-data");
    fs::write(&escaped, b"external bytes").expect("external file");
    fs::remove_file(journal_file(root.as_path())).expect("remove isolated journal");
    fs::hard_link(&escaped, journal_file(root.as_path())).expect("hard link");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::PathSecurity)
    ));
    assert_eq!(
        fs::read(&escaped).expect("external file unchanged"),
        b"external bytes"
    );
}

#[test]
fn xdg_policy_is_explicit_and_deterministic() {
    let scratch = Scratch::new("xdg-policy");
    let root = StateRoot::from_xdg_state_home(scratch.child("xdg-state")).expect("xdg root");
    assert_eq!(
        root.as_path(),
        scratch.child("xdg-state").join("automata").join("runner")
    );
    assert_eq!(
        StateRoot::from_xdg_state_home("").expect_err("empty"),
        StateRootError::MissingXdgStateHome
    );
}
