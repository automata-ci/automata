mod support;

use std::{fs, fs::OpenOptions};

use automata_core::RunnerId;
use automata_runner_journal::{
    FileJournal, JournalError, MAX_JOURNAL_BYTES, RUNNER_JOURNAL_SCHEMA_VERSION, RunnerJournal,
};
use support::{Fixture, Scratch, journal_file};

fn initialized() -> (Scratch, Fixture) {
    let scratch = Scratch::new("corrupt-data");
    let fixture = Fixture::new();
    drop(fixture.open(&scratch));
    (scratch, fixture)
}

#[test]
fn truncated_unknown_and_noncanonical_data_are_rejected() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let path = journal_file(root.as_path());
    let valid = fs::read(&path).expect("valid bytes");

    fs::write(&path, &valid[..valid.len() / 2]).expect("truncate fixture");
    assert!(matches!(
        FileJournal::open(root.clone(), fixture.runner_id),
        Err(JournalError::Corrupt)
    ));

    let mut unknown = valid.clone();
    unknown.pop();
    unknown.extend_from_slice(b",\"unknown_field\":true}");
    fs::write(&path, unknown).expect("unknown fixture");
    assert!(matches!(
        FileJournal::open(root.clone(), fixture.runner_id),
        Err(JournalError::Corrupt)
    ));

    let mut noncanonical = valid;
    noncanonical.push(b'\n');
    fs::write(&path, noncanonical).expect("noncanonical fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn unsupported_schema_is_distinct_from_corruption() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let path = journal_file(root.as_path());
    let valid = fs::read_to_string(&path).expect("valid text");
    let altered = valid.replacen(
        &format!("\"schema_version\":{RUNNER_JOURNAL_SCHEMA_VERSION}"),
        "\"schema_version\":99",
        1,
    );
    fs::write(path, altered).expect("unsupported fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::UnsupportedSchema {
            supported: RUNNER_JOURNAL_SCHEMA_VERSION,
            received: 99
        })
    ));
}

#[test]
fn unsupported_legacy_shape_is_identified_before_current_schema_decode() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let path = journal_file(root.as_path());
    fs::write(path, br#"{"schema_version":1}"#).expect("legacy schema probe");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::UnsupportedSchema {
            supported: RUNNER_JOURNAL_SCHEMA_VERSION,
            received: 1
        })
    ));
}

#[test]
fn legacy_versioned_filename_is_never_silently_reinitialized() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    fs::remove_file(journal_file(root.as_path())).expect("remove current fixture");
    fs::write(
        root.as_path().join("runner-journal-v1.json"),
        br#"{"schema_version":1}"#,
    )
    .expect("legacy filename fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::UnsupportedSchema { received: 1, .. })
    ));
}

#[test]
fn canonical_data_with_invalid_lease_interval_is_rejected_on_recovery() {
    let scratch = Scratch::new("invalid-lease-on-disk");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = FileJournal::open(root.clone(), fixture.runner_id).expect("open");
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    drop(journal);
    let path = journal_file(root.as_path());
    let valid = fs::read_to_string(&path).expect("valid text");
    let invalid = valid.replacen("\"expires_at\":50000", "\"expires_at\":39999", 1);
    assert_ne!(invalid, valid, "lease expiration fixture must be replaced");
    fs::write(path, invalid).expect("invalid lease fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn file_size_is_checked_before_decode_allocation() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let path = journal_file(root.as_path());
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open fixture")
        .set_len(u64::try_from(MAX_JOURNAL_BYTES).expect("limit") + 1)
        .expect("oversize fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Oversized { .. })
    ));
}

#[test]
fn configured_runner_identity_cannot_replace_the_stable_identity() {
    let (scratch, _fixture) = initialized();
    assert!(matches!(
        FileJournal::open(scratch.state_root(), RunnerId::new()),
        Err(JournalError::RunnerIdentityMismatch { .. })
    ));
}
