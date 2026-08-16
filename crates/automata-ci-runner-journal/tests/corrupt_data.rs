use super::support;

use std::{fs, fs::OpenOptions};

use automata_ci_core::{LogStreamId, RunnerId};
use automata_ci_runner_journal::{
    FileJournal, JournalError, MAX_DELIVERY_ENQUEUED_AT_MILLIS, MAX_JOURNAL_BYTES,
    RUNNER_JOURNAL_SCHEMA_VERSION, RunnerJournal,
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
fn unsupported_schema_is_identified_before_current_shape_decode() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let path = journal_file(root.as_path());
    let unsupported = RUNNER_JOURNAL_SCHEMA_VERSION + 1;
    fs::write(path, format!(r#"{{"schema_version":{unsupported}}}"#))
        .expect("unsupported schema probe");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::UnsupportedSchema {
            supported: RUNNER_JOURNAL_SCHEMA_VERSION,
            received
        }) if received == unsupported
    ));
}

#[test]
fn obsolete_versioned_filename_is_never_silently_reinitialized() {
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let current_path = journal_file(root.as_path());
    let obsolete_path = root.as_path().join("runner-journal-v1.json");
    fs::write(&obsolete_path, br#"{"schema_version":1}"#).expect("obsolete filename fixture");
    assert!(matches!(
        FileJournal::open(root.clone(), fixture.runner_id),
        Err(JournalError::ObsoleteState)
    ));
    fs::remove_file(current_path).expect("remove current fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::ObsoleteState)
    ));
}

#[test]
fn previous_schema_is_rejected_without_rewrite() {
    assert_eq!(RUNNER_JOURNAL_SCHEMA_VERSION, 7);
    let (scratch, fixture) = initialized();
    let root = scratch.state_root();
    let path = journal_file(root.as_path());
    let current = fs::read_to_string(&path).expect("current journal");
    let previous = current.replacen(
        &format!("\"schema_version\":{RUNNER_JOURNAL_SCHEMA_VERSION}"),
        &format!("\"schema_version\":{}", RUNNER_JOURNAL_SCHEMA_VERSION - 1),
        1,
    );
    fs::write(&path, &previous).expect("previous schema fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::UnsupportedSchema {
            supported: RUNNER_JOURNAL_SCHEMA_VERSION,
            received
        }) if received == RUNNER_JOURNAL_SCHEMA_VERSION - 1
    ));
    assert_eq!(
        fs::read_to_string(path).expect("unchanged rejected journal"),
        previous
    );
}

#[test]
fn current_v7_schema_requires_explicit_windows_broker_grant_field() {
    assert_eq!(RUNNER_JOURNAL_SCHEMA_VERSION, 7);
    let scratch = Scratch::new("missing-windows-broker-grant-v7");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = fixture.open(&scratch);
    let offer = fixture.offer(1);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, offer.clone())
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    journal
        .record_runtime_authority_delivery(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            fixture.runtime_authority_delivery(&offer),
        )
        .expect("authority delivery");
    drop(journal);

    let path = journal_file(root.as_path());
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("current v7 journal"))
            .expect("valid journal JSON");
    assert_eq!(value["schema_version"], serde_json::json!(7));
    let delivery = value["slots"][0]["runtime_authority_delivery"]
        .as_object_mut()
        .expect("runtime-authority delivery object");
    assert_eq!(
        delivery.remove("windows_hyperv_broker_grant"),
        Some(serde_json::Value::Null)
    );
    fs::write(
        &path,
        serde_json::to_vec(&value).expect("encode missing-field fixture"),
    )
    .expect("write missing-field fixture");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn current_schema_requires_endpoint_operation_collection() {
    let scratch = Scratch::new("missing-endpoint-operations");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    drop(journal);

    let path = journal_file(root.as_path());
    let current = fs::read_to_string(&path).expect("current journal");
    let missing = current.replacen("\"endpoint_operations\":[],", "", 1);
    assert_ne!(missing, current, "endpoint collection fixture must apply");
    fs::write(path, missing).expect("write missing endpoint collection");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn current_schema_requires_segment_collection_metadata() {
    let scratch = Scratch::new("missing-log-segments");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let stream = LogStreamId::new();
    journal
        .open_log_stream(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
        )
        .expect("open stream");
    drop(journal);

    let path = journal_file(root.as_path());
    let current = fs::read_to_string(&path).expect("current journal");
    let missing_segments = current.replacen("\"segments\":[],", "", 1);
    assert_ne!(missing_segments, current, "segment fixture must apply");
    fs::write(path, missing_segments).expect("write missing segment metadata");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn current_schema_rejects_incoherent_segment_endpoints() {
    let scratch = Scratch::new("invalid-segment-endpoint");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let stream = LogStreamId::new();
    journal
        .open_log_stream(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
        )
        .expect("open stream");
    journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            Fixture::log_segment(stream, 0, false, 32, 0x84),
            Fixture::delivery_time(),
        )
        .expect("record segment");
    drop(journal);

    let path = journal_file(root.as_path());
    let current = fs::read_to_string(&path).expect("current journal");
    let invalid_endpoint = current.replacen("\"last_sequence\":0", "\"last_sequence\":1", 1);
    assert_ne!(
        invalid_endpoint, current,
        "segment endpoint fixture must apply"
    );
    fs::write(path, invalid_endpoint).expect("write invalid segment endpoint");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn current_schema_canonically_requires_bounded_log_enqueue_times() {
    let scratch = Scratch::new("log-enqueue-time-schema");
    let fixture = Fixture::new();
    let root = scratch.state_root();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let stream = LogStreamId::new();
    journal
        .open_log_stream(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
        )
        .expect("open stream");
    journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            Fixture::log_segment(stream, 0, false, 32, 0x85),
            Fixture::delivery_time(),
        )
        .expect("record segment");
    drop(journal);

    let path = journal_file(root.as_path());
    let canonical = fs::read_to_string(&path).expect("canonical journal");
    let timestamp_field = format!(
        "\"segment_enqueued_at\":[{}]",
        Fixture::delivery_time().get()
    );
    assert!(canonical.contains(&timestamp_field));
    let reopened =
        FileJournal::open(root.clone(), fixture.runner_id).expect("decode current schema");
    assert_eq!(
        reopened
            .snapshot()
            .expect("recovered timestamp")
            .pending_delivery_timestamps()
            .log_stream(),
        Some(Fixture::delivery_time())
    );
    drop(reopened);
    assert_eq!(
        fs::read_to_string(&path).expect("unchanged canonical bytes"),
        canonical
    );

    let out_of_range = canonical.replacen(
        &timestamp_field,
        &format!(
            "\"segment_enqueued_at\":[{}]",
            MAX_DELIVERY_ENQUEUED_AT_MILLIS + 1
        ),
        1,
    );
    assert_ne!(out_of_range, canonical, "timestamp fixture must apply");
    fs::write(path, out_of_range).expect("write invalid enqueue timestamp");
    assert!(matches!(
        FileJournal::open(root, fixture.runner_id),
        Err(JournalError::Corrupt)
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
