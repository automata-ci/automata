use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Seek as _, SeekFrom, Write as _},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

use automata_ci_execution::{EnvironmentProfile, OperationId, SandboxCustody};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const LOCK_FILE_NAME: &str = ".automata-windows-hyperv-v2.lock";
const JOURNAL_FILE_NAME: &str = ".automata-windows-hyperv-v2.events";
const DURABLE_SCHEMA: u32 = 2;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[derive(Default)]
pub(crate) struct DurableSnapshot {
    pub(crate) creates: HashMap<OperationId, DurableCreate>,
    pub(crate) pending_destroys: HashMap<OperationId, DurableDestroyRequest>,
    pub(crate) destroys: HashMap<OperationId, DurableDestroy>,
    pub(crate) entries: HashMap<String, DurableEntry>,
    pub(crate) tombstones: HashMap<String, DurableTombstone>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableCreate {
    pub(crate) operation_id: OperationId,
    pub(crate) fingerprint: String,
    pub(crate) handle: String,
    pub(crate) custody: SandboxCustody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableDestroy {
    pub(crate) operation_id: OperationId,
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) disposition: DurableDestroyDisposition,
    pub(crate) completed_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableDestroyRequest {
    pub(crate) operation_id: OperationId,
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) profile: EnvironmentProfile,
    pub(crate) custody: SandboxCustody,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DurableDestroyDisposition {
    Destroyed,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableEntry {
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) profile: EnvironmentProfile,
    pub(crate) custody: SandboxCustody,
    pub(crate) container: String,
    pub(crate) fingerprint: String,
    pub(crate) phase: DurableEntryPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DurableEntryPhase {
    Intent,
    Running,
    Destroying,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableTombstone {
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) profile: EnvironmentProfile,
    pub(crate) custody: SandboxCustody,
    pub(crate) completed_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableEvent {
    CreateIntent {
        create: DurableCreate,
        entry: DurableEntry,
    },
    CreateRunning {
        handle: String,
    },
    DestroyIntent {
        request: DurableDestroyRequest,
    },
    DestroyComplete {
        operation_id: OperationId,
    },
    DestroyAbsent {
        request: DurableDestroyRequest,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EventRecord {
    schema: u32,
    sequence: u64,
    checksum: [u8; 32],
    event: DurableEvent,
}

pub(crate) struct LifecycleJournal {
    _lock: File,
    journal: File,
    next_sequence: u64,
    poisoned: bool,
}

impl LifecycleJournal {
    pub(crate) fn open(root: &Path) -> io::Result<(Self, DurableSnapshot)> {
        let lock = open_exclusive_regular(&root.join(LOCK_FILE_NAME), true, false)?;
        let mut journal = open_exclusive_regular(&root.join(JOURNAL_FILE_NAME), true, false)?;
        if journal.metadata()?.len() > MAX_JOURNAL_BYTES {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        journal.seek(SeekFrom::Start(0))?;

        let mut snapshot = DurableSnapshot::default();
        let mut expected_sequence = 1_u64;
        let mut valid_length = 0_u64;
        let mut unterminated_tail = false;
        {
            let mut reader = BufReader::new(&mut journal);
            loop {
                match read_bounded_record(&mut reader)? {
                    RecordRead::End => break,
                    RecordRead::Unterminated => {
                        unterminated_tail = true;
                        break;
                    }
                    RecordRead::Complete(bytes) => {
                        let record: EventRecord = serde_json::from_slice(&bytes)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                        if record.schema != DURABLE_SCHEMA
                            || record.sequence != expected_sequence
                            || event_checksum(record.sequence, &record.event)? != record.checksum
                        {
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        apply_event(&mut snapshot, &record.event, record.sequence)?;
                        expected_sequence = expected_sequence
                            .checked_add(1)
                            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                        valid_length = valid_length
                            .checked_add(
                                u64::try_from(bytes.len())
                                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
                                    .checked_add(1)
                                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?,
                            )
                            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                    }
                }
            }
        }
        if unterminated_tail {
            journal.set_len(valid_length)?;
            journal.sync_all()?;
        }
        journal.seek(SeekFrom::End(0))?;
        Ok((
            Self {
                _lock: lock,
                journal,
                next_sequence: expected_sequence,
                poisoned: false,
            },
            snapshot,
        ))
    }

    pub(crate) fn append_to_snapshot(
        &mut self,
        snapshot: &mut DurableSnapshot,
        event: &DurableEvent,
    ) -> io::Result<u64> {
        let sequence = self.append(event)?;
        apply_event(snapshot, event, sequence)?;
        Ok(sequence)
    }

    fn append(&mut self, event: &DurableEvent) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::FileTooLarge))?;
        let record = EventRecord {
            schema: DURABLE_SCHEMA,
            sequence,
            checksum: event_checksum(sequence, event)?,
            event: event.clone(),
        };
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        bytes.push(b'\n');
        let length =
            u64::try_from(bytes.len()).map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
        let appended = self.journal.metadata()?.len().checked_add(length);
        if appended.is_none_or(|length| length > MAX_JOURNAL_BYTES) {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        if let Err(failure) = self
            .journal
            .write_all(&bytes)
            .and_then(|()| self.journal.flush())
            .and_then(|()| self.journal.sync_all())
        {
            // A failed write or synchronization can leave either a durable
            // record or a repairable partial tail. Do not append again from a
            // stale in-memory sequence; reopening is the only safe recovery.
            self.poisoned = true;
            return Err(failure);
        }
        self.next_sequence = next_sequence;
        Ok(sequence)
    }
}

enum RecordRead {
    End,
    Complete(Vec<u8>),
    Unterminated,
}

fn read_bounded_record(reader: &mut impl BufRead) -> io::Result<RecordRead> {
    let mut record = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if record.is_empty() {
                Ok(RecordRead::End)
            } else {
                Ok(RecordRead::Unterminated)
            };
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let length = record
                .len()
                .checked_add(newline)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            if length == 0 || length > MAX_EVENT_BYTES {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            record.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return Ok(RecordRead::Complete(record));
        }
        let length = record
            .len()
            .checked_add(available.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if length > MAX_EVENT_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        record.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn open_exclusive_regular(path: &Path, create: bool, append: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(create)
        .read(true)
        .write(true)
        .append(append)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(file)
}

fn apply_event(
    snapshot: &mut DurableSnapshot,
    event: &DurableEvent,
    sequence: u64,
) -> io::Result<()> {
    match event {
        DurableEvent::CreateIntent { create, entry } => apply_create(snapshot, create, entry),
        DurableEvent::CreateRunning { handle } => apply_running(snapshot, handle),
        DurableEvent::DestroyIntent { request } => apply_destroy_intent(snapshot, request),
        DurableEvent::DestroyComplete { operation_id } => {
            apply_destroy_complete(snapshot, *operation_id, sequence)
        }
        DurableEvent::DestroyAbsent { request } => {
            apply_destroy_absent(snapshot, request, sequence)
        }
    }
}

fn apply_create(
    snapshot: &mut DurableSnapshot,
    create: &DurableCreate,
    entry: &DurableEntry,
) -> io::Result<()> {
    if create.handle != entry.handle
        || create.fingerprint != entry.fingerprint
        || create.custody != entry.custody
        || entry.phase != DurableEntryPhase::Intent
        || snapshot.creates.contains_key(&create.operation_id)
        || snapshot.entries.contains_key(&entry.handle)
        || snapshot.tombstones.contains_key(&entry.handle)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    snapshot.creates.insert(create.operation_id, create.clone());
    snapshot.entries.insert(entry.handle.clone(), entry.clone());
    Ok(())
}

fn apply_running(snapshot: &mut DurableSnapshot, handle: &str) -> io::Result<()> {
    let entry = snapshot
        .entries
        .get_mut(handle)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if entry.phase != DurableEntryPhase::Intent {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    entry.phase = DurableEntryPhase::Running;
    Ok(())
}

fn apply_destroy_intent(
    snapshot: &mut DurableSnapshot,
    request: &DurableDestroyRequest,
) -> io::Result<()> {
    let entry = snapshot
        .entries
        .get_mut(&request.handle)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if snapshot
        .pending_destroys
        .contains_key(&request.operation_id)
        || snapshot.destroys.contains_key(&request.operation_id)
        || snapshot
            .pending_destroys
            .values()
            .any(|pending| pending.handle == request.handle)
        || !matches!(
            entry.phase,
            DurableEntryPhase::Intent | DurableEntryPhase::Running
        )
        || entry.generation != request.generation
        || entry.profile != request.profile
        || entry.custody != request.custody
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    entry.phase = DurableEntryPhase::Destroying;
    snapshot
        .pending_destroys
        .insert(request.operation_id, request.clone());
    Ok(())
}

fn apply_destroy_complete(
    snapshot: &mut DurableSnapshot,
    operation_id: OperationId,
    sequence: u64,
) -> io::Result<()> {
    let request = snapshot
        .pending_destroys
        .remove(&operation_id)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let entry = snapshot
        .entries
        .remove(&request.handle)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if entry.phase != DurableEntryPhase::Destroying
        || entry.generation != request.generation
        || entry.profile != request.profile
        || entry.custody != request.custody
        || snapshot.tombstones.contains_key(&request.handle)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    snapshot.tombstones.insert(
        request.handle.clone(),
        DurableTombstone {
            handle: request.handle.clone(),
            generation: request.generation,
            profile: request.profile,
            custody: request.custody,
            completed_sequence: sequence,
        },
    );
    snapshot.destroys.insert(
        operation_id,
        DurableDestroy {
            operation_id,
            handle: request.handle,
            generation: request.generation,
            disposition: DurableDestroyDisposition::Destroyed,
            completed_sequence: sequence,
        },
    );
    Ok(())
}

fn apply_destroy_absent(
    snapshot: &mut DurableSnapshot,
    request: &DurableDestroyRequest,
    sequence: u64,
) -> io::Result<()> {
    let tombstone = snapshot
        .tombstones
        .get(&request.handle)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if snapshot
        .pending_destroys
        .contains_key(&request.operation_id)
        || snapshot.destroys.contains_key(&request.operation_id)
        || tombstone.generation != request.generation
        || tombstone.profile != request.profile
        || tombstone.custody != request.custody
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    snapshot.destroys.insert(
        request.operation_id,
        DurableDestroy {
            operation_id: request.operation_id,
            handle: request.handle.clone(),
            generation: request.generation,
            disposition: DurableDestroyDisposition::AlreadyAbsent,
            completed_sequence: sequence,
        },
    );
    Ok(())
}

fn event_checksum(sequence: u64, event: &DurableEvent) -> io::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(&(DURABLE_SCHEMA, sequence, event))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, io::Write as _, num::NonZeroU16, path::PathBuf};

    use automata_ci_execution::{
        EnvironmentProfileId, RunnerId, SandboxCustody, SandboxGeneration, Sha256Digest,
    };

    use super::*;

    #[test]
    fn lifecycle_reopen_rejects_noncurrent_durable_schemas() {
        let root = TestRoot::new("schema");
        let (journal, _) = LifecycleJournal::open(&root.0).expect("initialize journal");
        drop(journal);
        for schema in [DURABLE_SCHEMA - 1, DURABLE_SCHEMA + 1] {
            let event = create_event();
            let sequence = 1;
            let mut bytes = serde_json::to_vec(&EventRecord {
                schema,
                sequence,
                checksum: event_checksum(sequence, &event).expect("checksum"),
                event,
            })
            .expect("record");
            bytes.push(b'\n');
            fs::write(root.0.join(JOURNAL_FILE_NAME), bytes).expect("replace journal");
            assert!(matches!(
                LifecycleJournal::open(&root.0),
                Err(error) if error.kind() == io::ErrorKind::InvalidData
            ));
        }
    }

    #[test]
    fn lifecycle_reopen_rejects_wrong_runner_and_slot_custody() {
        let runner_id = RunnerId::new();
        let expected = SandboxCustody::Job {
            runner_id,
            slot_ordinal: NonZeroU16::new(2).expect("non-zero slot"),
        };
        for (label, observed) in [
            (
                "runner",
                SandboxCustody::Job {
                    runner_id: RunnerId::new(),
                    slot_ordinal: NonZeroU16::new(2).expect("non-zero slot"),
                },
            ),
            (
                "slot",
                SandboxCustody::Job {
                    runner_id,
                    slot_ordinal: NonZeroU16::new(1).expect("non-zero slot"),
                },
            ),
        ] {
            let root = TestRoot::new(&format!("custody-{label}"));
            let mut event = create_event();
            let DurableEvent::CreateIntent { create, entry } = &mut event else {
                panic!("create fixture event");
            };
            create.custody = expected;
            entry.custody = observed;
            let sequence = 1;
            let mut bytes = serde_json::to_vec(&EventRecord {
                schema: DURABLE_SCHEMA,
                sequence,
                checksum: event_checksum(sequence, &event).expect("event checksum"),
                event,
            })
            .expect("event record");
            bytes.push(b'\n');
            fs::write(root.0.join(JOURNAL_FILE_NAME), bytes).expect("write journal");

            assert!(matches!(
                LifecycleJournal::open(&root.0),
                Err(error) if error.kind() == io::ErrorKind::InvalidData
            ));
        }
    }

    #[test]
    fn lifecycle_truncates_only_an_unterminated_tail() {
        let root = TestRoot::new("tail");
        let (mut journal, mut snapshot) =
            LifecycleJournal::open(&root.0).expect("initialize journal");
        journal
            .append_to_snapshot(&mut snapshot, &create_event())
            .expect("append create");
        drop(journal);
        let path = root.0.join(JOURNAL_FILE_NAME);
        let valid = fs::metadata(&path).expect("metadata").len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open tail")
            .write_all(b"{\"partial\":")
            .expect("append partial tail");
        let (journal, snapshot) = LifecycleJournal::open(&root.0).expect("repair tail");
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(fs::metadata(path).expect("metadata").len(), valid);
        drop(journal);
    }

    #[test]
    fn oversized_lifecycle_journal_fails_closed_before_parsing() {
        let root = TestRoot::new("oversized");
        let (journal, _) = LifecycleJournal::open(&root.0).expect("initialize journal");
        drop(journal);
        OpenOptions::new()
            .write(true)
            .open(root.0.join(JOURNAL_FILE_NAME))
            .expect("open journal")
            .set_len(MAX_JOURNAL_BYTES + 1)
            .expect("create sparse oversized journal");
        assert!(matches!(
            LifecycleJournal::open(&root.0),
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge
        ));
    }

    fn create_event() -> DurableEvent {
        let operation_id = OperationId::new();
        let generation = SandboxGeneration::new(1).expect("generation");
        let handle = format!(
            "wh2_{}_{}",
            operation_id.as_uuid().simple(),
            generation.get()
        );
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/windows-wal-test-v1").expect("profile"),
            Sha256Digest::from_bytes([0x57; 32]),
        );
        let custody = SandboxCustody::ProfileAdmission {
            runner_id: RunnerId::new(),
        };
        DurableEvent::CreateIntent {
            create: DurableCreate {
                operation_id,
                fingerprint: "11".repeat(32),
                handle: handle.clone(),
                custody,
            },
            entry: DurableEntry {
                handle,
                generation: generation.get(),
                profile,
                custody,
                container: format!(
                    "automata-windows-hyperv-{}",
                    operation_id.as_uuid().simple()
                ),
                fingerprint: "11".repeat(32),
                phase: DurableEntryPhase::Intent,
            },
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "automata-ci-windows-hyperv-wal-{label}-{}",
                OperationId::new()
            ));
            fs::create_dir_all(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
