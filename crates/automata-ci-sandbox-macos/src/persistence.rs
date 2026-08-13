use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, Seek as _, SeekFrom, Write as _},
};

use automata_ci_execution::{
    DestroyDisposition, EnvironmentProfile, OperationId, SandboxGeneration,
};
use rustix::{
    fs::{self, FlockOperation, Mode, OFlags, fchmod, flock, fstat, openat},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::filesystem::SecureRoot;

const LOCK_FILE_NAME: &str = ".automata-macos-virtualization-v1.lock";
const JOURNAL_FILE_NAME: &str = ".automata-macos-virtualization-v1.events";
const LEGACY_STATE_NAMES: [&str; 2] = [
    ".automata-macos-provider-v1.lock",
    ".automata-macos-provider-v1.events",
];
const DURABLE_SCHEMA: u32 = 1;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const FILE_MODE: Mode = Mode::from_raw_mode(0o600);

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
    pub(crate) fingerprint: [u8; 32],
    pub(crate) handle: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableEntry {
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) profile: EnvironmentProfile,
    pub(crate) workspace: String,
    pub(crate) scratch: String,
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
pub(crate) struct DurableDestroyRequest {
    pub(crate) operation_id: OperationId,
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) profile: EnvironmentProfile,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableDestroy {
    pub(crate) request: DurableDestroyRequest,
    pub(crate) disposition: DurableDestroyDisposition,
    pub(crate) completed_sequence: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DurableDestroyDisposition {
    Destroyed,
    AlreadyAbsent,
}

impl From<DurableDestroyDisposition> for DestroyDisposition {
    fn from(value: DurableDestroyDisposition) -> Self {
        match value {
            DurableDestroyDisposition::Destroyed => Self::Destroyed,
            DurableDestroyDisposition::AlreadyAbsent => Self::AlreadyAbsent,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableTombstone {
    pub(crate) handle: String,
    pub(crate) generation: u64,
    pub(crate) profile: EnvironmentProfile,
    pub(crate) completed_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableEvent {
    CreateIntent {
        create: DurableCreate,
        entry: DurableEntry,
    },
    CreateReady {
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
}

impl LifecycleJournal {
    pub(crate) fn open(root: &SecureRoot) -> io::Result<(Self, DurableSnapshot)> {
        reject_legacy_state(root)?;
        let lock = open_private_file(root, LOCK_FILE_NAME, false)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == Errno::AGAIN {
                io::Error::from(io::ErrorKind::WouldBlock)
            } else {
                error.into()
            }
        })?;
        let mut journal = File::from(open_private_file(root, JOURNAL_FILE_NAME, false)?);
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
                            || checksum(record.sequence, &record.event)? != record.checksum
                        {
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        apply_event(&mut snapshot, &record.event, record.sequence)?;
                        expected_sequence = expected_sequence
                            .checked_add(1)
                            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                        valid_length = valid_length
                            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX) + 1)
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
                _lock: File::from(lock),
                journal,
                next_sequence: expected_sequence,
            },
            snapshot,
        ))
    }

    pub(crate) fn append(&mut self, event: DurableEvent) -> io::Result<u64> {
        let sequence = self.next_sequence;
        let record = EventRecord {
            schema: DURABLE_SCHEMA,
            sequence,
            checksum: checksum(sequence, &event)?,
            event,
        };
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        let future_length = self
            .journal
            .metadata()?
            .len()
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX) + 1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::FileTooLarge))?;
        if future_length > MAX_JOURNAL_BYTES {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        bytes.push(b'\n');
        self.journal.write_all(&bytes)?;
        self.journal.flush()?;
        self.journal.sync_all()?;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::FileTooLarge))?;
        Ok(sequence)
    }

    pub(crate) fn append_to_snapshot(
        &mut self,
        snapshot: &mut DurableSnapshot,
        event: &DurableEvent,
    ) -> io::Result<u64> {
        let sequence = self.append(event.clone())?;
        apply_event(snapshot, event, sequence)?;
        Ok(sequence)
    }
}

fn reject_legacy_state(root: &SecureRoot) -> io::Result<()> {
    for name in LEGACY_STATE_NAMES {
        match openat(
            root.descriptor(),
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Err(Errno::NOENT) => {}
            Ok(_) | Err(Errno::LOOP | Errno::NOTDIR) => return Err(invalid()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn open_private_file(
    root: &SecureRoot,
    name: &str,
    append: bool,
) -> io::Result<rustix::fd::OwnedFd> {
    let mut flags = OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if append {
        flags |= OFlags::APPEND;
    }
    let descriptor = openat(root.descriptor(), name, flags, FILE_MODE).map_err(io::Error::from)?;
    let stat = fstat(&descriptor).map_err(io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    fchmod(&descriptor, FILE_MODE).map_err(io::Error::from)?;
    fs::fsync(root.descriptor()).map_err(io::Error::from)?;
    Ok(descriptor)
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
        if record.len().saturating_add(available.len()) > MAX_EVENT_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        record.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn checksum(sequence: u64, event: &DurableEvent) -> io::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(&(DURABLE_SCHEMA, sequence, event))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Sha256::digest(bytes).into())
}

fn apply_event(
    snapshot: &mut DurableSnapshot,
    event: &DurableEvent,
    sequence: u64,
) -> io::Result<()> {
    match event {
        DurableEvent::CreateIntent { create, entry } => {
            if create.handle != entry.handle
                || entry.phase != DurableEntryPhase::Intent
                || snapshot.creates.contains_key(&create.operation_id)
                || snapshot.entries.contains_key(&entry.handle)
                || snapshot.tombstones.contains_key(&entry.handle)
            {
                return Err(invalid());
            }
            snapshot.creates.insert(create.operation_id, create.clone());
            snapshot.entries.insert(entry.handle.clone(), entry.clone());
        }
        DurableEvent::CreateReady { handle } => {
            let entry = snapshot.entries.get_mut(handle).ok_or_else(invalid)?;
            if entry.phase != DurableEntryPhase::Intent {
                return Err(invalid());
            }
            entry.phase = DurableEntryPhase::Running;
        }
        DurableEvent::DestroyIntent { request } => {
            let entry = snapshot
                .entries
                .get_mut(&request.handle)
                .ok_or_else(invalid)?;
            if entry.generation != request.generation
                || entry.profile != request.profile
                || entry.phase == DurableEntryPhase::Destroying
                || snapshot
                    .pending_destroys
                    .contains_key(&request.operation_id)
                || snapshot.destroys.contains_key(&request.operation_id)
                || snapshot
                    .pending_destroys
                    .values()
                    .any(|pending| pending.handle == request.handle)
            {
                return Err(invalid());
            }
            entry.phase = DurableEntryPhase::Destroying;
            snapshot
                .pending_destroys
                .insert(request.operation_id, request.clone());
        }
        DurableEvent::DestroyComplete { operation_id } => {
            let request = snapshot
                .pending_destroys
                .remove(operation_id)
                .ok_or_else(invalid)?;
            let entry = snapshot
                .entries
                .remove(&request.handle)
                .ok_or_else(invalid)?;
            if entry.phase != DurableEntryPhase::Destroying
                || entry.generation != request.generation
                || entry.profile != request.profile
            {
                return Err(invalid());
            }
            snapshot.tombstones.insert(
                request.handle.clone(),
                DurableTombstone {
                    handle: request.handle.clone(),
                    generation: request.generation,
                    profile: request.profile.clone(),
                    completed_sequence: sequence,
                },
            );
            snapshot.destroys.insert(
                *operation_id,
                DurableDestroy {
                    request,
                    disposition: DurableDestroyDisposition::Destroyed,
                    completed_sequence: sequence,
                },
            );
        }
        DurableEvent::DestroyAbsent { request } => {
            let tombstone = snapshot
                .tombstones
                .get(&request.handle)
                .ok_or_else(invalid)?;
            if tombstone.generation != request.generation
                || tombstone.profile != request.profile
                || snapshot.destroys.contains_key(&request.operation_id)
            {
                return Err(invalid());
            }
            snapshot.destroys.insert(
                request.operation_id,
                DurableDestroy {
                    request: request.clone(),
                    disposition: DurableDestroyDisposition::AlreadyAbsent,
                    completed_sequence: sequence,
                },
            );
        }
    }
    Ok(())
}

pub(crate) fn recovered_generation(value: u64) -> io::Result<SandboxGeneration> {
    SandboxGeneration::new(value).map_err(|_| invalid())
}

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        path::PathBuf,
    };

    use automata_ci_execution::{EnvironmentProfileId, Sha256Digest, TargetPath};

    use super::*;

    #[test]
    fn journal_is_exclusive_and_recovers_only_an_unterminated_tail() {
        let fixture = TestRoot::new("journal");
        let root = fixture.secure_root();
        let (mut journal, snapshot) = LifecycleJournal::open(&root).expect("open journal");
        assert!(snapshot.entries.is_empty());
        assert!(matches!(
            LifecycleJournal::open(&root),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        let operation_id = OperationId::new();
        let handle = OperationId::new().to_string();
        let profile = profile();
        journal
            .append(DurableEvent::CreateIntent {
                create: DurableCreate {
                    operation_id,
                    fingerprint: [0x33; 32],
                    handle: handle.clone(),
                },
                entry: DurableEntry {
                    handle: handle.clone(),
                    generation: 1,
                    profile,
                    workspace: "/Users/automata-job/workspaces/job".to_owned(),
                    scratch: "/Users/automata-job/runner/job".to_owned(),
                    phase: DurableEntryPhase::Intent,
                },
            })
            .expect("append intent");
        journal
            .append(DurableEvent::CreateReady {
                handle: handle.clone(),
            })
            .expect("append ready");
        drop(journal);

        OpenOptions::new()
            .append(true)
            .open(fixture.path.join(JOURNAL_FILE_NAME))
            .and_then(|mut file| file.write_all(b"interrupted-tail"))
            .expect("append crash tail");
        let (_journal, snapshot) = LifecycleJournal::open(&root).expect("reopen journal");
        assert_eq!(
            snapshot
                .entries
                .get(&handle)
                .expect("recovered entry")
                .phase,
            DurableEntryPhase::Running
        );
        assert_eq!(
            snapshot
                .creates
                .get(&operation_id)
                .expect("recovered create")
                .fingerprint,
            [0x33; 32]
        );
    }

    #[test]
    fn legacy_native_state_is_rejected_without_migration() {
        let fixture = TestRoot::new("legacy");
        let root = fixture.secure_root();
        fs::write(
            fixture.path.join(LEGACY_STATE_NAMES[1]),
            b"legacy native state\n",
        )
        .expect("write legacy marker");
        assert!(matches!(
            LifecycleJournal::open(&root),
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert!(!fixture.path.join(JOURNAL_FILE_NAME).exists());
    }

    fn profile() -> EnvironmentProfile {
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/macos-15-arm64-vm-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x55; 32]),
        )
    }

    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            Self {
                path: std::env::current_dir()
                    .expect("current directory")
                    .join("target/agent-scratch/macos-virtualization-journal")
                    .join(format!("{label}-{}", OperationId::new())),
            }
        }

        fn secure_root(&self) -> SecureRoot {
            let target = TargetPath::posix(
                self.path
                    .to_str()
                    .expect("test root must have a Unicode path"),
            )
            .expect("test root target");
            SecureRoot::open_or_create(&self.path, target).expect("secure test root")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.path.exists() {
                fs::remove_dir_all(&self.path).expect("remove exact test root");
            }
        }
    }
}
