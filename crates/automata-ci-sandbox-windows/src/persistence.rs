use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Seek as _, SeekFrom, Write as _},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

use automata_ci_execution::{EnvironmentProfile, OperationId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const LOCK_FILE_NAME: &str = ".automata-windows-provider-v2.lock";
const JOURNAL_FILE_NAME: &str = ".automata-windows-provider-v2.events";
const DURABLE_SCHEMA: u32 = 1;
const MAX_EVENT_BYTES: usize = 64 * 1024;
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
    pub(crate) fingerprint: [u8; 32],
    pub(crate) handle: String,
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
    pub(crate) workspace: String,
    pub(crate) scratch: String,
    pub(crate) memory_bytes: u64,
    pub(crate) cpu_millis: u32,
    pub(crate) pids: u32,
    pub(crate) phase: DurableEntryPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DurableEntryPhase {
    Intent,
    WorkspaceReady,
    ScratchReady,
    Running,
    Destroying,
    Degraded,
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
    EntryPhase {
        handle: String,
        phase: DurableEntryPhase,
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
    #[cfg(test)]
    fail_next_append_after_sync: bool,
}

impl LifecycleJournal {
    pub(crate) fn open(root: &Path) -> io::Result<(Self, DurableSnapshot)> {
        let lock = open_exclusive_regular(&root.join(LOCK_FILE_NAME), true, false)?;
        let mut journal = open_exclusive_regular(&root.join(JOURNAL_FILE_NAME), true, false)?;
        journal.seek(SeekFrom::Start(0))?;

        let mut snapshot = DurableSnapshot::default();
        let mut expected_sequence = 1_u64;
        let mut valid_length = 0_u64;
        let mut has_unterminated_tail = false;
        {
            let mut reader = BufReader::new(&mut journal);
            loop {
                match read_bounded_record(&mut reader)? {
                    RecordRead::End => break,
                    RecordRead::Unterminated => {
                        has_unterminated_tail = true;
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
        if has_unterminated_tail {
            journal.set_len(valid_length)?;
            journal.sync_all()?;
        }
        journal.seek(SeekFrom::End(0))?;
        Ok((
            Self {
                _lock: lock,
                journal,
                next_sequence: expected_sequence,
                #[cfg(test)]
                fail_next_append_after_sync: false,
            },
            snapshot,
        ))
    }

    pub(crate) fn append(&mut self, event: DurableEvent) -> io::Result<u64> {
        let sequence = self.next_sequence;
        let checksum = event_checksum(sequence, &event)?;
        let record = EventRecord {
            schema: DURABLE_SCHEMA,
            sequence,
            checksum,
            event,
        };
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.is_empty() || bytes.len() > MAX_EVENT_BYTES {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        bytes.push(b'\n');
        self.journal.write_all(&bytes)?;
        self.journal.flush()?;
        self.journal.sync_all()?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_append_after_sync) {
            return Err(io::Error::other(
                "injected ambiguous append failure after sync",
            ));
        }
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::FileTooLarge))?;
        Ok(sequence)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_append_after_sync(&mut self) {
        self.fail_next_append_after_sync = true;
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
    require_regular(&file)?;
    Ok(file)
}

fn require_regular(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidData))
    }
}

fn apply_event(
    snapshot: &mut DurableSnapshot,
    event: &DurableEvent,
    sequence: u64,
) -> io::Result<()> {
    match event {
        DurableEvent::CreateIntent { create, entry } => {
            apply_create_intent(snapshot, create, entry)
        }
        DurableEvent::EntryPhase { handle, phase } => apply_entry_phase(snapshot, handle, *phase),
        DurableEvent::DestroyIntent { request } => apply_destroy_intent(snapshot, request),
        DurableEvent::DestroyComplete { operation_id } => {
            apply_destroy_complete(snapshot, *operation_id, sequence)
        }
        DurableEvent::DestroyAbsent { request } => {
            apply_destroy_absent(snapshot, request, sequence)
        }
    }
}

fn apply_create_intent(
    snapshot: &mut DurableSnapshot,
    create: &DurableCreate,
    entry: &DurableEntry,
) -> io::Result<()> {
    if create.handle != entry.handle
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

fn apply_entry_phase(
    snapshot: &mut DurableSnapshot,
    handle: &str,
    phase: DurableEntryPhase,
) -> io::Result<()> {
    let entry = snapshot
        .entries
        .get_mut(handle)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if !valid_phase_transition(entry.phase, phase)
        || (phase == DurableEntryPhase::Degraded
            && !snapshot
                .pending_destroys
                .values()
                .any(|request| request.handle == handle))
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    entry.phase = phase;
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
            DurableEntryPhase::Intent
                | DurableEntryPhase::WorkspaceReady
                | DurableEntryPhase::ScratchReady
                | DurableEntryPhase::Running
        )
        || entry.generation != request.generation
        || entry.profile != request.profile
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
        .get(&operation_id)
        .cloned()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let entry = snapshot
        .entries
        .get(&request.handle)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if entry.generation != request.generation
        || entry.profile != request.profile
        || !matches!(
            entry.phase,
            DurableEntryPhase::Destroying | DurableEntryPhase::Degraded
        )
        || snapshot.tombstones.contains_key(&request.handle)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    snapshot.entries.remove(&request.handle);
    snapshot.pending_destroys.remove(&operation_id);
    snapshot.tombstones.insert(
        request.handle.clone(),
        DurableTombstone {
            handle: request.handle.clone(),
            generation: request.generation,
            profile: request.profile,
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

fn valid_phase_transition(from: DurableEntryPhase, to: DurableEntryPhase) -> bool {
    from == to
        || matches!(
            (from, to),
            (DurableEntryPhase::Intent, DurableEntryPhase::WorkspaceReady)
                | (
                    DurableEntryPhase::WorkspaceReady,
                    DurableEntryPhase::ScratchReady
                )
                | (DurableEntryPhase::ScratchReady, DurableEntryPhase::Running)
                | (DurableEntryPhase::Destroying, DurableEntryPhase::Degraded)
        )
}

fn event_checksum(sequence: u64, event: &DurableEvent) -> io::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(&(DURABLE_SCHEMA, sequence, event))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::{BufWriter, Write as _},
        path::{Path, PathBuf},
    };

    use automata_ci_execution::{
        DestroyDisposition, DestroySandbox, EnvironmentProfileId, NeverCancelled, ProviderId,
        SandboxGeneration, SandboxHandle, SandboxProvider, SandboxState, Sha256Digest, TargetPath,
    };

    use super::*;
    use crate::provider::{WindowsSandboxProvider, WindowsSandboxProviderOptions};

    const MEMORY_BYTES: u64 = 64 * 1024 * 1024;
    const CPU_MILLIS: u32 = 1_000;
    const PIDS: u32 = 8;

    #[test]
    fn every_create_and_destroy_crash_phase_reopens_as_durable_absent() {
        let cases = [
            ("pre-mkdir", DurableEntryPhase::Intent, false, false),
            (
                "post-workspace-pre-sync",
                DurableEntryPhase::Intent,
                true,
                false,
            ),
            (
                "between-directories",
                DurableEntryPhase::WorkspaceReady,
                true,
                false,
            ),
            (
                "post-scratch-pre-sync",
                DurableEntryPhase::WorkspaceReady,
                true,
                true,
            ),
            (
                "scratch-committed",
                DurableEntryPhase::ScratchReady,
                true,
                true,
            ),
            ("running", DurableEntryPhase::Running, true, true),
            (
                "between-deletes",
                DurableEntryPhase::Destroying,
                true,
                false,
            ),
            (
                "post-delete-pre-complete",
                DurableEntryPhase::Destroying,
                false,
                false,
            ),
            ("degraded-delete", DurableEntryPhase::Degraded, true, false),
        ];

        for (name, phase, workspace_exists, scratch_exists) in cases {
            let fixture = DurableFixture::new(name);
            let pending_operation = fixture.seed(phase);
            if workspace_exists {
                fs::create_dir_all(&fixture.workspace).expect("create crash workspace");
            }
            if scratch_exists {
                fs::create_dir_all(&fixture.scratch).expect("create crash scratch");
            }

            let provider = WindowsSandboxProvider::open(
                WindowsSandboxProviderOptions::new(fixture.root.clone()).expect("provider options"),
            )
            .expect("reconcile recovered entry before provider exposure");
            let inspection = provider
                .inspect(&fixture.handle(), &NeverCancelled)
                .expect("recovered handle remains inspectable");
            assert_eq!(inspection.state(), SandboxState::Absent, "case {name}");
            assert!(!fixture.workspace.exists(), "case {name}");
            assert!(!fixture.scratch.exists(), "case {name}");

            let operation_id = pending_operation.unwrap_or_default();
            let disposition = provider
                .destroy(
                    &DestroySandbox::new(operation_id, fixture.handle(), fixture.generation),
                    &NeverCancelled,
                )
                .expect("exact recovered destroy replay");
            let expected = if pending_operation.is_some() {
                DestroyDisposition::Destroyed
            } else {
                DestroyDisposition::AlreadyAbsent
            };
            assert_eq!(disposition, expected, "case {name}");
        }
    }

    #[test]
    fn partial_final_destroy_record_is_truncated_and_exact_intent_is_completed() {
        let fixture = DurableFixture::new("partial-destroy");
        let destroy_operation = fixture
            .seed(DurableEntryPhase::Destroying)
            .expect("seeded destroy intent");
        fs::create_dir_all(&fixture.workspace).expect("create crash workspace");
        let completion = encoded_record(
            6,
            DurableEvent::DestroyComplete {
                operation_id: destroy_operation,
            },
        );
        let journal_path = fixture.root.join(JOURNAL_FILE_NAME);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&journal_path)
            .expect("open WAL after simulated process exit");
        file.write_all(&completion[..completion.len() / 2])
            .expect("write unterminated partial record");
        file.sync_all().expect("sync partial fault");
        drop(file);

        let provider = WindowsSandboxProvider::open(
            WindowsSandboxProviderOptions::new(fixture.root.clone()).expect("provider options"),
        )
        .expect("truncate partial tail and complete pending destroy");
        assert_eq!(
            provider
                .inspect(&fixture.handle(), &NeverCancelled)
                .expect("inspect recovered tombstone")
                .state(),
            SandboxState::Absent
        );
        assert_eq!(
            provider
                .destroy(
                    &DestroySandbox::new(destroy_operation, fixture.handle(), fixture.generation,),
                    &NeverCancelled,
                )
                .expect("replay exact pending destroy"),
            DestroyDisposition::Destroyed
        );
        assert!(!fixture.workspace.exists());
        assert!(!fixture.scratch.exists());
    }

    #[test]
    fn streaming_reopen_retains_oldest_witness_after_many_thousand_events() {
        let root = test_root("long-history");
        let guard = TestRoot(root.clone());
        fs::create_dir_all(&root).expect("create provider root");
        let (journal, snapshot) = LifecycleJournal::open(&root).expect("initialize WAL");
        assert!(snapshot.creates.is_empty());
        drop(journal);

        let profile = profile();
        let journal_path = root.join(JOURNAL_FILE_NAME);
        let file = OpenOptions::new()
            .append(true)
            .open(&journal_path)
            .expect("open WAL for batched history fixture");
        let mut writer = BufWriter::new(file);
        let mut sequence = 1_u64;
        let mut oldest = None;
        for index in 0..2_048_u32 {
            let create_operation = OperationId::new();
            let destroy_operation = OperationId::new();
            let handle = format!("history-{index:04}");
            if oldest.is_none() {
                oldest = Some((create_operation, destroy_operation, handle.clone()));
            }
            let entry = durable_entry(&root, &handle, profile.clone(), DurableEntryPhase::Intent);
            let events = [
                DurableEvent::CreateIntent {
                    create: DurableCreate {
                        operation_id: create_operation,
                        fingerprint: [u8::try_from(index % 251).expect("fingerprint byte"); 32],
                        handle: handle.clone(),
                    },
                    entry,
                },
                DurableEvent::DestroyIntent {
                    request: DurableDestroyRequest {
                        operation_id: destroy_operation,
                        handle: handle.clone(),
                        generation: 1,
                        profile: profile.clone(),
                    },
                },
                DurableEvent::DestroyComplete {
                    operation_id: destroy_operation,
                },
            ];
            for event in events {
                writer
                    .write_all(&encoded_record(sequence, event))
                    .expect("append complete history record");
                sequence = sequence.checked_add(1).expect("bounded test sequence");
            }
        }
        writer.flush().expect("flush batched history");
        writer.get_ref().sync_all().expect("sync batched history");
        drop(writer);
        assert!(
            fs::metadata(&journal_path).expect("WAL metadata").len() > 2 * 1024 * 1024,
            "history must exceed the former artificial journal cap"
        );

        let (journal, snapshot) = LifecycleJournal::open(&root).expect("stream large WAL");
        let (old_create, old_destroy, old_handle) = oldest.expect("oldest witness");
        assert_eq!(snapshot.creates.len(), 2_048);
        assert_eq!(snapshot.destroys.len(), 2_048);
        assert_eq!(snapshot.tombstones.len(), 2_048);
        assert!(snapshot.entries.is_empty());
        assert!(snapshot.pending_destroys.is_empty());
        assert_eq!(
            snapshot
                .creates
                .get(&old_create)
                .expect("oldest create witness")
                .handle,
            old_handle
        );
        assert_eq!(
            snapshot
                .destroys
                .get(&old_destroy)
                .expect("oldest destroy witness")
                .disposition,
            DurableDestroyDisposition::Destroyed
        );
        assert!(snapshot.tombstones.contains_key(&old_handle));
        drop(journal);
        drop(guard);
    }

    struct DurableFixture {
        root: PathBuf,
        workspace: PathBuf,
        scratch: PathBuf,
        handle: String,
        generation: SandboxGeneration,
        profile: EnvironmentProfile,
        _guard: TestRoot,
    }

    impl DurableFixture {
        fn new(label: &str) -> Self {
            let root = test_root(label);
            fs::create_dir_all(&root).expect("create provider root");
            let workspace = root.join("workspaces").join("job");
            let scratch = root.join("scratch").join("job");
            Self {
                root: root.clone(),
                workspace,
                scratch,
                handle: format!("recovered-{label}"),
                generation: SandboxGeneration::new(1).expect("generation"),
                profile: profile(),
                _guard: TestRoot(root),
            }
        }

        fn handle(&self) -> SandboxHandle {
            SandboxHandle::new(
                ProviderId::new("windows-native").expect("provider ID"),
                self.handle.clone(),
            )
            .expect("sandbox handle")
        }

        fn seed(&self, phase: DurableEntryPhase) -> Option<OperationId> {
            let (mut journal, snapshot) =
                LifecycleJournal::open(&self.root).expect("open empty WAL");
            assert!(snapshot.entries.is_empty());
            let create_operation = OperationId::new();
            journal
                .append(DurableEvent::CreateIntent {
                    create: DurableCreate {
                        operation_id: create_operation,
                        fingerprint: [0x51; 32],
                        handle: self.handle.clone(),
                    },
                    entry: durable_entry(
                        &self.root,
                        &self.handle,
                        self.profile.clone(),
                        DurableEntryPhase::Intent,
                    ),
                })
                .expect("append create intent");
            if matches!(
                phase,
                DurableEntryPhase::WorkspaceReady
                    | DurableEntryPhase::ScratchReady
                    | DurableEntryPhase::Running
                    | DurableEntryPhase::Destroying
                    | DurableEntryPhase::Degraded
            ) {
                journal
                    .append(DurableEvent::EntryPhase {
                        handle: self.handle.clone(),
                        phase: DurableEntryPhase::WorkspaceReady,
                    })
                    .expect("append workspace phase");
            }
            if matches!(
                phase,
                DurableEntryPhase::ScratchReady
                    | DurableEntryPhase::Running
                    | DurableEntryPhase::Destroying
                    | DurableEntryPhase::Degraded
            ) {
                journal
                    .append(DurableEvent::EntryPhase {
                        handle: self.handle.clone(),
                        phase: DurableEntryPhase::ScratchReady,
                    })
                    .expect("append scratch phase");
            }
            if matches!(
                phase,
                DurableEntryPhase::Running
                    | DurableEntryPhase::Destroying
                    | DurableEntryPhase::Degraded
            ) {
                journal
                    .append(DurableEvent::EntryPhase {
                        handle: self.handle.clone(),
                        phase: DurableEntryPhase::Running,
                    })
                    .expect("append running phase");
            }
            let pending = if matches!(
                phase,
                DurableEntryPhase::Destroying | DurableEntryPhase::Degraded
            ) {
                let operation_id = OperationId::new();
                journal
                    .append(DurableEvent::DestroyIntent {
                        request: DurableDestroyRequest {
                            operation_id,
                            handle: self.handle.clone(),
                            generation: self.generation.get(),
                            profile: self.profile.clone(),
                        },
                    })
                    .expect("append exact destroy intent");
                Some(operation_id)
            } else {
                None
            };
            if phase == DurableEntryPhase::Degraded {
                journal
                    .append(DurableEvent::EntryPhase {
                        handle: self.handle.clone(),
                        phase: DurableEntryPhase::Degraded,
                    })
                    .expect("append degraded phase");
            }
            pending
        }
    }

    fn durable_entry(
        root: &Path,
        handle: &str,
        profile: EnvironmentProfile,
        phase: DurableEntryPhase,
    ) -> DurableEntry {
        DurableEntry {
            handle: handle.to_owned(),
            generation: 1,
            profile,
            workspace: target(&root.join("workspaces").join("job"))
                .as_str()
                .to_owned(),
            scratch: target(&root.join("scratch").join("job"))
                .as_str()
                .to_owned(),
            memory_bytes: MEMORY_BYTES,
            cpu_millis: CPU_MILLIS,
            pids: PIDS,
            phase,
        }
    }

    fn encoded_record(sequence: u64, event: DurableEvent) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&EventRecord {
            schema: DURABLE_SCHEMA,
            sequence,
            checksum: event_checksum(sequence, &event).expect("event checksum"),
            event,
        })
        .expect("event record JSON");
        bytes.push(b'\n');
        bytes
    }

    fn profile() -> EnvironmentProfile {
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/windows-durability-test-v1")
                .expect("profile ID"),
            Sha256Digest::from_bytes([0x57; 32]),
        )
    }

    fn target(path: &Path) -> TargetPath {
        TargetPath::windows(path.to_str().expect("Unicode test path").replace('/', "\\"))
            .expect("absolute Windows target path")
    }

    fn test_root(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "automata-ci-sandbox-windows-wal-{label}-{}",
            OperationId::new()
        ))
    }

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
