#![allow(dead_code)]

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use automata_core::{
    AttemptId, FencingToken, JobIrVersion, JobLifecycle, Lease, LeaseId, LogSequence, LogStreamId,
    OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_protocol::{CommandSequence, PROTOCOL_MAX_VERSION, RunnerSlotOrdinal};
use automata_runner_journal::{
    ContentKind, DurableCommand, DurableContentRef, FileJournal, JobIrContentRef, LeaseOfferRecord,
    LogProductionRecord, RunnerJournal, RuntimeAuthorityContentRef, SessionBinding, StateRoot,
    TerminalResultRecord,
};
use automata_runner_spool::ProtectionId;
use automata_runner_spool::{ContentProtectionError, ContentProtector, SpoolRoot};
use sha2::{Digest as _, Sha256};

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/agent-scratch/runner-journal-tests")
            .join(format!("{label}-{}", OperationId::new()));
        fs::create_dir_all(&path).expect("create repository-local test scratch");
        let path = fs::canonicalize(path).expect("canonical repository-local test scratch");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn state_root(&self) -> StateRoot {
        StateRoot::explicit(self.child("state")).expect("valid test state root")
    }

    pub fn spool_root(&self) -> SpoolRoot {
        SpoolRoot::explicit(self.child("spool")).expect("valid test spool root")
    }
}

pub struct TestProtector {
    id: ProtectionId,
    key: [u8; 32],
}

impl TestProtector {
    pub fn new() -> Self {
        Self {
            id: ProtectionId::new("journal-test-aead-v1").expect("protection identifier"),
            key: [0x8d; 32],
        }
    }

    fn tag(&self, reference: &DurableContentRef, ciphertext: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(reference.cache_key().as_str().as_bytes());
        digest.update(ciphertext);
        digest.finalize().into()
    }
}

impl fmt::Debug for TestProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestProtector")
            .field("id", &self.id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ContentProtector for TestProtector {
    fn protection_id(&self) -> &ProtectionId {
        &self.id
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let mut protected = Vec::with_capacity(plaintext.len() + 32);
        protected.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()]),
        );
        let tag = self.tag(reference, &protected);
        protected.extend_from_slice(&tag);
        Ok(protected)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if protected.len() < 32 {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let tag_offset = protected.len() - 32;
        let ciphertext = &protected[..tag_offset];
        if protected[tag_offset..] != self.tag(reference, ciphertext) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        Ok(ciphertext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
pub struct Fixture {
    pub runner_id: RunnerId,
    pub session_id: RunnerSessionId,
    pub slot: RunnerSlotOrdinal,
    pub lease: Lease,
}

impl Fixture {
    pub fn new() -> Self {
        let runner_id = RunnerId::new();
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(7).expect("valid fence"),
            UnixMillis::new(40_000),
            UnixMillis::new(50_000),
        )
        .expect("valid lease");
        Self {
            runner_id,
            session_id: RunnerSessionId::new(),
            slot: RunnerSlotOrdinal::new(1).expect("valid slot"),
            lease,
        }
    }

    pub fn offer(&self, sequence: u64) -> LeaseOfferRecord {
        LeaseOfferRecord::new(
            self.slot,
            self.lease.clone(),
            JobIrContentRef::new(
                JobIrVersion::current(),
                Self::content(ContentKind::JobIr, 128, 0x5a),
            )
            .expect("valid JobIR content"),
            Self::runtime_authority(),
            Self::command(sequence),
        )
        .expect("valid offer")
    }

    pub fn binding(&self) -> SessionBinding {
        SessionBinding::new(
            self.session_id,
            PROTOCOL_MAX_VERSION,
            JobIrVersion::current(),
        )
    }

    pub fn command(sequence: u64) -> DurableCommand {
        let marker = u8::try_from(sequence % 251).expect("bounded marker") + 1;
        DurableCommand::new(
            CommandSequence::new(sequence).expect("valid command sequence"),
            OperationId::new(),
            Sha256Digest::from_bytes([marker; 32]),
        )
    }

    pub fn content(kind: ContentKind, size: u64, marker: u8) -> DurableContentRef {
        DurableContentRef::after_commit(
            kind,
            size,
            Sha256Digest::from_bytes([marker; 32]),
            ProtectionId::new("test-aead-key-v1").expect("valid protection identifier"),
        )
        .expect("valid durable content reference")
    }

    pub fn runtime_authority() -> RuntimeAuthorityContentRef {
        RuntimeAuthorityContentRef::new(Self::content(ContentKind::RuntimeAuthority, 96, 0xa7))
            .expect("valid runtime-authority content")
    }

    pub fn terminal_result() -> TerminalResultRecord {
        TerminalResultRecord::new(
            OperationId::new(),
            Self::content(ContentKind::TerminalResult, 64, 0x6b),
        )
        .expect("valid terminal result")
    }

    pub fn log_production(
        stream_id: LogStreamId,
        sequence: u64,
        end_of_stream: bool,
        size: u64,
        marker: u8,
    ) -> LogProductionRecord {
        LogProductionRecord::new(
            stream_id,
            LogSequence::new(sequence),
            end_of_stream,
            Self::content(ContentKind::LogSpool, size, marker),
        )
        .expect("valid log production")
    }

    pub fn open(&self, scratch: &Scratch) -> FileJournal {
        FileJournal::open(scratch.state_root(), self.runner_id).expect("open journal")
    }
}

pub fn journal_file(root: &Path) -> PathBuf {
    root.join("runner-journal.json")
}

pub fn record_and_ack_terminal(
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    terminal: JobLifecycle,
) {
    let result = Fixture::terminal_result();
    journal
        .record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            terminal,
            result.clone(),
        )
        .expect("record terminal result");
    journal
        .acknowledge_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            result.operation_id(),
        )
        .expect("acknowledge terminal result");
}
