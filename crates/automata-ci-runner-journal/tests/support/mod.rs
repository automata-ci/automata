#![allow(dead_code)]

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use automata_ci_core::{
    AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken, JobId, JobIrVersion,
    JobLifecycle, JobResourceAllocation, Lease, LeaseId, LogSequence, LogStreamId, OperationId,
    ResourceCapacity, RunId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
    WindowsHyperVBrokerGrant, WindowsHyperVBrokerGrantClaims, windows_action_archive_policy_sha256,
};
use automata_ci_protocol::{
    CommandSequence, INITIAL_RUNTIME_AUTHORITY_GENERATION, PROTOCOL_MAX_VERSION, RunnerSlotOrdinal,
    RuntimeAuthorityDeliveryBinding, runtime_authority_delivery_digest,
};
use automata_ci_runner_journal::{
    ContentKind, DurableCommand, DurableContentRef, FileJournal, JobIrContentRef, LeaseOfferRecord,
    LogSegment, LogSegmentPublication, RunnerJournal, RuntimeAuthorityContentRef,
    RuntimeAuthorityDeliveryRecord, SessionBinding, StateRoot, TerminalResultRecord,
};
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentProtectionError, ContentProtector, OpaqueContentIdentity,
    ProtectionId, SpoolRoot, endpoint_result_allocation,
};
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

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        if protection_id != &self.id {
            return Err(ContentProtectionError::KeyUnavailable);
        }
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(domain.separator());
        digest.update(material_digest);
        Ok(digest.finalize().into())
    }

    fn endpoint_result_protected_bytes(
        &self,
        _plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        Err(ContentProtectionError::Failed)
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
        self.offer_for(self.slot, sequence)
    }

    pub fn offer_for(&self, slot: RunnerSlotOrdinal, sequence: u64) -> LeaseOfferRecord {
        LeaseOfferRecord::new(
            slot,
            self.lease.clone(),
            JobIrContentRef::new(
                JobIrVersion::current(),
                Self::content(ContentKind::JobIr, 128, 0x5a),
            )
            .expect("valid JobIR content"),
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
        Self::content_with_protection_id(kind, size, marker, "test-aead-key-v1")
    }

    pub fn content_with_protection_id(
        kind: ContentKind,
        size: u64,
        marker: u8,
        protection_id: &str,
    ) -> DurableContentRef {
        let protection_id = ProtectionId::new(protection_id).expect("valid protection identifier");
        if kind == ContentKind::EndpointResult {
            DurableContentRef::after_endpoint_result_commit(
                endpoint_result_allocation(size).expect("bounded endpoint result allocation"),
                OpaqueContentIdentity::from_bytes([marker; 32]),
                protection_id,
            )
            .expect("valid opaque endpoint-result reference")
        } else {
            DurableContentRef::after_public_commit(
                kind,
                size,
                Sha256Digest::from_bytes([marker; 32]),
                protection_id,
            )
            .expect("valid public durable content reference")
        }
    }

    pub fn runtime_authority() -> RuntimeAuthorityContentRef {
        RuntimeAuthorityContentRef::new(Self::content(ContentKind::RuntimeAuthority, 96, 0xa7))
            .expect("valid runtime-authority content")
    }

    pub fn runtime_authority_delivery(
        &self,
        offer: &LeaseOfferRecord,
    ) -> RuntimeAuthorityDeliveryRecord {
        self.runtime_authority_delivery_with_content(offer, Self::runtime_authority())
    }

    pub fn runtime_authority_delivery_with_content(
        &self,
        offer: &LeaseOfferRecord,
        content: RuntimeAuthorityContentRef,
    ) -> RuntimeAuthorityDeliveryRecord {
        RuntimeAuthorityDeliveryRecord::new(
            RuntimeAuthorityDeliveryBinding::new(
                self.lease.attempt_id(),
                offer.slot(),
                self.lease.guard(),
                offer.command().operation_id(),
                offer.command().sequence(),
                offer
                    .job_ir()
                    .content()
                    .public_plaintext_sha256()
                    .expect("job IR has a public digest"),
                INITIAL_RUNTIME_AUTHORITY_GENERATION,
            ),
            OperationId::new(),
            OperationId::new(),
            runtime_authority_delivery_digest(
                content
                    .content()
                    .public_plaintext_sha256()
                    .expect("runtime authority has a public digest"),
                None,
            ),
            content,
            None,
        )
        .expect("valid runtime-authority delivery")
    }

    pub fn windows_hyperv_broker_grant(
        &self,
        offer: &LeaseOfferRecord,
        post_accept_operation_id: OperationId,
        session_id: RunnerSessionId,
    ) -> WindowsHyperVBrokerGrant {
        let capacity = ResourceCapacity::new(2_000, 2 * 1024 * 1024 * 1024, 0, 0);
        let allocation =
            JobResourceAllocation::new(capacity, capacity).expect("valid Windows allocation");
        let claims = WindowsHyperVBrokerGrantClaims::new(
            Sha256Digest::from_bytes([0x11; 32]),
            Sha256Digest::from_bytes([0x12; 32]),
            self.lease.attempt_id(),
            JobId::new(),
            RunId::new(),
            OperationId::new(),
            offer.command().operation_id(),
            offer.command().sequence().get(),
            post_accept_operation_id,
            Sha256Digest::from_bytes([0x13; 32]),
            self.runner_id,
            session_id,
            1,
            1,
            offer.slot().get(),
            self.lease.lease_id(),
            self.lease.fencing_token(),
            offer.job_ir().version(),
            offer
                .job_ir()
                .content()
                .public_plaintext_bytes()
                .expect("job IR has a public size"),
            offer
                .job_ir()
                .content()
                .public_plaintext_sha256()
                .expect("job IR has a public digest"),
            Sha256Digest::from_bytes([0x14; 32]),
            allocation,
            64,
            Sha256Digest::from_bytes([0x15; 32]),
            EnvironmentProfile::new(
                EnvironmentProfileId::new("example.test/windows").expect("valid profile id"),
                Sha256Digest::from_bytes([0x16; 32]),
            ),
            Sha256Digest::from_bytes([0x17; 32]),
            windows_action_archive_policy_sha256(),
            None,
            self.lease.issued_at(),
            self.lease.expires_at(),
        )
        .expect("valid Windows broker grant claims");
        WindowsHyperVBrokerGrant::new(Sha256Digest::from_bytes([0x18; 32]), claims, [0x19; 64])
            .expect("valid Windows broker grant")
    }

    pub fn runtime_authority_delivery_with_windows_grant(
        &self,
        offer: &LeaseOfferRecord,
    ) -> RuntimeAuthorityDeliveryRecord {
        self.runtime_authority_delivery_with_windows_grant_for_session(offer, self.session_id)
    }

    pub fn runtime_authority_delivery_with_windows_grant_for_session(
        &self,
        offer: &LeaseOfferRecord,
        session_id: RunnerSessionId,
    ) -> RuntimeAuthorityDeliveryRecord {
        let content = Self::runtime_authority();
        let request_operation_id = OperationId::new();
        let grant = self.windows_hyperv_broker_grant(offer, request_operation_id, session_id);
        RuntimeAuthorityDeliveryRecord::new(
            RuntimeAuthorityDeliveryBinding::new(
                self.lease.attempt_id(),
                offer.slot(),
                self.lease.guard(),
                offer.command().operation_id(),
                offer.command().sequence(),
                offer
                    .job_ir()
                    .content()
                    .public_plaintext_sha256()
                    .expect("job IR has a public digest"),
                INITIAL_RUNTIME_AUTHORITY_GENERATION,
            ),
            request_operation_id,
            OperationId::new(),
            runtime_authority_delivery_digest(
                content
                    .content()
                    .public_plaintext_sha256()
                    .expect("runtime authority has a public digest"),
                Some(&grant),
            ),
            content,
            Some(grant),
        )
        .expect("valid Windows runtime-authority delivery")
    }

    pub fn terminal_result() -> TerminalResultRecord {
        TerminalResultRecord::new(
            OperationId::new(),
            Self::content(ContentKind::TerminalResult, 64, 0x6b),
        )
        .expect("valid terminal result")
    }

    pub const fn delivery_time() -> UnixMillis {
        UnixMillis::new(45_000)
    }

    pub fn log_segment(
        stream_id: LogStreamId,
        sequence: u64,
        end_of_stream: bool,
        size: u64,
        marker: u8,
    ) -> LogSegmentPublication {
        let segment = LogSegment::new(
            LogSequence::new(sequence),
            LogSequence::new(sequence),
            1,
            size,
            Self::content(ContentKind::LogSpool, size, marker),
            end_of_stream,
            end_of_stream,
        )
        .expect("valid log segment");
        LogSegmentPublication::new(stream_id, None, segment).expect("valid log segment publication")
    }

    pub fn open(&self, scratch: &Scratch) -> FileJournal {
        FileJournal::open(scratch.state_root(), self.runner_id).expect("open journal")
    }
}

pub fn record_and_ack_runtime_authority(journal: &dyn RunnerJournal, fixture: &Fixture) {
    let snapshot = journal.snapshot().expect("snapshot accepted offer");
    let offer = snapshot
        .slot(fixture.slot)
        .expect("accepted slot")
        .offer()
        .clone();
    let delivered = journal
        .record_runtime_authority_delivery(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            fixture.runtime_authority_delivery(&offer),
        )
        .expect("record runtime-authority delivery");
    let delivery = delivered
        .slot(fixture.slot)
        .expect("accepted slot")
        .runtime_authority_delivery()
        .expect("runtime-authority delivery");
    journal
        .acknowledge_runtime_authority_delivery(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            delivery.binding().generation(),
            delivery.bundle_digest(),
            delivery.acknowledgement_operation_id(),
        )
        .expect("acknowledge runtime-authority delivery");
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
            Fixture::delivery_time(),
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
