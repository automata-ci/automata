mod support;

use std::sync::Arc;

use automata_ci_core::{JobLifecycle, LogStreamId, OperationId, Sha256Digest};
use automata_ci_protocol::LeaseRejectionReason;
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, JournalError,
    OrphanAbandonmentPermissions, OrphanAbandonmentReason, OrphanAuthorityError,
    OrphanAuthorityGrant, OrphanAuthorityProof, OrphanAuthorityVerifier, OrphanClaim,
    OrphanDelivery, ProviderName, ProviderOperation, ProviderOperationKind, RunnerJournal,
    SandboxHandle, SandboxIdentity, SessionBinding,
};
use support::{Fixture, Scratch};

struct GrantingVerifier {
    authority_operation_id: OperationId,
    permissions: OrphanAbandonmentPermissions,
}

impl OrphanAuthorityVerifier for GrantingVerifier {
    fn verify(
        &self,
        claim: OrphanClaim,
        proof: &OrphanAuthorityProof,
    ) -> Result<OrphanAuthorityGrant, OrphanAuthorityError> {
        if proof.expose() != b"authenticated control-plane orphan proof" {
            return Err(OrphanAuthorityError::Denied);
        }
        Ok(OrphanAuthorityGrant::new(
            claim,
            self.authority_operation_id,
            Sha256Digest::from_bytes([0xc4; 32]),
            self.permissions,
        ))
    }
}

struct DenyingVerifier;

impl OrphanAuthorityVerifier for DenyingVerifier {
    fn verify(
        &self,
        _claim: OrphanClaim,
        _proof: &OrphanAuthorityProof,
    ) -> Result<OrphanAuthorityGrant, OrphanAuthorityError> {
        Err(OrphanAuthorityError::Denied)
    }
}

#[derive(Debug)]
struct FailAfterRename;

impl CommitFaultInjector for FailAfterRename {
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault> {
        if stage == CommitStage::Renamed {
            Err(CommitFault)
        } else {
            Ok(())
        }
    }
}

fn proof() -> OrphanAuthorityProof {
    OrphanAuthorityProof::new(b"authenticated control-plane orphan proof".to_vec())
        .expect("bounded proof")
}

fn grant_all(authority_operation_id: OperationId) -> GrantingVerifier {
    GrantingVerifier {
        authority_operation_id,
        permissions: OrphanAbandonmentPermissions::new(true, true, true),
    }
}

fn prepare_undelivered_result_and_log(journal: &dyn RunnerJournal, fixture: &Fixture) {
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
        .expect("open log");
    journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            Fixture::log_segment(stream, 0, false, 24, 0x82),
            Fixture::delivery_time(),
        )
        .expect("produce log");
    journal
        .record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            Fixture::terminal_result(),
            Fixture::delivery_time(),
        )
        .expect("record unacknowledged result");
}

fn prepare_running_sandbox(journal: &dyn RunnerJournal, fixture: &Fixture) {
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Preparing,
        )
        .expect("preparing");
    let create = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(create, ProviderOperationKind::CreateSandbox),
        )
        .expect("create intent");
    journal
        .record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            create,
            SandboxIdentity::new(
                ProviderName::new("podman").expect("provider"),
                SandboxHandle::new("orphan:sandbox-7").expect("handle"),
            ),
        )
        .expect("created");
    let start = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(start, ProviderOperationKind::StartSandbox),
        )
        .expect("start intent");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            start,
        )
        .expect("started");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Running,
        )
        .expect("running");
}

#[test]
#[allow(clippy::too_many_lines)]
fn authority_is_required_and_orphan_deliveries_remain_until_explicit_abandonment() {
    let scratch = Scratch::new("orphan-delivery-recovery");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_undelivered_result_and_log(&journal, &fixture);

    let before_denial = journal.snapshot().expect("before denial");
    assert_eq!(
        before_denial
            .pending_delivery_timestamps()
            .terminal_result(),
        Some(Fixture::delivery_time())
    );
    assert_eq!(
        before_denial.pending_delivery_timestamps().log_stream(),
        Some(Fixture::delivery_time())
    );
    assert!(matches!(
        journal.authorize_orphan(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            &DenyingVerifier,
            &proof(),
        ),
        Err(JournalError::OrphanAuthority(OrphanAuthorityError::Denied))
    ));
    assert_eq!(journal.snapshot().expect("unchanged"), before_denial);
    assert!(!format!("{:?}", proof()).contains("authenticated control-plane"));
    drop(journal);

    let authority_operation_id = OperationId::new();
    let faulting = FileJournal::open_with_options(
        scratch.state_root(),
        fixture.runner_id,
        FileJournalOptions::new().with_fault_injector(Arc::new(FailAfterRename)),
    )
    .expect("open faulting journal");
    assert!(matches!(
        faulting.authorize_orphan(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            &grant_all(authority_operation_id),
            &proof(),
        ),
        Err(JournalError::CommitOutcomeUnknown)
    ));
    drop(faulting);

    let journal = fixture.open(&scratch);
    let recovered = journal.snapshot().expect("recover authority");
    let orphan = recovered
        .slot(fixture.slot)
        .expect("slot")
        .orphan()
        .expect("orphan record");
    assert_eq!(orphan.authority_operation_id(), authority_operation_id);
    assert_eq!(
        recovered.pending_delivery_timestamps().terminal_result(),
        Some(Fixture::delivery_time())
    );
    assert_eq!(
        recovered.pending_delivery_timestamps().log_stream(),
        Some(Fixture::delivery_time())
    );
    assert!(matches!(
        journal.release_slot(fixture.session_id, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(_))
    ));
    let result_abandoned = journal
        .abandon_orphan_delivery(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            authority_operation_id,
            OrphanDelivery::TerminalResult,
            OrphanAbandonmentReason::SessionInvalidated,
        )
        .expect("authorized result abandonment");
    assert_eq!(
        result_abandoned
            .pending_delivery_timestamps()
            .terminal_result(),
        None
    );
    assert_eq!(
        result_abandoned.pending_delivery_timestamps().log_stream(),
        Some(Fixture::delivery_time())
    );
    let log_abandoned = journal
        .abandon_orphan_delivery(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            authority_operation_id,
            OrphanDelivery::LogStream,
            OrphanAbandonmentReason::SessionInvalidated,
        )
        .expect("authorized log abandonment");
    assert_eq!(
        log_abandoned.pending_delivery_timestamps().log_stream(),
        None
    );
    let released = journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release authorized orphan");
    assert!(released.slots().is_empty());

    let new_binding = SessionBinding::new(
        automata_ci_core::RunnerSessionId::new(),
        fixture.binding().selected_protocol(),
        fixture.binding().selected_job_ir(),
    );
    let adopted = journal
        .begin_session(new_binding)
        .expect("adopt new server-authorized session after release");
    assert_eq!(
        adopted.session().expect("new session").session_id(),
        new_binding.session_id()
    );
}

#[test]
fn orphan_cleanup_allows_only_idempotent_stop_and_destroy_before_release() {
    let scratch = Scratch::new("orphan-provider-cleanup");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_running_sandbox(&journal, &fixture);
    let authority_operation_id = OperationId::new();
    journal
        .authorize_orphan(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            &grant_all(authority_operation_id),
            &proof(),
        )
        .expect("authorize old fence cleanup");
    assert_eq!(
        journal
            .snapshot()
            .expect("orphan")
            .slot(fixture.slot)
            .expect("slot")
            .lifecycle(),
        JobLifecycle::Lost
    );
    assert!(
        journal
            .record_provider_intent(
                fixture.session_id,
                fixture.slot,
                fixture.lease.guard(),
                ProviderOperation::intent(OperationId::new(), ProviderOperationKind::StartSandbox),
            )
            .is_err()
    );

    let stop = ProviderOperation::intent(OperationId::new(), ProviderOperationKind::StopSandbox);
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stop,
        )
        .expect("orphan stop intent");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stop.operation_id(),
        )
        .expect("orphan stopped");
    let stop_replay_before = journal.snapshot().expect("before replay").revision();
    let stop_replay = journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stop,
        )
        .expect("exact stop replay");
    assert_eq!(stop_replay.revision(), stop_replay_before);

    let destroy =
        ProviderOperation::intent(OperationId::new(), ProviderOperationKind::DestroySandbox);
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            destroy,
        )
        .expect("orphan destroy intent");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            destroy.operation_id(),
        )
        .expect("orphan destroyed");
    drop(journal);

    let journal = fixture.open(&scratch);
    assert!(
        journal
            .snapshot()
            .expect("recover cleanup")
            .slot(fixture.slot)
            .expect("slot")
            .sandbox()
            .is_none()
    );
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release reconciled orphan");
}

#[test]
fn rejected_orphan_response_requires_ack_or_authorized_abandonment() {
    let scratch = Scratch::new("orphan-rejection");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    let rejection_operation = OperationId::new();
    journal
        .reject_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseRejectionReason::ShuttingDown,
            rejection_operation,
            Fixture::delivery_time(),
        )
        .expect("reject");
    let authority_operation = OperationId::new();
    journal
        .authorize_orphan(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            &grant_all(authority_operation),
            &proof(),
        )
        .expect("authorize orphan");
    assert_eq!(
        journal
            .snapshot()
            .expect("pending rejection")
            .pending_delivery_timestamps()
            .lease_rejection(),
        Some(Fixture::delivery_time())
    );
    assert!(
        journal
            .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
            .is_err()
    );
    assert!(
        journal
            .abandon_orphan_delivery(
                fixture.session_id,
                fixture.slot,
                fixture.lease.guard(),
                OperationId::new(),
                OrphanDelivery::LeaseRejection,
                OrphanAbandonmentReason::ControlPlaneRejected,
            )
            .is_err()
    );
    let abandoned = journal
        .abandon_orphan_delivery(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            authority_operation,
            OrphanDelivery::LeaseRejection,
            OrphanAbandonmentReason::ControlPlaneRejected,
        )
        .expect("authorized rejection abandonment");
    assert_eq!(
        abandoned.pending_delivery_timestamps().lease_rejection(),
        None
    );
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release rejected orphan");
}
