use std::{fmt, sync::Arc};

use automata_core::{OperationId, RunnerId, RunnerSessionId, Sha256Digest};
use automata_protocol::{
    HandshakeErrorCode, NegotiatedSession, ProtocolLimits, ServerToRunner, SessionDisposition,
};
use automata_runner_journal::{
    JournalContentRetainSet, OrphanAbandonmentPermissions, OrphanAbandonmentReason,
    OrphanAuthorityError, OrphanAuthorityGrant, OrphanAuthorityProof, OrphanAuthorityVerifier,
    OrphanClaim, OrphanDelivery, RunnerJournal, SlotSnapshot,
};
use automata_runner_spool::DurableContentStore;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::content::ContentOperationCoordinator;
use crate::events::DurableExecutionEvents;
use crate::{
    CleanupRequest, ExecutionCancellation, ExecutionCancellationReason, ExecutionEvents,
    JobExecutor, RunnerRuntimeError, RuntimeClock, RuntimeControlReply, RuntimeIdSource,
};

/// Coordinates authority adoption, provider cleanup, and delivery disposition
/// for a definitively invalidated old session.
pub(crate) struct OrphanRecoveryCoordinator {
    runner_id: RunnerId,
    protocol_limits: ProtocolLimits,
    journal: Arc<dyn RunnerJournal>,
    spool: Arc<dyn DurableContentStore>,
    executor: Arc<dyn JobExecutor>,
    clock: Arc<dyn RuntimeClock>,
    ids: Arc<dyn RuntimeIdSource>,
    content_operations: Arc<ContentOperationCoordinator>,
}

impl OrphanRecoveryCoordinator {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        runner_id: RunnerId,
        protocol_limits: ProtocolLimits,
        journal: Arc<dyn RunnerJournal>,
        spool: Arc<dyn DurableContentStore>,
        executor: Arc<dyn JobExecutor>,
        clock: Arc<dyn RuntimeClock>,
        ids: Arc<dyn RuntimeIdSource>,
        content_operations: Arc<ContentOperationCoordinator>,
    ) -> Self {
        Self {
            runner_id,
            protocol_limits,
            journal,
            spool,
            executor,
            clock,
            ids,
            content_operations,
        }
    }

    /// Adopts only a correlated, typed invalidation carrying explicit
    /// authority for the exact old session. The configured control client is
    /// the authenticated peer boundary; arbitrary remote and authorization
    /// errors never enter this method.
    pub(crate) fn authorize_from_reply(
        &self,
        expected_session_id: RunnerSessionId,
        hello_operation_id: OperationId,
        reply: &RuntimeControlReply,
    ) -> Result<(), RunnerRuntimeError> {
        let ServerToRunner::HandshakeRejected(rejection) = reply.message().message() else {
            return Err(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid);
        };
        if rejection.code() != HandshakeErrorCode::SessionNotResumable
            || rejection.in_reply_to() != hello_operation_id
        {
            return Err(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid);
        }
        let authorization = rejection
            .orphan_recovery()
            .ok_or(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid)?;
        if authorization.session_id() != expected_session_id {
            return Err(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid);
        }
        let permissions = authorization.permissions();
        let verifier = RejectionAuthorityVerifier {
            runner_id: self.runner_id,
            session_id: expected_session_id,
            authority_operation_id: rejection.operation_id(),
            evidence_digest: digest(reply.canonical_bytes()),
            permissions: OrphanAbandonmentPermissions::new(
                permissions.terminal_result(),
                permissions.log_delivery(),
                permissions.lease_rejection(),
            ),
        };
        let proof = OrphanAuthorityProof::new(reply.canonical_bytes().to_vec())
            .map_err(|_| RunnerRuntimeError::OrphanRecoveryAuthorityInvalid)?;
        let snapshot = self.journal.snapshot()?;
        if snapshot.runner_id() != self.runner_id
            || snapshot
                .session()
                .is_none_or(|session| session.session_id() != expected_session_id)
        {
            return Err(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid);
        }
        for slot in snapshot.slots() {
            if slot.orphan().is_none() {
                self.journal.authorize_orphan(
                    expected_session_id,
                    slot.slot(),
                    slot.offer().lease().guard(),
                    &verifier,
                    &proof,
                )?;
            }
        }
        Ok(())
    }

    /// Completes every already-authorized orphan without requiring the
    /// invalidation response to remain available after a crash.
    pub(crate) async fn reconcile_authorized(
        &self,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(RunnerRuntimeError::Shutdown);
            }
            let snapshot = self.journal.snapshot()?;
            let Some(slot) = snapshot
                .slots()
                .iter()
                .find(|slot| slot.orphan().is_some())
                .cloned()
            else {
                self.content_operations.run(|| {
                    self.spool
                        .reconcile(&JournalContentRetainSet::new(self.journal.as_ref()))
                })?;
                return Ok(());
            };
            let session = snapshot
                .session()
                .ok_or(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid)?;
            self.reconcile_slot(session, &slot, cancellation.clone())
                .await?;
        }
    }

    async fn reconcile_slot(
        &self,
        session: &automata_runner_journal::SessionSnapshot,
        slot: &SlotSnapshot,
        cancellation: CancellationToken,
    ) -> Result<(), RunnerRuntimeError> {
        let orphan = slot
            .orphan()
            .ok_or(RunnerRuntimeError::OrphanRecoveryAuthorityInvalid)?;
        let terminal_pending = slot
            .terminal_result()
            .is_some_and(|result| !result.is_acknowledged());
        let log_pending = slot
            .log_delivery()
            .is_some_and(|delivery| !delivery.is_fully_delivered());
        let rejection_pending = slot
            .rejection()
            .is_some_and(|rejection| !rejection.is_response_acknowledged());
        let permissions = orphan.permissions();
        if (terminal_pending && !permissions.terminal_result())
            || (log_pending && !permissions.log_delivery())
            || (rejection_pending && !permissions.lease_rejection())
        {
            return Err(RunnerRuntimeError::OrphanRecoveryPermissionMissing);
        }

        let session_id = session.session_id();
        let slot_ordinal = slot.slot();
        let lease = slot.offer().lease();
        let guard = lease.guard();
        for (pending, delivery) in [
            (terminal_pending, OrphanDelivery::TerminalResult),
            (log_pending, OrphanDelivery::LogStream),
            (rejection_pending, OrphanDelivery::LeaseRejection),
        ] {
            if pending {
                self.journal.abandon_orphan_delivery(
                    session_id,
                    slot_ordinal,
                    guard,
                    orphan.authority_operation_id(),
                    delivery,
                    OrphanAbandonmentReason::SessionInvalidated,
                )?;
            }
        }

        let refreshed = self
            .journal
            .snapshot()?
            .slot(slot_ordinal)
            .cloned()
            .ok_or(RunnerRuntimeError::ExecutorContract)?;
        if let Some(sandbox) = refreshed.sandbox().cloned() {
            let negotiated = NegotiatedSession::new(
                session.selected_protocol(),
                session.selected_job_ir(),
                session_id,
                SessionDisposition::Resumed,
                session.command_cursor(),
            );
            let events: Arc<dyn ExecutionEvents> = Arc::new(DurableExecutionEvents::new(
                Arc::clone(&self.journal),
                Arc::clone(&self.spool),
                Arc::clone(&self.ids),
                Arc::clone(&self.clock),
                negotiated,
                slot_ordinal,
                lease.attempt_id(),
                guard,
                self.protocol_limits,
                Arc::clone(&self.content_operations),
            ));
            let signal = ExecutionCancellation::new();
            let request =
                CleanupRequest::new(session_id, slot_ordinal, lease.attempt_id(), guard, sandbox);
            let cleanup = self.executor.cleanup(request, events, signal.clone());
            tokio::pin!(cleanup);
            tokio::select! {
                result = &mut cleanup => result.map_err(RunnerRuntimeError::Executor)?,
                () = cancellation.cancelled() => {
                    signal.signal(ExecutionCancellationReason::Shutdown);
                    return Err(RunnerRuntimeError::Shutdown);
                }
            }
            if self
                .journal
                .snapshot()?
                .slot(slot_ordinal)
                .is_some_and(|current| current.sandbox().is_some())
            {
                return Err(RunnerRuntimeError::ExecutorContract);
            }
        }

        self.journal.release_slot(session_id, slot_ordinal, guard)?;
        Ok(())
    }
}

impl fmt::Debug for OrphanRecoveryCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrphanRecoveryCoordinator")
            .field("runner_id", &self.runner_id)
            .field("protocol_limits", &self.protocol_limits)
            .finish_non_exhaustive()
    }
}

struct RejectionAuthorityVerifier {
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    authority_operation_id: OperationId,
    evidence_digest: Sha256Digest,
    permissions: OrphanAbandonmentPermissions,
}

impl OrphanAuthorityVerifier for RejectionAuthorityVerifier {
    fn verify(
        &self,
        claim: OrphanClaim,
        proof: &OrphanAuthorityProof,
    ) -> Result<OrphanAuthorityGrant, OrphanAuthorityError> {
        if claim.runner_id() != self.runner_id
            || claim.session_id() != self.session_id
            || digest(proof.expose()) != self.evidence_digest
        {
            return Err(OrphanAuthorityError::Denied);
        }
        Ok(OrphanAuthorityGrant::new(
            claim,
            self.authority_operation_id,
            self.evidence_digest,
            self.permissions,
        ))
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
