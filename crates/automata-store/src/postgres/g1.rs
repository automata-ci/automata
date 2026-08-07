use std::collections::BTreeSet;

use async_trait::async_trait;
use automata_core::{
    AttemptId, FencingToken, JobConclusion, JobId, JobIrVersion, JobLifecycle, Lease, LeaseGuard,
    LeaseId, LogSequence, OperationId, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId,
    RunnerCapabilities, RunnerGroup, RunnerId, RunnerRequirements, RunnerSessionId, Sha256Digest,
    UnixMillis,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{PostgresStore, lifecycle_name, parse_lifecycle};
use crate::{
    AcknowledgeRunnerCommands, AttemptAssignment, AttemptStoreError, BeginLeaseRequest,
    BegunLeaseRequest, BlockedAttempt, BlockedAttemptRepository, BlockedConclusion,
    CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload, CancellationActor,
    CancellationIntent, CancellationReason, CancellationRepository, ClaimRejection, ClaimedAttempt,
    CloseRunnerSession, CommandCursor, CommandReplayLimit, CommandSequence,
    CommitCommandAcknowledgement, CommitLeaseHeartbeat, CommitLeaseResponse,
    CommitRunnerLogSegment, CommitRunnerTerminalResult, CompleteLeaseRequest,
    ConcludeBlockedAttempt, CurrentRunnerSession, CurrentRunnerSessionRepository,
    DEFAULT_CANCELLATION_REASON, DocumentSchema, DurableRunnerCommand, EnqueueRunnerCommand,
    HeartbeatRunnerSession, JobDependency, JobIrMetadata, LeaseOfferClaim, LeaseOfferClaimStatus,
    LeaseOfferCommandIdentity, LeaseRequestKey, LeaseResponseAction, LogMetadataReceipt,
    LogMetadataRepository, LogSegmentMetadata, LogStreamMetadata, MAX_COMMAND_REPLAY_BYTES,
    NoWorkLeaseRequest, ObjectKey, OpenRunnerSession, PublishLeaseOffer, PublishedLeaseOffer,
    RequestCancellation, ResumeRunnerSession, RoutingDocument, RoutingLabel, RunnableAttempt,
    RunnableAttemptRepository, RunnableCursorAdvance, RunnableQueueKey, RunnableScanLimit,
    RunnableScanPage, RunnableScanRequest, RunnerClaimRepository, RunnerCommandOutbox,
    RunnerCommandPayload, RunnerControlTransactionRepository, RunnerGeneration, RunnerGroupId,
    RunnerLeaseOfferRepository, RunnerLeaseRequestRepository, RunnerOperationKind,
    RunnerOperationReceipt, RunnerOperationReceiptRepository, RunnerOperationRequest,
    RunnerOperationResponse, RunnerProtocolVersion, RunnerRoutingRepository, RunnerRoutingSnapshot,
    RunnerSessionFence, RunnerSessionRepository, RunnerSessionSnapshot, RunnerSlotAvailability,
    RunnerSlotAvailabilityRepository, RunnerSlotCount, SessionEpoch, StableRunnerSlot, StoreError,
    TerminalResultMetadata, TerminalResultReceipt, TerminalResultRepository, TryClaimAttempt,
    TryClaimOutcome, TryClaimReceipt, WORKFLOW_ADMISSION_EPOCH, WorkflowPlanRepository,
};

const LEASE_OPERATION_KIND: &str = "automata.lease-request.v1";
const LEASE_RPC_OPERATION_KIND: &str = "automata.runner.lease-request.v1";

pub(super) fn session_epoch_to_i64(value: SessionEpoch) -> Result<i64, AttemptStoreError> {
    i64::try_from(value.get())
        .map_err(|_| AttemptStoreError::corrupt_data("session epoch exceeds PostgreSQL BIGINT"))
}

pub(super) fn runner_generation_to_i64(value: RunnerGeneration) -> Result<i64, AttemptStoreError> {
    i64::try_from(value.get())
        .map_err(|_| AttemptStoreError::corrupt_data("runner generation exceeds PostgreSQL BIGINT"))
}

#[async_trait]
impl RunnerSessionRepository for PostgresStore {
    #[allow(clippy::too_many_lines)]
    async fn open_session(
        &self,
        request: OpenRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        validate_observed_capabilities(
            request.runner_id(),
            request.capability_snapshot().as_str(),
        )?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let runner = sqlx::query(
            r"
            SELECT generation, session_epoch, desired_state, updated_at_ms
            FROM runners
            WHERE id = $1
            FOR UPDATE
            ",
        )
        .bind(request.runner_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::RunnerNotFound(request.runner_id()))?;

        let generation = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
        if generation != request.expected_generation() {
            return Err(StoreError::generation_mismatch(
                request.runner_id(),
                request.expected_generation(),
                generation,
            ));
        }
        let desired_state =
            decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?;
        match desired_state {
            DurableDesiredRunnerState::Active => {}
            DurableDesiredRunnerState::Draining => {
                return Err(StoreError::RunnerNotAcceptingWork(request.runner_id()));
            }
            DurableDesiredRunnerState::Disabled => {
                return Err(StoreError::RunnerDisabled(request.runner_id()));
            }
        }
        let runner_changed_at =
            UnixMillis::new(runner.try_get("updated_at_ms").map_err(operation_error)?);
        if request.observed_at() < runner_changed_at {
            return Err(StoreError::SessionTimeRegression {
                session_id: request.session_id(),
                observed_at: request.observed_at(),
                durable_at: runner_changed_at,
            });
        }

        let last_live_heartbeat: Option<i64> = sqlx::query_scalar(
            r"
            SELECT max(heartbeat_at_ms)
            FROM runner_sessions
            WHERE runner_id = $1 AND disconnected_at_ms IS NULL
            ",
        )
        .bind(request.runner_id().as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if last_live_heartbeat.is_some_and(|value| request.observed_at().get() < value) {
            return Err(StoreError::SessionTimeRegression {
                session_id: request.session_id(),
                observed_at: request.observed_at(),
                durable_at: UnixMillis::new(last_live_heartbeat.unwrap_or_default()),
            });
        }

        let prior_epoch: i64 = runner.try_get("session_epoch").map_err(operation_error)?;
        let next_epoch = prior_epoch
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok())
            .and_then(|value| SessionEpoch::new(value).ok())
            .ok_or_else(|| StoreError::epoch_exhausted(request.runner_id()))?;

        sqlx::query(
            r"
            UPDATE runner_sessions
            SET disconnected_at_ms = $2
            WHERE runner_id = $1 AND disconnected_at_ms IS NULL
            ",
        )
        .bind(request.runner_id().as_uuid())
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        cleanup_disconnected_runner_lease_request_state(&mut transaction, request.runner_id())
            .await?;

        sqlx::query(
            r"
            UPDATE runners
            SET session_epoch = $2,
                status = CASE WHEN status = 'offline' THEN 'online' ELSE status END,
                last_seen_at_ms = $3,
                updated_at_ms = $3
            WHERE id = $1
            ",
        )
        .bind(request.runner_id().as_uuid())
        .bind(epoch_i64(next_epoch)?)
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;

        sqlx::query(
            r"
            INSERT INTO runner_sessions (
                id, runner_id, protocol_version, job_ir_schema,
                capability_snapshot, connected_at_ms, heartbeat_at_ms,
                runner_generation, session_epoch
            )
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $6, $7, $8)
            ",
        )
        .bind(request.session_id().as_uuid())
        .bind(request.runner_id().as_uuid())
        .bind(protocol_i32(request.protocol_version()))
        .bind(i32::from(request.job_ir_version().get()))
        .bind(request.capability_snapshot().as_str())
        .bind(request.observed_at().get())
        .bind(generation_i64(generation)?)
        .bind(epoch_i64(next_epoch)?)
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let snapshot = RunnerSessionSnapshot::try_new(
            RunnerSessionFence::new(
                request.session_id(),
                request.runner_id(),
                generation,
                next_epoch,
            ),
            request.protocol_version(),
            request.job_ir_version(),
            request.capability_snapshot().clone(),
            request.observed_at(),
            request.observed_at(),
            None,
            CommandCursor::initial(),
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(snapshot)
    }

    async fn close_session(&self, request: CloseRunnerSession) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_runner_fence(&mut transaction, request.fence()).await?;
        let snapshot = locked_session(&mut transaction, request.fence()).await?;
        if let Some(disconnected_at) = snapshot.disconnected_at() {
            if request.observed_at() < disconnected_at {
                return Err(StoreError::SessionTimeRegression {
                    session_id: request.fence().session_id(),
                    observed_at: request.observed_at(),
                    durable_at: disconnected_at,
                });
            }
            cleanup_session_lease_request_state(&mut transaction, request.fence().session_id())
                .await?;
            mark_runner_offline(&mut transaction, request.fence(), request.observed_at()).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(());
        }
        if request.observed_at() < snapshot.heartbeat_at() {
            return Err(StoreError::SessionTimeRegression {
                session_id: request.fence().session_id(),
                observed_at: request.observed_at(),
                durable_at: snapshot.heartbeat_at(),
            });
        }
        sqlx::query(
            r"
            UPDATE runner_sessions
            SET disconnected_at_ms = $5
            WHERE id = $1 AND runner_id = $2
              AND runner_generation = $3 AND session_epoch = $4
              AND disconnected_at_ms IS NULL
            ",
        )
        .bind(request.fence().session_id().as_uuid())
        .bind(request.fence().runner_id().as_uuid())
        .bind(generation_i64(request.fence().runner_generation())?)
        .bind(epoch_i64(request.fence().session_epoch())?)
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        cleanup_session_lease_request_state(&mut transaction, request.fence().session_id()).await?;
        mark_runner_offline(&mut transaction, request.fence(), request.observed_at()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn heartbeat_session(
        &self,
        request: HeartbeatRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_existing_session_authority(&mut transaction, request.fence()).await?;
        let current = locked_session(&mut transaction, request.fence()).await?;
        if current.disconnected_at().is_some() {
            return Err(StoreError::SessionClosed(request.fence().session_id()));
        }
        // Concurrent authenticated slot polls can sample the trusted clock in
        // one order and acquire this durable fence in another. A liveness-only
        // refresh must never regress the timestamp or reject the older sample.
        let observed_at = request.observed_at().max(current.heartbeat_at());
        update_session_liveness(
            &mut transaction,
            request.fence(),
            request.command_cursor(),
            observed_at,
            &current,
        )
        .await?;
        let snapshot = locked_session(&mut transaction, request.fence()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(snapshot)
    }

    async fn resume_session(
        &self,
        request: ResumeRunnerSession,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let runner = sqlx::query(
            "SELECT generation, session_epoch, status, desired_state FROM runners WHERE id = $1 FOR UPDATE",
        )
            .bind(request.runner_id().as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?
            .ok_or(StoreError::RunnerNotFound(request.runner_id()))?;
        let actual = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
        if actual != request.expected_generation() {
            return Err(StoreError::generation_mismatch(
                request.runner_id(),
                request.expected_generation(),
                actual,
            ));
        }
        let desired_state =
            decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?;
        if desired_state == DurableDesiredRunnerState::Disabled {
            return Err(StoreError::RunnerDisabled(request.runner_id()));
        }
        let status: &str = runner.try_get("status").map_err(operation_error)?;
        if status != "online" {
            return Err(StoreError::SessionClosed(request.session_id()));
        }
        let identity = sqlx::query(
            r"
            SELECT session_epoch, runner_generation, disconnected_at_ms
            FROM runner_sessions
            WHERE id = $1 AND runner_id = $2
            FOR UPDATE
            ",
        )
        .bind(request.session_id().as_uuid())
        .bind(request.runner_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::SessionNotFound(request.session_id()))?;
        if identity
            .try_get::<Option<i64>, _>("disconnected_at_ms")
            .map_err(operation_error)?
            .is_some()
        {
            return Err(StoreError::SessionClosed(request.session_id()));
        }
        let stored_generation = decode_generation(
            identity
                .try_get("runner_generation")
                .map_err(operation_error)?,
        )?;
        if stored_generation != actual {
            return Err(StoreError::fence_rejected(request.session_id()));
        }
        let epoch = decode_epoch(identity.try_get("session_epoch").map_err(operation_error)?)?;
        let current_epoch =
            decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
        if current_epoch != epoch {
            return Err(StoreError::fence_rejected(request.session_id()));
        }
        let fence =
            RunnerSessionFence::new(request.session_id(), request.runner_id(), actual, epoch);
        let current = locked_session(&mut transaction, fence).await?;
        if request.command_cursor().durable_value() < current.command_cursor().durable_value() {
            return Err(StoreError::CommandCursorBehind {
                session_id: request.session_id(),
                requested: request.command_cursor(),
                durable: current.command_cursor(),
            });
        }
        update_session_liveness(
            &mut transaction,
            fence,
            request.command_cursor(),
            request.observed_at(),
            &current,
        )
        .await?;
        let snapshot = locked_session(&mut transaction, fence).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(snapshot)
    }

    async fn get_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerSessionSnapshot, StoreError> {
        let row = session_query(fence)
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?
            .ok_or(StoreError::SessionNotFound(fence.session_id()))?;
        decode_session(&row, fence)
    }
}

#[async_trait]
impl CurrentRunnerSessionRepository for PostgresStore {
    async fn resolve_current_session(
        &self,
        request: CurrentRunnerSession,
    ) -> Result<Option<RunnerSessionFence>, StoreError> {
        let epoch = sqlx::query_scalar::<_, i64>(
            r"
            SELECT session.session_epoch
            FROM runners AS runner
            JOIN runner_sessions AS session ON session.runner_id = runner.id
            WHERE runner.id = $1
              AND runner.generation = $2
              AND runner.status = 'online'
              AND runner.desired_state IN ('active', 'draining')
              AND runner.session_epoch = session.session_epoch
              AND session.id = $3
              AND session.runner_generation = runner.generation
              AND session.disconnected_at_ms IS NULL
            ",
        )
        .bind(request.runner_id().as_uuid())
        .bind(generation_i64(request.generation())?)
        .bind(request.session_id().as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;
        epoch.map(decode_epoch).transpose().map(|epoch| {
            epoch.map(|epoch| {
                RunnerSessionFence::new(
                    request.session_id(),
                    request.runner_id(),
                    request.generation(),
                    epoch,
                )
            })
        })
    }
}

#[async_trait]
impl RunnerRoutingRepository for PostgresStore {
    async fn routing_for_session(
        &self,
        fence: RunnerSessionFence,
    ) -> Result<RunnerRoutingSnapshot, StoreError> {
        let row = sqlx::query(
            r"
            SELECT runner.group_id, runner_group.name AS group_name,
                   runner.labels, runner.capabilities::text AS registered_capabilities,
                   session.capability_snapshot::text AS negotiated_capabilities,
                   runner.slots, session.job_ir_schema
            FROM runner_sessions AS session
            JOIN runners AS runner ON runner.id = session.runner_id
            LEFT JOIN runner_groups AS runner_group ON runner_group.id = runner.group_id
            WHERE session.id = $1
              AND runner.id = $2
              AND runner.generation = $3
              AND session.runner_generation = $3
              AND runner.session_epoch = session.session_epoch
              AND session.session_epoch = $4
              AND session.disconnected_at_ms IS NULL
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fence.runner_id().as_uuid())
        .bind(generation_i64(fence.runner_generation())?)
        .bind(epoch_i64(fence.session_epoch())?)
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::fence_rejected(fence.session_id()))?;
        decode_routing(&row, fence)
    }
}

#[async_trait]
impl RunnerSlotAvailabilityRepository for PostgresStore {
    async fn slot_availability(
        &self,
        fence: RunnerSessionFence,
        slot: StableRunnerSlot,
        observed_at: UnixMillis,
    ) -> Result<RunnerSlotAvailability, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        if observed_at < routing.durable_at {
            return Err(StoreError::SessionTimeRegression {
                session_id: fence.session_id(),
                observed_at,
                durable_at: routing.durable_at,
            });
        }
        if !routing.online || !routing.accepts_new_work {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(RunnerSlotAvailability::RunnerUnavailable);
        }
        if !routing.slots.contains(slot) {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(RunnerSlotAvailability::OutOfRange);
        }

        let occupied = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM job_attempts
            WHERE runner_id = $1 AND runner_slot = $2 AND lease_id IS NOT NULL
            LIMIT 1
            ",
        )
        .bind(fence.runner_id().as_uuid())
        .bind(i32::from(slot.ordinal()))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let availability = occupied.map_or(RunnerSlotAvailability::Available, |attempt_id| {
            RunnerSlotAvailability::Occupied {
                attempt_id: AttemptId::from_uuid(attempt_id),
            }
        });
        transaction.commit().await.map_err(operation_error)?;
        Ok(availability)
    }
}

#[async_trait]
impl RunnerCommandOutbox for PostgresStore {
    async fn enqueue_command(
        &self,
        command: EnqueueRunnerCommand,
    ) -> Result<DurableRunnerCommand, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let durable = enqueue_command_in_transaction(&mut transaction, command).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(durable)
    }

    async fn replay_commands(
        &self,
        session: RunnerSessionFence,
        after: CommandCursor,
        limit: CommandReplayLimit,
    ) -> Result<Vec<DurableRunnerCommand>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, session)
            .await?
            .require_online(session)?;
        let rows = sqlx::query(
            r"
            WITH pending AS (
                SELECT command_sequence, operation_id, command_kind, command_schema,
                       command_digest, command_payload, created_at_ms,
                       sum(octet_length(command_payload)) OVER (
                           ORDER BY command_sequence
                       ) AS cumulative_payload_bytes
                FROM runner_command_outbox
                WHERE runner_session_id = $1
                  AND command_sequence > greatest(
                      $2,
                      (
                          SELECT acknowledged_command_sequence
                          FROM runner_sessions
                          WHERE id = $1
                      )
                  )
            )
            SELECT command_sequence, operation_id, command_kind, command_schema,
                   command_digest, command_payload, created_at_ms
            FROM pending
            WHERE cumulative_payload_bytes <= $4
            ORDER BY command_sequence
            LIMIT $3
            ",
        )
        .bind(session.session_id().as_uuid())
        .bind(cursor_i64(after)?)
        .bind(i64::from(limit.get()))
        .bind(i64::try_from(MAX_COMMAND_REPLAY_BYTES).map_err(|_| {
            StoreError::corrupt_data("command replay byte limit exceeds PostgreSQL BIGINT")
        })?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let commands = rows
            .iter()
            .map(|row| decode_outbox_command(row, session, true))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(commands)
    }

    async fn acknowledge_commands(
        &self,
        acknowledgement: AcknowledgeRunnerCommands,
    ) -> Result<CommandCursor, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_existing_session_authority(&mut transaction, acknowledgement.session()).await?;
        let current = locked_session(&mut transaction, acknowledgement.session()).await?;
        if current.disconnected_at().is_some() {
            return Err(StoreError::SessionClosed(
                acknowledgement.session().session_id(),
            ));
        }
        update_session_liveness(
            &mut transaction,
            acknowledgement.session(),
            acknowledgement.cursor(),
            acknowledgement.observed_at(),
            &current,
        )
        .await?;
        let updated = locked_session(&mut transaction, acknowledgement.session()).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(updated.command_cursor())
    }
}

#[async_trait]
impl RunnerOperationReceiptRepository for PostgresStore {
    async fn lookup_operation(
        &self,
        request: &RunnerOperationRequest,
    ) -> Result<Option<RunnerOperationReceipt>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, request.session())
            .await?
            .require_online(request.session())?;
        let row = sqlx::query(
            r"
            SELECT operation_kind, request_digest, response_schema,
                   response_digest, response_payload, committed_at_ms
            FROM runner_rpc_receipts
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(request.session().session_id().as_uuid())
        .bind(request.operation_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let receipt = row
            .as_ref()
            .map(|row| decode_generic_receipt(row, request, true))
            .transpose()?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn record_operation(
        &self,
        request: RunnerOperationRequest,
        response: RunnerOperationResponse,
        committed_at: UnixMillis,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, request.session())
            .await?
            .require_online(request.session())?;
        if request.kind().as_str() == LEASE_RPC_OPERATION_KIND {
            lock_current_lease_rpc_operation(&mut transaction, &request).await?;
        }
        let inserted = sqlx::query(
            r"
            INSERT INTO runner_rpc_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                request_digest, response_schema, response_digest,
                response_payload, committed_at_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (runner_session_id, operation_id) DO NOTHING
            ",
        )
        .bind(request.session().session_id().as_uuid())
        .bind(request.operation_id().as_uuid())
        .bind(request.session().runner_id().as_uuid())
        .bind(epoch_i64(request.session().session_epoch())?)
        .bind(generation_i64(request.session().runner_generation())?)
        .bind(request.kind().as_str())
        .bind(request.request_digest().as_bytes().as_slice())
        .bind(i32::from(response.schema().get()))
        .bind(response.digest().as_bytes().as_slice())
        .bind(response.payload())
        .bind(committed_at.get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        if inserted == 1 {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(RunnerOperationReceipt::new(
                request,
                response,
                committed_at,
                false,
            ));
        }
        let row = sqlx::query(
            r"
            SELECT operation_kind, request_digest, response_schema,
                   response_digest, response_payload, committed_at_ms
            FROM runner_rpc_receipts
            WHERE runner_session_id = $1 AND operation_id = $2
            FOR UPDATE
            ",
        )
        .bind(request.session().session_id().as_uuid())
        .bind(request.operation_id().as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let receipt = decode_generic_receipt(&row, &request, true)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

#[async_trait]
impl RunnerLeaseRequestRepository for PostgresStore {
    #[allow(clippy::too_many_lines)]
    async fn begin_lease_request(
        &self,
        request: BeginLeaseRequest,
    ) -> Result<BegunLeaseRequest, StoreError> {
        let key = request.request_key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let routing = lock_live_routing(&mut transaction, key.session()).await?;
        routing.require_online(key.session())?;
        if !routing.slots.contains(key.slot()) {
            return Err(StoreError::SlotOutOfRange {
                session_id: key.session().session_id(),
                slot: key.slot(),
            });
        }

        let current = sqlx::query(
            r"
            SELECT operation_id, request_digest, acknowledges_operation_id
            FROM runner_lease_request_heads
            WHERE runner_session_id = $1 AND runner_slot = $2
            FOR UPDATE
            ",
        )
        .bind(key.session().session_id().as_uuid())
        .bind(i32::from(key.slot().ordinal()))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let completed_response = if let Some(current) = current {
            let current_operation =
                OperationId::from_uuid(current.try_get("operation_id").map_err(operation_error)?);
            let current_digest = crate::value::decode_sha256_digest(
                current.try_get("request_digest").map_err(operation_error)?,
            )
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
            let current_predecessor = current
                .try_get::<Option<Uuid>, _>("acknowledges_operation_id")
                .map_err(operation_error)?
                .map(OperationId::from_uuid);

            if current_operation == key.operation_id() {
                if current_digest != request.request_digest()
                    || current_predecessor != key.acknowledges_operation_id()
                {
                    return Err(lease_request_conflict(key));
                }
                load_lease_rpc_response(&mut transaction, request, true).await?
            } else {
                if key.acknowledges_operation_id() != Some(current_operation) {
                    return Err(lease_request_conflict(key));
                }
                let current_key = if let Some(predecessor) = current_predecessor {
                    LeaseRequestKey::successor(
                        key.session(),
                        current_operation,
                        key.slot(),
                        predecessor,
                    )
                    .map_err(|error| StoreError::corrupt_data(error.to_string()))?
                } else {
                    LeaseRequestKey::first(key.session(), current_operation, key.slot())
                };
                let current_request = BeginLeaseRequest::new(current_key, current_digest);
                if load_lease_rpc_response(&mut transaction, current_request, false)
                    .await?
                    .is_none()
                {
                    return Err(lease_request_conflict(key));
                }

                sqlx::query(
                    r"
                    DELETE FROM runner_operation_receipts
                    WHERE runner_session_id = $1 AND operation_id = $2
                    ",
                )
                .bind(key.session().session_id().as_uuid())
                .bind(current_operation.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                let deleted = sqlx::query(
                    r"
                    DELETE FROM runner_rpc_receipts
                    WHERE runner_session_id = $1 AND operation_id = $2
                      AND operation_kind = $3
                    ",
                )
                .bind(key.session().session_id().as_uuid())
                .bind(current_operation.as_uuid())
                .bind(LEASE_RPC_OPERATION_KIND)
                .execute(&mut *transaction)
                .await
                .map_err(operation_error)?;
                if deleted.rows_affected() != 1 {
                    return Err(StoreError::invalid_operation_receipt(
                        "completed lease-request predecessor disappeared",
                    ));
                }
                let updated = sqlx::query(
                    r"
                    UPDATE runner_lease_request_heads
                    SET operation_id = $3, request_digest = $4,
                        acknowledges_operation_id = $5
                    WHERE runner_session_id = $1 AND runner_slot = $2
                      AND operation_id = $6
                    ",
                )
                .bind(key.session().session_id().as_uuid())
                .bind(i32::from(key.slot().ordinal()))
                .bind(key.operation_id().as_uuid())
                .bind(request.request_digest().as_bytes().as_slice())
                .bind(key.acknowledges_operation_id().map(OperationId::as_uuid))
                .bind(current_operation.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(|error| map_lease_head_write_error(error, key))?;
                if updated.rows_affected() != 1 {
                    return Err(lease_request_conflict(key));
                }
                None
            }
        } else {
            if key.acknowledges_operation_id().is_some() {
                return Err(lease_request_conflict(key));
            }
            sqlx::query(
                r"
                INSERT INTO runner_lease_request_heads (
                    runner_session_id, runner_slot, runner_id,
                    runner_session_epoch, runner_generation, operation_id,
                    request_digest, acknowledges_operation_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
                ",
            )
            .bind(key.session().session_id().as_uuid())
            .bind(i32::from(key.slot().ordinal()))
            .bind(key.session().runner_id().as_uuid())
            .bind(epoch_i64(key.session().session_epoch())?)
            .bind(generation_i64(key.session().runner_generation())?)
            .bind(key.operation_id().as_uuid())
            .bind(request.request_digest().as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|error| map_lease_head_write_error(error, key))?;
            None
        };

        transaction.commit().await.map_err(operation_error)?;
        Ok(BegunLeaseRequest::new(request, completed_response))
    }

    async fn complete_lease_request(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<RunnerOperationResponse, StoreError> {
        let begin = request.request();
        let key = begin.request_key();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, key.session())
            .await?
            .require_online(key.session())?;
        lock_current_lease_request_head(&mut transaction, key, Some(begin.request_digest()))
            .await?;
        let inserted = sqlx::query(
            r"
            INSERT INTO runner_rpc_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                request_digest, response_schema, response_digest,
                response_payload, committed_at_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (runner_session_id, operation_id) DO NOTHING
            ",
        )
        .bind(key.session().session_id().as_uuid())
        .bind(key.operation_id().as_uuid())
        .bind(key.session().runner_id().as_uuid())
        .bind(epoch_i64(key.session().session_epoch())?)
        .bind(generation_i64(key.session().runner_generation())?)
        .bind(LEASE_RPC_OPERATION_KIND)
        .bind(begin.request_digest().as_bytes().as_slice())
        .bind(i32::from(request.response().schema().get()))
        .bind(request.response().digest().as_bytes().as_slice())
        .bind(request.response().payload())
        .bind(request.completed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        let response = if inserted == 1 {
            request.into_response()
        } else {
            load_lease_rpc_response(&mut transaction, begin, true)
                .await?
                .ok_or_else(|| {
                    StoreError::invalid_operation_receipt(
                        "conflicting lease-request receipt disappeared",
                    )
                })?
        };
        transaction.commit().await.map_err(operation_error)?;
        Ok(response)
    }
}

#[async_trait]
impl RunnerLeaseOfferRepository for PostgresStore {
    async fn inspect_lease_offer_claim(
        &self,
        request: LeaseOfferClaim,
    ) -> Result<LeaseOfferClaimStatus, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.lease().attempt_id())
            .await?;
        let routing = lock_live_routing(&mut transaction, request.request().session()).await?;
        routing.require_online(request.request().session())?;
        if let Some(publication) =
            load_lease_offer_publication(&mut transaction, &request, None, true).await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LeaseOfferClaimStatus::Published(Box::new(publication)));
        }
        lock_exact_lease_offer_claim(&mut transaction, &request, &routing).await?;
        let current = lock_publishable_lease_offer_attempt(&mut transaction, &request).await?;
        if current && !routing.accepts_new_work {
            return Err(StoreError::RunnerNotAcceptingWork(
                request.request().session().runner_id(),
            ));
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(if current {
            LeaseOfferClaimStatus::Current
        } else {
            LeaseOfferClaimStatus::ClaimSuperseded
        })
    }

    async fn resolve_lease_offer_command(
        &self,
        identity: LeaseOfferCommandIdentity,
    ) -> Result<Option<PublishedLeaseOffer>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, identity.session())
            .await?
            .require_online(identity.session())?;
        let publication =
            load_lease_offer_publication_by_command(&mut transaction, identity).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(publication)
    }

    async fn publish_lease_offer(
        &self,
        request: PublishLeaseOffer,
    ) -> Result<PublishedLeaseOffer, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.lease().attempt_id())
            .await?;
        let routing = lock_live_routing(&mut transaction, request.request().session()).await?;
        routing.require_online(request.request().session())?;
        if let Some(publication) = load_lease_offer_publication(
            &mut transaction,
            request.claim(),
            Some(request.command()),
            true,
        )
        .await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(publication);
        }
        lock_exact_lease_offer_claim(&mut transaction, request.claim(), &routing).await?;
        if !lock_publishable_lease_offer_attempt(&mut transaction, request.claim()).await? {
            return Err(StoreError::AttemptFenceRejected(
                request.lease().attempt_id(),
            ));
        }
        if !routing.accepts_new_work {
            return Err(StoreError::RunnerNotAcceptingWork(
                request.request().session().runner_id(),
            ));
        }
        let command =
            enqueue_command_in_transaction(&mut transaction, request.command().clone()).await?;
        insert_lease_offer_publication(&mut transaction, &request, command.sequence()).await?;
        let publication = PublishedLeaseOffer::new(
            request.request().clone(),
            request.protocol_version(),
            request.slot(),
            request.lease().clone(),
            request.job_ir().clone(),
            command,
        );
        transaction.commit().await.map_err(operation_error)?;
        Ok(publication)
    }
}

#[async_trait]
impl RunnerControlTransactionRepository for PostgresStore {
    async fn commit_lease_response(
        &self,
        request: CommitLeaseResponse,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        routing.require_online(fence)?;
        let current = locked_session(&mut transaction, fence).await?;
        if !current.is_live() {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        if let Some(receipt) =
            load_generic_receipt(&mut transaction, request.request(), true).await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        verify_exact_published_offer(&mut transaction, &request).await?;
        update_session_liveness(
            &mut transaction,
            fence,
            request.command_cursor(),
            request.observed_at(),
            &current,
        )
        .await?;
        apply_lease_response(&mut transaction, &request).await?;
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            request.observed_at(),
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            request.request().clone(),
            request.response().clone(),
            request.observed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_lease_heartbeat(
        &self,
        request: CommitLeaseHeartbeat,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(
            &mut transaction,
            request.renewal().attempt_id(),
        )
        .await?;
        let routing = lock_live_routing(&mut transaction, fence).await?;
        if !routing.online {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        let current = locked_session(&mut transaction, fence).await?;
        if !current.is_live() {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        if let Some(receipt) =
            load_generic_receipt(&mut transaction, request.request(), true).await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        update_session_liveness(
            &mut transaction,
            fence,
            request.command_cursor(),
            request.renewal().observed_at(),
            &current,
        )
        .await?;
        if let Some(lifecycle) = request.reported_lifecycle() {
            commit_reported_lifecycle(&mut transaction, request.renewal(), lifecycle).await?;
        }
        let lease = super::renew_lease_in_transaction(&mut transaction, request.renewal()).await?;
        if lease.expires_at() != request.renewal().expires_at()
            || lease.guard() != request.renewal().guard()
            || lease.attempt_id() != request.renewal().attempt_id()
        {
            return Err(StoreError::corrupt_data(
                "atomic heartbeat renewal returned mismatched lease",
            ));
        }
        let receipt = insert_generic_receipt(
            &mut transaction,
            request.request().clone(),
            request.response().clone(),
            request.renewal().observed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_command_acknowledgement(
        &self,
        request: CommitCommandAcknowledgement,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = request.request().session();
        let routing = lock_live_routing(&mut transaction, fence).await?;
        if !routing.online {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        let current = locked_session(&mut transaction, fence).await?;
        if !current.is_live() {
            return Err(StoreError::SessionClosed(fence.session_id()));
        }
        if let Some(receipt) =
            load_generic_receipt(&mut transaction, request.request(), true).await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let acknowledgement = request.acknowledgement();
        update_session_liveness(
            &mut transaction,
            fence,
            acknowledgement.cursor(),
            acknowledgement.observed_at(),
            &current,
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            request.request().clone(),
            request.response().clone(),
            acknowledgement.observed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_runner_terminal_result(
        &self,
        request: CommitRunnerTerminalResult,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        lock_live_routing(&mut transaction, fence)
            .await?
            .require_online(fence)?;
        if let Some(receipt) =
            load_generic_receipt(&mut transaction, request.request(), true).await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let slot = lock_exact_active_attempt(
            &mut transaction,
            request.attempt_id(),
            fence,
            request.guard(),
            request.committed_at(),
        )
        .await?;
        insert_terminal_result(&mut transaction, &request, slot).await?;
        conclude_terminal_attempt(&mut transaction, &request).await?;
        close_cancellation_from_result(
            &mut transaction,
            request.attempt_id(),
            request.committed_at(),
        )
        .await?;
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            request.committed_at(),
        )
        .await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            request.request().clone(),
            request.response().clone(),
            request.committed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn commit_runner_log_segment(
        &self,
        request: CommitRunnerLogSegment,
    ) -> Result<RunnerOperationReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = request.request().session();
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        lock_live_routing(&mut transaction, fence)
            .await?
            .require_online(fence)?;
        if let Some(receipt) =
            load_generic_receipt(&mut transaction, request.request(), true).await?
        {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }
        let slot = lock_exact_active_attempt(
            &mut transaction,
            request.attempt_id(),
            fence,
            request.guard(),
            request.stored_at(),
        )
        .await?;
        append_runner_log_segment(&mut transaction, &request, slot).await?;
        let receipt = insert_generic_receipt(
            &mut transaction,
            request.request().clone(),
            request.response().clone(),
            request.stored_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

#[async_trait]
impl TerminalResultRepository for PostgresStore {
    async fn commit_terminal_result(
        &self,
        metadata: TerminalResultMetadata,
    ) -> Result<TerminalResultReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = metadata.assignment().session();
        super::admission::lock_attempt_concurrency(&mut transaction, metadata.attempt_id()).await?;
        lock_live_routing(&mut transaction, fence)
            .await?
            .require_online(fence)?;
        if let Some(row) = load_terminal_metadata(&mut transaction, metadata.attempt_id()).await? {
            if !terminal_metadata_matches(&row, &metadata)? {
                return Err(StoreError::ImmutableConflict("terminal result"));
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(TerminalResultReceipt::new(metadata, true));
        }
        let slot = lock_exact_active_attempt(
            &mut transaction,
            metadata.attempt_id(),
            fence,
            metadata.guard(),
            metadata.committed_at(),
        )
        .await?;
        if slot != metadata.assignment().slot() {
            return Err(StoreError::AttemptFenceRejected(metadata.attempt_id()));
        }
        insert_terminal_metadata(&mut transaction, &metadata).await?;
        conclude_terminal_metadata_attempt(&mut transaction, &metadata).await?;
        close_cancellation_from_result(
            &mut transaction,
            metadata.attempt_id(),
            metadata.committed_at(),
        )
        .await?;
        super::admission::reconcile_attempt_run(
            &mut transaction,
            metadata.attempt_id(),
            metadata.committed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(TerminalResultReceipt::new(metadata, false))
    }
}

#[async_trait]
impl LogMetadataRepository for PostgresStore {
    async fn create_log_stream(
        &self,
        metadata: LogStreamMetadata,
    ) -> Result<LogMetadataReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let fence = metadata.assignment().session();
        super::admission::lock_attempt_concurrency(&mut transaction, metadata.attempt_id()).await?;
        lock_live_routing(&mut transaction, fence)
            .await?
            .require_online(fence)?;
        let existing = sqlx::query(
            r"
            SELECT attempt_id, runner_session_id, operation_id, runner_id,
                   runner_session_epoch, runner_generation, runner_slot,
                   lease_id, fencing_token, log_schema, opened_at_ms
            FROM attempt_log_streams WHERE id = $1 FOR UPDATE
            ",
        )
        .bind(metadata.stream_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if let Some(row) = existing {
            if !log_stream_metadata_matches(&row, &metadata)? {
                return Err(StoreError::ImmutableConflict("log stream"));
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogMetadataReceipt::new(true));
        }
        let slot = lock_exact_active_attempt(
            &mut transaction,
            metadata.attempt_id(),
            fence,
            metadata.guard(),
            metadata.opened_at(),
        )
        .await?;
        if slot != metadata.assignment().slot() {
            return Err(StoreError::AttemptFenceRejected(metadata.attempt_id()));
        }
        insert_log_stream_metadata(&mut transaction, &metadata).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogMetadataReceipt::new(false))
    }

    async fn append_log_segment(
        &self,
        metadata: LogSegmentMetadata,
    ) -> Result<LogMetadataReceipt, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let identity = load_log_stream_identity(&mut transaction, metadata.stream_id()).await?;
        let attempt_id =
            AttemptId::from_uuid(identity.try_get("attempt_id").map_err(operation_error)?);
        super::admission::lock_attempt_concurrency(&mut transaction, attempt_id).await?;
        let fence = decode_stream_fence(&identity)?;
        lock_live_routing(&mut transaction, fence)
            .await?
            .require_online(fence)?;
        if let Some(row) = load_log_segment_by_operation(
            &mut transaction,
            metadata.stream_id(),
            metadata.operation_id(),
        )
        .await?
        {
            if !log_segment_metadata_matches(&row, &metadata)? {
                return Err(StoreError::ImmutableConflict("log segment"));
            }
            transaction.commit().await.map_err(operation_error)?;
            return Ok(LogMetadataReceipt::new(true));
        }
        let guard = LeaseGuard::new(
            automata_core::LeaseId::from_uuid(
                identity.try_get("lease_id").map_err(operation_error)?,
            ),
            decode_fencing(identity.try_get("fencing_token").map_err(operation_error)?)?,
        );
        let active_slot = lock_exact_active_attempt(
            &mut transaction,
            attempt_id,
            fence,
            guard,
            metadata.stored_at(),
        )
        .await?;
        let stream = load_locked_log_stream(&mut transaction, metadata.stream_id()).await?;
        if !log_stream_matches_active(&stream, attempt_id, fence, guard, active_slot)? {
            return Err(StoreError::ImmutableConflict("log stream"));
        }
        if stream
            .try_get::<Option<i64>, _>("closed_at_ms")
            .map_err(operation_error)?
            .is_some()
        {
            return Err(StoreError::ImmutableConflict("closed log stream"));
        }
        insert_contiguous_log_metadata(&mut transaction, &metadata).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(LogMetadataReceipt::new(false))
    }
}

async fn load_terminal_metadata(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT attempt_id, runner_session_id, operation_id, runner_id,
               runner_session_epoch, runner_generation, runner_slot, lease_id,
               fencing_token, result_schema, result_size_bytes, result_digest,
               result_object_key, conclusion, completed_at_ms, committed_at_ms
        FROM attempt_terminal_results WHERE attempt_id = $1 FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn terminal_metadata_matches(
    row: &sqlx::postgres::PgRow,
    metadata: &TerminalResultMetadata,
) -> Result<bool, StoreError> {
    let assignment = metadata.assignment();
    let fence = assignment.session();
    Ok(row
        .try_get::<Uuid, _>("attempt_id")
        .map_err(operation_error)?
        == metadata.attempt_id().as_uuid()
        && row
            .try_get::<Uuid, _>("runner_session_id")
            .map_err(operation_error)?
            == fence.session_id().as_uuid()
        && row
            .try_get::<Uuid, _>("operation_id")
            .map_err(operation_error)?
            == metadata.operation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("runner_id")
            .map_err(operation_error)?
            == fence.runner_id().as_uuid()
        && row
            .try_get::<i64, _>("runner_session_epoch")
            .map_err(operation_error)?
            == epoch_i64(fence.session_epoch())?
        && row
            .try_get::<i64, _>("runner_generation")
            .map_err(operation_error)?
            == generation_i64(fence.runner_generation())?
        && row
            .try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?
            == i32::from(assignment.slot().ordinal())
        && row
            .try_get::<Uuid, _>("lease_id")
            .map_err(operation_error)?
            == metadata.guard().lease_id().as_uuid()
        && row
            .try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?
            == fencing_i64(metadata.guard().fencing_token())?
        && row
            .try_get::<i32, _>("result_schema")
            .map_err(operation_error)?
            == i32::from(metadata.schema().get())
        && row
            .try_get::<i64, _>("result_size_bytes")
            .map_err(operation_error)?
            == size_i64(metadata.encoded_size(), "terminal result")?
        && crate::value::decode_sha256_digest(
            row.try_get("result_digest").map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?
            == metadata.digest()
        && row
            .try_get::<String, _>("result_object_key")
            .map_err(operation_error)?
            == metadata.object_key().as_str()
        && row
            .try_get::<String, _>("conclusion")
            .map_err(operation_error)?
            == conclusion_name(metadata.conclusion())
        && row
            .try_get::<i64, _>("completed_at_ms")
            .map_err(operation_error)?
            == metadata.completed_at().get()
        && row
            .try_get::<i64, _>("committed_at_ms")
            .map_err(operation_error)?
            == metadata.committed_at().get())
}

async fn insert_terminal_metadata(
    transaction: &mut Transaction<'_, Postgres>,
    metadata: &TerminalResultMetadata,
) -> Result<(), StoreError> {
    let assignment = metadata.assignment();
    let fence = assignment.session();
    sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot, lease_id,
            fencing_token, result_schema, result_size_bytes, result_digest,
            result_object_key, conclusion, completed_at_ms, committed_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ",
    )
    .bind(metadata.attempt_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(metadata.operation_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(assignment.slot().ordinal()))
    .bind(metadata.guard().lease_id().as_uuid())
    .bind(fencing_i64(metadata.guard().fencing_token())?)
    .bind(i32::from(metadata.schema().get()))
    .bind(size_i64(metadata.encoded_size(), "terminal result")?)
    .bind(metadata.digest().as_bytes().as_slice())
    .bind(metadata.object_key().as_str())
    .bind(conclusion_name(metadata.conclusion()))
    .bind(metadata.completed_at().get())
    .bind(metadata.committed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn conclude_terminal_metadata_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    metadata: &TerminalResultMetadata,
) -> Result<(), StoreError> {
    let assignment = metadata.assignment();
    let fence = assignment.session();
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $9, lease_id = NULL, runner_id = NULL,
            lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
            runner_session_id = NULL, runner_session_epoch = NULL,
            runner_generation = NULL, runner_slot = NULL, changed_at_ms = $10
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
          AND runner_slot = $8
          AND lifecycle IN ('leased','preparing','running','cancelling','finalizing')
          AND changed_at_ms <= $10 AND lease_expires_at_ms > $10
        ",
    )
    .bind(metadata.attempt_id().as_uuid())
    .bind(metadata.guard().lease_id().as_uuid())
    .bind(fencing_i64(metadata.guard().fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(assignment.slot().ordinal()))
    .bind(lifecycle_name(terminal_lifecycle(metadata.conclusion())))
    .bind(metadata.committed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(metadata.attempt_id()));
    }
    Ok(())
}

fn log_stream_metadata_matches(
    row: &sqlx::postgres::PgRow,
    metadata: &LogStreamMetadata,
) -> Result<bool, StoreError> {
    let assignment = metadata.assignment();
    let fence = assignment.session();
    Ok(row
        .try_get::<Uuid, _>("attempt_id")
        .map_err(operation_error)?
        == metadata.attempt_id().as_uuid()
        && row
            .try_get::<Uuid, _>("runner_session_id")
            .map_err(operation_error)?
            == fence.session_id().as_uuid()
        && row
            .try_get::<Uuid, _>("operation_id")
            .map_err(operation_error)?
            == metadata.operation_id().as_uuid()
        && row
            .try_get::<Uuid, _>("runner_id")
            .map_err(operation_error)?
            == fence.runner_id().as_uuid()
        && row
            .try_get::<i64, _>("runner_session_epoch")
            .map_err(operation_error)?
            == epoch_i64(fence.session_epoch())?
        && row
            .try_get::<i64, _>("runner_generation")
            .map_err(operation_error)?
            == generation_i64(fence.runner_generation())?
        && row
            .try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?
            == i32::from(assignment.slot().ordinal())
        && row
            .try_get::<Uuid, _>("lease_id")
            .map_err(operation_error)?
            == metadata.guard().lease_id().as_uuid()
        && row
            .try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?
            == fencing_i64(metadata.guard().fencing_token())?
        && row
            .try_get::<i32, _>("log_schema")
            .map_err(operation_error)?
            == i32::from(metadata.schema().get())
        && row
            .try_get::<i64, _>("opened_at_ms")
            .map_err(operation_error)?
            == metadata.opened_at().get())
}

async fn insert_log_stream_metadata(
    transaction: &mut Transaction<'_, Postgres>,
    metadata: &LogStreamMetadata,
) -> Result<(), StoreError> {
    let assignment = metadata.assignment();
    let fence = assignment.session();
    sqlx::query(
        r"
        INSERT INTO attempt_log_streams (
            id, attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot, lease_id,
            fencing_token, log_schema, opened_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ",
    )
    .bind(metadata.stream_id().as_uuid())
    .bind(metadata.attempt_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(metadata.operation_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(assignment.slot().ordinal()))
    .bind(metadata.guard().lease_id().as_uuid())
    .bind(fencing_i64(metadata.guard().fencing_token())?)
    .bind(i32::from(metadata.schema().get()))
    .bind(metadata.opened_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn load_log_segment_by_operation(
    transaction: &mut Transaction<'_, Postgres>,
    stream_id: automata_core::LogStreamId,
    operation_id: OperationId,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT stream_id, operation_id, first_sequence, last_sequence,
               object_key, object_digest, encoded_size_bytes,
               uncompressed_size_bytes, stored_at_ms, end_of_stream
        FROM attempt_log_segments
        WHERE stream_id = $1 AND operation_id = $2 FOR UPDATE
        ",
    )
    .bind(stream_id.as_uuid())
    .bind(operation_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn log_segment_metadata_matches(
    row: &sqlx::postgres::PgRow,
    metadata: &LogSegmentMetadata,
) -> Result<bool, StoreError> {
    Ok(row
        .try_get::<Uuid, _>("stream_id")
        .map_err(operation_error)?
        == metadata.stream_id().as_uuid()
        && row
            .try_get::<Uuid, _>("operation_id")
            .map_err(operation_error)?
            == metadata.operation_id().as_uuid()
        && row
            .try_get::<i64, _>("first_sequence")
            .map_err(operation_error)?
            == log_sequence_i64(metadata.first_sequence())?
        && row
            .try_get::<i64, _>("last_sequence")
            .map_err(operation_error)?
            == log_sequence_i64(metadata.last_sequence())?
        && row
            .try_get::<String, _>("object_key")
            .map_err(operation_error)?
            == metadata.object_key().as_str()
        && crate::value::decode_sha256_digest(
            row.try_get("object_digest").map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?
            == metadata.digest()
        && row
            .try_get::<i64, _>("encoded_size_bytes")
            .map_err(operation_error)?
            == size_i64(metadata.encoded_size(), "log segment")?
        && row
            .try_get::<i64, _>("uncompressed_size_bytes")
            .map_err(operation_error)?
            == size_i64(metadata.uncompressed_size(), "log segment")?
        && row
            .try_get::<i64, _>("stored_at_ms")
            .map_err(operation_error)?
            == metadata.stored_at().get()
        && row
            .try_get::<bool, _>("end_of_stream")
            .map_err(operation_error)?
            == metadata.is_end_of_stream())
}

async fn load_locked_log_stream(
    transaction: &mut Transaction<'_, Postgres>,
    stream_id: automata_core::LogStreamId,
) -> Result<sqlx::postgres::PgRow, StoreError> {
    sqlx::query(
        r"
        SELECT attempt_id, runner_session_id, runner_id, runner_session_epoch,
               runner_generation, runner_slot, lease_id, fencing_token, closed_at_ms
        FROM attempt_log_streams WHERE id = $1 FOR UPDATE
        ",
    )
    .bind(stream_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::ImmutableConflict("log stream"))
}

async fn load_log_stream_identity(
    transaction: &mut Transaction<'_, Postgres>,
    stream_id: automata_core::LogStreamId,
) -> Result<sqlx::postgres::PgRow, StoreError> {
    sqlx::query(
        r"
        SELECT attempt_id, runner_session_id, runner_id, runner_session_epoch,
               runner_generation, runner_slot, lease_id, fencing_token, closed_at_ms
        FROM attempt_log_streams WHERE id = $1
        ",
    )
    .bind(stream_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::ImmutableConflict("log stream"))
}

fn decode_stream_fence(row: &sqlx::postgres::PgRow) -> Result<RunnerSessionFence, StoreError> {
    Ok(RunnerSessionFence::new(
        RunnerSessionId::from_uuid(row.try_get("runner_session_id").map_err(operation_error)?),
        RunnerId::from_uuid(row.try_get("runner_id").map_err(operation_error)?),
        decode_generation(row.try_get("runner_generation").map_err(operation_error)?)?,
        decode_epoch(
            row.try_get("runner_session_epoch")
                .map_err(operation_error)?,
        )?,
    ))
}

fn log_stream_matches_active(
    row: &sqlx::postgres::PgRow,
    attempt_id: AttemptId,
    fence: RunnerSessionFence,
    guard: LeaseGuard,
    slot: StableRunnerSlot,
) -> Result<bool, StoreError> {
    Ok(decode_stream_fence(row)? == fence
        && row
            .try_get::<Uuid, _>("attempt_id")
            .map_err(operation_error)?
            == attempt_id.as_uuid()
        && row
            .try_get::<Uuid, _>("lease_id")
            .map_err(operation_error)?
            == guard.lease_id().as_uuid()
        && row
            .try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?
            == fencing_i64(guard.fencing_token())?
        && row
            .try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?
            == i32::from(slot.ordinal()))
}

async fn insert_contiguous_log_metadata(
    transaction: &mut Transaction<'_, Postgres>,
    metadata: &LogSegmentMetadata,
) -> Result<(), StoreError> {
    let prior: Option<i64> = sqlx::query_scalar(
        "SELECT max(last_sequence) FROM attempt_log_segments WHERE stream_id = $1",
    )
    .bind(metadata.stream_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if log_sequence_i64(metadata.first_sequence())?
        != prior.map_or(0, |value| value.saturating_add(1))
    {
        return Err(StoreError::ImmutableConflict("log sequence"));
    }
    sqlx::query(
        r"
        INSERT INTO attempt_log_segments (
            stream_id, operation_id, first_sequence, last_sequence, object_key,
            object_digest, encoded_size_bytes, uncompressed_size_bytes,
            stored_at_ms, end_of_stream
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ",
    )
    .bind(metadata.stream_id().as_uuid())
    .bind(metadata.operation_id().as_uuid())
    .bind(log_sequence_i64(metadata.first_sequence())?)
    .bind(log_sequence_i64(metadata.last_sequence())?)
    .bind(metadata.object_key().as_str())
    .bind(metadata.digest().as_bytes().as_slice())
    .bind(size_i64(metadata.encoded_size(), "log segment")?)
    .bind(size_i64(metadata.uncompressed_size(), "log segment")?)
    .bind(metadata.stored_at().get())
    .bind(metadata.is_end_of_stream())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if metadata.is_end_of_stream() {
        sqlx::query("UPDATE attempt_log_streams SET closed_at_ms = $2 WHERE id = $1")
            .bind(metadata.stream_id().as_uuid())
            .bind(metadata.stored_at().get())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
    }
    Ok(())
}

fn decode_fencing(value: i64) -> Result<FencingToken, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| FencingToken::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid log-stream fencing token"))
}

async fn verify_exact_published_offer(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLeaseResponse,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.changed_at_ms, attempt.lease_expires_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        JOIN job_attempts AS attempt ON attempt.id = publication.attempt_id
        WHERE publication.runner_session_id = $1
          AND publication.attempt_id = $2
          AND publication.runner_id = $3
          AND publication.runner_session_epoch = $4
          AND publication.runner_generation = $5
          AND publication.runner_slot = $6
          AND publication.lease_id = $7
          AND publication.fencing_token = $8
          AND attempt.runner_session_id = publication.runner_session_id
          AND attempt.runner_id = publication.runner_id
          AND attempt.runner_session_epoch = publication.runner_session_epoch
          AND attempt.runner_generation = publication.runner_generation
          AND attempt.runner_slot = publication.runner_slot
          AND attempt.lease_id = publication.lease_id
          AND attempt.fencing_token = publication.fencing_token
        FOR UPDATE OF publication, attempt
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(request.attempt_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptFenceRejected(request.attempt_id()))?;
    let lifecycle = parse_lifecycle(row.try_get("lifecycle").map_err(operation_error)?)
        .map_err(StoreError::from)?;
    if lifecycle != JobLifecycle::Leased {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    if request.observed_at() < changed_at {
        return Err(StoreError::AttemptTimeRegression {
            attempt_id: request.attempt_id(),
            observed_at: request.observed_at(),
            changed_at,
        });
    }
    let expires_at = UnixMillis::new(
        row.try_get("lease_expires_at_ms")
            .map_err(operation_error)?,
    );
    if request.observed_at() >= expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            request.attempt_id(),
        )));
    }
    Ok(())
}

async fn apply_lease_response(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitLeaseResponse,
) -> Result<(), StoreError> {
    let next = match request.action() {
        LeaseResponseAction::Accept => "preparing",
        LeaseResponseAction::Requeue => "queued",
        LeaseResponseAction::Fail => "failed",
    };
    let retain_lease = request.action() == LeaseResponseAction::Accept;
    let requeue = request.action() == LeaseResponseAction::Requeue;
    let fence = request.request().session();
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $9,
            lease_id = CASE WHEN $10 THEN lease_id ELSE NULL END,
            runner_id = CASE WHEN $10 THEN runner_id ELSE NULL END,
            lease_issued_at_ms = CASE WHEN $10 THEN lease_issued_at_ms ELSE NULL END,
            lease_expires_at_ms = CASE WHEN $10 THEN lease_expires_at_ms ELSE NULL END,
            runner_session_id = CASE WHEN $10 THEN runner_session_id ELSE NULL END,
            runner_session_epoch = CASE WHEN $10 THEN runner_session_epoch ELSE NULL END,
            runner_generation = CASE WHEN $10 THEN runner_generation ELSE NULL END,
            runner_slot = CASE WHEN $10 THEN runner_slot ELSE NULL END,
            lease_failures = lease_failures + CASE WHEN $11 THEN 1 ELSE 0 END,
            queued_at_ms = CASE WHEN $11 THEN $12 ELSE queued_at_ms END,
            changed_at_ms = $12
        WHERE id = $1 AND lifecycle = 'leased'
          AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
          AND runner_slot = $8 AND changed_at_ms <= $12
          AND lease_expires_at_ms > $12
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(next)
    .bind(retain_lease)
    .bind(requeue)
    .bind(request.observed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    Ok(())
}

async fn commit_reported_lifecycle(
    transaction: &mut Transaction<'_, Postgres>,
    renewal: crate::RenewLease,
    reported: JobLifecycle,
) -> Result<(), StoreError> {
    let snapshot = super::locked_snapshot(transaction, renewal.attempt_id()).await?;
    super::verify_guard(renewal.attempt_id(), renewal.guard(), &snapshot)?;
    super::verify_assignment(renewal.attempt_id(), renewal.session(), &snapshot)?;
    super::verify_mutation_time(renewal.attempt_id(), renewal.observed_at(), &snapshot)?;
    if snapshot.lifecycle == reported {
        return Ok(());
    }
    snapshot
        .lifecycle
        .validate_transition(reported)
        .map_err(|_| {
            StoreError::Attempt(AttemptStoreError::InvalidTransition {
                attempt_id: renewal.attempt_id(),
                from: snapshot.lifecycle,
                to: reported,
            })
        })?;
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $4, changed_at_ms = $5
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $6 AND runner_session_id = $7
          AND runner_session_epoch = $8 AND runner_generation = $9
          AND changed_at_ms <= $5 AND lease_expires_at_ms > $5
        ",
    )
    .bind(renewal.attempt_id().as_uuid())
    .bind(renewal.guard().lease_id().as_uuid())
    .bind(fencing_i64(renewal.guard().fencing_token())?)
    .bind(lifecycle_name(reported))
    .bind(renewal.observed_at().get())
    .bind(renewal.session().runner_id().as_uuid())
    .bind(renewal.session().session_id().as_uuid())
    .bind(epoch_i64(renewal.session().session_epoch())?)
    .bind(generation_i64(renewal.session().runner_generation())?)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(renewal.attempt_id()));
    }
    Ok(())
}

async fn lock_exact_active_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    fence: RunnerSessionFence,
    guard: LeaseGuard,
    observed_at: UnixMillis,
) -> Result<StableRunnerSlot, StoreError> {
    let row = sqlx::query(
        r"
        SELECT lifecycle, runner_slot, changed_at_ms, lease_expires_at_ms
        FROM job_attempts
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
        FOR UPDATE
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(guard.lease_id().as_uuid())
    .bind(fencing_i64(guard.fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptFenceRejected(attempt_id))?;
    let lifecycle = parse_lifecycle(row.try_get("lifecycle").map_err(operation_error)?)
        .map_err(StoreError::from)?;
    if !matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
            | JobLifecycle::Finalizing
    ) {
        return Err(StoreError::AttemptFenceRejected(attempt_id));
    }
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    if observed_at < changed_at {
        return Err(StoreError::AttemptTimeRegression {
            attempt_id,
            observed_at,
            changed_at,
        });
    }
    let expires_at = UnixMillis::new(
        row.try_get("lease_expires_at_ms")
            .map_err(operation_error)?,
    );
    if observed_at >= expires_at {
        return Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(
            attempt_id,
        )));
    }
    u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| StableRunnerSlot::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid active runner slot"))
}

async fn insert_terminal_result(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerTerminalResult,
    slot: StableRunnerSlot,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    let rows = sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, result_schema, result_size_bytes,
            result_digest, result_object_key, conclusion, completed_at_ms, committed_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(i32::from(slot.ordinal()))
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .bind(i32::from(request.schema().get()))
    .bind(size_i64(request.encoded_size(), "terminal result")?)
    .bind(request.digest().as_bytes().as_slice())
    .bind(request.object_key().as_str())
    .bind(conclusion_name(request.conclusion()))
    .bind(request.completed_at().get())
    .bind(request.committed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::ImmutableConflict("terminal result"));
    }
    Ok(())
}

async fn conclude_terminal_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerTerminalResult,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    let lifecycle = terminal_lifecycle(request.conclusion());
    let rows = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $8, lease_id = NULL, runner_id = NULL,
            lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
            runner_session_id = NULL, runner_session_epoch = NULL,
            runner_generation = NULL, runner_slot = NULL, changed_at_ms = $9
        WHERE id = $1 AND lease_id = $2 AND fencing_token = $3
          AND runner_id = $4 AND runner_session_id = $5
          AND runner_session_epoch = $6 AND runner_generation = $7
          AND lifecycle IN ('leased','preparing','running','cancelling','finalizing')
          AND runner_slot IS NOT NULL AND changed_at_ms <= $9
          AND lease_expires_at_ms > $9
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.guard().lease_id().as_uuid())
    .bind(fencing_i64(request.guard().fencing_token())?)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(generation_i64(fence.runner_generation())?)
    .bind(lifecycle_name(lifecycle))
    .bind(request.committed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    Ok(())
}

async fn append_runner_log_segment(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerLogSegment,
    slot: StableRunnerSlot,
) -> Result<(), StoreError> {
    ensure_runner_log_stream(transaction, request, slot).await?;
    let prior: Option<i64> = sqlx::query_scalar(
        "SELECT max(last_sequence) FROM attempt_log_segments WHERE stream_id = $1",
    )
    .bind(request.stream_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let expected = prior.map_or(0, |value| value.saturating_add(1));
    if log_sequence_i64(request.first_sequence())? != expected {
        return Err(StoreError::ImmutableConflict("log sequence"));
    }
    sqlx::query(
        r"
        INSERT INTO attempt_log_segments (
            stream_id, operation_id, first_sequence, last_sequence, object_key,
            object_digest, encoded_size_bytes, uncompressed_size_bytes,
            stored_at_ms, end_of_stream
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ",
    )
    .bind(request.stream_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .bind(log_sequence_i64(request.first_sequence())?)
    .bind(log_sequence_i64(request.last_sequence())?)
    .bind(request.object_key().as_str())
    .bind(request.digest().as_bytes().as_slice())
    .bind(size_i64(request.encoded_size(), "log segment")?)
    .bind(size_i64(request.uncompressed_size(), "log segment")?)
    .bind(request.stored_at().get())
    .bind(request.is_end_of_stream())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if request.is_end_of_stream() {
        sqlx::query("UPDATE attempt_log_streams SET closed_at_ms = $2 WHERE id = $1")
            .bind(request.stream_id().as_uuid())
            .bind(request.stored_at().get())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
    }
    Ok(())
}

async fn ensure_runner_log_stream(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CommitRunnerLogSegment,
    slot: StableRunnerSlot,
) -> Result<(), StoreError> {
    let fence = request.request().session();
    let stream = sqlx::query(
        r"
        SELECT attempt_id, runner_session_id, runner_id, runner_session_epoch,
               runner_generation, runner_slot, lease_id, fencing_token,
               log_schema, closed_at_ms
        FROM attempt_log_streams WHERE id = $1 FOR UPDATE
        ",
    )
    .bind(request.stream_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = stream {
        let exact = row
            .try_get::<Uuid, _>("attempt_id")
            .map_err(operation_error)?
            == request.attempt_id().as_uuid()
            && row
                .try_get::<Uuid, _>("runner_session_id")
                .map_err(operation_error)?
                == fence.session_id().as_uuid()
            && row
                .try_get::<Uuid, _>("runner_id")
                .map_err(operation_error)?
                == fence.runner_id().as_uuid()
            && row
                .try_get::<i64, _>("runner_session_epoch")
                .map_err(operation_error)?
                == epoch_i64(fence.session_epoch())?
            && row
                .try_get::<i64, _>("runner_generation")
                .map_err(operation_error)?
                == generation_i64(fence.runner_generation())?
            && row
                .try_get::<i32, _>("runner_slot")
                .map_err(operation_error)?
                == i32::from(slot.ordinal())
            && row
                .try_get::<Uuid, _>("lease_id")
                .map_err(operation_error)?
                == request.guard().lease_id().as_uuid()
            && row
                .try_get::<i64, _>("fencing_token")
                .map_err(operation_error)?
                == fencing_i64(request.guard().fencing_token())?
            && row
                .try_get::<i32, _>("log_schema")
                .map_err(operation_error)?
                == i32::from(request.schema().get())
            && row
                .try_get::<Option<i64>, _>("closed_at_ms")
                .map_err(operation_error)?
                .is_none();
        if !exact {
            return Err(StoreError::ImmutableConflict("log stream"));
        }
    } else {
        if request.first_sequence() != LogSequence::new(0) {
            return Err(StoreError::ImmutableConflict("log sequence"));
        }
        sqlx::query(
            r"
            INSERT INTO attempt_log_streams (
                id, attempt_id, runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, runner_slot, lease_id,
                fencing_token, log_schema, opened_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ",
        )
        .bind(request.stream_id().as_uuid())
        .bind(request.attempt_id().as_uuid())
        .bind(fence.session_id().as_uuid())
        .bind(request.request().operation_id().as_uuid())
        .bind(fence.runner_id().as_uuid())
        .bind(epoch_i64(fence.session_epoch())?)
        .bind(generation_i64(fence.runner_generation())?)
        .bind(i32::from(slot.ordinal()))
        .bind(request.guard().lease_id().as_uuid())
        .bind(fencing_i64(request.guard().fencing_token())?)
        .bind(i32::from(request.schema().get()))
        .bind(request.stored_at().get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

const fn conclusion_name(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "success",
        JobConclusion::Failure => "failure",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed_out",
        JobConclusion::Skipped => "skipped",
    }
}

const fn terminal_lifecycle(conclusion: JobConclusion) -> JobLifecycle {
    match conclusion {
        JobConclusion::Success => JobLifecycle::Succeeded,
        JobConclusion::Failure => JobLifecycle::Failed,
        JobConclusion::Cancelled => JobLifecycle::Cancelled,
        JobConclusion::TimedOut => JobLifecycle::TimedOut,
        JobConclusion::Skipped => JobLifecycle::Skipped,
    }
}

fn fencing_i64(value: FencingToken) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("fencing token exceeds PostgreSQL BIGINT"))
}

fn log_sequence_i64(value: LogSequence) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("log sequence exceeds PostgreSQL BIGINT"))
}

fn size_i64(value: u64, kind: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::corrupt_data(format!("{kind} size exceeds PostgreSQL BIGINT")))
}

async fn enqueue_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    command: EnqueueRunnerCommand,
) -> Result<DurableRunnerCommand, StoreError> {
    lock_live_routing(transaction, command.session())
        .await?
        .require_online(command.session())?;
    enqueue_locked_command_in_transaction(transaction, command).await
}

/// Enqueues a cancellation against the exact session recorded on an active
/// attempt, including a session that disconnected after receiving the lease.
/// The caller must hold the attempt's concurrency lock before entering this
/// function, preserving the global group -> session -> attempt lock order.
pub(super) async fn enqueue_cancellation_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    command: EnqueueRunnerCommand,
) -> Result<DurableRunnerCommand, StoreError> {
    lock_exact_command_session(transaction, command.session()).await?;
    enqueue_locked_command_in_transaction(transaction, command).await
}

async fn lock_exact_command_session(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
) -> Result<(), StoreError> {
    let exists = sqlx::query_scalar::<_, bool>(
        r"
        SELECT true
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        FOR UPDATE
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(session.runner_id().as_uuid())
    .bind(generation_i64(session.runner_generation())?)
    .bind(epoch_i64(session.session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .unwrap_or(false);
    if !exists {
        return Err(StoreError::fence_rejected(session.session_id()));
    }
    Ok(())
}

async fn enqueue_locked_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    command: EnqueueRunnerCommand,
) -> Result<DurableRunnerCommand, StoreError> {
    let existing = sqlx::query(
        r"
        SELECT command_sequence, operation_id, command_kind, command_schema,
               command_digest, command_payload, created_at_ms
        FROM runner_command_outbox
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(command.session().session_id().as_uuid())
    .bind(command.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(row) = existing {
        let durable = decode_outbox_command(&row, command.session(), true)?;
        if durable.request() != &command {
            return Err(StoreError::OperationConflict {
                session_id: command.session().session_id(),
                operation_id: command.operation_id(),
            });
        }
        return Ok(durable);
    }
    let sequence_value: Option<i64> = sqlx::query_scalar(
        r"
        UPDATE runner_sessions
        SET last_command_sequence = last_command_sequence + 1
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
          AND last_command_sequence < 9223372036854775807
        RETURNING last_command_sequence
        ",
    )
    .bind(command.session().session_id().as_uuid())
    .bind(command.session().runner_id().as_uuid())
    .bind(generation_i64(command.session().runner_generation())?)
    .bind(epoch_i64(command.session().session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let sequence_value = sequence_value.ok_or(StoreError::CommandSequenceExhausted(
        command.session().session_id(),
    ))?;
    let sequence = decode_sequence(sequence_value)?;
    sqlx::query(
        r"
        INSERT INTO runner_command_outbox (
            runner_session_id, command_sequence, operation_id, runner_id,
            runner_session_epoch, runner_generation, command_kind,
            command_schema, command_digest, command_payload, created_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ",
    )
    .bind(command.session().session_id().as_uuid())
    .bind(sequence_i64(sequence)?)
    .bind(command.operation_id().as_uuid())
    .bind(command.session().runner_id().as_uuid())
    .bind(epoch_i64(command.session().session_epoch())?)
    .bind(generation_i64(command.session().runner_generation())?)
    .bind(command.kind().as_str())
    .bind(i32::from(command.payload().schema().get()))
    .bind(command.payload().digest().as_bytes().as_slice())
    .bind(command.payload().bytes())
    .bind(command.created_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(DurableRunnerCommand::new(command, sequence, false))
}

fn decode_outbox_command(
    row: &sqlx::postgres::PgRow,
    session: RunnerSessionFence,
    replayed: bool,
) -> Result<DurableRunnerCommand, StoreError> {
    let sequence = decode_sequence(row.try_get("command_sequence").map_err(operation_error)?)?;
    let operation_id =
        OperationId::from_uuid(row.try_get("operation_id").map_err(operation_error)?);
    let kind = RunnerOperationKind::new(
        row.try_get::<String, _>("command_kind")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let schema = decode_schema(row.try_get("command_schema").map_err(operation_error)?)?;
    let bytes: Vec<u8> = row.try_get("command_payload").map_err(operation_error)?;
    let payload = RunnerCommandPayload::new(schema, bytes)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let stored_digest =
        crate::value::decode_sha256_digest(row.try_get("command_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if stored_digest != payload.digest() {
        return Err(StoreError::corrupt_data("runner command digest mismatch"));
    }
    let created_at = UnixMillis::new(row.try_get("created_at_ms").map_err(operation_error)?);
    Ok(DurableRunnerCommand::new(
        EnqueueRunnerCommand::new(session, operation_id, kind, payload, created_at),
        sequence,
        replayed,
    ))
}

async fn load_generic_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RunnerOperationRequest,
    replayed: bool,
) -> Result<Option<RunnerOperationReceipt>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT operation_kind, request_digest, response_schema,
               response_digest, response_payload, committed_at_ms
        FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref()
        .map(|row| decode_generic_receipt(row, request, replayed))
        .transpose()
}

async fn insert_generic_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: RunnerOperationRequest,
    response: RunnerOperationResponse,
    committed_at: UnixMillis,
) -> Result<RunnerOperationReceipt, StoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO runner_rpc_receipts (
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, response_schema, response_digest,
            response_payload, committed_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (runner_session_id, operation_id) DO NOTHING
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.session().runner_id().as_uuid())
    .bind(epoch_i64(request.session().session_epoch())?)
    .bind(generation_i64(request.session().runner_generation())?)
    .bind(request.kind().as_str())
    .bind(request.request_digest().as_bytes().as_slice())
    .bind(i32::from(response.schema().get()))
    .bind(response.digest().as_bytes().as_slice())
    .bind(response.payload())
    .bind(committed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if inserted == 1 {
        return Ok(RunnerOperationReceipt::new(
            request,
            response,
            committed_at,
            false,
        ));
    }
    load_generic_receipt(transaction, &request, true)
        .await?
        .ok_or_else(|| StoreError::corrupt_data("conflicting receipt disappeared"))
}

async fn load_lease_offer_publication(
    transaction: &mut Transaction<'_, Postgres>,
    expected: &LeaseOfferClaim,
    expected_command: Option<&EnqueueRunnerCommand>,
    replayed: bool,
) -> Result<Option<PublishedLeaseOffer>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT publication.request_operation_id, publication.runner_id,
               publication.runner_session_epoch, publication.runner_generation,
               publication.operation_kind, publication.request_digest,
               publication.protocol_version, publication.runner_slot,
               publication.attempt_id, publication.lease_id,
               publication.fencing_token, publication.lease_issued_at_ms,
               publication.lease_expires_at_ms, publication.job_id,
               publication.run_id, publication.job_ir_schema,
               publication.job_ir_size_bytes, publication.job_ir_digest,
               publication.job_ir_object_key,
               publication.created_at_ms AS publication_created_at_ms,
               command.command_sequence, command.operation_id,
               command.command_kind, command.command_schema,
               command.command_digest, command.command_payload,
               command.created_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        WHERE publication.runner_session_id = $1
          AND publication.request_operation_id = $2
        FOR UPDATE OF publication, command
        ",
    )
    .bind(expected.request().session().session_id().as_uuid())
    .bind(expected.request().operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    decode_lease_offer_publication(&row, expected, expected_command, replayed).map(Some)
}

async fn load_lease_offer_publication_by_command(
    transaction: &mut Transaction<'_, Postgres>,
    identity: LeaseOfferCommandIdentity,
) -> Result<Option<PublishedLeaseOffer>, StoreError> {
    let rows = sqlx::query(
        r"
        SELECT publication.request_operation_id, publication.runner_id,
               publication.runner_session_epoch, publication.runner_generation,
               publication.operation_kind, publication.request_digest,
               publication.protocol_version, publication.runner_slot,
               publication.attempt_id, publication.lease_id,
               publication.fencing_token, publication.lease_issued_at_ms,
               publication.lease_expires_at_ms, publication.job_id,
               publication.run_id, publication.job_ir_schema,
               publication.job_ir_size_bytes, publication.job_ir_digest,
               publication.job_ir_object_key,
               publication.created_at_ms AS publication_created_at_ms,
               command.command_sequence, command.operation_id,
               command.command_kind, command.command_schema,
               command.command_digest, command.command_payload,
               command.created_at_ms
        FROM runner_lease_offer_publications AS publication
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = publication.runner_session_id
         AND command.command_sequence = publication.command_sequence
        WHERE publication.runner_session_id = $1
          AND publication.command_sequence = $2
        LIMIT 2
        FOR UPDATE OF publication, command
        ",
    )
    .bind(identity.session().session_id().as_uuid())
    .bind(sequence_i64(identity.sequence())?)
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Ok(None)
        } else {
            Err(StoreError::corrupt_data(
                "multiple lease-offer publications reference one command",
            ))
        };
    };
    let publication = decode_lease_offer_publication_row(row, identity.session(), true)?;
    if publication.command().sequence() != identity.sequence()
        || publication.command().request().operation_id() != identity.operation_id()
    {
        return Err(StoreError::corrupt_data(
            "lease-offer publication resolved a different command identity",
        ));
    }
    Ok(Some(publication))
}

fn decode_lease_offer_publication(
    row: &sqlx::postgres::PgRow,
    expected: &LeaseOfferClaim,
    expected_command: Option<&EnqueueRunnerCommand>,
    replayed: bool,
) -> Result<PublishedLeaseOffer, StoreError> {
    let publication =
        decode_lease_offer_publication_row(row, expected.request().session(), replayed)?;
    let stable_command_matches = expected_command.is_none_or(|expected_command| {
        publication.command().request().session() == expected_command.session()
            && publication.command().request().kind() == expected_command.kind()
            && publication.command().request().payload() == expected_command.payload()
    });
    if publication.request() != expected.request()
        || publication.protocol_version() != expected.protocol_version()
        || publication.slot() != expected.slot()
        || publication.lease() != expected.lease()
        || publication.job_ir() != expected.job_ir()
        || !stable_command_matches
    {
        return Err(StoreError::OperationConflict {
            session_id: expected.request().session().session_id(),
            operation_id: expected.request().operation_id(),
        });
    }
    Ok(publication)
}

fn decode_lease_offer_publication_row(
    row: &sqlx::postgres::PgRow,
    session: RunnerSessionFence,
    replayed: bool,
) -> Result<PublishedLeaseOffer, StoreError> {
    let publication_runner_id =
        RunnerId::from_uuid(row.try_get("runner_id").map_err(operation_error)?);
    let publication_epoch = decode_epoch(
        row.try_get("runner_session_epoch")
            .map_err(operation_error)?,
    )?;
    let publication_generation =
        decode_generation(row.try_get("runner_generation").map_err(operation_error)?)?;
    if publication_runner_id != session.runner_id()
        || publication_epoch != session.session_epoch()
        || publication_generation != session.runner_generation()
    {
        return Err(StoreError::corrupt_data(
            "lease-offer publication has a mismatched session fence",
        ));
    }
    let request_operation_id = OperationId::from_uuid(
        row.try_get("request_operation_id")
            .map_err(operation_error)?,
    );
    let kind = RunnerOperationKind::new(
        row.try_get::<String, _>("operation_kind")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if kind.as_str() != LEASE_RPC_OPERATION_KIND {
        return Err(StoreError::corrupt_data(
            "lease-offer publication has an invalid request kind",
        ));
    }
    let digest =
        crate::value::decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let request = RunnerOperationRequest::new(session, request_operation_id, kind, digest);
    let protocol = decode_protocol(row.try_get("protocol_version").map_err(operation_error)?)?;
    let slot = u16::try_from(
        row.try_get::<i32, _>("runner_slot")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| StableRunnerSlot::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid lease-offer runner slot"))?;
    let fencing = u64::try_from(
        row.try_get::<i64, _>("fencing_token")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| FencingToken::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid lease-offer fencing token"))?;
    let lease = Lease::new(
        automata_core::LeaseId::from_uuid(row.try_get("lease_id").map_err(operation_error)?),
        AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
        request.session().runner_id(),
        fencing,
        UnixMillis::new(row.try_get("lease_issued_at_ms").map_err(operation_error)?),
        UnixMillis::new(
            row.try_get("lease_expires_at_ms")
                .map_err(operation_error)?,
        ),
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let job_ir = JobIrMetadata::new(
        JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?),
        RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?,
        u64::try_from(
            row.try_get::<i64, _>("job_ir_size_bytes")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative lease-offer JobIR size"))?,
        crate::value::decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
        ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let command = decode_outbox_command(row, request.session(), replayed)?;
    let publication_created_at = UnixMillis::new(
        row.try_get("publication_created_at_ms")
            .map_err(operation_error)?,
    );
    if publication_created_at != command.request().created_at() {
        return Err(StoreError::corrupt_data(
            "lease-offer publication and command creation times disagree",
        ));
    }
    Ok(PublishedLeaseOffer::new(
        request, protocol, slot, lease, job_ir, command,
    ))
}

async fn lock_exact_lease_offer_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &LeaseOfferClaim,
    routing: &LockedRouting,
) -> Result<(), StoreError> {
    let conflict = || StoreError::OperationConflict {
        session_id: request.request().session().session_id(),
        operation_id: request.request().operation_id(),
    };
    if request.request().kind().as_str() != LEASE_RPC_OPERATION_KIND
        || request.protocol_version() != routing.protocol_version
        || request.job_ir().version() != routing.job_ir_version
        || !routing.slots.contains(request.slot())
    {
        return Err(conflict());
    }
    let head = sqlx::query(
        r"
        SELECT operation_id, request_digest, acknowledges_operation_id
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND runner_slot = $2
        FOR UPDATE
        ",
    )
    .bind(request.request().session().session_id().as_uuid())
    .bind(i32::from(request.slot().ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(conflict)?;
    let operation_id =
        OperationId::from_uuid(head.try_get("operation_id").map_err(operation_error)?);
    let request_digest = crate::value::decode_sha256_digest(
        head.try_get("request_digest").map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let predecessor = head
        .try_get::<Option<Uuid>, _>("acknowledges_operation_id")
        .map_err(operation_error)?
        .map(OperationId::from_uuid);
    if operation_id != request.request().operation_id()
        || request_digest != request.request().request_digest()
    {
        return Err(conflict());
    }
    let key = if let Some(predecessor) = predecessor {
        LeaseRequestKey::successor(
            request.request().session(),
            operation_id,
            request.slot(),
            predecessor,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?
    } else {
        LeaseRequestKey::first(request.request().session(), operation_id, request.slot())
    };
    let receipt = claim_receipt_row(transaction, key)
        .await?
        .ok_or_else(conflict)
        .and_then(|row| decode_claim_receipt(&row, key, true))?;
    let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
        return Err(conflict());
    };
    if claimed.assignment() != AttemptAssignment::new(request.request().session(), request.slot())
        || claimed.lease() != request.lease()
        || claimed.job_ir() != request.job_ir()
    {
        return Err(conflict());
    }
    Ok(())
}

/// Locks the attempt row even when the repository-level concurrency advisory is absent.
async fn lock_publishable_lease_offer_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &LeaseOfferClaim,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle IN (
                   'leased', 'preparing', 'running', 'cancelling', 'finalizing'
               ) AS lifecycle_publishable,
               COALESCE(attempt.lease_id = $4
           AND attempt.fencing_token = $5
           AND attempt.runner_id = $6
           AND attempt.runner_session_id = $7
           AND attempt.runner_session_epoch = $8
           AND attempt.runner_generation = $9
           AND attempt.runner_slot = $10
           AND attempt.lease_issued_at_ms = $11
           AND attempt.lease_expires_at_ms = $12, FALSE) AS fence_matches,
               COALESCE(attempt.job_id = $2
           AND job.run_id = $3
           AND job.job_ir_schema = $13
           AND job.job_ir_size_bytes = $14
           AND job.job_ir_digest = $15
           AND job.job_ir_object_key = $16, FALSE)
               AS metadata_matches
        FROM job_attempts AS attempt
        LEFT JOIN jobs AS job ON job.id = attempt.job_id
        WHERE attempt.id = $1
        FOR UPDATE OF attempt
        ",
    )
    .bind(request.lease().attempt_id().as_uuid())
    .bind(request.job_ir().job_id().as_uuid())
    .bind(request.job_ir().run_id().as_uuid())
    .bind(request.lease().lease_id().as_uuid())
    .bind(
        i64::try_from(request.lease().fencing_token().get()).map_err(|_| {
            StoreError::corrupt_data("lease-offer fencing token exceeds PostgreSQL BIGINT")
        })?,
    )
    .bind(request.request().session().runner_id().as_uuid())
    .bind(request.request().session().session_id().as_uuid())
    .bind(epoch_i64(request.request().session().session_epoch())?)
    .bind(generation_i64(
        request.request().session().runner_generation(),
    )?)
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.lease().issued_at().get())
    .bind(request.lease().expires_at().get())
    .bind(i32::from(request.job_ir().version().get()))
    .bind(i64::try_from(request.job_ir().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("lease-offer JobIR size exceeds PostgreSQL BIGINT")
    })?)
    .bind(request.job_ir().digest().as_bytes().as_slice())
    .bind(request.job_ir().object_key().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let lifecycle_publishable = row
        .try_get::<bool, _>("lifecycle_publishable")
        .map_err(operation_error)?;
    let fence_matches = row
        .try_get::<bool, _>("fence_matches")
        .map_err(operation_error)?;
    if !lifecycle_publishable || !fence_matches {
        return Ok(false);
    }
    let metadata_matches = row
        .try_get::<bool, _>("metadata_matches")
        .map_err(operation_error)?;
    if !metadata_matches {
        return Err(StoreError::corrupt_data(
            "live lease-offer fence disagrees with immutable JobIR metadata",
        ));
    }
    Ok(true)
}

async fn insert_lease_offer_publication(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PublishLeaseOffer,
    sequence: CommandSequence,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        INSERT INTO runner_lease_offer_publications (
            runner_session_id, request_operation_id, runner_id,
            runner_session_epoch, runner_generation, operation_kind,
            request_digest, protocol_version, runner_slot,
            attempt_id, lease_id, fencing_token, lease_issued_at_ms,
            lease_expires_at_ms, job_id, run_id, job_ir_schema,
            job_ir_size_bytes, job_ir_digest, job_ir_object_key,
            command_sequence, created_at_ms
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
        )
        ",
    )
    .bind(request.request().session().session_id().as_uuid())
    .bind(request.request().operation_id().as_uuid())
    .bind(request.request().session().runner_id().as_uuid())
    .bind(epoch_i64(request.request().session().session_epoch())?)
    .bind(generation_i64(
        request.request().session().runner_generation(),
    )?)
    .bind(request.request().kind().as_str())
    .bind(request.request().request_digest().as_bytes().as_slice())
    .bind(protocol_i32(request.protocol_version()))
    .bind(i32::from(request.slot().ordinal()))
    .bind(request.lease().attempt_id().as_uuid())
    .bind(request.lease().lease_id().as_uuid())
    .bind(
        i64::try_from(request.lease().fencing_token().get()).map_err(|_| {
            StoreError::corrupt_data("lease-offer fencing token exceeds PostgreSQL BIGINT")
        })?,
    )
    .bind(request.lease().issued_at().get())
    .bind(request.lease().expires_at().get())
    .bind(request.job_ir().job_id().as_uuid())
    .bind(request.job_ir().run_id().as_uuid())
    .bind(i32::from(request.job_ir().version().get()))
    .bind(i64::try_from(request.job_ir().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("lease-offer JobIR size exceeds PostgreSQL BIGINT")
    })?)
    .bind(request.job_ir().digest().as_bytes().as_slice())
    .bind(request.job_ir().object_key().as_str())
    .bind(sequence_i64(sequence)?)
    .bind(request.command().created_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

fn decode_generic_receipt(
    row: &sqlx::postgres::PgRow,
    expected: &RunnerOperationRequest,
    replayed: bool,
) -> Result<RunnerOperationReceipt, StoreError> {
    let kind: &str = row.try_get("operation_kind").map_err(operation_error)?;
    let digest =
        crate::value::decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if kind != expected.kind().as_str() || digest != expected.request_digest() {
        return Err(StoreError::OperationConflict {
            session_id: expected.session().session_id(),
            operation_id: expected.operation_id(),
        });
    }
    let schema = decode_schema(row.try_get("response_schema").map_err(operation_error)?)?;
    let response = RunnerOperationResponse::new(
        schema,
        row.try_get("response_payload").map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let stored_response_digest = crate::value::decode_sha256_digest(
        row.try_get("response_digest").map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if stored_response_digest != response.digest() {
        return Err(StoreError::corrupt_data(
            "runner operation response digest mismatch",
        ));
    }
    Ok(RunnerOperationReceipt::new(
        expected.clone(),
        response,
        UnixMillis::new(row.try_get("committed_at_ms").map_err(operation_error)?),
        replayed,
    ))
}

fn lease_request_conflict(request: LeaseRequestKey) -> StoreError {
    StoreError::OperationConflict {
        session_id: request.session().session_id(),
        operation_id: request.operation_id(),
    }
}

fn map_lease_head_write_error(error: sqlx::Error, request: LeaseRequestKey) -> StoreError {
    if matches!(&error, sqlx::Error::Database(database) if database.is_unique_violation()) {
        lease_request_conflict(request)
    } else {
        operation_error(error)
    }
}

fn lease_rpc_operation_request(
    request: BeginLeaseRequest,
) -> Result<RunnerOperationRequest, StoreError> {
    let key = request.request_key();
    let kind = RunnerOperationKind::new(LEASE_RPC_OPERATION_KIND)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(RunnerOperationRequest::new(
        key.session(),
        key.operation_id(),
        kind,
        request.request_digest(),
    ))
}

async fn load_lease_rpc_response(
    transaction: &mut Transaction<'_, Postgres>,
    request: BeginLeaseRequest,
    replayed: bool,
) -> Result<Option<RunnerOperationResponse>, StoreError> {
    let operation = lease_rpc_operation_request(request)?;
    let row = sqlx::query(
        r"
        SELECT operation_kind, request_digest, response_schema,
               response_digest, response_payload, committed_at_ms
        FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(operation.session().session_id().as_uuid())
    .bind(operation.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref()
        .map(|row| decode_generic_receipt(row, &operation, replayed))
        .transpose()
        .map(|receipt| receipt.map(|receipt| receipt.response().clone()))
}

async fn lock_current_lease_request_head(
    transaction: &mut Transaction<'_, Postgres>,
    request: LeaseRequestKey,
    expected_rpc_digest: Option<Sha256Digest>,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT operation_id, request_digest, acknowledges_operation_id
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND runner_slot = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(i32::from(request.slot().ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| lease_request_conflict(request))?;
    let operation_id =
        OperationId::from_uuid(row.try_get("operation_id").map_err(operation_error)?);
    let predecessor = row
        .try_get::<Option<Uuid>, _>("acknowledges_operation_id")
        .map_err(operation_error)?
        .map(OperationId::from_uuid);
    let digest =
        crate::value::decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if operation_id != request.operation_id()
        || predecessor != request.acknowledges_operation_id()
        || expected_rpc_digest.is_some_and(|expected| expected != digest)
    {
        return Err(lease_request_conflict(request));
    }
    Ok(())
}

async fn lock_current_lease_rpc_operation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RunnerOperationRequest,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT request_digest
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::OperationConflict {
        session_id: request.session().session_id(),
        operation_id: request.operation_id(),
    })?;
    let digest =
        crate::value::decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if digest != request.request_digest() {
        return Err(StoreError::OperationConflict {
            session_id: request.session().session_id(),
            operation_id: request.operation_id(),
        });
    }
    Ok(())
}

async fn load_cancellation(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<Option<CancellationIntent>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT cancellation.operation_id AS cancellation_operation_id,
               cancellation.requested_by, cancellation.reason,
               cancellation.requested_at_ms, cancellation.acknowledged_at_ms,
               cancellation.delivery_session_id,
               cancellation.delivery_command_sequence,
               command.operation_id, command.command_kind, command.command_schema,
               command.command_digest, command.command_payload, command.created_at_ms,
               session.runner_id, session.runner_generation, session.session_epoch,
               session.protocol_version AS delivery_protocol_version,
               command.command_sequence
        FROM attempt_cancellation_intents AS cancellation
        LEFT JOIN runner_command_outbox AS command
          ON command.runner_session_id = cancellation.delivery_session_id
         AND command.command_sequence = cancellation.delivery_command_sequence
        LEFT JOIN runner_sessions AS session ON session.id = command.runner_session_id
        WHERE cancellation.attempt_id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let operation_id = OperationId::from_uuid(
        row.try_get("cancellation_operation_id")
            .map_err(operation_error)?,
    );
    let actor = CancellationActor::new(
        row.try_get::<String, _>("requested_by")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let reason = row
        .try_get::<Option<String>, _>("reason")
        .map_err(operation_error)?
        .map(CancellationReason::new)
        .transpose()
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let requested_at = UnixMillis::new(row.try_get("requested_at_ms").map_err(operation_error)?);
    let acknowledged_at = row
        .try_get::<Option<i64>, _>("acknowledged_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let delivery =
        decode_loaded_cancellation_delivery(&row, attempt_id, reason.as_ref(), requested_at)?;
    let mut request =
        RequestCancellation::new(operation_id, attempt_id, actor, reason, requested_at);
    if let Some(delivery) = &delivery {
        request = request.with_delivery(delivery.request().clone());
    }
    CancellationIntent::try_new(request, acknowledged_at, false, delivery)
        .map(Some)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_loaded_cancellation_delivery(
    row: &sqlx::postgres::PgRow,
    attempt_id: AttemptId,
    reason: Option<&CancellationReason>,
    requested_at: UnixMillis,
) -> Result<Option<DurableRunnerCommand>, StoreError> {
    let Some(session_id) = row
        .try_get::<Option<Uuid>, _>("delivery_session_id")
        .map_err(operation_error)?
    else {
        return Ok(None);
    };
    let runner_id = RunnerId::from_uuid(
        row.try_get::<Option<Uuid>, _>("runner_id")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery runner missing"))?,
    );
    let generation = decode_generation(
        row.try_get::<Option<i64>, _>("runner_generation")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery generation missing"))?,
    )?;
    let epoch = decode_epoch(
        row.try_get::<Option<i64>, _>("session_epoch")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery epoch missing"))?,
    )?;
    let fence = RunnerSessionFence::new(
        RunnerSessionId::from_uuid(session_id),
        runner_id,
        generation,
        epoch,
    );
    let durable = decode_outbox_command(row, fence, false)?;
    let protocol = decode_protocol(
        row.try_get::<Option<i32>, _>("delivery_protocol_version")
            .map_err(operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("cancellation delivery protocol missing"))?,
    )?;
    validate_loaded_cancel_job(&durable, attempt_id, reason, requested_at, protocol)?;
    Ok(Some(durable))
}

fn validate_loaded_cancel_job(
    delivery: &DurableRunnerCommand,
    attempt_id: AttemptId,
    reason: Option<&CancellationReason>,
    requested_at: UnixMillis,
    protocol: RunnerProtocolVersion,
) -> Result<(), StoreError> {
    let request = delivery.request();
    let payload = CancelJobCommandPayload::decode_json(request.payload().bytes())
        .map_err(|_| StoreError::corrupt_data("invalid durable cancellation command"))?;
    let expected_reason = reason.map_or(DEFAULT_CANCELLATION_REASON, CancellationReason::as_str);
    if request.kind().as_str() != CANCEL_JOB_COMMAND_KIND
        || request.payload().schema().get() != CANCEL_JOB_COMMAND_SCHEMA
        || request.created_at() != requested_at
        || payload.attempt_id() != attempt_id
        || payload.protocol_version() != protocol.get()
        || payload.reason() != expected_reason
        || payload.requested_at() != requested_at
    {
        return Err(StoreError::corrupt_data(
            "durable cancellation command does not match its intent",
        ));
    }
    Ok(())
}

fn same_cancellation_request(left: &RequestCancellation, right: &RequestCancellation) -> bool {
    left.operation_id() == right.operation_id()
        && left.attempt_id() == right.attempt_id()
        && left.actor() == right.actor()
        && left.reason() == right.reason()
        && left.requested_at() == right.requested_at()
        && left.delivery() == right.delivery()
}

fn lifecycle_is_active(lifecycle: JobLifecycle) -> bool {
    matches!(
        lifecycle,
        JobLifecycle::Leased
            | JobLifecycle::Preparing
            | JobLifecycle::Running
            | JobLifecycle::Cancelling
            | JobLifecycle::Finalizing
    )
}

async fn acknowledge_cancellations_through(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    cursor: CommandCursor,
    acknowledged_at: UnixMillis,
) -> Result<(), StoreError> {
    let Some(sequence) = cursor.acknowledged_through() else {
        return Ok(());
    };
    sqlx::query(
        r"
        UPDATE attempt_cancellation_intents
        SET acknowledged_at_ms = $3
        WHERE delivery_session_id = $1
          AND delivery_command_sequence <= $2
          AND acknowledged_at_ms IS NULL
          AND requested_at_ms <= $3
        ",
    )
    .bind(session.session_id().as_uuid())
    .bind(sequence_i64(sequence)?)
    .bind(acknowledged_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn close_cancellation_from_result(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
    acknowledged_at: UnixMillis,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        UPDATE attempt_cancellation_intents
        SET acknowledged_at_ms = $2
        WHERE attempt_id = $1 AND acknowledged_at_ms IS NULL
          AND requested_at_ms <= $2
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(acknowledged_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

fn decode_optional_attempt_session(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<RunnerSessionFence>, StoreError> {
    let runner_id: Option<Uuid> = row.try_get("runner_id").map_err(operation_error)?;
    let session_id: Option<Uuid> = row.try_get("runner_session_id").map_err(operation_error)?;
    let epoch: Option<i64> = row
        .try_get("runner_session_epoch")
        .map_err(operation_error)?;
    let generation: Option<i64> = row.try_get("runner_generation").map_err(operation_error)?;
    let slot: Option<i32> = row.try_get("runner_slot").map_err(operation_error)?;
    match (runner_id, session_id, epoch, generation, slot) {
        (None, None, None, None, None) => Ok(None),
        (Some(runner_id), Some(session_id), Some(epoch), Some(generation), Some(slot)) => {
            let slot = u16::try_from(slot)
                .ok()
                .and_then(|value| StableRunnerSlot::new(value).ok())
                .ok_or_else(|| StoreError::corrupt_data("invalid attempt runner slot"))?;
            let _ = slot;
            Ok(Some(RunnerSessionFence::new(
                RunnerSessionId::from_uuid(session_id),
                RunnerId::from_uuid(runner_id),
                decode_generation(generation)?,
                decode_epoch(epoch)?,
            )))
        }
        _ => Err(StoreError::corrupt_data(
            "partial active attempt session assignment",
        )),
    }
}

#[async_trait]
impl RunnerClaimRepository for PostgresStore {
    async fn lookup_lease_request(
        &self,
        request: LeaseRequestKey,
    ) -> Result<Option<TryClaimReceipt>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        lock_live_routing(&mut transaction, request.session())
            .await?
            .require_online(request.session())?;
        lock_current_lease_request_head(&mut transaction, request, None).await?;
        let row = claim_receipt_row(&mut transaction, request).await?;
        let receipt = row
            .as_ref()
            .map(|row| decode_claim_receipt(row, request, true))
            .transpose()?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn try_claim(&self, request: TryClaimAttempt) -> Result<TryClaimReceipt, StoreError> {
        let digest = request.request_digest();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let routing = lock_live_routing(&mut transaction, request.session()).await?;
        routing.require_online(request.session())?;
        lock_current_lease_request_head(&mut transaction, request.request_key(), None).await?;

        let inserted = sqlx::query(
            r"
            INSERT INTO runner_operation_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                selection_kind,
                request_digest, requested_attempt_id, requested_lease_id,
                runner_slot, scan_cursor_version, observed_at_ms,
                lease_expires_at_ms, outcome
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, 'claim', $7, $8, $9, $10, $11, $12, $13,
                'pending'
            )
            ON CONFLICT (runner_session_id, operation_id) DO NOTHING
            ",
        )
        .bind(request.session().session_id().as_uuid())
        .bind(request.operation_id().as_uuid())
        .bind(request.session().runner_id().as_uuid())
        .bind(epoch_i64(request.session().session_epoch())?)
        .bind(generation_i64(request.session().runner_generation())?)
        .bind(LEASE_OPERATION_KIND)
        .bind(digest.as_bytes().as_slice())
        .bind(request.attempt_id().as_uuid())
        .bind(request.lease_id().as_uuid())
        .bind(i32::from(request.slot().ordinal()))
        .bind(cursor_version_i64(request.cursor().expected_version())?)
        .bind(request.observed_at().get())
        .bind(request.expires_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();

        if inserted == 0 {
            let receipt = replay_claim(&mut transaction, request.request_key()).await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(receipt);
        }

        let (outcome, committed_cursor) = if routing.online && routing.accepts_new_work {
            let committed_cursor = advance_scan_cursor(
                &mut transaction,
                request.cursor(),
                &routing,
                request.observed_at(),
            )
            .await?;
            let outcome = if committed_cursor.is_some() {
                evaluate_claim(&mut transaction, &request, &routing).await?
            } else {
                TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded)
            };
            (outcome, committed_cursor)
        } else {
            (TryClaimOutcome::Rejected(ClaimRejection::NotRoutable), None)
        };
        complete_claim_receipt(&mut transaction, &request, &outcome, committed_cursor).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(TryClaimReceipt::new(request.request_key(), outcome, false))
    }

    async fn record_no_work(
        &self,
        request: NoWorkLeaseRequest,
    ) -> Result<TryClaimReceipt, StoreError> {
        let request_key = request.request_key();
        let digest = request_key.request_digest();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let routing = lock_live_routing(&mut transaction, request_key.session()).await?;
        routing.require_online(request_key.session())?;
        lock_current_lease_request_head(&mut transaction, request_key, None).await?;
        let inserted = sqlx::query(
            r"
            INSERT INTO runner_operation_receipts (
                runner_session_id, operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                selection_kind, request_digest, runner_slot,
                scan_cursor_version, observed_at_ms, outcome
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'no_work', $7, $8, $9, $10, 'pending')
            ON CONFLICT (runner_session_id, operation_id) DO NOTHING
            ",
        )
        .bind(request_key.session().session_id().as_uuid())
        .bind(request_key.operation_id().as_uuid())
        .bind(request_key.session().runner_id().as_uuid())
        .bind(epoch_i64(request_key.session().session_epoch())?)
        .bind(generation_i64(request_key.session().runner_generation())?)
        .bind(LEASE_OPERATION_KIND)
        .bind(digest.as_bytes().as_slice())
        .bind(i32::from(request_key.slot().ordinal()))
        .bind(cursor_version_i64(request.cursor().expected_version())?)
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        let receipt = if inserted == 1 {
            let (outcome, committed_cursor) = if routing.online && routing.accepts_new_work {
                let committed_cursor = advance_scan_cursor(
                    &mut transaction,
                    request.cursor(),
                    &routing,
                    request.observed_at(),
                )
                .await?;
                let outcome = if committed_cursor.is_some() {
                    TryClaimOutcome::NoWork
                } else {
                    TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded)
                };
                (outcome, committed_cursor)
            } else {
                (TryClaimOutcome::Rejected(ClaimRejection::NotRoutable), None)
            };
            complete_no_work_receipt(&mut transaction, &request, &outcome, committed_cursor)
                .await?;
            TryClaimReceipt::new(request_key, outcome, false)
        } else {
            replay_claim(&mut transaction, request_key).await?
        };
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }
}

#[async_trait]
impl WorkflowPlanRepository for PostgresStore {
    async fn get_job_ir_metadata(&self, job_id: JobId) -> Result<JobIrMetadata, StoreError> {
        let row = sqlx::query(
            r"
            SELECT run_id, job_ir_schema, job_ir_size_bytes,
                   job_ir_digest, job_ir_object_key
            FROM jobs
            WHERE id = $1
            ",
        )
        .bind(job_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::JobNotFound(job_id))?;
        let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
        let version =
            decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
        let size = u64::try_from(
            row.try_get::<i64, _>("job_ir_size_bytes")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("negative JobIR size"))?;
        let digest = crate::value::decode_sha256_digest(
            row.try_get("job_ir_digest").map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        let key = ObjectKey::new(
            row.try_get::<String, _>("job_ir_object_key")
                .map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        JobIrMetadata::new(job_id, run_id, version, size, digest, key)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))
    }

    async fn insert_dependency(&self, dependency: JobDependency) -> Result<(), StoreError> {
        sqlx::query(
            r"
            INSERT INTO job_dependencies (run_id, job_id, prerequisite_job_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (run_id, job_id, prerequisite_job_id) DO NOTHING
            ",
        )
        .bind(dependency.run_id().as_uuid())
        .bind(dependency.job_id().as_uuid())
        .bind(dependency.prerequisite_job_id().as_uuid())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;
        Ok(())
    }
}

#[async_trait]
impl CancellationRepository for PostgresStore {
    async fn request_cancellation(
        &self,
        request: RequestCancellation,
    ) -> Result<CancellationIntent, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        lock_cancellation_routing(&mut transaction, &request).await?;
        let attempt = lock_cancellation_attempt(&mut transaction, request.attempt_id()).await?;
        if let Some(existing) = load_cancellation(&mut transaction, request.attempt_id()).await? {
            if same_cancellation_request(existing.request(), &request) {
                let intent = CancellationIntent::try_new(
                    existing.request().clone(),
                    existing.acknowledged_at(),
                    true,
                    existing.delivery().cloned(),
                )
                .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
                transaction.commit().await.map_err(operation_error)?;
                return Ok(intent);
            }
            return Err(StoreError::ImmutableConflict("cancellation intent"));
        }
        if request.requested_at() < attempt.changed_at {
            return Err(StoreError::AttemptTimeRegression {
                attempt_id: request.attempt_id(),
                observed_at: request.requested_at(),
                changed_at: attempt.changed_at,
            });
        }
        let durable_delivery =
            prepare_cancellation_delivery(&mut transaction, &request, &attempt).await?;
        insert_cancellation_intent(&mut transaction, &request, durable_delivery.as_ref()).await?;
        transition_cancelled_attempt(&mut transaction, &request, attempt.lifecycle).await?;
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            request.requested_at(),
        )
        .await?;
        let intent = CancellationIntent::try_new(request, None, false, durable_delivery)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(intent)
    }

    async fn cancellation_for_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<CancellationIntent>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let intent = load_cancellation(&mut transaction, attempt_id).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(intent)
    }
}

#[derive(Clone, Copy, Debug)]
struct LockedCancellationAttempt {
    lifecycle: JobLifecycle,
    changed_at: UnixMillis,
    lease_expires_at: Option<UnixMillis>,
    session: Option<RunnerSessionFence>,
    guard: Option<LeaseGuard>,
    protocol_version: Option<RunnerProtocolVersion>,
}

async fn lock_cancellation_routing(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        r"
        SELECT lifecycle, runner_id, runner_session_id,
               runner_session_epoch, runner_generation, runner_slot
        FROM job_attempts
        WHERE id = $1
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptNotFound(request.attempt_id()))?;
    let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
    if !lifecycle_is_active(lifecycle) {
        return Ok(());
    }
    let delivery = request
        .delivery()
        .ok_or(StoreError::CancellationDeliveryRequired(
            request.attempt_id(),
        ))?;
    if decode_optional_attempt_session(&row)? != Some(delivery.session()) {
        return Err(StoreError::CancellationDeliveryMismatch(
            request.attempt_id(),
        ));
    }
    lock_live_routing(transaction, delivery.session())
        .await?
        .require_online(delivery.session())
}

async fn lock_cancellation_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: AttemptId,
) -> Result<LockedCancellationAttempt, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.changed_at_ms, attempt.lease_expires_at_ms,
               attempt.lease_id, attempt.fencing_token, attempt.runner_id,
               attempt.runner_session_id, attempt.runner_session_epoch,
               attempt.runner_generation, attempt.runner_slot, session.protocol_version
        FROM job_attempts AS attempt
        LEFT JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.runner_id = attempt.runner_id
         AND session.runner_generation = attempt.runner_generation
         AND session.session_epoch = attempt.runner_session_epoch
        WHERE attempt.id = $1
        FOR UPDATE OF attempt
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::AttemptNotFound(attempt_id))?;
    decode_cancellation_attempt(&row)
}

fn decode_cancellation_attempt(
    row: &sqlx::postgres::PgRow,
) -> Result<LockedCancellationAttempt, StoreError> {
    let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
    let lease_id = row
        .try_get::<Option<Uuid>, _>("lease_id")
        .map_err(operation_error)?
        .map(LeaseId::from_uuid);
    let raw_fence: i64 = row.try_get("fencing_token").map_err(operation_error)?;
    let guard = lease_id
        .map(|lease_id| decode_fencing(raw_fence).map(|fence| LeaseGuard::new(lease_id, fence)))
        .transpose()?;
    let protocol_version = row
        .try_get::<Option<i32>, _>("protocol_version")
        .map_err(operation_error)?
        .map(decode_protocol)
        .transpose()?;
    Ok(LockedCancellationAttempt {
        lifecycle,
        changed_at: UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?),
        lease_expires_at: row
            .try_get::<Option<i64>, _>("lease_expires_at_ms")
            .map_err(operation_error)?
            .map(UnixMillis::new),
        session: decode_optional_attempt_session(row)?,
        guard,
        protocol_version,
    })
}

async fn prepare_cancellation_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
    attempt: &LockedCancellationAttempt,
) -> Result<Option<DurableRunnerCommand>, StoreError> {
    if !lifecycle_is_active(attempt.lifecycle) {
        if request.delivery().is_some() {
            return Err(StoreError::CancellationDeliveryMismatch(
                request.attempt_id(),
            ));
        }
        return Ok(None);
    }
    let delivery = request
        .delivery()
        .ok_or(StoreError::CancellationDeliveryRequired(
            request.attempt_id(),
        ))?;
    validate_cancel_job_delivery(request, attempt, delivery)?;
    let expires_at = attempt
        .lease_expires_at
        .ok_or_else(|| StoreError::corrupt_data("active attempt lacks lease expiry"))?;
    if request.requested_at() >= expires_at {
        return Err(StoreError::AttemptFenceRejected(request.attempt_id()));
    }
    enqueue_locked_command_in_transaction(transaction, delivery.clone())
        .await
        .map(Some)
}

fn validate_cancel_job_delivery(
    request: &RequestCancellation,
    attempt: &LockedCancellationAttempt,
    delivery: &EnqueueRunnerCommand,
) -> Result<(), StoreError> {
    let expected_reason = request
        .reason()
        .map_or(DEFAULT_CANCELLATION_REASON, CancellationReason::as_str);
    let payload = CancelJobCommandPayload::decode_json(delivery.payload().bytes())
        .map_err(|_| StoreError::CancellationDeliveryMismatch(request.attempt_id()))?;
    let exact = delivery.kind().as_str() == CANCEL_JOB_COMMAND_KIND
        && delivery.payload().schema().get() == CANCEL_JOB_COMMAND_SCHEMA
        && delivery.created_at() == request.requested_at()
        && attempt.session == Some(delivery.session())
        && Some(payload.guard()) == attempt.guard
        && Some(payload.protocol_version())
            == attempt.protocol_version.map(RunnerProtocolVersion::get)
        && payload.attempt_id() == request.attempt_id()
        && payload.requested_at() == request.requested_at()
        && payload.reason() == expected_reason;
    if exact {
        Ok(())
    } else {
        Err(StoreError::CancellationDeliveryMismatch(
            request.attempt_id(),
        ))
    }
}

async fn insert_cancellation_intent(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
    delivery: Option<&DurableRunnerCommand>,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        INSERT INTO attempt_cancellation_intents (
            attempt_id, operation_id, requested_by, reason, requested_at_ms,
            delivery_session_id, delivery_command_sequence
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(request.actor().as_str())
    .bind(request.reason().map(CancellationReason::as_str))
    .bind(request.requested_at().get())
    .bind(delivery.map(|value| value.request().session().session_id().as_uuid()))
    .bind(
        delivery
            .map(DurableRunnerCommand::sequence)
            .map(sequence_i64)
            .transpose()?,
    )
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn transition_cancelled_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RequestCancellation,
    lifecycle: JobLifecycle,
) -> Result<(), StoreError> {
    let next = if lifecycle == JobLifecycle::Queued {
        Some("cancelled")
    } else if lifecycle_is_active(lifecycle) && lifecycle != JobLifecycle::Cancelling {
        Some("cancelling")
    } else {
        None
    };
    let Some(next) = next else {
        return Ok(());
    };
    sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = $2, changed_at_ms = $3
        WHERE id = $1 AND changed_at_ms <= $3
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(next)
    .bind(request.requested_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

#[async_trait]
impl BlockedAttemptRepository for PostgresStore {
    async fn scan_blocked(
        &self,
        limit: RunnableScanLimit,
        observed_at: UnixMillis,
    ) -> Result<Vec<BlockedAttempt>, StoreError> {
        let rows = sqlx::query(
            r"
            SELECT attempt.id AS attempt_id, attempt.job_id,
                   job.run_id, attempt.queued_at_ms
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            WHERE attempt.lifecycle = 'queued'
              AND attempt.queued_at_ms <= $1
              AND run.status IN ('queued', 'in_progress')
              AND NOT EXISTS (
                  SELECT 1 FROM attempt_cancellation_intents AS cancellation
                  WHERE cancellation.attempt_id = attempt.id
              )
              AND EXISTS (
                  SELECT 1
                  FROM job_dependencies AS dependency
                  WHERE dependency.run_id = job.run_id
                    AND dependency.job_id = job.id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM job_dependencies AS dependency
                  WHERE dependency.run_id = job.run_id
                    AND dependency.job_id = job.id
                    AND coalesce((
                        SELECT prerequisite_attempt.lifecycle
                        FROM job_attempts AS prerequisite_attempt
                        WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                        ORDER BY prerequisite_attempt.attempt_number DESC
                        LIMIT 1
                    ), '') NOT IN (
                        'succeeded', 'failed', 'cancelled', 'timed_out',
                        'skipped', 'lost'
                    )
              )
              AND EXISTS (
                  SELECT 1
                  FROM job_dependencies AS dependency
                  WHERE dependency.run_id = job.run_id
                    AND dependency.job_id = job.id
                    AND (
                        SELECT prerequisite_attempt.lifecycle
                        FROM job_attempts AS prerequisite_attempt
                        WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                        ORDER BY prerequisite_attempt.attempt_number DESC
                        LIMIT 1
                    ) IN ('failed', 'cancelled', 'timed_out', 'skipped', 'lost')
              )
            ORDER BY attempt.queued_at_ms, attempt.id
            LIMIT $2
            ",
        )
        .bind(observed_at.get())
        .bind(i64::from(limit.get()))
        .fetch_all(&self.pool)
        .await
        .map_err(operation_error)?;
        rows.iter()
            .map(|row| {
                Ok(BlockedAttempt::new(
                    AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
                    JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?),
                    RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?),
                    UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?),
                ))
            })
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    async fn conclude_blocked(
        &self,
        request: ConcludeBlockedAttempt,
    ) -> Result<BlockedConclusion, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        super::admission::lock_attempt_concurrency(&mut transaction, request.attempt_id()).await?;
        let row = sqlx::query(
            r"
            SELECT attempt.lifecycle, attempt.changed_at_ms, job.id AS job_id,
                   job.run_id, run.status AS run_status,
                   EXISTS (
                       SELECT 1 FROM attempt_cancellation_intents AS cancellation
                       WHERE cancellation.attempt_id = attempt.id
                   ) AS has_cancellation
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            WHERE attempt.id = $1
            FOR UPDATE OF attempt, run
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::AttemptNotFound(request.attempt_id()))?;
        let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
        if lifecycle == JobLifecycle::Skipped {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::AlreadySkipped);
        }
        if lifecycle != JobLifecycle::Queued {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NotQueued(lifecycle));
        }
        let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
        if request.observed_at() < changed_at {
            return Err(StoreError::AttemptTimeRegression {
                attempt_id: request.attempt_id(),
                observed_at: request.observed_at(),
                changed_at,
            });
        }
        let run_status: &str = row.try_get("run_status").map_err(operation_error)?;
        let has_cancellation: bool = row.try_get("has_cancellation").map_err(operation_error)?;
        if !matches!(run_status, "queued" | "in_progress") || has_cancellation {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NoLongerBlocked);
        }
        let job_id: Uuid = row.try_get("job_id").map_err(operation_error)?;
        let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
        let prerequisite_jobs = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT prerequisite.id
            FROM job_dependencies AS dependency
            JOIN jobs AS prerequisite
              ON prerequisite.run_id = dependency.run_id
             AND prerequisite.id = dependency.prerequisite_job_id
            WHERE dependency.run_id = $1 AND dependency.job_id = $2
            ORDER BY prerequisite.id
            FOR UPDATE OF prerequisite
            ",
        )
        .bind(run_id)
        .bind(job_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if prerequisite_jobs.is_empty() {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NoLongerBlocked);
        }
        let latest_rows = sqlx::query(
            r"
            SELECT dependency.prerequisite_job_id, latest.lifecycle
            FROM job_dependencies AS dependency
            LEFT JOIN LATERAL (
                SELECT prerequisite_attempt.lifecycle
                FROM job_attempts AS prerequisite_attempt
                WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                ORDER BY prerequisite_attempt.attempt_number DESC
                LIMIT 1
                FOR UPDATE
            ) AS latest ON TRUE
            WHERE dependency.run_id = $1 AND dependency.job_id = $2
            ORDER BY dependency.prerequisite_job_id
            ",
        )
        .bind(run_id)
        .bind(job_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let mut has_non_success = false;
        for latest in latest_rows {
            let lifecycle = latest
                .try_get::<Option<&str>, _>("lifecycle")
                .map_err(operation_error)?
                .map(parse_lifecycle_store)
                .transpose()?;
            let Some(lifecycle) = lifecycle else {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(BlockedConclusion::NoLongerBlocked);
            };
            if !lifecycle.is_terminal() {
                transaction.commit().await.map_err(operation_error)?;
                return Ok(BlockedConclusion::NoLongerBlocked);
            }
            has_non_success |= lifecycle != JobLifecycle::Succeeded;
        }
        if !has_non_success {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(BlockedConclusion::NoLongerBlocked);
        }
        let updated = sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = 'skipped', changed_at_ms = $2
            WHERE id = $1 AND lifecycle = 'queued' AND changed_at_ms <= $2
            ",
        )
        .bind(request.attempt_id().as_uuid())
        .bind(request.observed_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::corrupt_data(
                "locked blocked conclusion did not update exactly one attempt",
            ));
        }
        super::admission::reconcile_attempt_run(
            &mut transaction,
            request.attempt_id(),
            request.observed_at(),
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(BlockedConclusion::Skipped)
    }
}

#[async_trait]
impl RunnableAttemptRepository for PostgresStore {
    async fn scan_runnable(
        &self,
        request: RunnableScanRequest,
    ) -> Result<RunnableScanPage, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let routing = lock_live_routing(&mut transaction, request.session()).await?;
        routing.require_online(request.session())?;
        if request.observed_at() < routing.durable_at {
            return Err(StoreError::SessionTimeRegression {
                session_id: request.session().session_id(),
                observed_at: request.observed_at(),
                durable_at: routing.durable_at,
            });
        }
        if !routing.slots.contains(request.slot()) {
            return Err(StoreError::SlotOutOfRange {
                session_id: request.session().session_id(),
                slot: request.slot(),
            });
        }

        let fingerprint = routing_fingerprint(&routing, request.session().runner_generation())?;
        if !routing.accepts_new_work {
            let page = RunnableScanPage::try_new(
                request.session(),
                request.slot(),
                fingerprint,
                0,
                None,
                Vec::new(),
            )
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(page);
        }
        let stored = load_scan_cursor(&mut transaction, request.session(), request.slot()).await?;
        let expected_version = stored.as_ref().map_or(0, |cursor| cursor.version);
        let (after, upper) = stored
            .filter(|cursor| {
                cursor.routing_fingerprint == fingerprint
                    && cursor.runner_generation == request.session().runner_generation()
            })
            .map_or((None, None), |cursor| (cursor.after, cursor.cycle_upper));

        let mut cycle_upper = upper;
        let mut rows = if let Some(upper) = cycle_upper {
            if after.is_none_or(|after| after < upper) {
                scan_page_rows(&mut transaction, &routing, after, upper, request).await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // An exhausted finite cycle wraps exactly once. Capturing the new
        // high-water mark before reading the page prevents continuous arrivals
        // from keeping the scan in one non-terminating cycle.
        if rows.is_empty() {
            cycle_upper = scan_cycle_upper(&mut transaction, &routing, request).await?;
            rows = if let Some(upper) = cycle_upper {
                scan_page_rows(&mut transaction, &routing, None, upper, request).await?
            } else {
                Vec::new()
            };
        }

        let candidates = rows
            .iter()
            .map(decode_runnable_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        let page = RunnableScanPage::try_new(
            request.session(),
            request.slot(),
            fingerprint,
            expected_version,
            cycle_upper,
            candidates,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(page)
    }
}

#[derive(Clone, Debug)]
struct StoredScanCursor {
    runner_generation: RunnerGeneration,
    routing_fingerprint: Sha256Digest,
    version: u64,
    after: Option<RunnableQueueKey>,
    cycle_upper: Option<RunnableQueueKey>,
}

async fn load_scan_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
) -> Result<Option<StoredScanCursor>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT runner_generation, routing_fingerprint, cursor_version,
               after_queued_at_ms, after_attempt_id,
               cycle_upper_queued_at_ms, cycle_upper_attempt_id
        FROM runner_queue_cursors
        WHERE runner_id = $1 AND runner_slot = $2
        FOR UPDATE
        ",
    )
    .bind(session.runner_id().as_uuid())
    .bind(i32::from(slot.ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref().map(decode_scan_cursor).transpose()
}

fn decode_scan_cursor(row: &sqlx::postgres::PgRow) -> Result<StoredScanCursor, StoreError> {
    let version = u64::try_from(
        row.try_get::<i64, _>("cursor_version")
            .map_err(operation_error)?,
    )
    .ok()
    .filter(|version| *version > 0)
    .ok_or_else(|| StoreError::corrupt_data("invalid runnable cursor version"))?;
    Ok(StoredScanCursor {
        runner_generation: decode_generation(
            row.try_get("runner_generation").map_err(operation_error)?,
        )?,
        routing_fingerprint: crate::value::decode_sha256_digest(
            row.try_get("routing_fingerprint")
                .map_err(operation_error)?,
        )
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?,
        version,
        after: decode_queue_key(row, "after_queued_at_ms", "after_attempt_id")?,
        cycle_upper: decode_queue_key(row, "cycle_upper_queued_at_ms", "cycle_upper_attempt_id")?,
    })
}

fn decode_queue_key(
    row: &sqlx::postgres::PgRow,
    time_column: &str,
    id_column: &str,
) -> Result<Option<RunnableQueueKey>, StoreError> {
    let queued_at = row
        .try_get::<Option<i64>, _>(time_column)
        .map_err(operation_error)?;
    let attempt_id = row
        .try_get::<Option<Uuid>, _>(id_column)
        .map_err(operation_error)?;
    match (queued_at, attempt_id) {
        (None, None) => Ok(None),
        (Some(time), Some(id)) => Ok(Some(RunnableQueueKey::new(
            UnixMillis::new(time),
            AttemptId::from_uuid(id),
        ))),
        _ => Err(StoreError::corrupt_data(
            "partial runnable queue cursor key",
        )),
    }
}

async fn scan_cycle_upper(
    transaction: &mut Transaction<'_, Postgres>,
    routing: &LockedRouting,
    request: RunnableScanRequest,
) -> Result<Option<RunnableQueueKey>, StoreError> {
    let row = sqlx::query(
        r"
        SELECT attempt.queued_at_ms, attempt.id AS attempt_id
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1
          AND job.admission_epoch = $4
          AND job.job_ir_schema = $2
          AND attempt.lifecycle = 'queued'
          AND attempt.queued_at_ms <= $3
          AND run.status IN ('queued', 'in_progress')
          AND NOT EXISTS (
              SELECT 1 FROM attempt_cancellation_intents AS cancellation
              WHERE cancellation.attempt_id = attempt.id
          )
          AND (
              run.concurrency_group_key IS NULL
              OR EXISTS (
                  SELECT 1 FROM concurrency_groups AS concurrency
                  WHERE concurrency.repository_id = run.repository_id
                    AND concurrency.normalized_key = run.concurrency_group_key
                    AND concurrency.running_run_id = run.id
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM job_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.job_id = job.id
                AND coalesce((
                    SELECT prerequisite_attempt.lifecycle
                    FROM job_attempts AS prerequisite_attempt
                    WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                    ORDER BY prerequisite_attempt.attempt_number DESC
                    LIMIT 1
                ), '') <> 'succeeded'
          )
        ORDER BY attempt.queued_at_ms DESC, attempt.id DESC
        LIMIT 1
        ",
    )
    .bind(&routing.tenant_id)
    .bind(i32::from(routing.job_ir_version.get()))
    .bind(request.observed_at().get())
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    row.as_ref()
        .map(|row| {
            Ok(RunnableQueueKey::new(
                UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?),
                AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
            ))
        })
        .transpose()
}

async fn scan_page_rows(
    transaction: &mut Transaction<'_, Postgres>,
    routing: &LockedRouting,
    after: Option<RunnableQueueKey>,
    upper: RunnableQueueKey,
    request: RunnableScanRequest,
) -> Result<Vec<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT attempt.id AS attempt_id, attempt.job_id, attempt.queued_at_ms,
               job.run_id, job.requirements, job.job_ir_schema,
               job.job_ir_size_bytes, job.job_ir_digest, job.job_ir_object_key
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE repository.tenant_id = $1
          AND job.admission_epoch = $9
          AND job.job_ir_schema = $2
          AND attempt.lifecycle = 'queued'
          AND attempt.queued_at_ms <= $3
          AND (
              $4::BIGINT IS NULL
              OR (attempt.queued_at_ms, attempt.id) > ($4, $5::UUID)
          )
          AND (attempt.queued_at_ms, attempt.id) <= ($6, $7)
          AND run.status IN ('queued', 'in_progress')
          AND NOT EXISTS (
              SELECT 1 FROM attempt_cancellation_intents AS cancellation
              WHERE cancellation.attempt_id = attempt.id
          )
          AND (
              run.concurrency_group_key IS NULL
              OR EXISTS (
                  SELECT 1 FROM concurrency_groups AS concurrency
                  WHERE concurrency.repository_id = run.repository_id
                    AND concurrency.normalized_key = run.concurrency_group_key
                    AND concurrency.running_run_id = run.id
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM job_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.job_id = job.id
                AND coalesce((
                    SELECT prerequisite_attempt.lifecycle
                    FROM job_attempts AS prerequisite_attempt
                    WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                    ORDER BY prerequisite_attempt.attempt_number DESC
                    LIMIT 1
                ), '') <> 'succeeded'
          )
        ORDER BY attempt.queued_at_ms, attempt.id
        LIMIT $8
        ",
    )
    .bind(&routing.tenant_id)
    .bind(i32::from(routing.job_ir_version.get()))
    .bind(request.observed_at().get())
    .bind(after.map(|key| key.queued_at().get()))
    .bind(after.map(|key| key.attempt_id().as_uuid()))
    .bind(upper.queued_at().get())
    .bind(upper.attempt_id().as_uuid())
    .bind(i64::from(request.limit().get()))
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableDesiredRunnerState {
    Active,
    Draining,
    Disabled,
}

#[derive(Debug)]
struct LockedRouting {
    tenant_id: String,
    group_name: Option<String>,
    labels: BTreeSet<RoutingLabel>,
    slots: RunnerSlotCount,
    protocol_version: RunnerProtocolVersion,
    job_ir_version: JobIrVersion,
    registered_capabilities: RunnerCapabilities,
    observed_capabilities: RunnerCapabilities,
    online: bool,
    accepts_new_work: bool,
    durable_at: UnixMillis,
}

impl LockedRouting {
    fn require_online(&self, fence: RunnerSessionFence) -> Result<(), StoreError> {
        if self.online {
            Ok(())
        } else {
            Err(StoreError::SessionClosed(fence.session_id()))
        }
    }
}

fn decode_desired_runner_state(value: &str) -> Result<DurableDesiredRunnerState, StoreError> {
    match value {
        "active" => Ok(DurableDesiredRunnerState::Active),
        "draining" => Ok(DurableDesiredRunnerState::Draining),
        "disabled" => Ok(DurableDesiredRunnerState::Disabled),
        _ => Err(StoreError::corrupt_data("invalid runner desired state")),
    }
}

fn routing_fingerprint(
    routing: &LockedRouting,
    generation: RunnerGeneration,
) -> Result<Sha256Digest, StoreError> {
    fn field(digest: &mut Sha256, value: &[u8]) {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value);
    }

    let mut digest = Sha256::new();
    digest.update(b"automata.store.runner-routing-fingerprint.v1\0");
    digest.update(generation.get().to_be_bytes());
    digest.update(routing.job_ir_version.get().to_be_bytes());
    field(&mut digest, routing.tenant_id.as_bytes());
    field(
        &mut digest,
        routing.group_name.as_deref().unwrap_or_default().as_bytes(),
    );
    for label in &routing.labels {
        field(&mut digest, label.as_str().as_bytes());
    }
    let registered = serde_json::to_vec(&routing.registered_capabilities)
        .map_err(|_| StoreError::corrupt_data("registered capabilities are not canonical"))?;
    let observed = serde_json::to_vec(&routing.observed_capabilities)
        .map_err(|_| StoreError::corrupt_data("observed capabilities are not canonical"))?;
    field(&mut digest, &registered);
    field(&mut digest, &observed);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

#[allow(clippy::too_many_lines)]
async fn lock_live_routing(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<LockedRouting, StoreError> {
    let runner_id: Uuid = sqlx::query_scalar("SELECT runner_id FROM runner_sessions WHERE id = $1")
        .bind(fence.session_id().as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(StoreError::SessionNotFound(fence.session_id()))?;
    if runner_id != fence.runner_id().as_uuid() {
        return Err(StoreError::fence_rejected(fence.session_id()));
    }

    let runner = sqlx::query(
        r"
        SELECT runner.tenant_id, runner.generation, runner.session_epoch, runner.group_id,
               runner_group.normalized_name AS group_name,
               runner.labels, runner.slots, runner.status, runner.desired_state,
               runner.capabilities
        FROM runners AS runner
        LEFT JOIN runner_groups AS runner_group ON runner_group.id = runner.group_id
        WHERE runner.id = $1
        FOR UPDATE OF runner
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let actual_generation =
        decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    if actual_generation != fence.runner_generation() {
        return Err(StoreError::generation_mismatch(
            fence.runner_id(),
            fence.runner_generation(),
            actual_generation,
        ));
    }
    let current_epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
    if current_epoch != fence.session_epoch() {
        return Err(StoreError::fence_rejected(fence.session_id()));
    }
    let status: &str = runner.try_get("status").map_err(operation_error)?;
    let desired_state =
        decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?;
    if desired_state == DurableDesiredRunnerState::Disabled {
        return Err(StoreError::RunnerDisabled(fence.runner_id()));
    }

    let session = sqlx::query(
        r"
        SELECT runner_generation, session_epoch, protocol_version, job_ir_schema,
               capability_snapshot, heartbeat_at_ms, disconnected_at_ms
        FROM runner_sessions
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(fence.session_id().as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let stored_generation = decode_generation(
        session
            .try_get("runner_generation")
            .map_err(operation_error)?,
    )?;
    let stored_epoch = decode_epoch(session.try_get("session_epoch").map_err(operation_error)?)?;
    let disconnected: Option<i64> = session
        .try_get("disconnected_at_ms")
        .map_err(operation_error)?;
    if stored_generation != fence.runner_generation() || stored_epoch != fence.session_epoch() {
        return Err(StoreError::fence_rejected(fence.session_id()));
    }
    if disconnected.is_some() {
        return Err(StoreError::SessionClosed(fence.session_id()));
    }

    let slots = u16::try_from(runner.try_get::<i32, _>("slots").map_err(operation_error)?)
        .ok()
        .and_then(|value| RunnerSlotCount::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid registered runner slots"))?;
    let registered_capabilities: RunnerCapabilities = serde_json::from_value(
        runner
            .try_get::<serde_json::Value, _>("capabilities")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid registered runner capabilities"))?;
    registered_capabilities
        .validate()
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if registered_capabilities.runner_id() != fence.runner_id() {
        return Err(StoreError::corrupt_data(
            "registered capabilities identify a different runner",
        ));
    }
    let observed_capabilities: RunnerCapabilities = serde_json::from_value(
        session
            .try_get::<serde_json::Value, _>("capability_snapshot")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid observed runner capabilities"))?;
    observed_capabilities
        .validate()
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    if observed_capabilities.runner_id() != fence.runner_id() {
        return Err(StoreError::corrupt_data(
            "observed capabilities identify a different runner",
        ));
    }
    Ok(LockedRouting {
        tenant_id: runner.try_get("tenant_id").map_err(operation_error)?,
        group_name: runner.try_get("group_name").map_err(operation_error)?,
        labels: decode_routing_labels(
            runner
                .try_get::<Vec<String>, _>("labels")
                .map_err(operation_error)?,
            "durable runner routing labels contain case-folded duplicates",
        )?,
        slots,
        protocol_version: decode_protocol(
            session
                .try_get("protocol_version")
                .map_err(operation_error)?,
        )?,
        job_ir_version: decode_job_ir_version(
            session.try_get("job_ir_schema").map_err(operation_error)?,
        )?,
        registered_capabilities,
        observed_capabilities,
        online: status == "online",
        accepts_new_work: desired_state == DurableDesiredRunnerState::Active,
        durable_at: UnixMillis::new(
            session
                .try_get("heartbeat_at_ms")
                .map_err(operation_error)?,
        ),
    })
}

async fn lock_existing_session_authority(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<(), StoreError> {
    let runner = sqlx::query(
        r"
        SELECT generation, session_epoch, status, desired_state
        FROM runners
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let generation = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    if generation != fence.runner_generation() {
        return Err(StoreError::generation_mismatch(
            fence.runner_id(),
            fence.runner_generation(),
            generation,
        ));
    }
    let epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
    if epoch != fence.session_epoch() {
        return Err(StoreError::fence_rejected(fence.session_id()));
    }
    if decode_desired_runner_state(runner.try_get("desired_state").map_err(operation_error)?)?
        == DurableDesiredRunnerState::Disabled
    {
        return Err(StoreError::RunnerDisabled(fence.runner_id()));
    }
    match runner
        .try_get::<&str, _>("status")
        .map_err(operation_error)?
    {
        "online" => Ok(()),
        "offline" => Err(StoreError::SessionClosed(fence.session_id())),
        _ => Err(StoreError::corrupt_data("invalid observed runner status")),
    }
}

async fn lock_runner_fence(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<(), StoreError> {
    let runner = sqlx::query(
        r"
        SELECT generation, session_epoch
        FROM runners
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(StoreError::RunnerNotFound(fence.runner_id()))?;
    let generation = decode_generation(runner.try_get("generation").map_err(operation_error)?)?;
    let epoch = decode_epoch(runner.try_get("session_epoch").map_err(operation_error)?)?;
    if generation != fence.runner_generation() || epoch != fence.session_epoch() {
        return Err(StoreError::fence_rejected(fence.session_id()));
    }
    Ok(())
}

async fn mark_runner_offline(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
    observed_at: UnixMillis,
) -> Result<(), StoreError> {
    let updated = sqlx::query(
        r"
        UPDATE runners
        SET status = 'offline',
            last_seen_at_ms = greatest(coalesce(last_seen_at_ms, $4), $4),
            updated_at_ms = greatest(updated_at_ms, $4)
        WHERE id = $1 AND generation = $2 AND session_epoch = $3
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(observed_at.get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::fence_rejected(fence.session_id()));
    }
    Ok(())
}

pub(super) async fn cleanup_session_lease_request_state(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: RunnerSessionId,
) -> Result<(), StoreError> {
    cleanup_session_lease_request_state_uuid(transaction, session_id.as_uuid()).await
}

pub(super) async fn cleanup_session_lease_request_state_uuid(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM runner_operation_receipts WHERE runner_session_id = $1")
        .bind(session_id)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_rpc_receipts
        WHERE runner_session_id = $1 AND operation_kind = $2
        ",
    )
    .bind(session_id)
    .bind(LEASE_RPC_OPERATION_KIND)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query("DELETE FROM runner_lease_request_heads WHERE runner_session_id = $1")
        .bind(session_id)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn cleanup_disconnected_runner_lease_request_state(
    transaction: &mut Transaction<'_, Postgres>,
    runner_id: RunnerId,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        DELETE FROM runner_operation_receipts AS receipt
        USING runner_sessions AS session
        WHERE receipt.runner_session_id = session.id
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_rpc_receipts AS receipt
        USING runner_sessions AS session
        WHERE receipt.runner_session_id = session.id
          AND receipt.operation_kind = $2
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(LEASE_RPC_OPERATION_KIND)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        DELETE FROM runner_lease_request_heads AS head
        USING runner_sessions AS session
        WHERE head.runner_session_id = session.id
          AND session.runner_id = $1
          AND session.disconnected_at_ms IS NOT NULL
        ",
    )
    .bind(runner_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn advance_scan_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    cursor: RunnableCursorAdvance,
    routing: &LockedRouting,
    observed_at: UnixMillis,
) -> Result<Option<u64>, StoreError> {
    if cursor.routing_fingerprint()
        != routing_fingerprint(routing, cursor.session().runner_generation())?
    {
        return Ok(None);
    }
    let next_version = cursor
        .expected_version()
        .checked_add(1)
        .filter(|version| i64::try_from(*version).is_ok())
        .ok_or_else(|| StoreError::corrupt_data("runnable cursor version exhausted"))?;
    let through = cursor.through();
    let upper = cursor.cycle_upper();
    if through.is_some_and(|key| upper.is_none_or(|upper| key > upper)) {
        return Err(StoreError::corrupt_data(
            "runnable cursor advancement exceeds cycle high-water mark",
        ));
    }
    let rows = if cursor.expected_version() == 0 {
        sqlx::query(
            r"
            INSERT INTO runner_queue_cursors (
                runner_id, runner_slot, runner_generation, routing_fingerprint,
                cursor_version, after_queued_at_ms, after_attempt_id,
                cycle_upper_queued_at_ms, cycle_upper_attempt_id, updated_at_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (runner_id, runner_slot) DO NOTHING
            ",
        )
        .bind(cursor.session().runner_id().as_uuid())
        .bind(i32::from(cursor.slot().ordinal()))
        .bind(generation_i64(cursor.session().runner_generation())?)
        .bind(cursor.routing_fingerprint().as_bytes().as_slice())
        .bind(cursor_version_i64(next_version)?)
        .bind(through.map(|key| key.queued_at().get()))
        .bind(through.map(|key| key.attempt_id().as_uuid()))
        .bind(upper.map(|key| key.queued_at().get()))
        .bind(upper.map(|key| key.attempt_id().as_uuid()))
        .bind(observed_at.get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected()
    } else {
        sqlx::query(
            r"
            UPDATE runner_queue_cursors
            SET runner_generation = $3,
                routing_fingerprint = $4,
                cursor_version = $5,
                after_queued_at_ms = $6,
                after_attempt_id = $7,
                cycle_upper_queued_at_ms = $8,
                cycle_upper_attempt_id = $9,
                updated_at_ms = $10
            WHERE runner_id = $1 AND runner_slot = $2 AND cursor_version = $11
            ",
        )
        .bind(cursor.session().runner_id().as_uuid())
        .bind(i32::from(cursor.slot().ordinal()))
        .bind(generation_i64(cursor.session().runner_generation())?)
        .bind(cursor.routing_fingerprint().as_bytes().as_slice())
        .bind(cursor_version_i64(next_version)?)
        .bind(through.map(|key| key.queued_at().get()))
        .bind(through.map(|key| key.attempt_id().as_uuid()))
        .bind(upper.map(|key| key.queued_at().get()))
        .bind(upper.map(|key| key.attempt_id().as_uuid()))
        .bind(observed_at.get())
        .bind(cursor_version_i64(cursor.expected_version())?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected()
    };
    Ok((rows == 1).then_some(next_version))
}

#[allow(clippy::too_many_lines)]
async fn evaluate_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &TryClaimAttempt,
    routing: &LockedRouting,
) -> Result<TryClaimOutcome, StoreError> {
    if !routing.online || !routing.accepts_new_work {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::NotRoutable));
    }
    if !routing.slots.contains(request.slot()) {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::SlotOutOfRange));
    }
    let occupied = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM job_attempts
        WHERE runner_id = $1 AND runner_slot = $2 AND lease_id IS NOT NULL
        LIMIT 1
        ",
    )
    .bind(request.session().runner_id().as_uuid())
    .bind(i32::from(request.slot().ordinal()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let Some(attempt_id) = occupied {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied {
            attempt_id: AttemptId::from_uuid(attempt_id),
        }));
    }

    let row = sqlx::query(
        r"
        SELECT attempt.lifecycle, attempt.fencing_token, attempt.changed_at_ms,
               job.id AS job_id, job.admission_epoch, job.job_ir_schema,
               job.job_ir_size_bytes, job.job_ir_digest, job.job_ir_object_key,
               job.requirements,
               repository.tenant_id, run.id AS run_id, run.repository_id,
               run.status AS run_status, run.concurrency_group_key,
               EXISTS (
                   SELECT 1 FROM attempt_cancellation_intents AS cancellation
                   WHERE cancellation.attempt_id = attempt.id
               ) AS has_cancellation,
               NOT EXISTS (
                   SELECT 1
                   FROM job_dependencies AS dependency
                   WHERE dependency.run_id = job.run_id
                     AND dependency.job_id = job.id
                     AND coalesce((
                         SELECT prerequisite_attempt.lifecycle
                         FROM job_attempts AS prerequisite_attempt
                         WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                         ORDER BY prerequisite_attempt.attempt_number DESC
                         LIMIT 1
                     ), '') <> 'succeeded'
               ) AS dependencies_succeeded
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE attempt.id = $1
        FOR UPDATE OF attempt, run
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::AttemptNotFound));
    };
    let lifecycle = parse_lifecycle_store(row.try_get("lifecycle").map_err(operation_error)?)?;
    if lifecycle != JobLifecycle::Queued {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::AttemptNotQueued(
            lifecycle,
        )));
    }
    let run_status: &str = row.try_get("run_status").map_err(operation_error)?;
    let has_cancellation: bool = row.try_get("has_cancellation").map_err(operation_error)?;
    let dependencies_succeeded: bool = row
        .try_get("dependencies_succeeded")
        .map_err(operation_error)?;
    let concurrency_key: Option<String> = row
        .try_get("concurrency_group_key")
        .map_err(operation_error)?;
    let run_id: Uuid = row.try_get("run_id").map_err(operation_error)?;
    if !matches!(run_status, "queued" | "in_progress")
        || has_cancellation
        || !dependencies_succeeded
    {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable));
    }
    if let Some(concurrency_key) = concurrency_key {
        let repository_id: Uuid = row.try_get("repository_id").map_err(operation_error)?;
        let running_run_id: Option<Uuid> = sqlx::query_scalar(
            r"
            SELECT running_run_id
            FROM concurrency_groups
            WHERE repository_id = $1 AND normalized_key = $2
            FOR UPDATE
            ",
        )
        .bind(repository_id)
        .bind(concurrency_key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .flatten();
        if running_run_id != Some(run_id) {
            return Ok(TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable));
        }
    }
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    if request.observed_at() < changed_at {
        return Err(StoreError::AttemptTimeRegression {
            attempt_id: request.attempt_id(),
            observed_at: request.observed_at(),
            changed_at,
        });
    }

    let tenant_id: String = row.try_get("tenant_id").map_err(operation_error)?;
    let admission_epoch: i32 = row.try_get("admission_epoch").map_err(operation_error)?;
    let job_version =
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let requirements: RunnerRequirements = serde_json::from_value(
        row.try_get::<serde_json::Value, _>("requirements")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid durable runner requirements"))?;
    let machine_requirements = requirements
        .clone()
        .with_labels(std::iter::empty::<automata_core::RunnerLabel>())
        .with_eligible_groups(std::iter::empty::<automata_core::RunnerGroup>());
    let capabilities_match = routing
        .registered_capabilities
        .satisfies(&machine_requirements)
        .is_ok()
        && routing
            .observed_capabilities
            .satisfies(&machine_requirements)
            .is_ok();
    let labels_match = requirements.labels().iter().all(|label| {
        RoutingLabel::new(label.as_str())
            .ok()
            .is_some_and(|label| routing.labels.contains(&label))
    });
    let group_matches = requirements.eligible_groups().is_empty()
        || routing.group_name.as_ref().is_some_and(|name| {
            RunnerGroup::new(name)
                .ok()
                .is_some_and(|group| requirements.eligible_groups().contains(&group))
        });
    if tenant_id != routing.tenant_id
        || admission_epoch != i32::from(WORKFLOW_ADMISSION_EPOCH)
        || !labels_match
        || !group_matches
        || !capabilities_match
        || job_version != routing.job_ir_version
    {
        return Ok(TryClaimOutcome::Rejected(ClaimRejection::NotRoutable));
    }

    let raw_fence: i64 = row.try_get("fencing_token").map_err(operation_error)?;
    let fencing_token = if raw_fence == 0 {
        FencingToken::new(1)
    } else {
        let current = crate::operation::decode_fencing_token(raw_fence)?;
        current.checked_next()
    }
    .map_err(|_| StoreError::FencingTokenExhausted {
        attempt_id: request.attempt_id(),
    })?;

    let updated = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'leased', fencing_token = $2, lease_id = $3,
            runner_id = $4, lease_issued_at_ms = $5, lease_expires_at_ms = $6,
            runner_session_id = $7, runner_session_epoch = $8,
            runner_generation = $9, runner_slot = $10, changed_at_ms = $5
        WHERE id = $1 AND lifecycle = 'queued' AND changed_at_ms <= $5
        ",
    )
    .bind(request.attempt_id().as_uuid())
    .bind(fence_i64(fencing_token)?)
    .bind(request.lease_id().as_uuid())
    .bind(request.session().runner_id().as_uuid())
    .bind(request.observed_at().get())
    .bind(request.expires_at().get())
    .bind(request.session().session_id().as_uuid())
    .bind(epoch_i64(request.session().session_epoch())?)
    .bind(generation_i64(request.session().runner_generation())?)
    .bind(i32::from(request.slot().ordinal()))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(StoreError::corrupt_data(
            "locked claim update did not affect exactly one attempt",
        ));
    }
    super::admission::reconcile_attempt_run(
        transaction,
        request.attempt_id(),
        request.observed_at(),
    )
    .await?;
    let lease = Lease::new(
        request.lease_id(),
        request.attempt_id(),
        request.session().runner_id(),
        fencing_token,
        request.observed_at(),
        request.expires_at(),
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let assignment = AttemptAssignment::new(request.session(), request.slot());
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let size = u64::try_from(
        row.try_get::<i64, _>("job_ir_size_bytes")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative JobIR size"))?;
    let digest =
        crate::value::decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let object_key = ObjectKey::new(
        row.try_get::<String, _>("job_ir_object_key")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let metadata = JobIrMetadata::new(job_id, run_id, job_version, size, digest, object_key)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let claimed = ClaimedAttempt::try_new(lease, assignment, metadata)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(TryClaimOutcome::Claimed(Box::new(claimed)))
}

#[allow(clippy::too_many_lines)]
async fn complete_claim_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &TryClaimAttempt,
    outcome: &TryClaimOutcome,
    committed_cursor: Option<u64>,
) -> Result<(), StoreError> {
    let (name, fencing_token, lifecycle, occupied_attempt) = match outcome {
        TryClaimOutcome::Claimed(claimed) => (
            "claimed",
            Some(fence_i64(claimed.lease().fencing_token())?),
            None,
            None,
        ),
        TryClaimOutcome::Rejected(ClaimRejection::AttemptNotFound) => {
            ("attempt_not_found", None, None, None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::AttemptNotQueued(lifecycle)) => {
            ("not_queued", None, Some(lifecycle_name(*lifecycle)), None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable) => {
            ("not_runnable", None, None, None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::NotRoutable) => {
            if committed_cursor.is_some() {
                ("not_routable", None, None, None)
            } else {
                ("authority_rejected", None, None, None)
            }
        }
        TryClaimOutcome::Rejected(ClaimRejection::SlotOutOfRange) => {
            ("slot_out_of_range", None, None, None)
        }
        TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied { attempt_id }) => {
            ("slot_occupied", None, None, Some(attempt_id.as_uuid()))
        }
        TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded) => {
            ("scan_superseded", None, None, None)
        }
        TryClaimOutcome::NoWork => {
            return Err(StoreError::invalid_operation_receipt(
                "claim completion received a no-work outcome",
            ));
        }
    };
    let result = sqlx::query(
        r"
        UPDATE runner_operation_receipts
        SET outcome = $3, claimed_fencing_token = $4,
            rejection_lifecycle = $5, occupied_attempt_id = $6,
            committed_cursor_version = $7,
            claimed_job_id = $8, claimed_run_id = $9,
            claimed_job_ir_schema = $10, claimed_job_ir_size_bytes = $11,
            claimed_job_ir_digest = $12, claimed_job_ir_object_key = $13,
            completed_at_ms = $14
        WHERE runner_session_id = $1 AND operation_id = $2 AND outcome = 'pending'
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .bind(name)
    .bind(fencing_token)
    .bind(lifecycle)
    .bind(occupied_attempt)
    .bind(committed_cursor.map(cursor_version_i64).transpose()?)
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.job_id().as_uuid()),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.run_id().as_uuid()),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| i32::from(metadata.version().get())),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| i64::try_from(metadata.encoded_size()))
            .transpose()
            .map_err(|_| StoreError::corrupt_data("JobIR size exceeds PostgreSQL BIGINT"))?,
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.digest().as_bytes().to_vec()),
    )
    .bind(
        outcome
            .claimed_job_ir()
            .map(|metadata| metadata.object_key().as_str()),
    )
    .bind(request.observed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::invalid_operation_receipt(
            "pending receipt could not be completed",
        ));
    }
    Ok(())
}

async fn complete_no_work_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NoWorkLeaseRequest,
    outcome: &TryClaimOutcome,
    committed_cursor: Option<u64>,
) -> Result<(), StoreError> {
    let name = match outcome {
        TryClaimOutcome::NoWork => "no_work",
        TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded) => "scan_superseded",
        TryClaimOutcome::Rejected(ClaimRejection::NotRoutable) if committed_cursor.is_none() => {
            "authority_rejected"
        }
        _ => {
            return Err(StoreError::invalid_operation_receipt(
                "no-work completion received an invalid outcome",
            ));
        }
    };
    let result = sqlx::query(
        r"
        UPDATE runner_operation_receipts
        SET outcome = $3, committed_cursor_version = $4, completed_at_ms = $5
        WHERE runner_session_id = $1 AND operation_id = $2 AND outcome = 'pending'
        ",
    )
    .bind(request.request_key().session().session_id().as_uuid())
    .bind(request.request_key().operation_id().as_uuid())
    .bind(name)
    .bind(committed_cursor.map(cursor_version_i64).transpose()?)
    .bind(request.observed_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::invalid_operation_receipt(
            "pending no-work receipt could not be completed",
        ));
    }
    Ok(())
}

async fn replay_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: LeaseRequestKey,
) -> Result<TryClaimReceipt, StoreError> {
    let row = claim_receipt_row(transaction, request)
        .await?
        .ok_or_else(|| StoreError::invalid_operation_receipt("conflicting receipt disappeared"))?;
    decode_claim_receipt(&row, request, true)
}

async fn claim_receipt_row(
    transaction: &mut Transaction<'_, Postgres>,
    request: LeaseRequestKey,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query(
        r"
        SELECT operation_kind, selection_kind, request_digest, outcome,
               scan_cursor_version, committed_cursor_version, claimed_fencing_token,
               rejection_lifecycle, occupied_attempt_id, requested_attempt_id,
               requested_lease_id, runner_slot, observed_at_ms, lease_expires_at_ms,
               claimed_job_id, claimed_run_id, claimed_job_ir_schema,
               claimed_job_ir_size_bytes, claimed_job_ir_digest,
               claimed_job_ir_object_key
        FROM runner_operation_receipts
        WHERE runner_session_id = $1 AND operation_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.session().session_id().as_uuid())
    .bind(request.operation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

fn decode_claim_receipt(
    row: &sqlx::postgres::PgRow,
    request: LeaseRequestKey,
    replayed: bool,
) -> Result<TryClaimReceipt, StoreError> {
    let kind: &str = row.try_get("operation_kind").map_err(operation_error)?;
    let stored_digest =
        crate::value::decode_sha256_digest(row.try_get("request_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::invalid_operation_receipt(error.to_string()))?;
    let raw_slot: i32 = row.try_get("runner_slot").map_err(operation_error)?;
    let stored_slot = u16::try_from(raw_slot)
        .ok()
        .and_then(|value| StableRunnerSlot::new(value).ok())
        .ok_or_else(|| StoreError::invalid_operation_receipt("invalid runner slot"))?;
    if kind != LEASE_OPERATION_KIND
        || stored_digest != request.request_digest()
        || stored_slot != request.slot()
    {
        return Err(StoreError::OperationConflict {
            session_id: request.session().session_id(),
            operation_id: request.operation_id(),
        });
    }
    let name: &str = row.try_get("outcome").map_err(operation_error)?;
    let outcome = match name {
        "claimed" => {
            let attempt_id = receipt_attempt_id(row)?;
            let lease_id = receipt_lease_id(row)?;
            let observed_at = receipt_observed_at(row)?;
            let expires_at = receipt_expires_at(row)?;
            let raw_fence: i64 = row
                .try_get::<Option<i64>, _>("claimed_fencing_token")
                .map_err(operation_error)?
                .ok_or_else(|| StoreError::invalid_operation_receipt("claimed fence missing"))?;
            let fencing_token = crate::operation::decode_fencing_token(raw_fence)?;
            let lease = Lease::new(
                lease_id,
                attempt_id,
                request.session().runner_id(),
                fencing_token,
                observed_at,
                expires_at,
            )
            .map_err(|error| StoreError::invalid_operation_receipt(error.to_string()))?;
            let claimed = ClaimedAttempt::try_new(
                lease,
                AttemptAssignment::new(request.session(), stored_slot),
                decode_receipt_job_ir(row)?,
            )
            .map_err(|error| StoreError::invalid_operation_receipt(error.to_string()))?;
            TryClaimOutcome::Claimed(Box::new(claimed))
        }
        "attempt_not_found" => TryClaimOutcome::Rejected(ClaimRejection::AttemptNotFound),
        "not_queued" => {
            let lifecycle: &str = row
                .try_get::<Option<&str>, _>("rejection_lifecycle")
                .map_err(operation_error)?
                .ok_or_else(|| StoreError::invalid_operation_receipt("lifecycle missing"))?;
            TryClaimOutcome::Rejected(ClaimRejection::AttemptNotQueued(parse_lifecycle_store(
                lifecycle,
            )?))
        }
        "not_routable" | "authority_rejected" => {
            TryClaimOutcome::Rejected(ClaimRejection::NotRoutable)
        }
        "not_runnable" => TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable),
        "slot_out_of_range" => TryClaimOutcome::Rejected(ClaimRejection::SlotOutOfRange),
        "slot_occupied" => {
            let attempt_id: Uuid = row
                .try_get::<Option<Uuid>, _>("occupied_attempt_id")
                .map_err(operation_error)?
                .ok_or_else(|| StoreError::invalid_operation_receipt("occupied attempt missing"))?;
            TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied {
                attempt_id: AttemptId::from_uuid(attempt_id),
            })
        }
        "scan_superseded" => TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded),
        "no_work" => TryClaimOutcome::NoWork,
        "pending" => {
            return Err(StoreError::invalid_operation_receipt(
                "pending receipt escaped its transaction",
            ));
        }
        other => {
            return Err(StoreError::invalid_operation_receipt(format!(
                "unknown outcome {other:?}"
            )));
        }
    };
    Ok(TryClaimReceipt::new(request, outcome, replayed))
}

fn decode_receipt_job_ir(row: &sqlx::postgres::PgRow) -> Result<JobIrMetadata, StoreError> {
    let job_id = row
        .try_get::<Option<Uuid>, _>("claimed_job_id")
        .map_err(operation_error)?
        .map(JobId::from_uuid)
        .ok_or_else(|| StoreError::invalid_operation_receipt("claimed job missing"))?;
    let run_id = row
        .try_get::<Option<Uuid>, _>("claimed_run_id")
        .map_err(operation_error)?
        .map(RunId::from_uuid)
        .ok_or_else(|| StoreError::invalid_operation_receipt("claimed run missing"))?;
    let version = row
        .try_get::<Option<i32>, _>("claimed_job_ir_schema")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::invalid_operation_receipt("claimed JobIR version missing"))
        .and_then(decode_job_ir_version)?;
    let size = row
        .try_get::<Option<i64>, _>("claimed_job_ir_size_bytes")
        .map_err(operation_error)?
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| StoreError::invalid_operation_receipt("claimed JobIR size missing"))?;
    let digest = row
        .try_get::<Option<Vec<u8>>, _>("claimed_job_ir_digest")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::invalid_operation_receipt("claimed JobIR digest missing"))
        .and_then(|value| {
            crate::value::decode_sha256_digest(value)
                .map_err(|error| StoreError::invalid_operation_receipt(error.to_string()))
        })?;
    let object_key = row
        .try_get::<Option<String>, _>("claimed_job_ir_object_key")
        .map_err(operation_error)?
        .ok_or_else(|| StoreError::invalid_operation_receipt("claimed JobIR key missing"))
        .and_then(|value| {
            ObjectKey::new(value)
                .map_err(|error| StoreError::invalid_operation_receipt(error.to_string()))
        })?;
    JobIrMetadata::new(job_id, run_id, version, size, digest, object_key)
        .map_err(|error| StoreError::invalid_operation_receipt(error.to_string()))
}

fn receipt_attempt_id(row: &sqlx::postgres::PgRow) -> Result<AttemptId, StoreError> {
    row.try_get::<Option<Uuid>, _>("requested_attempt_id")
        .map_err(operation_error)?
        .map(AttemptId::from_uuid)
        .ok_or_else(|| StoreError::invalid_operation_receipt("selected attempt missing"))
}

fn receipt_lease_id(row: &sqlx::postgres::PgRow) -> Result<automata_core::LeaseId, StoreError> {
    row.try_get::<Option<Uuid>, _>("requested_lease_id")
        .map_err(operation_error)?
        .map(automata_core::LeaseId::from_uuid)
        .ok_or_else(|| StoreError::invalid_operation_receipt("selected lease missing"))
}

fn receipt_observed_at(row: &sqlx::postgres::PgRow) -> Result<UnixMillis, StoreError> {
    Ok(UnixMillis::new(
        row.try_get("observed_at_ms").map_err(operation_error)?,
    ))
}

fn receipt_expires_at(row: &sqlx::postgres::PgRow) -> Result<UnixMillis, StoreError> {
    row.try_get::<Option<i64>, _>("lease_expires_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new)
        .ok_or_else(|| StoreError::invalid_operation_receipt("selected lease expiry missing"))
}

fn session_query(
    fence: RunnerSessionFence,
) -> sqlx::query::Query<'static, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        r"
        SELECT protocol_version, job_ir_schema, capability_snapshot::text AS capability_snapshot,
               connected_at_ms, heartbeat_at_ms, disconnected_at_ms,
               acknowledged_command_sequence
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation()).unwrap_or_default())
    .bind(epoch_i64(fence.session_epoch()).unwrap_or_default())
}

async fn locked_session(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
) -> Result<RunnerSessionSnapshot, StoreError> {
    let row = sqlx::query(
        r"
        SELECT protocol_version, job_ir_schema, capability_snapshot::text AS capability_snapshot,
               connected_at_ms, heartbeat_at_ms, disconnected_at_ms,
               acknowledged_command_sequence
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        FOR UPDATE
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::fence_rejected(fence.session_id()))?;
    decode_session(&row, fence)
}

async fn update_session_liveness(
    transaction: &mut Transaction<'_, Postgres>,
    fence: RunnerSessionFence,
    requested_cursor: CommandCursor,
    observed_at: UnixMillis,
    current: &RunnerSessionSnapshot,
) -> Result<(), StoreError> {
    if observed_at < current.heartbeat_at() {
        return Err(StoreError::SessionTimeRegression {
            session_id: fence.session_id(),
            observed_at,
            durable_at: current.heartbeat_at(),
        });
    }
    let last_sequence: i64 = sqlx::query_scalar(
        r"
        SELECT last_command_sequence
        FROM runner_sessions
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let available = decode_cursor(last_sequence)?;
    if requested_cursor.durable_value() > available.durable_value() {
        return Err(StoreError::CommandCursorAhead {
            session_id: fence.session_id(),
            requested: requested_cursor,
            available,
        });
    }
    sqlx::query(
        r"
        UPDATE runner_sessions
        SET heartbeat_at_ms = $5,
            acknowledged_command_sequence = greatest(
                acknowledged_command_sequence, $6
            )
        WHERE id = $1 AND runner_id = $2
          AND runner_generation = $3 AND session_epoch = $4
          AND disconnected_at_ms IS NULL
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(generation_i64(fence.runner_generation())?)
    .bind(epoch_i64(fence.session_epoch())?)
    .bind(observed_at.get())
    .bind(cursor_i64(requested_cursor)?)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        UPDATE runners
        SET last_seen_at_ms = greatest(coalesce(last_seen_at_ms, $2), $2),
            updated_at_ms = greatest(updated_at_ms, $2)
        WHERE id = $1 AND generation = $3
        ",
    )
    .bind(fence.runner_id().as_uuid())
    .bind(observed_at.get())
    .bind(generation_i64(fence.runner_generation())?)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    acknowledge_cancellations_through(transaction, fence, requested_cursor, observed_at).await?;
    Ok(())
}

fn decode_session(
    row: &sqlx::postgres::PgRow,
    fence: RunnerSessionFence,
) -> Result<RunnerSessionSnapshot, StoreError> {
    let protocol = u16::try_from(
        row.try_get::<i32, _>("protocol_version")
            .map_err(operation_error)?,
    )
    .ok()
    .and_then(|value| RunnerProtocolVersion::new(value).ok())
    .ok_or_else(|| StoreError::corrupt_data("invalid runner protocol version"))?;
    let version = decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let capabilities = RoutingDocument::new(
        row.try_get::<String, _>("capability_snapshot")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let connected_at = UnixMillis::new(row.try_get("connected_at_ms").map_err(operation_error)?);
    let heartbeat_at = UnixMillis::new(row.try_get("heartbeat_at_ms").map_err(operation_error)?);
    let disconnected_at = row
        .try_get::<Option<i64>, _>("disconnected_at_ms")
        .map_err(operation_error)?
        .map(UnixMillis::new);
    let command_cursor = decode_cursor(
        row.try_get("acknowledged_command_sequence")
            .map_err(operation_error)?,
    )?;
    RunnerSessionSnapshot::try_new(
        fence,
        protocol,
        version,
        capabilities,
        connected_at,
        heartbeat_at,
        disconnected_at,
        command_cursor,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_routing(
    row: &sqlx::postgres::PgRow,
    fence: RunnerSessionFence,
) -> Result<RunnerRoutingSnapshot, StoreError> {
    let group_id = row
        .try_get::<Option<Uuid>, _>("group_id")
        .map_err(operation_error)?
        .map(RunnerGroupId::from_uuid);
    let group_name: Option<String> = row.try_get("group_name").map_err(operation_error)?;
    let group = match (group_id, group_name) {
        (None, None) => None,
        (Some(id), Some(name)) => Some((id, name)),
        _ => {
            return Err(StoreError::corrupt_data(
                "partial runner group routing identity",
            ));
        }
    };
    let labels = row
        .try_get::<Vec<String>, _>("labels")
        .map_err(operation_error)?
        .into_iter()
        .map(|label| {
            RoutingLabel::new(label).map_err(|error| StoreError::corrupt_data(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let registered = RoutingDocument::new(
        row.try_get::<String, _>("registered_capabilities")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let negotiated = RoutingDocument::new(
        row.try_get::<String, _>("negotiated_capabilities")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let slots = u16::try_from(row.try_get::<i32, _>("slots").map_err(operation_error)?)
        .ok()
        .and_then(|value| RunnerSlotCount::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid registered runner slots"))?;
    let job_ir_version =
        decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    RunnerRoutingSnapshot::try_new(
        fence,
        group,
        labels,
        registered,
        negotiated,
        slots,
        job_ir_version,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn decode_routing_labels(
    raw: Vec<String>,
    duplicate_message: &'static str,
) -> Result<BTreeSet<RoutingLabel>, StoreError> {
    let raw_len = raw.len();
    let labels = raw
        .into_iter()
        .map(|label| {
            RoutingLabel::new(label).map_err(|error| StoreError::corrupt_data(error.to_string()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if labels.len() != raw_len {
        return Err(StoreError::corrupt_data(duplicate_message));
    }
    Ok(labels)
}

fn decode_runnable_attempt(row: &sqlx::postgres::PgRow) -> Result<RunnableAttempt, StoreError> {
    let attempt_id = AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?);
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let run_id = RunId::from_uuid(row.try_get("run_id").map_err(operation_error)?);
    let queued_at = UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?);
    let requirements_value: serde_json::Value =
        row.try_get("requirements").map_err(operation_error)?;
    let requirements: RunnerRequirements = serde_json::from_value(requirements_value)
        .map_err(|_| StoreError::corrupt_data("invalid durable runner requirements"))?;
    if requirements.schema_version() != RUNNER_REQUIREMENTS_SCHEMA_VERSION {
        return Err(StoreError::corrupt_data(format!(
            "unsupported runner requirements schema {}",
            requirements.schema_version()
        )));
    }
    let version = decode_job_ir_version(row.try_get("job_ir_schema").map_err(operation_error)?)?;
    let size = u64::try_from(
        row.try_get::<i64, _>("job_ir_size_bytes")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("negative JobIR size"))?;
    let digest =
        crate::value::decode_sha256_digest(row.try_get("job_ir_digest").map_err(operation_error)?)
            .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let key = ObjectKey::new(
        row.try_get::<String, _>("job_ir_object_key")
            .map_err(operation_error)?,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    let ir_metadata = JobIrMetadata::new(job_id, run_id, version, size, digest, key)
        .map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    RunnableAttempt::try_new(
        attempt_id,
        job_id,
        run_id,
        queued_at,
        requirements,
        ir_metadata,
    )
    .map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn operation_error(error: sqlx::Error) -> StoreError {
    StoreError::operation(error)
}

fn validate_observed_capabilities(
    runner_id: RunnerId,
    document: &str,
) -> Result<RunnerCapabilities, StoreError> {
    let capabilities: RunnerCapabilities = serde_json::from_str(document)
        .map_err(|_| StoreError::InvalidCapabilitySnapshot(runner_id))?;
    capabilities
        .validate()
        .map_err(|_| StoreError::InvalidCapabilitySnapshot(runner_id))?;
    if capabilities.runner_id() != runner_id {
        return Err(StoreError::InvalidCapabilitySnapshot(runner_id));
    }
    Ok(capabilities)
}

fn decode_generation(value: i64) -> Result<RunnerGeneration, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| RunnerGeneration::new(value).ok())
        .ok_or_else(|| StoreError::invalid_generation(value))
}

fn decode_epoch(value: i64) -> Result<SessionEpoch, StoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| SessionEpoch::new(value).ok())
        .ok_or_else(|| StoreError::invalid_session_epoch(value))
}

fn decode_cursor(value: i64) -> Result<CommandCursor, StoreError> {
    if value == 0 {
        return Ok(CommandCursor::initial());
    }
    let value =
        u64::try_from(value).map_err(|_| StoreError::corrupt_data("negative command cursor"))?;
    let sequence =
        CommandSequence::new(value).map_err(|error| StoreError::corrupt_data(error.to_string()))?;
    Ok(CommandCursor::through(sequence))
}

fn decode_sequence(value: i64) -> Result<CommandSequence, StoreError> {
    let value = u64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("negative server command sequence"))?;
    CommandSequence::new(value).map_err(|error| StoreError::corrupt_data(error.to_string()))
}

fn sequence_i64(value: CommandSequence) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("command sequence exceeds PostgreSQL BIGINT"))
}

fn cursor_i64(value: CommandCursor) -> Result<i64, StoreError> {
    i64::try_from(value.durable_value())
        .map_err(|_| StoreError::corrupt_data("command cursor exceeds PostgreSQL BIGINT"))
}

fn decode_schema(value: i32) -> Result<DocumentSchema, StoreError> {
    u16::try_from(value)
        .ok()
        .and_then(|value| DocumentSchema::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data(format!("invalid document schema {value}")))
}

fn decode_job_ir_version(value: i32) -> Result<JobIrVersion, StoreError> {
    u16::try_from(value)
        .ok()
        .and_then(|value| JobIrVersion::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid JobIR version"))
}

fn cursor_version_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("runnable cursor version exceeds PostgreSQL BIGINT"))
}

fn generation_i64(value: RunnerGeneration) -> Result<i64, StoreError> {
    i64::try_from(value.get()).map_err(|_| StoreError::invalid_generation(i64::MAX))
}

fn epoch_i64(value: SessionEpoch) -> Result<i64, StoreError> {
    i64::try_from(value.get()).map_err(|_| StoreError::invalid_session_epoch(i64::MAX))
}

fn protocol_i32(value: RunnerProtocolVersion) -> i32 {
    i32::from(value.get())
}

fn decode_protocol(value: i32) -> Result<RunnerProtocolVersion, StoreError> {
    u16::try_from(value)
        .ok()
        .and_then(|value| RunnerProtocolVersion::new(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("invalid runner protocol version"))
}

fn fence_i64(value: FencingToken) -> Result<i64, StoreError> {
    i64::try_from(value.get())
        .map_err(|_| StoreError::corrupt_data("fencing token exceeds PostgreSQL BIGINT"))
}

fn parse_lifecycle_store(value: &str) -> Result<JobLifecycle, StoreError> {
    parse_lifecycle(value).map_err(|error| StoreError::corrupt_data(error.to_string()))
}
