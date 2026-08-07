use std::{fmt, io::Write as _, sync::Arc};

use automata_auth::machine::AuthenticatedMachine;
use automata_blob::{
    BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_control::{
    AuthenticatedRunnerSession, ClaimedLeasePoll, LeaseClock, LeasePollError, LeasePollOutcome,
};
use automata_core::{JobIrVersionRange, LogAck, OperationId, Sha256Digest, UnixMillis};
use automata_protocol::{
    CommandAck, CommandCursor, CommandSequence, ErrorMessage, HandshakeErrorCode,
    HandshakeRejected, LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRenewal, LogAckMessage,
    MessageHeader, NegotiatedSession, NoWork, OperationAck, OrphanDeliveryPermissions,
    ProtocolLimits, RemoteErrorCode, RunnerHello, RunnerToServer, SUPPORTED_PROTOCOL_RANGE,
    ServerCommandHeader, ServerHello, ServerTiming, ServerToRunner, SessionDisposition,
    SessionOrphanAuthorization, ValidatedRunnerToServer, negotiate_job_ir, negotiate_protocol,
};
use automata_protocol_protobuf::{
    decode_server_frame as decode_server_protobuf, encode_server_frame,
};
use automata_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerRequest, HandlerFuture,
    RunnerControlHandler,
};
use automata_store::{
    AcknowledgeRunnerCommands, AttemptStoreError, BeginLeaseRequest,
    CommandCursor as StoreCommandCursor, CommandReplayLimit,
    CommandSequence as StoreCommandSequence, CommitCommandAcknowledgement, CommitLeaseHeartbeat,
    CommitLeaseResponse, CommitRunnerLogSegment, CommitRunnerTerminalResult, CompleteLeaseRequest,
    DocumentSchema, HeartbeatRunnerSession, LeaseRequestKey, LeaseResponseAction, ObjectKey,
    OpenRunnerSession, RenewLease, ResumeRunnerSession, RoutingDocument, RunnerCommandOutbox,
    RunnerControlTransactionRepository, RunnerLeaseRequestRepository, RunnerOperationKind,
    RunnerOperationReceipt, RunnerOperationReceiptRepository, RunnerOperationRequest,
    RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionFence, RunnerSessionRepository,
    RunnerSessionSnapshot, StableRunnerSlot, StoreError,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::port::{
    AuthorizedRunnerRegistration, ControlIdGenerator, ControlPortError, DesiredRunnerState,
    JobIrObjectReader, LeaseOfferClaim, LeaseOfferClaimStatus, LeaseOfferCommand,
    LeaseOfferCommandPublisher, LeaseOfferPublishOutcome, LeasePoller,
    RunnerRegistrationAuthorizer, RunnerSessionFenceResolver, RuntimeAuthorityIssueRequest,
    RuntimeAuthorityIssuer, decode_durable_server_command, is_durable_lease_offer_command,
};
use crate::verify::verify_job_ir_blob;

const HEARTBEAT_KIND: &str = "automata.runner.lease-heartbeat.v1";
const COMMAND_ACK_KIND: &str = "automata.runner.command-ack.v1";
const LEASE_RESPONSE_KIND: &str = "automata.runner.lease-response.v1";
const JOB_RESULT_KIND: &str = "automata.runner.job-result.v1";
const LOG_BATCH_KIND: &str = "automata.runner.log-batch.v1";
const JOB_RESULT_MEDIA_TYPE: &str = "application/vnd.automata.job-result+json";
const LOG_SEGMENT_MEDIA_TYPE: &str = "application/vnd.automata.log-segment+json+gzip";

/// Largest supported heartbeat interval: five minutes.
pub const MAX_HEARTBEAT_INTERVAL_MILLIS: u32 = 5 * 60 * 1_000;
/// Largest supported lease duration: thirty minutes.
pub const MAX_LEASE_DURATION_MILLIS: u32 = 30 * 60 * 1_000;
/// Largest supported no-work backoff: five minutes.
pub const MAX_NO_WORK_RETRY_AFTER_MILLIS: u32 = 5 * 60 * 1_000;

/// Validated server timing and response limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerControlConfig {
    heartbeat_interval_millis: u32,
    lease_duration_millis: u32,
    no_work_retry_after_millis: u32,
    protocol_limits: ProtocolLimits,
}

impl RunnerControlConfig {
    /// Creates bounded timing policy with at least two heartbeat opportunities per lease.
    ///
    /// # Errors
    /// Returns a typed error when a duration is zero, exceeds its G1 bound, or the lease is less
    /// than twice the heartbeat interval.
    pub const fn new(
        heartbeat_interval_millis: u32,
        lease_duration_millis: u32,
        no_work_retry_after_millis: u32,
        protocol_limits: ProtocolLimits,
    ) -> Result<Self, RunnerControlConfigError> {
        if heartbeat_interval_millis == 0
            || lease_duration_millis == 0
            || no_work_retry_after_millis == 0
        {
            return Err(RunnerControlConfigError::ZeroDuration);
        }
        if heartbeat_interval_millis > MAX_HEARTBEAT_INTERVAL_MILLIS {
            return Err(RunnerControlConfigError::HeartbeatIntervalTooLarge {
                value: heartbeat_interval_millis,
                maximum: MAX_HEARTBEAT_INTERVAL_MILLIS,
            });
        }
        if lease_duration_millis > MAX_LEASE_DURATION_MILLIS {
            return Err(RunnerControlConfigError::LeaseDurationTooLarge {
                value: lease_duration_millis,
                maximum: MAX_LEASE_DURATION_MILLIS,
            });
        }
        if no_work_retry_after_millis > MAX_NO_WORK_RETRY_AFTER_MILLIS {
            return Err(RunnerControlConfigError::NoWorkRetryAfterTooLarge {
                value: no_work_retry_after_millis,
                maximum: MAX_NO_WORK_RETRY_AFTER_MILLIS,
            });
        }
        if heartbeat_interval_millis > lease_duration_millis / 2 {
            return Err(RunnerControlConfigError::LeaseDurationTooShort {
                heartbeat_interval_millis,
                lease_duration_millis,
            });
        }
        Ok(Self {
            heartbeat_interval_millis,
            lease_duration_millis,
            no_work_retry_after_millis,
            protocol_limits,
        })
    }

    /// Returns the heartbeat interval sent to a runner.
    #[must_use]
    pub const fn heartbeat_interval_millis(self) -> u32 {
        self.heartbeat_interval_millis
    }
    /// Returns the trusted lease extension.
    #[must_use]
    pub const fn lease_duration_millis(self) -> u32 {
        self.lease_duration_millis
    }
    /// Returns the bounded no-work retry delay.
    #[must_use]
    pub const fn no_work_retry_after_millis(self) -> u32 {
        self.no_work_retry_after_millis
    }
    /// Returns protocol allocation limits.
    #[must_use]
    pub const fn protocol_limits(self) -> ProtocolLimits {
        self.protocol_limits
    }
}

impl Default for RunnerControlConfig {
    fn default() -> Self {
        Self::new(15_000, 60_000, 1_000, ProtocolLimits::default())
            .expect("default runner-control timing policy is valid")
    }
}

/// Invalid runner-control policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerControlConfigError {
    /// A configured timing duration was zero.
    #[error("runner control durations must be nonzero")]
    ZeroDuration,
    /// Heartbeats are too sparse for the supported liveness policy.
    #[error("heartbeat interval {value}ms exceeds the {maximum}ms maximum")]
    HeartbeatIntervalTooLarge {
        /// Rejected configured value.
        value: u32,
        /// Supported maximum.
        maximum: u32,
    },
    /// A lease is too long for bounded G1 recovery.
    #[error("lease duration {value}ms exceeds the {maximum}ms maximum")]
    LeaseDurationTooLarge {
        /// Rejected configured value.
        value: u32,
        /// Supported maximum.
        maximum: u32,
    },
    /// A no-work response could make a runner idle for too long.
    #[error("no-work retry delay {value}ms exceeds the {maximum}ms maximum")]
    NoWorkRetryAfterTooLarge {
        /// Rejected configured value.
        value: u32,
        /// Supported maximum.
        maximum: u32,
    },
    /// The lease does not permit two full heartbeat intervals.
    #[error(
        "lease duration {lease_duration_millis}ms must be at least twice heartbeat interval {heartbeat_interval_millis}ms"
    )]
    LeaseDurationTooShort {
        /// Configured heartbeat interval.
        heartbeat_interval_millis: u32,
        /// Configured lease duration.
        lease_duration_millis: u32,
    },
}

/// Authentication and durable-session collaborators.
pub struct RunnerIdentityPorts {
    authorizer: Arc<dyn RunnerRegistrationAuthorizer>,
    fence_resolver: Arc<dyn RunnerSessionFenceResolver>,
    sessions: Arc<dyn RunnerSessionRepository>,
}

impl RunnerIdentityPorts {
    /// Groups the authority resolver and durable session repository.
    #[must_use]
    pub const fn new(
        authorizer: Arc<dyn RunnerRegistrationAuthorizer>,
        fence_resolver: Arc<dyn RunnerSessionFenceResolver>,
        sessions: Arc<dyn RunnerSessionRepository>,
    ) -> Self {
        Self {
            authorizer,
            fence_resolver,
            sessions,
        }
    }
}

impl fmt::Debug for RunnerIdentityPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerIdentityPorts")
            .finish_non_exhaustive()
    }
}

/// Scheduler and immutable lease-offer collaborators.
pub struct RunnerLeasePorts {
    lease_poller: Arc<dyn LeasePoller>,
    job_ir_objects: Arc<dyn JobIrObjectReader>,
    lease_offers: Arc<dyn LeaseOfferCommandPublisher>,
}

impl RunnerLeasePorts {
    /// Groups scheduling, immutable `JobIR`, and typed offer publication.
    #[must_use]
    pub const fn new(
        lease_poller: Arc<dyn LeasePoller>,
        job_ir_objects: Arc<dyn JobIrObjectReader>,
        lease_offers: Arc<dyn LeaseOfferCommandPublisher>,
    ) -> Self {
        Self {
            lease_poller,
            job_ir_objects,
            lease_offers,
        }
    }
}

impl fmt::Debug for RunnerLeasePorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerLeasePorts").finish_non_exhaustive()
    }
}

/// Durable ingress, transactions, receipts, and server-command outbox.
pub struct RunnerDurabilityPorts {
    ingress_objects: Arc<dyn ImmutableBlobStore>,
    transactions: Arc<dyn RunnerControlTransactionRepository>,
    receipts: Arc<dyn RunnerOperationReceiptRepository>,
    lease_requests: Arc<dyn RunnerLeaseRequestRepository>,
    commands: Arc<dyn RunnerCommandOutbox>,
}

impl RunnerDurabilityPorts {
    /// Groups ingress persistence, atomic mutations, receipts, and command replay.
    #[must_use]
    pub const fn new(
        ingress_objects: Arc<dyn ImmutableBlobStore>,
        transactions: Arc<dyn RunnerControlTransactionRepository>,
        receipts: Arc<dyn RunnerOperationReceiptRepository>,
        lease_requests: Arc<dyn RunnerLeaseRequestRepository>,
        commands: Arc<dyn RunnerCommandOutbox>,
    ) -> Self {
        Self {
            ingress_objects,
            transactions,
            receipts,
            lease_requests,
            commands,
        }
    }
}

impl fmt::Debug for RunnerDurabilityPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerDurabilityPorts")
            .finish_non_exhaustive()
    }
}

/// Shared, replica-neutral ports used by [`DurableRunnerControlHandler`].
pub struct RunnerControlPorts {
    identity: RunnerIdentityPorts,
    lease: RunnerLeasePorts,
    durability: RunnerDurabilityPorts,
    runtime_authorities: Option<Arc<dyn RuntimeAuthorityIssuer>>,
    clock: Arc<dyn LeaseClock>,
    ids: Arc<dyn ControlIdGenerator>,
}

impl fmt::Debug for RunnerControlPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerControlPorts").finish_non_exhaustive()
    }
}

impl RunnerControlPorts {
    /// Composes all shared-state and trusted-source ports.
    #[must_use]
    pub fn new(
        identity: RunnerIdentityPorts,
        lease: RunnerLeasePorts,
        durability: RunnerDurabilityPorts,
        clock: Arc<dyn LeaseClock>,
        ids: Arc<dyn ControlIdGenerator>,
    ) -> Self {
        Self {
            identity,
            lease,
            durability,
            runtime_authorities: None,
            clock,
            ids,
        }
    }

    /// Installs the mandatory, server-side per-attempt authority issuer.
    ///
    /// Without this adapter the handler refuses to construct a lease offer.
    #[must_use]
    pub fn with_runtime_authority_issuer(
        mut self,
        issuer: Arc<dyn RuntimeAuthorityIssuer>,
    ) -> Self {
        self.runtime_authorities = Some(issuer);
        self
    }
}

/// mTLS-authenticated, durable runner-control application handler.
pub struct DurableRunnerControlHandler {
    ports: RunnerControlPorts,
    config: RunnerControlConfig,
}

impl fmt::Debug for DurableRunnerControlHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableRunnerControlHandler")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DurableRunnerControlHandler {
    /// Creates a stateless handler over shared durable ports.
    #[must_use]
    pub const fn new(ports: RunnerControlPorts, config: RunnerControlConfig) -> Self {
        Self { ports, config }
    }

    /// Handles a validated hello using a fresh authenticated machine assertion.
    ///
    /// # Errors
    /// Returns a sanitized application error for cancellation, unavailable/corrupt shared state,
    /// or an invariant violation. Authentication and negotiation failures are correlated protocol
    /// rejections.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_handshake(
        &self,
        machine: &AuthenticatedMachine,
        hello: &RunnerHello,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        Self::not_cancelled(cancellation)?;
        let registration = match self.ports.identity.authorizer.authorize(machine).await {
            Ok(Some(value)) if registration_matches(machine, &value) => value,
            Ok(_) => return Ok(self.reject(hello, HandshakeErrorCode::Unauthorized)),
            Err(error) => return Err(port_application_error(error)),
        };
        if registration.runner_id() != hello.runner().runner_id()
            || registration.desired_state() == DesiredRunnerState::Disabled
        {
            return Ok(self.reject(hello, HandshakeErrorCode::Unauthorized));
        }
        let Ok(protocol) = negotiate_protocol(SUPPORTED_PROTOCOL_RANGE, hello.supported_protocol())
        else {
            return Ok(self.reject(hello, HandshakeErrorCode::UnsupportedProtocol));
        };
        let Ok(job_ir) = negotiate_job_ir(JobIrVersionRange::current(), hello.supported_job_ir())
        else {
            return Ok(self.reject(hello, HandshakeErrorCode::UnsupportedJobIr));
        };
        let now = self.ports.clock.now();
        let snapshot = if let Some(resume) = hello.resume() {
            let Some(fence) = self
                .ports
                .identity
                .fence_resolver
                .resolve_current(
                    registration.runner_id(),
                    registration.generation(),
                    resume.session_id(),
                )
                .await
                .map_err(port_application_error)?
            else {
                return Ok(self.reject_non_resumable(hello, resume.session_id()));
            };
            let current = match self.ports.identity.sessions.get_session(fence).await {
                Ok(value) => value,
                Err(error) if is_handshake_rejection(&error) => {
                    return Ok(self.reject_non_resumable(hello, resume.session_id()));
                }
                Err(error) => return Err(store_application_error(error)),
            };
            if !snapshot_matches(
                &current,
                &registration,
                protocol,
                job_ir,
                resume.session_id(),
            ) {
                return Ok(self.reject_non_resumable(hello, resume.session_id()));
            }
            Self::not_cancelled(cancellation)?;
            match self
                .ports
                .identity
                .sessions
                .resume_session(ResumeRunnerSession::new(
                    registration.runner_id(),
                    registration.generation(),
                    resume.session_id(),
                    protocol_cursor_to_store(resume.command_cursor())?,
                    now,
                ))
                .await
            {
                Ok(value) => value,
                Err(error) if is_handshake_rejection(&error) => {
                    return Ok(self.reject_non_resumable(hello, resume.session_id()));
                }
                Err(error) => return Err(store_application_error(error)),
            }
        } else {
            if registration.desired_state() != DesiredRunnerState::Active {
                return Ok(self.reject(hello, HandshakeErrorCode::Unauthorized));
            }
            let mut observed = hello.runner().clone();
            observed = observed
                .with_labels(std::iter::empty())
                .with_groups(std::iter::empty());
            let json = serde_json::to_string(&observed)
                .map_err(|_| app(ApplicationErrorKind::Internal))?;
            let capabilities =
                RoutingDocument::new(json).map_err(|_| app(ApplicationErrorKind::Internal))?;
            Self::not_cancelled(cancellation)?;
            match self
                .ports
                .identity
                .sessions
                .open_session(OpenRunnerSession::new(
                    self.ports.ids.next_session_id(),
                    registration.runner_id(),
                    registration.generation(),
                    RunnerProtocolVersion::new(protocol.get())
                        .map_err(|_| app(ApplicationErrorKind::Internal))?,
                    job_ir,
                    capabilities,
                    now,
                ))
                .await
            {
                Ok(value) => value,
                Err(error) if is_handshake_rejection(&error) => {
                    return Ok(self.reject(hello, HandshakeErrorCode::Unauthorized));
                }
                Err(error) => return Err(store_application_error(error)),
            }
        };
        if snapshot.job_ir_version() != automata_core::JobIrVersion::current()
            || !snapshot_matches(
                &snapshot,
                &registration,
                protocol,
                job_ir,
                snapshot.fence().session_id(),
            )
        {
            return Err(app(ApplicationErrorKind::Internal));
        }
        let disposition = if hello.resume().is_some() {
            SessionDisposition::Resumed
        } else {
            SessionDisposition::Opened
        };
        Ok(ServerToRunner::Hello(ServerHello::new(
            self.ports.ids.next_operation_id(),
            hello.operation_id(),
            NegotiatedSession::new(
                protocol,
                job_ir,
                snapshot.fence().session_id(),
                disposition,
                store_cursor_to_protocol(snapshot.command_cursor())?,
            ),
            ServerTiming::new(
                now,
                self.config.heartbeat_interval_millis,
                self.config.lease_duration_millis,
            ),
        )))
    }

    /// Handles one validated post-handshake message and canonical request byte string.
    ///
    /// # Errors
    /// Returns a sanitized application error if fresh authentication, durable session fencing,
    /// cancellation, receipt validation, or a supported mutation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_sync(
        &self,
        machine: &AuthenticatedMachine,
        message: &ValidatedRunnerToServer,
        canonical_bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        Self::not_cancelled(cancellation)?;
        let runner_message = message.message();
        let header =
            runner_header(runner_message).ok_or_else(|| app(ApplicationErrorKind::Conflict))?;
        let registration = self
            .ports
            .identity
            .authorizer
            .authorize(machine)
            .await
            .map_err(port_application_error)?
            .filter(|value| registration_matches(machine, value))
            .ok_or_else(|| app(ApplicationErrorKind::Forbidden))?;
        if registration.desired_state() == DesiredRunnerState::Disabled {
            return Err(app(ApplicationErrorKind::Forbidden));
        }
        let fence = self
            .ports
            .identity
            .fence_resolver
            .resolve_current(
                registration.runner_id(),
                registration.generation(),
                header.session_id(),
            )
            .await
            .map_err(port_application_error)?
            .ok_or_else(|| app(ApplicationErrorKind::StaleSession))?;
        let snapshot = self
            .ports
            .identity
            .sessions
            .get_session(fence)
            .await
            .map_err(store_application_error)?;
        if !snapshot_matches(
            &snapshot,
            &registration,
            header.protocol_version(),
            snapshot.job_ir_version(),
            header.session_id(),
        ) || !snapshot.is_live()
        {
            return Err(app(ApplicationErrorKind::StaleSession));
        }
        let is_command_ack = matches!(runner_message, RunnerToServer::CommandAck(_));
        let replay_after = match runner_message {
            RunnerToServer::CommandAck(ack) => protocol_cursor_to_store(ack.command_cursor())?,
            _ => snapshot.command_cursor(),
        };
        let digest = sha256(canonical_bytes);
        if let RunnerToServer::LeaseRequest(request) = runner_message {
            return self
                .handle_lease_request(
                    fence,
                    &snapshot,
                    request,
                    digest,
                    replay_after,
                    cancellation,
                )
                .await;
        }
        if !is_command_ack
            && let Some(command) = self
                .next_pending_command(fence, snapshot.protocol_version(), replay_after)
                .await?
        {
            return Ok(command);
        }
        let response = match runner_message {
            RunnerToServer::Heartbeat(heartbeat) => {
                self.handle_heartbeat(fence, &snapshot, heartbeat, digest, cancellation)
                    .await
            }
            RunnerToServer::LeaseResponse(response) => {
                self.handle_lease_response(fence, &snapshot, response, digest, cancellation)
                    .await
            }
            RunnerToServer::JobResult(result) => {
                self.handle_job_result(fence, result, digest, cancellation)
                    .await
            }
            RunnerToServer::LogBatch(batch) => {
                self.handle_log_batch(fence, batch, digest, cancellation)
                    .await
            }
            RunnerToServer::CommandAck(ack) => {
                self.handle_command_ack(fence, &snapshot, *ack, digest, cancellation)
                    .await
            }
            RunnerToServer::Hello(_) => Err(app(ApplicationErrorKind::Conflict)),
            _ => Ok(self.unsupported(header)),
        }?;
        if let Some(command) = self
            .next_pending_command(fence, snapshot.protocol_version(), replay_after)
            .await?
        {
            return Ok(command);
        }
        Ok(response)
    }

    /// Handles one transport-facing sync exchange after independent machine authentication.
    ///
    /// A stale durable fence is a recoverable session outcome for the runner, not a generic HTTP
    /// conflict. Only that application outcome is converted into a correlated protocol error;
    /// authorization, conflict, cancellation, availability, and internal failures retain their
    /// original transport semantics.
    ///
    /// # Errors
    ///
    /// Returns the unchanged application failure for every outcome other than a stale session.
    pub async fn handle_transport_sync(
        &self,
        machine: &AuthenticatedMachine,
        message: &ValidatedRunnerToServer,
        canonical_bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let request_header = runner_header(message.message());
        let result = self
            .handle_sync(machine, message, canonical_bytes, cancellation)
            .await;
        match (request_header, result) {
            (Some(request_header), Err(error))
                if error.kind() == ApplicationErrorKind::StaleSession =>
            {
                Ok(ServerToRunner::Error(ErrorMessage::new(
                    self.reply_header(request_header),
                    RemoteErrorCode::StaleSession,
                    "runner session is stale",
                    false,
                )))
            }
            (_, result) => result,
        }
    }

    async fn next_pending_command(
        &self,
        fence: RunnerSessionFence,
        protocol: RunnerProtocolVersion,
        after: StoreCommandCursor,
    ) -> Result<Option<ServerToRunner>, ApplicationError> {
        let limit = CommandReplayLimit::new(1).map_err(|_| app(ApplicationErrorKind::Internal))?;
        let mut commands = self
            .ports
            .durability
            .commands
            .replay_commands(fence, after, limit)
            .await
            .map_err(store_application_error)?;
        let Some(command) = commands.pop() else {
            return Ok(None);
        };
        if !commands.is_empty() || command.request().session() != fence {
            return Err(app(ApplicationErrorKind::Internal));
        }
        let protocol_version = automata_protocol::ProtocolVersion::new(protocol.get())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let sequence = CommandSequence::new(command.sequence().get())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let resolved = self
            .ports
            .lease
            .lease_offers
            .resolve_replay(fence, command.request().operation_id(), sequence)
            .await
            .map_err(port_application_error)?;
        let command = match resolved {
            Some(resolved)
                if resolved.sequence() == command.sequence()
                    && resolved.request() == command.request() =>
            {
                resolved
            }
            Some(_) => return Err(app(ApplicationErrorKind::Internal)),
            None if is_durable_lease_offer_command(&command) => {
                return Err(app(ApplicationErrorKind::Internal));
            }
            None => command,
        };
        decode_durable_server_command(&command, protocol_version, &self.config.protocol_limits)
            .map(Some)
            .map_err(port_application_error)
    }

    async fn handle_lease_request(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        request: &automata_protocol::LeaseRequest,
        digest: Sha256Digest,
        replay_after: StoreCommandCursor,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        Self::not_cancelled(cancellation)?;
        let slot = StableRunnerSlot::new(request.slot().get())
            .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        let request_key = match request.acknowledges_operation_id() {
            Some(predecessor) => LeaseRequestKey::successor(
                fence,
                request.header().operation_id(),
                slot,
                predecessor,
            )
            .map_err(|_| app(ApplicationErrorKind::Conflict))?,
            None => LeaseRequestKey::first(fence, request.header().operation_id(), slot),
        };
        let begin = BeginLeaseRequest::new(request_key, digest);
        let admission = self
            .ports
            .durability
            .lease_requests
            .begin_lease_request(begin)
            .await
            .map_err(store_application_error)?;
        Self::not_cancelled(cancellation)?;
        self.ports
            .identity
            .sessions
            .heartbeat_session(HeartbeatRunnerSession::new(
                fence,
                snapshot.command_cursor(),
                self.ports.clock.now(),
            ))
            .await
            .map_err(store_application_error)?;
        if let Some(response) = admission.completed_response() {
            let response =
                decode_receipt(response, request.header(), &self.config.protocol_limits)?;
            return self
                .validate_lease_offer_response(fence, request.header().protocol_version(), response)
                .await;
        }
        if let Some(command) = self
            .next_pending_command(fence, snapshot.protocol_version(), replay_after)
            .await?
        {
            return self
                .complete_lease_request(begin, request.header(), command)
                .await;
        }
        Self::not_cancelled(cancellation)?;
        let outcome = self
            .ports
            .lease
            .lease_poller
            .poll(
                AuthenticatedRunnerSession::new(
                    fence,
                    request.header().protocol_version(),
                    snapshot.job_ir_version(),
                ),
                request,
            )
            .await
            .map_err(lease_poll_application_error)?;
        let response = match outcome {
            LeasePollOutcome::NoWork { .. } | LeasePollOutcome::Rejected { .. } => {
                self.no_work_response(request.header())
            }
            LeasePollOutcome::Claimed(claimed) => {
                self.build_lease_offer(fence, snapshot, request, digest, claimed, cancellation)
                    .await?
            }
        };
        let actual_response = if let Some(command) = self
            .next_pending_command(fence, snapshot.protocol_version(), replay_after)
            .await?
        {
            command
        } else {
            response
        };
        self.complete_lease_request(begin, request.header(), actual_response)
            .await
    }

    async fn complete_lease_request(
        &self,
        begin: BeginLeaseRequest,
        header: MessageHeader,
        response: ServerToRunner,
    ) -> Result<ServerToRunner, ApplicationError> {
        let durable = self.durable_response(&response)?;
        let completed = self
            .ports
            .durability
            .lease_requests
            .complete_lease_request(CompleteLeaseRequest::new(
                begin,
                durable,
                self.ports.clock.now(),
            ))
            .await
            .map_err(store_application_error)?;
        let response = decode_receipt(&completed, header, &self.config.protocol_limits)?;
        self.validate_lease_offer_response(
            begin.request_key().session(),
            header.protocol_version(),
            response,
        )
        .await
    }

    async fn validate_lease_offer_response(
        &self,
        fence: RunnerSessionFence,
        protocol_version: automata_protocol::ProtocolVersion,
        response: ServerToRunner,
    ) -> Result<ServerToRunner, ApplicationError> {
        let (operation_id, sequence, claims_offer) = match &response {
            ServerToRunner::LeaseOffer(offer) => (
                offer.header().operation_id(),
                offer.header().sequence(),
                true,
            ),
            ServerToRunner::CancelJob(cancel) => (
                cancel.header().operation_id(),
                cancel.header().sequence(),
                false,
            ),
            _ => return Ok(response),
        };
        let resolved = self
            .ports
            .lease
            .lease_offers
            .resolve_replay(fence, operation_id, sequence)
            .await
            .map_err(port_application_error)?;
        let Some(command) = resolved else {
            return if claims_offer {
                Err(app(ApplicationErrorKind::Internal))
            } else {
                Ok(response)
            };
        };
        let durable =
            decode_durable_server_command(&command, protocol_version, &self.config.protocol_limits)
                .map_err(port_application_error)?;
        if durable != response {
            return Err(app(ApplicationErrorKind::Internal));
        }
        Ok(response)
    }

    #[allow(clippy::too_many_lines)]
    async fn build_lease_offer(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        request: &automata_protocol::LeaseRequest,
        digest: Sha256Digest,
        claimed: ClaimedLeasePoll,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        Self::not_cancelled(cancellation)?;
        let metadata = claimed.job_ir();
        if metadata.version() != snapshot.job_ir_version() {
            return Err(app(ApplicationErrorKind::Internal));
        }
        let claim_status = self
            .ports
            .lease
            .lease_offers
            .inspect(LeaseOfferClaim::new(
                fence,
                request.header().operation_id(),
                digest,
                request.header().protocol_version(),
                claimed.slot(),
                claimed.lease().clone(),
                metadata.clone(),
            ))
            .await
            .map_err(port_application_error)?;
        match claim_status {
            LeaseOfferClaimStatus::Published(command) => {
                let response = decode_durable_server_command(
                    &command,
                    request.header().protocol_version(),
                    &self.config.protocol_limits,
                )
                .map_err(port_application_error)?;
                if !matches!(response, ServerToRunner::LeaseOffer(_)) {
                    return Err(app(ApplicationErrorKind::Internal));
                }
                return Ok(response);
            }
            LeaseOfferClaimStatus::ClaimSuperseded => {
                return Ok(self.no_work_response(request.header()));
            }
            LeaseOfferClaimStatus::Current => {}
        }
        if claimed.lease().expires_at() <= self.ports.clock.now() {
            return Err(app(ApplicationErrorKind::Unavailable));
        }
        let bytes = self
            .ports
            .lease
            .job_ir_objects
            .read_job_ir(metadata, metadata.encoded_size())
            .await
            .map_err(port_application_error)?;
        let job = verify_job_ir_blob(
            metadata,
            &bytes,
            snapshot.job_ir_version(),
            &self.config.protocol_limits,
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        Self::not_cancelled(cancellation)?;
        let authority_started_at = self.ports.clock.now();
        if claimed.lease().expires_at() <= authority_started_at {
            return Err(app(ApplicationErrorKind::Unavailable));
        }
        let authority_issuer = self
            .ports
            .runtime_authorities
            .as_ref()
            .ok_or_else(|| app(ApplicationErrorKind::Unavailable))?;
        let runtime_authorities = authority_issuer
            .issue(RuntimeAuthorityIssueRequest::new(
                &job,
                claimed.lease(),
                claimed.lease().issued_at(),
            ))
            .await
            .map_err(port_application_error)?;
        runtime_authorities
            .validate_for(&job, claimed.lease())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let publish_at = self.ports.clock.now();
        if claimed.lease().expires_at() <= publish_at
            || runtime_authorities
                .as_slice()
                .iter()
                .any(|authority| authority.expires_at() <= publish_at)
        {
            return Err(app(ApplicationErrorKind::Unavailable));
        }
        let publication = self
            .ports
            .lease
            .lease_offers
            .publish(LeaseOfferCommand::new(
                fence,
                request.header().operation_id(),
                digest,
                request.header().protocol_version(),
                claimed.slot(),
                claimed.lease().clone(),
                metadata.clone(),
                job.clone(),
                runtime_authorities.clone(),
                publish_at,
            ))
            .await
            .map_err(port_application_error)?;
        let LeaseOfferPublishOutcome::Published(published) = publication else {
            return Ok(self.no_work_response(request.header()));
        };
        Ok(ServerToRunner::LeaseOffer(Box::new(LeaseOffer::new(
            ServerCommandHeader::new(
                request.header().protocol_version(),
                fence.session_id(),
                published.operation_id(),
                published.sequence(),
            ),
            claimed.slot(),
            claimed.lease().clone(),
            job,
            runtime_authorities,
        ))))
    }

    async fn handle_heartbeat(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        heartbeat: &LeaseHeartbeat,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let now = self.ports.clock.now();
        let expires_at = UnixMillis::new(
            now.get()
                .checked_add(i64::from(self.config.lease_duration_millis))
                .ok_or_else(|| app(ApplicationErrorKind::Internal))?,
        );
        let response = ServerToRunner::LeaseRenewal(LeaseRenewal::new(
            self.reply_header(heartbeat.header()),
            heartbeat.attempt_id(),
            heartbeat.guard(),
            expires_at,
        ));
        let request = receipt_request(
            fence,
            heartbeat.header().operation_id(),
            HEARTBEAT_KIND,
            digest,
        )?;
        let renewal = RenewLease::new(
            heartbeat.attempt_id(),
            fence,
            heartbeat.guard(),
            now,
            expires_at,
        )
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        let transaction = CommitLeaseHeartbeat::new(
            request.clone(),
            snapshot.command_cursor(),
            renewal,
            self.durable_response(&response)?,
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?
        .with_reported_lifecycle(heartbeat.lifecycle())
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        Self::not_cancelled(cancellation)?;
        let receipt = self
            .ports
            .durability
            .transactions
            .commit_lease_heartbeat(transaction)
            .await
            .map_err(store_application_error)?;
        decode_operation_receipt(
            &receipt,
            &request,
            heartbeat.header(),
            &self.config.protocol_limits,
        )
    }

    async fn handle_lease_response(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        response: &automata_protocol::LeaseResponse,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        if let Some(replayed) = self
            .lookup_receipt(fence, response.header(), LEASE_RESPONSE_KIND, digest)
            .await?
        {
            return Ok(replayed);
        }
        let action = match response.disposition() {
            LeaseDisposition::Accepted => LeaseResponseAction::Accept,
            LeaseDisposition::Rejected(
                automata_protocol::LeaseRejectionReason::CapacityChanged
                | automata_protocol::LeaseRejectionReason::CapabilityChanged
                | automata_protocol::LeaseRejectionReason::ShuttingDown,
            ) => LeaseResponseAction::Requeue,
            LeaseDisposition::Rejected(automata_protocol::LeaseRejectionReason::InvalidJob) => {
                LeaseResponseAction::Fail
            }
        };
        let reply =
            ServerToRunner::OperationAck(OperationAck::new(self.reply_header(response.header())));
        let request = receipt_request(
            fence,
            response.header().operation_id(),
            LEASE_RESPONSE_KIND,
            digest,
        )?;
        let slot = automata_store::StableRunnerSlot::new(response.slot().get())
            .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        let transaction = CommitLeaseResponse::new(
            request.clone(),
            snapshot.command_cursor(),
            response.attempt_id(),
            slot,
            response.guard(),
            action,
            self.ports.clock.now(),
            self.durable_response(&reply)?,
        );
        Self::not_cancelled(cancellation)?;
        let receipt = self
            .ports
            .durability
            .transactions
            .commit_lease_response(transaction)
            .await
            .map_err(store_application_error)?;
        decode_operation_receipt(
            &receipt,
            &request,
            response.header(),
            &self.config.protocol_limits,
        )
    }

    async fn handle_job_result(
        &self,
        fence: RunnerSessionFence,
        message: &automata_protocol::JobResultMessage,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        if let Some(replayed) = self
            .lookup_receipt(fence, message.header(), JOB_RESULT_KIND, digest)
            .await?
        {
            return Ok(replayed);
        }
        let bytes = serde_json::to_vec(message.result())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let key = terminal_object_key(fence, message);
        let payload = immutable_payload(key, JOB_RESULT_MEDIA_TYPE, bytes)?;
        let descriptor = payload.descriptor().clone();
        Self::not_cancelled(cancellation)?;
        self.ports
            .durability
            .ingress_objects
            .put_if_absent(payload)
            .await
            .map_err(blob_application_error)?;
        Self::not_cancelled(cancellation)?;
        let reply =
            ServerToRunner::OperationAck(OperationAck::new(self.reply_header(message.header())));
        let request = receipt_request(
            fence,
            message.header().operation_id(),
            JOB_RESULT_KIND,
            digest,
        )?;
        let now = self.ports.clock.now();
        let committed_at = now.max(message.result().completed_at());
        let transaction = CommitRunnerTerminalResult::new(
            request.clone(),
            message.result().attempt_id(),
            message.guard(),
            DocumentSchema::new(message.result().schema_version())
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            descriptor.size(),
            descriptor.digest(),
            ObjectKey::new(descriptor.key().as_str().to_owned())
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            message.result().conclusion(),
            message.result().completed_at(),
            committed_at,
            self.durable_response(&reply)?,
        )
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        let receipt = self
            .ports
            .durability
            .transactions
            .commit_runner_terminal_result(transaction)
            .await
            .map_err(store_application_error)?;
        decode_operation_receipt(
            &receipt,
            &request,
            message.header(),
            &self.config.protocol_limits,
        )
    }

    async fn handle_log_batch(
        &self,
        fence: RunnerSessionFence,
        batch: &automata_protocol::LogBatch,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        if let Some(replayed) = self
            .lookup_receipt(fence, batch.header(), LOG_BATCH_KIND, digest)
            .await?
        {
            return Ok(replayed);
        }
        let first = batch
            .frames()
            .first()
            .ok_or_else(|| app(ApplicationErrorKind::Conflict))?;
        let last = batch
            .frames()
            .last()
            .ok_or_else(|| app(ApplicationErrorKind::Conflict))?;
        let uncompressed =
            serde_json::to_vec(batch.frames()).map_err(|_| app(ApplicationErrorKind::Internal))?;
        let compressed = deterministic_gzip(&uncompressed)?;
        let key = log_object_key(fence, batch, first.sequence(), last.sequence());
        let payload = immutable_payload(key, LOG_SEGMENT_MEDIA_TYPE, compressed)?;
        let descriptor = payload.descriptor().clone();
        Self::not_cancelled(cancellation)?;
        self.ports
            .durability
            .ingress_objects
            .put_if_absent(payload)
            .await
            .map_err(blob_application_error)?;
        Self::not_cancelled(cancellation)?;
        let reply = ServerToRunner::LogAck(LogAckMessage::new(
            self.reply_header(batch.header()),
            LogAck::new(first.stream_id(), Some(last.sequence())),
        ));
        let request =
            receipt_request(fence, batch.header().operation_id(), LOG_BATCH_KIND, digest)?;
        let transaction = CommitRunnerLogSegment::new(
            request.clone(),
            first.attempt_id(),
            batch.guard(),
            first.stream_id(),
            DocumentSchema::new(first.schema_version())
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            first.sequence(),
            last.sequence(),
            ObjectKey::new(descriptor.key().as_str().to_owned())
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            descriptor.digest(),
            descriptor.size(),
            u64::try_from(uncompressed.len()).map_err(|_| app(ApplicationErrorKind::Internal))?,
            self.ports.clock.now(),
            last.is_end_of_stream(),
            self.durable_response(&reply)?,
        )
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        let receipt = self
            .ports
            .durability
            .transactions
            .commit_runner_log_segment(transaction)
            .await
            .map_err(store_application_error)?;
        decode_operation_receipt(
            &receipt,
            &request,
            batch.header(),
            &self.config.protocol_limits,
        )
    }

    async fn handle_command_ack(
        &self,
        fence: RunnerSessionFence,
        _snapshot: &RunnerSessionSnapshot,
        ack: CommandAck,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let now = self.ports.clock.now();
        let response =
            ServerToRunner::OperationAck(OperationAck::new(self.reply_header(ack.header())));
        let request =
            receipt_request(fence, ack.header().operation_id(), COMMAND_ACK_KIND, digest)?;
        let acknowledgement = AcknowledgeRunnerCommands::new(
            fence,
            protocol_cursor_to_store(ack.command_cursor())?,
            now,
        );
        let transaction = CommitCommandAcknowledgement::new(
            request.clone(),
            acknowledgement,
            self.durable_response(&response)?,
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        Self::not_cancelled(cancellation)?;
        let receipt = self
            .ports
            .durability
            .transactions
            .commit_command_acknowledgement(transaction)
            .await
            .map_err(store_application_error)?;
        decode_operation_receipt(
            &receipt,
            &request,
            ack.header(),
            &self.config.protocol_limits,
        )
    }

    async fn lookup_receipt(
        &self,
        fence: RunnerSessionFence,
        header: MessageHeader,
        kind: &str,
        digest: Sha256Digest,
    ) -> Result<Option<ServerToRunner>, ApplicationError> {
        let request = receipt_request(fence, header.operation_id(), kind, digest)?;
        let receipt = self
            .ports
            .durability
            .receipts
            .lookup_operation(&request)
            .await
            .map_err(store_application_error)?;
        receipt
            .map(|value| {
                decode_operation_receipt(&value, &request, header, &self.config.protocol_limits)
            })
            .transpose()
    }

    fn durable_response(
        &self,
        response: &ServerToRunner,
    ) -> Result<RunnerOperationResponse, ApplicationError> {
        let mut bytes = Zeroizing::new(
            encode_server_frame(response, &self.config.protocol_limits)
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
        );
        let schema = DocumentSchema::new(automata_protocol::MESSAGE_SCHEMA_VERSION)
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        RunnerOperationResponse::new(schema, std::mem::take(&mut *bytes))
            .map_err(|_| app(ApplicationErrorKind::Internal))
    }

    fn reject(&self, hello: &RunnerHello, code: HandshakeErrorCode) -> ServerToRunner {
        ServerToRunner::HandshakeRejected(HandshakeRejected::new(
            self.ports.ids.next_operation_id(),
            hello.operation_id(),
            code,
            SUPPORTED_PROTOCOL_RANGE,
            "runner handshake was rejected",
        ))
    }

    fn reject_non_resumable(
        &self,
        hello: &RunnerHello,
        session_id: automata_core::RunnerSessionId,
    ) -> ServerToRunner {
        ServerToRunner::HandshakeRejected(HandshakeRejected::session_not_resumable(
            self.ports.ids.next_operation_id(),
            hello.operation_id(),
            SUPPORTED_PROTOCOL_RANGE,
            SessionOrphanAuthorization::new(
                session_id,
                OrphanDeliveryPermissions::new(true, true, true),
            ),
            "runner handshake was rejected",
        ))
    }

    fn unsupported(&self, request: MessageHeader) -> ServerToRunner {
        ServerToRunner::Error(ErrorMessage::new(
            self.reply_header(request),
            RemoteErrorCode::InvalidMessage,
            "runner message is not supported by this application version",
            false,
        ))
    }

    fn reply_header(&self, request: MessageHeader) -> MessageHeader {
        MessageHeader::reply(
            request.protocol_version(),
            request.session_id(),
            self.ports.ids.next_operation_id(),
            request.operation_id(),
        )
    }

    fn no_work_response(&self, request: MessageHeader) -> ServerToRunner {
        ServerToRunner::NoWork(NoWork::new(
            self.reply_header(request),
            self.config.no_work_retry_after_millis,
        ))
    }

    fn not_cancelled(token: &CancellationToken) -> Result<(), ApplicationError> {
        if token.is_cancelled() {
            Err(app(ApplicationErrorKind::Unavailable))
        } else {
            Ok(())
        }
    }
}

impl RunnerControlHandler for DurableRunnerControlHandler {
    fn handshake(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(async move {
            let (machine, message, _canonical, cancellation) = request.into_parts();
            match message.into_message() {
                RunnerToServer::Hello(hello) => {
                    self.handle_handshake(&machine, &hello, &cancellation).await
                }
                _ => Err(app(ApplicationErrorKind::Conflict)),
            }
        })
    }

    fn sync(&self, request: AuthenticatedRunnerRequest) -> HandlerFuture<'_> {
        Box::pin(async move {
            let (machine, message, canonical, cancellation) = request.into_parts();
            self.handle_transport_sync(&machine, &message, &canonical, &cancellation)
                .await
        })
    }
}

fn registration_matches(
    machine: &AuthenticatedMachine,
    registration: &AuthorizedRunnerRegistration,
) -> bool {
    machine.external_identity() == registration.external_identity()
        && bool::from(
            machine
                .certificate_sha256()
                .ct_eq(registration.certificate_sha256()),
        )
}

fn snapshot_matches(
    snapshot: &RunnerSessionSnapshot,
    registration: &AuthorizedRunnerRegistration,
    protocol: automata_protocol::ProtocolVersion,
    job_ir: automata_core::JobIrVersion,
    session_id: automata_core::RunnerSessionId,
) -> bool {
    snapshot.is_live()
        && snapshot.fence().session_id() == session_id
        && snapshot.fence().runner_id() == registration.runner_id()
        && snapshot.fence().runner_generation() == registration.generation()
        && snapshot.protocol_version().get() == protocol.get()
        && snapshot.job_ir_version() == job_ir
}

fn runner_header(message: &RunnerToServer) -> Option<MessageHeader> {
    match message {
        RunnerToServer::Hello(_) => None,
        RunnerToServer::LeaseRequest(value) => Some(value.header()),
        RunnerToServer::LeaseResponse(value) => Some(value.header()),
        RunnerToServer::Heartbeat(value) => Some(value.header()),
        RunnerToServer::JobState(value) => Some(value.header()),
        RunnerToServer::JobResult(value) => Some(value.header()),
        RunnerToServer::LogBatch(value) => Some(value.header()),
        RunnerToServer::CommandAck(value) => Some(value.header()),
    }
}

fn protocol_cursor_to_store(cursor: CommandCursor) -> Result<StoreCommandCursor, ApplicationError> {
    cursor
        .acknowledged_through()
        .map_or(Ok(StoreCommandCursor::initial()), |sequence| {
            StoreCommandSequence::new(sequence.get())
                .map(StoreCommandCursor::through)
                .map_err(|_| app(ApplicationErrorKind::Internal))
        })
}

fn store_cursor_to_protocol(cursor: StoreCommandCursor) -> Result<CommandCursor, ApplicationError> {
    cursor
        .acknowledged_through()
        .map_or(Ok(CommandCursor::initial()), |sequence| {
            CommandSequence::new(sequence.get())
                .map(CommandCursor::through)
                .map_err(|_| app(ApplicationErrorKind::Internal))
        })
}

fn receipt_request(
    fence: RunnerSessionFence,
    operation_id: OperationId,
    kind: &str,
    digest: Sha256Digest,
) -> Result<RunnerOperationRequest, ApplicationError> {
    let kind = RunnerOperationKind::new(kind).map_err(|_| app(ApplicationErrorKind::Internal))?;
    Ok(RunnerOperationRequest::new(
        fence,
        operation_id,
        kind,
        digest,
    ))
}

fn decode_receipt(
    response: &RunnerOperationResponse,
    request: MessageHeader,
    limits: &ProtocolLimits,
) -> Result<ServerToRunner, ApplicationError> {
    if response.schema().get() != automata_protocol::MESSAGE_SCHEMA_VERSION
        || sha256(response.payload()) != response.digest()
    {
        return Err(app(ApplicationErrorKind::Internal));
    }
    let message = decode_server_protobuf(response.payload(), limits)
        .map(automata_protocol::ValidatedServerToRunner::into_message)
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
    if !response_correlates(&message, request) {
        return Err(app(ApplicationErrorKind::Internal));
    }
    Ok(message)
}

fn decode_operation_receipt(
    receipt: &RunnerOperationReceipt,
    expected: &RunnerOperationRequest,
    request: MessageHeader,
    limits: &ProtocolLimits,
) -> Result<ServerToRunner, ApplicationError> {
    if receipt.request() != expected {
        return Err(app(ApplicationErrorKind::Internal));
    }
    decode_receipt(receipt.response(), request, limits)
}

fn response_correlates(response: &ServerToRunner, request: MessageHeader) -> bool {
    match response {
        ServerToRunner::LeaseOffer(value) => value
            .header()
            .validate_for(request.protocol_version(), request.session_id())
            .is_ok(),
        ServerToRunner::CancelJob(value) => value
            .header()
            .validate_for(request.protocol_version(), request.session_id())
            .is_ok(),
        ServerToRunner::LeaseRenewal(value) => value.header().validate_reply_for(request).is_ok(),
        ServerToRunner::LogAck(value) => value.header().validate_reply_for(request).is_ok(),
        ServerToRunner::OperationAck(value) => value.header().validate_reply_for(request).is_ok(),
        ServerToRunner::NoWork(value) => value.header().validate_reply_for(request).is_ok(),
        ServerToRunner::Error(value) => value.header().validate_reply_for(request).is_ok(),
        ServerToRunner::Hello(_) | ServerToRunner::HandshakeRejected(_) => false,
    }
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn terminal_object_key(
    fence: RunnerSessionFence,
    message: &automata_protocol::JobResultMessage,
) -> String {
    format!(
        "runner-results/{}/{}/{}/{}/{}/{}.json",
        fence.runner_id().as_uuid(),
        fence.session_id().as_uuid(),
        message.result().attempt_id().as_uuid(),
        message.guard().lease_id().as_uuid(),
        message.guard().fencing_token().get(),
        message.header().operation_id().as_uuid(),
    )
}

fn log_object_key(
    fence: RunnerSessionFence,
    batch: &automata_protocol::LogBatch,
    first: automata_core::LogSequence,
    last: automata_core::LogSequence,
) -> String {
    let frame = &batch.frames()[0];
    format!(
        "runner-logs/{}/{}/{}/{}/{}/{}-{}-{}.json.gz",
        fence.runner_id().as_uuid(),
        fence.session_id().as_uuid(),
        frame.attempt_id().as_uuid(),
        frame.stream_id().as_uuid(),
        batch.guard().fencing_token().get(),
        first.get(),
        last.get(),
        batch.header().operation_id().as_uuid(),
    )
}

fn immutable_payload(
    key: String,
    media_type: &'static str,
    bytes: Vec<u8>,
) -> Result<BlobPayload, ApplicationError> {
    let key = BlobKey::new(key).map_err(|_| app(ApplicationErrorKind::Internal))?;
    let media_type = MediaType::new(media_type).map_err(|_| app(ApplicationErrorKind::Internal))?;
    Ok(BlobPayload::from_bytes(key, media_type, bytes.into()))
}

fn deterministic_gzip(bytes: &[u8]) -> Result<Vec<u8>, ApplicationError> {
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::new(6));
    encoder
        .write_all(bytes)
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
    encoder
        .finish()
        .map_err(|_| app(ApplicationErrorKind::Internal))
}

const fn blob_application_error(error: BlobStoreError) -> ApplicationError {
    match error.kind() {
        BlobStoreErrorKind::Unavailable | BlobStoreErrorKind::Unauthorized => {
            app(ApplicationErrorKind::Unavailable)
        }
        BlobStoreErrorKind::Conflict => app(ApplicationErrorKind::Conflict),
        BlobStoreErrorKind::NotFound
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::TooLarge
        | BlobStoreErrorKind::InvalidResponse => app(ApplicationErrorKind::Internal),
    }
}

const fn app(kind: ApplicationErrorKind) -> ApplicationError {
    ApplicationError::new(kind)
}

const fn port_application_error(error: ControlPortError) -> ApplicationError {
    match error {
        ControlPortError::Unavailable => app(ApplicationErrorKind::Unavailable),
        ControlPortError::Corrupt => app(ApplicationErrorKind::Internal),
        ControlPortError::Conflict => app(ApplicationErrorKind::Conflict),
    }
}

fn lease_poll_application_error(error: LeasePollError) -> ApplicationError {
    match error {
        LeasePollError::Store(error) => store_application_error(error),
        _ => app(ApplicationErrorKind::Unavailable),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn store_application_error(error: StoreError) -> ApplicationError {
    match error {
        StoreError::Attempt(AttemptStoreError::Operation(_)) => {
            app(ApplicationErrorKind::Unavailable)
        }
        StoreError::Attempt(
            AttemptStoreError::NotFound(_)
            | AttemptStoreError::NotQueued { .. }
            | AttemptStoreError::FenceRejected(_)
            | AttemptStoreError::RunnerRejected(_)
            | AttemptStoreError::InvalidTransition { .. }
            | AttemptStoreError::RenewalDoesNotExtend(_)
            | AttemptStoreError::LeaseExpired(_)
            | AttemptStoreError::MutationPredatesState { .. },
        )
        | StoreError::OperationConflict { .. }
        | StoreError::CommandCursorAhead { .. }
        | StoreError::SlotOutOfRange { .. }
        | StoreError::AttemptFenceRejected(_)
        | StoreError::ImmutableConflict(_) => app(ApplicationErrorKind::Conflict),
        StoreError::RunnerNotFound(_)
        | StoreError::RunnerDisabled(_)
        | StoreError::RunnerGenerationMismatch { .. } => app(ApplicationErrorKind::Forbidden),
        StoreError::SessionNotFound(_)
        | StoreError::SessionClosed(_)
        | StoreError::SessionFenceRejected(_)
        | StoreError::CommandCursorBehind { .. } => app(ApplicationErrorKind::StaleSession),
        StoreError::Operation(_) => app(ApplicationErrorKind::Unavailable),
        _ => app(ApplicationErrorKind::Internal),
    }
}

const fn is_handshake_rejection(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::RunnerNotFound(_)
            | StoreError::RunnerDisabled(_)
            | StoreError::RunnerGenerationMismatch { .. }
            | StoreError::SessionNotFound(_)
            | StoreError::SessionClosed(_)
            | StoreError::SessionFenceRejected(_)
            | StoreError::CommandCursorAhead { .. }
            | StoreError::CommandCursorBehind { .. }
    )
}
