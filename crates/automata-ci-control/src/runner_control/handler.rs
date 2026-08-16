use std::{fmt, io::Write as _, sync::Arc, time::Instant};

use crate::attempt::RenewLease;
use crate::lease::{
    AuthenticatedRunnerSession, BeginLeaseRequest, ClaimedLeasePoll, CompleteLeaseRequest,
    LeaseClock, LeasePollError, LeasePollOutcome, LeaseRequestCompletion, LeaseRequestKey,
    RevokedLeaseOfferFallback, repository::RunnerLeaseRequestRepository,
};
use automata_ci_auth::machine::AuthenticatedMachine;
use automata_ci_blob::{
    BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{
    JobAuthorityProfile, JobIrEnvelope, JobIrVersionRange, JobLifecycle, LogAck, OperationId,
    Sha256Digest, TrustSecretAuthority, UnixMillis,
};
use automata_ci_protocol::{
    CommandAck, CommandCursor, CommandSequence, ErrorMessage, HandshakeErrorCode,
    HandshakeRejected, JobRuntimeAuthorities, LeaseDisposition, LeaseHeartbeat, LeaseOffer,
    LeaseRenewal, LogAckMessage, ManagedSecretBindingOverlay, MessageHeader, NegotiatedSession,
    NoWork, OperationAck, OrphanDeliveryPermissions, ProtocolLimits, RemoteErrorCode, RunnerHello,
    RunnerToServer, RuntimeAuthorityAck, RuntimeAuthorityGrant, RuntimeAuthorityRequest,
    SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming, ServerToRunner,
    SessionDisposition, SessionOrphanAuthorization, SessionResume, ValidatedRunnerToServer,
    negotiate_job_ir, negotiate_protocol,
};
use automata_ci_protocol_protobuf::{
    decode_server_frame as decode_server_protobuf, encode_runtime_authorities, encode_server_frame,
};
use automata_ci_runner_transport::{
    ApplicationError, ApplicationErrorKind, AuthenticatedRunnerRequest, HandlerFuture,
    RunnerControlHandler,
};
use automata_ci_store::{
    AcknowledgeRunnerCommands, AttemptStoreError, CommandCursor as StoreCommandCursor,
    CommandReplayDisposition, CommandReplayLimit, CommandSequence as StoreCommandSequence,
    DocumentSchema, HeartbeatRunnerSession, ObjectKey, OpenRunnerSession, ResumeRunnerSession,
    RoutingDocument, RunnerOperationKind, RunnerOperationReceipt, RunnerOperationRequest,
    RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionFence, RunnerSessionSnapshot,
    StableRunnerSlot, StoreError,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::durable::{
    AcknowledgeRuntimeAuthorityDelivery, AuthorizeRuntimeAuthorityDelivery,
    CommitCommandAcknowledgement, CommitLeaseHeartbeat, CommitLeaseResponse,
    CommitRunnerLogSegment, CommitRunnerTerminalResult, CommitRuntimeAuthorityDelivery,
    LeaseResponseAction, PublishedLeaseOffer, RunnerControlTransactionRepository,
    RunnerLogAdmissionRequest, RuntimeAuthorityDeliveryRepository,
};
use super::observer::NoopRunnerControlObserver;
use super::port::{
    AuthorizedRunnerRegistration, ControlIdGenerator, ControlPortError, DesiredRunnerState,
    JobIrObjectReader, LeaseOfferClaim, LeaseOfferClaimStatus, LeaseOfferCommand,
    LeaseOfferCommandPublisher, LeaseOfferPublishOutcome, LeaseOfferReplayResolution, LeasePoller,
    ManagedSecretBindingIssuer, RunnerRegistrationAuthorizer, RunnerSessionFenceResolver,
    RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer, decode_durable_server_command,
    is_durable_lease_offer_command,
};
use super::repository::{
    RunnerCommandOutbox, RunnerOperationReceiptRepository, RunnerSessionRepository,
};
use super::verify::verify_job_ir_blob;
use super::{
    LeaseOfferObservation, RunnerControlFailure, RunnerControlMessageKind,
    RunnerControlMessageOutcome, RunnerControlObserver, RunnerDurableDisposition,
    RunnerDurableMessageKind, RunnerHandshakeOutcome, RunnerHandshakeRejection,
    RunnerLeaseRequestStage, RunnerRuntimeAuthorityRequestStage,
};

const HEARTBEAT_KIND: &str = "automata.runner.lease-heartbeat.v1";
const COMMAND_ACK_KIND: &str = "automata.runner.command-ack.v1";
const LEASE_RESPONSE_KIND: &str = "automata.runner.lease-response.v1";
const JOB_RESULT_KIND: &str = "automata.runner.job-result.v1";
const LOG_BATCH_KIND: &str = "automata.runner.log-batch.v1";
const RUNTIME_AUTHORITY_REQUEST_KIND: &str = "automata.runner.runtime-authority-request.v2";
const RUNTIME_AUTHORITY_ACK_KIND: &str = "automata.runner.runtime-authority-ack.v2";

enum PendingCommand {
    Found(ServerToRunner),
    Empty,
    Saturated,
}

/// Immutable media type used for canonical terminal [`automata_ci_core::JobResult`] JSON.
const JOB_RESULT_MEDIA_TYPE: &str = "application/vnd.automata.job-result+json";
/// Immutable media type used for deterministic gzip-compressed log-frame JSON.
pub const LOG_SEGMENT_MEDIA_TYPE: &str = "application/vnd.automata.log-segment+json+gzip";

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
    runtime_authority_deliveries: Arc<dyn RuntimeAuthorityDeliveryRepository>,
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
        runtime_authority_deliveries: Arc<dyn RuntimeAuthorityDeliveryRepository>,
    ) -> Self {
        Self {
            ingress_objects,
            transactions,
            receipts,
            lease_requests,
            commands,
            runtime_authority_deliveries,
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
    managed_secret_bindings: Option<Arc<dyn ManagedSecretBindingIssuer>>,
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
            managed_secret_bindings: None,
            clock,
            ids,
        }
    }

    /// Installs the server-side per-attempt authority issuer for standard jobs.
    ///
    /// Without this adapter the handler refuses standard jobs. A validated
    /// credential-free job bypasses issuance and receives an empty bundle.
    #[must_use]
    pub fn with_runtime_authority_issuer(
        mut self,
        issuer: Arc<dyn RuntimeAuthorityIssuer>,
    ) -> Self {
        self.runtime_authorities = Some(issuer);
        self
    }

    /// Installs post-lease, value-free managed-secret grant issuance.
    #[must_use]
    pub fn with_managed_secret_binding_issuer(
        mut self,
        issuer: Arc<dyn ManagedSecretBindingIssuer>,
    ) -> Self {
        self.managed_secret_bindings = Some(issuer);
        self
    }
}

/// mTLS-authenticated, durable runner-control application handler.
pub struct DurableRunnerControlHandler {
    ports: RunnerControlPorts,
    config: RunnerControlConfig,
    observer: Arc<dyn RunnerControlObserver>,
}

impl fmt::Debug for DurableRunnerControlHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableRunnerControlHandler")
            .field("config", &self.config)
            .field("observer", &self.observer)
            .finish_non_exhaustive()
    }
}

impl DurableRunnerControlHandler {
    /// Creates a stateless handler over shared durable ports.
    #[must_use]
    pub fn new(ports: RunnerControlPorts, config: RunnerControlConfig) -> Self {
        Self {
            ports,
            config,
            observer: Arc::new(NoopRunnerControlObserver),
        }
    }

    /// Installs a provider-neutral semantic observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn RunnerControlObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Handles a validated hello using a fresh authenticated machine assertion.
    ///
    /// # Errors
    /// Returns a sanitized application error for cancellation, unavailable/corrupt shared state,
    /// or an invariant violation. Authentication and negotiation failures are correlated protocol
    /// rejections.
    pub async fn handle_handshake(
        &self,
        machine: &AuthenticatedMachine,
        hello: &RunnerHello,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let started = Instant::now();
        let result = self
            .handle_handshake_inner(machine, hello, cancellation)
            .await;
        self.observer
            .observe_handshake(handshake_outcome(&result), started.elapsed());
        result
    }

    async fn handle_handshake_inner(
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
        let (snapshot, disposition) = if let Some(resume) = hello.resume() {
            let Some(snapshot) = self
                .resume_handshake_session(
                    &registration,
                    resume,
                    protocol,
                    job_ir,
                    now,
                    cancellation,
                )
                .await?
            else {
                return Ok(self.reject_non_resumable(hello, resume.session_id()));
            };
            (snapshot, SessionDisposition::Resumed)
        } else {
            if registration.desired_state() != DesiredRunnerState::Active {
                return Ok(self.reject(hello, HandshakeErrorCode::Unauthorized));
            }
            let Some(snapshot) = self
                .open_handshake_session(&registration, hello, protocol, job_ir, now, cancellation)
                .await?
            else {
                return Ok(self.reject(hello, HandshakeErrorCode::Unauthorized));
            };
            (snapshot, SessionDisposition::Opened)
        };
        if snapshot.job_ir_version() != automata_ci_core::JobIrVersion::current()
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
                snapshot.heartbeat_at(),
                self.config.heartbeat_interval_millis,
                self.config.lease_duration_millis,
            ),
        )))
    }

    async fn resume_handshake_session(
        &self,
        registration: &AuthorizedRunnerRegistration,
        resume: SessionResume,
        protocol: automata_ci_protocol::ProtocolVersion,
        job_ir: automata_ci_core::JobIrVersion,
        now: UnixMillis,
        cancellation: &CancellationToken,
    ) -> Result<Option<RunnerSessionSnapshot>, ApplicationError> {
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
            return Ok(None);
        };
        let current = match self.ports.identity.sessions.get_session(fence).await {
            Ok(value) => value,
            Err(error) if is_handshake_rejection(&error) => return Ok(None),
            Err(error) => return Err(store_application_error(error)),
        };
        if !snapshot_matches(
            &current,
            registration,
            protocol,
            job_ir,
            resume.session_id(),
        ) {
            return Ok(None);
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
            Ok(value) => Ok(Some(value)),
            Err(error) if is_handshake_rejection(&error) => Ok(None),
            Err(error) => Err(store_application_error(error)),
        }
    }

    async fn open_handshake_session(
        &self,
        registration: &AuthorizedRunnerRegistration,
        hello: &RunnerHello,
        protocol: automata_ci_protocol::ProtocolVersion,
        job_ir: automata_ci_core::JobIrVersion,
        now: UnixMillis,
        cancellation: &CancellationToken,
    ) -> Result<Option<RunnerSessionSnapshot>, ApplicationError> {
        let observed = hello
            .runner()
            .clone()
            .with_labels(std::iter::empty())
            .with_groups(std::iter::empty());
        let json =
            serde_json::to_string(&observed).map_err(|_| app(ApplicationErrorKind::Internal))?;
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
            Ok(value) => Ok(Some(value)),
            Err(error) if is_handshake_rejection(&error) => Ok(None),
            Err(error) => Err(store_application_error(error)),
        }
    }

    /// Handles one validated post-handshake message and canonical request byte string.
    ///
    /// # Errors
    /// Returns a sanitized application error if fresh authentication, durable session fencing,
    /// cancellation, receipt validation, or a supported mutation fails.
    pub async fn handle_sync(
        &self,
        machine: &AuthenticatedMachine,
        message: &ValidatedRunnerToServer,
        canonical_bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        self.handle_sync_inner(machine, message, canonical_bytes, cancellation)
            .await
    }

    async fn handle_sync_inner(
        &self,
        machine: &AuthenticatedMachine,
        message: &ValidatedRunnerToServer,
        canonical_bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let runner_message = message.message();
        Self::not_cancelled(cancellation).map_err(|error| {
            self.observe_lease_request_message_failure(
                runner_message,
                RunnerLeaseRequestStage::RequestValidation,
                error,
            )
        })?;
        let header = runner_header(runner_message)
            .ok_or_else(|| app(ApplicationErrorKind::Conflict))
            .map_err(|error| {
                self.observe_lease_request_message_failure(
                    runner_message,
                    RunnerLeaseRequestStage::RequestValidation,
                    error,
                )
            })?;
        let (fence, snapshot) = self
            .authenticated_sync_session(machine, header)
            .await
            .map_err(|error| {
                self.observe_lease_request_message_failure(
                    runner_message,
                    RunnerLeaseRequestStage::SessionAuthentication,
                    error,
                )
            })?;
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
        if let Some(response) = self
            .handle_runtime_authority_message(fence, runner_message, digest, cancellation)
            .await
        {
            return response;
        }
        if !is_command_ack {
            match self
                .next_pending_command(fence, snapshot.protocol_version(), replay_after)
                .await?
            {
                PendingCommand::Found(command) => return Ok(command),
                PendingCommand::Empty => {}
                PendingCommand::Saturated => {
                    return Err(app(ApplicationErrorKind::Unavailable));
                }
            }
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
            RunnerToServer::RuntimeAuthorityRequest(_) | RunnerToServer::RuntimeAuthorityAck(_) => {
                Err(app(ApplicationErrorKind::Internal))
            }
            RunnerToServer::Hello(_) => Err(app(ApplicationErrorKind::Conflict)),
            _ => Ok(self.unsupported(header)),
        }?;
        match self
            .next_pending_command(fence, snapshot.protocol_version(), replay_after)
            .await?
        {
            PendingCommand::Found(command) => Ok(command),
            PendingCommand::Empty => Ok(response),
            PendingCommand::Saturated => Err(app(ApplicationErrorKind::Unavailable)),
        }
    }

    async fn handle_runtime_authority_message(
        &self,
        fence: RunnerSessionFence,
        message: &RunnerToServer,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Option<Result<ServerToRunner, ApplicationError>> {
        match message {
            RunnerToServer::RuntimeAuthorityRequest(request) => Some(
                self.handle_runtime_authority_request(fence, request, digest, cancellation)
                    .await,
            ),
            RunnerToServer::RuntimeAuthorityAck(acknowledgement) => Some(
                self.handle_runtime_authority_ack(fence, acknowledgement, digest, cancellation)
                    .await,
            ),
            _ => None,
        }
    }

    async fn authenticated_sync_session(
        &self,
        machine: &AuthenticatedMachine,
        header: MessageHeader,
    ) -> Result<(RunnerSessionFence, RunnerSessionSnapshot), ApplicationError> {
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
        Ok((fence, snapshot))
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
        let started = Instant::now();
        let kind = message_kind(message.message());
        let request_header = runner_header(message.message());
        let result = self
            .handle_sync_inner(machine, message, canonical_bytes, cancellation)
            .await;
        let result = match (request_header, result) {
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
        };
        if let Some(kind) = kind {
            self.observer
                .observe_message(kind, message_outcome(&result), started.elapsed());
        }
        result
    }

    async fn next_pending_command(
        &self,
        fence: RunnerSessionFence,
        protocol: RunnerProtocolVersion,
        after: StoreCommandCursor,
    ) -> Result<PendingCommand, ApplicationError> {
        let limit = CommandReplayLimit::new(1).map_err(|_| app(ApplicationErrorKind::Internal))?;
        let protocol_version = automata_ci_protocol::ProtocolVersion::new(protocol.get())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let mut commands = self
            .ports
            .durability
            .commands
            .replay_commands(fence, after, limit)
            .await
            .map_err(store_application_error)?;
        let disposition = commands.disposition();
        let Some(command) = commands.pop() else {
            return Ok(match disposition {
                CommandReplayDisposition::Exhausted => PendingCommand::Empty,
                CommandReplayDisposition::Saturated => PendingCommand::Saturated,
            });
        };
        if !commands.is_empty() || command.request().session() != fence {
            return Err(app(ApplicationErrorKind::Internal));
        }
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
            LeaseOfferReplayResolution::Published(resolved)
                if resolved.sequence() == command.sequence()
                    && resolved.request() == command.request() =>
            {
                resolved
            }
            LeaseOfferReplayResolution::Revoked if is_durable_lease_offer_command(&command) => {
                // The Store persisted this exact publication's monotonic revocation
                // marker while resolving the race. Do not start another replay
                // transaction in the same request: retrying from the same durable
                // acknowledgement cursor will exclude the marker and continue.
                return Ok(PendingCommand::Saturated);
            }
            LeaseOfferReplayResolution::Published(_) | LeaseOfferReplayResolution::Revoked => {
                return Err(app(ApplicationErrorKind::Internal));
            }
            LeaseOfferReplayResolution::NotPublished
                if is_durable_lease_offer_command(&command) =>
            {
                return Err(app(ApplicationErrorKind::Internal));
            }
            LeaseOfferReplayResolution::NotPublished => command,
        };
        decode_durable_server_command(&command, protocol_version, &self.config.protocol_limits)
            .map(PendingCommand::Found)
            .map_err(port_application_error)
    }

    #[allow(clippy::too_many_lines)] // One handler keeps validation, claim, and response stages adjacent.
    async fn handle_lease_request(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        request: &automata_ci_protocol::LeaseRequest,
        digest: Sha256Digest,
        replay_after: StoreCommandCursor,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let mut stage = RunnerLeaseRequestStage::RequestValidation;
        let result = async {
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

            stage = RunnerLeaseRequestStage::DurableAdmission;
            let admission = self
                .ports
                .durability
                .lease_requests
                .begin_lease_request(begin)
                .await
                .map_err(store_application_error)?;

            stage = RunnerLeaseRequestStage::SessionHeartbeat;
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
            if let Some(completion) = admission.completion() {
                stage = RunnerLeaseRequestStage::CompletedRequestReplay;
                return self
                    .resolve_lease_request_completion(fence, request.header(), completion)
                    .await;
            }

            stage = RunnerLeaseRequestStage::PrePollCommandReplay;
            match self
                .next_pending_command(fence, snapshot.protocol_version(), replay_after)
                .await?
            {
                PendingCommand::Found(command) => {
                    stage = RunnerLeaseRequestStage::DurableCompletion;
                    return self
                        .complete_lease_request(begin, request.header(), command)
                        .await;
                }
                PendingCommand::Empty => {}
                PendingCommand::Saturated => {
                    return Err(app(ApplicationErrorKind::Unavailable));
                }
            }

            stage = RunnerLeaseRequestStage::LeasePoll;
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
                    stage = RunnerLeaseRequestStage::OfferBuild;
                    self.build_lease_offer(
                        fence,
                        snapshot,
                        request,
                        digest,
                        claimed,
                        cancellation,
                        &mut stage,
                    )
                    .await?
                }
            };

            stage = RunnerLeaseRequestStage::PostPollCommandReplay;
            let actual_response = match self
                .next_pending_command(fence, snapshot.protocol_version(), replay_after)
                .await?
            {
                PendingCommand::Found(command) => command,
                PendingCommand::Empty => response,
                PendingCommand::Saturated => {
                    return Err(app(ApplicationErrorKind::Unavailable));
                }
            };

            stage = RunnerLeaseRequestStage::ResponseValidation;
            let actual_response = self
                .validate_lease_offer_response(fence, request.header(), actual_response, None, true)
                .await?;

            stage = RunnerLeaseRequestStage::DurableCompletion;
            self.complete_lease_request(begin, request.header(), actual_response)
                .await
        }
        .await;
        if let Err(error) = &result {
            self.observer
                .observe_lease_request_failure(stage, control_failure(error.kind()));
        }
        result
    }

    fn observe_lease_request_message_failure(
        &self,
        message: &RunnerToServer,
        stage: RunnerLeaseRequestStage,
        error: ApplicationError,
    ) -> ApplicationError {
        if matches!(message, RunnerToServer::LeaseRequest(_)) {
            self.observer
                .observe_lease_request_failure(stage, control_failure(error.kind()));
        }
        error
    }

    async fn complete_lease_request(
        &self,
        begin: BeginLeaseRequest,
        header: MessageHeader,
        response: ServerToRunner,
    ) -> Result<ServerToRunner, ApplicationError> {
        let durable = self.durable_response(&response)?;
        let completion = if let ServerToRunner::LeaseOffer(offer) = &response {
            let sequence = StoreCommandSequence::new(offer.header().sequence().get())
                .map_err(|_| app(ApplicationErrorKind::Internal))?;
            let revoked_message =
                self.revoked_offer_no_work_response(header, offer.header().operation_id());
            let ServerToRunner::NoWork(no_work) = &revoked_message else {
                return Err(app(ApplicationErrorKind::Internal));
            };
            let revoked_response = self.durable_response(&revoked_message)?;
            let revoked_fallback = RevokedLeaseOfferFallback::new(
                no_work.header().operation_id(),
                no_work.retry_after_millis(),
                revoked_response.schema(),
                revoked_response.digest(),
            )
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
            CompleteLeaseRequest::for_lease_offer_with_fallback(
                begin,
                durable,
                revoked_response,
                revoked_fallback,
                self.ports.clock.now(),
                automata_ci_store::LeaseOfferCommandIdentity::new(
                    begin.request_key().session(),
                    offer.header().operation_id(),
                    sequence,
                ),
            )
            .map_err(|_| app(ApplicationErrorKind::Internal))?
        } else {
            CompleteLeaseRequest::without_lease_offer(begin, durable, self.ports.clock.now())
        };
        let completed = match self
            .ports
            .durability
            .lease_requests
            .complete_lease_request(completion)
            .await
        {
            Ok(completed) => completed,
            Err(error) => return Err(store_application_error(error)),
        };
        self.resolve_lease_request_completion(begin.request_key().session(), header, &completed)
            .await
    }

    async fn resolve_lease_request_completion(
        &self,
        fence: RunnerSessionFence,
        request_header: MessageHeader,
        completion: &LeaseRequestCompletion,
    ) -> Result<ServerToRunner, ApplicationError> {
        match completion {
            LeaseRequestCompletion::Response(response) => {
                let response =
                    decode_receipt(response, request_header, &self.config.protocol_limits)?;
                self.validate_lease_offer_response(fence, request_header, response, None, false)
                    .await
            }
            LeaseRequestCompletion::LiveLeaseOffer { response, fallback } => {
                let response =
                    decode_receipt(response, request_header, &self.config.protocol_limits)?;
                self.validate_lease_offer_response(
                    fence,
                    request_header,
                    response,
                    Some(*fallback),
                    false,
                )
                .await
            }
            LeaseRequestCompletion::RevokedLeaseOffer { fallback, .. } => {
                self.revoked_offer_no_work_from_fallback(request_header, *fallback)
            }
        }
    }

    async fn validate_lease_offer_response(
        &self,
        fence: RunnerSessionFence,
        request_header: MessageHeader,
        response: ServerToRunner,
        revoked_fallback: Option<RevokedLeaseOfferFallback>,
        allow_store_revocation_resolution: bool,
    ) -> Result<ServerToRunner, ApplicationError> {
        let (operation_id, sequence, revoked_offer_operation_id) = match &response {
            ServerToRunner::LeaseOffer(offer) => (
                offer.header().operation_id(),
                offer.header().sequence(),
                Some(offer.header().operation_id()),
            ),
            ServerToRunner::CancelJob(cancel) => (
                cancel.header().operation_id(),
                cancel.header().sequence(),
                None,
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
        let command = match resolved {
            LeaseOfferReplayResolution::Published(command) => command,
            LeaseOfferReplayResolution::Revoked => {
                return if revoked_offer_operation_id.is_some()
                    && let Some(fallback) = revoked_fallback
                {
                    self.revoked_offer_no_work_from_fallback(request_header, fallback)
                } else if revoked_offer_operation_id.is_some() && allow_store_revocation_resolution
                {
                    // This is a newly built offer, not a replay. Preserve its typed offer
                    // identity so the durable completion transaction can atomically persist
                    // the already-computed fallback and its revoked payload disposition.
                    Ok(response)
                } else {
                    Err(app(ApplicationErrorKind::Internal))
                };
            }
            LeaseOfferReplayResolution::NotPublished if revoked_offer_operation_id.is_some() => {
                return Err(app(ApplicationErrorKind::Internal));
            }
            LeaseOfferReplayResolution::NotPublished => return Ok(response),
        };
        let durable = decode_durable_server_command(
            &command,
            request_header.protocol_version(),
            &self.config.protocol_limits,
        )
        .map_err(port_application_error)?;
        if durable != response {
            return Err(app(ApplicationErrorKind::Internal));
        }
        Ok(response)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn build_lease_offer(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        request: &automata_ci_protocol::LeaseRequest,
        digest: Sha256Digest,
        claimed: ClaimedLeasePoll,
        cancellation: &CancellationToken,
        stage: &mut RunnerLeaseRequestStage,
    ) -> Result<ServerToRunner, ApplicationError> {
        let result = self
            .build_lease_offer_inner(
                fence,
                snapshot,
                request,
                digest,
                claimed,
                cancellation,
                stage,
            )
            .await;
        if result.is_err() {
            self.observer
                .observe_lease_offer(LeaseOfferObservation::Failed);
        }
        result
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn build_lease_offer_inner(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        request: &automata_ci_protocol::LeaseRequest,
        digest: Sha256Digest,
        claimed: ClaimedLeasePoll,
        cancellation: &CancellationToken,
        stage: &mut RunnerLeaseRequestStage,
    ) -> Result<ServerToRunner, ApplicationError> {
        Self::not_cancelled(cancellation)?;
        let metadata = claimed.job_ir();
        if metadata.version() != snapshot.job_ir_version() {
            return Err(app(ApplicationErrorKind::Internal));
        }
        let claim = LeaseOfferClaim::new(
            fence,
            request.header().operation_id(),
            digest,
            request.header().protocol_version(),
            claimed.slot(),
            claimed.lease().clone(),
            metadata.clone(),
        );
        *stage = RunnerLeaseRequestStage::OfferClaimInspection;
        let claim_status = self
            .ports
            .lease
            .lease_offers
            .inspect(claim.clone())
            .await
            .map_err(port_application_error)?;
        match claim_status {
            LeaseOfferClaimStatus::Published(command) => {
                *stage = RunnerLeaseRequestStage::OfferPublishedClaimDecode;
                let response = decode_durable_server_command(
                    &command,
                    request.header().protocol_version(),
                    &self.config.protocol_limits,
                )
                .map_err(port_application_error)?;
                if !matches!(response, ServerToRunner::LeaseOffer(_)) {
                    return Err(app(ApplicationErrorKind::Internal));
                }
                self.observer
                    .observe_lease_offer(LeaseOfferObservation::Replay);
                return Ok(response);
            }
            LeaseOfferClaimStatus::ClaimSuperseded => {
                self.observer
                    .observe_lease_offer(LeaseOfferObservation::Superseded);
                return Ok(self.no_work_response(request.header()));
            }
            LeaseOfferClaimStatus::Current => {}
        }
        *stage = RunnerLeaseRequestStage::OfferJobIrRead;
        let bytes = self
            .ports
            .lease
            .job_ir_objects
            .read_job_ir(metadata, metadata.encoded_size())
            .await
            .map_err(port_application_error)?;
        *stage = RunnerLeaseRequestStage::OfferJobIrVerification;
        let job = verify_job_ir_blob(
            metadata,
            &bytes,
            snapshot.job_ir_version(),
            &self.config.protocol_limits,
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        Self::not_cancelled(cancellation)?;
        let authority_slot = StableRunnerSlot::new(claim.slot().get())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        *stage = RunnerLeaseRequestStage::OfferRuntimeAuthorityRequest;
        let authority_request = RuntimeAuthorityIssueRequest::new(
            &job,
            claim.job_ir_metadata(),
            claim.lease(),
            claim.lease().issued_at(),
            claim.session(),
            authority_slot,
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        *stage = RunnerLeaseRequestStage::OfferManagedSecretBindingIssue;
        let managed_secret_bindings = match (
            job.job().authority_profile(),
            job.job().trust_snapshot().authority().secrets(),
            self.ports.managed_secret_bindings.as_ref(),
        ) {
            (JobAuthorityProfile::Standard, TrustSecretAuthority::Eligible, Some(issuer)) => issuer
                .issue(authority_request)
                .await
                .map_err(port_application_error)?,
            (
                JobAuthorityProfile::CredentialFree | JobAuthorityProfile::Standard,
                TrustSecretAuthority::Denied,
                _,
            )
            | (
                JobAuthorityProfile::CredentialFree | JobAuthorityProfile::Standard,
                TrustSecretAuthority::Eligible,
                None,
            )
            | (JobAuthorityProfile::CredentialFree, TrustSecretAuthority::Eligible, Some(_)) => {
                ManagedSecretBindingOverlay::empty(claim.lease())
            }
        };
        *stage = RunnerLeaseRequestStage::OfferManagedSecretBindingValidation;
        managed_secret_bindings
            .validate_for(claim.lease())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        Self::not_cancelled(cancellation)?;
        let publish_at = claimed.lease().issued_at();
        *stage = RunnerLeaseRequestStage::OfferCommandConstruction;
        let command = LeaseOfferCommand::try_new(claim, job.clone(), publish_at)
            .and_then(|command| {
                command.with_managed_secret_bindings(managed_secret_bindings.clone())
            })
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        *stage = RunnerLeaseRequestStage::OfferCommandPublication;
        let publication = self
            .ports
            .lease
            .lease_offers
            .publish(command)
            .await
            .map_err(port_application_error)?;
        let LeaseOfferPublishOutcome::Published(published) = publication else {
            self.observer
                .observe_lease_offer(LeaseOfferObservation::Superseded);
            return Ok(self.no_work_response(request.header()));
        };
        self.observer
            .observe_lease_offer(if published.was_replayed() {
                LeaseOfferObservation::Replay
            } else {
                LeaseOfferObservation::Published
            });
        *stage = RunnerLeaseRequestStage::OfferConstruction;
        let offer = LeaseOffer::new(
            ServerCommandHeader::new(
                request.header().protocol_version(),
                fence.session_id(),
                published.operation_id(),
                published.sequence(),
            ),
            claimed.slot(),
            claimed.lease().clone(),
            job,
        )
        .with_managed_secret_bindings(managed_secret_bindings)
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        Ok(ServerToRunner::LeaseOffer(Box::new(offer)))
    }

    async fn handle_runtime_authority_request(
        &self,
        fence: RunnerSessionFence,
        request: &RuntimeAuthorityRequest,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let mut stage = RunnerRuntimeAuthorityRequestStage::RequestValidation;
        let result = async {
            Self::not_cancelled(cancellation)?;
            let durable_request = receipt_request(
                fence,
                request.header().operation_id(),
                RUNTIME_AUTHORITY_REQUEST_KIND,
                digest,
            )?;
            let protocol_version =
                RunnerProtocolVersion::new(request.header().protocol_version().get())
                    .map_err(|_| app(ApplicationErrorKind::Internal))?;
            let authorization = AuthorizeRuntimeAuthorityDelivery::new(
                durable_request,
                protocol_version,
                request.binding(),
                self.ports.clock.now(),
            )
            .map_err(|_| app(ApplicationErrorKind::Conflict))?;

            stage = RunnerRuntimeAuthorityRequestStage::DurableAuthorization;
            let admission = self
                .ports
                .durability
                .runtime_authority_deliveries
                .authorize_runtime_authority_delivery(authorization)
                .await
                .map_err(store_application_error)?;
            Self::not_cancelled(cancellation)?;

            stage = RunnerRuntimeAuthorityRequestStage::JobIrRead;
            let metadata = admission.offer().job_ir();
            let bytes = self
                .ports
                .lease
                .job_ir_objects
                .read_job_ir(metadata, metadata.encoded_size())
                .await
                .map_err(port_application_error)?;

            stage = RunnerRuntimeAuthorityRequestStage::JobIrVerification;
            let job = verify_job_ir_blob(
                metadata,
                &bytes,
                automata_ci_core::JobIrVersion::current(),
                &self.config.protocol_limits,
            )
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
            Self::not_cancelled(cancellation)?;

            stage = RunnerRuntimeAuthorityRequestStage::AuthorityIssue;
            let offer = admission.offer();
            let authorities = self.issue_runtime_authorities(&job, offer).await?;

            stage = RunnerRuntimeAuthorityRequestStage::AuthorityValidation;
            authorities
                .validate_for(&job, offer.lease())
                .map_err(|_| app(ApplicationErrorKind::Internal))?;

            stage = RunnerRuntimeAuthorityRequestStage::BundleEncoding;
            let encoded = Zeroizing::new(
                encode_runtime_authorities(
                    &authorities,
                    &job,
                    offer.lease(),
                    &self.config.protocol_limits,
                )
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            );
            let bundle_digest = sha256(&encoded);
            if admission
                .committed_bundle_digest()
                .is_some_and(|committed| committed != bundle_digest)
            {
                return Err(app(ApplicationErrorKind::Internal));
            }

            stage = RunnerRuntimeAuthorityRequestStage::CommitConstruction;
            let commit = CommitRuntimeAuthorityDelivery::new(
                admission,
                bundle_digest,
                self.ports.clock.now(),
            )
            .map_err(|_| app(ApplicationErrorKind::Conflict))?;
            Self::not_cancelled(cancellation)?;

            stage = RunnerRuntimeAuthorityRequestStage::DurableCommit;
            self.ports
                .durability
                .runtime_authority_deliveries
                .commit_runtime_authority_delivery(commit)
                .await
                .map_err(store_application_error)?;
            Ok(ServerToRunner::RuntimeAuthorityGrant(Box::new(
                RuntimeAuthorityGrant::new(
                    self.reply_header(request.header()),
                    request.binding(),
                    bundle_digest,
                    authorities,
                ),
            )))
        }
        .await;
        if let Err(error) = &result {
            self.observer
                .observe_runtime_authority_request_failure(stage, control_failure(error.kind()));
        }
        result
    }

    async fn issue_runtime_authorities(
        &self,
        job: &JobIrEnvelope,
        offer: &PublishedLeaseOffer,
    ) -> Result<JobRuntimeAuthorities, ApplicationError> {
        let issuance = RuntimeAuthorityIssueRequest::new(
            job,
            offer.job_ir(),
            offer.lease(),
            offer.lease().issued_at(),
            offer.request().session(),
            offer.slot(),
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        match (
            job.job().authority_profile(),
            job.job().trust_snapshot().authority().permissions(),
        ) {
            (JobAuthorityProfile::CredentialFree, _)
            | (
                JobAuthorityProfile::Standard,
                automata_ci_core::TrustPermissionAuthority::DenyAll,
            ) => JobRuntimeAuthorities::new(Vec::new(), job, offer.lease())
                .map_err(|_| app(ApplicationErrorKind::Internal)),
            (JobAuthorityProfile::Standard, _) => self
                .ports
                .runtime_authorities
                .as_ref()
                .ok_or_else(|| app(ApplicationErrorKind::Unavailable))?
                .issue(issuance)
                .await
                .map_err(port_application_error),
        }
    }

    async fn handle_runtime_authority_ack(
        &self,
        fence: RunnerSessionFence,
        acknowledgement: &RuntimeAuthorityAck,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let header = acknowledgement.header();
        let request = receipt_request(
            fence,
            header.operation_id(),
            RUNTIME_AUTHORITY_ACK_KIND,
            digest,
        )?;
        let protocol_version = RunnerProtocolVersion::new(header.protocol_version().get())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let acknowledgement = AcknowledgeRuntimeAuthorityDelivery::new(
            request,
            protocol_version,
            acknowledgement.binding(),
            acknowledgement.bundle_digest(),
            self.ports.clock.now(),
        )
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        Self::not_cancelled(cancellation)?;
        self.ports
            .durability
            .runtime_authority_deliveries
            .acknowledge_runtime_authority_delivery(acknowledgement)
            .await
            .map_err(store_application_error)?;
        Ok(ServerToRunner::OperationAck(OperationAck::new(
            self.reply_header(header),
        )))
    }

    async fn handle_heartbeat(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        heartbeat: &LeaseHeartbeat,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let reported_lifecycle = heartbeat.lifecycle();
        if reported_lifecycle == JobLifecycle::Queued || reported_lifecycle.is_terminal() {
            return Err(app(ApplicationErrorKind::Conflict));
        }
        if let Some((replayed, _)) = self
            .lookup_receipt(fence, heartbeat.header(), HEARTBEAT_KIND, digest)
            .await?
        {
            return self
                .commit_replayed_lease_heartbeat(
                    fence,
                    snapshot,
                    heartbeat,
                    digest,
                    replayed,
                    cancellation,
                )
                .await;
        }
        let now = self.ports.clock.now();
        let proposed_expires_at = UnixMillis::new(
            now.get()
                .checked_add(i64::from(self.config.lease_duration_millis))
                .ok_or_else(|| app(ApplicationErrorKind::Internal))?,
        );
        let proposed_renewal = RenewLease::new(
            heartbeat.attempt_id(),
            fence,
            heartbeat.guard(),
            now,
            proposed_expires_at,
        )
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        Self::not_cancelled(cancellation)?;
        let authorized = self
            .ports
            .durability
            .transactions
            .authorize_lease_renewal(proposed_renewal, reported_lifecycle)
            .await;
        let renewal = match authorized {
            Ok(renewal) => renewal,
            Err(error) => return Err(store_application_error(error)),
        };
        let response = ServerToRunner::LeaseRenewal(LeaseRenewal::new(
            self.reply_header(heartbeat.header()),
            heartbeat.attempt_id(),
            heartbeat.guard(),
            renewal.expires_at(),
        ));
        let request = receipt_request(
            fence,
            heartbeat.header().operation_id(),
            HEARTBEAT_KIND,
            digest,
        )?;
        let transaction = CommitLeaseHeartbeat::new(
            request.clone(),
            snapshot.command_cursor(),
            renewal,
            self.durable_response(&response)?,
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?
        .with_reported_lifecycle(reported_lifecycle)
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        Self::not_cancelled(cancellation)?;
        let receipt = self
            .ports
            .durability
            .transactions
            .commit_lease_heartbeat(transaction)
            .await
            .map_err(store_application_error)?;
        self.observe_operation_receipt(
            RunnerDurableMessageKind::LeaseRenewal,
            &receipt,
            &request,
            heartbeat.header(),
            0,
        )
    }

    async fn commit_replayed_lease_heartbeat(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        heartbeat: &LeaseHeartbeat,
        digest: Sha256Digest,
        replayed: ServerToRunner,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let ServerToRunner::LeaseRenewal(replayed_renewal) = &replayed else {
            return Err(app(ApplicationErrorKind::Internal));
        };
        replayed_renewal
            .validate_for(heartbeat)
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let replay_observed_at = UnixMillis::new(
            replayed_renewal
                .expires_at()
                .get()
                .checked_sub(1)
                .ok_or_else(|| app(ApplicationErrorKind::Internal))?,
        );
        let replay_renewal = RenewLease::new(
            replayed_renewal.attempt_id(),
            fence,
            replayed_renewal.guard(),
            replay_observed_at,
            replayed_renewal.expires_at(),
        )
        .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let request = receipt_request(
            fence,
            heartbeat.header().operation_id(),
            HEARTBEAT_KIND,
            digest,
        )?;
        let transaction = CommitLeaseHeartbeat::new(
            request.clone(),
            snapshot.command_cursor(),
            replay_renewal,
            self.durable_response(&replayed)?,
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
        self.observe_operation_receipt(
            RunnerDurableMessageKind::LeaseRenewal,
            &receipt,
            &request,
            heartbeat.header(),
            0,
        )
    }

    async fn handle_lease_response(
        &self,
        fence: RunnerSessionFence,
        snapshot: &RunnerSessionSnapshot,
        response: &automata_ci_protocol::LeaseResponse,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        let action = match response.disposition() {
            LeaseDisposition::Accepted => LeaseResponseAction::Accept,
            LeaseDisposition::Rejected(
                automata_ci_protocol::LeaseRejectionReason::CapacityChanged
                | automata_ci_protocol::LeaseRejectionReason::CapabilityChanged
                | automata_ci_protocol::LeaseRejectionReason::ShuttingDown,
            ) => LeaseResponseAction::Requeue,
            LeaseDisposition::Rejected(automata_ci_protocol::LeaseRejectionReason::InvalidJob) => {
                LeaseResponseAction::Fail
            }
        };
        if action != LeaseResponseAction::Accept
            && let Some((replayed, disposition)) = self
                .lookup_receipt(fence, response.header(), LEASE_RESPONSE_KIND, digest)
                .await?
        {
            self.observer
                .observe_durable(RunnerDurableMessageKind::LeaseResponse, disposition, 0);
            return Ok(replayed);
        }
        let reply =
            ServerToRunner::OperationAck(OperationAck::new(self.reply_header(response.header())));
        let request = receipt_request(
            fence,
            response.header().operation_id(),
            LEASE_RESPONSE_KIND,
            digest,
        )?;
        let slot = automata_ci_store::StableRunnerSlot::new(response.slot().get())
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
        self.observe_operation_receipt(
            RunnerDurableMessageKind::LeaseResponse,
            &receipt,
            &request,
            response.header(),
            0,
        )
    }

    async fn handle_job_result(
        &self,
        fence: RunnerSessionFence,
        message: &automata_ci_protocol::JobResultMessage,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        if let Some((replayed, disposition)) = self
            .lookup_receipt(fence, message.header(), JOB_RESULT_KIND, digest)
            .await?
        {
            self.observer
                .observe_durable(RunnerDurableMessageKind::JobResult, disposition, 0);
            return Ok(replayed);
        }
        let bytes = serde_json::to_vec(message.result())
            .map_err(|_| app(ApplicationErrorKind::Internal))?;
        let result_bytes =
            u64::try_from(bytes.len()).map_err(|_| app(ApplicationErrorKind::Internal))?;
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
        self.observe_operation_receipt(
            RunnerDurableMessageKind::JobResult,
            &receipt,
            &request,
            message.header(),
            result_bytes,
        )
    }

    async fn handle_log_batch(
        &self,
        fence: RunnerSessionFence,
        batch: &automata_ci_protocol::LogBatch,
        digest: Sha256Digest,
        cancellation: &CancellationToken,
    ) -> Result<ServerToRunner, ApplicationError> {
        if let Some((replayed, disposition)) = self
            .lookup_receipt(fence, batch.header(), LOG_BATCH_KIND, digest)
            .await?
        {
            self.observer
                .observe_durable(RunnerDurableMessageKind::LogBatch, disposition, 0);
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
        let request =
            receipt_request(fence, batch.header().operation_id(), LOG_BATCH_KIND, digest)?;
        let admission_request = RunnerLogAdmissionRequest::new(
            request.clone(),
            first.attempt_id(),
            batch.guard(),
            first.stream_id(),
            DocumentSchema::new(first.schema_version())
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            first.sequence(),
            last.sequence(),
            self.ports.clock.now(),
            last.is_end_of_stream(),
        )
        .map_err(|_| app(ApplicationErrorKind::Conflict))?;
        Self::not_cancelled(cancellation)?;
        let admission = self
            .ports
            .durability
            .transactions
            .admit_runner_log_segment(admission_request.clone())
            .await
            .map_err(store_application_error)?;
        if admission.request() != &admission_request {
            return Err(app(ApplicationErrorKind::Internal));
        }
        let uncompressed =
            serde_json::to_vec(batch.frames()).map_err(|_| app(ApplicationErrorKind::Internal))?;
        let log_bytes =
            u64::try_from(uncompressed.len()).map_err(|_| app(ApplicationErrorKind::Internal))?;
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
        let transaction = CommitRunnerLogSegment::new(
            admission,
            ObjectKey::new(descriptor.key().as_str().to_owned())
                .map_err(|_| app(ApplicationErrorKind::Internal))?,
            descriptor.digest(),
            descriptor.size(),
            log_bytes,
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
        self.observe_operation_receipt(
            RunnerDurableMessageKind::LogBatch,
            &receipt,
            &request,
            batch.header(),
            log_bytes,
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
        self.observe_operation_receipt(
            RunnerDurableMessageKind::CommandAck,
            &receipt,
            &request,
            ack.header(),
            0,
        )
    }

    fn observe_operation_receipt(
        &self,
        kind: RunnerDurableMessageKind,
        receipt: &RunnerOperationReceipt,
        request: &RunnerOperationRequest,
        header: MessageHeader,
        bytes: u64,
    ) -> Result<ServerToRunner, ApplicationError> {
        let response =
            decode_operation_receipt(receipt, request, header, &self.config.protocol_limits)?;
        let disposition = durable_disposition(receipt);
        self.observer.observe_durable(
            kind,
            disposition,
            if disposition == RunnerDurableDisposition::New {
                bytes
            } else {
                0
            },
        );
        Ok(response)
    }

    async fn lookup_receipt(
        &self,
        fence: RunnerSessionFence,
        header: MessageHeader,
        kind: &str,
        digest: Sha256Digest,
    ) -> Result<Option<(ServerToRunner, RunnerDurableDisposition)>, ApplicationError> {
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
                let disposition = durable_disposition(&value);
                decode_operation_receipt(&value, &request, header, &self.config.protocol_limits)
                    .map(|response| (response, disposition))
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
        let schema = DocumentSchema::new(automata_ci_protocol::MESSAGE_SCHEMA_VERSION)
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
        session_id: automata_ci_core::RunnerSessionId,
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

    fn revoked_offer_no_work_response(
        &self,
        request: MessageHeader,
        offer_operation_id: OperationId,
    ) -> ServerToRunner {
        let mut digest = Sha256::new();
        digest.update(b"automata.runner.revoked-lease-offer-no-work.v1");
        digest.update(offer_operation_id.as_uuid().as_bytes());
        digest.update(request.operation_id().as_uuid().as_bytes());
        let digest = Sha256Digest::from_bytes(digest.finalize().into());
        let encoded_operation_id = digest.to_string();
        let operation_id: OperationId = encoded_operation_id[..32]
            .parse()
            .expect("a SHA-256 prefix is a valid UUID representation");
        ServerToRunner::NoWork(NoWork::new(
            MessageHeader::reply(
                request.protocol_version(),
                request.session_id(),
                operation_id,
                request.operation_id(),
            ),
            self.config.no_work_retry_after_millis,
        ))
    }

    fn revoked_offer_no_work_from_fallback(
        &self,
        request: MessageHeader,
        fallback: RevokedLeaseOfferFallback,
    ) -> Result<ServerToRunner, ApplicationError> {
        let response = ServerToRunner::NoWork(NoWork::new(
            MessageHeader::reply(
                request.protocol_version(),
                request.session_id(),
                fallback.response_operation_id(),
                request.operation_id(),
            ),
            fallback.retry_after_millis(),
        ));
        let canonical = self.durable_response(&response)?;
        if canonical.schema() != fallback.response_schema()
            || canonical.digest() != fallback.response_digest()
        {
            return Err(app(ApplicationErrorKind::Internal));
        }
        Ok(response)
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
    protocol: automata_ci_protocol::ProtocolVersion,
    job_ir: automata_ci_core::JobIrVersion,
    session_id: automata_ci_core::RunnerSessionId,
) -> bool {
    snapshot.is_live()
        && snapshot.fence().session_id() == session_id
        && snapshot.fence().runner_id() == registration.runner_id()
        && snapshot.fence().runner_generation() == registration.generation()
        && snapshot.protocol_version().get() == protocol.get()
        && snapshot.job_ir_version() == job_ir
}

fn handshake_outcome(result: &Result<ServerToRunner, ApplicationError>) -> RunnerHandshakeOutcome {
    match result {
        Ok(ServerToRunner::Hello(hello)) => match hello.session_disposition() {
            SessionDisposition::Opened => RunnerHandshakeOutcome::Opened,
            SessionDisposition::Resumed => RunnerHandshakeOutcome::Resumed,
        },
        Ok(ServerToRunner::HandshakeRejected(rejected)) => {
            RunnerHandshakeOutcome::Rejected(match rejected.code() {
                HandshakeErrorCode::InvalidHello | HandshakeErrorCode::Unauthenticated => {
                    return RunnerHandshakeOutcome::Failed(RunnerControlFailure::Internal);
                }
                HandshakeErrorCode::UnsupportedProtocol => {
                    RunnerHandshakeRejection::UnsupportedProtocol
                }
                HandshakeErrorCode::UnsupportedJobIr => RunnerHandshakeRejection::UnsupportedJobIr,
                HandshakeErrorCode::Unauthorized => RunnerHandshakeRejection::Unauthorized,
                HandshakeErrorCode::SessionNotResumable => {
                    RunnerHandshakeRejection::SessionNotResumable
                }
            })
        }
        Ok(_) => RunnerHandshakeOutcome::Failed(RunnerControlFailure::Internal),
        Err(error) => RunnerHandshakeOutcome::Failed(control_failure(error.kind())),
    }
}

fn message_outcome(
    result: &Result<ServerToRunner, ApplicationError>,
) -> RunnerControlMessageOutcome {
    match result {
        Ok(ServerToRunner::Error(_)) => RunnerControlMessageOutcome::ProtocolError,
        Ok(_) => RunnerControlMessageOutcome::Success,
        Err(error) => RunnerControlMessageOutcome::Failed(control_failure(error.kind())),
    }
}

const fn control_failure(kind: ApplicationErrorKind) -> RunnerControlFailure {
    match kind {
        ApplicationErrorKind::Forbidden => RunnerControlFailure::Forbidden,
        // The production sync boundary converts stale sessions into a
        // correlated protocol error before observation. A stale handshake is
        // an application invariant failure, not a reachable label value.
        ApplicationErrorKind::StaleSession | ApplicationErrorKind::Internal => {
            RunnerControlFailure::Internal
        }
        ApplicationErrorKind::Conflict => RunnerControlFailure::Conflict,
        ApplicationErrorKind::Unavailable => RunnerControlFailure::Unavailable,
    }
}

const fn message_kind(message: &RunnerToServer) -> Option<RunnerControlMessageKind> {
    match message {
        RunnerToServer::LeaseRequest(_) => Some(RunnerControlMessageKind::LeaseRequest),
        RunnerToServer::LeaseResponse(_) => Some(RunnerControlMessageKind::LeaseResponse),
        RunnerToServer::RuntimeAuthorityRequest(_) => {
            Some(RunnerControlMessageKind::RuntimeAuthorityRequest)
        }
        RunnerToServer::RuntimeAuthorityAck(_) => {
            Some(RunnerControlMessageKind::RuntimeAuthorityAck)
        }
        RunnerToServer::Heartbeat(_) => Some(RunnerControlMessageKind::Heartbeat),
        RunnerToServer::JobState(_) => Some(RunnerControlMessageKind::JobState),
        RunnerToServer::JobResult(_) => Some(RunnerControlMessageKind::JobResult),
        RunnerToServer::LogBatch(_) => Some(RunnerControlMessageKind::LogBatch),
        RunnerToServer::CommandAck(_) => Some(RunnerControlMessageKind::CommandAck),
        RunnerToServer::Hello(_) => None,
    }
}

const fn durable_disposition(receipt: &RunnerOperationReceipt) -> RunnerDurableDisposition {
    if receipt.was_replayed() {
        RunnerDurableDisposition::Replay
    } else {
        RunnerDurableDisposition::New
    }
}

fn runner_header(message: &RunnerToServer) -> Option<MessageHeader> {
    match message {
        RunnerToServer::Hello(_) => None,
        RunnerToServer::LeaseRequest(value) => Some(value.header()),
        RunnerToServer::LeaseResponse(value) => Some(value.header()),
        RunnerToServer::RuntimeAuthorityRequest(value) => Some(value.header()),
        RunnerToServer::RuntimeAuthorityAck(value) => Some(value.header()),
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
    if response.schema().get() != automata_ci_protocol::MESSAGE_SCHEMA_VERSION
        || sha256(response.payload()) != response.digest()
    {
        return Err(app(ApplicationErrorKind::Internal));
    }
    let message = decode_server_protobuf(response.payload(), limits)
        .map(automata_ci_protocol::ValidatedServerToRunner::into_message)
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
        ServerToRunner::RuntimeAuthorityGrant(value) => {
            value.header().validate_reply_for(request).is_ok()
        }
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
    message: &automata_ci_protocol::JobResultMessage,
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
    batch: &automata_ci_protocol::LogBatch,
    first: automata_ci_core::LogSequence,
    last: automata_ci_core::LogSequence,
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
            | AttemptStoreError::RuntimeAuthorityUnavailable(_)
            | AttemptStoreError::RuntimeAuthorityCeilingExceeded(_)
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
