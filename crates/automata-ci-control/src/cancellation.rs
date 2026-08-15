//! Durable cancellation intent values, runner commands, and repository port.

use async_trait::async_trait;
use automata_ci_core::{AttemptId, LeaseGuard, OperationId, UnixMillis};
use automata_ci_store::{
    DurableRunnerCommand, EnqueueRunnerCommand, RunnerProtocolVersion, StoreError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CANCELLATION_ACTOR_BYTES: usize = 255;
const MAX_CANCELLATION_REASON_BYTES: usize = 1024;

/// Durable outbox kind for a typed runner cancellation command.
pub const CANCEL_JOB_COMMAND_KIND: &str = "automata.runner.cancel-job.v1";
/// Independently versioned JSON payload schema for [`CancelJobCommandPayload`].
pub const CANCEL_JOB_COMMAND_SCHEMA: u16 = 1;
/// Wire-visible reason used when an administrative request has no custom reason.
pub const DEFAULT_CANCELLATION_REASON: &str = "workflow cancellation requested";

/// Sequence-independent body persisted for one replayable `CancelJob` command.
///
/// The durable outbox owns the operation ID and sequence. The runner-control
/// adapter reconstructs the protocol header from those durable coordinates,
/// which keeps the payload byte-identical before and after sequence allocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelJobCommandPayload {
    attempt_id: AttemptId,
    guard: LeaseGuard,
    protocol_version: u16,
    reason: String,
    requested_at: UnixMillis,
    schema: u16,
}

impl CancelJobCommandPayload {
    /// Creates a validated current-schema cancellation command body.
    ///
    /// # Errors
    ///
    /// Rejects an invalid wire-visible reason.
    pub fn new(
        attempt_id: AttemptId,
        guard: LeaseGuard,
        protocol_version: RunnerProtocolVersion,
        reason: impl Into<String>,
        requested_at: UnixMillis,
    ) -> Result<Self, CancellationValueError> {
        let reason = reason.into();
        CancellationReason::new(reason.clone())?;
        Ok(Self {
            attempt_id,
            guard,
            protocol_version: protocol_version.get(),
            reason,
            requested_at,
            schema: CANCEL_JOB_COMMAND_SCHEMA,
        })
    }

    /// Decodes and validates a durable JSON body.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON, another payload schema, an invalid protocol
    /// version, or an invalid reason.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, CancellationValueError> {
        let payload: Self =
            serde_json::from_slice(bytes).map_err(|_| CancellationValueError::InvalidCommand)?;
        if payload.schema != CANCEL_JOB_COMMAND_SCHEMA
            || RunnerProtocolVersion::new(payload.protocol_version).is_err()
            || CancellationReason::new(payload.reason.clone()).is_err()
        {
            return Err(CancellationValueError::InvalidCommand);
        }
        Ok(payload)
    }

    /// Encodes the canonical durable JSON representation.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization unexpectedly fails.
    pub fn encode_json(&self) -> Result<Vec<u8>, CancellationValueError> {
        serde_json::to_vec(self).map_err(|_| CancellationValueError::InvalidCommand)
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the active lease guard.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    /// Returns the selected runner protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the wire-visible cancellation reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns the trusted cancellation-request time.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
}

/// Sanitized principal or subsystem that requested cancellation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CancellationActor(String);

impl CancellationActor {
    /// Creates a bounded actor identifier with no control characters.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, CancellationValueError> {
        let value = value.into();
        if !is_valid_text(&value, MAX_CANCELLATION_ACTOR_BYTES) {
            return Err(CancellationValueError::InvalidActor);
        }
        Ok(Self(value))
    }

    /// Returns the validated actor identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Optional bounded human-facing cancellation reason.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CancellationReason(String);

impl CancellationReason {
    /// Creates a bounded reason with no control characters.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, CancellationValueError> {
        let value = value.into();
        if !is_valid_text(&value, MAX_CANCELLATION_REASON_BYTES) {
            return Err(CancellationValueError::InvalidReason);
        }
        Ok(Self(value))
    }

    /// Returns the validated human-facing reason.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

/// Invalid cancellation actor, reason, or durable command payload.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CancellationValueError {
    /// The cancellation actor is empty, oversized, or control-bearing.
    #[error("cancellation actor is invalid")]
    InvalidActor,
    /// The cancellation reason is empty, oversized, or control-bearing.
    #[error("cancellation reason is invalid")]
    InvalidReason,
    /// The durable runner command is malformed or uses an unsupported schema.
    #[error("durable cancellation command is invalid")]
    InvalidCommand,
}

/// Durable intent written before cancellation is delivered to a runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCancellation {
    operation_id: OperationId,
    attempt_id: AttemptId,
    actor: CancellationActor,
    reason: Option<CancellationReason>,
    requested_at: UnixMillis,
    delivery: Option<EnqueueRunnerCommand>,
}

impl RequestCancellation {
    /// Creates a cancellation request without runner delivery metadata.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        attempt_id: AttemptId,
        actor: CancellationActor,
        reason: Option<CancellationReason>,
        requested_at: UnixMillis,
    ) -> Self {
        Self {
            operation_id,
            attempt_id,
            actor,
            reason,
            requested_at,
            delivery: None,
        }
    }

    /// Adds the exact cancel command that must be committed to the active
    /// attempt's session outbox in the same transaction as the intent.
    #[must_use]
    pub fn with_delivery(mut self, delivery: EnqueueRunnerCommand) -> Self {
        self.delivery = Some(delivery);
        self
    }

    /// Returns the idempotent cancellation operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the target attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the principal or subsystem requesting cancellation.
    #[must_use]
    pub const fn actor(&self) -> &CancellationActor {
        &self.actor
    }

    /// Returns the optional human-facing cancellation reason.
    #[must_use]
    pub const fn reason(&self) -> Option<&CancellationReason> {
        self.reason.as_ref()
    }

    /// Returns the trusted request time.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }

    /// Returns the runner command to enqueue atomically, if any.
    #[must_use]
    pub const fn delivery(&self) -> Option<&EnqueueRunnerCommand> {
        self.delivery.as_ref()
    }
}

/// Immutable first cancellation request for an attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationIntent {
    request: RequestCancellation,
    acknowledged_at: Option<UnixMillis>,
    replayed: bool,
    delivery: Option<DurableRunnerCommand>,
}

impl CancellationIntent {
    /// Constructs a decoded durable intent.
    ///
    /// # Errors
    ///
    /// Rejects an acknowledgement before the request.
    pub fn try_new(
        request: RequestCancellation,
        acknowledged_at: Option<UnixMillis>,
        replayed: bool,
        delivery: Option<DurableRunnerCommand>,
    ) -> Result<Self, CancellationIntentError> {
        if acknowledged_at.is_some_and(|value| value < request.requested_at()) {
            return Err(CancellationIntentError::AcknowledgedBeforeRequest);
        }
        Ok(Self {
            request,
            acknowledged_at,
            replayed,
            delivery,
        })
    }

    /// Returns the immutable first cancellation request.
    #[must_use]
    pub const fn request(&self) -> &RequestCancellation {
        &self.request
    }

    /// Returns the runner acknowledgement time, if acknowledged.
    #[must_use]
    pub const fn acknowledged_at(&self) -> Option<UnixMillis> {
        self.acknowledged_at
    }

    /// Reports whether the repository replayed a prior intent.
    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }

    /// Returns the durable runner command associated with the intent, if any.
    #[must_use]
    pub const fn delivery(&self) -> Option<&DurableRunnerCommand> {
        self.delivery.as_ref()
    }
}

/// Invalid timing in a decoded cancellation intent.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CancellationIntentError {
    /// The acknowledgement time precedes the original request.
    #[error("cancellation acknowledgement precedes its durable request")]
    AcknowledgedBeforeRequest,
}

/// Durable cancellation-intent port.
#[async_trait]
pub trait CancellationRepository: Send + Sync {
    /// Persists the first request. Exact operation retries return that intent;
    /// a different request for the same attempt conflicts.
    async fn request_cancellation(
        &self,
        request: RequestCancellation,
    ) -> Result<CancellationIntent, StoreError>;

    /// Fetches the immutable cancellation intent for an attempt, if present.
    async fn cancellation_for_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<CancellationIntent>, StoreError>;
}
