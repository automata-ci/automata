use async_trait::async_trait;
use automata_core::{AttemptId, LeaseGuard, OperationId, UnixMillis};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DurableRunnerCommand, EnqueueRunnerCommand, RunnerProtocolVersion, StoreError,
    value::validate_text,
};

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

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

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
        validate_text(&value, MAX_CANCELLATION_ACTOR_BYTES, "cancellation actor")
            .map_err(|_| CancellationValueError::InvalidActor)?;
        Ok(Self(value))
    }

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
        validate_text(&value, MAX_CANCELLATION_REASON_BYTES, "cancellation reason")
            .map_err(|_| CancellationValueError::InvalidReason)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CancellationValueError {
    #[error("cancellation actor is invalid")]
    InvalidActor,
    #[error("cancellation reason is invalid")]
    InvalidReason,
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

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn actor(&self) -> &CancellationActor {
        &self.actor
    }

    #[must_use]
    pub const fn reason(&self) -> Option<&CancellationReason> {
        self.reason.as_ref()
    }

    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }

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

    #[must_use]
    pub const fn request(&self) -> &RequestCancellation {
        &self.request
    }

    #[must_use]
    pub const fn acknowledged_at(&self) -> Option<UnixMillis> {
        self.acknowledged_at
    }

    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }

    #[must_use]
    pub const fn delivery(&self) -> Option<&DurableRunnerCommand> {
        self.delivery.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CancellationIntentError {
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

    async fn cancellation_for_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<CancellationIntent>, StoreError>;
}
