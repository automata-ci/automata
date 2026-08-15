use automata_ci_core::OperationId;
use automata_ci_runner_spool::{ContentKind, DurableContentRef, endpoint_result_allocation};
use serde::{Deserialize, Serialize};

use crate::{
    ENDPOINT_REQUEST_COMMITMENT_BYTES, JournalInvariantError, MAX_ENDPOINT_RESULT_ALLOCATION_BYTES,
    MAX_ENDPOINT_RESULT_CONTENT_BYTES, MIN_ENDPOINT_RESULT_ALLOCATION_BYTES,
};

/// Closed execution-endpoint operation domain retained for exact replay.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointOperationKind {
    /// Executes one literal argv request.
    Exec,
    /// Delivers one portable signal.
    Signal,
    /// Waits for the sandbox's primary workload.
    Wait,
    /// Copies bounded bytes into the sandbox.
    CopyTo,
    /// Copies bounded bytes out of the sandbox.
    CopyFrom,
}

/// Protected fixed-size commitment to an exact endpoint request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EndpointRequestContentRef(DurableContentRef);

impl EndpointRequestContentRef {
    /// Binds an already durable request commitment.
    ///
    /// # Errors
    ///
    /// Rejects a reference with the wrong semantic kind or byte length.
    pub fn new(content: DurableContentRef) -> Result<Self, JournalInvariantError> {
        let value = Self(content);
        value.validate()?;
        Ok(value)
    }

    /// Returns the protected immutable content identity.
    #[must_use]
    pub const fn content(&self) -> &DurableContentRef {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        if self.0.kind() != ContentKind::EndpointRequest
            || self.0.public_plaintext_bytes() != Some(ENDPOINT_REQUEST_COMMITMENT_BYTES)
        {
            return Err(JournalInvariantError::InvalidEndpointRequestContent);
        }
        Ok(())
    }
}

/// Protected exact result of one endpoint operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EndpointResultContentRef(DurableContentRef);

impl EndpointResultContentRef {
    /// Binds an already durable endpoint result.
    ///
    /// # Errors
    ///
    /// Rejects a reference with the wrong kind or protected allocation class.
    pub fn new(content: DurableContentRef) -> Result<Self, JournalInvariantError> {
        let value = Self(content);
        value.validate()?;
        Ok(value)
    }

    /// Returns the protected immutable content identity.
    #[must_use]
    pub const fn content(&self) -> &DurableContentRef {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        let allocation = self.0.endpoint_result_allocation_bytes();
        if self.0.kind() != ContentKind::EndpointResult
            || allocation.is_none_or(|bytes| {
                !(MIN_ENDPOINT_RESULT_ALLOCATION_BYTES..=MAX_ENDPOINT_RESULT_ALLOCATION_BYTES)
                    .contains(&bytes)
            })
        {
            return Err(JournalInvariantError::InvalidEndpointResultContent);
        }
        Ok(())
    }
}

/// Non-evicting linearization record for one exact endpoint operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointOperation {
    #[serde(rename = "id")]
    operation_id: OperationId,
    kind: EndpointOperationKind,
    request: EndpointRequestContentRef,
    #[serde(rename = "reservation")]
    reserved_result_bytes: u64,
    state: EndpointOperationState,
}

/// Closed durable phase/outcome of one execution-endpoint operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "phase", deny_unknown_fields)]
pub enum EndpointOperationState {
    /// The exact request is accepted, but no backend call is permitted yet.
    Accepted,
    /// Permission to expose the exact request to the backend is durable.
    InvocationCommitted,
    /// Termination won the durable race, but backend quiescence is not proven.
    CancellationRequested,
    /// Cancellation is complete after the exact sandbox was proven absent.
    Cancelled,
    /// Recovery proved the exact sandbox generation absent after ambiguity.
    Abandoned,
    /// The exact protected result won the operation's durable race.
    Completed {
        /// Payload-first protected result bytes.
        result: EndpointResultContentRef,
    },
}

impl EndpointOperation {
    /// Creates an accepted operation from a payload-first request commitment.
    ///
    /// # Errors
    ///
    /// Rejects invalid content or an empty/oversized result reservation.
    pub fn accepted(
        operation_id: OperationId,
        kind: EndpointOperationKind,
        request: EndpointRequestContentRef,
        reserved_result_bytes: u64,
    ) -> Result<Self, JournalInvariantError> {
        request.validate()?;
        if reserved_result_bytes == 0 || reserved_result_bytes > MAX_ENDPOINT_RESULT_CONTENT_BYTES {
            return Err(JournalInvariantError::InvalidEndpointResultReservation);
        }
        Ok(Self {
            operation_id,
            kind,
            request,
            reserved_result_bytes,
            state: EndpointOperationState::Accepted,
        })
    }

    /// Returns the stable endpoint operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the closed endpoint operation kind.
    #[must_use]
    pub const fn kind(&self) -> EndpointOperationKind {
        self.kind
    }

    /// Returns the protected exact-request commitment.
    #[must_use]
    pub const fn request(&self) -> &EndpointRequestContentRef {
        &self.request
    }

    /// Returns the result capacity reserved before the backend may run.
    #[must_use]
    pub const fn reserved_result_bytes(&self) -> u64 {
        self.reserved_result_bytes
    }

    /// Returns the closed durable phase/outcome.
    #[must_use]
    pub const fn state(&self) -> &EndpointOperationState {
        &self.state
    }

    /// Reports whether recovery must complete before finalization is legal.
    #[must_use]
    pub const fn is_recovery_pending(&self) -> bool {
        matches!(
            self.state,
            EndpointOperationState::Accepted
                | EndpointOperationState::InvocationCommitted
                | EndpointOperationState::CancellationRequested
        )
    }

    /// Returns the exact protected result when result publication won.
    #[must_use]
    pub const fn result(&self) -> Option<&EndpointResultContentRef> {
        match &self.state {
            EndpointOperationState::Completed { result } => Some(result),
            _ => None,
        }
    }

    /// Returns bytes charged against the per-slot retained-content budget.
    ///
    /// # Errors
    ///
    /// Rejects an incoherent result allocation or arithmetic overflow.
    pub fn accounted_content_bytes(&self) -> Result<u64, JournalInvariantError> {
        let result_bytes = match &self.state {
            EndpointOperationState::Accepted
            | EndpointOperationState::InvocationCommitted
            | EndpointOperationState::CancellationRequested => {
                endpoint_result_allocation(self.reserved_result_bytes)
                    .map_err(|_| JournalInvariantError::InvalidEndpointResultReservation)?
            }
            EndpointOperationState::Completed { result } => result
                .content()
                .endpoint_result_allocation_bytes()
                .ok_or(JournalInvariantError::InvalidEndpointResultContent)?,
            EndpointOperationState::Cancelled | EndpointOperationState::Abandoned => 0,
        };
        ENDPOINT_REQUEST_COMMITMENT_BYTES
            .checked_add(result_bytes)
            .ok_or(JournalInvariantError::DecodedStateInvalid)
    }

    /// Returns protected references charged against the per-slot reference budget.
    #[must_use]
    pub const fn accounted_content_refs(&self) -> usize {
        match self.state {
            EndpointOperationState::Accepted
            | EndpointOperationState::InvocationCommitted
            | EndpointOperationState::CancellationRequested
            | EndpointOperationState::Completed { .. } => 2,
            EndpointOperationState::Cancelled | EndpointOperationState::Abandoned => 1,
        }
    }

    pub(crate) fn matches_acceptance(&self, candidate: &Self) -> bool {
        self.operation_id == candidate.operation_id
            && self.kind == candidate.kind
            && self.request == candidate.request
            && self.reserved_result_bytes == candidate.reserved_result_bytes
    }

    pub(crate) fn commit_invocation(&mut self) -> Result<bool, JournalInvariantError> {
        match self.state {
            EndpointOperationState::Accepted => {
                self.state = EndpointOperationState::InvocationCommitted;
                Ok(true)
            }
            EndpointOperationState::InvocationCommitted => Ok(false),
            EndpointOperationState::CancellationRequested | EndpointOperationState::Cancelled => {
                Err(JournalInvariantError::EndpointOperationCancelled)
            }
            EndpointOperationState::Abandoned | EndpointOperationState::Completed { .. } => {
                Err(JournalInvariantError::EndpointOperationResolved)
            }
        }
    }

    pub(crate) fn request_cancellation(&mut self) -> bool {
        match self.state {
            EndpointOperationState::Accepted => {
                self.state = EndpointOperationState::Cancelled;
                true
            }
            EndpointOperationState::InvocationCommitted => {
                self.state = EndpointOperationState::CancellationRequested;
                true
            }
            EndpointOperationState::CancellationRequested
            | EndpointOperationState::Cancelled
            | EndpointOperationState::Abandoned
            | EndpointOperationState::Completed { .. } => false,
        }
    }

    pub(crate) fn complete_cancellation(&mut self) -> Result<bool, JournalInvariantError> {
        match self.state {
            EndpointOperationState::CancellationRequested => {
                self.state = EndpointOperationState::Cancelled;
                Ok(true)
            }
            EndpointOperationState::Cancelled => Ok(false),
            _ => Err(JournalInvariantError::EndpointCancellationNotRequested),
        }
    }

    pub(crate) fn abandon(&mut self) -> Result<bool, JournalInvariantError> {
        match self.state {
            EndpointOperationState::InvocationCommitted
            | EndpointOperationState::CancellationRequested => {
                self.state = EndpointOperationState::Abandoned;
                Ok(true)
            }
            EndpointOperationState::Abandoned => Ok(false),
            _ => Err(JournalInvariantError::EndpointOperationNotAbandonable),
        }
    }

    pub(crate) fn record_result(
        &mut self,
        result: EndpointResultContentRef,
    ) -> Result<bool, JournalInvariantError> {
        result.validate()?;
        let reserved_allocation = endpoint_result_allocation(self.reserved_result_bytes)
            .map_err(|_| JournalInvariantError::InvalidEndpointResultReservation)?;
        if result.content().accounted_bytes() > reserved_allocation {
            return Err(JournalInvariantError::EndpointResultExceedsReservation);
        }
        match &self.state {
            EndpointOperationState::InvocationCommitted => {
                self.state = EndpointOperationState::Completed { result };
                Ok(true)
            }
            EndpointOperationState::Completed { result: existing } if existing == &result => {
                Ok(false)
            }
            EndpointOperationState::Completed { .. } => {
                Err(JournalInvariantError::EndpointResultReplayConflict)
            }
            EndpointOperationState::CancellationRequested
            | EndpointOperationState::Cancelled
            | EndpointOperationState::Abandoned => {
                Err(JournalInvariantError::EndpointOperationCancelled)
            }
            EndpointOperationState::Accepted => {
                Err(JournalInvariantError::EndpointInvocationNotCommitted)
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        self.request.validate()?;
        if self.reserved_result_bytes == 0
            || self.reserved_result_bytes > MAX_ENDPOINT_RESULT_CONTENT_BYTES
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        if let EndpointOperationState::Completed { result } = &self.state {
            result.validate()?;
            let reserved_allocation = endpoint_result_allocation(self.reserved_result_bytes)
                .map_err(|_| JournalInvariantError::DecodedStateInvalid)?;
            if result.content().accounted_bytes() > reserved_allocation {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
        }
        self.accounted_content_bytes()?
            .checked_sub(ENDPOINT_REQUEST_COMMITMENT_BYTES)
            .ok_or(JournalInvariantError::DecodedStateInvalid)?;
        Ok(())
    }
}
