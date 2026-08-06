//! Size-first JSON framing and validated message wrappers.

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::{MessageValidationError, ProtocolLimits, RunnerToServer, ServerToRunner};

/// Runner message that has passed all local schema and resource checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRunnerToServer(RunnerToServer);

impl ValidatedRunnerToServer {
    /// Validates an owned decoded runner message under trusted limits.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] before the message can be acted on.
    pub fn new(
        message: RunnerToServer,
        limits: &ProtocolLimits,
    ) -> Result<Self, MessageValidationError> {
        message.validate(limits)?;
        Ok(Self(message))
    }

    #[must_use]
    pub const fn message(&self) -> &RunnerToServer {
        &self.0
    }

    #[must_use]
    pub fn into_message(self) -> RunnerToServer {
        self.0
    }
}

impl TryFrom<RunnerToServer> for ValidatedRunnerToServer {
    type Error = MessageValidationError;

    fn try_from(message: RunnerToServer) -> Result<Self, Self::Error> {
        Self::new(message, &ProtocolLimits::default())
    }
}

/// Server message that has passed all local schema and resource checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedServerToRunner(ServerToRunner);

impl ValidatedServerToRunner {
    /// Validates an owned decoded server message under trusted limits.
    ///
    /// # Errors
    ///
    /// Returns [`MessageValidationError`] before the message can be acted on.
    pub fn new(
        message: ServerToRunner,
        limits: &ProtocolLimits,
    ) -> Result<Self, MessageValidationError> {
        message.validate(limits)?;
        Ok(Self(message))
    }

    #[must_use]
    pub const fn message(&self) -> &ServerToRunner {
        &self.0
    }

    #[must_use]
    pub fn into_message(self) -> ServerToRunner {
        self.0
    }
}

impl TryFrom<ServerToRunner> for ValidatedServerToRunner {
    type Error = MessageValidationError;

    fn try_from(message: ServerToRunner) -> Result<Self, Self::Error> {
        Self::new(message, &ProtocolLimits::default())
    }
}

/// Checks frame bytes before Serde can allocate nested values, then validates
/// the resulting owned message.
///
/// # Errors
///
/// Returns [`ProtocolDecodeError`] for empty/oversized frames, malformed JSON,
/// or a semantically invalid message.
pub fn decode_runner_frame(
    frame: &[u8],
    limits: &ProtocolLimits,
) -> Result<ValidatedRunnerToServer, ProtocolDecodeError> {
    let message = decode_json(frame, limits)?;
    ValidatedRunnerToServer::new(message, limits).map_err(ProtocolDecodeError::InvalidMessage)
}

/// Size-first counterpart of [`decode_runner_frame`] for server messages.
///
/// # Errors
///
/// Returns [`ProtocolDecodeError`] for empty/oversized frames, malformed JSON,
/// or a semantically invalid message.
pub fn decode_server_frame(
    frame: &[u8],
    limits: &ProtocolLimits,
) -> Result<ValidatedServerToRunner, ProtocolDecodeError> {
    let message = decode_json(frame, limits)?;
    ValidatedServerToRunner::new(message, limits).map_err(ProtocolDecodeError::InvalidMessage)
}

/// Validates and encodes one runner message within the same frame budget used
/// by the decoder.
///
/// # Errors
///
/// Returns [`ProtocolEncodeError`] for an invalid message, serialization
/// failure, or an encoded frame that exceeds the configured ceiling.
pub fn encode_runner_frame(
    message: RunnerToServer,
    limits: &ProtocolLimits,
) -> Result<Vec<u8>, ProtocolEncodeError> {
    let validated = ValidatedRunnerToServer::new(message, limits)?;
    encode_json(validated.message(), limits)
}

/// Validates and encodes one server message within the negotiated budget.
///
/// # Errors
///
/// Returns [`ProtocolEncodeError`] for an invalid message, serialization
/// failure, or an encoded frame that exceeds the configured ceiling.
pub fn encode_server_frame(
    message: ServerToRunner,
    limits: &ProtocolLimits,
) -> Result<Vec<u8>, ProtocolEncodeError> {
    let validated = ValidatedServerToRunner::new(message, limits)?;
    encode_json(validated.message(), limits)
}

fn decode_json<T: DeserializeOwned>(
    frame: &[u8],
    limits: &ProtocolLimits,
) -> Result<T, ProtocolDecodeError> {
    if frame.is_empty() {
        return Err(ProtocolDecodeError::EmptyFrame);
    }
    if frame.len() > limits.max_frame_bytes() {
        return Err(ProtocolDecodeError::FrameTooLarge {
            size: frame.len(),
            maximum: limits.max_frame_bytes(),
        });
    }
    serde_json::from_slice(frame).map_err(ProtocolDecodeError::MalformedJson)
}

fn encode_json<T: Serialize>(
    message: &T,
    limits: &ProtocolLimits,
) -> Result<Vec<u8>, ProtocolEncodeError> {
    let encoded = serde_json::to_vec(message).map_err(ProtocolEncodeError::Serialization)?;
    if encoded.len() > limits.max_frame_bytes() {
        return Err(ProtocolEncodeError::FrameTooLarge {
            size: encoded.len(),
            maximum: limits.max_frame_bytes(),
        });
    }
    Ok(encoded)
}

/// Failure while decoding an untrusted transport frame.
#[derive(Debug, Error)]
pub enum ProtocolDecodeError {
    #[error("protocol frame is empty")]
    EmptyFrame,
    #[error("protocol frame has {size} bytes; maximum is {maximum}")]
    FrameTooLarge { size: usize, maximum: usize },
    #[error("protocol frame is not valid JSON")]
    MalformedJson(#[source] serde_json::Error),
    #[error("protocol message failed validation")]
    InvalidMessage(#[source] MessageValidationError),
}

/// Failure while validating or encoding a local protocol message.
#[derive(Debug, Error)]
pub enum ProtocolEncodeError {
    #[error("protocol message failed validation")]
    InvalidMessage(#[from] MessageValidationError),
    #[error("protocol message could not be serialized")]
    Serialization(#[source] serde_json::Error),
    #[error("encoded protocol frame has {size} bytes; maximum is {maximum}")]
    FrameTooLarge { size: usize, maximum: usize },
}
