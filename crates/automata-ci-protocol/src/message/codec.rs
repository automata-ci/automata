//! Validated message wrappers for transport adapters and handlers.

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
    /// Borrows the validated runner message without discarding its proof.
    pub const fn message(&self) -> &RunnerToServer {
        &self.0
    }

    #[must_use]
    /// Consumes the validation proof and returns the owned runner message.
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
    /// Borrows the validated server message without discarding its proof.
    pub const fn message(&self) -> &ServerToRunner {
        &self.0
    }

    #[must_use]
    /// Consumes the validation proof and returns the owned server message.
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
