use automata_core::{JobIrVersion, OperationId};
use automata_runner_spool::{ContentKind, DurableContentRef};
use serde::{Deserialize, Serialize};

use crate::{
    JournalInvariantError, MAX_JOB_IR_CONTENT_BYTES, MAX_RUNTIME_AUTHORITY_CONTENT_BYTES,
    MAX_TERMINAL_RESULT_CONTENT_BYTES,
};

/// Exact negotiated schema and durable immutable bytes for one `JobIR`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobIrContentRef {
    version: JobIrVersion,
    content: DurableContentRef,
}

/// Exact protected bytes containing the job-scoped runtime-authority bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RuntimeAuthorityContentRef(DurableContentRef);

impl RuntimeAuthorityContentRef {
    /// Binds a protected, already durable runtime-authority object.
    ///
    /// # Errors
    ///
    /// Rejects the wrong semantic content kind or an empty/oversized payload.
    pub fn new(content: DurableContentRef) -> Result<Self, JournalInvariantError> {
        let value = Self(content);
        value.validate()?;
        Ok(value)
    }

    /// Returns the protected content identity.
    #[must_use]
    pub const fn content(&self) -> &DurableContentRef {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        if self.0.kind() != ContentKind::RuntimeAuthority
            || self.0.size() == 0
            || self.0.size() > MAX_RUNTIME_AUTHORITY_CONTENT_BYTES
        {
            return Err(JournalInvariantError::InvalidRuntimeAuthorityContent);
        }
        Ok(())
    }
}

impl JobIrContentRef {
    /// Binds a selected `JobIR` version to bytes already committed by the
    /// durable-content adapter.
    ///
    /// # Errors
    ///
    /// Rejects the wrong semantic content kind or an oversized payload.
    pub fn new(
        version: JobIrVersion,
        content: DurableContentRef,
    ) -> Result<Self, JournalInvariantError> {
        let value = Self { version, content };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn version(&self) -> JobIrVersion {
        self.version
    }

    #[must_use]
    pub const fn content(&self) -> &DurableContentRef {
        &self.content
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        if self.content.kind() != ContentKind::JobIr
            || self.content.size() == 0
            || self.content.size() > MAX_JOB_IR_CONTENT_BYTES
        {
            return Err(JournalInvariantError::InvalidJobIrContent);
        }
        Ok(())
    }
}

/// Exact replayable terminal-result outbox entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalResultRecord {
    operation_id: OperationId,
    content: DurableContentRef,
    acknowledged: bool,
}

impl TerminalResultRecord {
    /// Creates an unacknowledged outbox entry from already durable bytes.
    ///
    /// # Errors
    ///
    /// Rejects the wrong semantic content kind or an oversized payload.
    pub fn new(
        operation_id: OperationId,
        content: DurableContentRef,
    ) -> Result<Self, JournalInvariantError> {
        let value = Self {
            operation_id,
            content,
            acknowledged: false,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn content(&self) -> &DurableContentRef {
        &self.content
    }

    #[must_use]
    pub const fn is_acknowledged(&self) -> bool {
        self.acknowledged
    }

    pub(crate) fn acknowledge(&mut self) {
        self.acknowledged = true;
    }

    pub(crate) fn matches_unacknowledged(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id
            && self.content == other.content
            && !other.acknowledged
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        if self.content.kind() != ContentKind::TerminalResult
            || self.content.size() == 0
            || self.content.size() > MAX_TERMINAL_RESULT_CONTENT_BYTES
        {
            return Err(JournalInvariantError::InvalidTerminalResultContent);
        }
        Ok(())
    }
}
