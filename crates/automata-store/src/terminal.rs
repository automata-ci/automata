use async_trait::async_trait;
use automata_core::{AttemptId, JobConclusion, LeaseGuard, OperationId, UnixMillis};
use thiserror::Error;

use crate::{
    AttemptAssignment, DocumentSchema, MAX_TERMINAL_RESULT_BYTES, ObjectKey, Sha256Digest,
    StoreError,
};

/// Immutable, fenced terminal-result object metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalResultMetadata {
    operation_id: OperationId,
    attempt_id: AttemptId,
    assignment: AttemptAssignment,
    guard: LeaseGuard,
    schema: DocumentSchema,
    encoded_size: u64,
    digest: Sha256Digest,
    object_key: ObjectKey,
    conclusion: JobConclusion,
    completed_at: UnixMillis,
    committed_at: UnixMillis,
}

impl TerminalResultMetadata {
    /// Creates validated terminal-result metadata.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized objects and a commit before completion.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        attempt_id: AttemptId,
        assignment: AttemptAssignment,
        guard: LeaseGuard,
        schema: DocumentSchema,
        encoded_size: u64,
        digest: Sha256Digest,
        object_key: ObjectKey,
        conclusion: JobConclusion,
        completed_at: UnixMillis,
        committed_at: UnixMillis,
    ) -> Result<Self, TerminalResultMetadataError> {
        if encoded_size == 0 || encoded_size > MAX_TERMINAL_RESULT_BYTES {
            return Err(TerminalResultMetadataError::InvalidEncodedSize {
                size: encoded_size,
                maximum: MAX_TERMINAL_RESULT_BYTES,
            });
        }
        if committed_at < completed_at {
            return Err(TerminalResultMetadataError::CommittedBeforeCompletion);
        }
        Ok(Self {
            operation_id,
            attempt_id,
            assignment,
            guard,
            schema,
            encoded_size,
            digest,
            object_key,
            conclusion,
            completed_at,
            committed_at,
        })
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
    pub const fn assignment(&self) -> AttemptAssignment {
        self.assignment
    }

    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn schema(&self) -> DocumentSchema {
        self.schema
    }

    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }

    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }

    #[must_use]
    pub const fn committed_at(&self) -> UnixMillis {
        self.committed_at
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TerminalResultMetadataError {
    #[error("terminal result size {size} is outside 1..={maximum}")]
    InvalidEncodedSize { size: u64, maximum: u64 },
    #[error("terminal result was committed before job completion")]
    CommittedBeforeCompletion,
}

/// Result of an immutable terminal metadata commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalResultReceipt {
    metadata: TerminalResultMetadata,
    replayed: bool,
}

impl TerminalResultReceipt {
    #[must_use]
    pub const fn new(metadata: TerminalResultMetadata, replayed: bool) -> Self {
        Self { metadata, replayed }
    }

    #[must_use]
    pub const fn metadata(&self) -> &TerminalResultMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        self.replayed
    }
}

/// Fenced immutable terminal-result metadata port.
#[async_trait]
pub trait TerminalResultRepository: Send + Sync {
    /// Commits the first fenced result. An exact retry replays the original
    /// metadata; any reuse of the attempt or operation key with different
    /// immutable contents conflicts.
    async fn commit_terminal_result(
        &self,
        metadata: TerminalResultMetadata,
    ) -> Result<TerminalResultReceipt, StoreError>;
}
