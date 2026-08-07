use std::num::NonZeroU64;

use automata_core::{LogSequence, LogStreamId};
use automata_runner_spool::{ContentKind, DurableContentRef};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{JournalInvariantError, MAX_LOG_SPOOL_CONTENT_BYTES};

/// One-based local sequence for retryable runner-to-control-plane operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OutboundOperationSequence(NonZeroU64);

impl OutboundOperationSequence {
    pub const MAX: u64 = i64::MAX as u64;

    /// Creates a bounded one-based sequence.
    ///
    /// # Errors
    ///
    /// Rejects zero and values that cannot fit durable signed storage.
    pub fn new(value: u64) -> Result<Self, JournalInvariantError> {
        if value > Self::MAX {
            return Err(JournalInvariantError::InvalidOutboundOperationSequence);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(JournalInvariantError::InvalidOutboundOperationSequence)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn checked_next(self) -> Result<Self, JournalInvariantError> {
        let next = self
            .get()
            .checked_add(1)
            .ok_or(JournalInvariantError::CounterExhausted)?;
        Self::new(next).map_err(|_| JournalInvariantError::CounterExhausted)
    }
}

impl<'de> Deserialize<'de> for OutboundOperationSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Highest contiguous runner operation made durable for retry/replay.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundOperationCursor {
    contiguous_through: Option<OutboundOperationSequence>,
}

impl OutboundOperationCursor {
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            contiguous_through: None,
        }
    }

    #[must_use]
    pub const fn contiguous_through(self) -> Option<OutboundOperationSequence> {
        self.contiguous_through
    }

    pub(crate) fn advance(
        &mut self,
        received: OutboundOperationSequence,
    ) -> Result<(), JournalInvariantError> {
        let expected = match self.contiguous_through {
            Some(current) => current.checked_next()?,
            None => OutboundOperationSequence(NonZeroU64::MIN),
        };
        if received != expected {
            return Err(JournalInvariantError::OutboundOperationSequenceMismatch {
                expected,
                received,
            });
        }
        self.contiguous_through = Some(received);
        Ok(())
    }
}

/// Local production and remote acknowledgement cursors for a durable log
/// stream. Payload bytes live in the log spool, not in this metadata journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogDeliveryCursor {
    stream_id: LogStreamId,
    spool_content: DurableContentRef,
    produced_through: Option<LogSequence>,
    acknowledged_through: Option<LogSequence>,
    end_of_stream: Option<LogSequence>,
}

impl LogDeliveryCursor {
    /// Opens a stream bound to an already durable, empty spool object.
    ///
    /// # Errors
    ///
    /// Rejects a non-log, non-empty, or oversized initial object.
    pub fn new(
        stream_id: LogStreamId,
        spool_content: DurableContentRef,
    ) -> Result<Self, JournalInvariantError> {
        let value = Self {
            stream_id,
            spool_content,
            produced_through: None,
            acknowledged_through: None,
            end_of_stream: None,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    #[must_use]
    pub const fn spool_content(&self) -> &DurableContentRef {
        &self.spool_content
    }

    #[must_use]
    pub const fn produced_through(&self) -> Option<LogSequence> {
        self.produced_through
    }

    #[must_use]
    pub const fn acknowledged_through(&self) -> Option<LogSequence> {
        self.acknowledged_through
    }

    #[must_use]
    pub const fn end_of_stream(&self) -> Option<LogSequence> {
        self.end_of_stream
    }

    /// Whether a terminal frame was produced and every frame through it was
    /// durably acknowledged by the control plane.
    #[must_use]
    pub fn is_fully_delivered(&self) -> bool {
        self.end_of_stream
            .is_some_and(|end| self.acknowledged_through == Some(end))
    }

    pub(crate) fn record_produced(
        &mut self,
        sequence: LogSequence,
        end_of_stream: bool,
        spool_content: DurableContentRef,
    ) -> Result<(), JournalInvariantError> {
        if self.end_of_stream.is_some() {
            return Err(JournalInvariantError::LogStreamClosed);
        }
        let expected = match self.produced_through {
            Some(current) => current
                .checked_next()
                .map_err(|_| JournalInvariantError::CounterExhausted)?,
            None => LogSequence::new(0),
        };
        if sequence != expected {
            return Err(JournalInvariantError::LogProductionGap);
        }
        validate_log_content(&spool_content)?;
        if spool_content.size() <= self.spool_content.size() {
            return Err(JournalInvariantError::LogSpoolRegression);
        }
        self.spool_content = spool_content;
        self.produced_through = Some(sequence);
        if end_of_stream {
            self.end_of_stream = Some(sequence);
        }
        Ok(())
    }

    pub(crate) fn acknowledge(
        &mut self,
        sequence: LogSequence,
    ) -> Result<(), JournalInvariantError> {
        let Some(produced) = self.produced_through else {
            return Err(JournalInvariantError::InvalidLogAcknowledgement);
        };
        if sequence > produced || self.acknowledged_through.is_some_and(|old| sequence < old) {
            return Err(JournalInvariantError::InvalidLogAcknowledgement);
        }
        self.acknowledged_through = Some(sequence);
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        validate_log_content(&self.spool_content)?;
        if self.produced_through.is_none() && self.spool_content.size() != 0 {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        Ok(())
    }
}

fn validate_log_content(content: &DurableContentRef) -> Result<(), JournalInvariantError> {
    if content.kind() != ContentKind::LogSpool || content.size() > MAX_LOG_SPOOL_CONTENT_BYTES {
        Err(JournalInvariantError::InvalidLogSpoolContent)
    } else {
        Ok(())
    }
}

/// One exact durable log-spool advance correlated to a protocol frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogProductionRecord {
    stream_id: LogStreamId,
    sequence: LogSequence,
    end_of_stream: bool,
    spool_content: DurableContentRef,
}

impl LogProductionRecord {
    /// Binds a produced frame to the cumulative spool bytes committed first.
    ///
    /// # Errors
    ///
    /// Rejects the wrong content kind or an oversized spool object.
    pub fn new(
        stream_id: LogStreamId,
        sequence: LogSequence,
        end_of_stream: bool,
        spool_content: DurableContentRef,
    ) -> Result<Self, JournalInvariantError> {
        validate_log_content(&spool_content)?;
        Ok(Self {
            stream_id,
            sequence,
            end_of_stream,
            spool_content,
        })
    }

    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    #[must_use]
    pub const fn sequence(&self) -> LogSequence {
        self.sequence
    }

    #[must_use]
    pub const fn end_of_stream(&self) -> bool {
        self.end_of_stream
    }

    #[must_use]
    pub const fn spool_content(&self) -> &DurableContentRef {
        &self.spool_content
    }
}
