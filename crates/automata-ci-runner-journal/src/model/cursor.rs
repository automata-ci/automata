use std::num::NonZeroU64;

use automata_ci_core::{LogSequence, LogStreamId, UnixMillis};
use automata_ci_runner_spool::{ContentKind, DurableContentRef};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    JournalInvariantError, MAX_LOG_SEGMENT_FRAMES, MAX_LOG_SEGMENTS_PER_SLOT,
    MAX_LOG_SPOOL_CONTENT_BYTES,
};

/// One-based local sequence for retryable runner-to-control-plane operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OutboundOperationSequence(NonZeroU64);

impl OutboundOperationSequence {
    /// Largest sequence representable in signed durable storage.
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

    /// Returns the one-based numeric sequence.
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
    /// Creates a cursor before any outbound operation has been committed.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            contiguous_through: None,
        }
    }

    /// Returns the highest contiguous operation known durable, if any.
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

/// One immutable, bounded log-delivery segment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogSegment {
    first_sequence: LogSequence,
    last_sequence: LogSequence,
    frame_count: u32,
    payload_bytes: u64,
    content: DurableContentRef,
    sealed: bool,
    end_of_stream: bool,
}

impl LogSegment {
    /// Describes an immutable segment object already committed to the spool.
    ///
    /// # Errors
    ///
    /// Rejects empty, non-contiguous, oversized, or incoherent metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        first_sequence: LogSequence,
        last_sequence: LogSequence,
        frame_count: u32,
        payload_bytes: u64,
        content: DurableContentRef,
        sealed: bool,
        end_of_stream: bool,
    ) -> Result<Self, JournalInvariantError> {
        let value = Self {
            first_sequence,
            last_sequence,
            frame_count,
            payload_bytes,
            content,
            sealed,
            end_of_stream,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the first logical frame sequence stored in this object.
    #[must_use]
    pub const fn first_sequence(&self) -> LogSequence {
        self.first_sequence
    }

    /// Returns the last logical frame sequence stored in this object.
    #[must_use]
    pub const fn last_sequence(&self) -> LogSequence {
        self.last_sequence
    }

    /// Returns the exact number of contiguous frames in the object.
    #[must_use]
    pub const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Returns the unencoded application-payload byte count.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Returns the immutable spool identity containing the encoded frames.
    #[must_use]
    pub const fn content(&self) -> &DurableContentRef {
        &self.content
    }

    /// Reports whether the object can serve as the delivery head.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Reports whether the final frame closes the stream.
    #[must_use]
    pub const fn ends_stream(&self) -> bool {
        self.end_of_stream
    }

    fn seal(&mut self) {
        self.sealed = true;
    }

    fn validate(&self) -> Result<(), JournalInvariantError> {
        validate_log_content(&self.content)?;
        let expected_frames = self
            .last_sequence
            .get()
            .checked_sub(self.first_sequence.get())
            .and_then(|span| span.checked_add(1))
            .ok_or(JournalInvariantError::InvalidLogSegment)?;
        if self.content.accounted_bytes() == 0
            || self.frame_count == 0
            || usize::try_from(self.frame_count).unwrap_or(usize::MAX) > MAX_LOG_SEGMENT_FRAMES
            || u64::from(self.frame_count) != expected_frames
            || self.payload_bytes > MAX_LOG_SPOOL_CONTENT_BYTES
            || self.payload_bytes > self.content.accounted_bytes()
            || (self.end_of_stream && !self.sealed)
        {
            return Err(JournalInvariantError::InvalidLogSegment);
        }
        Ok(())
    }
}

/// One payload-first replacement or creation of the single open tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogSegmentPublication {
    stream_id: LogStreamId,
    previous_open_content: Option<DurableContentRef>,
    segment: LogSegment,
}

impl LogSegmentPublication {
    /// Binds new immutable bytes to the exact open-tail identity they replace.
    ///
    /// `previous_open_content` is absent only when starting a new segment.
    ///
    /// # Errors
    ///
    /// Rejects invalid segment metadata or a non-log previous identity.
    pub fn new(
        stream_id: LogStreamId,
        previous_open_content: Option<DurableContentRef>,
        segment: LogSegment,
    ) -> Result<Self, JournalInvariantError> {
        segment.validate()?;
        if let Some(previous) = &previous_open_content {
            validate_log_content(previous)?;
        }
        Ok(Self {
            stream_id,
            previous_open_content,
            segment,
        })
    }

    /// Returns the slot's durable log-stream identity.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    /// Returns the exact open object replaced by this payload-first update.
    #[must_use]
    pub const fn previous_open_content(&self) -> Option<&DurableContentRef> {
        self.previous_open_content.as_ref()
    }

    /// Returns the immutable replacement or newly created tail description.
    #[must_use]
    pub const fn segment(&self) -> &LogSegment {
        &self.segment
    }
}

/// Exact identity of one sealed head accepted by the control plane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogSegmentAcknowledgement {
    stream_id: LogStreamId,
    through: LogSequence,
    head_content: DurableContentRef,
}

impl LogSegmentAcknowledgement {
    /// Creates an ACK fenced to one immutable durable head.
    ///
    /// # Errors
    ///
    /// Rejects a non-log or oversized content identity.
    pub fn new(
        stream_id: LogStreamId,
        through: LogSequence,
        head_content: DurableContentRef,
    ) -> Result<Self, JournalInvariantError> {
        validate_log_content(&head_content)?;
        Ok(Self {
            stream_id,
            through,
            head_content,
        })
    }

    /// Returns the durable stream identity accepted by the control plane.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    /// Returns the final frame sequence of the accepted sealed head.
    #[must_use]
    pub const fn through(&self) -> LogSequence {
        self.through
    }

    /// Returns the exact immutable head identity that was accepted.
    ///
    /// ACK processing compares this value with the current sealed head and
    /// retains it as the single bounded replay witness; an ACK never supplies
    /// or creates payload bytes.
    #[must_use]
    pub const fn head_content(&self) -> &DurableContentRef {
        &self.head_content
    }

    fn validate(&self) -> Result<(), JournalInvariantError> {
        validate_log_content(&self.head_content)
    }
}

/// Local production and remote acknowledgement state for a durable segmented
/// log stream. Segment bytes live in immutable spool objects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogDeliveryCursor {
    stream_id: LogStreamId,
    segments: Vec<LogSegment>,
    segment_enqueued_at: Vec<UnixMillis>,
    produced_through: Option<LogSequence>,
    end_of_stream: Option<LogSequence>,
    last_acknowledgement: Option<LogSegmentAcknowledgement>,
}

impl LogDeliveryCursor {
    /// Opens an empty durable stream.
    #[must_use]
    pub const fn new(stream_id: LogStreamId) -> Self {
        Self {
            stream_id,
            segments: Vec::new(),
            segment_enqueued_at: Vec::new(),
            produced_through: None,
            end_of_stream: None,
            last_acknowledgement: None,
        }
    }

    /// Returns the one stream identity permanently bound to this cursor.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }

    /// Returns retained immutable segments in delivery order.
    #[must_use]
    pub fn segments(&self) -> &[LogSegment] {
        &self.segments
    }

    /// Returns the exact next segment eligible for acknowledgement.
    #[must_use]
    pub fn head_segment(&self) -> Option<&LogSegment> {
        self.segments.first()
    }

    /// Returns the single unsealed tail eligible for payload-first replacement.
    #[must_use]
    pub fn open_segment(&self) -> Option<&LogSegment> {
        self.segments.last().filter(|segment| !segment.is_sealed())
    }

    /// Returns the highest logical frame sequence committed locally.
    #[must_use]
    pub const fn produced_through(&self) -> Option<LogSequence> {
        self.produced_through
    }

    /// Returns the highest exact-head acknowledgement retained for replay.
    #[must_use]
    pub fn acknowledged_through(&self) -> Option<LogSequence> {
        self.last_acknowledgement
            .as_ref()
            .map(LogSegmentAcknowledgement::through)
    }

    /// Returns the terminal frame sequence, once produced.
    #[must_use]
    pub const fn end_of_stream(&self) -> Option<LogSequence> {
        self.end_of_stream
    }

    /// Whether a terminal frame was produced and every frame through it was
    /// durably acknowledged by the control plane.
    #[must_use]
    pub fn is_fully_delivered(&self) -> bool {
        self.end_of_stream
            .is_some_and(|end| self.acknowledged_through() == Some(end) && self.segments.is_empty())
    }

    /// Returns the aggregate immutable object bytes still retained for delivery.
    ///
    /// The value is saturating for inspection; journal mutations reject before
    /// the configured per-slot content ceiling can be crossed.
    #[must_use]
    pub fn backlog_content_bytes(&self) -> u64 {
        self.segments.iter().fold(0_u64, |total, segment| {
            total.saturating_add(segment.content().accounted_bytes())
        })
    }

    pub(crate) fn oldest_pending_enqueued_at(&self) -> Option<UnixMillis> {
        self.segment_enqueued_at.first().copied()
    }

    pub(crate) fn record_segment(
        &mut self,
        publication: &LogSegmentPublication,
        enqueued_at: UnixMillis,
    ) -> Result<(), JournalInvariantError> {
        if self.end_of_stream.is_some() {
            return Err(JournalInvariantError::LogStreamClosed);
        }
        let candidate = publication.segment();
        candidate.validate()?;
        let expected_first = self.produced_through.map_or_else(
            || Ok(LogSequence::new(0)),
            |sequence| {
                sequence
                    .checked_next()
                    .map_err(|_| JournalInvariantError::CounterExhausted)
            },
        )?;
        if let Some(previous) = publication.previous_open_content() {
            let current = self
                .segments
                .last()
                .ok_or(JournalInvariantError::LogSegmentMutationConflict)?;
            if current.is_sealed() || current.content() != previous {
                return Err(JournalInvariantError::LogSegmentMutationConflict);
            }
            let expected_last = current
                .last_sequence()
                .checked_next()
                .map_err(|_| JournalInvariantError::CounterExhausted)?;
            if candidate.first_sequence() != current.first_sequence()
                || candidate.last_sequence() != expected_last
                || candidate.frame_count() != current.frame_count().saturating_add(1)
                || candidate.payload_bytes() < current.payload_bytes()
                || candidate.content().accounted_bytes() <= current.content().accounted_bytes()
            {
                return Err(JournalInvariantError::InvalidLogSegment);
            }
            let retained = self
                .backlog_content_bytes()
                .checked_sub(current.content().accounted_bytes())
                .and_then(|bytes| bytes.checked_add(candidate.content().accounted_bytes()))
                .ok_or(JournalInvariantError::LogBacklogLimit)?;
            if retained > MAX_LOG_SPOOL_CONTENT_BYTES {
                return Err(JournalInvariantError::LogBacklogLimit);
            }
            let last = self
                .segments
                .last_mut()
                .ok_or(JournalInvariantError::LogSegmentMutationConflict)?;
            *last = candidate.clone();
        } else {
            crate::validate_delivery_enqueued_at(enqueued_at)?;
            if self.open_segment().is_some()
                || candidate.first_sequence() != expected_first
                || candidate.first_sequence() != candidate.last_sequence()
                || candidate.frame_count() != 1
            {
                return Err(JournalInvariantError::InvalidLogSegment);
            }
            if self.segments.len() >= MAX_LOG_SEGMENTS_PER_SLOT {
                return Err(JournalInvariantError::LogSegmentLimit);
            }
            let retained = self
                .backlog_content_bytes()
                .checked_add(candidate.content().accounted_bytes())
                .ok_or(JournalInvariantError::LogBacklogLimit)?;
            if retained > MAX_LOG_SPOOL_CONTENT_BYTES {
                return Err(JournalInvariantError::LogBacklogLimit);
            }
            self.segments.push(candidate.clone());
            self.segment_enqueued_at.push(enqueued_at);
        }
        self.produced_through = Some(candidate.last_sequence());
        if candidate.ends_stream() {
            self.end_of_stream = Some(candidate.last_sequence());
        }
        Ok(())
    }

    pub(crate) fn seal_segment(
        &mut self,
        expected_content: &DurableContentRef,
    ) -> Result<bool, JournalInvariantError> {
        let tail = self
            .segments
            .last_mut()
            .ok_or(JournalInvariantError::LogSegmentMutationConflict)?;
        if tail.content() != expected_content {
            return Err(JournalInvariantError::LogSegmentMutationConflict);
        }
        if tail.is_sealed() {
            return Ok(false);
        }
        tail.seal();
        Ok(true)
    }

    pub(crate) fn acknowledge_segment(
        &mut self,
        acknowledgement: &LogSegmentAcknowledgement,
    ) -> Result<bool, JournalInvariantError> {
        if let Some(previous) = &self.last_acknowledgement
            && acknowledgement.through().get() <= previous.through().get()
        {
            return if previous == acknowledgement {
                Ok(false)
            } else {
                Err(JournalInvariantError::LogAcknowledgementConflict)
            };
        }
        let head = self
            .segments
            .first()
            .ok_or(JournalInvariantError::InvalidLogAcknowledgement)?;
        if !head.is_sealed()
            || head.last_sequence() != acknowledgement.through()
            || head.content() != acknowledgement.head_content()
        {
            return Err(JournalInvariantError::LogAcknowledgementConflict);
        }
        self.segments.remove(0);
        self.segment_enqueued_at.remove(0);
        self.last_acknowledgement = Some(acknowledgement.clone());
        Ok(true)
    }

    pub(crate) fn validate(&self) -> Result<(), JournalInvariantError> {
        if self.segments.len() > MAX_LOG_SEGMENTS_PER_SLOT {
            return Err(JournalInvariantError::DecodedCollectionLimit);
        }
        if self.segment_enqueued_at.len() != self.segments.len() {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        for enqueued_at in &self.segment_enqueued_at {
            crate::validate_delivery_enqueued_at(*enqueued_at)?;
        }
        if let Some(acknowledgement) = &self.last_acknowledgement {
            acknowledgement.validate()?;
            if acknowledgement.stream_id() != self.stream_id {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
        }
        let mut expected = match (self.last_acknowledgement.as_ref(), self.segments.is_empty()) {
            (_, true) | (None, false) => LogSequence::new(0),
            (Some(acknowledgement), false) => acknowledgement
                .through()
                .checked_next()
                .map_err(|_| JournalInvariantError::DecodedStateInvalid)?,
        };
        let mut total = 0_u64;
        for (index, segment) in self.segments.iter().enumerate() {
            segment.validate()?;
            if segment.first_sequence() != expected
                || (!segment.is_sealed() && index + 1 != self.segments.len())
                || (segment.ends_stream() && index + 1 != self.segments.len())
            {
                return Err(JournalInvariantError::DecodedStateInvalid);
            }
            expected = segment
                .last_sequence()
                .checked_next()
                .map_err(|_| JournalInvariantError::DecodedStateInvalid)?;
            total = total
                .checked_add(segment.content().accounted_bytes())
                .ok_or(JournalInvariantError::DecodedStateInvalid)?;
        }
        if total > MAX_LOG_SPOOL_CONTENT_BYTES {
            return Err(JournalInvariantError::DecodedCollectionLimit);
        }
        let durable_last = self
            .segments
            .last()
            .map(LogSegment::last_sequence)
            .or_else(|| {
                self.last_acknowledgement
                    .as_ref()
                    .map(LogSegmentAcknowledgement::through)
            });
        if self.produced_through != durable_last
            || self.end_of_stream.is_some_and(|end| {
                self.produced_through != Some(end)
                    || self
                        .segments
                        .last()
                        .is_some_and(|segment| !segment.ends_stream())
            })
            || self.segments.iter().any(|segment| {
                segment.ends_stream() && Some(segment.last_sequence()) != self.end_of_stream
            })
        {
            return Err(JournalInvariantError::DecodedStateInvalid);
        }
        Ok(())
    }
}

fn validate_log_content(content: &DurableContentRef) -> Result<(), JournalInvariantError> {
    if content.kind() != ContentKind::LogSpool
        || content.accounted_bytes() > MAX_LOG_SPOOL_CONTENT_BYTES
    {
        Err(JournalInvariantError::InvalidLogSpoolContent)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{LogSequence, LogStreamId, Sha256Digest, UnixMillis};
    use automata_ci_runner_spool::{ContentKind, DurableContentRef, ProtectionId};

    use super::{LogDeliveryCursor, LogSegment, LogSegmentAcknowledgement, LogSegmentPublication};
    use crate::{JournalInvariantError, MAX_LOG_SEGMENTS_PER_SLOT, MAX_LOG_SPOOL_CONTENT_BYTES};

    fn content(size: u64, marker: u8) -> DurableContentRef {
        DurableContentRef::after_public_commit(
            ContentKind::LogSpool,
            size,
            Sha256Digest::from_bytes([marker; 32]),
            ProtectionId::new("cursor-bound-test-key").expect("protection ID"),
        )
        .expect("bounded log content")
    }

    fn sealed_segment(sequence: u64, size: u64, marker: u8) -> LogSegment {
        LogSegment::new(
            LogSequence::new(sequence),
            LogSequence::new(sequence),
            1,
            0,
            content(size, marker),
            true,
            false,
        )
        .expect("sealed segment")
    }

    #[test]
    fn segment_count_is_bounded_before_journal_growth() {
        let stream_id = LogStreamId::new();
        let mut cursor = LogDeliveryCursor::new(stream_id);

        for index in 0..MAX_LOG_SEGMENTS_PER_SLOT {
            let segment = sealed_segment(
                u64::try_from(index).expect("bounded sequence"),
                1,
                u8::try_from(index).unwrap_or(u8::MAX),
            );
            let publication =
                LogSegmentPublication::new(stream_id, None, segment).expect("publication");
            cursor
                .record_segment(&publication, UnixMillis::new(1_000))
                .expect("segment inside bound");
        }

        let overflow = sealed_segment(
            u64::try_from(MAX_LOG_SEGMENTS_PER_SLOT).expect("bounded sequence"),
            1,
            0xfe,
        );
        let publication =
            LogSegmentPublication::new(stream_id, None, overflow).expect("publication");
        assert_eq!(
            cursor.record_segment(&publication, UnixMillis::new(1_000)),
            Err(JournalInvariantError::LogSegmentLimit)
        );
        assert_eq!(cursor.segments().len(), MAX_LOG_SEGMENTS_PER_SLOT);
    }

    #[test]
    fn aggregate_content_is_bounded_before_journal_growth() {
        let stream_id = LogStreamId::new();
        let mut cursor = LogDeliveryCursor::new(stream_id);
        let full = sealed_segment(0, MAX_LOG_SPOOL_CONTENT_BYTES, 0xa5);
        cursor
            .record_segment(
                &LogSegmentPublication::new(stream_id, None, full).expect("publication"),
                UnixMillis::new(1_000),
            )
            .expect("exact aggregate bound");

        let overflow = sealed_segment(1, 1, 0x5a);
        let publication =
            LogSegmentPublication::new(stream_id, None, overflow).expect("publication");
        assert_eq!(
            cursor.record_segment(&publication, UnixMillis::new(2_000)),
            Err(JournalInvariantError::LogBacklogLimit)
        );
        assert_eq!(cursor.segments().len(), 1);
        assert_eq!(cursor.backlog_content_bytes(), MAX_LOG_SPOOL_CONTENT_BYTES);
    }

    #[test]
    fn acknowledgement_older_than_the_bounded_replay_witness_conflicts() {
        let stream_id = LogStreamId::new();
        let mut cursor = LogDeliveryCursor::new(stream_id);
        let first = sealed_segment(0, 1, 0x11);
        let first_content = first.content().clone();
        let second = sealed_segment(1, 1, 0x22);
        let second_content = second.content().clone();
        cursor
            .record_segment(
                &LogSegmentPublication::new(stream_id, None, first).expect("first publication"),
                UnixMillis::new(1_000),
            )
            .expect("first segment");
        cursor
            .record_segment(
                &LogSegmentPublication::new(stream_id, None, second).expect("second publication"),
                UnixMillis::new(2_000),
            )
            .expect("second segment");
        let first_ack =
            LogSegmentAcknowledgement::new(stream_id, LogSequence::new(0), first_content)
                .expect("first ACK");
        cursor
            .acknowledge_segment(&first_ack)
            .expect("acknowledge first head");
        cursor
            .acknowledge_segment(
                &LogSegmentAcknowledgement::new(stream_id, LogSequence::new(1), second_content)
                    .expect("second ACK"),
            )
            .expect("acknowledge second head");

        assert_eq!(
            cursor.acknowledge_segment(&first_ack),
            Err(JournalInvariantError::LogAcknowledgementConflict)
        );
    }
}
