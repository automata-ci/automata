//! Trusted resource budgets applied to complete protocol frames.

use thiserror::Error;

/// Absolute ceiling accepted by the JSON protocol implementation.
pub const MAX_CONFIGURABLE_FRAME_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_FRAME_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_COLLECTION_ITEMS: usize = 4_096;
const DEFAULT_TEXT_BYTES: usize = 1024 * 1024;
const DEFAULT_LOG_FRAMES: usize = 16;
const DEFAULT_LOG_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Bounded allocation policy selected by trusted transport configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    frame_bytes: usize,
    collection_items: usize,
    text_bytes: usize,
    log_frames_per_batch: usize,
    log_payload_bytes_per_batch: usize,
}

impl ProtocolLimits {
    /// Creates a coherent set of nonzero resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolLimitsError`] if a value is zero, the frame ceiling is
    /// exceeded, or a nested budget is larger than its containing budget.
    pub const fn new(
        max_frame_bytes: usize,
        max_collection_items: usize,
        max_text_bytes: usize,
        max_log_frames_per_batch: usize,
        max_log_payload_bytes_per_batch: usize,
    ) -> Result<Self, ProtocolLimitsError> {
        if max_frame_bytes == 0
            || max_collection_items == 0
            || max_text_bytes == 0
            || max_log_frames_per_batch == 0
            || max_log_payload_bytes_per_batch == 0
        {
            return Err(ProtocolLimitsError::ZeroLimit);
        }
        if max_frame_bytes > MAX_CONFIGURABLE_FRAME_BYTES {
            return Err(ProtocolLimitsError::FrameLimitTooLarge);
        }
        if max_text_bytes > max_frame_bytes
            || max_log_payload_bytes_per_batch > max_frame_bytes
            || max_log_frames_per_batch > max_collection_items
        {
            return Err(ProtocolLimitsError::Incoherent);
        }
        Ok(Self {
            frame_bytes: max_frame_bytes,
            collection_items: max_collection_items,
            text_bytes: max_text_bytes,
            log_frames_per_batch: max_log_frames_per_batch,
            log_payload_bytes_per_batch: max_log_payload_bytes_per_batch,
        })
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.frame_bytes
    }

    #[must_use]
    pub const fn max_collection_items(self) -> usize {
        self.collection_items
    }

    #[must_use]
    pub const fn max_text_bytes(self) -> usize {
        self.text_bytes
    }

    #[must_use]
    pub const fn max_log_frames_per_batch(self) -> usize {
        self.log_frames_per_batch
    }

    #[must_use]
    pub const fn max_log_payload_bytes_per_batch(self) -> usize {
        self.log_payload_bytes_per_batch
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            frame_bytes: DEFAULT_FRAME_BYTES,
            collection_items: DEFAULT_COLLECTION_ITEMS,
            text_bytes: DEFAULT_TEXT_BYTES,
            log_frames_per_batch: DEFAULT_LOG_FRAMES,
            log_payload_bytes_per_batch: DEFAULT_LOG_PAYLOAD_BYTES,
        }
    }
}

/// Invalid trusted protocol-limit configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolLimitsError {
    #[error("protocol limits must be nonzero")]
    ZeroLimit,
    #[error("protocol frame limit exceeds the absolute 64 MiB ceiling")]
    FrameLimitTooLarge,
    #[error("nested protocol limits must fit inside their containing budgets")]
    Incoherent,
}
