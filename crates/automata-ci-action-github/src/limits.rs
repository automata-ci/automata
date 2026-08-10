use thiserror::Error;

const MAX_SOURCE_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_DEPTH: usize = 256;
const MAX_NODES: usize = 1_000_000;
const MAX_DECODED_TEXT_BYTES: usize = 32 * 1_024 * 1_024;

/// Independent ceilings applied before and during YAML decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubActionMetadataLimits {
    source_bytes: usize,
    depth: usize,
    nodes: usize,
    decoded_text_bytes: usize,
}

impl GithubActionMetadataLimits {
    /// Creates a bounded metadata policy.
    ///
    /// # Errors
    ///
    /// Rejects zero values and values above the hard safety ceilings.
    pub const fn new(
        maximum_source_bytes: usize,
        maximum_depth: usize,
        maximum_nodes: usize,
        maximum_decoded_text_bytes: usize,
    ) -> Result<Self, GithubActionMetadataLimitsError> {
        if maximum_source_bytes == 0
            || maximum_source_bytes > MAX_SOURCE_BYTES
            || maximum_depth == 0
            || maximum_depth > MAX_DEPTH
            || maximum_nodes == 0
            || maximum_nodes > MAX_NODES
            || maximum_decoded_text_bytes == 0
            || maximum_decoded_text_bytes > MAX_DECODED_TEXT_BYTES
        {
            return Err(GithubActionMetadataLimitsError);
        }
        Ok(Self {
            source_bytes: maximum_source_bytes,
            depth: maximum_depth,
            nodes: maximum_nodes,
            decoded_text_bytes: maximum_decoded_text_bytes,
        })
    }

    #[must_use]
    /// Returns the maximum accepted encoded YAML size in bytes.
    pub const fn maximum_source_bytes(self) -> usize {
        self.source_bytes
    }

    #[must_use]
    /// Returns the maximum nested YAML collection depth.
    pub const fn maximum_depth(self) -> usize {
        self.depth
    }

    #[must_use]
    /// Returns the maximum number of scalar and collection nodes.
    pub const fn maximum_nodes(self) -> usize {
        self.nodes
    }

    #[must_use]
    /// Returns the maximum aggregate bytes across decoded YAML scalar text.
    pub const fn maximum_decoded_text_bytes(self) -> usize {
        self.decoded_text_bytes
    }
}

impl Default for GithubActionMetadataLimits {
    fn default() -> Self {
        // Matches the reviewed runner's depth/event scale while remaining below the
        // provider-neutral action document hard ceiling.
        Self {
            source_bytes: 10 * 1_024 * 1_024,
            depth: 100,
            nodes: 1_000_000,
            decoded_text_bytes: 16 * 1_024 * 1_024,
        }
    }
}

/// Error returned when requested metadata limits are zero or exceed hard safety ceilings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub action metadata limit is zero or exceeds a hard safety ceiling")]
pub struct GithubActionMetadataLimitsError;
