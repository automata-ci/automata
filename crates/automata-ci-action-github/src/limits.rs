use thiserror::Error;

// foundation-governance: parity-limit
const MAX_SOURCE_BYTES: usize = 16_777_216;
// foundation-governance: parity-limit
const MAX_DEPTH: usize = 256;
// foundation-governance: parity-limit
const MAX_NODES: usize = 1_000_000;
// foundation-governance: parity-limit
const MAX_DECODED_TEXT_BYTES: usize = 33_554_432;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubActionMetadataLimitRejection {
    SourceBytes,
    Depth,
    Nodes,
    DecodedTextBytes,
}

const fn metadata_limit_rejection(
    source_bytes: usize,
    depth: usize,
    nodes: usize,
    decoded_text_bytes: usize,
) -> Option<GithubActionMetadataLimitRejection> {
    if source_bytes > MAX_SOURCE_BYTES {
        return Some(GithubActionMetadataLimitRejection::SourceBytes);
    }
    if depth > MAX_DEPTH {
        return Some(GithubActionMetadataLimitRejection::Depth);
    }
    if nodes > MAX_NODES {
        return Some(GithubActionMetadataLimitRejection::Nodes);
    }
    if decoded_text_bytes > MAX_DECODED_TEXT_BYTES {
        return Some(GithubActionMetadataLimitRejection::DecodedTextBytes);
    }
    None
}

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
            || maximum_depth == 0
            || maximum_nodes == 0
            || maximum_decoded_text_bytes == 0
            || metadata_limit_rejection(
                maximum_source_bytes,
                maximum_depth,
                maximum_nodes,
                maximum_decoded_text_bytes,
            )
            .is_some()
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

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        GithubActionMetadataLimitRejection, MAX_DECODED_TEXT_BYTES, MAX_DEPTH, MAX_NODES,
        MAX_SOURCE_BYTES, metadata_limit_rejection,
    };

    #[test]
    fn metadata_source_byte_limit_has_exact_boundaries() {
        assert_eq!(
            metadata_limit_rejection(MAX_SOURCE_BYTES - 1, 1, 1, 1),
            None
        );
        assert_eq!(metadata_limit_rejection(MAX_SOURCE_BYTES, 1, 1, 1), None);
        assert_eq!(
            metadata_limit_rejection(MAX_SOURCE_BYTES + 1, 1, 1, 1),
            Some(GithubActionMetadataLimitRejection::SourceBytes)
        );
    }

    #[test]
    fn metadata_depth_limit_has_exact_boundaries() {
        assert_eq!(metadata_limit_rejection(1, MAX_DEPTH - 1, 1, 1), None);
        assert_eq!(metadata_limit_rejection(1, MAX_DEPTH, 1, 1), None);
        assert_eq!(
            metadata_limit_rejection(1, MAX_DEPTH + 1, 1, 1),
            Some(GithubActionMetadataLimitRejection::Depth)
        );
    }

    #[test]
    fn metadata_node_limit_has_exact_boundaries() {
        assert_eq!(metadata_limit_rejection(1, 1, MAX_NODES - 1, 1), None);
        assert_eq!(metadata_limit_rejection(1, 1, MAX_NODES, 1), None);
        assert_eq!(
            metadata_limit_rejection(1, 1, MAX_NODES + 1, 1),
            Some(GithubActionMetadataLimitRejection::Nodes)
        );
    }

    #[test]
    fn metadata_decoded_text_byte_limit_has_exact_boundaries() {
        assert_eq!(
            metadata_limit_rejection(1, 1, 1, MAX_DECODED_TEXT_BYTES - 1),
            None
        );
        assert_eq!(
            metadata_limit_rejection(1, 1, 1, MAX_DECODED_TEXT_BYTES),
            None
        );
        assert_eq!(
            metadata_limit_rejection(1, 1, 1, MAX_DECODED_TEXT_BYTES + 1),
            Some(GithubActionMetadataLimitRejection::DecodedTextBytes)
        );
    }
}
