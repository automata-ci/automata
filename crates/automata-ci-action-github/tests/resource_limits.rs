use crate::support;

use automata_ci_action_github::{
    ActionMetadataDecoder as _, GithubActionMetadataDecoder, GithubActionMetadataLimits,
    MetadataDecodeErrorKind,
};
use support::metadata_document;

#[test]
fn limit_construction_rejects_zero_and_excessive_values() {
    assert!(GithubActionMetadataLimits::new(0, 1, 1, 1).is_err());
    assert!(GithubActionMetadataLimits::new(1, 0, 1, 1).is_err());
    assert!(GithubActionMetadataLimits::new(1, 1, 0, 1).is_err());
    assert!(GithubActionMetadataLimits::new(1, 1, 1, 0).is_err());
    assert!(GithubActionMetadataLimits::new(16 * 1_024 * 1_024 + 1, 1, 1, 1).is_err());
    assert!(GithubActionMetadataLimits::new(1, 257, 1, 1).is_err());
    assert!(GithubActionMetadataLimits::new(1, 1, 1_000_001, 1).is_err());
}

#[test]
fn source_depth_node_and_decoded_text_budgets_are_independent() {
    let source_limited = GithubActionMetadataDecoder::new(
        GithubActionMetadataLimits::new(16, 100, 1_000, 1_000).unwrap(),
    );
    assert_resource_limit(
        &source_limited,
        b"runs:\n  using: node24\n  main: index.js\n",
        "yaml.source",
    );

    let depth_limited = GithubActionMetadataDecoder::new(
        GithubActionMetadataLimits::new(1_000, 3, 1_000, 1_000).unwrap(),
    );
    assert_resource_limit(
        &depth_limited,
        b"future: [[[[value]]]]\nruns:\n  using: node24\n  main: index.js\n",
        "yaml.depth",
    );

    let node_limited = GithubActionMetadataDecoder::new(
        GithubActionMetadataLimits::new(1_000, 100, 4, 1_000).unwrap(),
    );
    assert_resource_limit(
        &node_limited,
        b"runs:\n  using: node24\n  main: index.js\n",
        "yaml.nodes",
    );

    let text_limited = GithubActionMetadataDecoder::new(
        GithubActionMetadataLimits::new(1_000, 100, 1_000, 8).unwrap(),
    );
    assert_resource_limit(
        &text_limited,
        b"runs:\n  using: node24\n  main: index.js\n",
        "yaml.text",
    );
}

fn assert_resource_limit(decoder: &GithubActionMetadataDecoder, source: &[u8], field: &str) {
    let error = decoder.decode(&metadata_document(source)).unwrap_err();
    assert_eq!(error.kind(), MetadataDecodeErrorKind::ResourceLimit);
    assert_eq!(error.field(), field);
}
