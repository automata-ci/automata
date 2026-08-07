mod support;

use automata_action_github::{
    ActionMetadataDecoder as _, GithubActionMetadataDecoder, MetadataDecodeErrorKind,
};
use support::{decode, dockerfile_document, metadata_document};

#[test]
fn duplicate_keys_aliases_merge_keys_and_tags_fail_closed() {
    let duplicate =
        decode("runs:\n  using: node24\n  USING: node20\n  main: index.js\n").unwrap_err();
    assert_eq!(duplicate.kind(), MetadataDecodeErrorKind::DuplicateKey);

    let anchor =
        decode("shared: &shared\n  value: one\nruns:\n  using: node24\n  main: index.js\n")
            .unwrap_err();
    assert_eq!(anchor.kind(), MetadataDecodeErrorKind::AliasOrAnchor);

    let alias =
        decode("shared: &shared value\ncopy: *shared\nruns:\n  using: node24\n  main: index.js\n")
            .unwrap_err();
    assert_eq!(alias.kind(), MetadataDecodeErrorKind::AliasOrAnchor);

    let merge =
        decode("future:\n  <<:\n    value: one\nruns:\n  using: node24\n  main: index.js\n")
            .unwrap_err();
    assert_eq!(merge.kind(), MetadataDecodeErrorKind::MergeKey);

    let tag = decode("runs:\n  using: node24\n  main: !!str index.js\n").unwrap_err();
    assert_eq!(tag.kind(), MetadataDecodeErrorKind::ExplicitTag);
}

#[test]
fn malformed_multidocument_and_complex_key_yaml_is_rejected() {
    let malformed = decode("runs: [\n").unwrap_err();
    assert_eq!(malformed.kind(), MetadataDecodeErrorKind::InvalidYaml);

    let documents = decode(
        "runs:\n  using: node24\n  main: index.js\n---\nruns:\n  using: node24\n  main: other.js\n",
    )
    .unwrap_err();
    assert_eq!(documents.kind(), MetadataDecodeErrorKind::InvalidYaml);

    let complex = decode("? [complex, key]\n: value\nruns:\n  using: node24\n  main: index.js\n")
        .unwrap_err();
    assert_eq!(complex.kind(), MetadataDecodeErrorKind::InvalidStructure);
}

#[test]
fn unsupported_plugins_and_runtimes_have_distinct_errors() {
    let plugin = decode("runs:\n  plugin: internal-handler\n").unwrap_err();
    assert_eq!(plugin.kind(), MetadataDecodeErrorKind::UnsupportedPlugin);
    assert_eq!(plugin.field(), "runs.plugin");

    let runtime = decode("runs:\n  using: node99\n  main: index.js\n").unwrap_err();
    assert_eq!(runtime.kind(), MetadataDecodeErrorKind::UnsupportedRuntime);
    assert_eq!(runtime.field(), "runs.using");
}

#[test]
fn kind_specific_required_fields_are_enforced() {
    for (source, field) in [
        ("runs: {}\n", "runs.using"),
        ("runs:\n  using: node24\n", "runs.main"),
        ("runs:\n  using: docker\n", "runs.image"),
        ("runs:\n  using: composite\n", "runs.steps"),
        (
            "runs:\n  using: composite\n  steps:\n    - run: echo hi\n",
            "runs.steps[].shell",
        ),
    ] {
        let error = decode(source).unwrap_err();
        assert_eq!(error.kind(), MetadataDecodeErrorKind::MissingRequiredField);
        assert_eq!(error.field(), field);
    }
}

#[test]
fn javascript_and_local_dockerfile_paths_cannot_escape_the_bundle() {
    for unsafe_path in [
        "/host/index.js",
        "../index.js",
        "dist/../../index.js",
        "dist\\index.js",
        "C:/index.js",
        "dist//index.js",
        "${{inputs.entrypoint}}",
    ] {
        let source = format!("runs:\n  using: node24\n  main: '{unsafe_path}'\n");
        let error = decode(&source).unwrap_err();
        assert_eq!(error.kind(), MetadataDecodeErrorKind::UnsafeEntryPath);
        assert_eq!(error.field(), "runs.main");
    }

    let docker = decode("runs:\n  using: docker\n  image: ../Dockerfile\n").unwrap_err();
    assert_eq!(docker.kind(), MetadataDecodeErrorKind::UnsafeEntryPath);
    assert_eq!(docker.field(), "runs.image");
}

#[test]
fn schema_rejects_unknown_output_and_wrong_runtime_properties() {
    let output =
        decode("outputs:\n  result:\n    future: x\nruns:\n  using: node24\n  main: index.js\n")
            .unwrap_err();
    assert_eq!(output.kind(), MetadataDecodeErrorKind::InvalidStructure);

    let wrong_runtime =
        decode("runs:\n  using: node24\n  main: index.js\n  image: Dockerfile\n").unwrap_err();
    assert_eq!(
        wrong_runtime.kind(),
        MetadataDecodeErrorKind::InvalidStructure
    );
}

#[test]
fn non_metadata_definitions_and_non_utf8_yaml_are_typed() {
    let decoder = GithubActionMetadataDecoder::default();
    let dockerfile = decoder
        .decode(&dockerfile_document(b"FROM scratch\n"))
        .unwrap_err();
    assert_eq!(
        dockerfile.kind(),
        MetadataDecodeErrorKind::UnsupportedDefinition
    );

    let invalid_utf8 = decoder
        .decode(&metadata_document(&[0xff, 0xfe, 0xfd]))
        .unwrap_err();
    assert_eq!(invalid_utf8.kind(), MetadataDecodeErrorKind::InvalidUtf8);
}
