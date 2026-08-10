mod support;

use automata_ci_action_github::{JavascriptRuntime, MetadataDecodeErrorKind};
use support::decode;

#[test]
fn using_values_and_input_metadata_names_are_case_insensitive() {
    let metadata = decode(
        r"
name: Case
description: Case
inputs:
  value:
    DEFAULT: fallback
    DEPRECATIONMESSAGE: old
runs:
  using: NoDe24
  main: index.js
",
    )
    .unwrap();
    assert_eq!(
        metadata.javascript().unwrap().runtime(),
        JavascriptRuntime::Node24
    );
    assert_eq!(metadata.inputs()[0].default().unwrap().text(), "fallback");
    assert_eq!(
        metadata.inputs()[0].deprecation_message().unwrap().text(),
        "old"
    );
}

#[test]
fn unknown_top_level_fields_are_ignored_but_retained_as_names() {
    let metadata = decode(
        r"
name: Forward compatible
description: Forward compatible
branding:
  icon: box
future-field:
  nested: [one, two]
runs:
  using: node24
  main: index.js
",
    )
    .unwrap();
    assert_eq!(
        metadata.ignored_top_level_keys(),
        &["branding".to_owned(), "future-field".to_owned()]
    );
}

#[test]
fn unknown_runs_fields_are_rejected_like_the_runner_schema() {
    let error = decode(
        "name: X\ndescription: X\nruns:\n  using: node24\n  main: index.js\n  future: true\n",
    )
    .unwrap_err();
    assert_eq!(error.kind(), MetadataDecodeErrorKind::InvalidStructure);
    assert_eq!(error.field(), "runs.property");
}

#[test]
fn runner_key_casing_is_not_silently_canonicalized() {
    let top_level =
        decode("name: X\ndescription: X\nRUNS:\n  using: node24\n  main: index.js\n").unwrap_err();
    assert_eq!(
        top_level.kind(),
        MetadataDecodeErrorKind::MissingRequiredField
    );
    assert_eq!(top_level.field(), "runs");

    let run_property =
        decode("name: X\ndescription: X\nruns:\n  using: node24\n  MAIN: index.js\n").unwrap_err();
    assert_eq!(
        run_property.kind(),
        MetadataDecodeErrorKind::MissingRequiredField
    );
    assert_eq!(run_property.field(), "runs.main");
}

#[test]
fn absent_display_fields_match_the_runner_load_contract() {
    let metadata = decode("runs:\n  using: node24\n  main: index.js\n").unwrap();
    assert_eq!(metadata.name(), None);
    assert_eq!(metadata.description(), None);
}

#[test]
fn every_javascript_runtime_accepted_by_the_baseline_is_modeled() {
    for (using, expected) in [
        ("node12", JavascriptRuntime::Node12),
        ("node16", JavascriptRuntime::Node16),
        ("node20", JavascriptRuntime::Node20),
        ("node24", JavascriptRuntime::Node24),
    ] {
        let source = format!("runs:\n  using: {using}\n  main: index.js\n");
        let metadata = decode(&source).unwrap();
        assert_eq!(metadata.javascript().unwrap().runtime(), expected);
    }
}
