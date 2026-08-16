use crate::support;

use automata_ci_workflow_github::{ScalarResolution, YamlNode};

const WORKFLOW_LF: &str =
    "on: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo test\n";

#[test]
fn bom_and_newline_style_are_retained_but_do_not_change_semantics() {
    let bom = format!("\u{feff}{WORKFLOW_LF}");
    let crlf = WORKFLOW_LF.replace('\n', "\r\n");
    let plain = support::parse_accepted(WORKFLOW_LF);
    let with_bom = support::parse_accepted(&bom);
    let with_crlf = support::parse_accepted(&crlf);
    assert_eq!(with_bom.plan().expect("BOM plan").source().text(), bom);
    assert_eq!(with_crlf.plan().expect("CRLF plan").source().text(), crlf);
    assert_eq!(workflow_shape(&plain), workflow_shape(&with_bom));
    assert_eq!(workflow_shape(&plain), workflow_shape(&with_crlf));
    let bom_root = with_bom
        .plan()
        .expect("BOM plan")
        .document()
        .root()
        .as_mapping()
        .expect("root mapping");
    assert_eq!(bom_root[0].key().span().start().byte_offset(), 3);
    assert_eq!(
        with_bom
            .plan()
            .expect("BOM plan")
            .source()
            .slice(bom_root[0].key().span()),
        Some("on")
    );
}

#[test]
fn empty_and_trailing_documents_are_rejected_as_document_count_errors() {
    let empty = support::parse("");
    assert!(empty.plan().is_none());
    assert!(
        empty
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.document_count")
    );

    let explicit_empty = support::parse("---\n");
    assert!(explicit_empty.plan().is_none());
    assert!(
        explicit_empty
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.expected_mapping")
    );

    let trailing = support::parse("on: push\njobs: {}\n---\n");
    assert!(trailing.plan().is_none());
    assert!(
        trailing
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.document_count")
    );
}

#[test]
fn quoted_and_unquoted_on_keys_decode_identically() {
    let unquoted = support::parse_accepted(WORKFLOW_LF);
    let quoted = support::parse_accepted(&WORKFLOW_LF.replacen("on:", "'on':", 1));
    assert_eq!(workflow_shape(&unquoted), workflow_shape(&quoted));
}

#[test]
fn yaml_1_2_does_not_resolve_on_off_yes_or_no_as_booleans() {
    let source = "on: push\nenv:\n  ON_VALUE: on\n  OFF_VALUE: off\n  YES_VALUE: yes\n  NO_VALUE: no\n  TRUE_VALUE: true\n  QUOTED_TRUE: 'true'\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo test\n";
    let report = support::parse_accepted(source);
    let plan = report.plan().expect("plan");
    let root = plan.document().root().as_mapping().expect("mapping");
    let on_key = root[0].key().as_scalar().expect("on key");
    assert_eq!(on_key.decoded(), "on");
    assert_eq!(on_key.resolution(), ScalarResolution::String);

    let env = mapping_value(plan.document().root(), "env");
    let env = env.as_mapping().expect("env mapping");
    let resolutions = env
        .iter()
        .map(|entry| {
            (
                entry.key().as_scalar().expect("key").decoded(),
                entry.value().as_scalar().expect("value").resolution(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        resolutions,
        [
            ("ON_VALUE", ScalarResolution::String),
            ("OFF_VALUE", ScalarResolution::String),
            ("YES_VALUE", ScalarResolution::String),
            ("NO_VALUE", ScalarResolution::String),
            ("TRUE_VALUE", ScalarResolution::Boolean),
            ("QUOTED_TRUE", ScalarResolution::String),
        ]
    );
}

#[test]
fn yaml_1_2_numeric_resolution_rejects_underscores_and_signed_nondecimal_integers() {
    let source = "on: push\nenv:\n  UNDERSCORED_INTEGER: 1_000\n  UNDERSCORED_FLOAT: 1.0_0\n  SIGNED_HEX: -0x10\n  INTEGER: 1000\n  HEX: 0x10\n  FLOAT: .5\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo test\n";
    let report = support::parse_accepted(source);

    let env = mapping_value(report.plan().expect("plan").document().root(), "env");
    let resolutions = env
        .as_mapping()
        .expect("env mapping")
        .iter()
        .map(|entry| entry.value().as_scalar().expect("value").resolution())
        .collect::<Vec<_>>();
    assert_eq!(
        resolutions,
        [
            ScalarResolution::String,
            ScalarResolution::String,
            ScalarResolution::String,
            ScalarResolution::Integer,
            ScalarResolution::Integer,
            ScalarResolution::Float,
        ]
    );
}

#[test]
fn original_text_is_an_exact_round_trip_artifact() {
    let source = include_str!("fixtures/valid.yml");
    let report = support::parse(source);
    let plan = report.plan().expect("plan");
    assert_eq!(plan.source().text().as_bytes(), source.as_bytes());
    assert!(plan.source().text().starts_with("# The comments"));
}

#[test]
fn spans_use_utf8_byte_offsets_and_one_based_display_locations() {
    let source = "name: 'café'\non: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo test\n";
    let report = support::parse_accepted(source);
    let plan = report.plan().expect("plan");
    let name = plan.document().root().as_mapping().expect("mapping")[0].value();
    assert_eq!(plan.source().slice(name.span()), Some("'café'"));
    assert_eq!(name.span().start().line(), 1);
    assert_eq!(name.span().start().column(), 7);
    assert_eq!(
        name.span().end().byte_offset() - name.span().start().byte_offset(),
        7
    );
}

fn mapping_value<'node>(node: &'node YamlNode, key: &str) -> &'node YamlNode {
    node.as_mapping()
        .expect("mapping")
        .iter()
        .find(|entry| {
            entry
                .key()
                .as_scalar()
                .is_some_and(|scalar| scalar.decoded() == key)
        })
        .expect("key")
        .value()
}

fn workflow_shape(
    report: &automata_ci_workflow_github::GithubFrontendReport,
) -> (Vec<String>, Vec<String>) {
    let workflow = report.plan().expect("plan").workflow();
    let events = workflow
        .triggers()
        .expect("triggers")
        .events()
        .iter()
        .map(|event| format!("{:?}", event.name().value()))
        .collect();
    let jobs = workflow
        .jobs()
        .iter()
        .map(|job| job.id().as_str().to_owned())
        .collect();
    (events, jobs)
}
