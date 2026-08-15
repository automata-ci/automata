use crate::support;

use automata_ci_workflow_github::{DiagnosticKind, YamlNodeKind};

#[test]
fn malformed_yaml_is_a_syntax_diagnostic_with_no_plan() {
    let report = support::parse(include_str!("fixtures/malformed.yml"));
    assert!(report.plan().is_none());
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.kind() == DiagnosticKind::Syntax)
        .expect("syntax diagnostic");
    assert_eq!(diagnostic.code(), "yaml.invalid_syntax");
    assert!(diagnostic.primary_span().start().line() >= 1);
}

#[test]
fn duplicate_keys_are_semantic_and_point_to_both_definitions() {
    let report = support::parse(include_str!("fixtures/duplicate.yml"));
    assert!(report.plan().is_some());
    let duplicates = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.duplicate_mapping_key")
        .collect::<Vec<_>>();
    assert_eq!(duplicates.len(), 2);
    assert!(duplicates.iter().all(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Semantic && diagnostic.related().len() == 1
    }));
}

#[test]
fn unknown_fields_are_preserved_and_rejected_as_unsupported() {
    let source = "on: push\nmystery: 42\njobs:\n  build:\n    runs-on: linux\n    mystery-job-option: true\n    steps:\n      - run: echo test\n        mystery-step-option: value\n";
    let report = support::parse(source);
    assert!(!report.is_accepted());
    let plan = report.plan().expect("loss-aware plan");
    assert_eq!(plan.workflow().extensions()[0].path(), "workflow.mystery");
    assert_eq!(
        plan.workflow().jobs()[0].job().extensions()[0].path(),
        "jobs.build.mystery-job-option"
    );
    assert_eq!(
        plan.workflow().jobs()[0].job().steps()[0].extensions()[0].path(),
        "jobs.build.steps[0].mystery-step-option"
    );
    assert_eq!(
        report
            .diagnostics_of_kind(DiagnosticKind::Unsupported)
            .count(),
        3
    );
}

#[test]
fn anchors_and_aliases_retain_original_evidence_and_decode_from_an_expanded_tree() {
    let source = include_str!("fixtures/aliases.yml");
    let report = support::parse(source);
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());

    let plan = report.plan().expect("plan");
    let jobs = plan.document().root().as_mapping().expect("root")[3]
        .value()
        .as_mapping()
        .expect("jobs");
    let job_fields = jobs[0].value().as_mapping().expect("job");
    assert!(
        job_fields
            .iter()
            .any(|entry| matches!(entry.value().kind(), YamlNodeKind::Alias(_)))
    );
    let expanded_jobs = plan.expanded_document().root().as_mapping().expect("root")[3]
        .value()
        .as_mapping()
        .expect("jobs");
    let expanded_fields = expanded_jobs[0].value().as_mapping().expect("job");
    assert!(
        expanded_fields
            .iter()
            .all(|entry| { !matches!(entry.value().kind(), YamlNodeKind::Alias(_)) })
    );
}

#[test]
fn yaml_merge_keys_are_called_out_separately_from_alias_support() {
    let source = "on: push\nbase: &base\n  runs-on: linux\njobs:\n  build:\n    <<: *base\n    steps:\n      - run: echo test\n";
    let report = support::parse(source);
    assert!(report.plan().is_some());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.yaml_merge_key")
    );
}

#[test]
fn semantic_step_errors_are_distinct_from_unsupported_fields() {
    let source = "jobs:\n  invalid id!:\n    runs-on: linux\n    steps:\n      - run: echo run\n        uses: actions/example@v1\n";
    let report = support::parse(source);
    assert!(report.plan().is_some());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.triggers_required")
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.invalid_job_id")
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.multiple_step_executions")
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code().starts_with("github."))
            .all(|diagnostic| diagnostic.kind() == DiagnosticKind::Semantic)
    );
}
