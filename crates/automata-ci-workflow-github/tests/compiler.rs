use crate::support;

use automata_ci_core::{WorkflowEventProvenance, WorkflowPlan, WorkflowPlanVersion};
use automata_ci_workflow_github::{
    CompilationDisposition, DiagnosticKind, GithubEventMetadata, WorkflowNotSelectedReason,
};

fn event(name: &str) -> WorkflowEventProvenance {
    WorkflowEventProvenance::new("github", name)
        .with_delivery_id("compiler-current")
        .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
        .with_git_ref("refs/heads/main")
}

fn compile(source: &str, event_name: &str) -> automata_ci_workflow_github::CompilationReport {
    let parsed = support::parse(source);
    let metadata = match event_name {
        "push" => Some(GithubEventMetadata::push(false)),
        "pull_request" => Some(GithubEventMetadata::pull_request("opened", "main")),
        _ => None,
    };
    support::compile(
        parsed.plan().expect("loss-aware source plan"),
        event(event_name),
        metadata,
    )
}

#[test]
fn inherent_compiler_emits_only_the_current_logical_plan() {
    let source = r"on: workflow_dispatch
jobs:
  verify:
    runs-on: linux
    steps:
      - run: echo verify
";
    let parsed = support::parse_accepted(source);
    let report = support::compile(
        parsed.plan().expect("source plan"),
        event("workflow_dispatch"),
        None,
    );

    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let plan = report.plan().expect("current plan");
    assert_eq!(plan.version(), WorkflowPlanVersion::v1());
    assert_eq!(plan.jobs().len(), 1);
    plan.validate().expect("valid current plan");
    let encoded = serde_json::to_string(plan).expect("serialize plan");
    let decoded: WorkflowPlan = serde_json::from_str(&encoded).expect("deserialize plan");
    assert_eq!(decoded, *plan);
}

#[test]
fn compiler_rejects_duplicate_keys_retained_by_the_loss_aware_frontend() {
    let report = compile(
        "on: workflow_dispatch\njobs:\n  verify:\n    runs-on: linux\n    steps: [{run: echo one}]\n  verify:\n    runs-on: linux\n    steps: [{run: echo two}]\n",
        "workflow_dispatch",
    );
    assert!(report.plan().is_none());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "github.compile.duplicate_mapping_key"
            && diagnostic.related().len() == 1
    }));
}

#[test]
fn compiler_defensively_rejects_complex_mapping_keys_that_decoding_skipped() {
    let source = "on: workflow_dispatch\nenv:\n  ? [lossy, key]\n  : value\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n";
    let report = compile(source, "workflow_dispatch");
    assert!(report.plan().is_none());
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.compile.yaml_complex_mapping_key")
        .expect("complex-key compiler diagnostic");
    assert_eq!(diagnostic.kind(), DiagnosticKind::Unsupported);
    assert_eq!(
        source.get(
            diagnostic.primary_span().start().byte_offset()
                ..diagnostic.primary_span().end().byte_offset()
        ),
        Some("[lossy, key]")
    );
}

#[test]
fn compiler_rejects_unknown_event_filter_fields_retained_by_decoding() {
    for (source, event_name) in [
        (
            "on:\n  push:\n    mystery: true\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
            "push",
        ),
        (
            "on:\n  merge_group:\n    mystery: true\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
            "merge_group",
        ),
        (
            "on:\n  repository_dispatch:\n    mystery: true\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
            "repository_dispatch",
        ),
    ] {
        let report = compile(source, event_name);
        assert!(report.plan().is_none(), "{:#?}", report.diagnostics());
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.kind() == DiagnosticKind::Unsupported
                && diagnostic.code() == "github.compile.unsupported_field"
        }));
    }
}

#[test]
fn compiler_rejects_invalid_event_filters() {
    let cases = [
        (
            "on:\n  push:\n    branches: [main]\n    branches-ignore: [legacy]\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: true}]\n",
            "github.compile.mutually_exclusive_filters",
        ),
        (
            "on:\n  push:\n    branches: ['!legacy/**']\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: true}]\n",
            "github.compile.negative_filter_without_positive",
        ),
        (
            "on:\n  push:\n    branches: ['release/[']\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: true}]\n",
            "github.compile.invalid_filter_pattern",
        ),
    ];
    for (source, code) in cases {
        let report = compile(source, "push");
        assert!(report.plan().is_none(), "{code} must suppress the plan");
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code),
            "missing {code}: {:#?}",
            report.diagnostics()
        );
    }
}

#[test]
fn compiler_distinguishes_unconfigured_events_from_lossy_yaml_rejection() {
    let unconfigured = compile(
        "on: workflow_dispatch\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
        "schedule",
    );
    assert!(unconfigured.plan().is_none());
    assert_eq!(
        unconfigured.disposition(),
        CompilationDisposition::NotSelected(WorkflowNotSelectedReason::EventNotConfigured)
    );
    assert!(unconfigured.diagnostics().is_empty());

    let invalid_unconfigured = compile(
        "on: workflow_dispatch\nunknown-workflow-field: true\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
        "schedule",
    );
    assert_eq!(
        invalid_unconfigured.disposition(),
        CompilationDisposition::Rejected,
        "invalid source must not be disguised as ordinary non-selection"
    );
    assert!(invalid_unconfigured.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Unsupported
            && diagnostic.code() == "github.compile.unsupported_field"
    }));

    let aliases = compile(include_str!("fixtures/aliases.yml"), "push");
    assert!(aliases.is_accepted(), "{:#?}", aliases.diagnostics());
    assert_eq!(aliases.disposition(), CompilationDisposition::Accepted);
    assert!(aliases.plan().is_some());
}
