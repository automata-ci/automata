mod support;

use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_github::{
    CompilationDisposition, CompilationReport, CompileWorkflowRequest, GithubEventMetadata,
    GithubWorkflowCompiler, WorkflowNotSelectedReason,
};

fn compile(
    source: &str,
    event_name: &str,
    metadata: Option<GithubEventMetadata>,
) -> CompilationReport {
    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    let request = CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", event_name)
            .with_delivery_id("synthetic-event-configuration")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_git_ref("refs/heads/main"),
    );
    let request = match metadata {
        Some(metadata) => request.with_event_metadata(metadata),
        None => request,
    };
    GithubWorkflowCompiler::new().compile(request)
}

fn assert_rejected_with(report: &CompilationReport, code: &str) {
    assert!(
        report.plan().is_none(),
        "unexpected plan: {:#?}",
        report.plan()
    );
    assert!(
        report.disposition() == CompilationDisposition::Rejected,
        "unexpected disposition: {:?}",
        report.disposition()
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == code),
        "missing diagnostic `{code}`: {:#?}",
        report.diagnostics()
    );
}

fn assert_not_selected(report: &CompilationReport, reason: WorkflowNotSelectedReason) {
    assert_eq!(report.plan(), None);
    assert_eq!(
        report.disposition(),
        CompilationDisposition::NotSelected(reason)
    );
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
}

#[test]
fn empty_dispatch_and_reusable_workflow_contracts_are_admitted() {
    for (source, event_name) in [
        (
            "on:\n  workflow_dispatch: {}\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "workflow_dispatch",
        ),
        (
            "on:\n  workflow_dispatch:\n    inputs: {}\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "workflow_dispatch",
        ),
        (
            "on:\n  workflow_call: {}\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "workflow_call",
        ),
        (
            "on:\n  workflow_call:\n    inputs: {}\n    secrets: {}\n    outputs: {}\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "workflow_call",
        ),
    ] {
        let report = compile(source, event_name, None);
        assert!(report.is_accepted(), "{:#?}", report.diagnostics());
        assert_eq!(
            report
                .plan()
                .expect("compiled plan")
                .event()
                .configured_trigger_span()
                .expect("selected trigger")
                .source_id(),
            "test.yml"
        );
    }
}

#[test]
fn configured_dispatch_inputs_require_verified_payload_evidence() {
    let source = "on:\n  workflow_dispatch:\n    inputs:\n      target:\n        type: string\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    assert_rejected_with(
        &compile(source, "workflow_dispatch", None),
        "github.compile.event_metadata_required",
    );
}

#[test]
fn schedule_admission_requires_the_exact_firing_cron() {
    let source = "on:\n  schedule:\n    - cron: '15 4 * * 1-5'\n    - cron: '45 16 * * 2,4'\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";

    let matching = compile(
        source,
        "schedule",
        Some(GithubEventMetadata::schedule("45 16 * * 2,4")),
    );
    assert!(matching.is_accepted(), "{:#?}", matching.diagnostics());
    let parsed = support::parse(source);
    let replay =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_preselected_event(
            parsed.plan().expect("replay source plan"),
            matching.plan().expect("initial plan").event().clone(),
        ));
    assert!(replay.is_accepted(), "{:#?}", replay.diagnostics());

    assert_not_selected(
        &compile(
            source,
            "schedule",
            Some(GithubEventMetadata::schedule("0 0 * * *")),
        ),
        WorkflowNotSelectedReason::ScheduleNotConfigured,
    );
    assert_rejected_with(
        &compile(source, "schedule", None),
        "github.compile.event_metadata_required",
    );
    assert_rejected_with(
        &compile(source, "schedule", Some(GithubEventMetadata::push(false))),
        "github.compile.event_metadata_mismatch",
    );
}

#[test]
fn merge_group_requires_exact_authenticated_metadata() {
    let source =
        "on: merge_group\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let selected = compile(
        source,
        "merge_group",
        Some(GithubEventMetadata::merge_group(
            "checks_requested",
            "refs/heads/main",
        )),
    );
    assert!(selected.is_accepted(), "{:#?}", selected.diagnostics());

    let configured = "on:\n  merge_group:\n    types: [checks_requested]\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let configured_selected = compile(
        configured,
        "merge_group",
        Some(GithubEventMetadata::merge_group(
            "checks_requested",
            "refs/heads/main",
        )),
    );
    assert!(
        configured_selected.is_accepted(),
        "{:#?}",
        configured_selected.diagnostics()
    );

    assert_not_selected(
        &compile(
            source,
            "merge_group",
            Some(GithubEventMetadata::merge_group(
                "destroyed",
                "refs/heads/main",
            )),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
    assert_not_selected(
        &compile(
            configured,
            "merge_group",
            Some(GithubEventMetadata::merge_group(
                "destroyed",
                "refs/heads/main",
            )),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
    let unsupported_type = "on:\n  merge_group:\n    types: [destroyed]\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    assert_rejected_with(
        &compile(
            unsupported_type,
            "merge_group",
            Some(GithubEventMetadata::merge_group(
                "checks_requested",
                "refs/heads/main",
            )),
        ),
        "github.compile.unsupported_merge_group_type",
    );
    assert_rejected_with(
        &compile(source, "merge_group", None),
        "github.compile.event_metadata_required",
    );
    assert_rejected_with(
        &compile(
            source,
            "merge_group",
            Some(GithubEventMetadata::pull_request("opened", "main")),
        ),
        "github.compile.event_metadata_mismatch",
    );
    assert_rejected_with(
        &compile(
            source,
            "merge_group",
            Some(GithubEventMetadata::merge_group("checks_requested", "main")),
        ),
        "github.compile.invalid_merge_group_metadata",
    );
}

#[test]
fn malformed_or_not_yet_evaluable_event_configuration_is_diagnostic() {
    for (source, event_name, metadata, code) in [
        (
            "on: schedule\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "schedule",
            Some(GithubEventMetadata::schedule("0 0 * * *")),
            "github.compile.schedule_configuration_required",
        ),
        (
            "on:\n  schedule: []\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "schedule",
            Some(GithubEventMetadata::schedule("0 0 * * *")),
            "github.compile.empty_schedule",
        ),
        (
            "on:\n  schedule:\n    - cron: '0 0 * * *'\n      timezone: Invalid/Nowhere\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "schedule",
            Some(GithubEventMetadata::schedule("0 0 * * *")),
            "github.compile.invalid_schedule_timezone",
        ),
        (
            "on:\n  schedule:\n    - cron: '0 12 * *'\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "schedule",
            Some(GithubEventMetadata::schedule("0 12 * *")),
            "github.compile.invalid_schedule_cron",
        ),
        (
            "on:\n  workflow_dispatch:\n    inputs: []\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "workflow_dispatch",
            None,
            "github.compile.invalid_event_contract",
        ),
        (
            "on:\n  workflow_call: invalid\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n",
            "workflow_call",
            None,
            "github.compile.invalid_workflow_call_configuration",
        ),
    ] {
        assert_rejected_with(&compile(source, event_name, metadata), code);
    }
}
