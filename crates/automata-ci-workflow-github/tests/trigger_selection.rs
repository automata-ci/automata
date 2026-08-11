mod support;

use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_github::{
    CompilationDisposition, CompilationReport, CompileWorkflowRequest, GithubChangedFilesV1,
    GithubEventMetadataV1, GithubWorkflowCompiler, WorkflowNotSelectedReason,
};

const EXACT_REPOSITORY_CI: &str = include_str!("fixtures/repository-ci.yml");

fn event(name: &str, git_ref: &str) -> WorkflowEventProvenance {
    WorkflowEventProvenance::new("github", name)
        .with_delivery_id("delivery-trigger-selection")
        .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
        .with_git_ref(git_ref)
}

fn compile(
    source: &str,
    event: WorkflowEventProvenance,
    metadata: Option<GithubEventMetadataV1>,
) -> CompilationReport {
    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    let request = CompileWorkflowRequest::new(parsed.plan().expect("source plan"), event);
    let request = match metadata {
        Some(metadata) => request.with_event_metadata_v1(metadata),
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
        "ordinary non-selection must not emit diagnostics: {:#?}",
        report.diagnostics()
    );
}

#[test]
fn exact_repository_ci_selects_only_live_main_pushes() {
    let main = compile(
        EXACT_REPOSITORY_CI,
        event("push", "refs/heads/main"),
        Some(GithubEventMetadataV1::push(false)),
    );
    assert!(main.is_accepted(), "{:#?}", main.diagnostics());

    for (git_ref, metadata, reason) in [
        (
            "refs/heads/feature/not-main",
            GithubEventMetadataV1::push(false),
            WorkflowNotSelectedReason::EventFiltersNotMatched,
        ),
        (
            "refs/tags/main",
            GithubEventMetadataV1::push(false),
            WorkflowNotSelectedReason::EventFiltersNotMatched,
        ),
        (
            "refs/heads/main",
            GithubEventMetadataV1::push(true),
            WorkflowNotSelectedReason::DeletedPush,
        ),
    ] {
        assert_not_selected(
            &compile(EXACT_REPOSITORY_CI, event("push", git_ref), Some(metadata)),
            reason,
        );
    }
}

#[test]
fn event_absence_is_structured_non_selection_without_diagnostics() {
    let source = "on: workflow_dispatch\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    assert_not_selected(
        &compile(
            source,
            event("push", "refs/heads/main"),
            Some(GithubEventMetadataV1::push(false)),
        ),
        WorkflowNotSelectedReason::EventNotConfigured,
    );
}

#[test]
fn repository_dispatch_types_select_only_the_exact_custom_event() {
    let filtered = "on:\n  repository_dispatch:\n    types: [synthetic_signal, secondary_signal]\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let matching = compile(
        filtered,
        event("repository_dispatch", "refs/heads/main"),
        Some(GithubEventMetadataV1::repository_dispatch(
            "synthetic_signal",
        )),
    );
    assert!(matching.is_accepted(), "{:#?}", matching.diagnostics());

    assert_not_selected(
        &compile(
            filtered,
            event("repository_dispatch", "refs/heads/main"),
            Some(GithubEventMetadataV1::repository_dispatch(
                "unmatched_signal",
            )),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );

    let unfiltered = "on: repository_dispatch\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let any_custom = compile(
        unfiltered,
        event("repository_dispatch", "refs/heads/main"),
        Some(GithubEventMetadataV1::repository_dispatch("any_signal")),
    );
    assert!(any_custom.is_accepted(), "{:#?}", any_custom.diagnostics());
}

#[test]
fn repository_dispatch_requires_exact_bounded_metadata() {
    let source = "on: repository_dispatch\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    assert_rejected_with(
        &compile(
            source,
            event("repository_dispatch", "refs/heads/main"),
            None,
        ),
        "github.compile.event_metadata_required",
    );
    assert_rejected_with(
        &compile(
            source,
            event("repository_dispatch", "refs/heads/main"),
            Some(GithubEventMetadataV1::push(false)),
        ),
        "github.compile.event_metadata_mismatch",
    );
    for event_type in [String::new(), "x".repeat(101), "bad\nevent".to_owned()] {
        assert_rejected_with(
            &compile(
                source,
                event("repository_dispatch", "refs/heads/main"),
                Some(GithubEventMetadataV1::repository_dispatch(event_type)),
            ),
            "github.compile.invalid_repository_dispatch_metadata",
        );
    }
}

#[test]
fn exact_repository_ci_uses_github_default_pull_request_actions() {
    for action in ["opened", "synchronize", "reopened"] {
        let report = compile(
            EXACT_REPOSITORY_CI,
            event("pull_request", "refs/pull/42/merge"),
            Some(GithubEventMetadataV1::pull_request(action, "main")),
        );
        assert!(
            report.is_accepted(),
            "{action}: {:#?}",
            report.diagnostics()
        );
    }

    assert_not_selected(
        &compile(
            EXACT_REPOSITORY_CI,
            event("pull_request", "refs/pull/42/merge"),
            Some(GithubEventMetadataV1::pull_request("closed", "main")),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
}

#[test]
fn pull_request_branch_filters_use_target_base_never_event_or_head_ref() {
    let source = "on:\n  pull_request:\n    branches: [main]\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let matching_base = compile(
        source,
        event("pull_request", "refs/heads/feature/head"),
        Some(GithubEventMetadataV1::pull_request("opened", "main")),
    );
    assert!(
        matching_base.is_accepted(),
        "{:#?}",
        matching_base.diagnostics()
    );

    assert_not_selected(
        &compile(
            source,
            event("pull_request", "refs/heads/main"),
            Some(GithubEventMetadataV1::pull_request(
                "opened",
                "feature/head",
            )),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
}

#[test]
fn explicit_pull_request_types_replace_the_default_action_set() {
    let source = "on:\n  pull_request:\n    types: [closed]\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let closed = compile(
        source,
        event("pull_request", "refs/pull/42/merge"),
        Some(GithubEventMetadataV1::pull_request("closed", "main")),
    );
    assert!(closed.is_accepted(), "{:#?}", closed.diagnostics());

    assert_not_selected(
        &compile(
            source,
            event("pull_request", "refs/pull/42/merge"),
            Some(GithubEventMetadataV1::pull_request("opened", "main")),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
}

#[test]
fn ordered_negative_patterns_exclude_and_later_reinclude() {
    let source = "on:\n  push:\n    branches:\n      - releases/**\n      - '!releases/**-alpha'\n      - releases/beta/3-alpha\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let reincluded = compile(
        source,
        event("push", "refs/heads/releases/beta/3-alpha"),
        Some(GithubEventMetadataV1::push(false)),
    );
    assert!(reincluded.is_accepted(), "{:#?}", reincluded.diagnostics());

    assert_not_selected(
        &compile(
            source,
            event("push", "refs/heads/releases/10-alpha"),
            Some(GithubEventMetadataV1::push(false)),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
}

#[test]
fn push_branch_and_tag_filters_are_ref_kind_specific() {
    let source = "on:\n  push:\n    tags: ['v[12].[0-9]+.[0-9]+']\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let tag = compile(
        source,
        event("push", "refs/tags/v2.10.1"),
        Some(GithubEventMetadataV1::push(false)),
    );
    assert!(tag.is_accepted(), "{:#?}", tag.diagnostics());

    assert_not_selected(
        &compile(
            source,
            event("push", "refs/heads/v2.10.1"),
            Some(GithubEventMetadataV1::push(false)),
        ),
        WorkflowNotSelectedReason::EventFiltersNotMatched,
    );
}

#[test]
fn changed_file_filters_require_verified_metadata_and_honor_ordered_patterns() {
    let source = "on:\n  push:\n    paths:\n      - src/**\n      - '!src/generated/**'\n      - src/generated/keep.rs\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let missing = compile(
        source,
        event("push", "refs/heads/main"),
        Some(GithubEventMetadataV1::push(false)),
    );
    assert_eq!(
        missing.disposition(),
        CompilationDisposition::RequiresChangedFiles
    );
    assert!(missing.requires_changed_files());
    assert_eq!(missing.plan(), None);
    assert!(
        missing.diagnostics().is_empty(),
        "missing provider evidence is not invalid metadata: {:#?}",
        missing.diagnostics()
    );

    let matching = GithubEventMetadataV1::push_with_changed_files(
        false,
        GithubChangedFilesV1::complete(["src/generated/keep.rs"]),
    );
    let report = compile(source, event("push", "refs/heads/main"), Some(matching));
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());

    for path in ["src/generated/output.rs", "docs/readme.md"] {
        assert_not_selected(
            &compile(
                source,
                event("push", "refs/heads/main"),
                Some(GithubEventMetadataV1::push_with_changed_files(
                    false,
                    GithubChangedFilesV1::complete([path]),
                )),
            ),
            WorkflowNotSelectedReason::EventFiltersNotMatched,
        );
    }
}

#[test]
fn tag_pushes_never_require_changed_file_metadata() {
    let source = "on:\n  push:\n    tags: ['v*']\n    paths: ['src/**']\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let report = compile(
        source,
        event("push", "refs/tags/v1.2.3"),
        Some(GithubEventMetadataV1::push(false)),
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
}

#[test]
fn paths_ignore_requires_at_least_one_changed_file_outside_the_ignore_set() {
    let source = "on:\n  pull_request:\n    branches: [main]\n    paths-ignore: ['docs/**']\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    for files in [Vec::<&str>::new(), vec!["docs/readme.md"]] {
        assert_not_selected(
            &compile(
                source,
                event("pull_request", "refs/pull/42/merge"),
                Some(GithubEventMetadataV1::pull_request_with_changed_files(
                    "opened",
                    "main",
                    GithubChangedFilesV1::complete(files),
                )),
            ),
            WorkflowNotSelectedReason::EventFiltersNotMatched,
        );
    }

    let report = compile(
        source,
        event("pull_request", "refs/pull/42/merge"),
        Some(GithubEventMetadataV1::pull_request_with_changed_files(
            "opened",
            "main",
            GithubChangedFilesV1::complete(["docs/readme.md", "src/lib.rs"]),
        )),
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
}

#[test]
fn provider_diff_bypass_matches_paths_without_exposing_file_names() {
    let source = "on:\n  push:\n    paths: ['src/**']\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let report = compile(
        source,
        event("push", "refs/heads/main"),
        Some(GithubEventMetadataV1::push_with_changed_files(
            false,
            GithubChangedFilesV1::bypass_path_filters(),
        )),
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
}

#[test]
fn invalid_changed_file_metadata_is_bounded_and_sanitized() {
    let sentinel = "private-path-sentinel";
    let source = "on:\n  push:\n    paths: ['**']\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let report = compile(
        source,
        event("push", "refs/heads/main"),
        Some(GithubEventMetadataV1::push_with_changed_files(
            false,
            GithubChangedFilesV1::complete([format!("{sentinel}\n")]),
        )),
    );
    assert_rejected_with(&report, "github.compile.invalid_changed_files_metadata");
    assert!(!format!("{:?}", report.diagnostics()).contains(sentinel));
}

#[test]
fn changed_file_metadata_accepts_exactly_the_provider_filter_window() {
    let source = "on:\n  push:\n    paths: ['src/**']\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - run: true\n";
    let files = (0..3_000).map(|index| format!("src/file-{index}.rs"));
    let report = compile(
        source,
        event("push", "refs/heads/main"),
        Some(GithubEventMetadataV1::push_with_changed_files(
            false,
            GithubChangedFilesV1::complete(files),
        )),
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());

    let files = (0..3_001).map(|index| format!("src/file-{index}.rs"));
    let report = compile(
        source,
        event("push", "refs/heads/main"),
        Some(GithubEventMetadataV1::push_with_changed_files(
            false,
            GithubChangedFilesV1::complete(files),
        )),
    );
    assert_rejected_with(&report, "github.compile.invalid_changed_files_metadata");
}

#[test]
fn push_and_pull_request_fail_closed_without_versioned_metadata() {
    for (name, git_ref) in [
        ("push", "refs/heads/main"),
        ("pull_request", "refs/pull/42/merge"),
    ] {
        assert_rejected_with(
            &compile(EXACT_REPOSITORY_CI, event(name, git_ref), None),
            "github.compile.event_metadata_required",
        );
    }

    let dispatch = compile(
        EXACT_REPOSITORY_CI,
        event("workflow_dispatch", "refs/heads/main"),
        None,
    );
    assert!(dispatch.is_accepted(), "{:#?}", dispatch.diagnostics());
}

#[test]
fn preselected_recompilation_validates_the_exact_trigger_span() {
    let parsed = support::parse(EXACT_REPOSITORY_CI);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let initial = GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::new(
            parsed.plan().expect("source plan"),
            event("push", "refs/heads/main"),
        )
        .with_event_metadata_v1(GithubEventMetadataV1::push(false)),
    );
    let plan = initial.plan().expect("initial plan");
    let replay =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_preselected_event(
            parsed.plan().expect("source plan"),
            plan.event().clone(),
        ));
    assert!(replay.is_accepted(), "{:#?}", replay.diagnostics());
    assert_eq!(replay.plan(), Some(plan));

    let shifted_source = format!("\n{EXACT_REPOSITORY_CI}");
    let shifted = support::parse(&shifted_source);
    assert!(shifted.is_accepted(), "{:#?}", shifted.diagnostics());
    assert_rejected_with(
        &GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_preselected_event(
            shifted.plan().expect("shifted plan"),
            plan.event().clone(),
        )),
        "github.compile.preselected_trigger_mismatch",
    );
}
