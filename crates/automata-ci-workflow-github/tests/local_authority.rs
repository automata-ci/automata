use std::sync::Arc;

use automata_ci_core::{PlanSourceOrigin, Sha256Digest, WorkflowEventProvenance};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend,
    LocalWorkflowDispatchEvidence, LocalWorkflowDispatchInputs, LocalWorkflowDispatchInputsError,
    LocalWorkflowSourceEvidence, MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS,
    MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS, ParseWorkflowRequest, SourceId, SourceOrigin,
    SourceProvenance, WorkflowFrontend as _,
};

const REPOSITORY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PATH: &str = ".github/workflows/check.yml";
const WORKFLOW: &str = r"on:
  workflow_dispatch:
    inputs:
      enabled:
        type: boolean
        required: true
jobs:
  check:
    runs-on: linux
    steps:
      - run: true
";

fn parse(revision: &str, source: &str) -> automata_ci_workflow_github::GithubFrontendReport {
    GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
        SourceProvenance::new(
            SourceId::new(PATH),
            SourceOrigin::Repository {
                repository: Arc::from(REPOSITORY),
                revision: Arc::from(revision),
                path: Arc::from(PATH),
            },
        ),
        source,
    ))
}

#[test]
fn local_dispatch_is_closed_snapshot_authority_and_values_are_redacted() {
    let digest = Sha256Digest::from_bytes([7; 32]);
    let revision = digest.to_string();
    let parsed = parse(&revision, WORKFLOW);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let inputs = LocalWorkflowDispatchInputs::try_new([("enabled", "true")]).unwrap();
    assert!(!format!("{inputs:?}").contains("true"));
    let report =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_local_workflow_dispatch(
            parsed.plan().unwrap(),
            LocalWorkflowDispatchEvidence::new(LocalWorkflowSourceEvidence::new(digest), inputs),
        ));
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let plan = report.plan().unwrap();
    assert_eq!(plan.source().provider(), "local");
    assert_eq!(plan.event().provider(), "local");
    assert_eq!(plan.event().name(), "workflow_dispatch");
    let PlanSourceOrigin::Repository {
        revision: actual, ..
    } = plan.source().origin()
    else {
        panic!("repository provenance");
    };
    assert_eq!(actual, &revision);
    assert!(plan.event().delivery_id().is_none());
    assert!(plan.event().commit_sha().is_none());

    let mismatched = parse(&Sha256Digest::from_bytes([8; 32]).to_string(), WORKFLOW);
    let rejected =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_local_workflow_dispatch(
            mismatched.plan().unwrap(),
            LocalWorkflowDispatchEvidence::new(
                LocalWorkflowSourceEvidence::new(digest),
                LocalWorkflowDispatchInputs::try_new([("enabled", "true")]).unwrap(),
            ),
        ));
    assert!(!rejected.is_accepted());
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.compile.local_snapshot_mismatch")
    );
}

#[test]
fn github_constructor_cannot_accept_local_event_provenance() {
    let digest = Sha256Digest::from_bytes([9; 32]);
    let parsed = parse(&digest.to_string(), WORKFLOW);
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().unwrap(),
        WorkflowEventProvenance::new("local", "workflow_dispatch"),
    ));
    assert!(!report.is_accepted());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.compile.event_provider")
    );
}

#[test]
fn local_reusable_compilation_retains_local_source_and_event_authority() {
    let digest = Sha256Digest::from_bytes([10; 32]);
    let source = r"on:
  workflow_call: {}
jobs:
  check:
    runs-on: linux
    steps:
      - run: true
";
    let parsed = parse(&digest.to_string(), source);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let report =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_local_workflow_call(
            parsed.plan().unwrap(),
            LocalWorkflowSourceEvidence::new(digest),
        ));
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let plan = report.plan().unwrap();
    assert_eq!(plan.source().provider(), "local");
    assert_eq!(plan.event().provider(), "local");
    assert_eq!(plan.event().name(), "workflow_call");
    assert!(plan.event().delivery_id().is_none());
    assert!(plan.event().commit_sha().is_none());
}

#[test]
fn local_dispatch_inputs_are_bounded_and_never_debug_values() {
    let too_many = (0..=MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS)
        .map(|index| (format!("input_{index}"), String::new()));
    assert_eq!(
        LocalWorkflowDispatchInputs::try_new(too_many),
        Err(LocalWorkflowDispatchInputsError::TooManyInputs)
    );
    assert_eq!(
        LocalWorkflowDispatchInputs::try_new([(
            "input",
            "x".repeat(MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS),
        )]),
        Err(LocalWorkflowDispatchInputsError::PayloadTooLarge)
    );
    assert_eq!(
        LocalWorkflowDispatchInputs::try_new([("input", "line\nbreak")]),
        Err(LocalWorkflowDispatchInputsError::InvalidInputValue)
    );
    let redacted = LocalWorkflowDispatchInputs::try_new([("input", "secret-marker")]).unwrap();
    assert!(!format!("{redacted:?}").contains("secret-marker"));
}
