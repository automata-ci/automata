use crate::support;

use automata_ci_core::{ContextValue, WorkflowEventProvenance};
use automata_ci_workflow_github::{
    CompilationReport, CompileWorkflowRequest, GithubEventMetadata, GithubWorkflowCompiler,
    GithubWorkflowDispatchInputDefault, GithubWorkflowDispatchInputType,
    GithubWorkflowDispatchInputValue, GithubWorkflowDispatchInputs,
    GithubWorkflowDispatchInputsError, MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS,
    MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS,
};

const JOB: &str = "jobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: true\n";

fn compile(source: &str, inputs: Option<GithubWorkflowDispatchInputs>) -> CompilationReport {
    let parsed = support::parse_accepted(source);
    support::compile(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("synthetic-dispatch")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_git_ref("refs/heads/main"),
        inputs.map(GithubEventMetadata::workflow_dispatch),
    )
}

fn payload(
    values: impl IntoIterator<Item = (&'static str, GithubWorkflowDispatchInputValue)>,
) -> GithubWorkflowDispatchInputs {
    GithubWorkflowDispatchInputs::try_new(values).expect("bounded synthetic payload")
}

fn assert_rejected_with(report: &CompilationReport, code: &str) {
    support::assert_rejected_with(report, code);
    assert!(report.workflow_dispatch_contract().is_none());
    assert!(report.workflow_dispatch_inputs().is_none());
}

#[test]
fn typed_contract_resolves_exact_payload_types_and_defaults() {
    let source = format!(
        "on:\n  workflow_dispatch:\n    inputs:\n      target:\n        description: Deployment target\n        required: true\n        type: choice\n        options: [test, live]\n      dry_run:\n        type: boolean\n        default: false\n      note:\n        type: string\n        default: ready\n      channel:\n        type: choice\n        options: [stable, edge]\n      suffix:\n        type: string\n{JOB}"
    );
    let report = compile(
        &source,
        Some(payload([
            (
                "target",
                GithubWorkflowDispatchInputValue::String("live".to_owned()),
            ),
            (
                "dry_run",
                GithubWorkflowDispatchInputValue::String("true".to_owned()),
            ),
        ])),
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());

    let contract = report
        .workflow_dispatch_contract()
        .expect("typed dispatch contract");
    assert_eq!(contract.inputs().len(), 5);
    let target = contract
        .inputs()
        .iter()
        .find_map(|(key, value)| (key.as_str() == "target").then_some(value))
        .expect("target definition");
    assert_eq!(target.input_type(), GithubWorkflowDispatchInputType::Choice);
    assert!(target.required());
    assert_eq!(target.description(), Some("Deployment target"));
    assert_eq!(target.options(), ["test", "live"]);
    let dry_run = contract
        .inputs()
        .iter()
        .find_map(|(key, value)| (key.as_str() == "dry_run").then_some(value))
        .expect("dry-run definition");
    assert_eq!(
        dry_run.default(),
        Some(&GithubWorkflowDispatchInputDefault::Boolean(false))
    );

    let inputs = report
        .workflow_dispatch_inputs()
        .and_then(ContextValue::as_object)
        .expect("canonical inputs object");
    assert_eq!(
        inputs.get("target").and_then(ContextValue::as_string),
        Some("live")
    );
    assert_eq!(
        inputs.get("dry_run").and_then(ContextValue::as_boolean),
        Some(true)
    );
    assert_eq!(
        inputs.get("note").and_then(ContextValue::as_string),
        Some("ready")
    );
    assert_eq!(
        inputs.get("channel").and_then(ContextValue::as_string),
        Some("")
    );
    assert_eq!(
        inputs.get("suffix").and_then(ContextValue::as_string),
        Some("")
    );
}

#[test]
fn configured_inputs_fail_closed_without_exact_verified_evidence() {
    let source = format!(
        "on:\n  workflow_dispatch:\n    inputs:\n      target:\n        required: true\n        type: choice\n        options: [test, live]\n      enabled:\n        type: boolean\n{JOB}"
    );

    assert_rejected_with(
        &compile(&source, None),
        "github.compile.event_metadata_required",
    );
    assert_rejected_with(
        &compile(&source, Some(payload([]))),
        "github.compile.required_workflow_dispatch_input_missing",
    );
    assert_rejected_with(
        &compile(
            &source,
            Some(payload([(
                "target",
                GithubWorkflowDispatchInputValue::String("other".to_owned()),
            )])),
        ),
        "github.compile.invalid_workflow_dispatch_choice_input",
    );
    assert_rejected_with(
        &compile(
            &source,
            Some(payload([
                (
                    "target",
                    GithubWorkflowDispatchInputValue::String("test".to_owned()),
                ),
                (
                    "extra",
                    GithubWorkflowDispatchInputValue::String("value".to_owned()),
                ),
            ])),
        ),
        "github.compile.unknown_workflow_dispatch_input",
    );
    assert_rejected_with(
        &compile(
            &source,
            Some(payload([
                (
                    "target",
                    GithubWorkflowDispatchInputValue::String("test".to_owned()),
                ),
                (
                    "enabled",
                    GithubWorkflowDispatchInputValue::String("TRUE".to_owned()),
                ),
            ])),
        ),
        "github.compile.invalid_workflow_dispatch_boolean_input",
    );
}

#[test]
fn malformed_or_unsupported_source_contracts_are_rejected() {
    for (definition, code) in [
        (
            "type: choice",
            "github.compile.workflow_dispatch_choice_options_required",
        ),
        (
            "type: choice\n        options: [one, two]\n        default: three",
            "github.compile.workflow_dispatch_choice_default_not_allowed",
        ),
        (
            "type: boolean\n        default: 'false'",
            "github.compile.invalid_workflow_dispatch_boolean",
        ),
        (
            "type: string\n        options: [one]",
            "github.compile.workflow_dispatch_options_require_choice",
        ),
        (
            "description: missing type",
            "github.compile.workflow_dispatch_input_type_required",
        ),
        (
            "type: number",
            "github.compile.unsupported_workflow_dispatch_input_type",
        ),
    ] {
        let source = format!(
            "on:\n  workflow_dispatch:\n    inputs:\n      value:\n        {definition}\n{JOB}"
        );
        assert_rejected_with(&compile(&source, Some(payload([]))), code);
    }
}

#[test]
fn verified_payload_wrapper_enforces_canonical_resource_bounds() {
    let redacted = GithubWorkflowDispatchInputs::try_new([("token", "private-value")])
        .expect("bounded payload");
    let debug = format!("{redacted:?}");
    assert!(!debug.contains("private-value"));
    assert!(debug.contains("input_count"));

    assert_eq!(
        GithubWorkflowDispatchInputs::try_new([("duplicate", "first"), ("duplicate", "second")]),
        Err(GithubWorkflowDispatchInputsError::DuplicateInputKey)
    );
    assert_eq!(
        GithubWorkflowDispatchInputs::try_new([(" invalid ", "value")]),
        Err(GithubWorkflowDispatchInputsError::InvalidInputKey)
    );
}

#[test]
fn workflow_dispatch_definition_count_boundaries() {
    let source = |count| {
        let definitions = (0..count)
            .map(|index| format!("      input_{index}:\n        type: string"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("on:\n  workflow_dispatch:\n    inputs:\n{definitions}\n{JOB}")
    };

    for count in [
        MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS - 1,
        MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS,
    ] {
        let report = compile(&source(count), Some(payload([])));
        assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    }
    assert_rejected_with(
        &compile(
            &source(MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS + 1),
            Some(payload([])),
        ),
        "github.compile.too_many_workflow_dispatch_inputs",
    );
}

#[test]
fn workflow_dispatch_input_count_boundaries() {
    let inputs = |count| {
        (0..count)
            .map(|index| (format!("input_{index}"), "value"))
            .collect::<Vec<_>>()
    };

    assert!(
        GithubWorkflowDispatchInputs::try_new(inputs(MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS - 1))
            .is_ok()
    );
    assert!(
        GithubWorkflowDispatchInputs::try_new(inputs(MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS)).is_ok()
    );
    assert_eq!(
        GithubWorkflowDispatchInputs::try_new(inputs(MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS + 1)),
        Err(GithubWorkflowDispatchInputsError::TooManyInputs)
    );
}

#[test]
fn workflow_dispatch_character_boundaries() {
    let input = |total_characters| [("v", "x".repeat(total_characters - 1))];

    assert!(
        GithubWorkflowDispatchInputs::try_new(input(
            MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS - 1
        ))
        .is_ok()
    );
    assert!(
        GithubWorkflowDispatchInputs::try_new(input(MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS))
            .is_ok()
    );
    assert_eq!(
        GithubWorkflowDispatchInputs::try_new(input(
            MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS + 1
        )),
        Err(GithubWorkflowDispatchInputsError::PayloadTooLarge)
    );
}

#[test]
fn configured_dispatch_replay_remains_closed_without_persisted_input_evidence() {
    let source = format!(
        "on:\n  workflow_dispatch:\n    inputs:\n      value:\n        type: string\n{JOB}"
    );
    let initial = compile(
        &source,
        Some(payload([(
            "value",
            GithubWorkflowDispatchInputValue::String("verified".to_owned()),
        )])),
    );
    assert!(initial.is_accepted(), "{:#?}", initial.diagnostics());

    let parsed = support::parse(&source);
    let replay =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_preselected_event(
            parsed.plan().expect("source plan"),
            initial.plan().expect("initial plan").event().clone(),
        ));
    assert_rejected_with(
        &replay,
        "github.compile.workflow_dispatch_input_evidence_required",
    );
}

#[test]
fn configured_dispatch_replay_accepts_exact_durable_input_evidence() {
    let source = format!(
        "on:\n  workflow_dispatch:\n    inputs:\n      target:\n        type: choice\n        required: true\n        options: [test, live]\n      dry_run:\n        type: boolean\n{JOB}"
    );
    let durable_inputs = payload([
        (
            "target",
            GithubWorkflowDispatchInputValue::String("live".to_owned()),
        ),
        ("dry_run", GithubWorkflowDispatchInputValue::Boolean(true)),
    ]);
    let initial = compile(&source, Some(durable_inputs.clone()));
    assert!(initial.is_accepted(), "{:#?}", initial.diagnostics());

    let parsed = support::parse(&source);
    let replay = GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::for_preselected_event_with_metadata(
            parsed.plan().expect("source plan"),
            initial.plan().expect("initial plan").event().clone(),
            GithubEventMetadata::workflow_dispatch(durable_inputs),
        ),
    );
    assert!(replay.is_accepted(), "{:#?}", replay.diagnostics());
    assert_eq!(replay.plan(), initial.plan());
    assert_eq!(
        replay.workflow_dispatch_inputs(),
        initial.workflow_dispatch_inputs()
    );
}
