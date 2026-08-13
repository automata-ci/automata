mod support;

use automata_ci_core::{LogicalJobKind, ReusableSecretForwarding, WorkflowEventProvenance};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, DiagnosticKind, GithubEventMetadata, GithubWorkflowCompiler,
    ReusableWorkflowSecrets, ScalarResolution,
};

#[test]
fn source_model_decodes_local_and_remote_reusable_workflow_calls() {
    let source = r"on: push
jobs:
  prepare:
    runs-on: linux
    steps:
      - run: echo prepare
  local_call:
    name: Local reusable workflow
    needs: prepare
    if: ${{ github.ref == 'refs/heads/main' }}
    permissions:
      contents: read
    concurrency: reusable-${{ github.ref }}
    strategy:
      matrix:
        target: [debug, release]
    uses: ./.github/workflows/reusable.yml
    with:
      artifact-name: package-${{ github.sha }}
      retry-count: 2
    secrets:
      access-token: ${{ secrets.ACCESS_TOKEN }}
  remote_call:
    uses: example/automation/.github/workflows/release.yml@0123456789012345678901234567890123456789
    secrets: inherit
";

    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "source diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("source plan");

    let local_job = plan.workflow().jobs()[1].job();
    assert!(local_job.runner().is_none());
    assert!(local_job.steps().is_empty());
    assert!(local_job.strategy().is_some());
    let local_call = local_job
        .reusable_workflow_call()
        .expect("local reusable-workflow call");
    assert_eq!(
        local_call.reference().expect("call reference").value(),
        "./.github/workflows/reusable.yml"
    );
    assert_eq!(
        plan.source()
            .slice(local_call.reference().expect("call reference").span())
            .expect("reference source"),
        "./.github/workflows/reusable.yml"
    );

    let inputs = local_call.inputs().expect("caller inputs");
    assert_eq!(inputs.values().entries().len(), 2);
    assert_eq!(inputs.values().entries()[0].key().value(), "artifact-name");
    assert_eq!(
        inputs.values().entries()[0].value().decoded(),
        "package-${{ github.sha }}"
    );
    assert_eq!(
        inputs.values().entries()[1].value().resolution(),
        ScalarResolution::Integer
    );
    assert!(
        plan.source()
            .slice(inputs.span())
            .expect("inputs source")
            .contains("artifact-name:")
    );

    let ReusableWorkflowSecrets::Mapping(secret_map) =
        local_call.secrets().expect("explicit secret bindings")
    else {
        panic!("local call must retain a secret mapping");
    };
    assert_eq!(secret_map.values().entries().len(), 1);
    assert_eq!(
        secret_map.values().entries()[0].value().decoded(),
        "${{ secrets.ACCESS_TOKEN }}"
    );
    assert!(
        plan.source()
            .slice(secret_map.span())
            .expect("secret map source")
            .contains("access-token:")
    );

    let remote_call = plan.workflow().jobs()[2]
        .job()
        .reusable_workflow_call()
        .expect("remote reusable-workflow call");
    assert_eq!(
        remote_call.reference().expect("remote reference").value(),
        "example/automation/.github/workflows/release.yml@0123456789012345678901234567890123456789"
    );
    let ReusableWorkflowSecrets::Inherit(span) = remote_call.secrets().expect("inherited secrets")
    else {
        panic!("remote call must retain `secrets: inherit`");
    };
    assert_eq!(
        plan.source().slice(span).expect("inherit source"),
        "inherit"
    );
}

#[test]
fn reusable_workflow_call_rejects_every_step_job_only_field() {
    let source = r"on: push
jobs:
  mixed:
    uses: ./.github/workflows/reusable.yml
    strategy:
      fail-fast: false
      matrix:
        target: [debug]
    env:
      MODE: release
    outputs:
      digest: value
    environment: staging
    defaults:
      run:
        shell: bash
    runs-on: linux
    timeout-minutes: 15
    continue-on-error: false
    steps:
      - run: echo invalid
";

    let report = support::parse(source);
    assert!(!report.is_accepted());
    let diagnostics = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.step_job_field_on_reusable_workflow_call")
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 8, "diagnostics: {diagnostics:#?}");
    let mut fields = diagnostics
        .iter()
        .map(|diagnostic| {
            assert_eq!(diagnostic.kind(), DiagnosticKind::Semantic);
            report
                .source()
                .slice(diagnostic.primary_span())
                .expect("field source")
                .to_owned()
        })
        .collect::<Vec<_>>();
    fields.sort();
    assert_eq!(
        fields,
        [
            "continue-on-error",
            "defaults",
            "env",
            "environment",
            "outputs",
            "runs-on",
            "steps",
            "timeout-minutes",
        ]
    );
    assert!(
        !report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message().contains("strategy"))
    );

    let mixed = report
        .plan()
        .expect("loss-aware source plan")
        .workflow()
        .jobs()[0]
        .job();
    assert!(mixed.reusable_workflow_call().is_some());
    assert!(mixed.runner().is_some());
    assert_eq!(mixed.steps().len(), 1);
    assert!(mixed.outputs().is_some());
    assert!(mixed.deployment_environment().is_some());
}

#[test]
fn caller_options_without_uses_have_field_specific_diagnostics_and_are_retained() {
    let source = r"on: push
jobs:
  build:
    runs-on: linux
    with:
      mode: release
    secrets: inherit
    steps:
      - run: echo build
";

    let report = support::parse(source);
    assert!(!report.is_accepted());
    for (code, field) in [
        ("github.reusable_workflow_with_requires_uses", "with"),
        ("github.reusable_workflow_secrets_requires_uses", "secrets"),
    ] {
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code() == code)
            .unwrap_or_else(|| panic!("missing {code}"));
        assert_eq!(diagnostic.kind(), DiagnosticKind::Semantic);
        assert_eq!(
            report
                .source()
                .slice(diagnostic.primary_span())
                .expect("diagnostic source"),
            field
        );
    }
    assert!(!report.diagnostics().iter().any(|diagnostic| matches!(
        diagnostic.code(),
        "github.runner_required" | "github.steps_required"
    )));

    let call = report
        .plan()
        .expect("loss-aware source plan")
        .workflow()
        .jobs()[0]
        .job()
        .reusable_workflow_call()
        .expect("recognized caller-only fields");
    assert!(call.reference().is_none());
    assert_eq!(call.inputs().expect("retained inputs").values().len(), 1);
    assert!(matches!(
        call.secrets(),
        Some(ReusableWorkflowSecrets::Inherit(_))
    ));
}

#[test]
fn missing_reference_and_invalid_secrets_are_precise_semantic_errors() {
    let source = r"on: push
jobs:
  missing_reference:
    uses: null
    with: {}
  invalid_secrets:
    uses: ./.github/workflows/reusable.yml
    secrets: everything
";

    let report = support::parse(source);
    assert!(!report.is_accepted());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Semantic
            && diagnostic.code() == "github.reusable_workflow_reference_required"
            && diagnostic.message().contains("jobs.missing_reference.uses")
    }));
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Semantic
            && diagnostic.code() == "github.invalid_reusable_workflow_secrets"
            && diagnostic
                .message()
                .contains("jobs.invalid_secrets.secrets")
    }));
    assert!(!report.diagnostics().iter().any(|diagnostic| matches!(
        diagnostic.code(),
        "github.runner_required" | "github.steps_required"
    )));

    let missing_reference = report
        .plan()
        .expect("loss-aware source plan")
        .workflow()
        .jobs()[0]
        .job()
        .reusable_workflow_call()
        .expect("retained malformed call");
    assert!(missing_reference.reference().is_none());
    assert!(missing_reference.inputs().is_some());
}

#[test]
fn unknown_call_job_fields_remain_extensions() {
    let source = r"on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    future-call-policy: guarded
";

    let report = support::parse(source);
    assert!(!report.is_accepted());
    let job = report
        .plan()
        .expect("loss-aware source plan")
        .workflow()
        .jobs()[0]
        .job();
    assert!(job.reusable_workflow_call().is_some());
    assert_eq!(job.extensions().len(), 1);
    assert_eq!(job.extensions()[0].path(), "jobs.call.future-call-policy");
}

#[test]
fn current_lowering_retains_durable_reusable_workflow_invocation() {
    let source = r"on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      channel: stable
    secrets: inherit
";

    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    let report = GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::new(
            parsed.plan().expect("source plan"),
            WorkflowEventProvenance::new("github", "push").with_git_ref("refs/heads/main"),
        )
        .with_event_metadata(GithubEventMetadata::push(false)),
    );

    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let job = &report.plan().expect("current plan").jobs()[0];
    let LogicalJobKind::ReusableWorkflow(invocation) = job.execution() else {
        panic!("reusable workflow invocation");
    };
    assert_eq!(
        invocation.reference().value(),
        "./.github/workflows/reusable.yml"
    );
    assert_eq!(invocation.inputs().len(), 1);
    assert!(matches!(
        invocation.secrets(),
        ReusableSecretForwarding::Inherit(_)
    ));
}
