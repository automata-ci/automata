mod support;

use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_github::{
    CompileWorkflowRequest, DiagnosticKind, GithubWorkflowCompiler, JobEnvironment,
    ScalarResolution,
};

#[test]
fn source_model_decodes_job_outputs_and_both_environment_forms() {
    let source = r#"on: push
jobs:
  package:
    runs-on: linux
    outputs:
      digest: ${{ steps.archive.outputs.digest }}
      publishable: true
    environment:
      name: preview-${{ github.run_id }}
      url: "https://deployments.example.invalid/${{ github.run_id }}"
    steps:
      - id: archive
        run: echo package
  publish:
    needs: package
    runs-on: linux
    environment: production
    steps:
      - run: echo publish
"#;

    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "source diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("source plan");

    let package = plan.workflow().jobs()[0].job();
    let outputs = package.outputs().expect("job outputs");
    assert_eq!(outputs.values().entries().len(), 2);
    assert_eq!(outputs.values().entries()[0].key().value(), "digest");
    assert_eq!(
        outputs.values().entries()[0].value().decoded(),
        "${{ steps.archive.outputs.digest }}"
    );
    assert!(
        outputs.values().entries()[0]
            .value()
            .contains_expression_candidate()
    );
    assert_eq!(
        outputs.values().entries()[1].value().resolution(),
        ScalarResolution::Boolean
    );
    assert!(
        plan.source()
            .slice(outputs.span())
            .expect("outputs source")
            .contains("digest:")
    );

    let JobEnvironment::Detailed(environment) = package
        .deployment_environment()
        .expect("detailed environment")
    else {
        panic!("mapping form must remain detailed");
    };
    assert_eq!(
        environment.name().expect("environment name").value(),
        "preview-${{ github.run_id }}"
    );
    assert_eq!(
        environment.url().expect("environment URL").value(),
        "https://deployments.example.invalid/${{ github.run_id }}"
    );
    assert!(environment.extensions().is_empty());

    let publish = plan.workflow().jobs()[1].job();
    let JobEnvironment::Name(name) = publish.deployment_environment().expect("named environment")
    else {
        panic!("scalar form must remain a name");
    };
    assert_eq!(name.value(), "production");
}

#[test]
fn malformed_job_metadata_has_field_specific_diagnostics_and_is_retained() {
    let source = r"on: push
jobs:
  malformed:
    runs-on: linux
    outputs:
      - not-a-mapping
    environment:
      url: https://deployments.example.invalid/run
      policy: protected
    steps:
      - run: echo test
";

    let report = support::parse(source);
    assert!(!report.is_accepted());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Semantic
            && diagnostic.code() == "github.expected_mapping"
            && diagnostic.message().contains("jobs.malformed.outputs")
    }));
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Semantic
            && diagnostic.code() == "github.job_environment_name_required"
            && diagnostic
                .message()
                .contains("jobs.malformed.environment.name")
    }));
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Unsupported
            && diagnostic.code() == "github.unsupported_field"
            && diagnostic
                .message()
                .contains("jobs.malformed.environment.policy")
    }));

    let environment = report.plan().expect("loss-aware plan").workflow().jobs()[0]
        .job()
        .deployment_environment()
        .expect("retained environment");
    assert!(environment.name().is_none());
    assert_eq!(environment.extensions().len(), 1);
    assert_eq!(
        environment.extensions()[0].path(),
        "jobs.malformed.environment.policy"
    );
}

#[test]
fn environment_rejects_sequence_form_with_one_precise_diagnostic() {
    let source = r"on: push
jobs:
  deploy:
    runs-on: linux
    environment: [staging, production]
    steps:
      - run: echo deploy
";

    let report = support::parse(source);
    let diagnostics = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.expected_job_environment")
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].kind(), DiagnosticKind::Semantic);
    assert!(
        diagnostics[0]
            .message()
            .contains("scalar name or a mapping with a `name` field")
    );
}

#[test]
fn current_lowering_fails_closed_for_malformed_output_and_environment_shapes() {
    let cases = [
        ("outputs", "artifact", "github.compile.invalid_job_outputs"),
        ("outputs", "null", "github.compile.invalid_job_outputs"),
        (
            "outputs",
            "[artifact]",
            "github.compile.invalid_job_outputs",
        ),
        (
            "environment",
            "null",
            "github.compile.invalid_job_environment",
        ),
        (
            "environment",
            "[staging, production]",
            "github.compile.invalid_job_environment",
        ),
    ];

    for (field, value, code) in cases {
        let source = format!(
            "on: workflow_dispatch\njobs:\n  test:\n    runs-on: linux\n    {field}: {value}\n    steps: [{{run: echo test}}]\n"
        );
        let parsed = support::parse(&source);
        let plan = parsed.plan().expect("loss-aware source plan");
        let job = plan.workflow().jobs()[0].job();
        match field {
            "outputs" => assert!(job.outputs().is_none()),
            "environment" => assert!(job.deployment_environment().is_none()),
            _ => unreachable!("test field is fixed"),
        }

        let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
            plan,
            WorkflowEventProvenance::new("github", "workflow_dispatch"),
        ));
        assert!(report.plan().is_none(), "{field}: {value}");
        let diagnostics = report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code() == code)
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1, "{field}: {value}: {diagnostics:#?}");
        assert_eq!(diagnostics[0].kind(), DiagnosticKind::Semantic);
        assert_eq!(
            plan.source().slice(diagnostics[0].primary_span()),
            Some(value)
        );
    }
}

#[test]
fn current_lowering_retains_job_outputs_without_deployment_semantics() {
    let source = r"on: workflow_dispatch
jobs:
  release:
    runs-on: linux
    outputs:
      artifact: ${{ steps.build.outputs.artifact }}
    steps:
      - id: build
        run: echo build
";

    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
    ));

    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let job = &report.plan().expect("current plan").jobs()[0];
    assert_eq!(job.outputs().len(), 1);
    assert_eq!(job.outputs()[0].key().value().as_str(), "artifact");
    assert!(job.deployment().is_none());
}
