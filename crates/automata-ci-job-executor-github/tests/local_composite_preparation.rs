use std::sync::Arc;

use automata_ci_action_actions::{GithubActionMetadataDecoder, JavascriptRuntime};
use automata_ci_core::ActionReference;
use automata_ci_execution::TargetPath;
use automata_ci_job_executor_github::{
    ActionPreparationErrorKind, CheckedOutLocalActionPreparer, LocalActionPreparationRequest,
    PreparedActionExecution, PreparedBoolean, PreparedCompositeStep, PreparedValue,
    PreparedValueSegment,
};
use automata_ci_workflow_actions::GithubConditionCompiler;

const COMPOSITE: &str = r#"
name: Synthetic composite
description: Exercises the generic prepared contract
inputs:
  target:
    default: prefix-${{ github.ref }}
outputs:
  greeting:
    value: ${{ steps.greet.outputs.value }}
runs:
  using: composite
  steps:
    - id: greet
      name: Greet ${{ inputs.target }}
      if: ${{ inputs.target != '' }}
      run: echo "value=${{ inputs.target }}" >> "$GITHUB_OUTPUT"
      shell: bash
      working-directory: ${{ github.action_path }}
      env:
        TARGET: ${{ inputs.target }}
      continue-on-error: ${{ inputs.allow_failure == 'true' }}
    - name: Repository child
      uses: owner/action/subdirectory@v1
      with:
        value: before-${{ inputs.target }}-after
      env:
        MODE: synthetic
    - name: Local child
      uses: ./nested/action
      with:
        value: ${{ steps.greet.outputs.value }}
"#;

fn preparer() -> CheckedOutLocalActionPreparer {
    CheckedOutLocalActionPreparer::new(
        Arc::new(GithubActionMetadataDecoder::default()),
        GithubConditionCompiler::default(),
    )
}

fn prepared_fixture(source: &str) -> automata_ci_job_executor_github::PreparedLocalAction {
    let reference = ActionReference::Local {
        path: "./.github/actions/fixture".to_owned(),
    };
    preparer()
        .prepare(LocalActionPreparationRequest::new(
            &reference,
            Some(source.as_bytes()),
            None,
        ))
        .expect("real action metadata fixture prepares")
}

#[test]
#[allow(clippy::too_many_lines)] // One cross-action fixture table keeps order and scalar assertions adjacent.
fn checkout_setup_and_artifact_fixtures_preserve_runner_input_contracts() {
    let checkout = prepared_fixture(include_str!(
        "../../automata-ci-action-actions/tests/fixtures/checkout-v6.0.2-de0fac2-action.yml"
    ));
    let expected_checkout_inputs = [
        "repository",
        "ref",
        "token",
        "ssh-key",
        "ssh-known-hosts",
        "ssh-strict",
        "ssh-user",
        "persist-credentials",
        "path",
        "clean",
        "filter",
        "sparse-checkout",
        "sparse-checkout-cone-mode",
        "fetch-depth",
        "fetch-tags",
        "show-progress",
        "lfs",
        "submodules",
        "set-safe-directory",
        "github-server-url",
    ];
    assert_eq!(
        checkout
            .definition()
            .inputs()
            .iter()
            .map(automata_ci_job_executor_github::PreparedInput::name)
            .collect::<Vec<_>>(),
        expected_checkout_inputs
    );
    assert_eq!(
        checkout
            .definition()
            .javascript()
            .expect("checkout JavaScript")
            .runtime(),
        JavascriptRuntime::Node24
    );
    let checkout_server = checkout
        .definition()
        .inputs()
        .iter()
        .find(|input| input.name() == "github-server-url")
        .expect("checkout server input");
    assert_eq!(checkout_server.required(), Some("false"));
    assert!(checkout_server.default().is_none());
    let checkout_filter = checkout
        .definition()
        .inputs()
        .iter()
        .find(|input| input.name() == "filter")
        .expect("checkout filter input");
    assert!(matches!(
        checkout_filter.default(),
        Some(PreparedValue::Literal(value)) if value.is_empty()
    ));
    let checkout_strict = checkout
        .definition()
        .inputs()
        .iter()
        .find(|input| input.name() == "ssh-strict")
        .expect("checkout strict input");
    assert!(matches!(
        checkout_strict.default(),
        Some(PreparedValue::Literal(value)) if value == "true"
    ));

    let setup = prepared_fixture(include_str!(
        "../../automata-ci-action-actions/tests/fixtures/setup-node-v6-representative.yml"
    ));
    let deprecated = setup
        .definition()
        .inputs()
        .iter()
        .find(|input| input.name() == "package-manager-cache")
        .expect("setup-node deprecated input");
    assert_eq!(deprecated.deprecation_message(), Some("Use cache instead"));
    assert!(matches!(
        deprecated.default(),
        Some(PreparedValue::Literal(value)) if value == "true"
    ));

    let artifact = prepared_fixture(include_str!(
        "../../automata-ci-action-actions/tests/fixtures/upload-artifact-v7-representative.yml"
    ));
    let path = artifact
        .definition()
        .inputs()
        .iter()
        .find(|input| input.name() == "path")
        .expect("artifact path input");
    assert_eq!(path.required(), Some("true"));
    assert!(path.default().is_none());
    let compression = artifact
        .definition()
        .inputs()
        .iter()
        .find(|input| input.name() == "compression-level")
        .expect("artifact compression input");
    assert!(matches!(
        compression.default(),
        Some(PreparedValue::Literal(value)) if value == "6"
    ));
    assert_eq!(artifact.definition().outputs().len(), 3);
}

#[test]
fn multiline_deprecation_metadata_is_canonicalized_for_one_line_diagnostics() {
    let reference = ActionReference::Local {
        path: "./.github/actions/cache-shape".to_owned(),
    };
    let prepared = preparer()
        .prepare(LocalActionPreparationRequest::new(
            &reference,
            Some(
                b"inputs:\n  save-always:\n    deprecationMessage: |\n      save-always does not work as intended and will be removed.\n      Use actions/cache/restore instead.\nruns:\n  using: node24\n  main: index.js\n",
            ),
            None,
        ))
        .expect("ordinary metadata line breaks are safe after canonicalization");
    let input = &prepared.definition().inputs()[0];
    assert_eq!(
        input.deprecation_message(),
        Some(
            "save-always does not work as intended and will be removed. Use actions/cache/restore instead."
        )
    );
}

#[test]
fn unsafe_deprecation_metadata_fails_preparation_without_becoming_a_log_record() {
    let reference = ActionReference::Local {
        path: "./.github/actions/unsafe-message".to_owned(),
    };
    let error = preparer()
        .prepare(LocalActionPreparationRequest::new(
            &reference,
            Some(
                b"inputs:\n  old:\n    deprecationMessage: \"first\\u001bforged\"\nruns:\n  using: node24\n  main: index.js\n",
            ),
            None,
        ))
        .expect_err("control-containing diagnostics fail closed");
    assert_eq!(error.kind(), ActionPreparationErrorKind::Metadata);
}

#[test]
fn checked_out_composite_is_compiled_without_executing_user_code() {
    let reference = ActionReference::Local {
        path: "./.github/actions/synthetic".to_owned(),
    };
    let prepared = preparer()
        .prepare(LocalActionPreparationRequest::new(
            &reference,
            Some(COMPOSITE.as_bytes()),
            Some(b"this lower-precedence candidate is deliberately invalid: ["),
        ))
        .expect("action.yml takes precedence and compiles");

    assert_eq!(prepared.path(), "./.github/actions/synthetic");
    let definition = prepared.definition();
    assert_eq!(definition.inputs().len(), 1);
    let PreparedValue::Template(default) = definition.inputs()[0].default().expect("input default")
    else {
        panic!("interpolated input default must remain a template");
    };
    assert!(matches!(default[0], PreparedValueSegment::Literal(_)));
    assert!(matches!(default[1], PreparedValueSegment::Expression(_)));
    assert_eq!(definition.outputs().len(), 1);
    assert!(matches!(
        definition.outputs()[0].value(),
        Some(PreparedValue::Expression(_))
    ));

    let PreparedActionExecution::Composite(composite) = definition.execution() else {
        panic!("composite execution must remain explicit");
    };
    assert_eq!(composite.steps().len(), 3);

    let PreparedCompositeStep::Run(run) = &composite.steps()[0] else {
        panic!("first child must be a run step");
    };
    assert_eq!(run.metadata().id().expect("explicit ID").as_str(), "greet");
    assert!(matches!(
        run.metadata().continue_on_error(),
        PreparedBoolean::Expression(_)
    ));
    assert!(matches!(run.command(), PreparedValue::Template(_)));
    assert!(matches!(run.shell(), PreparedValue::Literal(value) if value == "bash"));
    assert!(matches!(
        run.working_directory(),
        Some(PreparedValue::Expression(_))
    ));
    assert_eq!(run.environment()[0].name(), "TARGET");
    assert!(matches!(
        run.environment()[0].value(),
        PreparedValue::Expression(_)
    ));

    let PreparedCompositeStep::Uses(repository) = &composite.steps()[1] else {
        panic!("second child must be a nested action");
    };
    assert_eq!(
        repository.reference(),
        &ActionReference::Repository {
            repository: "owner/action".to_owned(),
            selector: "v1".to_owned(),
            subpath: Some("subdirectory".to_owned()),
        }
    );
    assert!(matches!(
        repository.inputs()[0].value(),
        PreparedValue::Template(_)
    ));

    let PreparedCompositeStep::Uses(local) = &composite.steps()[2] else {
        panic!("third child must be a nested action");
    };
    assert_eq!(
        local.reference(),
        &ActionReference::Local {
            path: "./nested/action".to_owned(),
        }
    );
}

#[test]
fn local_reference_resolves_only_contained_metadata_candidates() {
    let reference = ActionReference::Local {
        path: "./actions/synthetic/nested".to_owned(),
    };
    let posix = CheckedOutLocalActionPreparer::definition_paths(
        &TargetPath::posix("/__w/repository/repository").expect("workspace"),
        &reference,
    )
    .expect("contained POSIX candidates");
    assert_eq!(
        posix.action_yml().as_str(),
        "/__w/repository/repository/actions/synthetic/nested/action.yml"
    );
    assert_eq!(
        posix.action_yaml().as_str(),
        "/__w/repository/repository/actions/synthetic/nested/action.yaml"
    );

    let windows = CheckedOutLocalActionPreparer::definition_paths(
        &TargetPath::windows(r"D:\a\repository\repository").expect("workspace"),
        &reference,
    )
    .expect("contained Windows candidates");
    assert_eq!(
        windows.action_yml().as_str(),
        r"D:\a\repository\repository\actions\synthetic\nested\action.yml"
    );
    assert_eq!(
        windows.action_yaml().as_str(),
        r"D:\a\repository\repository\actions\synthetic\nested\action.yaml"
    );
}

#[test]
fn action_yaml_is_used_only_when_action_yml_is_absent() {
    let reference = ActionReference::Local {
        path: "./actions/fallback".to_owned(),
    };
    let prepared = preparer()
        .prepare(LocalActionPreparationRequest::new(
            &reference,
            None,
            Some(COMPOSITE.as_bytes()),
        ))
        .expect("action.yaml fallback compiles");
    assert!(prepared.definition().composite().is_some());
}

#[test]
fn local_preparation_rejects_unsafe_missing_and_dynamic_references() {
    for path in [
        "../outside",
        "./../outside",
        "./action/../outside",
        "./action/",
    ] {
        let reference = ActionReference::Local {
            path: path.to_owned(),
        };
        let error = preparer()
            .prepare(LocalActionPreparationRequest::new(
                &reference,
                Some(COMPOSITE.as_bytes()),
                None,
            ))
            .expect_err("unsafe local path must fail closed");
        assert_eq!(error.kind(), ActionPreparationErrorKind::Metadata);
    }

    let reference = ActionReference::Local {
        path: "./action".to_owned(),
    };
    let missing = preparer()
        .prepare(LocalActionPreparationRequest::new(&reference, None, None))
        .expect_err("missing metadata must fail closed");
    assert_eq!(missing.kind(), ActionPreparationErrorKind::Metadata);

    let dynamic = COMPOSITE.replace(
        "uses: ./nested/action",
        "uses: ${{ inputs.dynamic_action }}",
    );
    let error = preparer()
        .prepare(LocalActionPreparationRequest::new(
            &reference,
            Some(dynamic.as_bytes()),
            None,
        ))
        .expect_err("dynamic nested references must fail closed");
    assert_eq!(error.kind(), ActionPreparationErrorKind::Metadata);
}

#[test]
fn request_debug_reports_sizes_without_metadata_content() {
    let reference = ActionReference::Local {
        path: "./action".to_owned(),
    };
    let request =
        LocalActionPreparationRequest::new(&reference, Some(b"secret-looking-metadata"), None);
    let debug = format!("{request:?}");
    assert!(debug.contains("23"));
    assert!(!debug.contains("secret-looking-metadata"));
}
