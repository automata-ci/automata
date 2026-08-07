use automata_core::{
    Architecture, ContainerFeature, OperatingSystem, RequirementMismatch, RunnerCapabilities,
    RunnerFeature, RunnerId, RunnerPlatform, RunnerRequirements, SandboxFeature,
};

const KNOWN_RUNNER_JSON: &str = include_str!("fixtures/capabilities/runner-v1-known.json");
const FUTURE_RUNNER_JSON: &str = include_str!("fixtures/capabilities/runner-v1-future.json");
const FUTURE_REQUIREMENTS_JSON: &str =
    include_str!("fixtures/capabilities/requirements-v2-future.json");

fn runner() -> RunnerCapabilities {
    RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
}

#[test]
fn newer_optional_advertisements_are_preserved_and_ignored_by_old_requirements() {
    let future_sandbox =
        SandboxFeature::new("dev.firecracker/uffd-snapshot@v2").expect("valid future sandbox ID");
    let future_container =
        ContainerFeature::new("io.podman/quadlet@v3").expect("valid future container ID");
    let future_runner =
        RunnerFeature::new("com.example/future-runtime@v9").expect("valid future runner ID");

    let known: RunnerCapabilities =
        serde_json::from_str(KNOWN_RUNNER_JSON).expect("decode exact known-version fixture");
    let decoded: RunnerCapabilities = serde_json::from_str(FUTURE_RUNNER_JSON)
        .expect("older code decodes exact future-version fixture");

    assert!(known.features().contains(&RunnerFeature::SHELL_STEPS));
    assert!(decoded.sandbox().features().contains(&future_sandbox));
    assert!(decoded.containers().features().contains(&future_container));
    assert!(decoded.features().contains(&future_runner));
    assert_eq!(
        serde_json::to_value(&decoded).expect("re-serialize decoded advertisement"),
        serde_json::from_str::<serde_json::Value>(FUTURE_RUNNER_JSON)
            .expect("decode fixture as generic JSON"),
    );

    let old_requirements =
        RunnerRequirements::default().with_features([RunnerFeature::SHELL_STEPS]);
    assert_eq!(decoded.satisfies(&old_requirements), Ok(()));
}

#[test]
fn newer_required_identifier_decodes_and_produces_a_typed_missing_feature() {
    let future =
        RunnerFeature::new("com.example/future-runtime@v9").expect("valid future runner ID");
    let decoded: RunnerRequirements = serde_json::from_str(FUTURE_REQUIREMENTS_JSON)
        .expect("decode exact fixture with unknown required feature");
    assert_eq!(decoded.features().iter().next(), Some(&future));
    assert_eq!(
        serde_json::to_value(&decoded).expect("re-serialize future requirements"),
        serde_json::from_str::<serde_json::Value>(FUTURE_REQUIREMENTS_JSON)
            .expect("decode fixture as generic JSON"),
    );

    let mismatches = runner()
        .satisfies(&decoded)
        .expect_err("an unadvertised required feature must not match");
    assert_eq!(
        mismatches.as_slice(),
        &[RequirementMismatch::MissingRunnerFeature(future)],
    );
}

#[test]
fn missing_custom_features_keep_their_sandbox_and_container_domains() {
    let sandbox = SandboxFeature::new("org.example/confidential-vm@v2")
        .expect("valid custom sandbox feature");
    let container = ContainerFeature::new("org.example/image-lazy-pull@v1")
        .expect("valid custom container feature");
    let requirements = RunnerRequirements::default()
        .with_sandbox_features([sandbox.clone()])
        .with_container_features([container.clone()]);

    let mismatches = runner()
        .satisfies(&requirements)
        .expect_err("custom required features are unavailable");
    assert_eq!(
        mismatches.as_slice(),
        &[
            RequirementMismatch::MissingSandboxFeature(sandbox),
            RequirementMismatch::MissingContainerFeature(container),
        ],
    );
}
