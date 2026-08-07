use std::collections::BTreeSet;

use automata_core::{
    Architecture, ContainerCapabilities, ContainerFeature, EnvironmentProfile,
    EnvironmentProfileId, IsolationLevel, OperatingSystem, RequirementMismatch, ResourceCapacity,
    ResourceKind, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId, RunnerLabel,
    RunnerPlatform, RunnerRequirements, SandboxCapabilities, SandboxFeature, SelectorError,
    Sha256Digest,
};

fn label(value: &str) -> RunnerLabel {
    RunnerLabel::new(value).expect("valid test label")
}

fn group(value: &str) -> RunnerGroup {
    RunnerGroup::new(value).expect("valid test group")
}

fn profile(digest_byte: u8) -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("github.com/ubuntu-24.04").expect("valid profile ID"),
        Sha256Digest::from_bytes([digest_byte; 32]),
    )
}

fn capable_runner() -> RunnerCapabilities {
    RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label("Self-Hosted"), label("LINUX"), label("x64")])
    .with_groups([group("trusted")])
    .with_max_parallel_jobs(2)
    .expect("positive slot count")
    .with_resources_per_job(ResourceCapacity::new(
        4_000,
        8 * 1024 * 1024 * 1024,
        20 * 1024 * 1024 * 1024,
        0,
    ))
    .with_sandbox(SandboxCapabilities::new(
        IsolationLevel::VirtualMachine,
        [SandboxFeature::NETWORK_ISOLATION],
    ))
    .with_containers(ContainerCapabilities::new([
        ContainerFeature::SERVICE_CONTAINERS,
    ]))
    .with_features([RunnerFeature::SHELL_STEPS])
}

#[test]
fn label_matching_is_case_insensitive_superset_matching() {
    let runner = capable_runner();
    let required: BTreeSet<_> = [label("linux"), label("SELF-HOSTED")].into();
    assert!(runner.has_all_labels(&required));

    let unavailable: BTreeSet<_> = [label("linux"), label("gpu")].into();
    assert!(!runner.has_all_labels(&unavailable));
}

#[test]
fn every_subset_of_advertised_labels_matches_property_style() {
    let runner = capable_runner();
    let labels: Vec<_> = runner.labels().iter().cloned().collect();
    for mask in 0..(1_usize << labels.len()) {
        let subset = labels
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, label)| label.clone())
            .collect();
        assert!(runner.has_all_labels(&subset));
    }
}

#[test]
fn typed_requirement_matching_checks_groups_resources_and_features() {
    let runner = capable_runner();
    let requirements = RunnerRequirements::default()
        .with_labels([label("linux")])
        .with_eligible_groups([group("trusted"), group("fallback")])
        .with_operating_system(OperatingSystem::Linux)
        .with_architecture(Architecture::X86_64)
        .with_minimum_resources(ResourceCapacity::new(2_000, 4 * 1024 * 1024 * 1024, 1, 0))
        .with_minimum_isolation(IsolationLevel::SharedKernel)
        .with_sandbox_features([SandboxFeature::NETWORK_ISOLATION])
        .with_container_features([ContainerFeature::SERVICE_CONTAINERS])
        .with_features([RunnerFeature::SHELL_STEPS]);
    assert_eq!(runner.satisfies(&requirements), Ok(()));

    let unavailable = requirements
        .with_labels([label("linux"), label("gpu")])
        .with_minimum_resources(ResourceCapacity::new(2_000, 4 * 1024 * 1024 * 1024, 1, 1))
        .with_container_features([
            ContainerFeature::SERVICE_CONTAINERS,
            ContainerFeature::PRIVILEGED_CONTAINERS,
        ]);
    let errors = runner
        .satisfies(&unavailable)
        .expect_err("missing typed requirements must reject runner");
    assert!(
        errors
            .as_slice()
            .contains(&RequirementMismatch::MissingLabel(label("gpu")))
    );
    assert!(errors.iter().any(|error| matches!(
        error,
        RequirementMismatch::InsufficientResource {
            resource: ResourceKind::GpuCount,
            ..
        }
    )));
    assert!(
        errors
            .as_slice()
            .contains(&RequirementMismatch::MissingContainerFeature(
                ContainerFeature::PRIVILEGED_CONTAINERS,
            ),)
    );
}

#[test]
fn selectors_reject_ambiguous_whitespace() {
    assert_eq!(
        RunnerLabel::new(" linux"),
        Err(SelectorError::SurroundingWhitespace("runner label")),
    );
}

#[test]
fn mismatch_variants_have_stable_round_trippable_json() {
    let mismatch = RequirementMismatch::MissingLabel(label("GPU"));
    let json = serde_json::to_string(&mismatch).expect("serialize mismatch");
    assert_eq!(json, r#"{"kind":"missing_label","details":"gpu"}"#);
    assert_eq!(
        serde_json::from_str::<RequirementMismatch>(&json).expect("deserialize mismatch"),
        mismatch,
    );
}

#[test]
fn feature_mismatches_use_the_extensible_identifier_wire_shape() {
    let mismatch = RequirementMismatch::MissingRunnerFeature(RunnerFeature::SHELL_STEPS);
    let json = serde_json::to_string(&mismatch).expect("serialize mismatch");
    assert_eq!(
        json,
        r#"{"kind":"missing_runner_feature","details":"automata.core/shell-steps@v1"}"#,
    );
    assert_eq!(
        serde_json::from_str::<RequirementMismatch>(&json).expect("deserialize mismatch"),
        mismatch,
    );
}

#[test]
fn environment_profile_requires_the_exact_attested_profile() {
    let required = profile(0x11);
    let requirements = RunnerRequirements::default().with_environment_profile(required.clone());

    let labels_and_features_only = capable_runner()
        .with_labels([label("ubuntu-24.04")])
        .with_features([
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::new("github.com/ubuntu-24-04@v1").expect("valid feature"),
        ]);
    let mismatch = labels_and_features_only
        .satisfies(&requirements)
        .expect_err("labels and features cannot impersonate an attested profile");
    assert!(mismatch.iter().any(|item| matches!(
        item,
        RequirementMismatch::EnvironmentProfile {
            required: actual,
            available,
        } if actual == &required && available.is_empty()
    )));

    let wrong_digest = capable_runner().with_environment_profiles([profile(0x22)]);
    let mismatch = wrong_digest
        .satisfies(&requirements)
        .expect_err("the same profile ID with a different digest must not match");
    assert!(mismatch.iter().any(|item| matches!(
        item,
        RequirementMismatch::EnvironmentProfile {
            required: actual,
            available,
        } if actual == &required && available.contains(&profile(0x22))
    )));

    assert_eq!(
        capable_runner()
            .with_environment_profiles([required])
            .satisfies(&requirements),
        Ok(())
    );
}

#[test]
fn environment_profiles_have_strict_namespaced_serde() {
    let value = profile(0x33);
    let json = serde_json::to_value(&value).expect("serialize profile");
    assert_eq!(json["id"], "github.com/ubuntu-24.04");
    assert_eq!(
        serde_json::from_value::<EnvironmentProfile>(json.clone()).expect("deserialize profile"),
        value
    );

    let mut unknown = json;
    unknown["future"] = serde_json::json!(true);
    assert!(serde_json::from_value::<EnvironmentProfile>(unknown).is_err());
    assert!(EnvironmentProfileId::new("ubuntu-24.04").is_err());
    assert!(EnvironmentProfileId::new("GitHub.com/ubuntu-24.04").is_err());
}
