use std::collections::BTreeSet;

use automata_ci_control::scheduling::{
    AuthorizedRunnerRouting, EffectiveRunner, EffectiveRunnerError, RoutingRequirements,
    RunnerCapabilityIntersectionError, RunnerEvidence, RunnerEvidenceError, RunnerSlot,
    RunnerSlotError, SessionGuard, intersect_runner_capabilities,
};
use automata_ci_core::{
    Architecture, ContainerCapabilities, ContainerFeature, EnvironmentProfile,
    EnvironmentProfileId, OperatingSystem, ResourceCapacity, RunnerCapabilities, RunnerFeature,
    RunnerLabel, RunnerPlatform, RunnerRequirements, SandboxCapabilities, SandboxFeature,
    Sha256Digest, UnixMillis,
};
use serde_json::json;

use super::scheduling_support::{group, label, observed_capabilities, runner_id, session_id};

#[test]
fn session_and_slot_wire_shapes_preserve_distinct_stable_identities() {
    let runner_id = runner_id(1);
    let session = SessionGuard::new(runner_id, session_id(1));
    let slot = RunnerSlot::new(runner_id, 2).expect("slot must be valid");

    assert_eq!(session.runner_id(), runner_id);
    assert_ne!(
        session.runner_id().to_string(),
        session.session_id().to_string()
    );
    assert_eq!(slot.runner_id(), runner_id);
    assert_eq!(slot.ordinal(), 2);
    assert_eq!(
        serde_json::to_value(slot).expect("slot must serialize"),
        json!({"runner_id": runner_id, "ordinal": 2})
    );
    assert!(
        serde_json::from_value::<RunnerSlot>(json!({
            "runner_id": runner_id,
            "ordinal": 0
        }))
        .is_err()
    );
    assert_eq!(
        RunnerSlot::new(runner_id, 0),
        Err(RunnerSlotError::ZeroOrdinal)
    );
}

#[test]
fn evidence_is_bound_to_the_authenticated_runner() {
    let authenticated = runner_id(1);
    let advertised = runner_id(2);
    let error = RunnerEvidence::new(
        SessionGuard::new(authenticated, session_id(1)),
        observed_capabilities(advertised, 1),
        UnixMillis::new(100),
    )
    .expect_err("cross-runner evidence must fail");

    assert_eq!(
        error,
        RunnerEvidenceError::RunnerIdentityMismatch {
            authenticated,
            advertised,
        }
    );
}

#[test]
fn effective_state_may_add_server_selectors_but_cannot_invent_execution_ability() {
    let runner_id = runner_id(1);
    let evidence = RunnerEvidence::new(
        SessionGuard::new(runner_id, session_id(1)),
        observed_capabilities(runner_id, 4),
        UnixMillis::new(100),
    )
    .expect("evidence must be valid");
    let effective = observed_capabilities(runner_id, 2);
    let authorized = EffectiveRunner::authorize(
        &evidence,
        AuthorizedRunnerRouting::new([label("linux"), label("trusted")], [group("production")]),
        effective,
        [
            RunnerSlot::new(runner_id, 1).expect("slot must be valid"),
            RunnerSlot::new(runner_id, 2).expect("slot must be valid"),
        ],
    )
    .expect("reduced effective state must be valid");

    assert!(
        authorized
            .capabilities()
            .labels()
            .contains(&label("trusted"))
    );
    assert!(
        authorized
            .capabilities()
            .groups()
            .contains(&group("production"))
    );
    assert_eq!(authorized.available_slots().len(), 2);

    let elevated = observed_capabilities(runner_id, 4).with_features([RunnerFeature::OIDC_TOKENS]);
    assert_eq!(
        EffectiveRunner::authorize(&evidence, AuthorizedRunnerRouting::default(), elevated, []),
        Err(EffectiveRunnerError::UnobservedRunnerFeature(
            RunnerFeature::OIDC_TOKENS
        ))
    );
}

#[test]
fn effective_state_rejects_resource_slot_and_container_escalation() {
    let runner_id = runner_id(1);
    let evidence = RunnerEvidence::new(
        SessionGuard::new(runner_id, session_id(1)),
        observed_capabilities(runner_id, 4),
        UnixMillis::new(100),
    )
    .expect("evidence must be valid");

    let excessive_memory = observed_capabilities(runner_id, 4).with_resources_per_job(
        ResourceCapacity::new(4_000, 9 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, 1),
    );
    assert!(matches!(
        EffectiveRunner::authorize(
            &evidence,
            AuthorizedRunnerRouting::default(),
            excessive_memory,
            []
        ),
        Err(EffectiveRunnerError::ResourceExceedsEvidence { .. })
    ));

    let unobserved_container =
        observed_capabilities(runner_id, 4).with_containers(ContainerCapabilities::new([
            ContainerFeature::SERVICE_CONTAINERS,
        ]));
    assert_eq!(
        EffectiveRunner::authorize(
            &evidence,
            AuthorizedRunnerRouting::default(),
            unobserved_container,
            []
        ),
        Err(EffectiveRunnerError::UnobservedContainerFeature(
            ContainerFeature::SERVICE_CONTAINERS
        ))
    );

    let valid = observed_capabilities(runner_id, 2);
    assert_eq!(
        EffectiveRunner::authorize(
            &evidence,
            AuthorizedRunnerRouting::default(),
            valid.clone(),
            [RunnerSlot::new(runner_id, 3).expect("slot must be valid")]
        ),
        Err(EffectiveRunnerError::SlotOutOfRange {
            ordinal: 3,
            maximum: 2,
        })
    );
    let duplicate = RunnerSlot::new(runner_id, 1).expect("slot must be valid");
    assert_eq!(
        EffectiveRunner::authorize(
            &evidence,
            AuthorizedRunnerRouting::default(),
            valid,
            [duplicate, duplicate]
        ),
        Err(EffectiveRunnerError::DuplicateSlot(duplicate))
    );
}

#[test]
fn registered_service_container_ceiling_requires_live_observation() {
    let runner_id = runner_id(1);
    let observed_without_service = observed_capabilities(runner_id, 2);
    let mut registered_features = observed_without_service.containers().features().clone();
    registered_features.insert(ContainerFeature::SERVICE_CONTAINERS);
    let registered = observed_without_service
        .clone()
        .with_containers(ContainerCapabilities::new(registered_features.clone()));

    let reduced = intersect_runner_capabilities(&registered, &observed_without_service)
        .expect("valid observed capabilities must reduce registered authority");
    assert!(
        !reduced
            .containers()
            .features()
            .contains(&ContainerFeature::SERVICE_CONTAINERS),
        "an unobserved registered feature must not become effective"
    );

    let observed_with_service =
        observed_without_service.with_containers(ContainerCapabilities::new(registered_features));
    let retained = intersect_runner_capabilities(&registered, &observed_with_service)
        .expect("matching registered and observed capabilities must intersect");
    assert!(
        retained
            .containers()
            .features()
            .contains(&ContainerFeature::SERVICE_CONTAINERS),
        "an exactly registered and observed feature must remain effective"
    );
}

#[test]
fn pre_enrollment_admitted_windows_actions_survive_live_capability_intersection() {
    let runner_id = runner_id(7);
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.example/windows-server-2025-hyperv")
            .expect("profile ID"),
        Sha256Digest::from_bytes([7; 32]),
    );
    let action_features = [
        RunnerFeature::SHELL_STEPS,
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::LOCAL_ACTIONS,
        RunnerFeature::NODE12_ACTIONS,
        RunnerFeature::NODE16_ACTIONS,
        RunnerFeature::NODE20_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ];
    let admitted = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
    )
    .with_features(action_features.clone())
    .with_environment_profiles([profile]);

    let effective = intersect_runner_capabilities(&admitted, &admitted)
        .expect("the exact registered and independently observed inventory must intersect");

    for feature in action_features {
        assert!(
            effective.features().contains(&feature),
            "a pre-enrollment admitted and live-observed Windows feature must remain schedulable"
        );
    }
}

#[test]
fn routing_requirement_json_rejects_unknown_schema_before_admission() {
    let mut encoded =
        serde_json::to_value(RunnerRequirements::default()).expect("requirements must serialize");
    encoded["schema_version"] = json!(u16::MAX);
    assert!(serde_json::from_value::<RunnerRequirements>(encoded).is_err());
    assert!(RoutingRequirements::new(RunnerRequirements::default()).is_ok());
}

#[test]
fn effective_state_cannot_smuggle_runner_identity_through_selectors() {
    let authenticated = runner_id(1);
    let evidence = RunnerEvidence::new(
        SessionGuard::new(authenticated, session_id(1)),
        observed_capabilities(authenticated, 1),
        UnixMillis::new(100),
    )
    .expect("evidence must be valid");
    let other = runner_id(2);
    let effective = RunnerCapabilities::new(
        other,
        observed_capabilities(authenticated, 1).platform().clone(),
    );

    assert_eq!(
        EffectiveRunner::authorize(&evidence, AuthorizedRunnerRouting::default(), effective, []),
        Err(EffectiveRunnerError::RunnerIdentityMismatch {
            authenticated,
            effective: other,
        })
    );
}

#[test]
fn effective_machine_input_rejects_mixed_administrative_selectors() {
    let runner_id = runner_id(1);
    let evidence = RunnerEvidence::new(
        SessionGuard::new(runner_id, session_id(1)),
        observed_capabilities(runner_id, 1),
        UnixMillis::new(100),
    )
    .expect("evidence must be valid");
    let mixed = observed_capabilities(runner_id, 1)
        .with_labels([RunnerLabel::new("linux").expect("label must be valid")]);

    assert_eq!(
        EffectiveRunner::authorize(&evidence, AuthorizedRunnerRouting::default(), mixed, []),
        Err(EffectiveRunnerError::SelectorsNotSeparated)
    );
}

#[test]
fn runner_advertised_selectors_never_become_effective_routing() {
    let runner_id = runner_id(1);
    let advertised = observed_capabilities(runner_id, 1)
        .with_labels([label("self-promoted")])
        .with_groups([group("production")]);
    let evidence = RunnerEvidence::new(
        SessionGuard::new(runner_id, session_id(1)),
        advertised,
        UnixMillis::new(100),
    )
    .expect("evidence must be valid");

    let effective = EffectiveRunner::authorize(
        &evidence,
        AuthorizedRunnerRouting::new([label("linux")], [group("untrusted")]),
        observed_capabilities(runner_id, 1),
        [RunnerSlot::new(runner_id, 1).expect("slot")],
    )
    .expect("server routing must be authoritative");

    assert_eq!(
        effective.capabilities().labels(),
        &BTreeSet::from([label("linux")])
    );
    assert_eq!(
        effective.capabilities().groups(),
        &BTreeSet::from([group("untrusted")])
    );
    assert!(
        !effective
            .capabilities()
            .labels()
            .contains(&label("self-promoted"))
    );
    assert!(
        !effective
            .capabilities()
            .groups()
            .contains(&group("production"))
    );
}

#[test]
fn capability_intersection_is_least_authority_and_excludes_selectors() {
    let runner_id = runner_id(1);
    let shared_profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.com/shared").expect("profile ID"),
        Sha256Digest::from_bytes([1; 32]),
    );
    let registered_only_profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.com/registered").expect("profile ID"),
        Sha256Digest::from_bytes([2; 32]),
    );
    let observed_only_profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.com/observed").expect("profile ID"),
        Sha256Digest::from_bytes([3; 32]),
    );
    let registered = observed_capabilities(runner_id, 4)
        .with_labels([label("registered-label")])
        .with_groups([group("registered-group")])
        .with_environment_profiles([shared_profile.clone(), registered_only_profile]);
    let observed = observed_capabilities(runner_id, 2)
        .with_resources_per_job(ResourceCapacity::new(2_000, 1024, 2048, 0))
        .with_sandbox(SandboxCapabilities::new(
            automata_ci_core::IsolationLevel::Process,
            [SandboxFeature::CLEAN_WORKSPACE],
        ))
        .with_containers(ContainerCapabilities::new([
            ContainerFeature::JOB_CONTAINERS,
        ]))
        .with_features([RunnerFeature::SHELL_STEPS, RunnerFeature::OIDC_TOKENS])
        .with_environment_profiles([shared_profile.clone(), observed_only_profile]);

    let effective = intersect_runner_capabilities(&registered, &observed)
        .expect("compatible identities must intersect");

    assert_eq!(effective.max_parallel_jobs(), 2);
    assert_eq!(
        effective.resources_per_job(),
        ResourceCapacity::new(2_000, 1024, 2048, 0)
    );
    assert_eq!(
        effective.features(),
        &BTreeSet::from([RunnerFeature::SHELL_STEPS])
    );
    assert_eq!(
        effective.environment_profiles(),
        &BTreeSet::from([shared_profile])
    );
    assert!(effective.labels().is_empty());
    assert!(effective.groups().is_empty());
}

#[test]
fn capability_intersection_rejects_identity_and_platform_disagreement() {
    let registered = observed_capabilities(runner_id(1), 1);
    let other_runner = observed_capabilities(runner_id(2), 1);
    assert_eq!(
        intersect_runner_capabilities(&registered, &other_runner),
        Err(RunnerCapabilityIntersectionError::RunnerIdentityMismatch {
            registered: runner_id(1),
            observed: runner_id(2),
        })
    );

    let other_platform = RunnerCapabilities::new(
        runner_id(1),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::Aarch64),
    );
    assert_eq!(
        intersect_runner_capabilities(&registered, &other_platform),
        Err(RunnerCapabilityIntersectionError::PlatformMismatch)
    );
}
