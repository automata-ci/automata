use automata_core::{
    CapabilityIdError, ContainerFeature, MAX_CAPABILITY_ID_LENGTH, RunnerFeature, SandboxFeature,
};

#[test]
fn known_identifiers_have_stable_namespaced_wire_values() {
    assert_eq!(
        SandboxFeature::NETWORK_ISOLATION.as_str(),
        "automata.core/network-isolation@v1",
    );
    assert_eq!(
        ContainerFeature::SERVICE_CONTAINERS.as_str(),
        "automata.core/service-containers@v1",
    );
    assert_eq!(
        RunnerFeature::SHELL_STEPS.as_str(),
        "automata.core/shell-steps@v1",
    );
}

#[test]
fn custom_provider_identifiers_round_trip_without_losing_identity() {
    let sandbox = SandboxFeature::new("dev.firecracker/fast-snapshot@v2")
        .expect("valid future sandbox capability");
    let containers = ContainerFeature::new("io.containerd/lazy-pull@v12")
        .expect("valid provider container capability");
    let runner = RunnerFeature::new("com.example/action-runtime@v65535")
        .expect("valid future runner capability");

    assert_eq!(sandbox.namespace(), "dev.firecracker");
    assert_eq!(sandbox.name(), "fast-snapshot");
    assert_eq!(sandbox.major_version(), 2);
    assert_eq!(containers.major_version(), 12);
    assert_eq!(runner.major_version(), u16::MAX);

    for (encoded, expected) in [
        (
            serde_json::to_string(&sandbox).expect("serialize sandbox ID"),
            r#""dev.firecracker/fast-snapshot@v2""#,
        ),
        (
            serde_json::to_string(&containers).expect("serialize container ID"),
            r#""io.containerd/lazy-pull@v12""#,
        ),
        (
            serde_json::to_string(&runner).expect("serialize runner ID"),
            r#""com.example/action-runtime@v65535""#,
        ),
    ] {
        assert_eq!(encoded, expected);
    }

    assert_eq!(
        serde_json::from_str::<SandboxFeature>(r#""dev.firecracker/fast-snapshot@v2""#)
            .expect("deserialize future sandbox ID"),
        sandbox,
    );
    assert_eq!(
        serde_json::from_str::<ContainerFeature>(r#""io.containerd/lazy-pull@v12""#)
            .expect("deserialize provider container ID"),
        containers,
    );
    assert_eq!(
        serde_json::from_str::<RunnerFeature>(r#""com.example/action-runtime@v65535""#)
            .expect("deserialize future runner ID"),
        runner,
    );
}

#[test]
fn capability_identifier_grammar_rejects_noncanonical_values() {
    let cases = [
        ("", CapabilityIdError::Empty),
        ("shell_steps", CapabilityIdError::InvalidVersion),
        (
            "automata.core/shell-steps",
            CapabilityIdError::InvalidVersion,
        ),
        (
            "automata.core/shell-steps@v0",
            CapabilityIdError::InvalidVersion,
        ),
        (
            "automata.core/shell-steps@v01",
            CapabilityIdError::InvalidVersion,
        ),
        (
            "automata.core/shell-steps@v65536",
            CapabilityIdError::InvalidVersion,
        ),
        (
            "Automata.core/shell-steps@v1",
            CapabilityIdError::InvalidNamespace,
        ),
        (
            "automata..core/shell-steps@v1",
            CapabilityIdError::InvalidNamespace,
        ),
        (
            "automata.core/ShellSteps@v1",
            CapabilityIdError::InvalidName,
        ),
        (
            "automata.core/-shell-steps@v1",
            CapabilityIdError::InvalidName,
        ),
        (
            "automata.core/shell_steps@v1",
            CapabilityIdError::InvalidName,
        ),
        (
            "automata.core/shell-steps/@v1",
            CapabilityIdError::InvalidName,
        ),
        ("automata.core/café@v1", CapabilityIdError::NonAscii),
    ];

    for (value, expected) in cases {
        assert_eq!(RunnerFeature::new(value), Err(expected), "value: {value}");
        let json = serde_json::to_string(value).expect("serialize invalid test string");
        assert!(
            serde_json::from_str::<RunnerFeature>(&json).is_err(),
            "serde accepted invalid value: {value}",
        );
    }
}

#[test]
fn identifier_length_limit_is_measured_in_wire_bytes() {
    let fixed_bytes = "com.example/@v1".len();
    let maximum = format!(
        "com.example/{}@v1",
        "a".repeat(MAX_CAPABILITY_ID_LENGTH - fixed_bytes),
    );
    assert_eq!(maximum.len(), MAX_CAPABILITY_ID_LENGTH);
    assert!(RunnerFeature::new(&maximum).is_ok());

    let overlong = format!("{maximum}a");
    assert_eq!(
        RunnerFeature::new(overlong),
        Err(CapabilityIdError::TooLong {
            max: MAX_CAPABILITY_ID_LENGTH,
        }),
    );
}

#[test]
fn the_three_capability_domains_use_the_same_grammar_but_distinct_types() {
    let value = "org.example/shared-name@v3";
    let sandbox = SandboxFeature::new(value).expect("valid sandbox ID");
    let containers = ContainerFeature::new(value).expect("valid container ID");
    let runner = RunnerFeature::new(value).expect("valid runner ID");

    assert_eq!(sandbox.as_str(), containers.as_str());
    assert_eq!(containers.as_str(), runner.as_str());
}
