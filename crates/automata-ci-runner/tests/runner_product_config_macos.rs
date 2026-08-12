#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use automata_ci_core::{Architecture, IsolationLevel, OperatingSystem, RunnerFeature};
use automata_ci_execution::{SandboxLaunch, SandboxPrivilegePolicy};
use automata_ci_runner::product::{RunnerProductConfig, RunnerProductConfigError};

fn baseline() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../config/runner.macos.example.json"))
        .expect("checked-in macOS runner configuration JSON")
}

fn parse(value: &serde_json::Value) -> Result<RunnerProductConfig, RunnerProductConfigError> {
    RunnerProductConfig::from_json(
        &serde_json::to_vec(value).expect("serialize mutated macOS configuration"),
    )
}

#[test]
fn checked_in_macos_configuration_selects_host_shared_arm64_execution() {
    let config = parse(&baseline()).expect("checked-in macOS runner configuration");

    assert!(config.macos_native().is_some());
    assert!(config.podman().is_none());
    assert!(config.kubernetes().is_none());
    assert!(config.windows_native().is_none());
    assert_eq!(config.executor().privilege(), SandboxPrivilegePolicy::Host);
    assert_eq!(
        config.inventory().platform().operating_system(),
        &OperatingSystem::Macos
    );
    assert_eq!(
        config.inventory().platform().architecture(),
        &Architecture::Aarch64
    );
    assert_eq!(
        config.inventory().sandbox().maximum_isolation(),
        IsolationLevel::Process
    );
    assert!(
        config
            .inventory()
            .features()
            .contains(&RunnerFeature::SHELL_STEPS)
    );
    assert!(
        !config
            .inventory()
            .features()
            .contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
    );
    let environment = config
        .environments()
        .first_key_value()
        .expect("native macOS environment")
        .1;
    assert!(matches!(environment.launch(), SandboxLaunch::Native));
    assert_eq!(
        environment.workspace().as_str(),
        "/Users/automata-runner/Library/Application Support/Automata/native/workspaces"
    );
    assert_eq!(
        config
            .executor()
            .toolchain()
            .sha256sum()
            .expect("shasum")
            .as_str(),
        "/usr/bin/shasum"
    );
}

#[test]
fn macos_configuration_rejects_unsupported_native_surface() {
    let mut no_provider = baseline();
    no_provider
        .as_object_mut()
        .expect("configuration object")
        .remove("macos_native");
    assert_eq!(
        parse(&no_provider).expect_err("a provider is required"),
        RunnerProductConfigError::InvalidProvider
    );

    for (field, invalid) in [
        ("network", serde_json::json!("private_egress")),
        ("root_filesystem", serde_json::json!("writable")),
        ("privilege", serde_json::json!("unprivileged")),
        ("privilege", serde_json::json!("administrator")),
    ] {
        let mut value = baseline();
        value["executor"][field] = invalid;
        assert_eq!(
            parse(&value).expect_err("macOS host policy must remain explicit"),
            RunnerProductConfigError::InvalidExecutor
        );
    }

    let mut parallel = baseline();
    parallel["inventory"]["max_parallel_jobs"] = serde_json::json!(2);
    assert_eq!(
        parse(&parallel).expect_err("native macOS is one-slot"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut javascript = baseline();
    javascript["executor"]["toolchain"]["node20"] = serde_json::json!("/opt/homebrew/bin/node");
    assert_eq!(
        parse(&javascript).expect_err("JavaScript actions are not supported"),
        RunnerProductConfigError::InvalidExecutor
    );

    for field in ["ephemeral_disk_bytes", "gpu_count"] {
        let mut value = baseline();
        value["executor"]["resources"][field] = serde_json::json!(1);
        value["inventory"]["resources_per_job"][field] = serde_json::json!(1);
        assert!(parse(&value).is_err(), "nonzero {field} must fail closed");
    }
}

#[test]
fn macos_provider_roots_are_private_disjoint_descendants() {
    for (section, invalid) in [
        ("executor", "/Users/automata-runner/outside/runner"),
        ("inventory", "/Users/automata-runner/outside/workspaces"),
        (
            "inventory",
            "/Users/automata-runner/Library/Application Support/Automata/native/runner/workspaces",
        ),
    ] {
        let mut value = baseline();
        if section == "executor" {
            value["executor"]["runner_root"] = serde_json::json!(invalid);
        } else {
            value["inventory"]["environment_profiles"][0]["workspace"] = serde_json::json!(invalid);
        }
        assert_eq!(
            parse(&value).expect_err("provider-owned roots require disjoint descendants"),
            RunnerProductConfigError::InvalidInventory
        );
    }

    let mut overlap = baseline();
    overlap["state"]["journal"] = serde_json::json!(
        "/Users/automata-runner/Library/Application Support/Automata/native/journal"
    );
    assert_eq!(
        parse(&overlap).expect_err("durable and native roots cannot overlap"),
        RunnerProductConfigError::InvalidStateRoots
    );
}
