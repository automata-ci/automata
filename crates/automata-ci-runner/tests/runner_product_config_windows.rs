#![cfg(windows)]

use std::collections::BTreeSet;

use automata_ci_core::{
    Architecture, IsolationLevel, OperatingSystem, RunnerFeature, SandboxFeature,
};
use automata_ci_execution::{
    NetworkPolicy, RootFilesystemPolicy, SandboxLaunch, SandboxPrivilegePolicy,
};
use automata_ci_runner::product::{RunnerProductConfig, RunnerProductConfigError};

fn baseline() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../config/runner.windows.example.json"))
        .expect("checked-in Windows configuration JSON")
}

fn parse(value: &serde_json::Value) -> Result<RunnerProductConfig, RunnerProductConfigError> {
    RunnerProductConfig::from_json(
        &serde_json::to_vec(value).expect("serialize mutated Windows configuration"),
    )
}

#[test]
fn checked_in_windows_configuration_selects_only_hyperv_containers() {
    let config = parse(&baseline()).expect("checked-in Windows runner configuration");
    let windows = config.windows_hyperv().expect("Windows Hyper-V provider");

    assert!(config.podman().is_none());
    assert!(config.kubernetes().is_none());
    assert!(config.macos_virtualization().is_none());
    assert_eq!(
        windows.runtime_executable(),
        std::path::Path::new(r"C:\Program Files\Docker\docker.exe")
    );
    assert_eq!(
        windows.guest_agent_path().as_str(),
        r"C:\automata\guest\automata-ci-sandbox-guest.exe"
    );
    assert_eq!(
        windows.operation_timeout(),
        std::time::Duration::from_mins(2)
    );
    assert_eq!(config.executor().network(), NetworkPolicy::Disabled);
    assert_eq!(
        config.executor().root_filesystem(),
        RootFilesystemPolicy::Writable
    );
    assert_eq!(
        config.executor().privilege(),
        SandboxPrivilegePolicy::Unprivileged
    );
    assert_eq!(
        config.inventory().platform().operating_system(),
        &OperatingSystem::Windows
    );
    assert_eq!(
        config.inventory().platform().architecture(),
        &Architecture::X86_64
    );
    assert_eq!(
        config.inventory().sandbox().maximum_isolation(),
        IsolationLevel::VirtualMachine
    );
    assert_eq!(
        config.inventory().sandbox().features(),
        &BTreeSet::from([
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
        ])
    );
    for feature in [RunnerFeature::SHELL_STEPS, RunnerFeature::COMMAND_FILES] {
        assert!(config.inventory().features().contains(&feature));
    }
    assert!(
        !config
            .inventory()
            .features()
            .contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
    );

    let environment = config
        .environments()
        .first_key_value()
        .expect("Hyper-V container environment")
        .1;
    let SandboxLaunch::WindowsHyperVContainer { image, keepalive } = environment.launch() else {
        panic!("Windows must not expose another launch mode")
    };
    assert!(image.reference().contains("@sha256:"));
    assert_eq!(
        keepalive.program().as_str(),
        r"C:\automata\guest\automata-ci-sandbox-guest.exe"
    );
    assert_eq!(keepalive.arguments(), &["keepalive".to_owned()]);
    assert_eq!(environment.workspace().as_str(), r"C:\__w");
    assert!(config.executor().toolchain().node24().is_none());
}

#[test]
fn legacy_and_alternate_windows_providers_are_rejected() {
    let mut no_provider = baseline();
    no_provider
        .as_object_mut()
        .expect("configuration object")
        .remove("windows_hyperv");
    assert_eq!(
        parse(&no_provider).expect_err("a provider is required"),
        RunnerProductConfigError::InvalidProvider
    );

    let mut legacy = baseline();
    legacy
        .as_object_mut()
        .expect("configuration object")
        .remove("windows_hyperv");
    legacy["windows_native"] = serde_json::json!({});
    assert_eq!(
        parse(&legacy).expect_err("the native provider key must be unknown"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut schema_two = baseline();
    schema_two["schema_version"] = serde_json::json!(2);
    assert_eq!(
        parse(&schema_two).expect_err("schema v2 must not be migrated implicitly"),
        RunnerProductConfigError::UnsupportedSchema
    );

    let linux = serde_json::from_slice::<serde_json::Value>(include_bytes!(
        "../config/runner.local-1.example.json"
    ))
    .expect("checked-in Linux configuration JSON");
    let mut two_providers = baseline();
    two_providers["podman"] = linux["podman"].clone();
    assert_eq!(
        parse(&two_providers).expect_err("multiple providers must fail closed"),
        RunnerProductConfigError::InvalidProvider
    );
}

#[test]
fn windows_configuration_rejects_every_weaker_boundary() {
    for (field, invalid_value) in [
        ("network", serde_json::json!("private_egress")),
        ("network", serde_json::json!("host")),
        ("root_filesystem", serde_json::json!("read_only")),
        ("root_filesystem", serde_json::json!("host")),
        ("privilege", serde_json::json!("administrator")),
        ("privilege", serde_json::json!("host")),
    ] {
        let mut value = baseline();
        value["executor"][field] = invalid_value;
        assert_eq!(
            parse(&value).expect_err("Hyper-V isolation policy is mandatory"),
            RunnerProductConfigError::InvalidExecutor
        );
    }

    let mut parallel = baseline();
    parallel["inventory"]["max_parallel_jobs"] = serde_json::json!(2);
    parse(&parallel).expect("independent Hyper-V containers may run concurrently");

    for field in ["ephemeral_disk_bytes", "gpu_count"] {
        let mut value = baseline();
        value["executor"]["resources"][field] = serde_json::json!(1);
        value["inventory"]["resources_per_job"][field] = serde_json::json!(1);
        assert!(parse(&value).is_err(), "nonzero {field} must fail closed");
    }
}

#[test]
fn windows_container_image_runtime_and_guest_agent_are_pinned() {
    let mut mutable_image = baseline();
    mutable_image["inventory"]["environment_profiles"][0]["image"] =
        serde_json::json!("mcr.microsoft.com/windows/servercore:ltsc2025");
    assert_eq!(
        parse(&mutable_image).expect_err("mutable images must be rejected"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut missing_keepalive = baseline();
    missing_keepalive["inventory"]["environment_profiles"][0]
        .as_object_mut()
        .expect("profile object")
        .remove("keepalive_program");
    assert_eq!(
        parse(&missing_keepalive).expect_err("an in-image keepalive is required"),
        RunnerProductConfigError::InvalidInventory
    );

    for (field, invalid) in [
        ("runtime_executable", serde_json::json!(r"docker.exe")),
        ("runtime_sha256", serde_json::json!("not-a-digest")),
        ("guest_agent_path", serde_json::json!(r"C:\guest\agent.cmd")),
        (
            "guest_agent_path",
            serde_json::json!(r"C:\guest\%AUTOMATA_AGENT%.exe"),
        ),
        ("operation_timeout_seconds", serde_json::json!(0)),
        ("operation_timeout_seconds", serde_json::json!(601)),
    ] {
        let mut value = baseline();
        value["windows_hyperv"][field] = invalid;
        assert_eq!(
            parse(&value).expect_err("runtime and guest configuration must be exact"),
            RunnerProductConfigError::InvalidProvider,
            "invalid {field}"
        );
    }

    let mut mismatched_guest = baseline();
    mismatched_guest["windows_hyperv"]["guest_agent_path"] =
        serde_json::json!(r"C:\automata\guest\different-agent.exe");
    assert_eq!(
        parse(&mismatched_guest).expect_err("provider and launch guest paths must agree"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut alternate_keepalive = baseline();
    alternate_keepalive["inventory"]["environment_profiles"][0]["keepalive_arguments"] =
        serde_json::json!(["stdio-once"]);
    assert_eq!(
        parse(&alternate_keepalive).expect_err("the exact keepalive mode is mandatory"),
        RunnerProductConfigError::InvalidInventory
    );
}

#[test]
fn windows_container_toolchain_and_paths_are_in_image_and_literal() {
    let mut configured_node = baseline();
    configured_node["executor"]["toolchain"]["node24"] =
        serde_json::json!(r"C:\Program Files\nodejs\node.exe");
    assert_eq!(
        parse(&configured_node).expect_err("Windows action execution is not advertised"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut legacy_node = baseline();
    legacy_node["executor"]["toolchain"]["node20"] =
        serde_json::json!(r"C:\Program Files\nodejs\node.exe");
    assert_eq!(
        parse(&legacy_node).expect_err("only Node 24 is supported"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut packaged_shell = baseline();
    packaged_shell["executor"]["toolchain"]["pwsh"] =
        serde_json::json!(r"C:\Users\ContainerUser\AppData\Local\Microsoft\WindowsApps\pwsh.exe");
    assert_eq!(
        parse(&packaged_shell).expect_err("WindowsApps tools are not admitted"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut expanded_runner_root = baseline();
    expanded_runner_root["executor"]["runner_root"] =
        serde_json::json!(r"C:\automata\%RUNNER_ROOT%");
    assert_eq!(
        parse(&expanded_runner_root).expect_err("expanded paths must fail closed"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut expanded_workspace = baseline();
    expanded_workspace["inventory"]["environment_profiles"][0]["workspace"] =
        serde_json::json!(r"C:\%WORKSPACE%");
    assert_eq!(
        parse(&expanded_workspace).expect_err("expanded workspace must fail closed"),
        RunnerProductConfigError::InvalidInventory
    );

    for invalid in [r"C:\PROGRA~1\PowerShell", r"C:\Program Filés\PowerShell"] {
        let mut aliased_workspace = baseline();
        aliased_workspace["inventory"]["environment_profiles"][0]["workspace"] =
            serde_json::json!(invalid);
        assert_eq!(
            parse(&aliased_workspace)
                .expect_err("ambiguous Windows namespace aliases must fail closed"),
            RunnerProductConfigError::InvalidInventory,
            "invalid workspace {invalid}"
        );
    }

    let mut short_runner_root = baseline();
    short_runner_root["executor"]["runner_root"] = serde_json::json!(r"C:\AUTOMA~1\runner");
    assert_eq!(
        parse(&short_runner_root).expect_err("8.3 executor paths must fail closed"),
        RunnerProductConfigError::InvalidExecutor
    );
}

#[test]
fn windows_state_and_container_roots_are_disjoint_and_unambiguous() {
    let mut aliased = baseline();
    aliased["state"]["journal"] = serde_json::json!(r"c:\AUTOMATA\STATE\SPOOL\journal-alias");
    assert_eq!(
        parse(&aliased).expect_err("case-insensitive state roots overlap"),
        RunnerProductConfigError::InvalidStateRoots
    );

    for invalid in [
        r"\\server\share\automata\journal",
        r"\\?\C:\automata\state\journal",
        r"\\.\C:\automata\state\journal",
        r"C:\automata\state\CON",
        r"C:\AUTOMA~1\state\journal",
        r"C:\automáta\state\journal",
    ] {
        let mut value = baseline();
        value["state"]["journal"] = serde_json::json!(invalid);
        assert_eq!(
            parse(&value).expect_err("ambiguous Windows state path must fail closed"),
            RunnerProductConfigError::InvalidStateRoots,
            "invalid root {invalid}"
        );
    }

    let mut guest_overlap = baseline();
    guest_overlap["executor"]["runner_root"] = serde_json::json!(r"C:\__w\runner");
    assert_eq!(
        parse(&guest_overlap).expect_err("container roots must be disjoint"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut tool_overlap = baseline();
    tool_overlap["inventory"]["environment_profiles"][0]["workspace"] =
        serde_json::json!(r"C:\Program Files\PowerShell");
    assert_eq!(
        parse(&tool_overlap).expect_err("the workspace must not contain an admitted tool"),
        RunnerProductConfigError::InvalidInventory
    );
}
